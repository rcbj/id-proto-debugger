// File: sts_admin_api_operations.js
//
// ---------------------------------------------------------------------------
// EVERY OPERATION OF THE MOCK STS'S MANAGEMENT API, DRIVEN FOR REAL.
//
// `tests/admin_api.js` next door asserts that the API is SHAPED right: that the
// OpenAPI document is well formed, that every console page and every console
// action has an operation, that every documented RESPONSE property appears in a
// live reply, and that one revocation reaches RFC 7662 introspection. It is a
// parity and schema test, and it deliberately exercises a handful of the
// operations for real.
//
// This file is the other half: **does EVERY ONE of those operations DO what it
// says?** The count is not written down here on purpose — it was ninety when
// this file was written and it is over a hundred and thirty now, and a number
// in a comment is the first thing to go stale. What keeps the claim honest is
// the LEDGER at the end of the run: every operation the document declares must
// have been driven by this file, or hold a row in NOT_DRIVEN_HERE saying who
// drives it and why. Nothing in the mock can answer that about itself. Every POST there
// calls the same function the console's form posts to, so the two doors cannot
// drift from each other — but they can both be wrong together, and the
// arrangement that makes them one implementation is exactly what stops either
// of them noticing.
//
// SIX THINGS IT ASSERTS THAT NOTHING ELSE DOES, and the last two are about
// THIS FILE rather than about the service — they are what stop the four above
// from quietly covering less than they say.
//
//   * **THE DOCUMENTED EXAMPLE IS REPLAYED AGAINST THE SERVICE.** Every POST
//     operation but six carries an `examples` body in its request schema, and
//     that example is the thing a caller copies first. Each one is sent, and a
//     refusal whose reason is about the SHAPE of the request — "Which
//     application? Send `application` with…", "Name the relying party in
//     `rp`" — fails the job, because it means the document names a property the
//     handler does not read. `mgmt-api/CLAUDE.md` names this defect class
//     itself and says it is uncovered: *"a documented request property that
//     changes nothing is the same class of defect as a documented response
//     property that is never sent"*, and it records one that lived for months
//     (`createRealm` documenting an `overrides` field the shared action
//     function dropped). A refusal about the REFERENT — "there is no
//     application called my-web-app" — is legitimate and is allowed, because
//     an example has to name something.
//   * **THE ROUND TRIP.** A write is followed by a READ THROUGH A DIFFERENT
//     OPERATION, never by believing the write's own account of itself. A
//     handler that answers `{ok: true}` and changes nothing passes every check
//     in admin_api.js.
//   * **THE REFUSAL SENTENCES COUNT THEIR OWN LISTS.** Each action handler
//     answers an unknown action by naming the ones it knows — *"Unknown action
//     "x". The six are: …"* — and that sentence is not decoration: it is what
//     admin_api.js reads to check the console/API parity. So a sentence that
//     says "six" over a list of seven, or that omits an action the handler
//     really has, silently narrows the only check that notices a missing
//     operation. Both halves are asserted here: the count matches the list, and
//     the list matches the operations the document declares.
//   * **A CONFIGURATION CHANGE REACHES THE PERSISTENCE STORE.** Setting a value
//     and reading it back proves only that something is holding it in memory.
//     What `/admin/persistence` promises is that it was WRITTEN, so the write
//     counter, the dirty flag and the failure counter are read either side of
//     the change. When the service is running in `memory` mode — the default,
//     and what the containerized stack uses — that is REPORTED rather than
//     skipped silently, because "the store is off" and "the store did not
//     write" look identical from a distance and only one of them is fine.
//   * **EVERY DOCUMENTED OPERATION WAS DRIVEN — checked, not claimed.** The
//     walks here are driven off the document (every GET, and every POST that
//     carries an example), so an operation arriving with NO example and no
//     section of its own would be covered by nothing while this file went on
//     calling itself "every operation". A ledger of what was really called is
//     compared with the document at the end of the run, and an exemption is a
//     row in a table with a sentence in it. `resetAllSettings` was exactly
//     that hole when the ledger was added, and is driven now.
//   * **AND EVERY ACCEPTED WRITE WAS READ BACK.** The round trip above is a
//     rule this file keeps by hand, which means it is a rule the next section
//     can forget: four actions posted and none read would pass every other
//     check here AND be reported as four more operations covered. The same
//     ledger requires a GET of the resource each successful POST wrote, in the
//     scope it wrote it in — the structural half of the round trip, enforced
//     rather than remembered.
//
// ---------------------------------------------------------------------------
// ALMOST EVERYTHING HAPPENS IN A TRUST REALM THIS FILE CREATES AND REMOVES.
//
// A management API test is by definition a test that writes to the thing every
// other job reads. The mock holds its admin state in memory and never restarts
// between jobs, so a claim set left changed here changes what every later
// job's tokens contain — which is why admin_api.js restores everything it
// touches, one value at a time, and why it is EXCLUSIVE in run-report.js.
//
// Trust realms make that mostly unnecessary. A realm is a whole logical copy of
// this service under a path prefix, with its own directory subtree, its own
// applications registry, its own federation register, its own claim sets, its
// own tokens and its own configuration overrides. So this job creates one,
// performs every destructive thing inside it — `forget`, `revoke-all`,
// `reset-all`, `delete` — and removes it at the end, which takes the whole
// subtree with it. What is left to restore by hand is only what is genuinely
// process-wide, and that list is short and is named where it is touched: the
// two admin roles (groups in the DEFAULT realm, by design), the SPIFFE signing
// authority, and one process-wide setting.
//
// It is still EXCLUSIVE in run-report.js, for one reason that a realm cannot
// fix: `/admin-api/spiffe/rotate` replaces the signing authority for the whole
// process, and a SPIFFE job holding a stream open across that would see its
// SVID stop verifying with nothing to say why.
//
// Needs the STS mock and nothing else — no browser, no Keycloak.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");
const names = require("./random_username.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_admin_api_operations",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// The throwaway realm. The id has to satisfy realms.js's pattern — lower case,
// digits and hyphens — so the run stamp is lower-cased rather than used raw.
const REALM = ("adminapi-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

// Where the operations under test are reached. `api` is the throwaway realm's
// door and is what almost everything uses; `rootApi` is the default realm's,
// and is used only for the five realm-registry operations and for the two
// process-wide things this file has to touch.
var api = base + "/realm/" + REALM + "/admin-api";
var rootApi = base + "/admin-api";

// Set by the run so the summary at the end can say what it actually proved
// about the store rather than implying a mode it did not meet.
var persistenceMode = "unknown";

// ---------------------------------------------------------------------------
// A refusal is "about the shape" when it is telling the caller which FIELD to
// send. Those are the sentences the mock writes when the body did not carry the
// identifier the handler reads — which, for a body copied verbatim out of the
// service's own OpenAPI document, can only mean the document and the handler
// disagree about the field's name.
//
// It is deliberately a small set of literal openings rather than a guess at
// intent: a refusal about the REFERENT ("there is no application called x") is
// legitimate, common, and must not be caught here, and the two read alike to
// anything cleverer than a prefix match.
// ---------------------------------------------------------------------------
const SHAPE_REFUSALS = [
  /^Which\b/,          // "Which application? Send `application` with …"
  /^Name the\b/,       // "Name the relationship by its id, in `id`."
  /^A value is required/,
  /^Send\b/
];

function isShapeRefusal(message) {
  const text = String(message || "");
  return SHAPE_REFUSALS.some(function (pattern) { return pattern.test(text); });
}

// The number words the mock's refusal sentences use to count their own lists.
// It writes "The six are: …" rather than "The 6 are: …" almost everywhere, and
// `common/claim_attributes.js` writes the digit — so both spellings are read.
const NUMBER_WORDS = {
  one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8,
  nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14,
  fifteen: 15
};

function wordToNumber(word) {
  const key = String(word || "").toLowerCase();
  if (Object.prototype.hasOwnProperty.call(NUMBER_WORDS, key)) {
    return NUMBER_WORDS[key];
  }
  if (/^\d+$/.test(key)) {
    return Number(key);
  }
  return null;
}

// A list the mock wrote for a person to read, back into an array. It spells
// them two ways and both are ordinary English: "create, set, add, forget" for
// four or more, and "grant and revoke" for two — so a splitter that knew only
// about commas would read the second as one item called "grant and revoke",
// which is a check that then passes for the wrong reason on every two-action
// resource in the API.
function splitList(text) {
  return String(text || "")
      .split(/,\s*|\s+and\s+/)
      .map(function (one) { return one.trim(); })
      .filter(Boolean);
}

// ---------------------------------------------------------------------------
// THE LEDGER: WHAT THIS FILE ACTUALLY DROVE, AND THE TWO THINGS IT IS ASKED AT
// THE END OF THE RUN.
//
// Both questions exist because of one weakness, and it is a weakness of the
// WALKS below rather than of the service. They are driven off the document —
// every GET in it, and every POST that carries an example — so an operation
// that arrives with NO example and no section of its own is driven by nothing
// and reported by nothing. Six POST operations already carry no example, which
// is exactly the shape of the hole, and the only guard against a seventh was a
// floor ("more than sixty examples were found") that a seventh would pass.
//
//   * **EVERY DOCUMENTED OPERATION WAS DRIVEN.** Read off the document at the
//     end of the run against the paths this file really called. An exemption is
//     A ROW IN A TABLE WITH A REASON IN IT, so that "not covered here" is a
//     sentence somebody wrote rather than an absence nobody can see — and the
//     rows are themselves checked against the document, because a row left
//     behind after an operation is renamed turns a check off silently.
//   * **EVERY ACCEPTED WRITE WAS READ BACK.** A POST that answered 200 must be
//     followed, before the run ends, by a GET of the resource it wrote: the
//     `/applications/create` by a `/applications`, the `/spiffe/entries/update`
//     by a `/spiffe/entries`. It is the structural half of the round-trip rule
//     this file already keeps by hand — a handler that answers `{ok: true}` and
//     changes nothing passes every other check here, and the assertion that
//     would have caught it is the one somebody forgot to write.
//
// The pairing is by RESOURCE and by SCOPE, and the scope half is not
// decoration: a write made at the root and read back under the realm prefix is
// a read of a different store, which is the exact defect
// theConfigurationDoorsRoundTrip() exists to catch.
//
// What it deliberately does NOT assert is the reverse direction — that every
// path this file drove is in the document. The probes below post to
// `/<resource>/__no_such_action__` on purpose, and console/API parity is
// tests/admin_api.js's question, asked against the console rather than against
// this file's own call list.
// ---------------------------------------------------------------------------
const ledger = [];

// Every call this file makes, in order. The sequence number is what makes
// "read back AFTERWARDS" a checkable claim — a read that happened before the
// write is not evidence about the write — and the query string is dropped
// because `/logout?user=x` and `/logout` are one resource read two ways.
function record(method, path, root, accepted) {
  ledger.push({ method: method, path: String(path).split("?")[0],
                scope: root ? "root" : "realm", at: ledger.length + 1,
                accepted: accepted });
}

// ---------------------------------------------------------------------------
// The two verbs. Neither asserts anything about the status: an operation that
// is EXPECTED to refuse is as much a part of this surface as one that is
// expected to succeed, so the caller decides.
// ---------------------------------------------------------------------------
async function get(path, root) {
  log.debug("Entering get(). path=" + path);
  const r = await common.httpJson((root ? rootApi : api) + path);
  record("GET", path, root, r.status === 200);
  log.debug("Leaving get(). status=" + r.status);
  return r;
}

async function post(path, body, root) {
  log.debug("Entering post(). path=" + path);
  const r = await common.httpJson((root ? rootApi : api) + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  // A refusal is DRIVEN but not ACCEPTED: it changed nothing, so there is
  // nothing for a read to confirm, and requiring one would push this file into
  // reading a resource after every probe it makes.
  record("POST", path, root,
         r.status === 200 && !!r.body && r.body.ok !== false);
  log.debug("Leaving post(). status=" + r.status);
  return r;
}

// A POST that must succeed. The failure message carries the errors the service
// returned rather than the status alone, because every refusal here is a
// sentence written for a person and quoting it is most of the diagnosis.
async function ok(path, body, what, root) {
  log.debug("Entering ok(). path=" + path);
  const r = await post(path, body, root);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + path + " should have " + what + "; it answered " + r.status +
    " " + JSON.stringify((r.body && r.body.errors) || r.body).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// A POST that must be REFUSED, and refused for a stated reason. `expect` is a
// regular expression against the joined errors: a 400 is not on its own
// evidence that the refusal was the intended one, and a check that accepted any
// 400 would pass against a handler that had started refusing everything.
async function refused(path, body, expect, what, root) {
  log.debug("Entering refused(). path=" + path);
  const r = await post(path, body, root);
  const errors = ((r.body && r.body.errors) || []).join(" | ");
  assert.strictEqual(r.status, 400,
    "POST " + path + " should refuse " + what + " with 400; it answered " +
    r.status + " " + JSON.stringify(r.body).slice(0, 300));
  assert.ok(expect.test(errors),
    "POST " + path + " refused " + what + ", which is right, but the reason " +
    "should match " + expect + " so that a caller can tell WHICH refusal it " +
    "met. It said: " + errors);
  log.debug("Leaving refused().");
  return r.body;
}

// ---------------------------------------------------------------------------
// THE SERVICE, AND WHY A MISSING ONE IS A SKIP AND A STALE ONE IS A FAILURE.
//
// Nothing listening is an ordinary state: half the jobs in this suite run
// against walt.id or a static deployment with no mock at all. A service that
// ANSWERS and has no /admin-api on it is not — it is the parent project's `sts`
// gitlink pinned at a commit older than the feature, and a skip there would
// report a hundred and thirty operations green having driven none of them.
// That is the rule tests/CLAUDE.md states and tests/sts_saml11.js already
// follows.
// ---------------------------------------------------------------------------
async function theServiceIsThere() {
  log.debug("Entering theServiceIsThere().");
  let reply;
  try {
    reply = await common.httpJson(rootApi + "/status");
  } catch (e) {
    log.warn("No STS is listening at " + base + " (" + e.message + "). " +
             "Skipping: this job needs the mock and nothing else.");
    log.debug("Leaving theServiceIsThere(). Nothing listening.");
    return false;
  }
  assert.strictEqual(reply.status, 200,
    "GET " + rootApi + "/status answered " + reply.status + ". A service is " +
    "listening at " + base + " and has no management API on it, which is " +
    "almost always the parent project's `sts` submodule pinned at a commit " +
    "older than /admin-api. This is a FAILURE and not a skip: a skip here " +
    "reports this API's whole surface green having driven none of it.");
  assert.ok(Array.isArray(reply.body.pages) && reply.body.pages.length > 20,
    "the status reply should carry the console's page list; got " +
    JSON.stringify(reply.body.pages));
  log.info("[service] OK — " + base + " answers, with " +
           reply.body.pages.length + " console pages behind it.");
  log.debug("Leaving theServiceIsThere(). It is there.");
  return true;
}

// ---------------------------------------------------------------------------
// THE THROWAWAY REALM, and the three properties of the realm registry that are
// asserted while making it. Those five operations are the only ones in this API
// that are NOT realm-scoped — there is one registry for the process — so they
// are exercised here, at the root, rather than inside the realm they create.
// ---------------------------------------------------------------------------
async function theRealmRegistryWorks() {
  log.debug("Entering theRealmRegistryWorks().");
  log.info("=== The realm registry (create, update, set, unset) ===");
  const before = await get("/realms", true);
  assert.strictEqual(before.status, 200, "GET /admin-api/realms should answer 200.");
  assert.strictEqual(before.body.current, "default",
    "called at the root, the realm registry should say the call arrived in " +
    "the default realm; it said " + before.body.current + ". `current` is " +
    "the one member of this reply that differs per prefix and it is what a " +
    "caller uses to know which service it is talking to.");
  const existing = (before.body.realms || []).map(function (r) { return r.id; });
  assert.ok(existing.indexOf(REALM) < 0,
    "the realm " + REALM + " should not already exist — the id carries this " +
    "run's stamp so that two concurrent runs cannot collide. Found: " +
    existing.join(", "));

  // createRealm's `overrides` is the property mgmt-api/CLAUDE.md records as
  // having been documented, exampled, validated by realms.create() and DROPPED
  // by the shared action function in between, for months. It is asserted on the
  // way in for that reason: a create that answers 200 and produces a realm
  // configured differently from the one asked for is the exact defect.
  const created = await ok("/realms/create", {
    id: REALM,
    name: "Management API operations test",
    description: "Created by tests/sts_admin_api_operations.js; removed at the end.",
    overrides: { "saml2.entityId": "urn:test:" + REALM + ":idp" }
  }, "created the throwaway realm", true);
  assert.strictEqual(created.realm, REALM,
    "the create should name the realm it made.");

  const row = await realmRow();
  assert.ok(row, "the realm should be in GET /admin-api/realms after being created.");
  assert.strictEqual(row.name, "Management API operations test",
    "the create's `name` should be on the row; it says " + row.name);
  assert.strictEqual(realmSetting(row, "saml2.entityId"),
    "urn:test:" + REALM + ":idp",
    "THE `overrides` FIELD OF createRealm MUST REACH THE REALM. It is " +
    "documented, exampled and validated, and the shared realmsAction() " +
    "dropped it for months while answering 200 — mgmt-api/CLAUDE.md records " +
    "that as the case its parity rule cannot catch, because the console's " +
    "form has no such field for the API to disagree with. The row's " +
    "overrides are " + JSON.stringify(row.overrides));

  // And the setting really is in force under the realm's prefix — the row
  // carrying it is the registry's account of itself, which is the thing the
  // defect above was consistent with.
  const config = await get("/config");
  assert.strictEqual(config.status, 200,
    "GET " + api + "/config should answer 200 inside the new realm.");
  assert.strictEqual(config.body.realm, REALM,
    "the configuration read under /realm/" + REALM + " should say it is that " +
    "realm's; it said " + config.body.realm);
  assert.strictEqual(settingValue(config.body, "saml2.entityId"),
    "urn:test:" + REALM + ":idp",
    "and the override the realm was created with should be the effective " +
    "value of saml2.entityId inside it.");

  await ok("/realms/update", { id: REALM, description: "Updated by the test." },
    "updated the realm", true);
  assert.strictEqual((await realmRow()).description, "Updated by the test.",
    "`update` should change the description on the row.");

  await ok("/realms/set", { id: REALM, key: "saml.issuer",
                            value: "urn:test:" + REALM + ":issuer" },
    "set a realm setting", true);
  assert.strictEqual(realmSetting(await realmRow(), "saml.issuer"),
    "urn:test:" + REALM + ":issuer",
    "`set` should put the value on the realm's own settings.");

  await ok("/realms/unset", { id: REALM, key: "saml.issuer" },
    "unset a realm setting", true);
  // `unset` puts the SEEDED value back rather than removing the row: six
  // settings are seeded onto every realm at create time, because a realm whose
  // issuer was the default realm's would mint assertions the two could not be
  // told apart by. So what must change is the VALUE, not the row's presence.
  assert.notStrictEqual(realmSetting(await realmRow(), "saml.issuer"),
    "urn:test:" + REALM + ":issuer",
    "`unset` should take the value this test set back off the realm; it is " +
    "still there.");

  // The one refusal the registry has that nothing else does, and it is a real
  // one rather than a validation: removing the realm the CALL arrived in would
  // leave the caller talking to a prefix that had stopped existing.
  await refused("/realms/remove", { id: REALM },
    /current|the realm this|arrived|talking/i,
    "removing the realm the call arrived in");

  log.info("[realms] OK — created " + REALM + ", its create-time overrides " +
           "reached it, update/set/unset round-tripped, and `remove` refuses " +
           "the realm it is called in.");
  log.debug("Leaving theRealmRegistryWorks().");
}

// The throwaway realm's row in the registry, read fresh each time.
async function realmRow() {
  log.debug("Entering realmRow().");
  const listed = await get("/realms", true);
  const row = (listed.body.realms || []).filter(function (r) {
    return r.id === REALM;
  })[0];
  log.debug("Leaving realmRow(). " + (row ? "found" : "absent"));
  return row;
}

// One setting off a realm's registry row. The row carries `settings` — a list
// of {key, value} — rather than the `overrides` object the create takes, and
// the two are deliberately different shapes: the create is told what to
// override and the row reports what the realm ACTUALLY carries, which is those
// overrides plus the six seeded onto every realm so that two realms cannot
// mint assertions their audiences could not tell apart.
function realmSetting(row, key) {
  const one = ((row && row.settings) || []).filter(function (setting) {
    return setting && setting.key === key;
  })[0];
  return one ? one.value : undefined;
}

// The effective value of one setting, out of the grouped /config reply. The
// document groups the settings, so a caller looking for one has to walk two
// levels — which is worth a function rather than four copies.
function settingValue(config, key) {
  log.debug("Entering settingValue(). key=" + key);
  let found;
  (config.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      if (setting.key === key) {
        found = setting;
      }
    });
  });
  log.debug("Leaving settingValue().");
  return found ? found.value : undefined;
}

function settingRow(config, key) {
  let found;
  (config.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      if (setting.key === key) {
        found = setting;
      }
    });
  });
  return found;
}

// ---------------------------------------------------------------------------
// THE REFUSAL SENTENCES, BOTH WAYS ROUND.
//
// Every action handler answers an unknown action by naming the ones it knows.
// That sentence is not documentation — tests/admin_api.js READS it to check
// that every console action has an API operation — so it is load-bearing, and a
// sentence that is short by one action narrows the only check that would have
// noticed the missing operation.
//
// Two assertions, and they fail on different things:
//
//   * THE COUNT MATCHES THE LIST. "The six are:" over a list of seven is a
//     sentence that was edited at one end. It is the cheapest possible signal
//     that an action was added and the prose beside it was not, and it costs
//     nothing to check.
//   * THE LIST MATCHES THE DOCUMENT. The operations under a resource are
//     generated from the table that registers them, so the document is the
//     handler's real repertoire; the sentence is a second copy of it, written
//     by hand. Every documented action must be in the sentence, and every
//     action in the sentence must be documented.
//
// The probe bodies matter, and admin_api.js already learnt why: the three claim
// set doors validate their `set` BEFORE they look at the action, so a probe
// with an empty body comes back naming the claim SETS in a sentence of exactly
// this shape. Each probe therefore carries whatever that door needs to reach
// its own switch, and the value is read off the service — the sets each door
// carries are in its own GET — rather than typed here.
// ---------------------------------------------------------------------------
async function theRefusalSentencesAreHonest(doc) {
  log.debug("Entering theRefusalSentencesAreHonest().");
  log.info("=== The refusal sentences (count, and against the document) ===");

  // resource -> the extra fields a probe needs to get past the validation that
  // happens before the action switch. Read off the service where it can be.
  const claimSets = await claimSetIdsPerDoor();
  const probes = {
    "claims": { set: claimSets["claims"] },
    "saml-attributes": { set: claimSets["saml-attributes"] },
    "userinfo-claims": { set: claimSets["userinfo-claims"] },
    "federation": { id: "no-such-relationship" },
    "saml2": { sp: "urn:no:such:sp" },
    "saml11": { rp: "urn:no:such:rp" },
    "logout": { user: "nobody-at-all" }
  };

  const documented = documentedActions(doc);
  const resources = Object.keys(documented).sort();
  assert.ok(resources.length > 15,
    "the document should declare POST operations under more than fifteen " +
    "resources; it declares " + resources.length + ". A collapse here means " +
    "the walk below is asserting almost nothing.");

  for (const resource of resources) {
    const body = Object.assign({ }, probes[resource] || {});
    const reply = await post("/" + resource + "/__no_such_action__", body);
    const errors = ((reply.body && reply.body.errors) || []).join(" ");
    assert.strictEqual(reply.status, 400,
      "POST /" + resource + "/__no_such_action__ should be refused 400; it " +
      "answered " + reply.status + " " + JSON.stringify(reply.body).slice(0, 200));
    // THREE PHRASINGS, one sentence. The mock writes "The six are: …" on most
    // resources, "There are two: …" where two reads better, and "The actions
    // here are: …" on the three SPIFFE ones — all ordinary English, and all
    // read here, because the requirement is that the sentence NAMES the
    // actions and not that every handler spells the naming the same way.
    // What is asserted is the naming and the count, in that order.
    const sentence = errors.match(
      /Unknown action "[^"]*"\.\s*([^:]*):\s*([^.]+)\./);
    assert.ok(sentence,
      "the refusal from /" + resource + " must NAME the actions it knows. " +
      "tests/admin_api.js reads exactly that sentence to check that every " +
      "console action has an operation here, so a handler that stopped " +
      "writing it would turn that check off with nothing failing. It said: " +
      errors);

    const listed = splitList(sentence[2]);
    // The count, when the sentence carries one: "The six are", "There are
    // two". "The actions here are" carries none, and a resource is entitled to
    // write it that way — so the count check is made where there is a count
    // and the list check is made everywhere.
    const counted = String(sentence[1] || "")
        .match(/\bThe\s+(\S+)\s+are\b|\bThere\s+(?:are|is)\s+(\S+)/);
    const claimed = counted ? wordToNumber(counted[1] || counted[2]) : null;
    if (claimed !== null) {
      assert.strictEqual(listed.length, claimed,
        "/" + resource + " says it has " + claimed + " actions and then " +
        "lists " + listed.length + " of them (" + listed.join(", ") + "). A " +
        "sentence edited at one end is the cheapest available signal that an " +
        "action was added and the prose beside it was not — and this " +
        "sentence is what the parity check reads.");
    }

    const declared = documented[resource].slice().sort();
    const said = listed.slice().sort();
    assert.deepStrictEqual(said, declared,
      "the actions /" + resource + " NAMES in its refusal must be exactly " +
      "the ones the OpenAPI document declares for it. The document is " +
      "generated from the table that registers the routes, so it is the real " +
      "repertoire; the sentence is a hand-written second copy, and this is " +
      "where the two are compared.\n" +
      "  the sentence says: " + said.join(", ") + "\n" +
      "  the document says: " + declared.join(", ") + "\n" +
      "An action in the document and not in the sentence is INVISIBLE to " +
      "tests/admin_api.js's parity check, which reads the sentence: the " +
      "console could lose the operation entirely and nothing would fail.");
    log.debug("[refusals] /" + resource + ": " + listed.length + " action(s).");
  }
  log.info("[refusals] OK — all " + resources.length + " action resources " +
           "name their actions, count them correctly, and agree with the " +
           "document.");
  log.debug("Leaving theRefusalSentencesAreHonest().");
}

// The claim set ids each of the three claim-set doors carries, read off the
// service. They are the same seven actions over different sets, and a probe
// naming a set the door does not carry never reaches the action switch.
async function claimSetIdsPerDoor() {
  log.debug("Entering claimSetIdsPerDoor().");
  const out = {};
  for (const resource of ["claims", "saml-attributes", "userinfo-claims"]) {
    const probe = await post("/" + resource + "/__no_such_action__", { set: "" });
    const errors = ((probe.body && probe.body.errors) || []).join(" ");
    const carried = errors.match(/(?:carries|carry|are)\s*(?:are)?:\s*([^.]+)\./);
    const first = carried ? carried[1].split(",")[0].trim() : "";
    assert.ok(first,
      "/" + resource + " asked with no `set` should name the sets it " +
      "carries, so that this file does not have to hold a second copy of " +
      "them. It said: " + errors);
    out[resource] = first;
    log.debug("[claim sets] /" + resource + " carries " + carried[1].trim());
  }
  log.debug("Leaving claimSetIdsPerDoor().");
  return out;
}

// resource -> [action, …], read out of the OpenAPI document. A path here is
// always /admin-api/<resource…>/<action>, and the resource may have two
// segments (spiffe/entries, spiffe/agents), so the action is the last one and
// the resource is everything before it.
function documentedActions(doc) {
  log.debug("Entering documentedActions().");
  const out = {};
  Object.keys(doc.paths).forEach(function (path) {
    if (!doc.paths[path].post) {
      return;
    }
    const parts = path.replace(/^\/admin-api\//, "").split("/");
    const action = parts.pop();
    const resource = parts.join("/");
    if (!resource) {
      return;
    }
    out[resource] = out[resource] || [];
    out[resource].push(action);
  });
  log.debug("Leaving documentedActions(). " + Object.keys(out).length + " resource(s).");
  return out;
}

// ---------------------------------------------------------------------------
// THE DOCUMENTED EXAMPLE, REPLAYED.
//
// All but six of the POST operations carry an example body in their request
// schema, and that example is the first thing a caller copies. Sending
// it is therefore the cheapest possible test of the one thing this API's
// generated document CANNOT check about itself: the document is generated from
// the table that registers the routes, so an operation cannot be undocumented —
// but the request BODY in that table is prose typed beside the row, and nothing
// compares it with the fields the handler actually reads.
//
// mgmt-api/CLAUDE.md names this defect class and records one that survived for
// months: `createRealm` documented an `overrides` property, gave it an example,
// and the shared action function built its argument out of three other fields
// and dropped it — 200 every time, and a realm configured differently from the
// one that was asked for. Its own diagnosis is the reason this check is here:
// *"a documented request property that changes nothing is the same class of
// defect as a documented response property that is never sent"*, and *"what it
// cannot catch is a field the API accepts and the console's form does not
// have, because there is then no second implementation to disagree with."*
//
// WHAT COUNTS AS A FAILURE, AND WHY THE LINE IS WHERE IT IS. An example has to
// name something — an application, a relationship, an agent — and naming
// something that does not exist here is not a defect in the example. So a
// refusal about the REFERENT is allowed and counted. A refusal about the SHAPE
// is not: "Which application? Send `application` with…" in reply to a body the
// service itself published means the document named a field the handler does
// not read, and a caller following the document gets 400 for ever.
//
// THREE RESOURCES ARE HELD BACK, each because its example escapes the
// throwaway realm this job cleans up by removing:
//
//   * `realms/*`   — the registry is process-wide; the five operations are
//                    exercised in theRealmRegistryWorks() against a realm this
//                    file owns, rather than against the example's `acme`.
//   * `rbac/*`     — the two console roles are groups in the DEFAULT realm by
//                    design, read there from every realm, so a grant made here
//                    would close the console's roster for every other job.
//                    Exercised explicitly, and revoked, below.
//   * `spiffe/rotate` — it replaces the signing authority for the whole
//                    process and has no opposite. Exercised once, deliberately,
//                    in the SPIFFE section.
// ---------------------------------------------------------------------------
const REPLAY_HELD_BACK = [/^\/realms\//, /^\/rbac\//, /^\/spiffe\/rotate$/];

async function everyDocumentedExampleIsAccepted(doc) {
  log.debug("Entering everyDocumentedExampleIsAccepted().");
  log.info("=== Every documented example body, replayed ===");
  const rows = [];
  Object.keys(doc.paths).forEach(function (path) {
    const operation = doc.paths[path].post;
    if (!operation) {
      return;
    }
    const relative = path.replace(/^\/admin-api/, "");
    if (REPLAY_HELD_BACK.some(function (p) { return p.test(relative); })) {
      return;
    }
    const schema = operation.requestBody &&
        operation.requestBody.content &&
        operation.requestBody.content["application/json"] &&
        operation.requestBody.content["application/json"].schema;
    const example = schema && Array.isArray(schema.examples) && schema.examples[0];
    if (!example) {
      return;
    }
    rows.push({ path: relative, example: example,
                operationId: operation.operationId });
  });

  assert.ok(rows.length > 60,
    "the document should carry an example body for most of its POST " +
    "operations; only " + rows.length + " were found. Either the examples " +
    "have gone or this walk is reading the schema in the wrong place, and " +
    "both make the check below vacuous.");

  const shapeFailures = [];
  let accepted = 0;
  let referent = 0;
  for (const row of rows) {
    const reply = await post(row.path, row.example);
    const errors = (reply.body && reply.body.errors) || [];
    if (reply.status === 200 && reply.body && reply.body.ok !== false) {
      accepted++;
      await theResourceReadsBack(row.path, row.operationId);
      continue;
    }
    const shaped = errors.filter(isShapeRefusal);
    if (shaped.length) {
      shapeFailures.push(row.operationId + " (POST " + row.path + "): " +
                         shaped.join(" | ") + "  — example was " +
                         JSON.stringify(row.example));
      continue;
    }
    assert.ok(reply.status === 400 && errors.length,
      "POST " + row.path + ", sent the document's own example, answered " +
      reply.status + " with no `errors` array: " +
      JSON.stringify(reply.body).slice(0, 300) + ". Every refusal on this " +
      "API carries `errors`, because a status alone is not something a " +
      "caller can act on.");
    referent++;
    log.debug("[example] " + row.operationId + " refused about its referent: " +
              errors.join(" | ").slice(0, 160));
  }

  assert.deepStrictEqual(shapeFailures, [],
    "THESE OPERATIONS REFUSED THEIR OWN DOCUMENTED EXAMPLE, AND REFUSED IT " +
    "FOR A REASON ABOUT THE SHAPE OF THE REQUEST — which means the OpenAPI " +
    "document names a property the handler does not read, and every caller " +
    "that copies the example gets 400 for ever:\n  " +
    shapeFailures.join("\n  "));

  log.info("[examples] OK — " + rows.length + " documented examples replayed: " +
           accepted + " accepted outright and read back through their own " +
           "resource, " + referent + " refused about a referent they name and " +
           "this service does not hold, none refused about the shape of the " +
           "body.");
  log.debug("Leaving everyDocumentedExampleIsAccepted().");
}

// ---------------------------------------------------------------------------
// THE READ BESIDE THE WRITE, for the sweep above.
//
// What it can assert is narrower than what the round-trip sections assert — a
// walk driven off the document has no idea what any particular example MEANT —
// but it is not nothing, and it is the half that generalises to an operation
// nobody has written a section for: the resource a write landed on must still
// answer, and must still answer JSON. This is the only place in the run where
// every resource is read IMMEDIATELY after being written to, so a handler that
// stores something its own listing then throws on is caught here rather than
// by the next person to load the page.
//
// Its other job is to keep this sweep inside the rule the whole file follows —
// a write is never believed on its own account. everyAcceptedWriteWasReadBack()
// is the enforcement of that rule, and this call is how the sixty-odd writes
// made here satisfy it.
// ---------------------------------------------------------------------------
async function theResourceReadsBack(path, operationId) {
  log.debug("Entering theResourceReadsBack(). path=" + path);
  const resource = path.split("/").slice(0, -1).join("/");
  const reply = await get(resource);
  assert.strictEqual(reply.status, 200,
    operationId + " accepted the document's own example, and GET " + api +
    resource + " — the read operation on the resource it just wrote — then " +
    "answered " + reply.status + " " + String(reply.raw).slice(0, 200) +
    ". A write that leaves its own resource unreadable is a 500 nobody meets " +
    "until the next page load.");
  assert.strictEqual(typeof reply.body, "object",
    operationId + " wrote " + resource + " and that resource then stopped " +
    "answering JSON: httpJson gave back " + typeof reply.body + " — " +
    String(reply.raw).slice(0, 200));
  log.debug("Leaving theResourceReadsBack().");
}

// ---------------------------------------------------------------------------
// EVERY GET ANSWERS, AND ANSWERS ABOUT THIS REALM.
//
// Fifty-odd read operations, walked from the document. Two things are asserted
// beyond the status, and the second is the one that matters: the reply must be
// an OBJECT rather than the HTML of a redirect or an error page — `httpJson`
// hands back the raw text when it cannot parse, and a string body is how a
// route that quietly stopped being JSON would look — and every resource that
// names a container DN must name THIS REALM'S, because the whole claim of the
// path prefix is that every one of these operations already works per realm
// without any of them having been edited.
// ---------------------------------------------------------------------------
async function everyReadAnswersAboutThisRealm(doc) {
  log.debug("Entering everyReadAnswersAboutThisRealm().");
  log.info("=== Every read operation, under the realm prefix ===");
  const paths = Object.keys(doc.paths).filter(function (path) {
    return !!doc.paths[path].get;
  }).map(function (path) {
    return path.replace(/^\/admin-api/, "");
  });
  assert.ok(paths.length > 30,
    "the document should declare more than thirty read operations; it " +
    "declares " + paths.length);

  let withContainer = 0;
  for (const path of paths) {
    // The two documentation routes answer HTML and JavaScript rather than
    // JSON, on purpose — they are the explorer. They are asserted by
    // tests/admin_api.js, which owns the CSP half of them.
    if (path === "/docs" || path === "/docs/explorer.js") {
      continue;
    }
    const reply = await get(path);
    assert.strictEqual(reply.status, 200,
      "GET " + api + path + " should answer 200; it answered " + reply.status +
      " " + String(reply.raw).slice(0, 200));
    assert.strictEqual(typeof reply.body, "object",
      "GET " + api + path + " should answer a JSON object. It answered " +
      typeof reply.body + ": " + String(reply.raw).slice(0, 200) + ". A " +
      "string body here is httpJson reporting that it could not parse the " +
      "reply, which is what a route that started returning HTML looks like.");
    const container = String(reply.body.container || reply.body.groupsDn || "");
    // ou=groups and ou=users on /rbac are DELIBERATELY the default realm's —
    // the two console roles are one roster for the process — so that resource
    // is the one exception and it is asserted the other way round below.
    if (container && path !== "/rbac" && /dc=/.test(container)) {
      assert.ok(container.indexOf("dc=" + REALM + ",") >= 0,
        "GET " + path + " names the container " + container + ", which is " +
        "not this realm's. Every store behind this API is per realm — that " +
        "is what makes /realm/<id>/admin-api a copy of the service rather " +
        "than a second view of one — so a container naming dc=example,dc=com " +
        "from inside " + REALM + " is a store that was left process-wide.");
      withContainer++;
    }
  }
  log.info("[reads] OK — " + (paths.length - 2) + " read operations answered " +
           "200 with a JSON object, and the " + withContainer + " that name a " +
           "directory container all named " + REALM + "'s.");
  log.debug("Leaving everyReadAnswersAboutThisRealm().");
}

// ---------------------------------------------------------------------------
// THE APPLICATIONS REGISTRY: all seven actions, each read back through the
// resource's own GET rather than believed off the write's reply.
//
// The two closed vocabularies this resource validates against are published by
// GET /applications/new for exactly this reason — a caller that reads them
// cannot construct a create the service will refuse — so they are read off the
// service and used, rather than typed here. That also makes the count check
// below possible, which is the one that has something to catch: the refusal
// names the kinds it knows AND says how many there are, in prose, and the two
// are edited independently.
// ---------------------------------------------------------------------------
async function theApplicationsRegistryRoundTrips() {
  log.debug("Entering theApplicationsRegistryRoundTrips().");
  log.info("=== Applications: create, set, add, remove, revoke-registration, " +
           "refresh-metadata, forget ===");
  const form = await get("/applications/new");
  assert.strictEqual(form.status, 200, "GET /applications/new should answer 200.");
  const kinds = (form.body.kinds || []).map(function (k) {
    return typeof k === "string" ? k : k.kind;
  });
  const families = (form.body.protocols || []).map(function (p) {
    return typeof p === "string" ? p : p.id;
  });
  assert.ok(kinds.length && families.length,
    "GET /applications/new should publish the kinds and the protocol " +
    "families a create is validated against; it published " +
    kinds.length + " and " + families.length + ".");
  assert.strictEqual(form.body.container,
    "ou=applications,dc=" + REALM + ",dc=example,dc=com",
    "and it should name THIS realm's container, since that is where a create " +
    "made through this prefix lands; it named " + form.body.container);

  // The kinds refusal counts its own list, and the two halves of that sentence
  // are edited independently — a ninth kind added to the table with the word
  // "eight" left beside it is a sentence that is wrong about the thing it
  // exists to explain.
  const badKind = await refused("/applications/create",
    { identifier: "kind-probe-" + REALM, kind: "no-such-kind" },
    /is not one of the kinds/, "an unknown kind");
  const kindSentence = (badKind.errors || []).join(" ")
      .match(/The\s+(\S+)\s+are:\s*([^.]+)\./);
  assert.ok(kindSentence,
    "the unknown-kind refusal should name the kinds it knows; it said " +
    (badKind.errors || []).join(" "));
  const kindsNamed = splitList(kindSentence[2]);
  assert.deepStrictEqual(kindsNamed.slice().sort(), kinds.slice().sort(),
    "the kinds the refusal names must be the kinds GET /applications/new " +
    "publishes — they are one table read through two doors.");
  assert.strictEqual(kindsNamed.length, wordToNumber(kindSentence[1]),
    "the unknown-kind refusal says there are " + kindSentence[1] + " kinds " +
    "and then lists " + kindsNamed.length + " of them: " +
    kindsNamed.join(", ") + ". The count is written into the sentence by " +
    "hand and the list is generated from the table, so they part company the " +
    "day a kind is added — which is the day the sentence is most likely to " +
    "be read.");

  const identifier = "app-" + names.usernameFor("stsapi-app");
  const created = await ok("/applications/create", {
    identifier: identifier,
    name: "Management API operations test",
    kind: kinds[0],
    protocols: [families[0]]
  }, "created an application");
  assert.ok(created.application && created.application.dn,
    "the create should answer with the entry it made, DN and all.");
  assert.ok(created.application.dn.indexOf("dc=" + REALM + ",") > 0,
    "and that entry should be in this realm's subtree; its DN is " +
    created.application.dn);

  assert.strictEqual((await application(identifier)).found, true,
    "and the entry should be findable through the registry's own read " +
    "operation immediately, rather than only in the create's account of " +
    "itself: every other assertion in this section reads through " +
    "GET /applications?application=…, so this is where that read is first " +
    "shown to see what the write made.");

  // An identifier names ONE application whatever protocol brought it, so a
  // second create is refused rather than merged. That refusal is what
  // tests/sts_applications.js reconciles against, so it is load-bearing
  // elsewhere in this suite.
  await refused("/applications/create", { identifier: identifier },
    /already/i, "a duplicate identifier");

  // set / add / remove, each confirmed by reading the ENTRY back. The
  // attributes are read off the service's own `editable` table: which
  // attributes take `set` and which take `add` is a fact about the mock's
  // EDITABLE table, and a copy of it here is the second definition that
  // mgmt-api/CLAUDE.md records going stale.
  const editable = form.body.editable || [];
  const single = editable.filter(function (row) {
    return row.mode === "set" && !row.sensitive;
  })[0];
  // The multi-valued one is taken from `declarations` rather than from
  // `editable`, and specifically from a row whose ROLE is `redirect`: several
  // multi-valued attributes hold a CLOSED VOCABULARY — appAllowedProtocol is
  // the list of declared families and refuses anything outside it — so a walk
  // that took the first multi-valued name it found would be asserting that
  // `add` refuses, which is a different (and already covered) claim. A
  // redirect attribute takes a URI and nothing here judges it.
  const declared = (form.body.declarations || []).filter(function (row) {
    return row.role === "redirect" && row.kind === "multi" && !row.sensitive;
  })[0];
  assert.ok(single && declared,
    "GET /applications/new should publish at least one single-valued " +
    "editable attribute and one multi-valued attribute that takes a free " +
    "value, since `set` and `add` are the two modes this table exists to " +
    "tell apart. It published " + editable.length + " editable rows and " +
    (form.body.declarations || []).length + " declarations.");
  const multi = { name: declared.attribute };

  await ok("/applications/set",
    { application: identifier, attribute: single.name, value: "set-by-the-test" },
    "set " + single.name);
  assert.ok(fieldValues(await application(identifier), single.name)
      .indexOf("set-by-the-test") >= 0,
    "`set` on " + single.name + " should be readable back through GET " +
    "/applications?application=…; the entry says " +
    JSON.stringify(fieldValues(await application(identifier), single.name)));

  await ok("/applications/add",
    { application: identifier, attribute: multi.name, value: "https://one.example/cb" },
    "added a first value to " + multi.name);
  await ok("/applications/add",
    { application: identifier, attribute: multi.name, value: "https://two.example/cb" },
    "added a second value to " + multi.name);
  let values = fieldValues(await application(identifier), multi.name);
  assert.ok(values.indexOf("https://one.example/cb") >= 0 &&
            values.indexOf("https://two.example/cb") >= 0,
    "`add` must ACCUMULATE on a multi-valued attribute rather than assign — " +
    "that is the whole difference between the two modes, and an `add` that " +
    "assigned would pass every single-value check in this file. " +
    multi.name + " holds " + JSON.stringify(values));

  await ok("/applications/remove",
    { application: identifier, attribute: multi.name, value: "https://one.example/cb" },
    "removed one value from " + multi.name);
  values = fieldValues(await application(identifier), multi.name);
  assert.ok(values.indexOf("https://one.example/cb") < 0 &&
            values.indexOf("https://two.example/cb") >= 0,
    "`remove` must take away the ONE value it was given and leave the rest; " +
    multi.name + " now holds " + JSON.stringify(values));

  // A derived attribute is refused BY NAME rather than written. That is the
  // property the `editable` table exists to give the console's two selects —
  // a form cannot offer what the action would refuse — and this is the door
  // that has no form in front of it.
  await refused("/applications/set",
    { application: identifier, attribute: "entryDN", value: "cn=nope" },
    /entryDN/, "a derived attribute");

  // Two refusals that name the referent rather than the field. They are the
  // ones this API answers most often, so their wording is worth pinning: a
  // caller that gets "which application?" when it sent one has a different
  // problem from one whose application is not here.
  await refused("/applications/revoke-registration", { application: identifier },
    /no registration to revoke|has no registration/i,
    "revoking a registration that was never made");
  await refused("/applications/refresh-metadata", { application: identifier },
    /metadata|samlSpMetadataUrl/i,
    "refreshing metadata from an entry that names no metadata URL");

  await ok("/applications/forget", { application: identifier },
    "forgot the application");
  assert.strictEqual((await application(identifier)).found, false,
    "after `forget` the entry must be gone from the registry; it is still there.");

  log.info("[applications] OK — seven actions round-tripped against the " +
           "entry, both refusal vocabularies read off the service, and " +
           "`forget` really removed it.");
  log.debug("Leaving theApplicationsRegistryRoundTrips().");
}

async function application(identifier) {
  log.debug("Entering application(). identifier=" + identifier);
  const reply = await get("/applications?application=" + encodeURIComponent(identifier));
  assert.strictEqual(reply.status, 200,
    "GET /applications?application=… should answer 200 whether or not the " +
    "entry is there; it answered " + reply.status);
  log.debug("Leaving application(). found=" + reply.body.found);
  return reply.body;
}

// One attribute's values off an application entry. The reply is FLAT — the
// entry's members at the top level rather than wrapped in an `application`
// member the way the WRITES answer — which is the shape tests/sts_applications.js
// already relies on.
//
// `attributes` is the WHOLE entry and `fields` beside it is the narrower
// editable subset, so the read goes to `attributes` first: an assertion that
// looked only at `fields` would report an attribute missing whenever the
// editable table narrowed, which is a change to a form and not to the entry.
function fieldValues(entry, attribute) {
  const fields = (entry && (entry.attributes || entry.fields)) || {};
  const held = fields[attribute];
  if (held === undefined || held === null) {
    return [];
  }
  return Array.isArray(held) ? held.map(String) : [String(held)];
}

// ---------------------------------------------------------------------------
// THE THREE CLAIM-SET DOORS: seven actions each, over different sets.
//
// /claims, /saml-attributes and /userinfo-claims are three resources over ONE
// action function, differing only in the set ids each carries — which is what
// makes them a mirror of the three PAGES rather than three models of one store.
// So the walk is one loop over the three doors, driven off each door's own set
// list, and what it asserts is that the seven actions behave the same through
// all three: fourteen operations built by one function is exactly the
// arrangement where six of them can be broken and nobody notices.
//
// THE `attributes` FAMILY IS THE HALF THAT NEEDS THIS MOST. `add`, `remove`,
// `clear` and `replace` write TYPED claims — a name and a literal value — and
// the other three select DIRECTORY ATTRIBUTES to carry into the same set. They
// are stored differently, in different modules, and only one of the two stores
// has ever been read per realm by anything in this suite.
// ---------------------------------------------------------------------------
const CLAIM_DOORS = ["claims", "saml-attributes", "userinfo-claims"];

async function theClaimSetDoorsRoundTrip() {
  log.debug("Entering theClaimSetDoorsRoundTrip().");
  log.info("=== The three claim-set doors: seven actions each ===");
  for (const door of CLAIM_DOORS) {
    const sets = await setsCarriedBy(door);
    assert.ok(sets.length,
      "/" + door + " should carry at least one claim set.");
    for (const set of sets) {
      await oneClaimSetRoundTrips(door, set);
    }
    log.info("[" + door + "] OK — seven actions over " + sets.length +
             " set(s): " + sets.join(", "));
  }
  await aClaimSetBelongsToItsRealm();
  log.debug("Leaving theClaimSetDoorsRoundTrip().");
}

// ---------------------------------------------------------------------------
// A CLAIM CONFIGURED IN ONE REALM MUST NOT BE CARRIED BY ANOTHER REALM'S
// TOKENS, and this is the assertion that says so from outside the process.
//
// It was not true until 2026-08-28. `CLAIM_SETS` in common/admin_stats.js was
// a plain object — one table for the process — so a custom claim added at
// /realm/acme/admin/claims was added to every realm's tokens at once, the
// DEFAULT realm's included, while each realm's console showed it as that
// realm's own configuration. The OTHER HALF of the same claim set was already
// per realm (the directory attributes, in common/claim_attributes.js), so one
// claim set disagreed with itself about whether it belonged to a realm.
//
// It is asserted HERE rather than by reading the two consoles, because the
// console reading the same table twice is exactly what the defect looked like
// from the console. What settles it is a TOKEN: mint one in each realm and
// look at what is in it.
// ---------------------------------------------------------------------------
async function aClaimSetBelongsToItsRealm() {
  log.debug("Entering aClaimSetBelongsToItsRealm().");
  log.info("=== A claim set belongs to the realm it was configured in ===");
  const claim = "only_in_" + REALM.replace(/-/g, "_");
  await ok("/claims/add",
    { set: "access_token", name: claim, value: "yes" },
    "added a custom claim in " + REALM);
  assert.strictEqual(typedClaim(await claimSet("claims", "access_token"), claim),
    "yes",
    "the claim should be readable back through this realm's own /claims " +
    "before anything is minted — the token below says what the SIGNER did " +
    "with it, and this says what the CONSOLE holds, which are the two halves " +
    "that disagreed while CLAIM_SETS was one table for the process.");

  const mine = await mintTokens(names.usernameFor("stsapi-claimrealm"),
                                "claim-realm-client-" + REALM);
  assert.strictEqual(claimOf(mine.access, claim), "yes",
    "the claim should be in a token minted BY THE REALM IT WAS CONFIGURED IN.");

  // The default realm's own token endpoint, which nothing in this section
  // configured.
  const elsewhere = await common.httpJson(base + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=password&username=" +
        encodeURIComponent(names.usernameFor("stsapi-elsewhere")) +
        "&password=x&client_id=claim-realm-elsewhere&scope=openid"
  });
  assert.strictEqual(elsewhere.status, 200,
    "the default realm's token endpoint should still mint a token; it " +
    "answered " + elsewhere.status);
  assert.strictEqual(claimOf(elsewhere.body.access_token, claim), "",
    "A CUSTOM CLAIM CONFIGURED IN " + REALM + " MUST NOT BE IN THE DEFAULT " +
    "REALM'S TOKENS. A trust realm is a whole logical copy of this service " +
    "with its own configuration — that is the entire claim the feature " +
    "makes — so a claim set held once for the process is configuration " +
    "leaking between realms in the artefact that matters most. The default " +
    "realm's access token carries " + claim + "=" +
    JSON.stringify(claimOf(elsewhere.body.access_token, claim)));

  // And the default realm's console must not SHOW it either, which is the
  // half an operator would notice.
  const theirs = await get("/claims", true);
  const names_ = ((theirs.body.sets || []).filter(function (row) {
    return row.id === "access_token";
  })[0] || {}).claims || [];
  assert.ok(!names_.some(function (row) { return row.name === claim; }),
    "and the default realm's /admin-api/claims must not list it; it lists " +
    JSON.stringify(names_.map(function (row) { return row.name; })));

  await ok("/claims/remove", { set: "access_token", name: claim },
    "removed the realm's custom claim again");
  assert.strictEqual(typedClaim(await claimSet("claims", "access_token"), claim),
    undefined,
    "and it should be gone from this realm's claim set afterwards — the " +
    "restore matters here as much as the change, because this door is not " +
    "inside the throwaway realm's teardown for the DEFAULT realm's sake.");
  log.info("[claim realms] OK — a claim configured in " + REALM + " reaches " +
           "that realm's tokens and neither the default realm's tokens nor " +
           "its console.");
  log.debug("Leaving aClaimSetBelongsToItsRealm().");
}

// The set ids one door carries, read off its own refusal rather than typed.
async function setsCarriedBy(door) {
  log.debug("Entering setsCarriedBy(). door=" + door);
  const probe = await post("/" + door + "/__no_such_action__", { set: "" });
  const errors = ((probe.body && probe.body.errors) || []).join(" ");
  const carried = errors.match(/(?:carries|carry|are)\s*(?:are)?:\s*([^.]+)\./);
  assert.ok(carried,
    "/" + door + " asked with no `set` should name the sets it carries: " + errors);
  const sets = splitList(carried[1]);
  log.debug("Leaving setsCarriedBy(). " + sets.join(", "));
  return sets;
}

async function oneClaimSetRoundTrips(door, set) {
  log.debug("Entering oneClaimSetRoundTrips(). door=" + door + ", set=" + set);
  const claim = "test_" + set.replace(/[^a-z0-9]/gi, "_");

  // The typed claims: add, remove, replace, clear.
  await ok("/" + door + "/add", { set: set, name: claim, value: "one" },
    "added a typed claim to " + set);
  assert.strictEqual(typedClaim(await claimSet(door, set), claim), "one",
    "`add` on /" + door + " should put " + claim + " into the " + set +
    " set, readable through GET /" + door + "?set=" + set + ".");

  // `replace` takes the WHOLE set rather than one claim, which is what makes
  // it the action a form's "save" posts: the page shows every row and sends
  // them all back, so a partial application would leave the set in a state
  // nobody asked for. Sending two here also checks that it does not simply
  // append — a `replace` that behaved as `add` would pass a one-row check.
  await ok("/" + door + "/replace",
    { set: set, claims: [{ name: claim, value: "two" },
                         { name: claim + "_b", value: "three" }] },
    "replaced the typed claims of " + set);
  let held = await claimSet(door, set);
  assert.strictEqual(typedClaim(held, claim), "two",
    "`replace` should leave the claim it was given, with the value it was " +
    "given; it reads " + typedClaim(held, claim));
  assert.strictEqual(typedClaims(held).length, 2,
    "and it should leave EXACTLY what it was given — two claims — rather " +
    "than adding them to what was there. It left " +
    JSON.stringify(typedClaims(held).map(function (c) { return c.name; })));
  await ok("/" + door + "/remove", { set: set, name: claim + "_b" },
    "removed the second claim again");
  assert.strictEqual(typedClaim(await claimSet(door, set), claim + "_b"), undefined,
    "`remove` should take the second claim out too — it is read back for the " +
    "same reason the first one is: `replace` put both there in one call, so a " +
    "`remove` that only ever removed the LAST claim would pass a check made " +
    "against a set with one row in it.");

  await ok("/" + door + "/remove", { set: set, name: claim },
    "removed a typed claim from " + set);
  assert.strictEqual(typedClaim(await claimSet(door, set), claim), undefined,
    "`remove` should take it out again.");

  // A name the set reserves is refused BY NAME. This is the one refusal on
  // these doors that protects a protocol rather than the form: a custom claim
  // called `iss` would be overwritten by the issuer at signing time, so a
  // service that accepted it would be storing something it will never send.
  const reserved = await reservedNameFor(door);
  if (reserved) {
    await refused("/" + door + "/add",
      { set: set, name: reserved, value: "x" },
      new RegExp(reserved.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
      "a reserved claim name (" + reserved + ")");
  }

  // The DIRECTORY ATTRIBUTE half. `attributes` selects, `attributes-all`
  // selects everything in the catalogue and `attributes-clear` empties it —
  // three actions over a different store from the four above.
  const catalogue = await attributeCatalogue(door);
  assert.ok(catalogue.length > 1,
    "GET /" + door + " should publish the attribute catalogue the three " +
    "`attributes` actions select from; it published " + catalogue.length);

  await ok("/" + door + "/attributes",
    { set: set, attributes: [catalogue[0]] },
    "selected one directory attribute for " + set + " — AND THIS IS THE " +
    "ACTION THAT IS BROKEN IN EVERY NON-DEFAULT TRUST REALM IF THE STORE " +
    "BEHIND IT IS SEEDED ONCE AT REQUIRE TIME RATHER THAN PER REALM. The " +
    "refusal to watch for is `There is no claim set called \"" + set +
    "\". The N are: … " + set + " …` — a sentence that lists the set it is " +
    "refusing, which is what a lookup against an empty per-realm partition " +
    "produces beside a list read from the process-wide table");
  assert.deepStrictEqual(selectedAttributes(await claimSet(door, set)),
    [catalogue[0]],
    "`attributes` should leave exactly the attribute it was given selected.");

  await ok("/" + door + "/attributes-all", { set: set },
    "selected every directory attribute for " + set);
  assert.strictEqual(selectedAttributes(await claimSet(door, set)).length,
    catalogue.length,
    "`attributes-all` should select the whole catalogue — " + catalogue.length +
    " attributes — and it selected " +
    selectedAttributes(await claimSet(door, set)).length);

  await ok("/" + door + "/attributes-clear", { set: set },
    "cleared the directory attributes for " + set);
  assert.deepStrictEqual(selectedAttributes(await claimSet(door, set)), [],
    "`attributes-clear` should leave none selected.");

  // `clear` last, because it is the one that empties the typed claims and the
  // checks above want something in there.
  await ok("/" + door + "/add", { set: set, name: claim, value: "three" },
    "added a claim back so that `clear` has something to clear");
  await ok("/" + door + "/clear", { set: set }, "cleared " + set);
  assert.deepStrictEqual(typedClaims(await claimSet(door, set)), [],
    "`clear` should leave the typed claim set empty.");
  log.debug("Leaving oneClaimSetRoundTrips().");
}

async function claimSet(door, set) {
  log.debug("Entering claimSet(). door=" + door + ", set=" + set);
  const reply = await get("/" + door);
  assert.strictEqual(reply.status, 200,
    "GET /" + door + " should answer 200; it answered " + reply.status);
  // The reply carries EVERY set this door holds, each with its own typed
  // claims and its own selected attributes, rather than one set chosen by a
  // query parameter. That is the shape the console's page needs (it draws them
  // all) and it is what /admin-api hands back unchanged.
  const one = (reply.body.sets || []).filter(function (row) {
    return row && row.id === set;
  })[0];
  assert.ok(one,
    "GET /" + door + " should carry the set \"" + set + "\" in its `sets` " +
    "member; it carries " +
    JSON.stringify((reply.body.sets || []).map(function (r) { return r.id; })));
  log.debug("Leaving claimSet().");
  return one;
}

// The typed claims of one set — a list of {name, value} — and one of them by
// name. `claims` is the member; `attributes` beside it is the OTHER half of
// the same set and is asserted separately, because the two are different
// stores in different modules and only one of them was ever per realm.
function typedClaims(set) {
  const held = (set && set.claims) || [];
  return Array.isArray(held) ? held : [];
}

function typedClaim(set, name) {
  const row = typedClaims(set).filter(function (one) {
    return one && one.name === name;
  })[0];
  return row ? row.value : undefined;
}

// The directory attributes selected into one set, sorted so that a comparison
// is about membership rather than about the order the catalogue happens to be
// in — which the mock deliberately keeps in CATALOGUE order rather than in the
// order they were ticked, because that order reaches the token.
function selectedAttributes(set) {
  const held = (set && set.attributes) || [];
  return Array.isArray(held) ? held.map(String).slice().sort() : [];
}

// Every attribute a set could select, off the door's own catalogue. The rows
// are keyed by their LDAP name, which is what the three `attributes` actions
// take.
async function attributeCatalogue(door) {
  log.debug("Entering attributeCatalogue(). door=" + door);
  const reply = await get("/" + door);
  const out = (reply.body.attributeCatalogue || []).map(function (row) {
    return typeof row === "string" ? row : row.ldap;
  }).filter(Boolean);
  log.debug("Leaving attributeCatalogue(). " + out.length);
  return out;
}

// A name this door will refuse, out of its own reserved list. Read off the
// service rather than typed here: the lists differ per family — a JWT reserves
// `iss` and `aud`, a SAML attribute set reserves nothing of the kind — and a
// copy in this file would be a second definition of a table that moves.
async function reservedNameFor(door) {
  log.debug("Entering reservedNameFor(). door=" + door);
  const reply = await get("/" + door);
  const reserved = reply.body.reservedJwtClaims || reply.body.reservedNames ||
      reply.body.reserved || [];
  const out = Array.isArray(reserved) && reserved.length ? String(reserved[0]) : "";
  log.debug("Leaving reservedNameFor(). " + (out || "(none)"));
  return out;
}

// ---------------------------------------------------------------------------
// THE FEDERATION REGISTER — the one resource on this API whose operations
// change what this service will BELIEVE.
//
// mgmt-api/CLAUDE.md says so in the sharpest form it says anything: this API is
// not gated, so `POST /admin-api/federation/create` is the door that works when
// the console cannot be reached — and it is also the door through which anybody
// who can reach this port configures a signing certificate this service will
// then trust, and mints themselves a session as anybody. That is not a new
// hole, but it makes these seven operations the ones worth driving properly.
//
// Two properties beyond the round trip, and both are about what the register
// REFUSES rather than what it stores:
//
//   * a relationship is created DISABLED, and `enable` is a separate act. The
//     whole feature is the one thing in this service that refuses by default,
//     and "created ready to use" would quietly undo that.
//   * `fedClientSecret` is never returned by this API. That is deliberately NOT
//     claimed as a security boundary — an ldapsearch of ou=federations shows it
//     — but it stops this API being a second way to read a credential that
//     belongs to somebody else's service.
// ---------------------------------------------------------------------------
async function theFederationRegisterRoundTrips() {
  log.debug("Entering theFederationRegisterRoundTrips().");
  log.info("=== Federation: create, set, add-value, remove-value, enable, " +
           "disable, delete ===");
  const index = await get("/federation");
  // Each row names itself by the field the CREATE takes — `role` and
  // `protocol` — rather than by a generic `id`, which is what makes this
  // listing usable as the vocabulary a caller constructs a create from.
  const roles = (index.body.roles || []).map(function (r) {
    return typeof r === "string" ? r : r.role;
  }).filter(Boolean);
  const protocols = (index.body.protocols || []).map(function (p) {
    return typeof p === "string" ? p : p.protocol;
  }).filter(Boolean);
  assert.ok(roles.length && protocols.length,
    "GET /federation should publish the roles and the protocols a create is " +
    "validated against; it published " + JSON.stringify(roles) + " and " +
    JSON.stringify(protocols));

  const id = "fed-" + names.usernameFor("stsapi-fed").toLowerCase()
      .replace(/[^a-z0-9-]/g, "");
  const created = await ok("/federation/create", {
    id: id, name: "Test relationship", role: roles[0], protocol: protocols[0]
  }, "created a federation relationship");
  assert.ok(created.relationship,
    "the create should answer with the relationship it made.");

  const fresh = await relationship(id);
  assert.strictEqual(fresh.enabled, false,
    "A NEW RELATIONSHIP MUST BE DISABLED. Federation is the one feature here " +
    "that refuses by default — there is no permissive answer available at " +
    "/federation/acs/{id}, because 'accept any assertion' means letting " +
    "anybody who can reach this port POST a document naming themselves as " +
    "anybody — so a create that came out ready to use would undo the whole " +
    "posture while answering 200. It reads enabled=" + fresh.enabled);
  assert.ok(Array.isArray(fresh.missing) && fresh.missing.length,
    "and it should say what it is still MISSING before it could be used; it " +
    "says " + JSON.stringify(fresh.missing));

  await ok("/federation/enable", { id: id }, "enabled the relationship");
  assert.strictEqual((await relationship(id)).enabled, true,
    "`enable` should flip it.");
  await ok("/federation/disable", { id: id }, "disabled the relationship");
  assert.strictEqual((await relationship(id)).enabled, false,
    "`disable` should flip it back.");

  // `set` names one attribute of the relationship, and an attribute this
  // register does not have is refused BY NAME rather than written — the
  // register IS ou=federations, so an unknown attribute would otherwise become
  // a directory attribute nobody reads.
  await refused("/federation/set",
    { id: id, field: "fedNoSuchThing", value: "x" },
    /fedNoSuchThing|not an attribute/,
    "an attribute the federation schema does not have");

  // `fedPeer` is the partner's own identifier — an entityID, an issuer, a
  // wtrealm — and it is single-valued, which is what makes it the right one to
  // drive `set` with. GET /federation?relationship= reports it as `peer`.
  await ok("/federation/set",
    { id: id, field: "fedPeer", value: "urn:partner:test" }, "set fedPeer");
  assert.strictEqual((await relationship(id)).peer, "urn:partner:test",
    "`set` on fedPeer should be readable back off the relationship, where " +
    "the drill-down reports it as `peer`.");

  // `add-value` and `remove-value` take a MULTI-VALUED field, and which
  // fields those are depends on the relationship's ROLE — `fedAttributeMap` on
  // a service-provider-side one, `fedRelease` on an identity-provider-side one
  // — so the field is chosen off the relationship's own `editable` table
  // rather than named here. `description` is skipped because the register
  // writes its own lines into it, so a value added there is not the only thing
  // in the list.
  //
  // WHAT THIS PAIR CANNOT CATCH, and it is worth writing down beside the
  // check that does not make it: the operations DOCUMENT an enum of three
  // fields and federation.js's update() does not enforce it. A single-valued
  // field sent to `remove-value` takes the single-valued branch and is
  // ASSIGNED the value — so a caller asking for a value to be taken off
  // fedSsoUrl gets 200 and a fedSsoUrl set to it. Asserting that here would
  // either lock in the behaviour or fail against the service as it stands, so
  // it is reported rather than encoded.
  const multiField = ((await relationship(id)).editable || []).filter(function (row) {
    return row.editable === "multi" && row.name !== "description" &&
        (row.role === "both" || row.role === roles[0]);
  })[0];
  assert.ok(multiField,
    "the relationship should publish at least one multi-valued editable " +
    "field for `add-value` to drive; a " + roles[0] + "-side relationship " +
    "published none.");
  const mapping = "urn:test:" + REALM + ":attr=employeeNumber";
  await ok("/federation/add-value",
    { id: id, field: multiField.name, value: mapping },
    "added a value to " + multiField.name);
  assert.ok(JSON.stringify((await relationship(id)).fields[multiField.name] || [])
      .indexOf(mapping) >= 0,
    "`add-value` should be readable back off the relationship's own field; " +
    multiField.name + " holds " +
    JSON.stringify((await relationship(id)).fields[multiField.name]));
  await ok("/federation/remove-value",
    { id: id, field: multiField.name, value: mapping },
    "removed the value again");
  assert.ok(JSON.stringify((await relationship(id)).fields[multiField.name] || [])
      .indexOf(mapping) < 0,
    "AND `remove-value` SHOULD REALLY TAKE IT OFF. This is the pair that is " +
    "easiest to get wrong in one direction only — a `remove-value` that " +
    "answers 200 having matched nothing looks exactly like one that worked — " +
    "and this relationship is about to be deleted, so the only place it can " +
    "be caught is here. " + multiField.name + " still holds " +
    JSON.stringify((await relationship(id)).fields[multiField.name]));

  // The secret is write-only through this door, on every read of it.
  const listed = await get("/federation");
  const asJson = JSON.stringify(listed.body);
  assert.ok(asJson.indexOf("fedClientSecret\":\"") < 0 ||
            /"fedClientSecret":\s*("(\(set[^"]*\)|)")/.test(asJson),
    "`fedClientSecret` must never come back through this API with a value in " +
    "it. It is not claimed as a security boundary — an ldapsearch of " +
    "ou=federations shows it — but this API must not be a SECOND way to read " +
    "a credential belonging to somebody else's service. The listing carries: " +
    (asJson.match(/"fedClientSecret":[^,}]*/) || ["(absent)"])[0]);

  await ok("/federation/delete", { id: id }, "deleted the relationship");
  assert.strictEqual((await relationship(id)).found, false,
    "after `delete` the relationship must be gone.");
  log.info("[federation] OK — seven actions round-tripped, a new " +
           "relationship is disabled and incomplete, an unknown attribute is " +
           "refused by name, and the client secret is never returned.");
  log.debug("Leaving theFederationRegisterRoundTrips().");
}

async function relationship(id) {
  log.debug("Entering relationship(). id=" + id);
  const reply = await get("/federation?relationship=" + encodeURIComponent(id));
  assert.strictEqual(reply.status, 200,
    "GET /federation?relationship=… should answer 200; it answered " + reply.status);
  log.debug("Leaving relationship(). found=" + reply.body.found);
  return reply.body;
}

// ---------------------------------------------------------------------------
// THE TWO SAML REGISTRIES. They are SEPARATE IMPLEMENTATIONS rather than one
// with a version flag — SAML 1.1 has no request message, no Single Logout and a
// different spelling for almost every shared element — which is why /saml2 has
// four actions and /saml11 has one, and why a walk that treated them as one
// resource would be asserting the thing that is not true.
// ---------------------------------------------------------------------------
async function theSamlRegistriesRoundTrip() {
  log.debug("Entering theSamlRegistriesRoundTrip().");
  log.info("=== SAML 2.0 (four actions) and SAML 1.1 (one) ===");
  const sp = "urn:test:" + REALM + ":sp";
  const registered = await ok("/saml2/register",
    { sp: sp, acs: "https://sp.example/acs/" + REALM },
    "registered a SAML 2.0 service provider");
  assert.ok(registered.application,
    "the register should answer with the application entry it made or found.");

  const one = await serviceProvider(sp);
  assert.ok(one.slug,
    "a registered service provider should have a SLUG: the metadata is " +
    "published per service provider, so the document's URL carries a digest " +
    "of the entityID rather than the entityID itself, and three shell " +
    "scripts in this suite compute that segment with sha256sum. A registry " +
    "that stopped publishing it would break them with nothing here failing.");
  assert.ok(String(one.metadataUrl || "").indexOf(one.slug) > 0,
    "and the metadata URL should carry that slug; it is " + one.metadataUrl);
  assert.ok(String(one.metadataUrl || "").indexOf("/realm/" + REALM + "/") > 0,
    "and the URL should be inside this realm, since the entry is; it is " +
    one.metadataUrl);

  await ok("/saml2/set-logout-service",
    { sp: sp, binding: "HTTP-Redirect", value: "https://sp.example/slo" },
    "added a single logout service");
  assert.ok(JSON.stringify(await serviceProvider(sp)).indexOf("https://sp.example/slo") > 0,
    "the logout service should be readable back off the service provider.");
  await ok("/saml2/remove-logout-service",
    { sp: sp, value: "https://sp.example/slo" },
    "removed the single logout service");
  assert.ok(JSON.stringify(await serviceProvider(sp))
      .indexOf("https://sp.example/slo") < 0,
    "and the logout service should be gone from the entry afterwards. A " +
    "SAML 2.0 SP that is still listed as having a SingleLogoutService it no " +
    "longer wants is sent a LogoutRequest it will refuse, which is a " +
    "failure a person meets in a browser rather than here.");

  // The certificate operation is the one on this resource whose documented
  // field name is easiest to get wrong, and getting it wrong is SILENT: the
  // handler reads `value`, and a body naming the field anything else answers
  // 200 with `changed: false` and stores nothing. So the assertion is on the
  // ENTRY, and it is deliberately made through the documented name.
  const certificate = "MIIBtest" + "A".repeat(40);
  const set = await ok("/saml2/set-signing-certificate",
    { sp: sp, value: certificate }, "recorded a signing certificate");
  assert.strictEqual(set.changed, true,
    "`set-signing-certificate` should report that it CHANGED something. This " +
    "handler answers 200 with `changed: false` when the body named a field " +
    "it does not read — which is what a caller following a stale document " +
    "gets, silently, for ever — so the reply's own account of itself is the " +
    "assertion worth making here.");
  assert.ok(JSON.stringify(await serviceProvider(sp)).indexOf(certificate) > 0,
    "and the certificate should be on the entry afterwards.");

  const rp = "urn:test:" + REALM + ":rp";
  await ok("/saml11/register", { rp: rp, target: "https://rp.example/" },
    "registered a SAML 1.1 relying party");
  const parties = (await get("/saml11")).body.relyingParties || [];
  assert.ok(parties.some(function (row) {
    return row.identifier === rp || row.rp === rp || row.entityId === rp;
  }), "the SAML 1.1 relying party should be in GET /saml11's list; it holds " +
      JSON.stringify(parties.map(function (r) {
        return r.identifier || r.rp || r.entityId;
      })));
  log.info("[saml] OK — SAML 2.0's four actions and SAML 1.1's one " +
           "round-tripped, and the metadata URL carries this realm and the " +
           "entityID's slug.");
  log.debug("Leaving theSamlRegistriesRoundTrip().");
}

async function serviceProvider(sp) {
  log.debug("Entering serviceProvider(). sp=" + sp);
  const reply = await get("/saml2?sp=" + encodeURIComponent(sp));
  assert.strictEqual(reply.status, 200,
    "GET /saml2?sp=… should answer 200; it answered " + reply.status);
  log.debug("Leaving serviceProvider(). found=" + reply.body.found);
  return reply.body;
}

// ---------------------------------------------------------------------------
// THE AUTHORIZATION SERVER PROFILES: five actions, and the one property that
// distinguishes `remove` from `reset` — which is the pair most likely to be
// collapsed into one by somebody tidying.
// ---------------------------------------------------------------------------
async function theAuthorizationServerProfilesRoundTrip() {
  log.debug("Entering theAuthorizationServerProfilesRoundTrip().");
  log.info("=== Authorization servers: create, set, remove, reset, delete ===");
  const index = await get("/authorization-servers");
  const members = (index.body.members || []).map(function (m) {
    return typeof m === "string" ? m : m.name;
  }).filter(Boolean);
  assert.ok(members.length,
    "GET /authorization-servers should publish the metadata members a " +
    "profile can override; it published none.");
  const member = members.filter(function (name) {
    return name === "code_challenge_methods_supported";
  })[0] || members[0];

  const id = "as-" + names.usernameFor("stsapi-as").toLowerCase()
      .replace(/[^a-z0-9-]/g, "");
  await ok("/authorization-servers/create", { id: id, name: "Test profile" },
    "created an authorization server profile");
  assert.ok(await profile(id), "the profile should be in the list after create.");

  await ok("/authorization-servers/set", { id: id, member: member, value: "S256" },
    "set a metadata member");
  assert.ok(JSON.stringify((await profile(id)).overrides || {}).indexOf("S256") > 0,
    "`set` should put the value in the profile's overrides; they are " +
    JSON.stringify((await profile(id)).overrides));

  // The distinction worth pinning: `remove` takes the member OUT of the
  // published document — an authorization server that says nothing about PKCE
  // is a different claim from one that says the default — and `reset` puts the
  // service's own value back. A tidy-up that made them one call would leave no
  // way to express the first, and both would still answer 200.
  await ok("/authorization-servers/remove", { id: id, member: member },
    "removed a metadata member");
  const removed = await profile(id);
  assert.ok((removed.removed || []).indexOf(member) >= 0,
    "`remove` should record the member as REMOVED rather than merely " +
    "unset — an authorization server whose metadata omits " + member + " is " +
    "making a different statement from one that carries the default, and " +
    "this profile's `removed` list is where that difference lives. It holds " +
    JSON.stringify(removed.removed));

  await ok("/authorization-servers/reset", { id: id, member: member },
    "reset a metadata member");
  const reset = await profile(id);
  assert.ok((reset.removed || []).indexOf(member) < 0 &&
            !Object.prototype.hasOwnProperty.call(reset.overrides || {}, member),
    "`reset` should undo both — neither overridden nor removed. It reads " +
    JSON.stringify({ overrides: reset.overrides, removed: reset.removed }));

  await ok("/authorization-servers/delete", { id: id }, "deleted the profile");
  assert.ok(!(await profile(id)),
    "after `delete` the profile must be gone from the list.");
  log.info("[authorization servers] OK — five actions round-tripped, and " +
           "`remove` and `reset` are two different things.");
  log.debug("Leaving theAuthorizationServerProfilesRoundTrip().");
}

async function profile(id) {
  log.debug("Entering profile(). id=" + id);
  const reply = await get("/authorization-servers");
  const one = (reply.body.authorizationServers || []).filter(function (row) {
    return row && row.id === id;
  })[0];
  log.debug("Leaving profile(). " + (one ? "found" : "absent"));
  return one;
}

// ---------------------------------------------------------------------------
// THE TWO VERIFIABLE-CREDENTIAL RESOURCES. Five actions each, over two
// different KINDS of list: /credential-claims selects from a catalogue and
// refuses anything outside it, and /verifier-request deliberately does NOT —
// asking for a claim no credential here carries is the whole point of a
// verifier, because what it tests is what the wallet does with a request it
// cannot satisfy. Two resources that look alike and disagree on their central
// rule is exactly the pair worth driving.
// ---------------------------------------------------------------------------
async function theCredentialResourcesRoundTrip() {
  log.debug("Entering theCredentialResourcesRoundTrip().");
  log.info("=== Credential claims and the verifier request: five actions each ===");

  const claims = await get("/credential-claims");
  const catalogue = (claims.body.attributes || []).map(function (row) {
    return typeof row === "string" ? row : (row.ldap || row.name);
  }).filter(Boolean);
  assert.ok(catalogue.length > 1,
    "GET /credential-claims should publish the catalogue it selects from.");
  const before = (claims.body.selected || []).slice();

  await ok("/credential-claims/select", { attributes: [catalogue[0]] },
    "selected one credential claim");
  assert.deepStrictEqual((await get("/credential-claims")).body.selected,
    [catalogue[0]], "`select` should replace the whole selection.");

  await ok("/credential-claims/add", { name: catalogue[1] },
    "added a credential claim");
  assert.ok((await get("/credential-claims")).body.selected.indexOf(catalogue[1]) >= 0,
    "`add` should put it in.");
  await ok("/credential-claims/remove", { name: catalogue[1] },
    "removed a credential claim");
  assert.ok((await get("/credential-claims")).body.selected.indexOf(catalogue[1]) < 0,
    "`remove` should take it out.");

  await refused("/credential-claims/add", { name: "no_such_attribute_at_all" },
    /catalogue/i,
    "a claim outside the catalogue — THIS resource is the one that refuses " +
    "one, and /verifier-request next door is the one that must not");

  await ok("/credential-claims/defaults", {}, "restored the defaults");
  assert.deepStrictEqual((await get("/credential-claims")).body.selected,
    (await get("/credential-claims")).body.defaults,
    "`defaults` should put the selection back to the published defaults.");

  // `populate` writes the selected attributes onto directory entries so that a
  // credential issued for somebody has something to carry. It is the one
  // action here that touches the directory, which is why it is done inside the
  // throwaway realm and asserted against that realm's own count.
  const populated = await ok("/credential-claims/populate", {},
    "populated the directory");
  assert.ok(populated.message || populated.updated !== undefined,
    "`populate` should say what it wrote; it answered " +
    JSON.stringify(populated).slice(0, 200));
  // Read back through the resource's own GET, and the assertion is the one
  // that says the sweep and the selection are ONE list: `populate` writes the
  // attributes this page has selected, so a sweep that carried some other
  // list would be writing attributes nobody asked for onto every entry in the
  // realm — and it would answer 200 and report a count either way.
  const sweep = populated.sweep || {};
  assert.deepStrictEqual((sweep.attributes || []).slice().sort(),
    ((await get("/credential-claims")).body.selected || []).slice().sort(),
    "`populate` should sweep exactly the attributes GET /credential-claims " +
    "says are selected. It swept " + JSON.stringify(sweep.attributes));
  assert.ok(Number(sweep.examined) > 0,
    "and it should have examined at least one directory entry — this realm " +
    "has people in it by now, and a sweep that examined none is one that " +
    "found the wrong subtree. It examined " + sweep.examined);

  const request = await get("/verifier-request");
  const formats = (request.body.formats || []).map(function (f) {
    return typeof f === "string" ? f : f.id;
  }).filter(Boolean);
  assert.ok(formats.length > 1,
    "GET /verifier-request should publish the formats `format` chooses between.");
  const startingFormat = request.body.format;

  await ok("/verifier-request/select", { claims: ["given_name"] },
    "selected one requested claim");
  assert.deepStrictEqual((await get("/verifier-request")).body.requested,
    ["given_name"],
    "`select` should REPLACE the whole request rather than add to it — it is " +
    "what a form's save posts, so a partial application leaves a verifier " +
    "asking for claims nobody ticked.");
  await ok("/verifier-request/add", { name: "not_a_claim_anything_here_issues" },
    "ASKED FOR A CLAIM NOTHING HERE ISSUES, which this resource must ALLOW. " +
    "A verifier that could only ask for claims the issuer beside it happens " +
    "to mint could never test what a wallet does with a request it cannot " +
    "satisfy, which is most of what a verifier is for");
  assert.ok((await get("/verifier-request")).body.requested
      .indexOf("not_a_claim_anything_here_issues") >= 0,
    "and the unsatisfiable claim should really be in the request.");
  await ok("/verifier-request/remove", { name: "not_a_claim_anything_here_issues" },
    "removed it again");
  assert.ok((await get("/verifier-request")).body.requested
      .indexOf("not_a_claim_anything_here_issues") < 0,
    "and it should really be out of the request afterwards: this resource " +
    "accepts a claim nothing here issues, so nothing else would ever fail if " +
    "`remove` quietly kept it.");

  const other = formats.filter(function (f) { return f !== startingFormat; })[0];
  await ok("/verifier-request/format", { format: other }, "changed the format");
  assert.strictEqual((await get("/verifier-request")).body.format, other,
    "`format` should change which credential format the request asks for.");
  const restored = await ok("/verifier-request/defaults", {},
    "restored the request defaults");
  const request2 = (await get("/verifier-request")).body;
  assert.deepStrictEqual(request2.requested, request2.defaults,
    "`defaults` should put the request back to what this process started " +
    "with — which the resource publishes as `defaults`, so the assertion is " +
    "against the service's own statement of them rather than against a copy " +
    "here. It answered " + JSON.stringify(restored.requested) + " and the " +
    "resource now reads " + JSON.stringify(request2.requested));
  // The FORMAT is deliberately not part of `defaults` — that action resets the
  // claims and says so — so it is put back by hand, for the reason every
  // section here restores what it changed: the verifier's configuration is
  // this realm's, and this realm is thrown away, but a reader who found the
  // format changed at the end of this section would reasonably think
  // `defaults` had failed to restore it.
  await ok("/verifier-request/format", { format: startingFormat },
    "put the format back");
  assert.strictEqual((await get("/verifier-request")).body.format, startingFormat,
    "and the format should be back where this section found it.");

  log.info("[credentials] OK — both resources' five actions round-tripped, " +
           "and the one that refuses an unknown claim and the one that must " +
           "not both behaved as they say.");
  log.debug("Leaving theCredentialResourcesRoundTrip(). before=" +
            before.length + " claim(s) were selected when it started.");
}

// ---------------------------------------------------------------------------
// SPIFFE: the registry's three actions, the agents' three, and the one that is
// process-wide.
//
// The registration entries and the agents are directory entries under this
// realm's ou=spiffe, so they are thrown away with the realm. `rotate` is not:
// there is ONE signing authority for the process, because a socket has no path
// to put a realm segment in. It is exercised once, here, and it is why this job
// is EXCLUSIVE in run-report.js — a SPIFFE job holding a stream open across a
// rotation would see its SVID stop verifying with nothing to say why.
// ---------------------------------------------------------------------------
async function theSpiffeDoorsRoundTrip() {
  log.debug("Entering theSpiffeDoorsRoundTrip().");
  log.info("=== SPIFFE: entries, agents, and the authority ===");
  const before = await get("/spiffe");
  assert.strictEqual(before.status, 200, "GET /spiffe should answer 200.");
  const trustDomain = before.body.trustDomain;
  assert.ok(trustDomain, "GET /spiffe should name the trust domain it issues for.");
  const sequenceBefore = Number((before.body.bundle || {}).sequence || 0);

  const spiffeId = "spiffe://" + trustDomain + "/test/" +
      names.usernameFor("stsapi-spiffe").toLowerCase().replace(/[^a-z0-9-]/g, "");
  const created = await ok("/spiffe/entries/create", {
    spiffeId: spiffeId,
    parentId: "spiffe://" + trustDomain + "/spire/agent/test",
    selectors: ["unix:uid:1000"]
  }, "created a registration entry");
  assert.ok(created.id, "the create should answer with the entry's id.");
  const entryId = created.id;
  assert.ok(String(created.entry.dn).indexOf("dc=" + REALM + ",") > 0,
    "and the entry should be in THIS realm's subtree; its DN is " +
    created.entry.dn);

  // `update` changes ONE field at a time, named — which is why it takes
  // `field` and `value` rather than a whole entry: the entry also carries what
  // HAPPENED (when it was created, how many SVIDs it has issued), and a
  // whole-entry PUT would give a caller a way to rewrite that.
  await ok("/spiffe/entries/update",
    { entry: entryId, field: "hint", value: "changed-by-the-test" },
    "updated one field of the registration entry");
  const updated = (await get("/spiffe/entries")).body.entries.filter(function (row) {
    return row.id === entryId;
  })[0];
  assert.ok(updated && String(updated.hint) === "changed-by-the-test",
    "`update` should change the field it was given; the entry holds hint=" +
    JSON.stringify(updated && updated.hint));

  // And a field that describes what HAPPENED is refused BY NAME rather than
  // written. That is the same rule the applications registry keeps for its
  // derived attributes, and here it protects the count of SVIDs an identity
  // has been issued — which is evidence rather than configuration.
  await refused("/spiffe/entries/update",
    { entry: entryId, field: "x509svidsIssued", value: "0" },
    /is not a field this page may change/,
    "rewriting what HAPPENED rather than what the entry may DO");

  await ok("/spiffe/entries/delete", { entry: entryId },
    "deleted the registration entry");
  assert.ok(!(await get("/spiffe/entries")).body.entries.some(function (row) {
    return row.id === entryId;
  }), "after `delete` the entry must be gone.");

  // The three agent actions need an agent, and this realm has none: an agent
  // exists because one ATTESTED, and nothing in this file speaks the Workload
  // API. So what is asserted is the refusal, which is the half a test can
  // reach — and it must name the AGENT rather than the field, because a body
  // carrying `agent` and getting "which agent?" would mean the document and
  // the handler disagree about the name.
  const noAgent = "spiffe://" + trustDomain + "/spire/agent/nothing-attested-here";
  for (const action of ["ban", "unban", "delete"]) {
    await refused("/spiffe/agents/" + action, { agent: noAgent },
      /No agent has the id/i,
      "acting on an agent that has never attested (" + action + ")");
  }
  assert.strictEqual((await get("/spiffe/agents")).body.total, 0,
    "and no agent should have appeared in this realm as a side effect.");

  // A federated bundle is a foreign trust domain's, and it is per realm.
  await ok("/spiffe/federation-set",
    { trustDomain: "other.example",
      bundleEndpointUrl: "https://other.example/bundle",
      bundleEndpointProfile: "https_web",
      document: { keys: [], spiffe_sequence: 1, spiffe_refresh_hint: 300 } },
    "recorded a federated bundle");
  assert.ok(JSON.stringify((await get("/spiffe")).body).indexOf("other.example") > 0,
    "the federated trust domain should be readable back off GET /spiffe.");
  await ok("/spiffe/federation-remove", { trustDomain: "other.example" },
    "removed the federated bundle");
  assert.ok(JSON.stringify((await get("/spiffe")).body).indexOf("other.example") < 0,
    "and the federated trust domain should be gone from GET /spiffe. A " +
    "bundle left behind is a foreign trust domain this authority goes on " +
    "publishing, which is the one thing in this pair that has a consequence " +
    "outside the console.");

  // Last, and once: rotating replaces the signing authority for the whole
  // process. The bundle's sequence number is what says it really happened —
  // a rotation that answered 200 and changed nothing would leave every
  // previously issued SVID verifying, which is the opposite of what was asked.
  const rotated = await ok("/spiffe/rotate", {}, "rotated the signing authority");
  assert.ok(rotated.ok !== false, "the rotation should report success.");
  const after = await get("/spiffe");
  assert.ok(Number((after.body.bundle || {}).sequence || 0) > sequenceBefore,
    "ROTATING MUST ADVANCE THE BUNDLE'S SEQUENCE. It was " + sequenceBefore +
    " and it is " + (after.body.bundle || {}).sequence + ". The sequence is " +
    "how a relying party knows the bundle it holds is stale, so a rotation " +
    "that left it alone would publish new keys nobody fetched.");
  log.info("[spiffe] OK — the registry's three actions and the two bundle " +
           "actions round-tripped, the three agent actions refuse by " +
           "referent, and a rotation advanced the bundle sequence from " +
           sequenceBefore + " to " + (after.body.bundle || {}).sequence + ".");
  log.debug("Leaving theSpiffeDoorsRoundTrip().");
}

// ---------------------------------------------------------------------------
// THE TOKEN DOORS. Six actions, and the only ones on this API whose effect can
// be confirmed by a PROTOCOL endpoint rather than by another view of the same
// store — which is what makes them worth driving properly: the API's whole
// claim is that it is not a second implementation.
//
// tests/admin_api.js already proves that ONE revocation reaches
// /oauth2/introspect. What is left, and is here, is the other five: `restore`,
// which RFC 7009 defines no opposite for and which exists so that a test does
// not have to restart the service; and the four BULK revocations, each of which
// selects a different way and any of which could be selecting everything.
// ---------------------------------------------------------------------------
async function theTokenDoorsRoundTrip() {
  log.debug("Entering theTokenDoorsRoundTrip().");
  log.info("=== Tokens: revoke, restore, and the four bulk revocations ===");
  // Two identities, and they must be two NAMES rather than one name with a
  // suffix: random_username.js stamps once per PROCESS, so `usernameFor("x")`
  // called twice is the same person — which is right (a test file is one
  // actor) and is exactly wrong for the assertion below, where the whole
  // point is that revoking one person's tokens leaves somebody else's alone.
  const user = names.usernameFor("stsapi-tokens");
  const other = names.usernameFor("stsapi-tokens-other");
  const client = "token-client-" + REALM;

  const mine = await mintTokens(user, client);
  const theirs = await mintTokens(other, client);
  assert.ok(mine.access && theirs.access,
    "the realm's token endpoint should mint a token for any username; it is " +
    "the same permissive endpoint every other job in this suite uses.");

  // One token, revoked and restored, confirmed at the protocol endpoint.
  assert.strictEqual(await introspectActive(mine.access), true,
    "a freshly minted access token should introspect as active.");
  await ok("/tokens/revoke", { jti: mine.jti }, "revoked one token by jti");
  assert.strictEqual(await introspectActive(mine.access), false,
    "REVOKING THROUGH THIS API MUST REACH RFC 7662 INTROSPECTION. There is " +
    "one revocation set in admin_stats.js serving both this door and " +
    "/oauth2/revoke; a second set would look correct from either side and " +
    "never see the other.");
  await ok("/tokens/restore", { jti: mine.jti }, "restored one token by jti");
  assert.strictEqual(await introspectActive(mine.access), true,
    "AND `restore` MUST REACH IT TOO. RFC 7009 defines no un-revoke and this " +
    "operation says so in its own summary; it exists because restarting the " +
    "service to get back to a working credential turns a two-second test " +
    "into a two-minute one. An un-revoke that only cleared the console's " +
    "list would leave the token dead at the endpoint that matters.");

  // revoke-user selects by username, and the assertion that matters is the
  // NEGATIVE one: somebody else's token must still be alive. A bulk operation
  // that revoked everything would pass every check but this.
  await ok("/tokens/revoke-user", { user: user }, "revoked one person's tokens");
  assert.strictEqual(await introspectActive(mine.access), false,
    "`revoke-user` should kill that person's token.");
  assert.strictEqual(await introspectActive(theirs.access), true,
    "AND IT MUST LEAVE EVERYBODY ELSE'S ALONE. This is the assertion the " +
    "four bulk operations exist to be checked by: each of them selects a " +
    "different way, and a selector that quietly matched everything would " +
    "satisfy every other check in this file.");

  // revoke-kind and revoke-subject select differently again. Both are checked
  // the same way and then everything is put back, one jti at a time, because
  // `revoke-all` has no opposite.
  const restoreThese = [mine.jti, mine.idJti, theirs.jti, theirs.idJti]
      .filter(Boolean);
  await ok("/tokens/revoke-kind", { kind: "id_token" },
    "revoked every ID Token");
  assert.strictEqual(await introspectActive(theirs.access), true,
    "`revoke-kind` on id_token must not touch an ACCESS token.");
  await ok("/tokens/revoke-subject", { subject: subjectOf(theirs) },
    "revoked one subject's tokens");
  assert.strictEqual(await introspectActive(theirs.access), false,
    "`revoke-subject` should kill the token whose `sub` it named.");

  await ok("/tokens/revoke-all", {}, "revoked everything in this realm");
  const listed = await get("/tokens");
  assert.ok(listed.body.revokedCount >= restoreThese.length,
    "`revoke-all` should leave everything this realm holds revoked; the " +
    "page reports " + listed.body.revokedCount + " revoked out of " +
    listed.body.held + " held.");

  for (const jti of restoreThese) {
    await ok("/tokens/restore", { jti: jti },
      "restored " + jti + " after the bulk revocations");
  }
  const afterRestores = await get("/tokens");
  assert.ok(afterRestores.body.revokedCount < listed.body.revokedCount,
    "the resource's own listing should show the restores too, not just the " +
    "protocol endpoint: it read " + listed.body.revokedCount + " revoked " +
    "after `revoke-all` and " + afterRestores.body.revokedCount + " after " +
    restoreThese.length + " restores. The two views are one revocation set " +
    "and this is where they are asked to agree.");
  assert.strictEqual(await introspectActive(mine.access), true,
    "and restoring one jti at a time should bring them back — which is the " +
    "only way back from `revoke-all`, and the reason `restore` exists.");
  log.info("[tokens] OK — six actions, each confirmed at /oauth2/introspect " +
           "rather than in the console's own list, and each bulk revocation " +
           "shown to leave something alone.");
  log.debug("Leaving theTokenDoorsRoundTrip().");
}

// A token set for one person, out of THIS REALM'S token endpoint. The password
// grant is used because this service checks no password anywhere and it needs
// no browser — which is the same reason every other node-only job in this
// suite reaches for it.
async function mintTokens(username, client) {
  log.debug("Entering mintTokens(). username=" + username);
  const body = "grant_type=password&username=" + encodeURIComponent(username) +
      "&password=" + encodeURIComponent(username) +
      "&client_id=" + encodeURIComponent(client) + "&scope=openid";
  const reply = await common.httpJson(base + "/realm/" + REALM + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body
  });
  assert.strictEqual(reply.status, 200,
    "the realm's token endpoint should mint a token for " + username +
    "; it answered " + reply.status + " " + String(reply.raw).slice(0, 200));
  const out = {
    access: reply.body.access_token,
    id: reply.body.id_token,
    jti: claimOf(reply.body.access_token, "jti"),
    idJti: claimOf(reply.body.id_token, "jti"),
    sub: claimOf(reply.body.access_token, "sub")
  };
  log.debug("Leaving mintTokens(). jti=" + out.jti);
  return out;
}

function subjectOf(tokens) {
  return tokens.sub;
}

// One claim out of a JWT, without verifying it: this file is asserting what the
// service RECORDED about a token, not whether the token is sound — sts_dpop.js
// and oauth2_sts_endpoints.js own that question.
function claimOf(jwt, name) {
  if (!jwt) {
    return "";
  }
  const parts = String(jwt).split(".");
  if (parts.length < 2) {
    return "";
  }
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return payload[name] || "";
  } catch (e) {
    // A token this service minted is always decodable; a body that is not is
    // worth reporting as an empty claim rather than as a crash, because the
    // assertion that follows says more about what went wrong.
    return "";
  }
}

async function introspectActive(token) {
  log.debug("Entering introspectActive().");
  const reply = await common.httpJson(base + "/realm/" + REALM + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(token)
  });
  assert.strictEqual(reply.status, 200,
    "introspection should answer 200 whatever it thinks of the token; it " +
    "answered " + reply.status);
  log.debug("Leaving introspectActive(). active=" + reply.body.active);
  return reply.body.active === true;
}

// ---------------------------------------------------------------------------
// THE DIRECTORY DOOR AND THE SIGN-OUT DOOR.
//
// `/users/create` is the only write on this API that puts a PERSON in the
// directory, and the rule it keeps is the one every door here keeps: ONE ENTRY
// PER PERSON, whatever protocol authenticated them. So the assertion is the
// second create being refused, not the first succeeding.
//
// `/logout` is the resource where three doors onto one behaviour deliberately
// DISAGREE, and that disagreement is the thing worth pinning: `POST /logout`
// with an empty body is a GLOBAL logout and is documented as such, while `POST
// /admin-api/logout/end` with an empty selection is REFUSED. The absence is the
// same and the intent is opposite — an empty selection arriving at `end` is a
// caller that built a list and got nothing.
// ---------------------------------------------------------------------------
async function theDirectoryAndSignOutDoorsRoundTrip() {
  log.debug("Entering theDirectoryAndSignOutDoorsRoundTrip().");
  log.info("=== Users, and the sign-out resource's four actions ===");
  const username = names.usernameFor("stsapi-directory");
  const created = await ok("/users/create", { username: username },
    "created a person in the directory");
  assert.ok(String(created.dn || "").indexOf("dc=" + REALM + ",") > 0,
    "the entry should land in THIS realm's ou=users; its DN is " + created.dn);
  const listedUsers = await get("/users?q=" + encodeURIComponent(username));
  assert.strictEqual(listedUsers.status, 200,
    "GET /users?q=… should answer 200; it answered " + listedUsers.status);
  assert.strictEqual(listedUsers.body.matched, 1,
    "and the person just created should be the one row that matches their " +
    "own name — read through the resource's own listing rather than believed " +
    "off the create's reply. It matched " + listedUsers.body.matched + " of " +
    listedUsers.body.known + " known.");
  assert.strictEqual((listedUsers.body.users[0] || {}).knownBy, "created",
    "and the register should say this entry is known because it was CREATED " +
    "rather than because somebody authenticated as them: this door is the " +
    "only one on this API that puts a person in the directory without a " +
    "sign-in, and that provenance is the whole difference. It says " +
    JSON.stringify((listedUsers.body.users[0] || {}).knownBy));

  await refused("/users/create", { username: username },
    /already/i,
    "a second entry for one person — one object per person is the rule this " +
    "directory keeps at every door, whatever protocol authenticated them");

  // The sign-out resource acts on somebody by NAME — it is the operator's
  // door, and /logout is the one that defaults to whoever is signed in — so a
  // body with no user never reaches the action at all.
  await refused("/logout/end", { select: ["session:nothing"] },
    /Name the identity|in `user`/,
    "a sign-out with no identity named");

  const tokens = await mintTokens(username, "logout-client-" + REALM);
  const inventory = await get("/logout?user=" + encodeURIComponent(username));
  assert.strictEqual(inventory.status, 200,
    "GET /logout?user=… should answer 200; it answered " + inventory.status);
  assert.ok((inventory.body.families || []).length > 5,
    "the sign-out view should list every family a logout reaches — the " +
    "prose for those lives in logout/logout.js and is rendered by both " +
    "doors, so a family added there appears here with no edit. It listed " +
    (inventory.body.families || []).length);
  const rows = inventory.body.rows || [];
  assert.ok(rows.length,
    "and after minting a token for " + username + " there should be " +
    "something live to end; the view lists none.");

  await refused("/logout/end", { user: username, select: [] },
    /Nothing was selected|global/i,
    "AN EMPTY SELECTION — which is the one place three doors onto one " +
    "behaviour deliberately disagree. `POST /logout` with an empty body is a " +
    "global logout and is documented as such; an empty `select` here is a " +
    "caller that built a list and got nothing, and signing that caller out " +
    "of everything would be the worst available reading of it");

  const ended = await ok("/logout/end",
    { user: username, select: [rows[0].id] },
    "ended one live thing by id");
  assert.ok(ended.result || ended.terminated || ended.ok,
    "`end` should say what it ended; it answered " +
    JSON.stringify(ended).slice(0, 200));
  const afterEnd = await get("/logout?user=" + encodeURIComponent(username));
  assert.ok(!(afterEnd.body.rows || []).some(function (one) {
    return one.id === rows[0].id;
  }), "AND THE THING IT ENDED MUST BE GONE FROM THE VIEW. `end` reports what " +
      "it terminated in its own reply, which is exactly the account a handler " +
      "that terminated nothing would also give — so the inventory is read " +
      "again and the row is looked for by id. It still lists " +
      JSON.stringify((afterEnd.body.rows || []).map(function (one) {
        return one.id;
      })));

  const globally = await ok("/logout/global", { user: username },
    "signed the person out globally");
  const terminated = (globally.result && globally.result.terminated) ||
      globally.terminated || [];
  assert.ok(Array.isArray(terminated),
    "`global` should report what it terminated; it answered " +
    JSON.stringify(globally).slice(0, 200));
  const afterGlobal = await get("/logout?user=" + encodeURIComponent(username));
  assert.deepStrictEqual((afterGlobal.body.rows || []).filter(function (one) {
    return one.terminable;
  }).map(function (one) { return one.id; }), [],
    "AND NOTHING TERMINABLE MAY BE LEFT. That is what `global` means, and it " +
    "is the assertion the reply cannot make for itself: a handler that ended " +
    "the first family and stopped would report a list of things it really " +
    "did end. What is left is the non-terminable rows, which the view lists " +
    "on purpose. It still holds " +
    JSON.stringify((afterGlobal.body.rows || []).filter(function (one) {
      return one.terminable;
    }).map(function (one) { return one.label; })));
  assert.strictEqual(await introspectActive(tokens.access), false,
    "and a global sign-out must reach the token, not just the session: it is " +
    "the same revocation set /oauth2/revoke writes to.");

  // The two NON-SPEC actions, which say so in their own summaries. RFC 7009
  // defines no un-revoke and a real KDC has no clear-the-instant; both exist so
  // that a test does not have to restart the service to get back to a working
  // credential.
  await ok("/logout/restore-token", { user: username, jti: tokens.jti },
    "restored a token the sign-out revoked");
  assert.strictEqual(await introspectActive(tokens.access), true,
    "`restore-token` must reach introspection, for the same reason " +
    "`/tokens/restore` must.");
  assert.ok((await get("/logout?user=" + encodeURIComponent(username)))
      .body.rows.some(function (one) {
        return one.family === "token" && one.terminable;
      }),
    "and the restored token should be something the sign-out view can end " +
    "again — the inventory and the revocation set are one store read two " +
    "ways, and an un-revoke that only reached introspection would leave this " +
    "page unable to offer the thing it had just been told about.");

  await ok("/logout/restore-kerberos", { user: username },
    "cleared the Kerberos sign-out instant");
  const krb5Row = (await get("/logout?user=" + encodeURIComponent(username)))
      .body.rows.filter(function (one) { return one.family === "krb5"; })[0];
  assert.ok(krb5Row,
    "the sign-out view should always carry a Kerberos row, even when there " +
    "is no principal — the absence is the answer, and omitting it would read " +
    "as a global logout having skipped the KDC.");
  assert.ok(!krb5Row.startedAt,
    "AND NO SIGN-OUT INSTANT MAY STAND AFTER `restore-kerberos`. The row's " +
    "`startedAt` IS that instant — it is 0 when there is none — so this is " +
    "the one reading of that action a caller can make; its own reply says " +
    "\"nothing changed\" whether it cleared an instant or never found one. " +
    "It reads " + krb5Row.startedAt + " (" + krb5Row.detail + ")");

  log.info("[users/logout] OK — one entry per person is enforced, the " +
           "sign-out view lists what is live, `end` refuses an empty " +
           "selection while `global` means everything, and both non-spec " +
           "restores reach the protocol endpoint.");
  log.debug("Leaving theDirectoryAndSignOutDoorsRoundTrip().");
}

// ---------------------------------------------------------------------------
// THE ADMIN ROLES, WHICH ARE THE ONE THING HERE THAT IS NOT REALM-SCOPED.
//
// The two console roles are ordinary groups in the DEFAULT realm's ou=groups,
// read there from every realm, and a grant made through
// /realm/<id>/admin-api/rbac/grant lands there too and says so in its reply.
// That is deliberate: a role is permission to change what EVERY realm does, so
// a per-realm roster would mean anybody who can create a realm can make
// themselves an administrator of the service.
//
// Which makes this the one section that must clean up after itself by hand, and
// the one that can lock every other job out of the console if it does not:
// while neither role group has a member, anybody who signs in holds both, and
// the FIRST grant closes that door for everybody who is not in the roster.
// ---------------------------------------------------------------------------
async function theAdminRolesRoundTrip() {
  log.debug("Entering theAdminRolesRoundTrip().");
  log.info("=== Admin roles: grant and revoke, in the DEFAULT realm ===");
  const before = await get("/rbac");
  assert.strictEqual(before.status, 200, "GET /rbac should answer 200.");
  // Each row names itself by the value the GRANT takes — `read` / `write` —
  // beside the group it really is (`cn=admin-read`). Both are published
  // because they are two different facts: one is what this API accepts and
  // the other is what an `ldapmodify` or a SCIM PATCH would write, and the
  // whole design of these roles is that those are four doors onto one
  // membership.
  const rolesAvailable = (before.body.roles || []).map(function (r) {
    return typeof r === "string" ? r : r.role;
  }).filter(Boolean);
  assert.ok(rolesAvailable.length === 2,
    "there should be exactly TWO console roles — read and write. They are " +
    "the whole of this console's authorization model, and a third would be a " +
    "design change rather than a configuration one. It published " +
    JSON.stringify(rolesAvailable));
  assert.ok(String(before.body.groupsDn || "").indexOf("dc=" + REALM) < 0,
    "READ FROM INSIDE " + REALM + ", THE ROSTER MUST STILL BE THE DEFAULT " +
    "REALM'S. The two roles are one roster for the process on purpose: a " +
    "role is permission to change what every realm does, so a per-realm " +
    "roster would let anybody who can create a realm administer the whole " +
    "service. It named " + before.body.groupsDn);

  const grantedBefore = before.body.grantCount;
  const subject = names.usernameFor("stsapi-role");
  const granted = await ok("/rbac/grant",
    { username: subject, role: rolesAvailable[0] },
    "granted a console role");
  // The reply says WHERE it landed by naming the DN it wrote, which is a
  // better answer than the word "default" would be: it is the same DN an
  // `ldapmodify` or a SCIM PATCH would write, which is the point of these
  // roles being ordinary groups rather than a store of the console's own.
  assert.ok(granted.dn && granted.member,
    "a grant should name the group it wrote and the member it added, so a " +
    "caller can reach the same membership through the other three doors. It " +
    "answered " + JSON.stringify(granted).slice(0, 300));
  assert.ok(String(granted.dn).indexOf("dc=" + REALM) < 0 &&
            String(granted.member).indexOf("dc=" + REALM) < 0,
    "A GRANT MADE UNDER A REALM PREFIX MUST LAND IN THE DEFAULT REALM, and " +
    "the DN in the reply is how it says so — a caller who did not read it " +
    "would reasonably believe it had made a " + REALM + " administrator. It " +
    "wrote " + granted.dn + " / " + granted.member);
  assert.strictEqual(granted.changed, true,
    "and it should report that it CHANGED the membership rather than " +
    "finding it already there.");

  const during = await get("/rbac");
  assert.strictEqual(during.body.grantCount, grantedBefore + 1,
    "the roster should have grown by one.");
  assert.ok((during.body.grants || []).some(function (row) {
    return String(row.username || row.user || "").indexOf(subject) >= 0;
  }), "and the person granted should be on it.");

  await ok("/rbac/revoke", { username: subject, role: rolesAvailable[0] },
    "revoked the console role");
  const after = await get("/rbac");
  assert.strictEqual(after.body.grantCount, grantedBefore,
    "AND THE ROSTER MUST BE BACK WHERE IT STARTED. While neither role group " +
    "has a member, anybody who signs in holds both — so a grant left behind " +
    "here closes the console for every other job in the run, and the job " +
    "that fails is not this one. It reads " + after.body.grantCount +
    " grant(s) against " + grantedBefore + " before.");
  log.info("[rbac] OK — grant and revoke round-tripped in the default " +
           "realm's directory, from inside " + REALM + ", and the roster is " +
           "back where it started.");
  log.debug("Leaving theAdminRolesRoundTrip().");
}

// ---------------------------------------------------------------------------
// THE CONFIGURATION DOORS, AND THE TWO NARROW ONES BESIDE THEM.
//
// `/config` is the wide door: four actions over a hundred and fifty settings,
// and `set-many` deliberately IGNORES a key it does not know, because a form
// posts fields the resource never declared. That is right for what it is and
// wrong for a caller that means to set a lifetime — a misspelt
// `oauth2.accessTokenTtlsS` succeeds, changes nothing, and reports success.
//
// So there are two NARROW doors, `/token-lifetimes` and `/saml-assertions`,
// whose whole reason to exist is a refusal the wide one cannot give. That is
// the test mgmt-api/CLAUDE.md sets for a third such resource — *"does a caller
// of the general operation get a wrong answer here"* — and it is asserted from
// both ends: the narrow door refuses an unknown key BY NAME, and the wide door
// does not, and both of those are the intended behaviour.
//
// One more thing is checked about the narrow doors, and it is the drift this
// file exists for: THE PROPERTIES THE DOCUMENT DECLARES MUST BE THE SETTINGS
// THE HANDLER ACCEPTS. The handler names them in its own refusal, so the two
// lists are comparable — and a document that is short by two is a caller who
// never discovers that two of the settings are settable here at all.
// ---------------------------------------------------------------------------
async function theConfigurationDoorsRoundTrip(doc) {
  log.debug("Entering theConfigurationDoorsRoundTrip().");
  log.info("=== Configuration: the wide door and the two narrow ones ===");

  // A runtime setting whose value is a small integer, chosen off the service's
  // own table rather than named here: an integer on the wire cannot be
  // satisfied by an echo the way a string can, and reading the table means
  // this file does not go stale when a setting is renamed.
  const table = (await get("/config")).body;
  const candidate = runtimeIntegerSetting(table);
  assert.ok(candidate,
    "the configuration table should carry at least one runtime integer " +
    "setting for this check to drive; it carries none.");
  const original = candidate.value;
  const wanted = Number(original) + 1;

  await ok("/config/set", { key: candidate.key, value: wanted },
    "set " + candidate.key);
  let row = settingRow((await get("/config")).body, candidate.key);
  assert.strictEqual(Number(row.value), wanted,
    "`set` should change the effective value of " + candidate.key + "; it " +
    "reads " + row.value);
  assert.strictEqual(row.source, "realm",
    "AND THE ROW MUST SAY THE VALUE CAME FROM THIS REALM. The five layers " +
    "are what /admin/config is a view of, and a value that changed without " +
    "the source moving would be a second store — but the distinction that " +
    "matters here is finer than that: a setting written under a realm prefix " +
    "is the REALM'S (`source: realm`, held on the realm row) and one written " +
    "at the root is the process's (`source: override`, held in the appconfig " +
    "store). They are two different places, and the same POST reaches " +
    "whichever one the prefix names. It says " + row.source);

  // The same setting at the ROOT, to see the other branch. A caller that only
  // ever drove one of the two would never notice them collapsing into each
  // other, and the persistence section below depends on their being different.
  const rootBefore = settingRow((await get("/config", true)).body, candidate.key);
  await ok("/config/set", { key: candidate.key, value: wanted + 1 },
    "set the same key at the root", true);
  const rootRow = settingRow((await get("/config", true)).body, candidate.key);
  assert.strictEqual(rootRow.source, "override",
    "the same setting written at the ROOT should be a process-wide override; " +
    "it says " + rootRow.source);
  assert.strictEqual(Number(settingRow((await get("/config")).body,
      candidate.key).value), wanted,
    "AND THE REALM'S VALUE MUST BE UNCHANGED BY IT. A realm override sits " +
    "above the process-wide one, so writing the process's must not reach " +
    "into a realm that has its own — which is the whole of what a realm is.");
  await ok("/config/reset", { key: candidate.key }, "reset it at the root", true);
  assert.strictEqual(settingRow((await get("/config", true)).body,
      candidate.key).source, rootBefore.source,
    "and the root's row should be back to " + rootBefore.source + ".");

  await ok("/config/reset", { key: candidate.key }, "reset " + candidate.key);
  row = settingRow((await get("/config")).body, candidate.key);
  assert.strictEqual(Number(row.value), Number(original),
    "`reset` should put the value back.");
  assert.notStrictEqual(row.source, "realm",
    "AND IT MUST TAKE THE OVERRIDE ROW AWAY, not merely write the old value " +
    "back. A `set` that restored the value would leave `source: override` on " +
    "the row for ever, which is what tests/admin_api.js trips over on the " +
    "next run against the same container — the reason tests/CLAUDE.md says " +
    "to restore with `reset` rather than with a second `set`. It says " +
    row.source);

  // set-many is all-or-nothing on the keys it KNOWS and silent about the ones
  // it does not. Both halves are deliberate and both are asserted, because
  // they look like the same behaviour from a single call.
  await ok("/config/set-many",
    { [candidate.key]: wanted, "no.such.setting.at.all": "ignored" },
    "set a section with an unknown field in it — which a FORM posts all the " +
    "time, and is why this door ignores it");
  assert.strictEqual(
    Number(settingRow((await get("/config")).body, candidate.key).value), wanted,
    "the known key in that section should have been applied.");
  await ok("/config/reset", { key: candidate.key }, "reset it again");

  // ---------------------------------------------------------------------
  // `reset-all`, IN THE REALM, AND ONLY IN THE REALM.
  //
  // config.js's clearAllOverrides() clears the overrides of the scope the
  // call ARRIVED IN — a realm's settings under a realm prefix, the process's
  // at the root — which is what makes it safe here and makes it the single
  // most destructive call in this suite at the root: it would drop whatever
  // every other job had pinned, and nothing would say so until one of them
  // failed for a reason that has nothing to do with itself.
  //
  // It is also the one operation on this API that carries no example body,
  // so nothing in the sweep reaches it. That is exactly the hole the coverage
  // ledger at the end of this run exists to keep shut.
  // ---------------------------------------------------------------------
  await ok("/config/set", { key: candidate.key, value: wanted },
    "set " + candidate.key + " again, so that `reset-all` has something to clear");
  const cleared = await ok("/config/reset-all", {},
    "cleared this realm's runtime overrides");
  assert.ok((cleared.cleared || []).indexOf(candidate.key) >= 0,
    "`reset-all` should NAME what it cleared — it is the one action on this " +
    "resource that a caller cannot predict the effect of, so the list is the " +
    "whole of its answer. It named " + JSON.stringify(cleared.cleared));
  row = settingRow((await get("/config")).body, candidate.key);
  assert.strictEqual(Number(row.value), Number(original),
    "and the value should be back where it started; it reads " + row.value);
  assert.notStrictEqual(row.source, "realm",
    "AND THE REALM'S OVERRIDE ROW MUST BE GONE, not merely holding the old " +
    "value again — the same distinction `reset` keeps one key at a time, " +
    "asked of the action that does the lot. It says " + row.source);

  // The narrow doors. Each is asked for its own list, twice: once out of the
  // OpenAPI document and once out of the handler's refusal.
  await aNarrowDoorRefusesByName(doc, "/token-lifetimes",
    "oauth2.accessTokenTtlS", "oauth2.accessTokenTtlsS");
  await aNarrowDoorRefusesByName(doc, "/saml-assertions",
    "saml2.assertionLifetimeMins", "saml2.assertionLifetimeMins");

  // The one member of /saml-assertions that earns the resource its place
  // beyond the parity: the WIDTH of the window an assertion actually states,
  // which is the lifetime plus TWICE the skew and which no setting states.
  const assertions = (await get("/saml-assertions")).body.assertions;
  assert.ok(assertions,
    "GET /saml-assertions should report the assertion settings.");
  assert.strictEqual(assertions.saml2WindowS,
    assertions.saml2LifetimeMin * 60 + 2 * assertions.clockSkewS,
    "saml2WindowS must be the lifetime plus TWICE the clock skew — the skew " +
    "is applied at both ends of the validity window, which is precisely the " +
    "thing a caller assembling this from the rows gets wrong, and is why " +
    "this resource reports it at all. It says " + assertions.saml2WindowS +
    " for a " + assertions.saml2LifetimeMin + "-minute lifetime and a " +
    assertions.clockSkewS + "-second skew.");

  // A RESTART-ONLY SETTING IS REFUSED BY NAME, WITH ITS REASON. That is the
  // property the whole five-layer arrangement rests on: only a runtime
  // setting can be overridden, which is what makes it safe for the
  // persistence store to re-apply saved overrides after every module has
  // loaded. A door that accepted one and ignored it would produce a console
  // showing a value the service is not using.
  const pinned = restartOnlySetting(table);
  assert.ok(pinned,
    "the configuration table should carry at least one restart-only setting.");
  await refused("/config/set", { key: pinned.key, value: pinned.value },
    /cannot be changed while this service is running/,
    "a restart-only setting (" + pinned.key + ")");
  assert.ok(/restart|listener|bound|process starts/i.test(
      JSON.stringify((await post("/config/set",
        { key: pinned.key, value: pinned.value })).body)),
    "and the refusal must say WHY it cannot be changed — `restartReason` is " +
    "on every such row precisely so that the answer is not just 'no'.");

  // Each narrow door SETS something through its own operation and is then
  // put back with `defaults`, and both halves are read off its rows. The set
  // is what makes the restore mean anything: `defaults` asked of a door that
  // nothing has changed passes whether it works or not.
  await aNarrowDoorSetsWhatItAccepts("/token-lifetimes");
  await ok("/token-lifetimes/defaults", {}, "restored the token lifetimes");
  await aNarrowDoorIsBackAtItsDefaults("/token-lifetimes");
  await aNarrowDoorSetsWhatItAccepts("/saml-assertions");
  await ok("/saml-assertions/defaults", {}, "restored the assertion lifetimes");
  await aNarrowDoorIsBackAtItsDefaults("/saml-assertions");
  log.info("[configuration] OK — set/reset/set-many round-tripped with the " +
           "source moving both ways, and both narrow doors refuse an " +
           "unknown key by name where the wide one ignores it.");
  log.debug("Leaving theConfigurationDoorsRoundTrip(). candidate was " +
            candidate.key);
  return candidate;
}

// A narrow door's `set`, driven with a value chosen off its own rows.
//
// The value is the published one moved by the published STEP, which is how
// this file avoids knowing anything about the setting: these are lifetimes in
// whole thirty-second or one-minute units, and a number typed here would be
// refused the day one of those bounds moved. Reading the row back is the
// assertion — `set` on these doors answers with a message either way.
async function aNarrowDoorSetsWhatItAccepts(path) {
  log.debug("Entering aNarrowDoorSetsWhatItAccepts(). path=" + path);
  const rows = (await get(path)).body.settings || [];
  const row = rows.filter(function (one) {
    return one.editable !== false && typeof one.value === "number";
  })[0];
  assert.ok(row,
    "GET " + path + " should publish at least one editable numeric setting; " +
    "it published " + rows.length + " row(s) and none that this can drive.");
  const step = Number(row.step) > 0 ? Number(row.step) : 1;
  const up = Number(row.value) + step;
  const wanted = (row.max === undefined || up <= Number(row.max))
    ? up
    : Number(row.value) - step;
  assert.ok(row.min === undefined || wanted >= Number(row.min),
    "the value this walk picked for " + row.key + " (" + wanted + ") is " +
    "outside the bounds the row publishes (" + row.min + ".." + row.max +
    "), which would make the refusal below say nothing about the door.");

  await ok(path + "/set", { [row.key]: wanted },
    "set " + row.key + " through " + path);
  const after = ((await get(path)).body.settings || []).filter(function (one) {
    return one.key === row.key;
  })[0];
  assert.strictEqual(Number(after.value), wanted,
    "`" + path + "/set` should change the value it was given: " + row.key +
    " was " + row.value + ", was sent " + wanted + ", and reads " + after.value +
    ". This is the door that exists BECAUSE /config/set-many answers 200 and " +
    "changes nothing when it does not recognise a key — so a narrow door " +
    "that did the same would be the defect it was built against, wearing the " +
    "refusal that proves it is a different resource.");
  assert.strictEqual(after.source, "realm",
    "and the row should say the value came from THIS REALM. These doors are " +
    "reached under the realm prefix like everything else here, so what they " +
    "write is the realm's own setting (`source: realm`) rather than the " +
    "process-wide override (`source: override`) the same call makes at the " +
    "root — which is why `overridden`, which is about the process-wide one, " +
    "is still false. It says source=" + after.source + ", overridden=" +
    after.overridden);
  log.debug("Leaving aNarrowDoorSetsWhatItAccepts(). " + row.key + "=" + wanted);
}

// A narrow door after its `defaults`, read back off the rows it publishes.
//
// It is the cheapest assertion in this section and the one most likely to have
// been left out, because `defaults` is what a test calls to TIDY UP and a
// tidy-up that quietly did nothing costs nothing until the next job — which
// finds a lifetime this file set, does not know it was set here, and fails
// somewhere else entirely. Each row carries its own `default` and its own
// `overridden` flag, so the check is against the service's statement of what a
// default is rather than against numbers typed in this file.
async function aNarrowDoorIsBackAtItsDefaults(path) {
  log.debug("Entering aNarrowDoorIsBackAtItsDefaults(). path=" + path);
  const rows = (await get(path)).body.settings || [];
  assert.ok(rows.length,
    "GET " + path + " should publish the settings rows this door writes; it " +
    "published none, and the check below then asserts nothing.");
  const stillSet = rows.filter(function (row) {
    return row.overridden || String(row.value) !== String(row.default);
  }).map(function (row) {
    return row.key + "=" + row.value + " (default " + row.default + ")";
  });
  assert.deepStrictEqual(stillSet, [],
    "AFTER " + path + "/defaults EVERY ONE OF ITS SETTINGS MUST BE AT ITS " +
    "DEFAULT, and hold no override row. `defaults` is what this file calls " +
    "to put back what it changed, so a `defaults` that answers 200 having " +
    "restored nothing leaves the damage AND the report that it was undone. " +
    "Still set: " + stillSet.join(", "));
  log.debug("Leaving aNarrowDoorIsBackAtItsDefaults(). " + rows.length + " row(s).");
}

// One narrow door: the names it accepts, checked against the document AND
// against its own refusal, and then a misspelling refused by name.
async function aNarrowDoorRefusesByName(doc, path, goodKey, misspelling) {
  log.debug("Entering aNarrowDoorRefusesByName(). path=" + path);
  const refusal = await post(path + "/set", { "no.such.key.here": 1 });
  const errors = ((refusal.body && refusal.body.errors) || []).join(" ");
  assert.strictEqual(refusal.status, 400,
    "POST " + path + "/set must REFUSE a key outside its own list. That " +
    "refusal is the entire reason this resource exists beside " +
    "/config/set-many, which ignores an unknown key on purpose — so a narrow " +
    "door that stopped refusing would be two operations over one function " +
    "with nothing to tell them apart. It answered " + refusal.status + " " +
    JSON.stringify(refusal.body).slice(0, 300));
  assert.ok(/no\.such\.key\.here/.test(errors),
    "and it must name the key it is refusing, so that a caller who misspelt " +
    "one is told which. It said: " + errors);

  // The list is read up to "It was also given", not up to the first full
  // stop: every name in it CONTAINS full stops (`oauth2.accessTokenTtlS`), so
  // a lazy match on `.` reads exactly one word and the comparison below then
  // fails for a reason that has nothing to do with the service.
  const named = (errors.match(/sets only\s+(.+?)\.\s+It was also given/) ||
                 errors.match(/sets only\s+(.+?)\.\s+Every other/) || [])[1];
  assert.ok(named,
    "the refusal from " + path + " should say which settings it DOES set; " +
    "it said: " + errors);
  const handlerKeys = splitList(named).sort();

  const schema = doc.paths["/admin-api" + path + "/set"].post.requestBody
      .content["application/json"].schema;
  const documentedKeys = Object.keys(schema.properties || {}).sort();
  assert.deepStrictEqual(documentedKeys, handlerKeys,
    "THE SETTINGS " + path + "/set DOCUMENTS MUST BE THE SETTINGS IT " +
    "ACCEPTS. This resource's whole claim is that it refuses anything " +
    "outside its own list BY NAME — so a document naming fewer of them is a " +
    "caller who never discovers that the others are settable here at all, " +
    "and one naming more is a caller whose request is refused for following " +
    "the document.\n" +
    "  the document declares: " + documentedKeys.join(", ") + "\n" +
    "  the handler accepts:   " + handlerKeys.join(", "));

  // And the misspelling the resource exists to catch, which the wide door
  // would have accepted in silence.
  if (misspelling !== goodKey) {
    const typo = await post(path + "/set", { [misspelling]: 60 });
    assert.strictEqual(typo.status, 400,
      "POST " + path + "/set with the near-miss " + misspelling + " must be " +
      "refused. That is the exact wrong answer /config/set-many gives — it " +
      "succeeds, changes nothing, and reports success — and this resource " +
      "exists to give a different one.");
  }
  log.debug("Leaving aNarrowDoorRefusesByName(). " + handlerKeys.length + " key(s).");
}

// A setting the table marks restart-only, for the refusal above. Like the one
// below it, it is CHOSEN off the service rather than named here.
function restartOnlySetting(table) {
  log.debug("Entering restartOnlySetting().");
  let chosen;
  (table.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      if (!chosen && setting.editable === false && setting.restartReason) {
        chosen = setting;
      }
    });
  });
  log.debug("Leaving restartOnlySetting(). " + (chosen ? chosen.key : "(none)"));
  return chosen;
}

// A runtime setting holding a small integer, off the service's own table. The
// candidate is chosen rather than named so that this file does not go stale
// when a setting is renamed — and integers are preferred because an integer on
// the wire cannot be satisfied by an echo the way a string can.
function runtimeIntegerSetting(table) {
  log.debug("Entering runtimeIntegerSetting().");
  let chosen;
  (table.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      // `editable` is the table's own word for "settable at runtime". A
      // restart-only setting is refused BY NAME with its reason rather than
      // accepted and ignored — which is asserted separately below — so it
      // must not be the one this walk drives.
      if (chosen || setting.editable !== true || setting.overridden) {
        return;
      }
      if (setting.type !== "int" && setting.type !== "integer" &&
          typeof setting.value !== "number") {
        return;
      }
      if (!Number.isInteger(setting.value) ||
          setting.value < 1 || setting.value > 100000) {
        return;
      }
      // Not a lifetime: the two narrow doors below drive those, and a value
      // left over from this check would make their refusals ambiguous.
      if (/Ttl|Lifetime|clockSkew/i.test(setting.key)) {
        return;
      }
      chosen = setting;
    });
  });
  log.debug("Leaving runtimeIntegerSetting(). " + (chosen ? chosen.key : "(none)"));
  return chosen;
}

// ---------------------------------------------------------------------------
// AND THE HALF THAT IS NOT ABOUT MEMORY: DID THE CHANGE REACH THE STORE?
//
// Setting a value and reading it back proves that something is holding it. What
// /admin/persistence promises is that it was WRITTEN — to an RFC 2849 file per
// realm, or to Postgres — and nothing about the value coming back says whether
// that happened. The store's own account of itself does: a write counter, a
// dirty flag, a failure counter and a last-write timestamp, all in `status`.
//
// A REALM'S overrides and a PROCESS-WIDE one are two different files and two
// different tables, and this checks both, because `configChanged(realmId)` is
// one function with a branch in it and the branch is invisible from either
// side alone.
//
// **A SERVICE IN `memory` MODE IS REPORTED, NOT SKIPPED.** That is the default
// and it is what the containerized stack runs, so most runs of this job will
// meet it — and "the store is off" and "the store did not write" look
// identical from a distance while only one of them is fine. What is asserted
// in that mode is the thing that IS true there: the status must say so, and it
// must not claim a write it did not make.
// ---------------------------------------------------------------------------
async function theConfigurationChangeReachesTheStore(candidate) {
  log.debug("Entering theConfigurationChangeReachesTheStore().");
  log.info("=== Persistence: does a setting change reach the store? ===");
  const before = (await get("/persistence", true)).body.status;
  assert.ok(before && before.mode,
    "GET /admin-api/persistence should carry a `status` member saying what " +
    "the store is actually doing. It is the only operation in its group that " +
    "does, and the reason is that a persistence setting that is SET and a " +
    "store that is WORKING are two different facts.");
  persistenceMode = before.mode;

  if (!before.enabled) {
    assert.strictEqual(before.mode, "memory",
      "a store that is not enabled should be in `memory` mode; it says " +
      before.mode);
    assert.strictEqual(before.persistsAppconfig, false,
      "and it must not claim to persist the appconfig overrides.");
    assert.strictEqual(before.persistsDirectory, false,
      "or the directory.");
    assert.strictEqual(before.writes, 0,
      "and it must not report having WRITTEN anything, which is the one " +
      "claim that would be actively misleading: a mock that reported writes " +
      "it never made would send somebody looking for a file that is not there.");
    log.info("[persistence] The store is OFF (persistence.mode=memory), which " +
             "is the default and what the containerized stack runs. The " +
             "value round trip above is asserted; the ON-DISK half is not " +
             "reachable from here and is asserted in mock-sts's own " +
             "tests/appconfig_persistence.js, which drives the store in " +
             "process against a temporary directory.");
    log.debug("Leaving theConfigurationChangeReachesTheStore(). Store off.");
    return;
  }

  assert.strictEqual(before.healthy, true,
    "the store is enabled and reports itself unhealthy: " + before.lastError);
  assert.strictEqual(before.coordinates, false,
    "and it must still say it does not COORDINATE. Two processes pointed at " +
    "one database each hold their own directory in memory and never see " +
    "each other's writes; a status that claimed otherwise would be the one " +
    "sentence somebody deployed against.");

  // A process-wide override, then a realm one. They take different branches
  // and land in different places.
  await ok("/config/set", { key: candidate.key, value: Number(candidate.value) + 2 },
    "set a process-wide setting to be persisted", true);
  const afterProcess = await settleThenStatus(before);
  assert.ok(afterProcess.writes > before.writes,
    "A PROCESS-WIDE SETTING CHANGE MUST REACH THE STORE. persistence.mode=" +
    before.mode + " and persistsAppconfig=" + before.persistsAppconfig +
    ", and the write counter went from " + before.writes + " to " +
    afterProcess.writes + ". The flush is scheduled rather than immediate, " +
    "so this waited for it; a counter that never moves means the override " +
    "store's slot in config.js is not filled.");
  assert.strictEqual(afterProcess.failures, before.failures,
    "and the write must have SUCCEEDED. A failure is recorded rather than " +
    "thrown here — a mock that refused to start because a database blinked " +
    "would be the one failure mode a mock must not have — so the failure " +
    "counter is the only thing that says it did not work. It went from " +
    before.failures + " to " + afterProcess.failures + ": " +
    afterProcess.lastError);
  assert.strictEqual(afterProcess.pending, false,
    "and nothing should still be waiting to be written.");
  assert.strictEqual(Number(settingRow((await get("/config", true)).body,
      candidate.key).value), Number(candidate.value) + 2,
    "and the value the store was told about should be the one the " +
    "configuration resource holds — the write counter says something was " +
    "written and only this says WHAT.");
  await ok("/config/reset", { key: candidate.key },
    "reset the process-wide setting", true);
  assert.notStrictEqual(settingRow((await get("/config", true)).body,
      candidate.key).source, "override",
    "and the process-wide override must be gone again: this section runs " +
    "against the DEFAULT realm, which the throwaway realm's teardown does " +
    "not clean up, so a row left here is a row every later job reads.");

  const beforeRealm = await settleThenStatus(afterProcess);
  await ok("/realms/set",
    { id: REALM, key: "saml.issuer", value: "urn:test:" + REALM + ":stored" },
    "set a REALM setting to be persisted", true);
  const afterRealm = await settleThenStatus(beforeRealm);
  assert.ok(afterRealm.writes > beforeRealm.writes,
    "A REALM'S OVERRIDES MUST REACH THE STORE TOO, and by a different route: " +
    "config.js decides whether an override is a realm's or the process's, " +
    "and persistence.js is TOLD which — a realm's lives on the realm row and " +
    "a process-wide one in the appconfig store, which are two different " +
    "files and two different tables. The counter went from " +
    beforeRealm.writes + " to " + afterRealm.writes);
  assert.strictEqual(afterRealm.failures, beforeRealm.failures,
    "and that write must have succeeded too: " + afterRealm.lastError);
  assert.ok(afterRealm.realmsTracked >= 1,
    "and the store should be tracking at least this realm; it tracks " +
    afterRealm.realmsTracked);
  assert.strictEqual(realmSetting(await realmRow(), "saml.issuer"),
    "urn:test:" + REALM + ":stored",
    "and the value that reached the store should be the one the registry " +
    "holds. The counters say a write happened; the registry row says it was " +
    "this write, which is the difference between a store that is working and " +
    "a store that is busy.");

  log.info("[persistence] OK — the store is " + before.mode + " at " +
           (before.dataDir || JSON.stringify(before.database)) + ". A " +
           "process-wide setting change and a realm setting change each " +
           "advanced the write counter with no failure and nothing left " +
           "pending.");
  log.debug("Leaving theConfigurationChangeReachesTheStore().");
}

// The store's status, after giving a scheduled flush time to happen. The delay
// is `writeDelayMs` — the store's own, read off it rather than guessed — plus a
// margin, and it polls rather than sleeping the whole time so that a fast store
// does not cost the run a second.
async function settleThenStatus(previous) {
  log.debug("Entering settleThenStatus().");
  const budget = Math.max(3000, Number(previous.writeDelayMs || 0) * 3);
  const until = Date.now() + budget;
  let status = previous;
  while (Date.now() < until) {
    await new Promise(function (resolve) { setTimeout(resolve, 150); });
    status = (await get("/persistence", true)).body.status;
    if (!status.pending && status.writes > previous.writes) {
      break;
    }
    if (status.failures > previous.failures) {
      break;
    }
  }
  log.debug("Leaving settleThenStatus(). writes=" + status.writes +
            ", pending=" + status.pending);
  return status;
}

// ---------------------------------------------------------------------------
// THE LEDGER, ASKED. Both checks read the document and this run's own call
// list, and neither of them drives anything — so they go last, after every
// section above has had its turn, and before the teardown (which drives
// `removeRealm` for real; the refusal of it is driven up in
// theRealmRegistryWorks()).
// ---------------------------------------------------------------------------

// The operations this file does not drive, and why. It is a TABLE rather than
// a filter for the reason the rest of this file prefers tables: an exemption
// with no sentence beside it is indistinguishable from an operation somebody
// forgot, which is the whole condition this check exists to end.
//
// Both rows are the explorer, which answers HTML and JavaScript rather than
// JSON. tests/admin_api.js drives them, and owns the harder half besides — the
// Content Security Policy that makes /admin-api/docs the fourth scripted page
// in a service whose default is `script-src 'none'`.
const NOT_DRIVEN_HERE = {
  "GET /docs":
    "the explorer PAGE: HTML, not JSON. Driven by tests/admin_api.js, which " +
    "also owns its CSP — this API's document is what it is drawn from, and " +
    "the document is driven here.",
  "GET /docs/explorer.js":
    "the explorer's script, driven and CSP-checked by tests/admin_api.js."
};

function everyDocumentedOperationWasDriven(doc) {
  log.debug("Entering everyDocumentedOperationWasDriven().");
  log.info("=== The ledger: every documented operation was driven ===");
  const documented = [];
  Object.keys(doc.paths).forEach(function (path) {
    const relative = path.replace(/^\/admin-api/, "");
    ["get", "post"].forEach(function (verb) {
      const operation = doc.paths[path][verb];
      if (!operation) {
        return;
      }
      documented.push({ key: verb.toUpperCase() + " " + relative,
                        operationId: operation.operationId });
    });
  });
  assert.ok(documented.length > 90,
    "the document should declare more than ninety operations; it declares " +
    documented.length + ". A collapse here would make this check pass by " +
    "having almost nothing to ask about, which is the one way a coverage " +
    "check can be worse than no coverage check.");

  const driven = {};
  ledger.forEach(function (call) {
    driven[call.method + " " + call.path] = true;
  });

  const missed = documented.filter(function (operation) {
    return !driven[operation.key] &&
        !Object.prototype.hasOwnProperty.call(NOT_DRIVEN_HERE, operation.key);
  }).map(function (operation) {
    return operation.operationId + "  (" + operation.key + ")";
  });
  assert.deepStrictEqual(missed, [],
    "THESE OPERATIONS ARE DOCUMENTED AND THIS FILE DRIVES NONE OF THEM. The " +
    "walks here are driven off the document — every GET, and every POST that " +
    "carries an example — so an operation that arrives with no example and " +
    "no section of its own is covered by nothing and reported by nothing. " +
    "Either drive it, or put a row in NOT_DRIVEN_HERE saying who does and " +
    "why:\n  " + missed.join("\n  "));

  // And the exemptions must still name real operations. A row left behind
  // after a rename excuses an operation that no longer exists while the one
  // that replaced it goes undriven — which is this check failing open.
  const keys = {};
  documented.forEach(function (operation) { keys[operation.key] = true; });
  const stale = Object.keys(NOT_DRIVEN_HERE).filter(function (key) {
    return !keys[key];
  });
  assert.deepStrictEqual(stale, [],
    "NOT_DRIVEN_HERE names operations this API does not have: " +
    stale.join(", ") + ". A stale exemption excuses an operation that is gone " +
    "and says nothing about the one that replaced it.");

  log.info("[ledger] OK — all " + (documented.length - Object.keys(NOT_DRIVEN_HERE).length) +
           " of this API's " + documented.length + " operations were driven " +
           "by this run; the " + Object.keys(NOT_DRIVEN_HERE).length +
           " exempt one(s) are the explorer, which tests/admin_api.js drives.");
  log.debug("Leaving everyDocumentedOperationWasDriven().");
}

// ---------------------------------------------------------------------------
// AND EVERY ACCEPTED WRITE WAS READ BACK THROUGH THE RESOURCE'S OWN GET.
//
// The sections above assert what each write MEANT — that the value is the one
// that was sent, that `add` accumulated where `set` assigned, that `remove`
// took away one thing and left the rest. This asserts the weaker property that
// makes those possible to trust: that a read happened at all, after the write,
// against the resource the write landed on and in the same scope.
//
// It is the check that catches the omission rather than the defect. A section
// added tomorrow that posts four actions and reads none of them would pass
// every other assertion in this file — including the coverage ledger above,
// which only asks whether an operation was DRIVEN — and would be reported as
// four more operations covered.
// ---------------------------------------------------------------------------
function everyAcceptedWriteWasReadBack() {
  log.debug("Entering everyAcceptedWriteWasReadBack().");
  log.info("=== The ledger: every accepted write was read back ===");
  const reads = ledger.filter(function (call) {
    return call.method === "GET" && call.accepted;
  });
  const writes = ledger.filter(function (call) {
    return call.method === "POST" && call.accepted;
  });
  assert.ok(writes.length > 40,
    "this file should have made more than forty accepted writes; it made " +
    writes.length + ". Below that the pairing check is asking about a run " +
    "that did not happen.");

  const unpaired = {};
  writes.forEach(function (write) {
    // `/spiffe/entries/create` is a write on `/spiffe/entries`, and
    // `/spiffe/federation-set` is a write on `/spiffe`: the action is the last
    // segment and the resource is everything before it, which is the same walk
    // documentedActions() does over the document.
    const resource = write.path.split("/").slice(0, -1).join("/");
    const paired = reads.some(function (read) {
      return read.path === resource && read.scope === write.scope &&
          read.at > write.at;
    });
    if (!paired) {
      unpaired["POST " + write.path + " (" + write.scope + ") — nothing read " +
               "GET " + resource + " in that scope afterwards"] = true;
    }
  });
  assert.deepStrictEqual(Object.keys(unpaired).sort(), [],
    "THESE WRITES SUCCEEDED AND NOTHING READ THEM BACK. Every write on this " +
    "API must be confirmed through the resource's own read operation, never " +
    "by believing the write's account of itself: a handler that answers " +
    "`{ok: true}` and changes nothing is the defect this whole file exists " +
    "to catch, and it passes every check that only looks at the reply.\n  " +
    Object.keys(unpaired).sort().join("\n  "));

  log.info("[ledger] OK — all " + writes.length + " accepted writes were " +
           "followed by a read of the resource they wrote, in the scope they " +
           "wrote it in.");
  log.debug("Leaving everyAcceptedWriteWasReadBack().");
}

// ---------------------------------------------------------------------------
// TEARDOWN. Removing the realm takes its directory subtree, its applications
// registry, its federation register, its claim sets, its SPIFFE registry, its
// tokens and its configuration overrides with it — which is the whole reason
// the work happened inside one.
//
// It runs in a `finally`, and it runs whether or not the assertions passed: a
// realm left behind is a realm every later job's `GET /realms` can see, and one
// left behind per failing run accumulates.
// ---------------------------------------------------------------------------
async function removeTheThrowawayRealm() {
  log.debug("Entering removeTheThrowawayRealm().");
  try {
    // Called at the ROOT, because `remove` refuses the realm the call arrived
    // in — which is the one refusal this registry has that is about the caller
    // rather than about the request.
    const reply = await post("/realms/remove", { id: REALM }, true);
    if (reply.status !== 200) {
      log.warn("Could not remove the throwaway realm " + REALM + ": " +
               JSON.stringify(reply.body).slice(0, 300) + ". It will show up " +
               "in GET /realms until this service restarts.");
      log.debug("Leaving removeTheThrowawayRealm(). It refused.");
      return;
    }
    const left = ((await get("/realms", true)).body.realms || [])
        .filter(function (r) { return r.id === REALM; });
    assert.deepStrictEqual(left, [],
      "the realm should be gone from the registry after `remove`.");
    log.info("[teardown] Removed the throwaway realm " + REALM +
             ", and with it everything this job created inside it.");
  } catch (e) {
    // Reported and not rethrown: a teardown that threw would replace the
    // failure that actually matters with the failure to tidy up after it.
    log.warn("Teardown could not finish: " + e.message);
  }
  log.debug("Leaving removeTheThrowawayRealm().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving every operation of the management API at " + rootApi);
  if (!(await theServiceIsThere())) {
    log.info("Skipped: no STS mock at " + base + ".");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const doc = (await get("/openapi.json", true)).body;
  assert.ok(doc && doc.paths,
    "GET /admin-api/openapi.json should answer the document; this file " +
    "drives every operation off it and asserts almost nothing without one.");

  await theRealmRegistryWorks();
  try {
    await theRefusalSentencesAreHonest(doc);
    await everyDocumentedExampleIsAccepted(doc);
    await everyReadAnswersAboutThisRealm(doc);
    await theApplicationsRegistryRoundTrips();
    await theClaimSetDoorsRoundTrip();
    await theFederationRegisterRoundTrips();
    await theSamlRegistriesRoundTrip();
    await theAuthorizationServerProfilesRoundTrip();
    await theCredentialResourcesRoundTrip();
    await theSpiffeDoorsRoundTrip();
    await theTokenDoorsRoundTrip();
    await theDirectoryAndSignOutDoorsRoundTrip();
    await theAdminRolesRoundTrip();
    const candidate = await theConfigurationDoorsRoundTrip(doc);
    await theConfigurationChangeReachesTheStore(candidate);
    everyDocumentedOperationWasDriven(doc);
    everyAcceptedWriteWasReadBack();
  } finally {
    await removeTheThrowawayRealm();
  }
  log.info("Test completed successfully. The store was in `" +
           persistenceMode + "` mode for this run.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_admin_api_operations")
  .description("Drive every operation of the mock STS's management API at " +
      "/admin-api for real: replay each documented example, round-trip each " +
      "write through a read, and check that a configuration change reaches " +
      "the persistence store.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // tests/jwk_pem_encoding.js fails the suite if a job does not declare it.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
