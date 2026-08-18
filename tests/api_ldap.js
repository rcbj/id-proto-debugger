// File: api_ldap.js
//
// The api's LDAP client (api/ldap_client.js and the eight POST /ldap/*
// endpoints) against the mock STS's embedded directory, over a real TCP socket.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A NODE TEST AND NOT A BROWSER ONE.
//
// LDAP is BER over a TCP socket (RFC 4511). A browser cannot speak it, so the
// whole protocol lives in the api and nothing about the exchange is visible
// from a page. `ldap_page.js` covers the page; this covers the protocol, and
// keeping them apart means a failure names which of the two broke.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS AND WHY EACH ONE EARNS ITS KEEP.
//
// The ten operations the workflow exists for — bind, create a user, delete a
// user, create a group, delete a group, add a user to a group, search users,
// search for the users in a group, search groups, update a user's attributes —
// are the easy half. A test that only did those would pass against an
// implementation with three defects that matter:
//
//  1. **An LDAP RESULT CODE MUST NOT BE AN HTTP ERROR.** `noSuchObject` on a DN
//     that is not there is the answer, not a failure of the endpoint, and the
//     api answers 200 with `ok: false` and the code. An implementation that
//     turned it into a 500 would put the most useful half of this workflow
//     behind an error page, and every "it worked" assertion would still pass.
//     So each negative here asserts the STATUS as well as the code.
//  2. **THE SCOPE HAS TO BE THE SCOPE THAT WAS ASKED FOR.** A wrong scope
//     returns a SUPERSET — every assertion about the contents still holds and
//     only the count differs — which is invisible in exactly the direction that
//     makes it hardest to find. It has already happened twice in this stack, in
//     the mock (ldapjs spells the scopes `single`/`subtree`, not `one`/`sub`)
//     and nearly again in the api. So `one` and `sub` are compared against each
//     other rather than each being checked for "some entries".
//  3. **MEMBERSHIP IS A MODIFY ON THE GROUP.** There is no "add member"
//     operation, and the two questions people ask about membership are answered
//     from opposite ends: the members of a group are read from the GROUP, and
//     the groups of a user are found by searching the GROUPS for a `member`
//     value naming the user. Both directions are asserted, because an
//     implementation that got one right and the other backwards looks correct
//     until somebody asks the other question.
//
// And two properties of the mock directory that the debugger teaches and that
// would be quietly wrong if they regressed: a bind succeeds with ANY password
// except the literal `invalid` (so result code 49 stays reachable), and
// deleting a user does NOT remove it from the groups that list it — referential
// integrity is a directory feature, not a protocol rule, and the dangling
// member is the thing worth seeing.
//
// Finally the auto-created user: LDAP_AUTOCREATE_USERS makes an entry appear
// under ou=users for anybody who authenticates to the mock through ANY
// protocol. That is one hook on one funnel, so it is cheap to break and cheap
// to check — authenticate over OAuth2 and look for the entry over LDAP.
//
// ---------------------------------------------------------------------------
// **Services needed:** the api, and the mock STS (its HTTP side and its LDAP
// listener). No browser. It SKIPS with a named reason for each missing piece,
// including an api or a mock that predates this workflow — "POST /ldap/search
// answered 404" reads as a broken deployment rather than as a build without the
// endpoint, and the two send you to different places.
//
// Every name this test creates is UNIQUE PER RUN. A test that only passes
// against a freshly started service is one nobody can re-run, and the mock's
// directory lives for the life of its process — so a fixed `uid=dave` would be
// `entryAlreadyExists` on the second run. That lesson is recorded in
// tests/CLAUDE.md against webauthn_oidc_mfa.js and applies unchanged here.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_ldap",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var apiUrl = process.env.API_URL || "http://localhost:4000";
// Where the mock's HTTP side is, as THIS TEST must reach it.
var stsUrl = process.env.STS_URL || "http://localhost:8081";
// Where the directory is, as the API must reach it — a different question, and
// on the containerized stack a different answer. It is its own variable rather
// than derived from stsUrl for the same reason KRB5_SPNEGO_URL is: the api
// resolves it, and the api's view of the mock is not the test's.
var ldapUrl = process.env.LDAP_URL || "ldap://sts:389";
var baseDn = process.env.LDAP_BASE_DN || "dc=example,dc=com";
var bindDn = process.env.LDAP_BIND_DN || "cn=admin,dc=example,dc=com";
// Any password works against this directory; this one is not a secret and is
// published on the mock's own GET /ldap page.
var password = process.env.LDAP_PASSWORD || "password!";

var usersDn = "ou=users," + baseDn;
var groupsDn = "ou=groups," + baseDn;

// Unique per run — see the note above about re-runnable tests. Derived from the
// clock and a little randomness rather than from the clock alone, because two
// runs started in the same second on a CI matrix would collide.
var stamp = Date.now().toString(36) +
    Math.floor(Math.random() * 1e6).toString(36);
var uid = "dbg-" + stamp;
var groupCn = "dbg-group-" + stamp;
var userDn = "uid=" + uid + "," + usersDn;
var groupDn = "cn=" + groupCn + "," + groupsDn;

function connection() {
  log.debug("Entering connection().");
  log.debug("Leaving connection().");
  return { url: ldapUrl, bindDn: bindDn, password: password };
}

// One call to the api. Returns the status AND the body, because on these
// endpoints the status is half the assertion — see point 1 above.
async function call(path, body) {
  log.debug("Entering call(). path=" + path);
  let response;
  try {
    response = await fetch(apiUrl + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  } catch (e) {
    // A refused connection arrives as an undici TypeError whose message is
    // "fetch failed" and whose stack is all internals; it names neither the
    // service nor the address.
    log.debug("Leaving call(). The fetch failed.");
    throw new Error("could not reach " + apiUrl + path + ": " +
      (e.cause ? e.cause.message : e.message) +
      ". Is the api running, and is API_URL right?");
  }
  const raw = await response.text();
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (e) {
    // Not JSON — an HTML error page from something in front of the api. The
    // raw text says more than a parse error would.
    payload = { error: raw };
  }
  log.debug("Leaving call(). status=" + response.status);
  return { status: response.status, body: payload };
}

// A shorthand for "this operation must have completed with LDAP success".
function assertSucceeded(answer, what) {
  log.debug("Entering assertSucceeded(). what=" + what);
  assert.strictEqual(answer.status, 200,
    what + " should answer HTTP 200; got " + answer.status + " with " +
    JSON.stringify(answer.body).slice(0, 400));
  assert.strictEqual(answer.body.ok, true,
    what + " should have succeeded; the directory answered " +
    JSON.stringify(answer.body.result) + " " +
    (answer.body.diagnosticMessage || ""));
  assert.strictEqual(answer.body.result.code, 0,
    what + " should be LDAP result 0 (success); got " +
    JSON.stringify(answer.body.result));
  log.debug("Leaving assertSucceeded().");
}

// And "this operation must have been REFUSED BY THE DIRECTORY" — which is a
// completed round trip with a non-zero code, not an HTTP error. The status
// assertion is the point of this helper.
function assertRefused(answer, code, what) {
  log.debug("Entering assertRefused(). what=" + what);
  assert.strictEqual(answer.status, 200,
    what + " is an LDAP RESULT, not a failure of the endpoint, so it must " +
    "still be HTTP 200 — an implementation that turned a result code into a " +
    "500 would put the most useful half of this workflow behind an error " +
    "page. Got " + answer.status + " with " +
    JSON.stringify(answer.body).slice(0, 400));
  assert.strictEqual(answer.body.ok, false,
    what + " should not have succeeded; got " +
    JSON.stringify(answer.body.result));
  assert.strictEqual(answer.body.result.code, code,
    what + " should be LDAP result " + code + "; got " +
    JSON.stringify(answer.body.result));
  log.debug("Leaving assertRefused().");
}

function dnsOf(answer) {
  log.debug("Entering dnsOf().");
  const list = ((answer.body && answer.body.entries) || []).map(
    function (entry) {
      return String(entry.dn || "").toLowerCase();
    });
  log.debug("Leaving dnsOf(). " + list.length + " entry/entries.");
  return list;
}

// ---------------------------------------------------------------------------
// Preconditions. Each answer is a different reason to skip, and naming which
// one matters: "the stack is not up", "this api predates LDAP" and "this mock
// predates its directory" send you to three different places.
// ---------------------------------------------------------------------------
async function preconditions() {
  log.debug("Entering preconditions().");
  let limits;
  try {
    limits = await fetch(apiUrl + "/ldap/limits");
  } catch (e) {
    log.debug("Leaving preconditions(). The api is unreachable.");
    return { ok: false, why: "could not reach the api at " + apiUrl + " (" +
      e.message + ")" };
  }
  if (limits.status === 404) {
    log.debug("Leaving preconditions(). The api has no LDAP endpoints.");
    return { ok: false, why: "the api at " + apiUrl + " answered 404 for " +
      "GET /ldap/limits, so it is a build without the LDAP endpoints rather " +
      "than one that is refusing to answer" };
  }
  if (!limits.ok) {
    log.debug("Leaving preconditions(). The api did not answer.");
    return { ok: false, why: "the api at " + apiUrl + " answered " +
      limits.status + " for GET /ldap/limits" };
  }
  const published = await limits.json();
  let directory;
  try {
    directory = await fetch(stsUrl + "/ldap?format=json");
  } catch (e) {
    log.debug("Leaving preconditions(). The mock is unreachable.");
    return { ok: false, why: "could not reach the mock STS at " + stsUrl +
      " (" + e.message + ")" };
  }
  if (!directory.ok) {
    log.debug("Leaving preconditions(). The mock has no directory.");
    return { ok: false, why: "the mock STS has no embedded LDAP directory (" +
      stsUrl + "/ldap answered " + directory.status + ") — the sts/ gitlink " +
      "probably predates it" };
  }
  const described = await directory.json();
  // The HTTP view answers 200 whether or not the socket bound — 389 is
  // privileged and well known, so "not root" and "the host's own slapd is
  // already there" are both real. Without this check the run would fail at the
  // first bind with a 502 that reads as a broken api rather than as a directory
  // that never came up.
  if (described.listening === false) {
    log.debug("Leaving preconditions(). The listener is down.");
    return { ok: false, why: "the mock STS's LDAP listener is not up: " +
      (described.listenError || "it never bound") + ". Something else " +
      "probably owns port " + described.port + " on that host; set LDAP_PORT " +
      "on the mock and ldapAllowedPorts on the api to move it" };
  }
  log.debug("Leaving preconditions(). Ready.");
  return { ok: true, limits: published, directory: described };
}

// ---------------------------------------------------------------------------
// 1. The bind, and the one password this directory refuses.
// ---------------------------------------------------------------------------
async function theBindAcceptsAnythingExceptOnePassword() {
  log.debug("Entering theBindAcceptsAnythingExceptOnePassword().");
  log.info("=== Bind ===");

  const good = await call("/ldap/bind", connection());
  assertSucceeded(good, "a simple bind with the configured DN");
  assert.strictEqual(good.body.bind.dn, bindDn,
    "the answer should report the DN that was bound, so a debugger can show " +
    "what was actually sent.");
  assert.strictEqual(good.body.bind.passwordChars, password.length,
    "and the LENGTH of the password, because \"did the field reach the api " +
    "at all\" is a real question when a bind fails — while never echoing the " +
    "password itself.");
  assert.ok(!JSON.stringify(good.body).includes(password),
    "the password must appear NOWHERE in the answer. It is the one value on " +
    "this endpoint that must not come back, and an implementation that " +
    "echoed the request wholesale would.");

  const anonymous = await call("/ldap/bind",
    { url: ldapUrl, bindDn: "", password: "" });
  assertSucceeded(anonymous, "an anonymous bind");
  assert.strictEqual(anonymous.body.bind.anonymous, true,
    "and it must be reported AS anonymous rather than as a bind with an " +
    "empty DN, which is the same thing on the wire and a different thing to " +
    "read.");

  const arbitrary = await call("/ldap/bind",
    { url: ldapUrl, bindDn: bindDn, password: "not-the-password-" + stamp });
  assertSucceeded(arbitrary, "a bind with an arbitrary password");

  // The one refusal, and the reason it exists: without it result code 49 is
  // unreachable against this directory and "the bind failed" becomes untestable.
  const refused = await call("/ldap/bind",
    { url: ldapUrl, bindDn: bindDn, password: "invalid" });
  assertRefused(refused, 49, "a bind with the literal password \"invalid\"");
  assert.strictEqual(refused.body.stoppedAt, "bind",
    "and the answer must say the exchange stopped AT the bind, so a reader " +
    "does not go looking for an operation that never ran.");
  log.info("bind: any password is accepted, \"invalid\" is 49, and the " +
           "password is never echoed.");
  log.debug("Leaving theBindAcceptsAnythingExceptOnePassword().");
}

// ---------------------------------------------------------------------------
// 2. Create a user, and read it back.
// ---------------------------------------------------------------------------
async function aUserIsCreated() {
  log.debug("Entering aUserIsCreated().");
  log.info("=== Create user " + userDn + " ===");
  const body = connection();
  body.dn = userDn;
  body.attributes = {
    objectClass: ["top", "person", "organizationalPerson", "inetOrgPerson"],
    uid: [uid],
    cn: ["Debugger " + stamp],
    sn: ["Debugger"],
    mail: [uid + "@sts-mock.example"],
    title: ["Created by tests/api_ldap.js"]
  };
  const added = await call("/ldap/add", body);
  assertSucceeded(added, "adding " + userDn);
  assert.strictEqual(added.body.request.dn, userDn,
    "the answer should report the DN that was sent.");

  // Adding it twice is entryAlreadyExists (68), and it is asserted because it
  // is the refusal a re-run of this test would hit if the names were not
  // unique — so it doubles as a check that they are.
  const again = await call("/ldap/add", body);
  assertRefused(again, 68, "adding " + userDn + " a second time");

  // A parent that does not exist is noSuchObject (32). A directory is a tree,
  // and a client that has never seen this refusal will write its first entry
  // into a real directory and not understand the error.
  const orphan = connection();
  orphan.dn = "uid=x," + "ou=no-such-container," + baseDn;
  orphan.attributes = { objectClass: ["top"], cn: ["x"] };
  assertRefused(await call("/ldap/add", orphan), 32,
    "adding an entry whose parent does not exist");
  log.debug("Leaving aUserIsCreated().");
}

// ---------------------------------------------------------------------------
// 3. Update the user's attributes.
// ---------------------------------------------------------------------------
async function theUsersAttributesAreUpdated() {
  log.debug("Entering theUsersAttributesAreUpdated().");
  log.info("=== Update " + userDn + " ===");
  const body = connection();
  body.dn = userDn;
  body.changes = [
    { operation: "replace", type: "title", values: ["Staff Engineer"] },
    { operation: "add", type: "telephoneNumber", values: ["+1 555 0100"] }
  ];
  assertSucceeded(await call("/ldap/modify", body), "modifying " + userDn);

  const read = connection();
  read.baseDn = userDn;
  read.scope = "base";
  read.filter = "(objectClass=*)";
  read.attributes = ["title", "telephoneNumber", "cn"];
  const answer = await call("/ldap/search", read);
  assertSucceeded(answer, "reading " + userDn + " back");
  assert.strictEqual(answer.body.entryCount, 1,
    "a base-scoped read of one entry returns exactly that entry.");
  const attrs = answer.body.entries[0].attributes;
  // The attribute name is compared case-insensitively: LDAP attribute
  // descriptions are case-insensitive (RFC 4512 section 2.5), and what a
  // directory sends back is its own spelling rather than the caller's.
  const byLowerName = {};
  Object.keys(attrs).forEach(function (name) {
    byLowerName[name.toLowerCase()] = attrs[name];
  });
  assert.deepStrictEqual(byLowerName.title, ["Staff Engineer"],
    "`replace` sets the attribute to exactly the values given. If this comes " +
    "back with the OLD title beside the new one, the change was sent as " +
    "`add` — which is the mistake the page's Users pane exists to make " +
    "visible, since these attributes are multi-valued in the schema even " +
    "where a person thinks of them as single-valued. Got " +
    JSON.stringify(byLowerName.title));
  assert.deepStrictEqual(byLowerName.telephonenumber, ["+1 555 0100"],
    "and `add` puts a value on an attribute that had none.");

  // Deleting an attribute that is not there is noSuchAttribute (16). Asserted
  // because an implementation that treated it as a no-op would look correct on
  // every positive case.
  const missing = connection();
  missing.dn = userDn;
  missing.changes = [{ operation: "delete", type: "employeeNumber",
                       values: [] }];
  assertRefused(await call("/ldap/modify", missing), 16,
    "deleting an attribute the entry does not have");
  log.debug("Leaving theUsersAttributesAreUpdated().");
}

// ---------------------------------------------------------------------------
// 4. Create a group, and put the user in it.
// ---------------------------------------------------------------------------
async function aGroupIsCreatedAndTheUserAddedToIt() {
  log.debug("Entering aGroupIsCreatedAndTheUserAddedToIt().");
  log.info("=== Create group " + groupDn + " and add " + userDn + " ===");
  const create = connection();
  create.dn = groupDn;
  create.attributes = {
    objectClass: ["top", "groupOfNames"],
    cn: [groupCn],
    description: ["Created by tests/api_ldap.js"],
    // A groupOfNames MUST have at least one member (RFC 4519), so it is seeded
    // with an entry that already exists rather than created empty.
    member: ["uid=alice," + usersDn]
  };
  assertSucceeded(await call("/ldap/add", create), "adding " + groupDn);

  // THERE IS NO "ADD MEMBER" OPERATION. Membership is a multi-valued `member`
  // attribute on the GROUP whose values are DNs, so this is a modify — which is
  // the single most useful thing this workflow teaches and the thing an
  // implementation is most likely to get backwards by putting the change on the
  // user.
  const join = connection();
  join.dn = groupDn;
  join.changes = [{ operation: "add", type: "member", values: [userDn] }];
  const joined = await call("/ldap/modify", join);
  assertSucceeded(joined, "adding " + userDn + " to " + groupDn);
  assert.strictEqual(joined.body.request.dn, groupDn,
    "the modify must be sent to the GROUP, not to the user: if this reports " +
    "the user's DN then membership has been implemented on the wrong object " +
    "and will look right only until somebody reads the group.");
  log.debug("Leaving aGroupIsCreatedAndTheUserAddedToIt().");
}

// ---------------------------------------------------------------------------
// 5. The four searches, and the scope that must be the scope asked for.
// ---------------------------------------------------------------------------
async function theSearchesAnswerTheFourQuestions() {
  log.debug("Entering theSearchesAnswerTheFourQuestions().");
  log.info("=== Search ===");

  // Users.
  const users = connection();
  users.baseDn = usersDn;
  users.scope = "sub";
  users.filter = "(objectClass=inetOrgPerson)";
  const foundUsers = await call("/ldap/search", users);
  assertSucceeded(foundUsers, "searching for users");
  assert.ok(dnsOf(foundUsers).includes(userDn.toLowerCase()),
    "the user created above must be among them. Got " +
    JSON.stringify(dnsOf(foundUsers)));

  // Groups.
  const groups = connection();
  groups.baseDn = groupsDn;
  groups.scope = "sub";
  groups.filter = "(objectClass=groupOfNames)";
  const foundGroups = await call("/ldap/search", groups);
  assertSucceeded(foundGroups, "searching for groups");
  assert.ok(dnsOf(foundGroups).includes(groupDn.toLowerCase()),
    "the group created above must be among them. Got " +
    JSON.stringify(dnsOf(foundGroups)));

  // THE USERS IN A GROUP: read from the GROUP, base scope, `member` only.
  const members = connection();
  members.baseDn = groupDn;
  members.scope = "base";
  members.filter = "(objectClass=*)";
  members.attributes = ["member"];
  const readMembers = await call("/ldap/search", members);
  assertSucceeded(readMembers, "reading the members of " + groupDn);
  assert.strictEqual(readMembers.body.entryCount, 1,
    "a base-scoped read returns the base entry and nothing else.");
  const memberAttr = readMembers.body.entries[0].attributes;
  const memberValues = (memberAttr.member || memberAttr.Member || [])
    .map(function (v) { return String(v).toLowerCase(); });
  assert.ok(memberValues.includes(userDn.toLowerCase()),
    "and the user must be in it. Got " + JSON.stringify(memberValues));

  // THE GROUPS A USER IS IN: found from the other end. There is no attribute on
  // the user that lists them — `memberOf` is a Microsoft extension and OpenLDAP
  // has it only behind an overlay — so the groups are searched for a `member`
  // value naming the user. An implementation that got this backwards would
  // still pass the check above, which is why both directions are here.
  const memberships = connection();
  memberships.baseDn = groupsDn;
  memberships.scope = "sub";
  memberships.filter = "(&(objectClass=groupOfNames)(member=" + userDn + "))";
  const foundMemberships = await call("/ldap/search", memberships);
  assertSucceeded(foundMemberships, "searching for the groups of a user");
  assert.ok(dnsOf(foundMemberships).includes(groupDn.toLowerCase()),
    "the group the user was added to must be found this way too. Got " +
    JSON.stringify(dnsOf(foundMemberships)));

  // THE SCOPE MUST BE THE SCOPE ASKED FOR, and this is the assertion that
  // catches the class of bug the scopes invite: a wrong scope returns a
  // SUPERSET, so every assertion about the contents still holds and only the
  // count differs. `one` under ou=users must NOT include ou=users itself, and
  // `sub` must.
  const oneLevel = connection();
  oneLevel.baseDn = usersDn;
  oneLevel.scope = "one";
  oneLevel.filter = "(objectClass=*)";
  const one = await call("/ldap/search", oneLevel);
  assertSucceeded(one, "a one-level search of " + usersDn);
  assert.ok(!dnsOf(one).includes(usersDn.toLowerCase()),
    "a ONE-level search must not return the base entry itself. If it does, " +
    "the scope was read as subtree — which returns a superset, so every " +
    "other assertion still passes and only the count is wrong. Got " +
    JSON.stringify(dnsOf(one)));

  const subtree = connection();
  subtree.baseDn = usersDn;
  subtree.scope = "sub";
  subtree.filter = "(objectClass=*)";
  const sub = await call("/ldap/search", subtree);
  assertSucceeded(sub, "a subtree search of " + usersDn);
  assert.ok(dnsOf(sub).includes(usersDn.toLowerCase()),
    "a SUBTREE search must return the base entry as well as its children.");
  assert.ok(sub.body.entryCount > one.body.entryCount,
    "and it must return more entries than the one-level search did (" +
    sub.body.entryCount + " vs " + one.body.entryCount + ").");

  const baseOnly = connection();
  baseOnly.baseDn = usersDn;
  baseOnly.scope = "base";
  baseOnly.filter = "(objectClass=*)";
  const only = await call("/ldap/search", baseOnly);
  assertSucceeded(only, "a base-scoped search of " + usersDn);
  assert.strictEqual(only.body.entryCount, 1,
    "a BASE search returns exactly one entry — the base itself.");

  // A presence filter must work. Named because it is the one that broke in
  // this stack: `(objectClass=*)` matched NOTHING while `(cn=x)` matched, and
  // the symptom was a successful search returning zero entries, which reads as
  // an empty directory rather than as a filter that could not see it.
  const presence = connection();
  presence.baseDn = baseDn;
  presence.scope = "sub";
  presence.filter = "(objectClass=*)";
  const everything = await call("/ldap/search", presence);
  assertSucceeded(everything, "a presence-filter search of the whole tree");
  assert.ok(everything.body.entryCount > 3,
    "`(objectClass=*)` is a PRESENCE filter and must match every entry. Zero " +
    "or one here means it matched on the attribute name's spelling — LDAP " +
    "attribute descriptions are case-insensitive, and a matcher that " +
    "compares them case-sensitively answers a successful search with no " +
    "entries, which looks like an empty directory. Got " +
    everything.body.entryCount);

  // A base that does not exist is noSuchObject (32) rather than an empty
  // result. The two are genuinely different answers and a client's retry logic
  // depends on telling them apart.
  const nowhere = connection();
  nowhere.baseDn = "ou=nowhere," + baseDn;
  nowhere.scope = "sub";
  nowhere.filter = "(objectClass=*)";
  assertRefused(await call("/ldap/search", nowhere), 32,
    "searching a base that does not exist");
  log.debug("Leaving theSearchesAnswerTheFourQuestions().");
}

// ---------------------------------------------------------------------------
// 6. Compare, which answers neither success nor an error.
// ---------------------------------------------------------------------------
async function compareAnswersTrueOrFalseAndNeitherIsSuccess() {
  log.debug("Entering compareAnswersTrueOrFalseAndNeitherIsSuccess().");
  log.info("=== Compare ===");
  const yes = connection();
  yes.dn = userDn;
  yes.attribute = "sn";
  yes.value = "Debugger";
  const matched = await call("/ldap/compare", yes);
  assert.strictEqual(matched.status, 200,
    "a compare answers HTTP 200 whichever way it goes.");
  assert.strictEqual(matched.body.matched, true,
    "the value is there, so this is compareTrue.");
  assert.strictEqual(matched.body.result.code, 6,
    "compareTrue is result code 6, NOT 0. A compare never answers success, " +
    "which is the detail an implementation reusing the generic success path " +
    "gets wrong. Got " + JSON.stringify(matched.body.result));

  const no = connection();
  no.dn = userDn;
  no.attribute = "sn";
  no.value = "Somebody Else";
  const notMatched = await call("/ldap/compare", no);
  assert.strictEqual(notMatched.status, 200,
    "a compare that does not match is still a completed operation.");
  assert.strictEqual(notMatched.body.matched, false,
    "the value is not there, so this is compareFalse.");
  assert.strictEqual(notMatched.body.result.code, 5,
    "compareFalse is result code 5. Got " +
    JSON.stringify(notMatched.body.result));
  log.debug("Leaving compareAnswersTrueOrFalseAndNeitherIsSuccess().");
}

// ---------------------------------------------------------------------------
// 7. Delete the user, delete the group, and the dangling member between them.
// ---------------------------------------------------------------------------
async function theUserAndGroupAreDeleted() {
  log.debug("Entering theUserAndGroupAreDeleted().");
  log.info("=== Delete ===");

  // A non-leaf is notAllowedOnNonLeaf (66). Asserted against ou=users, which
  // has children throughout this run.
  const nonLeaf = connection();
  nonLeaf.dn = usersDn;
  assertRefused(await call("/ldap/delete", nonLeaf), 66,
    "deleting a container that has children");

  const removeUser = connection();
  removeUser.dn = userDn;
  assertSucceeded(await call("/ldap/delete", removeUser),
    "deleting " + userDn);

  // Deleting it again is noSuchObject (32).
  assertRefused(await call("/ldap/delete", removeUser), 32,
    "deleting " + userDn + " a second time");

  // THE DANGLING MEMBER. The group still lists the DN that is gone, and that is
  // correct: referential integrity is a directory feature, not a protocol rule
  // — OpenLDAP needs an overlay for it and Active Directory does it in the DSA.
  // Asserted so that "tidying it away" is a deliberate change rather than an
  // accident, because tidying it away hides the thing worth seeing.
  const readGroup = connection();
  readGroup.baseDn = groupDn;
  readGroup.scope = "base";
  readGroup.filter = "(objectClass=*)";
  readGroup.attributes = ["member"];
  const after = await call("/ldap/search", readGroup);
  assertSucceeded(after, "reading " + groupDn + " after the delete");
  const remaining = (after.body.entries[0].attributes.member || [])
    .map(function (v) { return String(v).toLowerCase(); });
  assert.ok(remaining.includes(userDn.toLowerCase()),
    "the group must STILL list the deleted user as a member. Referential " +
    "integrity is not part of RFC 4511, and a directory that quietly removed " +
    "the value would be teaching a behaviour most real directories do not " +
    "have. Got " + JSON.stringify(remaining));

  const removeGroup = connection();
  removeGroup.dn = groupDn;
  assertSucceeded(await call("/ldap/delete", removeGroup),
    "deleting " + groupDn);
  log.debug("Leaving theUserAndGroupAreDeleted().");
}

// ---------------------------------------------------------------------------
// 8. What this service refuses to do at all — a 400, not a directory answer.
// ---------------------------------------------------------------------------
async function theApiRefusesWhatItWillNotDo() {
  log.debug("Entering theApiRefusesWhatItWillNotDo().");
  log.info("=== Refusals by the api itself ===");

  // A scheme that is not LDAP. Checked before anything is handed to the
  // library, because a parser that helpfully defaults an unknown scheme has
  // already made the decision.
  const wrongScheme = await call("/ldap/bind",
    { url: "http://" + ldapUrl.replace(/^ldaps?:\/\//, "") });
  assert.strictEqual(wrongScheme.status, 400,
    "an http:// URL is a refusal by THIS service, so it is a 400 rather than " +
    "a 502: the caller asked for something this service will not do. Got " +
    wrongScheme.status + " " + JSON.stringify(wrongScheme.body).slice(0, 200));
  assert.strictEqual(wrongScheme.body.code, "ELDAPBADURL",
    "and it must say which check refused it.");

  // A port outside the allowlist. The whole reason the allowlist exists is
  // that this endpoint opens a socket to a caller-named host and port.
  const wrongPort = await call("/ldap/bind",
    { url: ldapUrl.replace(/:\d+$/, "") + ":22" });
  assert.strictEqual(wrongPort.status, 400,
    "a port outside ldapAllowedPorts is a refusal by this service. Got " +
    wrongPort.status);
  assert.strictEqual(wrongPort.body.code, "ELDAPPORTNOTALLOWED",
    "and it must say which check refused it.");

  // A scope that is not one of the three. Refused here rather than relayed,
  // because a directory answering "protocolError" for it names nothing useful.
  const wrongScope = await call("/ldap/search",
    { url: ldapUrl, baseDn: baseDn, scope: "everything" });
  assert.strictEqual(wrongScope.status, 400,
    "an unknown scope is refused by this service. Got " + wrongScope.status);
  assert.strictEqual(wrongScope.body.code, "ELDAPBADSCOPE",
    "and it must say which check refused it.");

  // An unknown modify operation, likewise.
  const wrongChange = await call("/ldap/modify",
    { url: ldapUrl, dn: userDn,
      changes: [{ operation: "upsert", type: "cn", values: ["x"] }] });
  assert.strictEqual(wrongChange.status, 400,
    "an unknown modify operation is refused by this service. Got " +
    wrongChange.status);
  assert.strictEqual(wrongChange.body.code, "ELDAPBADCHANGE",
    "and it must say which check refused it.");

  // A host that is not there is a NETWORK failure, which is a different thing
  // and gets a different status: the caller asked for something reasonable and
  // the far end did not deliver. Collapsing the two is what makes a debugger
  // unable to tell a mistake from a fact about the directory.
  //
  // The host is `.invalid` — the RFC 2606 reserved TLD, which no resolver
  // answers — rather than a loopback port nothing happens to be listening on.
  // That distinction is not pedantry: this test's first version used
  // 127.0.0.1:1389, which is exactly where a HOST run of the mock puts its
  // directory, so the assertion failed against a perfectly healthy stack and
  // said the api had answered 200 for an unreachable host.
  const dead = await call("/ldap/bind",
    { url: "ldap://no-such-directory.invalid:389" });
  assert.ok(dead.status === 502 || dead.status === 400,
    "an unreachable directory answers 502 (or 400 if the address policy " +
    "refused it first). Got " + dead.status + " " +
    JSON.stringify(dead.body).slice(0, 200));
  assert.ok(dead.body.error,
    "and it must say what happened rather than answering with nothing — the " +
    "no-response branch is the COMMON branch on this endpoint, because " +
    "pointing it at a host that may not be there is the point.");
  log.debug("Leaving theApiRefusesWhatItWillNotDo().");
}

// ---------------------------------------------------------------------------
// 9. An LDAP object for every user who authenticates.
// ---------------------------------------------------------------------------
async function authenticatingAnywhereCreatesAnLdapUser(described) {
  log.debug("Entering authenticatingAnywhereCreatesAnLdapUser().");
  log.info("=== An entry for whoever authenticates ===");
  if (!described.autoCreateUsers) {
    log.warn("LDAP_AUTOCREATE_USERS is off on this mock, so there is nothing " +
             "to check here. It is ON by default; something set it.");
    log.debug("Leaving authenticatingAnywhereCreatesAnLdapUser(). Off.");
    return;
  }
  const who = "ldapuser" + stamp;
  // The OAuth2 password grant, which is the cheapest of the twelve protocol
  // families to drive from a node test. WHICH one is not the point — the hook
  // is on admin_stats.recordAuthentication(), the single funnel all of them go
  // through at the moment the credential is accepted, so one is enough to show
  // the hook is installed and any of them would do.
  const token = await fetch(stsUrl + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=password&username=" + encodeURIComponent(who) +
      "&password=whatever&client_id=api-ldap-test&scope=openid"
  });
  assert.ok(token.ok, "the mock's password grant should answer 200; got " +
            token.status);

  const search = connection();
  search.baseDn = usersDn;
  search.scope = "sub";
  search.filter = "(uid=" + who + ")";
  const found = await call("/ldap/search", search);
  assertSucceeded(found, "searching for the auto-created entry");
  assert.strictEqual(found.body.entryCount, 1,
    "authenticating to the mock through ANY protocol must create " +
    "uid=" + who + "," + usersDn + ". That is one hook on " +
    "admin_stats.recordAuthentication(), which every one of the twelve " +
    "protocol families already calls when a credential is accepted — so if " +
    "this is zero, the hook is not installed rather than one protocol being " +
    "missed. Got " + JSON.stringify(dnsOf(found)));

  // An LDAP bind does NOT seed one, and that is deliberate: a bind presents a
  // DN, which already names an object in this directory, so creating
  // `uid=cn=admin\,dc=example...` from one would be nonsense.
  const before = await call("/ldap/search", {
    url: ldapUrl, bindDn: bindDn, password: password,
    baseDn: usersDn, scope: "one", filter: "(objectClass=*)" });
  assertSucceeded(before, "counting the users before a bind");
  await call("/ldap/bind", {
    url: ldapUrl, bindDn: "cn=nobody-" + stamp + "," + baseDn,
    password: "whatever" });
  const after = await call("/ldap/search", {
    url: ldapUrl, bindDn: bindDn, password: password,
    baseDn: usersDn, scope: "one", filter: "(objectClass=*)" });
  assertSucceeded(after, "counting the users after a bind");
  assert.strictEqual(after.body.entryCount, before.body.entryCount,
    "an LDAP bind must not seed a user entry. The identity a bind presents " +
    "is a DN, not a user name, so an entry created from one would be " +
    "nonsense — and this directory's own binds would grow it without bound. " +
    "Before " + before.body.entryCount + ", after " + after.body.entryCount);
  log.debug("Leaving authenticatingAnywhereCreatesAnLdapUser().");
}

// ---------------------------------------------------------------------------
// 10. What the api publishes about itself.
// ---------------------------------------------------------------------------
async function theLimitsAreHonest(limits) {
  log.debug("Entering theLimitsAreHonest().");
  log.info("=== GET /ldap/limits ===");
  assert.ok(limits.allowedPorts === "any" || Array.isArray(limits.allowedPorts),
    "the allowed ports must be published, so the page can say so before a " +
    "call fails. A debugger that discovers its own limits by hitting them " +
    "reports them as somebody else's fault.");
  assert.deepStrictEqual(limits.scopes, ["base", "one", "sub"],
    "the three RFC 4511 scopes, published so the page builds its dropdown " +
    "from what this service will accept rather than from a list typed twice.");
  assert.deepStrictEqual(limits.modifyOperations,
    ["add", "delete", "replace"],
    "and the three modify operations, for the same reason.");
  assert.strictEqual(limits.followsReferrals, false,
    "a referral is RECORDED and not followed — following one means opening " +
    "a connection to a URL the DIRECTORY chose, which is a server-side " +
    "request forgery with a specification citation attached. It is published " +
    "rather than left to be discovered.");
  assert.ok(limits.limits && limits.limits.connectTimeout > 0 &&
            limits.limits.callTimeout > 0,
    "and both deadlines, which are separate on purpose: a directory that has " +
    "connected is alive and thinking, and a large subtree search legitimately " +
    "takes longer than a connect.");
  assert.ok(limits.limits.maxEntries > 0 && limits.limits.maxResultBytes > 0,
    "and both result caps. Both are needed: a million one-attribute entries " +
    "fits inside a megabyte and is still a million objects, while one entry " +
    "carrying a photograph is one object and is still megabytes.");
  log.debug("Leaving theLimitsAreHonest().");
}

async function test() {
  log.debug("Entering test().");
  const ready = await preconditions();
  if (!ready.ok) {
    log.warn("SKIP: " + ready.why);
    log.info("Test skipped.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("the api is at " + apiUrl + ", the directory it will open is " +
           ldapUrl + " (base " + baseDn + "), and this run's names are " +
           userDn + " and " + groupDn);

  await theLimitsAreHonest(ready.limits);
  await theBindAcceptsAnythingExceptOnePassword();
  await aUserIsCreated();
  await theUsersAttributesAreUpdated();
  await aGroupIsCreatedAndTheUserAddedToIt();
  await theSearchesAnswerTheFourQuestions();
  await compareAnswersTrueOrFalseAndNeitherIsSuccess();
  await theUserAndGroupAreDeleted();
  await theApiRefusesWhatItWillNotDo();
  await authenticatingAnywhereCreatesAnLdapUser(ready.directory);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("api_ldap")
  .description("Verify the api's LDAP client and the eight POST /ldap/* " +
      "endpoints against the mock STS's embedded directory.")
  .addOption(new Option("-a, --api <url>", "base url of the api")
      .default(apiUrl))
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
      "needs no browser)"))
  .parse(process.argv);
apiUrl = program.opts().api || apiUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
