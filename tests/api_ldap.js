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
// **AND THE SAME WORKFLOW OVER LDAPS.** The mock's directory answers on two raw
// sockets — plain 389 and TLS-from-the-first-byte 636 — and they are one directory:
// one store, one set of handlers, registered on two ldapjs server objects because
// that library decides between a net.Server and a tls.Server at construction. The
// failure that arrangement invites is a handler that lands on one instance and not
// the other, which presents as an operation that works in the clear and fails over
// TLS — read as a TLS fault, which it is not. So section 11 runs bind, add a user,
// add a group, put the user in it and modify the user against 636, then READS THE
// RESULT BACK OVER 389: the cross-socket read is the assertion, because everything
// else in that section would still pass against two directories that shared a port
// number and nothing else. It also pins the two facts about that listener that a
// client would otherwise learn wrongly — TLS does not make the password checked
// (every bind still succeeds, and "invalid" is still 49), and no CLIENT certificate
// is ever asked for there — and the one about its certificate: verification is ON by
// default in the api and a self-signed certificate is refused, so the workflow passes
// rejectUnauthorized: false deliberately and the negative is asserted rather than
// assumed. It is here rather than in a test of its own because a second file would
// duplicate every helper in this one and would still be testing the same directory.
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
// **Services needed:** the api, and the mock STS (its HTTP side and its two LDAP
// listeners — the LDAPS section skips on its own if 636 never bound, which is the
// ordinary outcome of a host run that is not root, while the rest of the file runs).
// No browser. It SKIPS with a named reason for each missing piece,
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
// Both are for the LDAPS section only, and both are node's own: `tls` opens one
// connection to port 636 to see WHICH certificate that socket serves — a question
// no HTTP page can answer about itself — and `crypto` turns the PEM the mock
// publishes over HTTP into the same SHA-256 fingerprint so the two can be compared.
const tls = require("tls");
const crypto = require("crypto");
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
// The same directory over TLS, again as the API must reach it. Left EMPTY by
// default rather than defaulted to ldaps://sts:636, because the port is the one
// thing this test should not guess: the mock publishes which port its LDAPS socket
// actually bound on GET /ldap, and a host run moves it (636 is privileged, so
// LDAPS_PORT=1636 is the usual answer — which is why the api's ldapAllowedPorts
// carries 1636 as well as 636). So the URL is BUILT below from the host of
// LDAP_URL, which is the api's view of the mock, and the port the mock reports.
// Setting LDAPS_URL overrides the whole of that for a deployment where the two
// sockets are not on the same host name.
var ldapsUrl = process.env.LDAPS_URL || "";
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
// The LDAPS section's own names. Separate from the two above rather than reusing
// them after the deletes in section 7, so that a failure names which transport
// created the entry it is complaining about — and so the two sections do not have
// to run in a particular order.
var uidTls = "dbg-tls-" + stamp;
var groupCnTls = "dbg-tls-group-" + stamp;
var userDnTls = "uid=" + uidTls + "," + usersDn;
var groupDnTls = "cn=" + groupCnTls + "," + groupsDn;

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


// ---------------------------------------------------------------------------
// 11. THE SAME DIRECTORY OVER LDAPS (port 636).
//
// Two sockets, one directory. The mock registers every handler on TWO ldapjs
// server objects — ldapjs picks a net.Server or a tls.Server at CONSTRUCTION, so
// TLS cannot be an option on one server — and the defect that arrangement invites
// is a handler registered on one instance and not the other. Its symptom is an
// operation that works in the clear and fails over TLS, which everybody reads as
// a TLS fault and nobody reads as a missing route.
//
// So the five operations are run over 636 and the RESULT IS READ BACK OVER 389.
// That last step is the assertion the rest of the section cannot make: bind, add,
// add, modify and modify all succeeding over TLS is equally consistent with a
// SECOND directory living behind 636, which would be a far worse bug than the one
// being looked for and completely invisible from this side.
//
// Three other things are pinned here because a client that learned them wrongly
// would carry the mistake to a real directory:
//
//  * **TLS is not authentication.** Every bind still succeeds and the literal
//    password `invalid` is still 49. Encryption changed what is on the wire, not
//    whether anything checks it — and "it is over LDAPS" is exactly the sentence
//    people substitute for "it is authenticated".
//  * **Certificate verification is ON by default in the api**, and the mock's
//    certificate is self-signed and regenerated on every start. So the workflow
//    passes `rejectUnauthorized: false` deliberately, and the refusal without it
//    is asserted rather than assumed: a client that quietly stopped verifying
//    would pass every other assertion in this file.
//  * **One certificate serves all of this service's TLS sockets** — 8443, 9443 and
//    636 — so trusting this mock is one fetch of GET /tls/server-certificate and
//    not three. That is checked from both ends: against what the mock SAYS it
//    serves, and against what the socket actually presents.
// ---------------------------------------------------------------------------

// The LDAPS URL, built from the api's view of the host and the port the mock says
// it bound. See the note beside `ldapsUrl` at the top for why this is not a
// constant.
function ldapsUrlFrom(described) {
  log.debug("Entering ldapsUrlFrom().");
  if (ldapsUrl) {
    log.debug("Leaving ldapsUrlFrom(). LDAPS_URL was set.");
    return ldapsUrl;
  }
  // The host of LDAP_URL, with any port and any path taken off. That URL is the
  // API's view of the directory, which on the containerized stack is neither this
  // test's view nor the browser's.
  const host = String(ldapUrl).replace(/^ldaps?:\/\//i, "").replace(/[/?#].*$/, "")
      .replace(/:\d+$/, "");
  const port = described.tls.port || 636;
  log.debug("Leaving ldapsUrlFrom(). Built one.");
  return "ldaps://" + host + ":" + port;
}

// A connection to the LDAPS listener. `rejectUnauthorized: false` is here rather
// than being the api's default: the api verifies unless it is explicitly told not
// to, and the mock's certificate is self-signed and regenerated every start, so
// there is nothing a truststore could hold between runs. The negative below is
// what keeps that flag honest.
function secureConnection() {
  log.debug("Entering secureConnection().");
  log.debug("Leaving secureConnection().");
  return { url: ldapsUrl, bindDn: bindDn, password: password,
           rejectUnauthorized: false };
}

// SHA-256 over the DER inside a PEM, formatted the way node and the mock both
// format a certificate fingerprint: uppercase hex, colon separated.
function fingerprintOf(pem) {
  log.debug("Entering fingerprintOf().");
  const der = Buffer.from(String(pem).replace(/-----[^-]+-----/g, "")
      .replace(/\s+/g, ""), "base64");
  const hex = crypto.createHash("sha256").update(der).digest("hex")
      .toUpperCase();
  log.debug("Leaving fingerprintOf().");
  return (hex.match(/.{2}/g) || []).join(":");
}

// What the LDAPS socket actually presents, from THIS test's view of the mock —
// the host of STS_URL, which preconditions() has already proved reachable, and the
// port the mock published. Resolves to null when the socket cannot be reached from
// here, which is a real possibility on a deployment that publishes the mock's HTTP
// port and not its directory: that is a gap in what this test can see rather than
// a failure, and it is logged as one.
function peerCertificateOverLdaps(port) {
  log.debug("Entering peerCertificateOverLdaps(). port=" + port);
  const host = new URL(stsUrl).hostname;
  log.debug("Leaving peerCertificateOverLdaps(). The promise is pending.");
  return new Promise(function (resolve) {
    let settled = false;
    function finish(value, why) {
      if (settled) return;
      settled = true;
      if (why) log.warn(why);
      resolve(value);
    }
    const socket = tls.connect({
      host: host, port: port, servername: host,
      // The certificate is self-signed by design, and this connection exists to
      // LOOK at it rather than to trust it. Nothing is sent over this socket.
      rejectUnauthorized: false
    }, function () {
      const cert = socket.getPeerCertificate();
      socket.end();
      finish(cert && cert.fingerprint256 ? cert : null,
        cert && cert.fingerprint256 ? "" : "the LDAPS socket at " + host + ":" +
          port + " presented no certificate this test could read");
    });
    socket.setTimeout(5000, function () {
      socket.destroy();
      finish(null, "the LDAPS socket at " + host + ":" + port + " did not " +
        "complete a handshake within 5s from THIS test's view of the mock; the " +
        "api reached it perfectly well, so the certificate check is skipped " +
        "rather than failed");
    });
    socket.on("error", function (e) {
      finish(null, "could not open TLS to " + host + ":" + port + " from this " +
        "test (" + e.message + "). The api reached the same directory, so this " +
        "is this test's view of the mock rather than a broken listener — the " +
        "certificate check is skipped and the rest of the LDAPS section stands");
    });
  });
}

async function theSameDirectoryAnswersOverLdaps(described) {
  log.debug("Entering theSameDirectoryAnswersOverLdaps().");
  log.info("=== LDAPS ===");

  // Three different reasons to skip, and they send you to three different places.
  // `tls` was a BOOLEAN false on the mock before LDAPS existed, so an old sts/
  // gitlink is told apart from a listener that failed to bind.
  if (!described.tls || typeof described.tls !== "object") {
    log.warn("SKIP (LDAPS): this mock publishes tls=" +
             JSON.stringify(described.tls) + " on GET /ldap, which is the shape " +
             "it had before it offered LDAPS — the sts/ gitlink predates it.");
    log.debug("Leaving theSameDirectoryAnswersOverLdaps(). No LDAPS in the mock.");
    return;
  }
  if (!described.tls.ldaps) {
    log.warn("SKIP (LDAPS): the mock is not offering LDAPS at all (" +
             (described.tls.error || "no reason was published") + "). It serves " +
             "the certificate its TLS endpoint generates, so this is a mock " +
             "whose TLS module produced none rather than a port problem.");
    log.debug("Leaving theSameDirectoryAnswersOverLdaps(). Not offered.");
    return;
  }
  if (!described.tls.listening) {
    log.warn("SKIP (LDAPS): the mock's LDAPS listener is not up: " +
             (described.tls.error || "it never bound") + ". 636 is privileged " +
             "exactly as 389 is, so a host run that is not root lands here; set " +
             "LDAPS_PORT on the mock (1636 is already in the api's " +
             "ldapAllowedPorts) to move it. The plain listener is a separate " +
             "socket and the rest of this file has just used it.");
    log.debug("Leaving theSameDirectoryAnswersOverLdaps(). Not listening.");
    return;
  }
  ldapsUrl = ldapsUrlFrom(described);
  log.info("the directory's second socket is " + ldapsUrl +
           " as the api must reach it");

  // --- the bind, which TLS does not make into a check ----------------------
  const bound = await call("/ldap/bind", secureConnection());
  assertSucceeded(bound, "a simple bind over LDAPS");
  assert.strictEqual(bound.body.target.secure, true,
    "the answer must report the connection as SECURE. It is the one field that " +
    "distinguishes this exchange from the identical one on 389, and a debugger " +
    "that cannot say whether a bind was encrypted is answering the wrong " +
    "question. Got " + JSON.stringify(bound.body.target));
  assert.strictEqual(bound.body.target.port, described.tls.port,
    "and on the port the mock published, so that a run against a moved " +
    "listener says which one it reached.");
  assert.ok(!JSON.stringify(bound.body).includes(password),
    "the password must not come back from this endpoint either. TLS is why it " +
    "was not readable on the wire; it says nothing about what the api echoes.");

  const anonymousTls = await call("/ldap/bind",
    { url: ldapsUrl, bindDn: "", password: "", rejectUnauthorized: false });
  assertSucceeded(anonymousTls, "an anonymous bind over LDAPS");

  const refusedTls = await call("/ldap/bind",
    { url: ldapsUrl, bindDn: bindDn, password: "invalid",
      rejectUnauthorized: false });
  assertRefused(refusedTls, 49,
    "a bind over LDAPS with the literal password \"invalid\"");
  log.info("LDAPS bind: still every password but \"invalid\", which is still " +
           "49. TLS changed what is on the wire and not whether it is checked.");

  // --- create a user -------------------------------------------------------
  const addUser = secureConnection();
  addUser.dn = userDnTls;
  addUser.attributes = {
    objectClass: ["top", "person", "organizationalPerson", "inetOrgPerson"],
    uid: [uidTls],
    cn: ["Debugger over TLS " + stamp],
    sn: ["Debugger"],
    mail: [uidTls + "@sts-mock.example"],
    title: ["Created over LDAPS by tests/api_ldap.js"]
  };
  assertSucceeded(await call("/ldap/add", addUser),
    "adding " + userDnTls + " over LDAPS");

  // --- create a group ------------------------------------------------------
  const addGroup = secureConnection();
  addGroup.dn = groupDnTls;
  addGroup.attributes = {
    objectClass: ["top", "groupOfNames"],
    cn: [groupCnTls],
    description: ["Created over LDAPS by tests/api_ldap.js"],
    // A groupOfNames must have a member (RFC 4519), so it is seeded with an
    // entry that already exists — the same reason section 4 gives.
    member: ["uid=alice," + usersDn]
  };
  assertSucceeded(await call("/ldap/add", addGroup),
    "adding " + groupDnTls + " over LDAPS");

  // --- put the user in the group, which is a modify ON THE GROUP -----------
  const join = secureConnection();
  join.dn = groupDnTls;
  join.changes = [{ operation: "add", type: "member", values: [userDnTls] }];
  const joined = await call("/ldap/modify", join);
  assertSucceeded(joined, "adding " + userDnTls + " to " + groupDnTls +
    " over LDAPS");
  assert.strictEqual(joined.body.request.dn, groupDnTls,
    "membership is a modify on the GROUP over TLS exactly as it is in the " +
    "clear — the transport does not move it to the user.");

  // --- modify the user -----------------------------------------------------
  const change = secureConnection();
  change.dn = userDnTls;
  change.changes = [
    { operation: "replace", type: "title", values: ["Staff Engineer over TLS"] },
    { operation: "add", type: "telephoneNumber", values: ["+1 555 0636"] }
  ];
  assertSucceeded(await call("/ldap/modify", change),
    "modifying " + userDnTls + " over LDAPS");

  // --- AND NOW READ IT BACK OVER 389 ---------------------------------------
  //
  // The assertion this whole section exists for. Everything above is equally
  // consistent with a second, separate directory behind 636; only a read from
  // the OTHER socket can tell the two apart, and "one store, two listeners" is
  // precisely what the mock claims.
  const readBack = connection();
  readBack.baseDn = userDnTls;
  readBack.scope = "base";
  readBack.filter = "(objectClass=*)";
  readBack.attributes = ["title", "telephoneNumber", "mail"];
  const plainRead = await call("/ldap/search", readBack);
  assertSucceeded(plainRead, "reading " + userDnTls + " back over PLAIN LDAP");
  assert.strictEqual(plainRead.body.entryCount, 1,
    "an entry created over LDAPS must be there when the plain listener is " +
    "asked for it. If this is noSuchObject, 636 is answering from a store of " +
    "its own — two directories sharing a base DN, which every other assertion " +
    "in this section would pass. Got " + JSON.stringify(dnsOf(plainRead)));
  const byLowerName = {};
  Object.keys(plainRead.body.entries[0].attributes).forEach(function (name) {
    byLowerName[name.toLowerCase()] =
      plainRead.body.entries[0].attributes[name];
  });
  assert.deepStrictEqual(byLowerName.title, ["Staff Engineer over TLS"],
    "and the modify sent over TLS must be visible in the clear, with `replace` " +
    "meaning replace on both listeners. Got " + JSON.stringify(byLowerName.title));
  assert.deepStrictEqual(byLowerName.telephonenumber, ["+1 555 0636"],
    "as must the `add`.");

  const readGroup = connection();
  readGroup.baseDn = groupDnTls;
  readGroup.scope = "base";
  readGroup.filter = "(objectClass=*)";
  readGroup.attributes = ["member"];
  const plainGroup = await call("/ldap/search", readGroup);
  assertSucceeded(plainGroup, "reading " + groupDnTls + " back over PLAIN LDAP");
  const members = (plainGroup.body.entries[0].attributes.member || [])
    .map(function (v) { return String(v).toLowerCase(); });
  assert.ok(members.includes(userDnTls.toLowerCase()),
    "and the membership added over TLS must be in the group the plain " +
    "listener reads. Got " + JSON.stringify(members));
  log.info("LDAPS: five operations over 636, all of them visible on 389. One " +
           "store, two sockets.");

  // --- what happens when verification is left ON ---------------------------
  //
  // Not a curiosity: every call above passed `rejectUnauthorized: false`, and an
  // api that had stopped verifying certificates altogether would answer all of
  // them identically. This is the only assertion in the file that would notice.
  const verified = await call("/ldap/bind",
    { url: ldapsUrl, bindDn: bindDn, password: password });
  assert.strictEqual(verified.status, 502,
    "with verification left at its default the api must REFUSE this " +
    "connection: the mock's certificate is self-signed and regenerated every " +
    "start, so nothing in a truststore can vouch for it. A 200 here means " +
    "certificates are not being verified at all — which would make every " +
    "`rejectUnauthorized: false` above a no-op and the setting a decoration. " +
    "Got " + verified.status + " " +
    JSON.stringify(verified.body).slice(0, 300));
  assert.ok(/certificate|self.signed|verif/i.test(String(verified.body.error)),
    "and it must say that the CERTIFICATE was the problem. \"Could not " +
    "connect\" for a refused certificate sends somebody to look at the network " +
    "for a trust decision. Got " + JSON.stringify(verified.body));

  // --- one certificate for all of this mock's TLS sockets ------------------
  const pem = await fetch(stsUrl + "/tls/server-certificate");
  assert.ok(pem.ok, "GET /tls/server-certificate should answer 200; got " +
            pem.status + ". It is where a caller gets the anchor for all three " +
            "of this mock's TLS sockets, so a directory that cannot be trusted " +
            "without it is a directory nobody can verify.");
  const published = fingerprintOf(await pem.text());
  assert.strictEqual(described.tls.certificate.fingerprint256, published,
    "GET /ldap says LDAPS serves the certificate the HTTPS listeners publish, " +
    "and that claim is what tells a caller ONE fetch is enough. If the two " +
    "fingerprints differ, the directory has generated a keypair of its own and " +
    "an ldapsearch against a truststore built for 8443 fails with `unable to " +
    "get local issuer certificate` — an error that names nothing and reads as " +
    "a broken directory. Published " + published + ", claimed " +
    described.tls.certificate.fingerprint256);

  // --- and take the two entries away again, over the same socket -----------
  //
  // Not merely tidiness, though a directory capped at 2000 entries that grows by
  // two on every run of this file is a reason on its own: delete is the one
  // operation left that this section has not sent over TLS, and it is the one
  // whose failure would be least visible — a delete that answered success on 636
  // while leaving the entry behind would look exactly like a passing test.
  const removeUserTls = secureConnection();
  removeUserTls.dn = userDnTls;
  assertSucceeded(await call("/ldap/delete", removeUserTls),
    "deleting " + userDnTls + " over LDAPS");
  const removeGroupTls = secureConnection();
  removeGroupTls.dn = groupDnTls;
  assertSucceeded(await call("/ldap/delete", removeGroupTls),
    "deleting " + groupDnTls + " over LDAPS");
  const gone = connection();
  gone.baseDn = usersDn;
  gone.scope = "one";
  gone.filter = "(uid=" + uidTls + ")";
  const nothing = await call("/ldap/search", gone);
  assertSucceeded(nothing, "looking for " + userDnTls + " after the delete");
  assert.strictEqual(nothing.body.entryCount, 0,
    "and the plain listener must agree it is gone. A delete that answered " +
    "success over TLS and left the entry in the store would look identical " +
    "from 636 and identical to a passing test. Got " +
    JSON.stringify(dnsOf(nothing)));

  const presented = await peerCertificateOverLdaps(described.tls.port);
  if (presented) {
    assert.strictEqual(presented.fingerprint256, published,
      "and the socket must actually PRESENT it. The two checks are different " +
      "claims: the one above is what the mock says about itself, this is what " +
      "636 hands a client during the handshake, and only the second is what a " +
      "truststore will be judged against. Presented " +
      presented.fingerprint256 + ", published " + published);
    log.info("LDAPS certificate: 636 presents the same certificate " +
             "/tls/server-certificate publishes, so trusting this mock is one " +
             "fetch and not three.");
  }
  log.debug("Leaving theSameDirectoryAnswersOverLdaps().");
}

// ---------------------------------------------------------------------------
// 12. A POPULATED DIRECTORY: 20 users, 10 groups, and one user in all of them.
//
// Everything above this point is one user and one group, which is the right
// shape for asserting what an operation MEANS and the wrong shape for asserting
// anything about a set. Three defects survive a one-of-each workflow untouched,
// and each of them is the kind that shows up first in somebody else's directory
// with a few hundred entries in it:
//
//  1. **A SEARCH THAT SILENTLY RETURNS FEWER ENTRIES THAN MATCHED.** There are
//     three caps between this test and the store — the api's `ldapMaxEntries`
//     and `maxContentLength`, and the mock's own LDAP_SIZE_LIMIT — and the
//     honest answer to hitting one is `sizeLimitExceeded` (4). The dishonest
//     one is a truncated list with result 0, which is indistinguishable from a
//     directory that holds exactly that many. With one user in the directory no
//     cap is anywhere near, so this cannot be seen at all; with twenty it is
//     one assertion. That is why the counts below are `strictEqual` and not
//     `ok(length >= 1)`.
//  2. **MEMBERSHIP THAT IS NOT PER-GROUP.** Ten groups with two members each
//     will pass "the group contains the user" for every group even if the
//     modify wrote to the wrong one, or to all of them, or if the api reused a
//     connection's last DN. So each group is read back and its member list is
//     compared for EXACT EQUALITY against the two users that belong in it —
//     a superset is a failure here, which is the only arrangement in which one
//     group's members leaking into another is visible.
//  3. **THE REVERSE LOOKUP AT FAN-OUT.** Section 5 asserts both directions with
//     one user in one group, where "the groups of a user" and "this one group"
//     are the same answer and a filter that ignored its `member` clause would
//     pass. Here one user is in TEN groups and every other user is in exactly
//     ONE, so a `(member=...)` filter that matches too much and one that matches
//     too little give different wrong answers, and neither is the right one.
//
// The pivot user is deliberately one of the twenty rather than a twenty-first,
// which makes ONE of the ten joins a re-add of a value that is already there.
// That is worth having on purpose: RFC 4511 section 4.6 makes adding an
// existing value `attributeOrValueExists` (20), **and this mock does not do
// that** — its modify handler filters values it already holds and answers
// success. The divergence is asserted rather than worked around, because a
// client that learns "re-adding a member is harmless" here will hit 20 the
// first time it points at a real directory, and a test that quietly avoided the
// case would be why nobody knew.
//
// Cost: about ninety round trips, each of which opens a connection in the api.
// They are sequential rather than concurrent so that a failure names the entry
// it happened on instead of one of twenty in flight.
//
// NOTE ON THE COUNTS. The brief for this section said twenty users, ten groups,
// two unique users per group — which uses each of the twenty exactly once — and
// then "one of the users in all 20 groups". There are ten groups, so the pivot
// joins TEN. Nothing here creates twenty groups; if that was the intent it is a
// one-line change to GROUP_COUNT and the pairing arithmetic follows it.
// ---------------------------------------------------------------------------
const USER_COUNT = 20;
const GROUP_COUNT = 10;
// Which of the twenty is in every group. Zero-based, so this is the first user —
// and therefore also one of the two that belong to the first group, which is
// what makes that join a duplicate. See above.
const PIVOT = 0;

// This section's own names, built from the same per-run stamp as everything
// else. The `pop` infix keeps them out of the way of the other sections' `dbg-`
// and `dbg-tls-` entries, so a filter here cannot pick one of those up and a
// failure names which section built the entry it is complaining about.
var popUid = function (n) {
  return "dbg-pop-" + stamp + "-" + String(n + 1).padStart(2, "0");
};
var popUserDn = function (n) {
  return "uid=" + popUid(n) + "," + usersDn;
};
var popGroupCn = function (n) {
  return "dbg-pop-group-" + stamp + "-" + String(n + 1).padStart(2, "0");
};
var popGroupDn = function (n) {
  return "cn=" + popGroupCn(n) + "," + groupsDn;
};
// Group g holds users 2g and 2g+1. Written once and read everywhere below,
// because the pairing is the thing every assertion in this section is about and
// a second copy of the arithmetic would be a second chance to get it wrong.
function pairFor(g) {
  return [2 * g, 2 * g + 1];
}

// The `member` values of one entry, lower-cased and sorted, as the comparable
// thing. Sorted because RFC 4511 puts no order on the values of an attribute —
// a directory may return them however it likes, and an assertion that depended
// on the order would be asserting an implementation detail.
async function memberDnsOf(dn) {
  log.debug("Entering memberDnsOf(). dn=" + dn);
  const read = connection();
  read.baseDn = dn;
  read.scope = "base";
  read.filter = "(objectClass=*)";
  read.attributes = ["member"];
  const answer = await call("/ldap/search", read);
  assertSucceeded(answer, "reading the members of " + dn);
  assert.strictEqual(answer.body.entryCount, 1,
    "a base-scoped read of " + dn + " returns exactly that entry.");
  const attrs = answer.body.entries[0].attributes;
  // Case-insensitively, for the reason section 3 gives: what comes back is the
  // directory's spelling of the attribute description, not the caller's.
  let values = [];
  Object.keys(attrs).forEach(function (name) {
    if (name.toLowerCase() === "member") {
      values = attrs[name];
    }
  });
  const out = values.map(function (v) { return String(v).toLowerCase(); }).sort();
  log.debug("Leaving memberDnsOf(). " + out.length + " member(s).");
  return out;
}

async function aPopulatedDirectory(limits) {
  log.debug("Entering aPopulatedDirectory().");
  log.info("=== Populate: " + USER_COUNT + " users, " + GROUP_COUNT +
           " groups, " + popUid(PIVOT) + " in all of them ===");

  // The caps have to be BIGGER than what this section is about to build, or the
  // counts below would fail for a reason that is not a defect. Checked and named
  // rather than assumed: "expected 20, got 10" against an api configured with
  // ldapMaxEntries: 10 sends somebody looking for a directory bug that is not
  // there. Skipped rather than failed, because a cap this low is a deployment's
  // choice and the rest of the file still stands.
  const cap = (limits && limits.limits && limits.limits.maxEntries) || 0;
  if (cap && cap <= USER_COUNT) {
    log.warn("SKIP section 12: the api returns at most " + cap + " entries " +
             "(ldapMaxEntries) and this section needs to read back " +
             USER_COUNT + ". Raise it, or accept that the fan-out is " +
             "unchecked in this deployment.");
    log.debug("Leaving aPopulatedDirectory(). Skipped: the cap is too low.");
    return;
  }

  // --- the twenty users --------------------------------------------------
  for (let n = 0; n < USER_COUNT; n++) {
    const body = connection();
    body.dn = popUserDn(n);
    body.attributes = {
      objectClass: ["top", "person", "organizationalPerson", "inetOrgPerson"],
      uid: [popUid(n)],
      cn: ["Populated " + (n + 1)],
      sn: ["Populated"],
      mail: [popUid(n) + "@sts-mock.example"],
      // The one attribute that says which section built this entry, for
      // somebody reading /ldap/directory or /admin/groups after a failed run
      // and wondering where thirty objects came from.
      title: ["Created by tests/api_ldap.js section 12"]
    };
    assertSucceeded(await call("/ldap/add", body), "adding " + popUserDn(n));
  }
  log.info(USER_COUNT + " users created under " + usersDn + ".");

  // --- the ten groups, each seeded with the FIRST of its two users --------
  //
  // Seeded with one of its own rather than with `uid=alice`: a groupOfNames MUST
  // carry at least one member (RFC 4519), and borrowing a seeded entry for that
  // would put a value in every group that the exact-equality assertions below
  // would then have to make an exception for — an exception being exactly the
  // hole through which a leaked member would travel unnoticed.
  for (let g = 0; g < GROUP_COUNT; g++) {
    const first = pairFor(g)[0];
    const create = connection();
    create.dn = popGroupDn(g);
    create.attributes = {
      objectClass: ["top", "groupOfNames"],
      cn: [popGroupCn(g)],
      description: ["Created by tests/api_ldap.js section 12"],
      member: [popUserDn(first)]
    };
    assertSucceeded(await call("/ldap/add", create), "adding " + popGroupDn(g));
  }
  log.info(GROUP_COUNT + " groups created under " + groupsDn + ".");

  // --- the second of each pair, which is a modify ON THE GROUP ------------
  for (let g = 0; g < GROUP_COUNT; g++) {
    const second = pairFor(g)[1];
    const join = connection();
    join.dn = popGroupDn(g);
    join.changes = [{ operation: "add", type: "member",
                      values: [popUserDn(second)] }];
    const joined = await call("/ldap/modify", join);
    assertSucceeded(joined, "adding " + popUserDn(second) + " to " +
      popGroupDn(g));
    assert.strictEqual(joined.body.request.dn, popGroupDn(g),
      "the modify must be sent to the GROUP. Section 4 asserts this once; it " +
      "is asserted again per group here because the failure this catches at " +
      "scale is different — a request DN that came from the LAST call rather " +
      "than from this one is invisible when there is only ever one group.");
  }

  // --- and the pivot user into every one of them --------------------------
  //
  // Including group 0, which already lists them. See the header: that add is a
  // duplicate, a real directory answers 20, and this one answers success — so
  // the assertion is on the SUCCESS and, immediately below, on the member list
  // not having grown.
  const pivotDn = popUserDn(PIVOT);
  for (let g = 0; g < GROUP_COUNT; g++) {
    const join = connection();
    join.dn = popGroupDn(g);
    join.changes = [{ operation: "add", type: "member", values: [pivotDn] }];
    const joined = await call("/ldap/modify", join);
    const duplicate = pairFor(g).indexOf(PIVOT) >= 0;
    assertSucceeded(joined, "adding " + pivotDn + " to " + popGroupDn(g) +
      (duplicate ? " (which already lists them)" : ""));
    if (duplicate) {
      log.info("re-adding " + pivotDn + " to " + popGroupDn(g) + " — a value " +
               "the group already holds — answered LDAP success. RFC 4511 " +
               "section 4.6 makes that attributeOrValueExists (20); this mock " +
               "filters the value instead. Asserted so the divergence is " +
               "recorded rather than discovered against a real directory.");
    }
  }
  log.info(pivotDn + " added to all " + GROUP_COUNT + " groups.");

  // --- every user is there, and there are exactly twenty of them ----------
  //
  // `one` rather than `sub`, and a substring filter on this run's own prefix, so
  // the count is a count of what this section built and not of whatever else the
  // directory has accumulated — the mock's store lives for the life of its
  // process and another test, or a previous run, may have left entries in it.
  const readUsers = connection();
  readUsers.baseDn = usersDn;
  readUsers.scope = "one";
  readUsers.filter = "(uid=dbg-pop-" + stamp + "-*)";
  const foundUsers = await call("/ldap/search", readUsers);
  assertSucceeded(foundUsers, "searching for this run's " + USER_COUNT +
    " users");
  const userDns = dnsOf(foundUsers).sort();
  assert.strictEqual(userDns.length, USER_COUNT,
    "exactly " + USER_COUNT + " users must come back. FEWER is the failure " +
    "this section exists for: a cap reached silently returns a short list with " +
    "result 0, which is indistinguishable from a directory that holds that " +
    "many — the honest answer is sizeLimitExceeded (4). MORE means the " +
    "substring filter matched something this run did not create. Got " +
    userDns.length + ": " + JSON.stringify(userDns));
  const expectedUserDns = [];
  for (let n = 0; n < USER_COUNT; n++) {
    expectedUserDns.push(popUserDn(n).toLowerCase());
  }
  assert.deepStrictEqual(userDns, expectedUserDns.sort(),
    "and they must be exactly the twenty that were created, which the count " +
    "alone does not say.");

  // --- and every group ----------------------------------------------------
  const readGroups = connection();
  readGroups.baseDn = groupsDn;
  readGroups.scope = "one";
  readGroups.filter = "(cn=dbg-pop-group-" + stamp + "-*)";
  const foundGroups = await call("/ldap/search", readGroups);
  assertSucceeded(foundGroups, "searching for this run's " + GROUP_COUNT +
    " groups");
  const groupDns = dnsOf(foundGroups).sort();
  const expectedGroupDns = [];
  for (let g = 0; g < GROUP_COUNT; g++) {
    expectedGroupDns.push(popGroupDn(g).toLowerCase());
  }
  assert.deepStrictEqual(groupDns, expectedGroupDns.sort(),
    "exactly the " + GROUP_COUNT + " groups this section created. Got " +
    JSON.stringify(groupDns));

  // --- each group holds EXACTLY the members it should ---------------------
  //
  // Exact equality, not "contains". Every membership defect worth catching at
  // this scale is a SUPERSET — a modify that landed on the wrong group, a
  // connection that reused the previous DN, a pivot added twice — and every one
  // of them passes a "contains" assertion on every group.
  for (let g = 0; g < GROUP_COUNT; g++) {
    const pair = pairFor(g);
    const expected = [popUserDn(pair[0]).toLowerCase(),
                      popUserDn(pair[1]).toLowerCase()];
    if (pair.indexOf(PIVOT) < 0) {
      expected.push(pivotDn.toLowerCase());
    }
    const actual = await memberDnsOf(popGroupDn(g));
    assert.deepStrictEqual(actual, expected.sort(),
      popGroupDn(g) + " must hold exactly " + expected.length + " members: " +
      "its own two users" +
      (pair.indexOf(PIVOT) < 0 ? " and the pivot" :
        " — the pivot being one of them already, which is why re-adding them " +
        "must NOT have produced a third value") + ". Got " +
      JSON.stringify(actual));
  }
  log.info("every group holds exactly its own two users plus the pivot, and " +
           "the pivot's own group holds two rather than three.");

  // --- the reverse lookup, which is where the fan-out is visible -----------
  //
  // There is no attribute on a user that lists their groups — see section 5 —
  // so this is a search of the GROUPS for a `member` value naming the user.
  // Two searches rather than one: the pivot must be found in all ten and any
  // other user in exactly one, and it takes both to tell a filter that matches
  // too much from one that matches too little. Either alone is passed by one of
  // the two wrong implementations.
  const pivotGroups = connection();
  pivotGroups.baseDn = groupsDn;
  pivotGroups.scope = "sub";
  pivotGroups.filter = "(&(cn=dbg-pop-group-" + stamp + "-*)(member=" +
    pivotDn + "))";
  const foundPivotGroups = await call("/ldap/search", pivotGroups);
  assertSucceeded(foundPivotGroups, "searching for the groups of " + pivotDn);
  assert.deepStrictEqual(dnsOf(foundPivotGroups).sort(), expectedGroupDns.sort(),
    "the pivot user must be found in ALL " + GROUP_COUNT + " groups from the " +
    "group end. Got " + JSON.stringify(dnsOf(foundPivotGroups).sort()));

  // A user who is in exactly one. The last of the twenty, so it is the second
  // of its pair — the one added by `modify` rather than seeded at create time,
  // which is the half of the membership path the check above does not reach.
  const loner = USER_COUNT - 1;
  const lonerGroup = popGroupDn(Math.floor(loner / 2));
  const lonerSearch = connection();
  lonerSearch.baseDn = groupsDn;
  lonerSearch.scope = "sub";
  lonerSearch.filter = "(&(cn=dbg-pop-group-" + stamp + "-*)(member=" +
    popUserDn(loner) + "))";
  const foundLoner = await call("/ldap/search", lonerSearch);
  assertSucceeded(foundLoner, "searching for the groups of " + popUserDn(loner));
  assert.deepStrictEqual(dnsOf(foundLoner), [lonerGroup.toLowerCase()],
    popUserDn(loner) + " belongs to exactly one group, " + lonerGroup + ". A " +
    "filter that ignored its `member` clause would answer all " + GROUP_COUNT +
    " here and would still have passed the pivot's search above. Got " +
    JSON.stringify(dnsOf(foundLoner)));

  // --- take it all away again ---------------------------------------------
  //
  // Thirty entries in a store that lives for the life of the mock's process is
  // not a leak that breaks anything, but it is thirty objects in every later
  // `/ldap/directory` and `/admin/groups` a person opens while debugging
  // something else. Groups first, then users, so that nothing is deleted out
  // from under a membership this section still has assertions about — the
  // dangling member that produces is section 7's lesson and is asserted there,
  // once, on purpose.
  for (let g = 0; g < GROUP_COUNT; g++) {
    const remove = connection();
    remove.dn = popGroupDn(g);
    assertSucceeded(await call("/ldap/delete", remove),
      "deleting " + popGroupDn(g));
  }
  for (let n = 0; n < USER_COUNT; n++) {
    const remove = connection();
    remove.dn = popUserDn(n);
    assertSucceeded(await call("/ldap/delete", remove),
      "deleting " + popUserDn(n));
  }

  // And the searches that found them must now find nothing — which is the one
  // assertion that says the deletes reached the store rather than merely
  // answering success. `entryCount` 0 with result 0 is the right answer to a
  // filter that matches nothing; it is not an error.
  const noUsers = await call("/ldap/search", readUsers);
  assertSucceeded(noUsers, "searching for this run's users after the deletes");
  assert.strictEqual(dnsOf(noUsers).length, 0,
    "every user this section created must be gone. Got " +
    JSON.stringify(dnsOf(noUsers)));
  const noGroups = await call("/ldap/search", readGroups);
  assertSucceeded(noGroups, "searching for this run's groups after the deletes");
  assert.strictEqual(dnsOf(noGroups).length, 0,
    "and every group. Got " + JSON.stringify(dnsOf(noGroups)));
  log.info("all " + (USER_COUNT + GROUP_COUNT) + " entries removed again.");
  log.debug("Leaving aPopulatedDirectory().");
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
  await theSameDirectoryAnswersOverLdaps(ready.directory);
  await aPopulatedDirectory(ready.limits);
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
