// File: ldap_page.js
//
// client/public/ldap.html — the LDAP Protocol Debugger, driven through its own
// buttons.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS WHEN api_ldap.js ALREADY DRIVES THE PROTOCOL.
//
// That test performs every operation with no browser and covers the protocol
// far harder than this one does — result codes, scopes, the negatives, the
// refusals. What it cannot cover is the things that only exist in a page, and
// each of them is a way for this workflow to be broken while the protocol is
// perfect:
//
//  1. **THE DNs THE SHORTHAND PANES BUILD.** The Users and Groups panes compose
//     `uid=<uid>,ou=users,<base>` and `cn=<cn>,ou=groups,<base>` from four
//     fields. Nothing in the protocol notices if that composition is wrong; the
//     operation simply happens somewhere else, succeeds, and the entry is not
//     where the reader is looking for it. So the page previews both DNs and
//     this test reads the preview as well as the outcome.
//  2. **MEMBERSHIP IS A MODIFY ON THE GROUP.** The single most useful thing
//     this page teaches, and the easiest to implement backwards — putting the
//     change on the user looks right until somebody reads the group. The
//     Exchange pane shows the request that was built, so this asserts against
//     the request and not only against the result.
//  3. **THE FOUR SEARCH PRESETS FILL THE FIELDS.** They exist to make the
//     filter visible, especially the one nobody guesses: the groups a user is
//     in are found by searching the GROUPS for a `member` value naming the
//     user, because there is no attribute on the user to read. A preset that
//     ran a hidden query would teach nothing, and the difference is invisible
//     from the results.
//  4. **A REFUSED OPERATION IS A DIFFERENT THING FROM A FAILED CALL.** A
//     `noSuchObject` is a completed round trip whose answer was "no". The page
//     has to show the result code rather than an error, and its Operations
//     History has to distinguish Failure (the directory said no) from Sent (the
//     api never answered) — which are the two states people most often confuse.
//
// And one thing that is neither: **the password is never written to
// localStorage.** Every other field on the page is remembered. That is the
// project-wide rule and it is checked here because nothing else can see it.
//
// **Services needed:** the client, the api and the mock STS's LDAP directory.
// No key material and no Web Crypto, so the secure-context hazard does not
// apply — but browser_flags.js is still called, because the PAGE talks to the
// api on loopback from whatever origin the suite is pointed at, and a fetch
// from a public origin to a private address is a Private Network Access
// request Chrome blocks or preflights. The symptom of missing that is a status
// line that never fills and a timeout naming an element rather than the
// network.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "ldap_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var apiUrl = process.env.API_URL || "http://localhost:4000";
var stsUrl = process.env.STS_URL || "http://localhost:8081";
// The directory as the API must reach it — not as this test or the browser
// would. On the containerized stack those are three different names, and it is
// the api that opens the socket.
var ldapUrl = process.env.LDAP_URL || "ldap://sts:389";
var baseDn = process.env.LDAP_BASE_DN || "dc=example,dc=com";
var bindDn = process.env.LDAP_BIND_DN || "cn=admin,dc=example,dc=com";
var password = process.env.LDAP_PASSWORD || "password!";

// Unique per run: the mock's directory lives for the life of its process, so a
// fixed uid is `entryAlreadyExists` on the second run and this test would only
// pass against a freshly started service. See tests/CLAUDE.md.
var stamp = Date.now().toString(36) +
    Math.floor(Math.random() * 1e6).toString(36);
var uid = "page-" + stamp;
var groupCn = "page-group-" + stamp;
var userDn = "uid=" + uid + ",ou=users," + baseDn;
var groupDn = "cn=" + groupCn + ",ou=groups," + baseDn;

// Content, not elements. Every field on this page is static markup, so
// until.elementLocated succeeds during parsing and says nothing about whether
// the operation happened.
async function waitForValue(driver, id, pattern, timeoutMs, what) {
  log.debug("Entering waitForValue(). id=" + id);
  let last = "";
  try {
    await driver.wait(async function () {
      last = await driver.findElement(By.id(id)).getAttribute("value");
      return pattern.test(String(last || ""));
    }, timeoutMs || 30000);
  } catch (e) {
    log.debug("Leaving waitForValue(). It never matched.");
    throw new Error(what + " (last value in #" + id + ": " +
        JSON.stringify(String(last || "").slice(0, 400)) + ")");
  }
  log.debug("Leaving waitForValue().");
  return String(last || "");
}

async function waitForText(driver, id, pattern, timeoutMs, what) {
  log.debug("Entering waitForText(). id=" + id);
  let last = "";
  try {
    await driver.wait(async function () {
      last = await driver.findElement(By.id(id)).getText();
      return pattern.test(String(last || ""));
    }, timeoutMs || 30000);
  } catch (e) {
    log.debug("Leaving waitForText(). It never matched.");
    throw new Error(what + " (last text in #" + id + ": " +
        JSON.stringify(String(last || "").slice(0, 400)) + ")");
  }
  log.debug("Leaving waitForText().");
  return String(last || "");
}

async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  const field = await driver.findElement(By.id(id));
  await field.clear();
  if (value !== "") await field.sendKeys(value);
  log.debug("Leaving setField().");
}

async function valueOf(driver, id) {
  log.debug("Entering valueOf(). " + id);
  const value = await driver.findElement(By.id(id)).getAttribute("value");
  log.debug("Leaving valueOf().");
  return String(value || "");
}

// Every status line on this page is a readonly text input, and each operation
// leaves one behind. A results box that persists between two identical actions
// must be emptied before the second one, or a wait is satisfied by the first
// one's text and the test reports an operation it never watched — the lesson
// tests/CLAUDE.md records against oauth2_token_revocation.js. So each step
// clears the status it is about to wait on.
async function clearStatus(driver, id) {
  log.debug("Entering clearStatus(). " + id);
  await driver.executeScript(
    "document.getElementById(arguments[0]).value = '';", id);
  log.debug("Leaving clearStatus().");
}

async function click(driver, id) {
  log.debug("Entering click(). " + id);
  const button = await driver.findElement(By.id(id));
  await driver.executeScript(
    "arguments[0].scrollIntoView({ block: 'center' });", button);
  await button.click();
  log.debug("Leaving click().");
}

// Run one operation from a button and wait for its status to settle. Returns
// the status text. Every step here goes through this, so no step can forget to
// clear first.
async function operate(driver, buttonId, statusId, pattern, what) {
  log.debug("Entering operate(). " + buttonId);
  await clearStatus(driver, statusId);
  await click(driver, buttonId);
  const status = await waitForValue(driver, statusId, pattern, 30000, what);
  log.debug("Leaving operate(). status=" + JSON.stringify(status.slice(0, 120)));
  return status;
}

async function preconditions() {
  log.debug("Entering preconditions().");
  try {
    const limits = await fetch(apiUrl + "/ldap/limits");
    if (limits.status === 404) {
      log.debug("Leaving preconditions(). The api has no LDAP endpoints.");
      return { ok: false, why: "the api at " + apiUrl + " answered 404 for " +
        "GET /ldap/limits, so it is a build without the LDAP endpoints" };
    }
    if (!limits.ok) {
      log.debug("Leaving preconditions(). The api did not answer.");
      return { ok: false, why: "the api at " + apiUrl + " answered " +
        limits.status + " for GET /ldap/limits" };
    }
    const directory = await fetch(stsUrl + "/ldap?format=json");
    if (!directory.ok) {
      log.debug("Leaving preconditions(). The mock has no directory.");
      return { ok: false, why: "the mock STS has no embedded LDAP directory " +
        "(" + stsUrl + "/ldap answered " + directory.status + ") — the sts/ " +
        "gitlink probably predates it" };
    }
    const described = await directory.json();
    if (described.listening === false) {
      // The HTTP view answers 200 whether or not the socket bound. See
      // tests/api_ldap.js for why that distinction has to be checked.
      log.debug("Leaving preconditions(). The listener is down.");
      return { ok: false, why: "the mock STS's LDAP listener is not up: " +
        (described.listenError || "it never bound") + ". Something else " +
        "probably owns port " + described.port + " on that host" };
    }
    const page = await fetch(baseUrl + "/ldap.html");
    if (!page.ok) {
      // A deployed static site has no LDAP page at all, which is a different
      // thing from having no api behind one.
      log.debug("Leaving preconditions(). The page is not deployed.");
      return { ok: false, why: baseUrl + "/ldap.html answered " + page.status +
        " — this target does not have the LDAP page (the static deployments " +
        "leave it out, because every button on it needs the api)" };
    }
    log.debug("Leaving preconditions(). Ready.");
    return { ok: true };
  } catch (e) {
    log.debug("Leaving preconditions(). Unreachable.");
    return { ok: false, why: "could not reach the stack (" + e.message + ")" };
  }
}

// ---------------------------------------------------------------------------
// 1. The connection pane, and the two things about it that only a page has.
// ---------------------------------------------------------------------------
async function theConnectionPaneBindsAndForgetsThePassword(driver) {
  log.debug("Entering theConnectionPaneBindsAndForgetsThePassword().");
  log.info("=== Connection & Bind ===");
  await driver.get(baseUrl + "/ldap.html");
  await driver.wait(until.elementLocated(By.id("btn_ldap_bind")), 20000);

  // The limits line is filled from GET /ldap/limits before anything is
  // attempted. A debugger that discovers its own limits by hitting them
  // reports them as somebody else's fault.
  const limits = await waitForText(driver, "ldap_limits",
    /will connect to/, 20000,
    "the page never reported what the api will do — it asks GET /ldap/limits " +
    "on load precisely so it can say so before a call fails");
  assert.ok(/389/.test(limits),
    "the published ports should include the assigned LDAP port. Got: " +
    JSON.stringify(limits));

  await setField(driver, "ldap_url", ldapUrl);
  await setField(driver, "ldap_base_dn", baseDn);
  await setField(driver, "ldap_bind_dn", bindDn);
  await setField(driver, "ldap_password", password);

  const ok = await operate(driver, "btn_ldap_bind", "ldap_bind_status",
    /succeeded|refused|HTTP/, "the bind produced no status at all");
  assert.ok(/succeeded/.test(ok),
    "the bind should have succeeded against a directory that accepts every " +
    "password. Got: " + JSON.stringify(ok));

  // The refusal, which is the only LDAP failure that is about credentials —
  // and the reason the mock refuses one password at all.
  await setField(driver, "ldap_password", "invalid");
  const refused = await operate(driver, "btn_ldap_bind", "ldap_bind_status",
    /refused|succeeded|HTTP/, "the second bind produced no status");
  assert.ok(/refused/.test(refused) && /49/.test(refused),
    "the literal password \"invalid\" must come back as LDAP result 49, and " +
    "the page must show the CODE — a page that said only \"it failed\" would " +
    "be hiding the one thing an operator's runbook is written against. Got: " +
    JSON.stringify(refused));
  assert.ok(/invalidCredentials/.test(refused),
    "and its name beside it, because the number alone is not readable. Got: " +
    JSON.stringify(refused));

  // THE PASSWORD IS NEVER STORED. Every other field on this page is. This is
  // the project-wide rule about key material and credentials, and nothing but
  // a browser test can see it.
  const stored = await driver.executeScript(
    "var out = {};" +
    "for (var i = 0; i < localStorage.length; i++) {" +
    "  var k = localStorage.key(i);" +
    "  if (k.indexOf('ldap_') === 0) out[k] = localStorage.getItem(k);" +
    "}" +
    "return out;");
  assert.ok(!Object.prototype.hasOwnProperty.call(stored, "ldap_password"),
    "the password must never be written to localStorage. Keys found: " +
    JSON.stringify(Object.keys(stored)));
  assert.ok(Object.values(stored).every(function (v) {
    return String(v).indexOf(password) === -1;
  }), "and it must not appear under another key either. Stored: " +
    JSON.stringify(stored));
  assert.strictEqual(stored.ldap_url, ldapUrl,
    "while the URL IS remembered — the rule is about credentials, not about " +
    "configuration, and a page that remembered nothing would be unusable.");
  assert.strictEqual(stored.ldap_base_dn, baseDn,
    "and so is the base DN.");

  await setField(driver, "ldap_password", password);
  log.debug("Leaving theConnectionPaneBindsAndForgetsThePassword().");
}

// ---------------------------------------------------------------------------
// 2. Create a user through the shorthand pane, and check the DN it built.
// ---------------------------------------------------------------------------
async function theUsersPaneBuildsTheDnAndCreatesTheEntry(driver) {
  log.debug("Entering theUsersPaneBuildsTheDnAndCreatesTheEntry().");
  log.info("=== Users pane: create " + userDn + " ===");
  await setField(driver, "ldap_user_uid", uid);
  await setField(driver, "ldap_user_cn", "Page Test " + stamp);
  await setField(driver, "ldap_user_sn", "Test");
  await setField(driver, "ldap_user_given_name", "Page");
  await setField(driver, "ldap_user_mail", uid + "@sts-mock.example");
  await setField(driver, "ldap_user_title", "Support Analyst");

  // THE DN PREVIEW. Nothing in the protocol notices a wrong composition — the
  // operation simply happens somewhere else and succeeds — so the page shows
  // what it will send and this reads it.
  const preview = await waitForText(driver, "ldap_user_dn_preview",
    new RegExp("uid=" + uid), 10000,
    "the Users pane never previewed the DN it would build");
  assert.strictEqual(preview.trim(), userDn,
    "the pane must build uid=<uid>,ou=users,<base DN>. Got " +
    JSON.stringify(preview.trim()) + ", expected " + JSON.stringify(userDn));

  const created = await operate(driver, "btn_ldap_create_user",
    "ldap_user_status", /succeeded|refused|HTTP/,
    "creating the user produced no status");
  assert.ok(/succeeded/.test(created),
    "creating " + userDn + " should have succeeded. Got: " +
    JSON.stringify(created));

  // The Exchange pane is this page's whole claim — it shows what was asked for
  // and what came back. A page that performed the operation and showed nothing
  // would be a client, not a debugger.
  const request = await valueOf(driver, "ldap_request_json");
  assert.ok(/POST .*\/ldap\/add/.test(request),
    "the Exchange pane must name the endpoint that was called. Got: " +
    JSON.stringify(request.slice(0, 200)));
  assert.ok(request.indexOf(userDn) !== -1,
    "and the DN that was sent.");
  assert.ok(request.indexOf(password) === -1,
    "and NOT the password: it is the one value redacted there, and a page " +
    "that echoed the request wholesale would put a credential in a textarea " +
    "somebody is about to paste into an issue.");
  assert.ok(/characters, not shown/.test(request),
    "though its LENGTH is kept, because \"did the field reach the api at " +
    "all\" is a real question when a bind fails.");
  const response = await valueOf(driver, "ldap_response_json");
  assert.ok(/HTTP 200/.test(response),
    "and the answer, verbatim. Got: " + JSON.stringify(response.slice(0, 200)));
  log.debug("Leaving theUsersPaneBuildsTheDnAndCreatesTheEntry().");
}

// ---------------------------------------------------------------------------
// 3. Update the user's attributes — a modify, with `replace` and not `add`.
// ---------------------------------------------------------------------------
async function theUsersAttributesAreUpdated(driver) {
  log.debug("Entering theUsersAttributesAreUpdated().");
  log.info("=== Users pane: update ===");
  await setField(driver, "ldap_user_title", "Staff Engineer");
  const updated = await operate(driver, "btn_ldap_update_user",
    "ldap_user_status", /succeeded|refused|HTTP/,
    "updating the user produced no status");
  assert.ok(/succeeded/.test(updated),
    "the update should have succeeded. Got: " + JSON.stringify(updated));

  const request = await valueOf(driver, "ldap_request_json");
  assert.ok(/"operation": *"replace"/.test(request),
    "the changes must be `replace` and not `add`. These attributes are " +
    "multi-valued in the schema even where a person thinks of them as " +
    "single-valued, so `add` would leave the old title beside the new one — " +
    "which is exactly the mistake this pane exists to make visible. Got: " +
    JSON.stringify(request.slice(0, 400)));
  assert.ok(request.indexOf("Staff Engineer") !== -1,
    "and carry the new value.");
  log.debug("Leaving theUsersAttributesAreUpdated().");
}

// ---------------------------------------------------------------------------
// 4. Create a group, and add the user to it — which is a modify on the GROUP.
// ---------------------------------------------------------------------------
async function theGroupsPaneCreatesAGroupAndAddsAMember(driver) {
  log.debug("Entering theGroupsPaneCreatesAGroupAndAddsAMember().");
  log.info("=== Groups pane: create " + groupDn + " ===");
  await setField(driver, "ldap_group_cn", groupCn);
  await setField(driver, "ldap_group_description", "Created by ldap_page.js");

  const preview = await waitForText(driver, "ldap_group_dn_preview",
    new RegExp("cn=" + groupCn), 10000,
    "the Groups pane never previewed the DN it would build");
  assert.strictEqual(preview.trim(), groupDn,
    "the pane must build cn=<cn>,ou=groups,<base DN>. Got " +
    JSON.stringify(preview.trim()));

  const created = await operate(driver, "btn_ldap_create_group",
    "ldap_group_status", /succeeded|refused|HTTP/,
    "creating the group produced no status");
  assert.ok(/succeeded/.test(created),
    "creating " + groupDn + " should have succeeded. Got: " +
    JSON.stringify(created));
  const createRequest = await valueOf(driver, "ldap_request_json");
  assert.ok(/"member"/.test(createRequest),
    "a groupOfNames MUST have at least one member (RFC 4519 makes `member` a " +
    "MUST attribute), so the pane seeds it with the user from the pane above " +
    "rather than sending an empty group that every real directory refuses. " +
    "Got: " + JSON.stringify(createRequest.slice(0, 400)));

  // THERE IS NO "ADD MEMBER" OPERATION. The change goes on the GROUP.
  const joined = await operate(driver, "btn_ldap_add_member",
    "ldap_group_status", /succeeded|refused|HTTP/,
    "adding the member produced no status");
  assert.ok(/succeeded/.test(joined),
    "adding the user to the group should have succeeded. Got: " +
    JSON.stringify(joined));
  const request = await valueOf(driver, "ldap_request_json");
  assert.ok(/POST .*\/ldap\/modify/.test(request),
    "membership is a MODIFY — there is no add-member operation in LDAP. Got: " +
    JSON.stringify(request.slice(0, 200)));
  const sent = JSON.parse(request.slice(request.indexOf("{")));
  assert.strictEqual(sent.dn, groupDn,
    "and it must be sent to the GROUP, not to the user. An implementation " +
    "that put the change on the user would look right until somebody read " +
    "the group. Got " + JSON.stringify(sent.dn));
  assert.deepStrictEqual(sent.changes,
    [{ operation: "add", type: "member", values: [userDn] }],
    "with exactly one `add` change on `member` whose value is the user's DN. " +
    "Got " + JSON.stringify(sent.changes));
  log.debug("Leaving theGroupsPaneCreatesAGroupAndAddsAMember().");
}

// ---------------------------------------------------------------------------
// 5. The four presets, which must FILL THE FIELDS rather than run a hidden
//    query — the filter is the thing worth reading.
// ---------------------------------------------------------------------------
async function theFourPresetsFillTheFieldsAndAnswer(driver) {
  log.debug("Entering theFourPresetsFillTheFieldsAndAnswer().");
  log.info("=== Search presets ===");

  await clearStatus(driver, "ldap_search_status");
  await click(driver, "btn_ldap_preset_users");
  await waitForValue(driver, "ldap_search_status", /succeeded|refused|HTTP/,
    30000, "the all-users preset produced no status");
  assert.strictEqual(await valueOf(driver, "ldap_search_filter"),
    "(objectClass=inetOrgPerson)",
    "the preset must FILL the filter field. A preset that ran a hidden query " +
    "would teach nothing, and the difference is invisible from the results.");
  assert.strictEqual(await valueOf(driver, "ldap_search_scope"), "sub",
    "and the scope.");
  let dns = await resultDns(driver);
  assert.ok(dns.includes(userDn.toLowerCase()),
    "the user created above must be among the results. Got " +
    JSON.stringify(dns));

  await clearStatus(driver, "ldap_search_status");
  await click(driver, "btn_ldap_preset_groups");
  await waitForValue(driver, "ldap_search_status", /succeeded|refused|HTTP/,
    30000, "the all-groups preset produced no status");
  assert.strictEqual(await valueOf(driver, "ldap_search_filter"),
    "(objectClass=groupOfNames)", "the groups preset fills its filter too.");
  dns = await resultDns(driver);
  assert.ok(dns.includes(groupDn.toLowerCase()),
    "the group created above must be among them. Got " + JSON.stringify(dns));

  // THE MEMBERS OF A GROUP: read from the GROUP, base scope, `member` only.
  await clearStatus(driver, "ldap_search_status");
  await click(driver, "btn_ldap_preset_group_members");
  await waitForValue(driver, "ldap_search_status", /succeeded|refused|HTTP/,
    30000, "the group-members preset produced no status");
  assert.strictEqual(await valueOf(driver, "ldap_search_base"), groupDn,
    "the members of a group are read from the GROUP ENTRY, so the base is " +
    "the group's own DN.");
  assert.strictEqual(await valueOf(driver, "ldap_search_scope"), "base",
    "at base scope — this is a read of one entry, not a search of the users.");
  assert.strictEqual(await valueOf(driver, "ldap_search_attributes"), "member",
    "asking only for `member`.");
  const memberText = await driver.findElement(
    By.id("ldap_search_results")).getText();
  assert.ok(memberText.indexOf(userDn) !== -1,
    "and the user must be listed in it. Got: " +
    JSON.stringify(memberText.slice(0, 400)));

  // THE GROUPS A USER IS IN: the one nobody guesses. There is no attribute on
  // the user to read — `memberOf` is a Microsoft extension — so the groups are
  // searched for a `member` value naming the user.
  await clearStatus(driver, "ldap_search_status");
  await click(driver, "btn_ldap_preset_user_groups");
  await waitForValue(driver, "ldap_search_status", /succeeded|refused|HTTP/,
    30000, "the user-groups preset produced no status");
  const filter = await valueOf(driver, "ldap_search_filter");
  assert.ok(filter.indexOf("member=" + userDn) !== -1,
    "the groups a user is in are found by searching the GROUPS for a " +
    "`member` value that is the user's DN — there is no attribute on the " +
    "user that lists them. A preset that searched the users instead would " +
    "return nothing and look like an empty directory. Got: " +
    JSON.stringify(filter));
  assert.ok(/objectClass=groupOfNames/.test(filter),
    "narrowed to groups, so a stray `member` attribute elsewhere does not " +
    "answer. Got: " + JSON.stringify(filter));
  dns = await resultDns(driver);
  assert.ok(dns.includes(groupDn.toLowerCase()),
    "and the group must be found this way too. Got " + JSON.stringify(dns));
  log.debug("Leaving theFourPresetsFillTheFieldsAndAnswer().");
}

// The DNs in the results table, lower-cased. Read from the rendered table
// rather than from the response textarea, because the table is what a reader
// sees and a page that fetched correctly and rendered nothing would otherwise
// pass.
async function resultDns(driver) {
  log.debug("Entering resultDns().");
  const dns = await driver.executeScript(
    "return Array.prototype.slice.call(" +
    "  document.querySelectorAll('#ldap_search_results .ldap-entry-dn')" +
    ").map(function (e) { return e.textContent.trim().toLowerCase(); });");
  log.debug("Leaving resultDns(). " + dns.length + " row(s).");
  return dns;
}

// ---------------------------------------------------------------------------
// 6. A refusal is a completed round trip, and the History has to say so.
// ---------------------------------------------------------------------------
async function aRefusalIsShownAsAResultAndLogged(driver) {
  log.debug("Entering aRefusalIsShownAsAResultAndLogged().");
  log.info("=== A refused operation ===");
  // Creating the same user again: entryAlreadyExists (68). The operation
  // completed; the answer was no.
  const again = await operate(driver, "btn_ldap_create_user",
    "ldap_user_status", /succeeded|refused|HTTP/,
    "the duplicate create produced no status");
  assert.ok(/refused/.test(again) && /68/.test(again),
    "creating the same entry twice is LDAP result 68, entryAlreadyExists, " +
    "and the page must show it as a RESULT rather than as an error — a " +
    "completed round trip whose answer was no. Got: " + JSON.stringify(again));

  const summary = await driver.findElement(
    By.id("ldap_result_summary")).getText();
  assert.ok(/LDAP result 68/.test(summary),
    "the Exchange pane's own line must name the code too, in the protocol's " +
    "vocabulary. Got: " + JSON.stringify(summary));

  // The Operations History. Failure means the directory said no; Sent means
  // the api never answered. Those are the two states people confuse, and the
  // second one is what a row left behind by a dead api looks like.
  const rows = await driver.executeScript(
    "return Array.prototype.slice.call(" +
    "  document.querySelectorAll('#ldap_operation_history tbody tr')" +
    ").map(function (tr) { return tr.textContent; });");
  assert.ok(rows.length >= 2,
    "the history must have a row per operation; got " + rows.length);
  assert.ok(rows.some(function (row) { return /Failure/.test(row) &&
      /68/.test(row); }),
    "the refused operation must be logged as a Failure carrying its result " +
    "code. Got: " + JSON.stringify(rows.slice(0, 3)));
  assert.ok(rows.some(function (row) { return /Success/.test(row); }),
    "and the ones that worked as Success.");
  assert.ok(!rows.some(function (row) { return /\bSent\b/.test(row); }),
    "and NOTHING may still be `Sent`: a row that stays Sent means the api " +
    "never answered, which is a different thing from a refusal and is the " +
    "state a dead api leaves behind. Got: " + JSON.stringify(rows.slice(0, 3)));
  log.debug("Leaving aRefusalIsShownAsAResultAndLogged().");
}

// ---------------------------------------------------------------------------
// 7. Delete both, and the dangling member in between.
// ---------------------------------------------------------------------------
async function theEntriesAreDeletedAndTheMemberDangles(driver) {
  log.debug("Entering theEntriesAreDeletedAndTheMemberDangles().");
  log.info("=== Delete ===");
  const deletedUser = await operate(driver, "btn_ldap_delete_user",
    "ldap_user_status", /succeeded|refused|HTTP/,
    "deleting the user produced no status");
  assert.ok(/succeeded/.test(deletedUser),
    "deleting " + userDn + " should have succeeded. Got: " +
    JSON.stringify(deletedUser));

  // The group STILL lists the DN that is gone. Referential integrity is a
  // directory feature, not a protocol rule, and the dangling member is the
  // thing this page exists to show rather than tidy away.
  await clearStatus(driver, "ldap_search_status");
  await click(driver, "btn_ldap_preset_group_members");
  await waitForValue(driver, "ldap_search_status", /succeeded|refused|HTTP/,
    30000, "reading the group after the delete produced no status");
  const members = await driver.findElement(
    By.id("ldap_search_results")).getText();
  assert.ok(members.indexOf(userDn) !== -1,
    "the group must STILL list the deleted user as a member. Nothing in RFC " +
    "4511 requires referential integrity — OpenLDAP needs an overlay for it " +
    "and Active Directory does it in the DSA — so a page that showed the " +
    "value gone would be teaching a behaviour most directories do not have. " +
    "Got: " + JSON.stringify(members.slice(0, 400)));

  const deletedGroup = await operate(driver, "btn_ldap_delete_group",
    "ldap_group_status", /succeeded|refused|HTTP/,
    "deleting the group produced no status");
  assert.ok(/succeeded/.test(deletedGroup),
    "deleting " + groupDn + " should have succeeded. Got: " +
    JSON.stringify(deletedGroup));
  log.debug("Leaving theEntriesAreDeletedAndTheMemberDangles().");
}

// ---------------------------------------------------------------------------
// 8. The Entry pane — the same operations in the protocol's own vocabulary,
//    and the bridge from the shorthand panes to it.
// ---------------------------------------------------------------------------
async function theEntryPaneShowsWhatTheShorthandSends(driver) {
  log.debug("Entering theEntryPaneShowsWhatTheShorthandSends().");
  log.info("=== Entry pane ===");
  await click(driver, "btn_ldap_fill_entry_group");
  const dn = await valueOf(driver, "ldap_entry_dn");
  assert.strictEqual(dn, groupDn,
    "\"Show as a raw operation\" must carry the DN the shorthand pane built " +
    "— that bridge is the whole reason both levels of abstraction are on one " +
    "page. Got " + JSON.stringify(dn));
  const changes = JSON.parse(await valueOf(driver, "ldap_entry_changes"));
  assert.deepStrictEqual(changes,
    [{ operation: "add", type: "member", values: [userDn] }],
    "and the change list, so a reader can see what the button sent and then " +
    "edit it. Got " + JSON.stringify(changes));

  // A delete against a DN that is gone: noSuchObject (32), through the raw
  // pane this time.
  const missing = await operate(driver, "btn_ldap_entry_delete",
    "ldap_entry_status", /succeeded|refused|HTTP/,
    "the raw delete produced no status");
  assert.ok(/refused/.test(missing) && /32/.test(missing),
    "deleting an entry that is not there is LDAP result 32, noSuchObject. " +
    "Got: " + JSON.stringify(missing));
  log.debug("Leaving theEntryPaneShowsWhatTheShorthandSends().");
}

// ---------------------------------------------------------------------------
// 9. Every `ldap-` class the page uses is defined in a sheet it actually loads.
//
// The same check tests/navigation.js makes for the pages it walks, repeated
// here because it CANNOT walk to this one: the LDAP card is among the three the
// static deployments disable, so adding it to that walk would fail every run
// against a deployed site. Without this the page could render completely
// unstyled with nothing 404ing and nothing failing, which is what happened to
// the WS-Federation pages after a stylesheet rename.
// ---------------------------------------------------------------------------
async function everyStyleClassIsDefined(driver) {
  log.debug("Entering everyStyleClassIsDefined().");
  log.info("=== Stylesheets ===");
  // Note the shape: this function is SERIALISED INTO THE BROWSER, so there is
  // no bunyan in it and a log line here would be `log is not defined` reported
  // as a page fault. What comes back is logged out here in node instead.
  const m = await driver.executeScript(
    "var links = Array.prototype.slice.call(" +
    "  document.querySelectorAll('link[rel=stylesheet]'))" +
    "  .map(function (l) { return l.getAttribute('href'); });" +
    "var empty = [];" +
    "var defined = {};" +
    "Array.prototype.slice.call(document.styleSheets).forEach(" +
    "  function (sheet) {" +
    "    var rules = null;" +
    "    try { rules = sheet.cssRules; } catch (e) { rules = null; }" +
    "    if (!rules || !rules.length) {" +
    "      if (sheet.href) empty.push(sheet.href); return; }" +
    "    Array.prototype.slice.call(rules).forEach(function collect(rule) {" +
    "      if (rule.selectorText) {" +
    "        (rule.selectorText.match(/\\.[A-Za-z0-9_-]+/g) || []).forEach(" +
    "          function (sel) { defined[sel.slice(1)] = true; });" +
    "      } else if (rule.cssRules) {" +
    "        Array.prototype.slice.call(rule.cssRules).forEach(collect);" +
    "      }" +
    "    });" +
    "  });" +
    "var used = {};" +
    "Array.prototype.slice.call(document.querySelectorAll('[class]'))" +
    "  .forEach(function (e) {" +
    "    Array.prototype.slice.call(e.classList).forEach(" +
    "      function (c) { used[c] = true; }); });" +
    "return { links: links, empty: empty," +
    "         used: Object.keys(used), defined: Object.keys(defined) };");
  assert.deepStrictEqual(m.empty, [],
    "these stylesheets loaded with no rules in them (a 404 serving an error " +
    "page, or an empty file): " + m.empty.join(", "));
  const definedSet = {};
  m.defined.forEach(function (c) { definedSet[c] = true; });
  const unstyled = m.used.filter(function (c) {
    return /^ldap-/.test(c) && !definedSet[c];
  });
  assert.deepStrictEqual(unstyled, [],
    "these `ldap-` classes are used on the page and defined in none of the " +
    "stylesheets it loads: " + unstyled.join(", ") + ". The page links: " +
    m.links.join(", ") + ". Note that the Operations History pane's classes " +
    "come from op_history.js with this workflow's prefix, so css/ldap.css has " +
    "to define ldap-history-scroll, ldap-table, ldap-history, " +
    "ldap-history-time and ldap-history-empty as well as the ones written in " +
    "the markup.");
  log.info("[styles] every ldap- class the page uses is defined; it links " +
           m.links.length + " stylesheet(s), all with rules.");
  log.debug("Leaving everyStyleClassIsDefined().");
}

// ---------------------------------------------------------------------------
// 10. The browser console must be clean.
// ---------------------------------------------------------------------------
async function theConsoleIsClean(driver) {
  log.debug("Entering theConsoleIsClean().");
  log.info("=== Browser console ===");
  const entries = await driver.manage().logs().get("browser");
  const severe = entries.filter(function (entry) {
    // A 404 for a favicon variant is noise from the icon set every page here
    // carries and says nothing about this workflow.
    return entry.level.name === "SEVERE" &&
      !/favicon|apple-icon|android-icon|ms-icon/.test(entry.message);
  });
  assert.deepStrictEqual(severe.map(function (e) { return e.message; }), [],
    "the page must produce no severe console errors. A bundle that failed to " +
    "load, or a handler that threw, shows up here and nowhere else — the " +
    "buttons simply stop working and every wait times out naming an element.");
  log.debug("Leaving theConsoleIsClean().");
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
  log.info("driving " + baseUrl + "/ldap.html against the api at " + apiUrl +
           ", which will open " + ldapUrl + " (base " + baseDn + "). This " +
           "run's names are " + userDn + " and " + groupDn);

  const options = new chrome.Options();
  // --headless=new, never bare --headless, and headless is not optional: a CI
  // runner and the tests container have no display, so a windowed session
  // fails at `session not created` naming the page it was about to visit.
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1600");
  // Not for Web Crypto — this page needs none — but for the Private Network
  // Access rules: the page fetches the api on loopback, and from a public
  // origin Chrome blocks or preflights that.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    await theConnectionPaneBindsAndForgetsThePassword(driver);
    await theUsersPaneBuildsTheDnAndCreatesTheEntry(driver);
    await theUsersAttributesAreUpdated(driver);
    await theGroupsPaneCreatesAGroupAndAddsAMember(driver);
    await theFourPresetsFillTheFieldsAndAnswer(driver);
    await aRefusalIsShownAsAResultAndLogged(driver);
    await theEntriesAreDeletedAndTheMemberDangles(driver);
    await theEntryPaneShowsWhatTheShorthandSends(driver);
    await everyStyleClassIsDefined(driver);
    await theConsoleIsClean(driver);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("ldap_page")
  .description("Verify the LDAP Protocol Debugger page: the DNs it builds, " +
      "the presets that fill its fields, the modify that is membership, and " +
      "the difference between a refusal and a call that never answered.")
  .addOption(new Option("-u, --url <url>",
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
