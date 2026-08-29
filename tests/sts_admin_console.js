// File: sts_admin_console.js
//
// ---------------------------------------------------------------------------
// THE MOCK STS'S ADMIN CONSOLE AT /admin: EVERY PAGE, AND EVERY BUTTON ON IT.
//
// The console is the one surface in that service that can CHANGE what every
// protocol endpoint does — a claim added here appears in every token, a setting
// changed here changes what a flow refuses — and it is the only surface with no
// test of its own. `tests/admin_api.js` and `tests/sts_admin_api_operations.js`
// drive the JSON door beside it, which is not the same thing: the API's whole
// design is that it decides nothing the console does not, so a defect in the
// PAGE — a form posting the wrong action, a control that renders and reaches
// nothing, a field the handler stopped reading — is invisible from over there
// by construction.
//
// IT NEEDS NO BROWSER, AND THAT IS A DESIGN DECISION RATHER THAN A COMPROMISE.
// This console has `script-src 'none'` and not one line of JavaScript on any of
// its thirty-eight pages: every control is a `<form>` and every button is a
// submit. So pressing a button IS posting the form's own fields to the form's
// own action — which is exactly what a browser would do, and what this file
// does. A Selenium job here would drive a browser in order to make it perform a
// form POST, and would be slower, flakier and no more truthful. What it would
// add is layout, which is not what this file is about.
//
// FIVE THINGS IT ASSERTS.
//
//   * **THE GATE.** `admin.authRequired` is on by default, so every page and
//     every form is behind a sign-on session and one of two roles. Four
//     behaviours are pinned, and each is a client's path through it: a browser
//     GET is REDIRECTED to the sign-in screen carrying the id of the request
//     waiting there; a `?format=json` read is REFUSED 401 rather than
//     redirected, because a redirect to an HTML screen is not an answer a
//     program can read; a POST with no session is NEVER redirected, because a
//     303 makes it a GET and the fields vanish; and `/admin-api` next door is
//     not gated at all, which is deliberate and is the way back in.
//   * **EVERY PAGE IS DRAWN, IN THE SHELL, UNDER THE POLICY.** All
//     thirty-eight, each with the nav, its own breadcrumb, and a
//     Content-Security-Policy that still says `script-src 'none'` and
//     `frame-ancestors 'none'` — the second of which has no fallback from
//     `default-src` and is therefore the clause a page loses by accident.
//   * **NO PAGE HAS A FORM INSIDE A FORM.** This is a regression guard for a
//     real defect: the HTML parser DROPS a nested `<form>` start tag and
//     adopts its children into the outer form, so `/admin/config`'s section
//     Save button performed a row's Reset. Nothing failed, the markup carried
//     a comment explaining why it was correct, and it was found with
//     `--dump-dom`. It is one scan of the markup here.
//   * **EVERY BUTTON DOES WHAT IT SAYS.** Each control is pressed the way a
//     browser presses it — the form's own hidden fields, posted to the form's
//     own action — and the effect is then read back through a DIFFERENT door
//     than the one that made it. The console answers a form POST with 303 and
//     the outcome in the query string, `?notice=…` on success and `?error=…`
//     on a refusal, so the button's own account of itself is available too and
//     is checked against what actually happened.
//   * **A SETTING CHANGED ON A PROTOCOL PAGE REACHES THE CONFIGURATION AND THE
//     STORE.** Since 2026-08-27 every one of `config.js`'s twenty-two groups is
//     drawn on the page for the protocol it configures, so a change is made
//     where a person would make it — on `/admin/kerberos`, not on
//     `/admin/config` — and is then looked for in three places: back on that
//     page, in `/admin-api/config` with its source moved, and in the
//     persistence store's own write counters.
//
// ---------------------------------------------------------------------------
// IT WORKS IN A TRUST REALM IT CREATES AND REMOVES, for the reason
// tests/sts_admin_api_operations.js does: this is a test that writes to the
// thing every other job reads, the mock never restarts between jobs, and a
// realm is a whole logical copy of the service whose removal takes its
// directory, its registries, its claim sets and its overrides with it.
//
// The console reached under a realm prefix is the same console — `/realm/<id>/
// admin/...` — and the gate is the exception that proves it: the two roles are
// groups in the DEFAULT realm and the gate accepts the DEFAULT realm's session
// and no other, so one sign-in reaches every realm's console. That is asserted
// here rather than assumed.
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
  // load, the arrangement tests/wait_for.js has.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_admin_console",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// The name this file signs into the console AS. It is a name and not a
// credential — the mock checks no password anywhere — and it is distinctive so
// that a row in /admin/audit says which test made it.
const CONSOLE_USER = "console-test-" + names.runStamp();

// The throwaway realm, and the console prefix that reaches it.
const REALM = ("console-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

var session = "";        // the cookie, or "" when the gate is off
var gateIsOn = false;    // what the service actually did, rather than assumed

function root(path) { return base + path; }
function realm(path) { return base + "/realm/" + REALM + path; }

// ---------------------------------------------------------------------------
// One console read, as a browser makes it: the session cookie, and redirects
// NOT followed — every assertion in this file about the gate is about the
// redirect itself.
// ---------------------------------------------------------------------------
async function page(url, options) {
  log.debug("Entering page(). url=" + url);
  const headers = Object.assign({}, (options && options.headers) || {});
  if (session && !(options && options.noSession)) {
    headers.Cookie = session;
  }
  const reply = await fetch(url, {
    method: (options && options.method) || "GET",
    headers: headers,
    body: (options && options.body) || undefined,
    redirect: "manual"
  });
  const text = await reply.text();
  log.debug("Leaving page(). status=" + reply.status);
  return { status: reply.status, headers: reply.headers, html: text,
           location: reply.headers.get("location") || "" };
}

// A console page as HTML, which must be 200 and must be a page.
async function html(path, options) {
  log.debug("Entering html(). path=" + path);
  const reply = await page(base + path, options);
  assert.strictEqual(reply.status, 200,
    "GET " + path + " should answer 200; it answered " + reply.status +
    (reply.location ? " -> " + reply.location : "") + ". " +
    (reply.status === 302 ? "A redirect here means the session was not " +
     "accepted, which is a different failure from the page being wrong." : ""));
  log.debug("Leaving html().");
  return reply;
}

// A console page's own JSON view. Every page answers one, and it is what
// /admin-api's matching GET returns — so it is the door this file reads an
// effect back through after pressing a button on the page.
async function json(path) {
  log.debug("Entering json(). path=" + path);
  const joiner = path.indexOf("?") >= 0 ? "&" : "?";
  const reply = await common.httpJson(base + path + joiner + "format=json",
      session ? { headers: { Cookie: session } } : undefined);
  assert.strictEqual(reply.status, 200,
    "GET " + path + "?format=json should answer 200; it answered " +
    reply.status + " " + String(reply.raw).slice(0, 200));
  assert.strictEqual(typeof reply.body, "object",
    "and it should answer a JSON object rather than " + typeof reply.body +
    ": " + String(reply.raw).slice(0, 200));
  log.debug("Leaving json().");
  return reply.body;
}

// ---------------------------------------------------------------------------
// PRESSING A BUTTON.
//
// This console has no script on any page, so a control is a `<form>` and a
// button is a submit — which means pressing one is posting the form's fields to
// the form's action, form-encoded, with the cookie. There is nothing a browser
// would add.
//
// The reply is a 303 whose Location carries the outcome: `?notice=…` when the
// action did something and `?error=…` when it refused. That is a redirect after
// POST for the ordinary reason (a reload must not repeat the action), and it is
// also the button's own account of itself — which is worth having beside the
// effect, because "it said it worked" and "it worked" are the two halves that
// this file exists to compare.
// ---------------------------------------------------------------------------
async function press(path, fields, what) {
  log.debug("Entering press(). path=" + path);
  const reply = await postForm(path, fields);
  assert.strictEqual(reply.status, 303,
    "posting " + path + " to " + what + " should answer 303 — a form POST on " +
    "this console redirects so that a reload cannot repeat the action. It " +
    "answered " + reply.status + " " + reply.html.slice(0, 200));
  const notice = outcomeOf(reply.location, "notice");
  const error = outcomeOf(reply.location, "error");
  assert.ok(!error,
    "pressing the control that should have " + what + " was REFUSED: " +
    error + "\n  (posted " + JSON.stringify(fields) + " to " + path + ")");
  assert.ok(notice,
    "and it should say what it did, in `notice`. This console answers every " +
    "form POST with an outcome in the query string, and a redirect carrying " +
    "neither a notice nor an error is a control that did something silently. " +
    "Location was " + reply.location);
  log.debug("Leaving press(). " + notice.slice(0, 80));
  return notice;
}

// The same, for a control that is EXPECTED to refuse. A console that answered
// 303 with a notice for a bad request would be one whose refusals are all in
// the API and none on the page a person is using.
async function pressAndBeRefused(path, fields, expect, what) {
  log.debug("Entering pressAndBeRefused(). path=" + path);
  const reply = await postForm(path, fields);
  assert.strictEqual(reply.status, 303,
    "a refused form POST is still a 303 — the refusal is drawn on the page " +
    "the reader is sent back to, not in a status code. " + path +
    " answered " + reply.status);
  const error = outcomeOf(reply.location, "error");
  assert.ok(error,
    "posting " + path + " with " + what + " should have been REFUSED, and it " +
    "came back with " + (outcomeOf(reply.location, "notice") || "nothing") +
    " instead. A control that accepts what the action behind it would refuse " +
    "is a control whose refusals only exist on /admin-api.");
  assert.ok(expect.test(error),
    "it was refused, which is right, but the reason should match " + expect +
    " so that this is a check on WHICH refusal was met. It said: " + error);
  log.debug("Leaving pressAndBeRefused().");
  return error;
}

async function postForm(path, fields) {
  log.debug("Entering postForm(). path=" + path);
  const body = Object.keys(fields).map(function (name) {
    const value = fields[name];
    // A repeated field is how a checkbox column posts — several values under
    // one name — and helpers.parseBody() cannot see one, which is why the mock
    // reads those through namesOf() instead. Sending them properly is what
    // makes this file a test of that arrangement rather than of one value.
    if (Array.isArray(value)) {
      return value.map(function (one) {
        return encodeURIComponent(name) + "=" + encodeURIComponent(one);
      }).join("&");
    }
    return encodeURIComponent(name) + "=" + encodeURIComponent(value);
  }).join("&");
  const reply = await page(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body
  });
  log.debug("Leaving postForm(). status=" + reply.status);
  return reply;
}

function outcomeOf(location, which) {
  const found = String(location || "").match(
      new RegExp("[?&]" + which + "=([^&]*)"));
  return found ? decodeURIComponent(found[1].replace(/\+/g, " ")) : "";
}

// ---------------------------------------------------------------------------
// READING THE MARKUP.
//
// A regular expression over HTML is normally the wrong tool, and here it is the
// right one for a specific reason: what is being asserted IS the markup. The
// question "is there a `<form>` start tag inside another one" cannot be asked
// of a parsed DOM at all — a parser answers it by silently repairing it, which
// is exactly the defect being looked for.
// ---------------------------------------------------------------------------
function formsOn(markup) {
  log.debug("Entering formsOn().");
  const forms = [];
  const pattern = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let found;
  while ((found = pattern.exec(markup))) {
    const attributes = found[1];
    const inner = found[2];
    forms.push({
      action: attributeOf(attributes, "action"),
      method: (attributeOf(attributes, "method") || "get").toUpperCase(),
      inner: inner,
      controls: controlsIn(inner)
    });
  }
  log.debug("Leaving formsOn(). " + forms.length + " form(s).");
  return forms;
}

function controlsIn(inner) {
  const controls = [];
  const pattern = /<(input|button|select|textarea)\b([^>]*)>/gi;
  let found;
  while ((found = pattern.exec(inner))) {
    controls.push({
      tag: found[1].toLowerCase(),
      name: attributeOf(found[2], "name"),
      type: (attributeOf(found[2], "type") || "").toLowerCase(),
      value: attributeOf(found[2], "value"),
      // `formaction` is how this console gives one form two buttons that post
      // to different places — which is what it reached for after the nested
      // `<form>` was removed, so a reader of these tests should know it is a
      // real part of the arrangement rather than an oddity.
      formaction: attributeOf(found[2], "formaction"),
      // A DISABLED CONTROL IS NOT SUBMITTED BY A BROWSER, and this console
      // relies on that: a settings section draws a RESTART-ONLY setting as a
      // disabled box so a reader can see the value in force, and the section's
      // Save must not carry it — `set-many` refuses a restart-only key by
      // name, so a form that submitted it would be refused every time,
      // including when nothing had been changed. A test that posted it would
      // be sending a request no browser can make and would report that
      // refusal as a defect.
      disabled: /\bdisabled\b/i.test(found[2])
    });
  }
  return controls;
}

function attributeOf(attributes, name) {
  const found = String(attributes || "").match(
      new RegExp(name + '="([^"]*)"', "i"));
  return found ? decode(found[1]) : "";
}

// The five entities this console's escaper writes. A value read out of markup
// and posted back has to be the value, not its escaped spelling — `back` is the
// one that matters, since it carries `?q=x&amp;per=10`.
function decode(text) {
  return String(text)
      .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

// ---------------------------------------------------------------------------
// THE GATE. Four behaviours, and each of them is a client's path through it.
//
// admin-ui/CLAUDE.md argues all four; what makes them worth asserting from
// outside is that three of them are ABSENCES — the thing that must not happen
// is a redirect — and an absence is what a refactor removes without noticing.
// ---------------------------------------------------------------------------
async function theGateBehaves() {
  log.debug("Entering theGateBehaves().");
  log.info("=== The gate in front of /admin ===");

  const browserGet = await page(root("/admin/tokens"), { noSession: true });
  if (browserGet.status !== 302) {
    log.warn("[gate] admin.authRequired is OFF (GET /admin/tokens with no " +
             "session answered " + browserGet.status + " and no redirect). " +
             "That is a legitimate state — the setting is switchable on " +
             "purpose — so the four checks below are skipped and every page " +
             "read in this file is made with no cookie. It is REPORTED " +
             "rather than passed over: a run that met an open console and a " +
             "run that met a working one prove different things.");
    gateIsOn = false;
    log.debug("Leaving theGateBehaves(). The gate is off.");
    return;
  }
  gateIsOn = true;

  assert.ok(/\/authn\/login/.test(browserGet.location),
    "a browser GET with no session should be sent to the sign-in screen; it " +
    "was sent to " + browserGet.location);
  const authn = (browserGet.location.match(/[?&]authn=([^&]+)/) || [])[1];
  assert.ok(authn,
    "and that redirect must carry the id of the request waiting there. " +
    "Without it the screen has nothing to sign in FOR and refuses the POST, " +
    "so a person who signed in would land back at the screen. Location was " +
    browserGet.location);

  // A program asking for JSON is REFUSED rather than redirected. A 302 to an
  // HTML sign-in screen is not an answer a program can read, and it is what
  // the naive implementation of this gate does to every caller alike.
  const asJson = await common.httpJson(root("/admin/tokens?format=json"));
  assert.strictEqual(asJson.status, 401,
    "GET /admin/tokens?format=json with no session must be REFUSED 401, not " +
    "redirected: a redirect to an HTML screen is not something a program can " +
    "act on, and this API-shaped read is exactly the caller that would meet " +
    "it. It answered " + asJson.status);
  assert.ok(asJson.body && /login_required|login/i.test(JSON.stringify(asJson.body)),
    "and the refusal should say what is missing; it said " +
    JSON.stringify(asJson.body).slice(0, 200));

  const asAccept = await common.httpJson(root("/admin/tokens"),
      { headers: { Accept: "application/json" } });
  assert.strictEqual(asAccept.status, 401,
    "and an Accept: application/json read must be refused the same way — the " +
    "query parameter is not the only way a program says what it wants. It " +
    "answered " + asAccept.status);

  // A POST is NEVER redirected, and this is the one that is easiest to get
  // wrong: sending a form POST to the sign-in screen with 303 turns it into a
  // GET, so the fields vanish and the person is signed in and then told
  // nothing happened.
  const postNoSession = await page(root("/admin/tokens"), {
    noSession: true,
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "action=revoke&jti=nothing"
  });
  assert.ok(postNoSession.status === 401 || postNoSession.status === 403,
    "A FORM POST WITH NO SESSION MUST NOT BE REDIRECTED. It answered " +
    postNoSession.status + " -> " + postNoSession.location + ". A 303 to the " +
    "sign-in screen makes the request a GET, so every field the person typed " +
    "is lost — they sign in, land on the page, and nothing they asked for " +
    "has happened.");

  // And the API next door is deliberately NOT behind any of this. Express
  // matches app.use('/admin', …) on segment boundaries, so /admin-api never
  // matched it — that is the arrangement rather than luck, and it is what a
  // test drives and what somebody locked out of the console reaches for.
  const api = await common.httpJson(root("/admin-api/status"));
  assert.strictEqual(api.status, 200,
    "/admin-api must NOT be gated. It is the door a test drives and the only " +
    "way back in when nobody holds a role — the screen that grants the first " +
    "role is behind the gate that role opens. It answered " + api.status);

  session = await signIn(CONSOLE_USER);
  const after = await page(root("/admin/tokens"));
  assert.strictEqual(after.status, 200,
    "and after signing in the same page should be drawn; it answered " +
    after.status + " -> " + after.location);
  log.info("[gate] OK — a browser GET is redirected with an `authn` id, a " +
           "JSON read is refused 401 twice over, a POST is refused rather " +
           "than redirected, /admin-api is open, and a session opens the " +
           "console.");
  log.debug("Leaving theGateBehaves().");
}

// The dance a browser does: ask for a page, read the pending request's id out
// of the redirect, post a name to /authn/login, keep the cookie. No password is
// checked anywhere in this service, so any pair is accepted.
async function signIn(username) {
  log.debug("Entering signIn(). username=" + username);
  const sent = await page(root("/admin"), { noSession: true });
  const authn = (sent.location.match(/[?&]authn=([^&]+)/) || [])[1];
  assert.ok(authn, "the sign-in redirect should carry an `authn` id; it was " +
      sent.location);
  const reply = await fetch(root("/authn/login"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "authn_id=" + encodeURIComponent(authn) +
          "&username=" + encodeURIComponent(username) +
          "&password=" + encodeURIComponent(username),
    redirect: "manual"
  });
  const cookie = (String(reply.headers.get("set-cookie") || "")
      .match(/(sts_mock_session=[^;]+)/) || [])[1];
  assert.ok(cookie,
    "signing in at /authn/login should set the session cookie; the reply was " +
    reply.status + ". This service checks no password, so a refusal here is " +
    "about the request rather than the credential.");
  log.debug("Leaving signIn().");
  return cookie;
}

// ---------------------------------------------------------------------------
// THE ROLE MODEL, which is the half of the gate a 302 cannot show.
//
// While NEITHER role group has a member, anybody who signs in holds BOTH —
// there is no password anywhere to bootstrap an administrator with, so the
// empty roster opens rather than closes. The moment somebody is granted a role
// the roster is enforced, INCLUDING AGAINST WHOEVER MADE THE GRANT.
//
// So this section closes the console against itself on purpose, checks that a
// reader can read and cannot write, and opens it again. It is the most
// destructive thing in this file and it is why the job is EXCLUSIVE: while it
// is running, every other job's console session holds nothing.
// ---------------------------------------------------------------------------
async function theTwoRolesAreEnforced() {
  log.debug("Entering theTwoRolesAreEnforced().");
  log.info("=== The two console roles ===");
  if (!gateIsOn) {
    log.info("[roles] Skipped: admin.authRequired is off, so there is no " +
             "gate for a role to open.");
    log.debug("Leaving theTwoRolesAreEnforced(). The gate is off.");
    return;
  }
  const roster = await common.httpJson(root("/admin-api/rbac"));
  assert.strictEqual(roster.status, 200, "GET /admin-api/rbac should answer 200.");
  if (roster.body.grantCount > 0) {
    log.warn("[roles] Skipped: the roster already has " +
             roster.body.grantCount + " grant(s) on it, so this run did not " +
             "meet the empty-roster state and closing the console would " +
             "change somebody else's configuration rather than this test's. " +
             "Reported rather than passed over.");
    log.debug("Leaving theTwoRolesAreEnforced(). The roster is not empty.");
    return;
  }

  const reader = "console-reader-" + names.runStamp();
  try {
    // Granting READ to somebody else is what closes the console: from this
    // moment the roster is enforced and this file's own session holds nothing.
    await grant(reader, "read");
    const shutOut = await page(root("/admin/tokens"));
    assert.strictEqual(shutOut.status, 403,
      "ONCE SOMEBODY HOLDS A ROLE THE ROSTER IS ENFORCED AGAINST EVERYBODY, " +
      "including whoever made the grant. " + CONSOLE_USER + " holds neither " +
      "role now and asked for /admin/tokens, which answered " +
      shutOut.status + " -> " + shutOut.location + ". A 302 here would mean " +
      "a signed-in person being sent back to a sign-in screen they have " +
      "already passed, which is the loop this 403 exists to avoid.");

    // The reader can READ every page and can POST none of them. That is the
    // whole difference between the two roles, and a console with one role
    // would pass every other check in this file.
    const readerSession = session;
    session = await signIn(reader);
    const read = await page(root("/admin/tokens"));
    assert.strictEqual(read.status, 200,
      "a holder of admin-read should be able to READ the console; " + reader +
      " got " + read.status);
    const write = await postForm("/admin/tokens",
        { action: "revoke", jti: "nothing-at-all" });
    assert.strictEqual(write.status, 403,
      "AND MUST NOT BE ABLE TO POST ANYTHING. admin-read is defined as " +
      "'look at every page and change nothing' — a reader can see which " +
      "tokens are revoked and cannot revoke one — so a form POST from one " +
      "must be refused 403. It answered " + write.status + " -> " +
      write.location);
    session = readerSession;
    log.info("[roles] OK — a grant closes the roster against everybody, a " +
             "reader reads every page, and a reader's form POST is refused " +
             "403.");
  } finally {
    // Whatever happened, the roster goes back to empty — through /admin-api,
    // which is not gated, because the console is now closed to this file.
    await revoke(reader, "read");
    const after = await common.httpJson(root("/admin-api/rbac"));
    assert.strictEqual(after.body.grantCount, 0,
      "AND THE ROSTER MUST BE EMPTY AGAIN. While it is not, every other job " +
      "in this run that reads a console page is refused 403 — and the job " +
      "that fails is not this one. It holds " + after.body.grantCount +
      " grant(s).");
    log.debug("[roles] The roster is empty again.");
  }
  log.debug("Leaving theTwoRolesAreEnforced().");
}

async function grant(username, role) {
  log.debug("Entering grant(). username=" + username);
  const reply = await common.httpJson(root("/admin-api/rbac/grant"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: username, role: role })
  });
  assert.ok(reply.status === 200 && reply.body.ok !== false,
    "granting " + role + " to " + username + " through the ungated API " +
    "should work; it answered " + reply.status + " " +
    JSON.stringify(reply.body).slice(0, 200));
  log.debug("Leaving grant().");
}

async function revoke(username, role) {
  log.debug("Entering revoke(). username=" + username);
  const reply = await common.httpJson(root("/admin-api/rbac/revoke"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: username, role: role })
  });
  if (reply.status !== 200) {
    log.warn("Could not revoke " + role + " from " + username + ": " +
             JSON.stringify(reply.body).slice(0, 200));
  }
  log.debug("Leaving revoke().");
}

// ---------------------------------------------------------------------------
// EVERY PAGE, DRAWN, IN THE SHELL, UNDER THE POLICY.
//
// The page list is read off the service (`GET /admin-api/status` carries the
// console's own `pages`), never typed here, so a page added to SECTIONS is a
// page this walk starts checking with no edit — which is the same principle
// the console's own nav follows, where NAV is DERIVED from SECTIONS rather
// than written twice.
// ---------------------------------------------------------------------------
async function everyPageIsDrawn(pages) {
  log.debug("Entering everyPageIsDrawn().");
  log.info("=== Every console page ===");
  let forms = 0;
  for (const path of pages) {
    const reply = await html(path);

    // The shell. A page that answered 200 with a body and no nav is a page
    // that was drawn OUTSIDE respond() — which is how a new route quietly
    // stops being part of the console.
    assert.ok(reply.html.indexOf("<nav") > 0 && reply.html.indexOf("navsec") > 0,
      path + " should be drawn in the console shell, with the grouped nav " +
      "down the left. A page drawn outside respond() answers 200 and looks " +
      "almost right.");
    assert.ok(/<p class="crumb">/.test(reply.html),
      path + " should carry a breadcrumb. It is on EVERY page — on /admin " +
      "itself it is the one crumb — because the nav answers 'what else is " +
      "there' and the trail answers 'where am I'.");

    // The policy. `frame-ancestors` is the clause with no fallback from
    // `default-src`, so it is the one a page loses by accident — five routes
    // in this service relax the policy by setting the whole header, and the
    // page works, the script runs, and the protection is gone.
    const policy = reply.headers.get("content-security-policy") || "";
    assert.ok(/frame-ancestors\s+'none'/.test(policy),
      path + " must carry `frame-ancestors 'none'` (RFC 9700 section 4.14). " +
      "It has NO FALLBACK from default-src, so `default-src 'none'` alone is " +
      "not enough and a relaxation that set the whole header would drop it " +
      "with nothing failing. The policy is: " + policy);
    assert.ok(/script-src\s+'none'/.test(policy),
      path + " must still be `script-src 'none'`. Not one page of this " +
      "console has a script on it — the two drawings are laid out on the " +
      "server for exactly this reason — so a page here that relaxed it " +
      "would be the first, and would need the argument made rather than " +
      "cited. The policy is: " + policy);
    assert.ok(/base-uri\s+'none'/.test(policy),
      path + " should carry `base-uri 'none'` beside it; the policy is: " +
      policy);

    // And the page really has no script on it, whatever the header says. The
    // header is the promise; this is the thing itself.
    assert.ok(reply.html.indexOf("<script") < 0,
      path + " has a <script> on it. The whole console is script-free and " +
      "the header says so, so this page would be blocked and broken rather " +
      "than dangerous — which is worse than either, because it looks fine " +
      "until somebody presses the control that needed it.");

    forms += formsOn(reply.html).length;
  }
  log.info("[pages] OK — all " + pages.length + " console pages are drawn in " +
           "the shell with a breadcrumb, under `script-src 'none'`, " +
           "`frame-ancestors 'none'` and `base-uri 'none'`, carrying " +
           forms + " forms between them and no script anywhere.");
  log.debug("Leaving everyPageIsDrawn().");
}

// ---------------------------------------------------------------------------
// NO PAGE HAS A FORM INSIDE A FORM, and this is a regression guard for a real
// defect rather than a tidiness rule.
//
// The HTML parser DROPS a nested `<form>` start tag and adopts its children
// into the OUTER form. So a section's Save button and a row's Reset button end
// up in one form, `parseBody()` takes the last value for a repeated name, and
// pressing Save performed the Reset. Nothing failed anywhere: the markup was
// well formed to a reader, the page rendered, the button worked — on the wrong
// thing. It was found on /admin/config with `--dump-dom`, by comparing the
// PARSED DOM against the source, and the fix was `formaction` on the button.
//
// The check is one scan of the source, and it is deliberately made against the
// SOURCE and not against a parsed tree: a parser answers this question by
// silently repairing it, which is the defect.
// ---------------------------------------------------------------------------
async function noPageNestsAForm(pages) {
  log.debug("Entering noPageNestsAForm().");
  log.info("=== No form inside a form ===");
  const offenders = [];
  for (const path of pages) {
    const reply = await html(path);
    let depth = 0;
    let worst = 0;
    const pattern = /<\/?form\b/gi;
    let found;
    while ((found = pattern.exec(reply.html))) {
      depth += found[0][1] === "/" ? -1 : 1;
      worst = Math.max(worst, depth);
    }
    if (worst > 1) {
      offenders.push(path);
    }
    assert.strictEqual(depth, 0,
      path + " has " + (depth > 0 ? depth + " unclosed" : (-depth) + " extra " +
      "closing") + " <form> tag(s). A page whose forms do not balance is a " +
      "page whose controls belong to whichever form the parser decided on.");
  }
  assert.deepStrictEqual(offenders, [],
    "THESE PAGES HAVE A <form> INSIDE ANOTHER <form>: " + offenders.join(", ") +
    ". The HTML parser drops the inner start tag and adopts its controls into " +
    "the outer form, so the two buttons post together and the last value of " +
    "a repeated name wins — which is how /admin/config's section Save came " +
    "to perform a row's Reset, with the markup carrying a comment explaining " +
    "why it was correct. Use `formaction` on the button instead.");
  log.info("[markup] OK — no page nests a form, and every page's form tags " +
           "balance.");
  log.debug("Leaving noPageNestsAForm().");
}

// ---------------------------------------------------------------------------
// EVERY CONTROL POSTS SOMEWHERE THAT EXISTS, AND NAMES AN ACTION THAT EXISTS.
//
// This is the structural half of "every button does what it is supposed to",
// and it covers every control on every page — including the ones the
// behavioural half below cannot reach, because they need a referent that this
// realm has none of.
//
// Two facts are read off the SERVICE rather than typed here: which paths accept
// a POST (the management API's index names the console control each of its
// operations mirrors) and which action names each handler knows (each one
// answers an unknown action by naming the ones it has). So a console control
// posting an action the handler does not have fails here, and so does one
// posting to a path with no POST route behind it — which is what a rename
// produces, and which draws and looks completely normal.
// ---------------------------------------------------------------------------
async function everyControlReachesSomething(pages) {
  log.debug("Entering everyControlReachesSomething().");
  log.info("=== Every control posts to a route that exists ===");
  const knownActions = await actionsByConsolePath();
  const problems = [];
  let checked = 0;

  for (const path of pages) {
    const reply = await html(path);
    for (const form of formsOn(reply.html)) {
      // A GET form is a filter or a page-size control: it changes nothing and
      // posts nowhere. It is checked further down, where the thing that
      // matters about it is that it carries the filter it must not drop.
      if (form.method !== "POST") {
        continue;
      }
      const targets = new Set();
      targets.add(form.action || path);
      form.controls.forEach(function (control) {
        if (control.formaction) {
          targets.add(control.formaction);
        }
      });
      for (const target of targets) {
        checked++;
        const route = String(target).split("?")[0];
        if (!Object.prototype.hasOwnProperty.call(knownActions, route)) {
          problems.push(path + ": a form posts to " + route +
                        ", which no /admin-api operation says it mirrors — " +
                        "so either that path has no POST route behind it, or " +
                        "it has one with no operation, which is the parity " +
                        "rule this service is written under.");
          continue;
        }
        const known = knownActions[route];
        if (!known.length) {
          continue;   // a POST route whose handler takes no `action` switch
        }
        const posted = actionValuesIn(form, target);
        posted.forEach(function (action) {
          if (known.indexOf(action) < 0) {
            problems.push(path + ": a control posts action=\"" + action +
                          "\" to " + route + ", and that handler knows only " +
                          known.join(", ") + ".");
          }
        });
      }
    }
  }
  assert.deepStrictEqual(problems, [],
    "CONTROLS ON THE CONSOLE THAT REACH NOTHING:\n  " + problems.join("\n  ") +
    "\nA control like this DRAWS PERFECTLY. The page renders, the button is " +
    "there, and pressing it produces a 404 or a refusal naming an action " +
    "nobody asked for — which is what a rename on either side produces, and " +
    "nothing inside the service can see it, because nothing there can see a " +
    "form appear on a page.");
  log.info("[controls] OK — " + checked + " form targets across " +
           pages.length + " pages, every one a POST route that exists, and " +
           "every action name one its handler knows.");
  log.debug("Leaving everyControlReachesSomething().");
}

// The action values a form would post to one target: the hidden `action` input,
// or the one in a `formaction`'s query string, which is how a second button on
// one form names a different action.
function actionValuesIn(form, target) {
  const values = [];
  const inQuery = String(target).match(/[?&]action=([^&]*)/);
  if (inQuery) {
    values.push(decodeURIComponent(inQuery[1]));
    return values;
  }
  form.controls.forEach(function (control) {
    if (control.name === "action" && control.value &&
        (control.tag === "input" || control.tag === "button")) {
      values.push(control.value);
    }
  });
  return values;
}

// console path -> the action names its handler knows, read off the service.
//
// The mapping comes from /admin-api's index, where every operation names the
// console control it MIRRORS — so this is the service's own account of which
// console paths take a POST, rather than a list in this file that would go
// stale exactly when a route was renamed. The action names come from each
// handler's own refusal, which is the same sentence tests/admin_api.js reads.
async function actionsByConsolePath() {
  log.debug("Entering actionsByConsolePath().");
  const index = await common.httpJson(root("/admin-api"));
  assert.strictEqual(index.status, 200,
    "GET /admin-api should answer its index; it answered " + index.status);
  const out = {};
  for (const operation of index.body.operations || []) {
    const mirrors = String(operation.mirrors || "");
    const found = mirrors.match(/^POST\s+(\/admin\S*)/);
    if (!found) {
      continue;
    }
    const consolePath = found[1].replace(/\/:.*$/, "").split("?")[0];
    if (Object.prototype.hasOwnProperty.call(out, consolePath)) {
      continue;
    }
    out[consolePath] = await actionsKnownAt(operation.path);
  }
  log.debug("Leaving actionsByConsolePath(). " +
            Object.keys(out).length + " console path(s) take a POST.");
  return out;
}

// The action names one API resource knows, out of its own refusal. Returns []
// for a handler that has no action switch at all, which is a legitimate shape
// and must not be read as "it knows none".
async function actionsKnownAt(apiPath) {
  log.debug("Entering actionsKnownAt(). apiPath=" + apiPath);
  const resource = String(apiPath).replace(/\/[^/]*$/, "");
  const probe = await common.httpJson(base + resource + "/__no_such_action__", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // Enough to get past the validation the three claim-set doors and the two
    // SAML ones do BEFORE they look at the action; a probe that never reaches
    // the switch comes back naming something else in a sentence of the same
    // shape, which admin_api.js already learnt the hard way.
    body: JSON.stringify({ set: "access_token", sp: "x", rp: "x",
                           id: "x", user: "x", entry: "x", agent: "x" })
  });
  const errors = ((probe.body && probe.body.errors) || []).join(" ");
  const sentence = errors.match(/Unknown action "[^"]*"\.\s*[^:]*:\s*([^.]+)\./);
  const out = sentence ? sentence[1].split(/,\s*|\s+and\s+/).map(function (one) {
    return one.trim();
  }).filter(Boolean) : [];
  log.debug("Leaving actionsKnownAt(). " + out.length + " action(s).");
  return out;
}

// ---------------------------------------------------------------------------
// PRESSING A FORM EXACTLY AS THE PAGE DREW IT.
//
// The forms above are checked structurally; this is what presses them. It
// builds the submission out of the form's OWN controls — every hidden input
// verbatim, every select's first option, and every text box from a table of
// values keyed by field name — which is what a browser sends, and which is the
// only way to reach the controls that are drawn PER ROW.
//
// Those row controls are the ones worth having: /admin/tokens draws a revoke
// button for every token it is holding, each carrying that token's own
// identifier and the `back` that keeps the reader's place in the list. A test
// that posted `{action: 'revoke', target: someJti}` would prove the handler
// works and would never notice the page rendering the wrong jti into the
// button beside it.
// ---------------------------------------------------------------------------
async function pressEveryFormOn(path, values, options) {
  log.debug("Entering pressEveryFormOn(). path=" + path);
  const settings = options || {};
  const reply = await html(path);
  const forms = formsOn(reply.html).filter(function (form) {
    return form.method === "POST";
  });
  assert.ok(forms.length,
    path + " should have at least one control on it to press; it has none.");
  let pressed = 0;
  for (const form of forms) {
    const target = form.action || path;
    if (settings.skip && settings.skip.some(function (p) {
      return p.test(target + " " + JSON.stringify(actionValuesIn(form, target)));
    })) {
      continue;
    }
    const fields = fieldsFor(form, values);
    if (fields === null) {
      log.debug("[press] skipping a form on " + path +
                " that needs a value nothing supplied.");
      continue;
    }
    const notice = await press(target, fields,
        "press the control on " + path + " whose action is " +
        JSON.stringify(actionValuesIn(form, target)));
    log.debug("[press] " + path + " " + JSON.stringify(fields).slice(0, 120) +
              " -> " + notice.slice(0, 100));
    pressed++;
  }
  log.debug("Leaving pressEveryFormOn(). " + pressed + " control(s) pressed.");
  return pressed;
}

// The submission one form would make. Returns null when a required text box has
// no value in the table — a caller that has nothing to type into a box has not
// pressed that button, and saying so is better than posting an empty string and
// asserting on whatever refusal comes back.
function fieldsFor(form, values, blanksAreValues) {
  log.debug("Entering fieldsFor().");
  const fields = {};
  let missing = false;
  form.controls.forEach(function (control) {
    if (!control.name || control.disabled) {
      return;
    }
    if (control.tag === "input" &&
        (control.type === "hidden" || control.type === "submit")) {
      // A hidden field goes verbatim — `action`, `back`, `from`, and the
      // per-row identifier that makes a row's button that row's.
      fields[control.name] = control.value;
      return;
    }
    if (control.tag === "button" && control.name === "action") {
      fields[control.name] = control.value;
      return;
    }
    if (control.tag === "select") {
      const chosen = Object.prototype.hasOwnProperty.call(values, control.name)
          ? values[control.name] : selectedOptionOf(form.inner, control.name);
      if (chosen === undefined) {
        missing = true;
        return;
      }
      fields[control.name] = chosen;
      return;
    }
    // A text box, a checkbox or a textarea.
    if (Object.prototype.hasOwnProperty.call(values, control.name)) {
      fields[control.name] = values[control.name];
      return;
    }
    if (control.value) {
      fields[control.name] = control.value;
      return;
    }
    if (blanksAreValues) {
      // A SETTINGS SECTION draws a box per setting, filled with the value in
      // force — and a setting whose value is the empty string draws an empty
      // box. A browser posts that box as an empty string, and so must this:
      // treating it as "nothing to type here" would drop the field, and
      // `set-many` is all-or-nothing over the fields it is GIVEN.
      fields[control.name] = "";
      return;
    }
    missing = true;
  });
  log.debug("Leaving fieldsFor(). " + (missing ? "incomplete" : "complete"));
  return missing ? null : fields;
}

// The option a named select would POST: the one marked `selected`, falling back
// to the first. Both halves matter. A select posts one of its own options and
// nothing else, so a test that invented a value would be sending a request no
// browser can make — and taking the FIRST option rather than the SELECTED one
// silently changes the setting on every save, which turns "press Save and
// nothing should change" into a test that changes something every time it runs.
function selectedOptionOf(inner, name) {
  const block = inner.match(new RegExp(
      '<select[^>]*name="' + name + '"[^>]*>([\\s\\S]*?)</select>', "i"));
  if (!block) {
    return undefined;
  }
  const chosen = block[1].match(/<option[^>]*value="([^"]*)"[^>]*\bselected\b/i) ||
      block[1].match(/<option[^>]*\bselected\b[^>]*value="([^"]*)"/i) ||
      block[1].match(/<option[^>]*value="([^"]*)"/i);
  return chosen ? decode(chosen[1]) : undefined;
}

// ---------------------------------------------------------------------------
// THE THROWAWAY REALM, MADE ON THE CONSOLE'S OWN FORM.
//
// It is created by pressing the button on /admin/realms rather than through the
// API, because that button is one of the controls under test — and because a
// realm made the other way would not prove that this one works.
// ---------------------------------------------------------------------------
async function theRealmIsCreatedOnTheForm() {
  log.debug("Entering theRealmIsCreatedOnTheForm().");
  log.info("=== Creating the throwaway realm on /admin/realms ===");
  const notice = await press("/admin/realms", {
    action: "create", id: REALM, name: "Console test",
    description: "Created by tests/sts_admin_console.js; removed at the end.",
    back: ""
  }, "create a trust realm");
  assert.ok(notice.indexOf(REALM) >= 0,
    "the notice should name the realm it made; it said " + notice);

  const listed = await json("/admin/realms");
  assert.ok((listed.realms || []).some(function (row) { return row.id === REALM; }),
    "and the realm should be on /admin/realms afterwards; it lists " +
    JSON.stringify((listed.realms || []).map(function (r) { return r.id; })));

  // The console under the realm's prefix is reachable WITH THE DEFAULT REALM'S
  // SESSION, and that is the one place this service reads a session across
  // realms. It is deliberate: the two roles are one roster for the process,
  // because a role is permission to change what every realm does — so a
  // per-realm roster would let anybody who can create a realm administer the
  // whole service.
  const inRealm = await page(realm("/admin/applications"));
  assert.strictEqual(inRealm.status, 200,
    "the console under /realm/" + REALM + " should be reachable with the " +
    "DEFAULT realm's session — it is the only session this service reads " +
    "across realms, and the reason is that the two admin roles are one " +
    "roster for the process. It answered " + inRealm.status + " -> " +
    inRealm.location);
  assert.ok(inRealm.html.indexOf(REALM) > 0,
    "and the page should say which realm it is showing; the console carries " +
    "a realm switcher on every page and shows ONE realm at a time, so a page " +
    "that named none would be one a reader could act on believing it was the " +
    "default realm's.");
  log.info("[realm] OK — created " + REALM + " on the form, and its console " +
           "is reachable with the default realm's session.");
  log.debug("Leaving theRealmIsCreatedOnTheForm().");
}

async function theRealmIsRemovedOnTheForm() {
  log.debug("Entering theRealmIsRemovedOnTheForm().");
  try {
    // Pressed at the ROOT: `remove` refuses the realm the call arrived in,
    // which is the registry's one refusal about the caller rather than the
    // request.
    const refused = await postForm("/realm/" + REALM + "/admin/realms",
        { action: "remove", id: REALM, back: "" });
    const error = outcomeOf(refused.location, "error");
    assert.ok(error,
      "removing a realm FROM INSIDE ITSELF must be refused — the caller " +
      "would be left talking to a prefix that had stopped existing. It said " +
      (outcomeOf(refused.location, "notice") || "nothing"));

    await press("/admin/realms", { action: "remove", id: REALM, back: "" },
        "remove the throwaway realm");
    const listed = await json("/admin/realms");
    assert.ok(!(listed.realms || []).some(function (row) {
      return row.id === REALM;
    }), "and it should be gone from /admin/realms.");
    log.info("[teardown] Removed " + REALM + " on the form, and with it " +
             "everything this job created inside it.");
  } catch (e) {
    // Reported and not rethrown: a teardown that threw would replace the
    // failure that actually matters with the failure to tidy up after it.
    log.warn("Teardown could not finish: " + e.message);
  }
  log.debug("Leaving theRealmIsRemovedOnTheForm().");
}

// ---------------------------------------------------------------------------
// THE DIRECTORY PAGES: create a person, create an application, and read each
// back through the page's own JSON view.
//
// /admin/users' form is the one control on that page and it arrived late — it
// was a page with no form on it for months, which is why mgmt-api/CLAUDE.md
// uses it as the worked example of the parity rule. What it does NOT do is
// make the person appear in the table, and that is the assertion worth having:
// the list is who this service has SEEN, and the entry is what the directory
// HOLDS, and a console that conflated them would be one where creating
// somebody looked like somebody having signed in.
// ---------------------------------------------------------------------------
async function theDirectoryPagesWork() {
  log.debug("Entering theDirectoryPagesWork().");
  log.info("=== /admin/users and /admin/applications ===");
  const person = names.usernameFor("console-person");
  const before = await json("/realm/" + REALM + "/admin/users");

  const notice = await press("/realm/" + REALM + "/admin/users",
      { action: "create", username: person, back: "" },
      "create a person in the directory");
  assert.ok(notice.indexOf(person) >= 0 && /dc=/.test(notice),
    "the notice should name the DN it created, so a reader can go and find " +
    "it with an ldapsearch; it said " + notice.slice(0, 200));

  const after = await json("/realm/" + REALM + "/admin/users");
  assert.strictEqual(after.authenticatedHere, before.authenticatedHere,
    "CREATING SOMEBODY MUST NOT COUNT AS AN AUTHENTICATION. This table is " +
    "who this service has SEEN and the entry is what the directory HOLDS; a " +
    "console that conflated them would show every person somebody typed as " +
    "though they had signed in. It went from " + before.authenticatedHere +
    " to " + after.authenticatedHere);

  const drill = await html("/realm/" + REALM + "/admin/users?user=" +
      encodeURIComponent(person));
  assert.ok(drill.html.indexOf(person) > 0,
    "and the person's own page should be reachable and should name them.");
  await pressAndBeRefused("/realm/" + REALM + "/admin/users",
      { action: "create", username: person, back: "" },
      /already/i,
      "a second entry for one person — one object per person is the rule " +
      "this directory keeps at every door");

  // The applications page, and the create form on /admin/applications/new,
  // which posts a REPEATED `protocol` field — the checkbox column. That is the
  // trap worth driving: helpers.parseBody() cannot see a repeated field, so
  // the create reads them through namesOf() instead, and a regression there
  // creates the application with ONE family out of five and answers 200.
  const identifier = "console-app-" + names.runStamp();
  const form = await html("/realm/" + REALM + "/admin/applications/new");
  // The families come off whichever form on that page draws the checkbox
  // column, found by looking for the boxes rather than by taking the first
  // form — the page also carries the realm switcher and a filter form, and
  // "the first form" is the kind of assumption that breaks silently when a
  // page grows a control above the one under test.
  const families = formsOn(form.html).reduce(function (found, one) {
    return found.length ? found : one.controls.filter(function (control) {
      return control.name === "protocol" && control.value;
    }).map(function (control) { return control.value; });
  }, []);
  assert.ok(families.length > 3,
    "/admin/applications/new should draw a checkbox per protocol family; it " +
    "drew " + families.length);

  await press("/realm/" + REALM + "/admin/applications", {
    action: "create", identifier: identifier, name: "Console test app",
    protocol: [families[0], families[1], families[2]], back: ""
  }, "create an application with three protocol families ticked");

  const entry = await json("/realm/" + REALM + "/admin/applications?application=" +
      encodeURIComponent(identifier));
  assert.strictEqual(entry.found, true,
    "the application should be in the registry after the create.");
  assert.deepStrictEqual((entry.allowedProtocols || []).slice().sort(),
    [families[0], families[1], families[2]].sort(),
    "AND ALL THREE TICKED FAMILIES MUST BE ON IT. The checkbox column posts " +
    "`protocol` REPEATED, and helpers.parseBody() cannot see a repeated " +
    "field — it takes the last value — so a create that read the body the " +
    "ordinary way declares ONE family out of three and answers 200. The " +
    "entry declares " + JSON.stringify(entry.allowedProtocols));

  log.info("[directory] OK — a person and an application created on the " +
           "console's own forms, the repeated checkbox column carried all " +
           "three families, and creating somebody counted as no sign-in.");
  log.debug("Leaving theDirectoryPagesWork(). identifier=" + identifier);
  return { person: person, identifier: identifier };
}

// ---------------------------------------------------------------------------
// THE TOKENS PAGE, WHICH IS WHERE THE ROW BUTTONS ARE.
//
// Every token this realm holds gets a revoke button of its own, carrying that
// token's identifier and the `back` that keeps the reader's place. Pressing
// them AS DRAWN is the assertion: a page that rendered the right list and the
// wrong identifier into the buttons beside it would pass every check made
// against the handler.
//
// The effect is confirmed at /oauth2/introspect rather than in the console's
// own list, because the console's list is the thing under test.
// ---------------------------------------------------------------------------
async function theTokensPageRevokesWhatItDraws() {
  log.debug("Entering theTokensPageRevokesWhatItDraws().");
  log.info("=== /admin/tokens: the row buttons, and the bulk ones ===");
  const person = names.usernameFor("console-token");
  const tokens = await mintTokens(person, "console-client-" + REALM);
  assert.strictEqual(await introspectActive(tokens.access), true,
    "a freshly minted access token should introspect as active.");

  // Find the row button for OUR token, out of the page's own markup, and press
  // exactly it. `target` is what the button carries; nothing here invents it.
  const listed = await html("/realm/" + REALM + "/admin/tokens");
  const rowForm = formsOn(listed.html).filter(function (form) {
    return form.method === "POST" && form.controls.some(function (control) {
      return control.name === "target" && control.value === tokens.jti;
    });
  })[0];
  assert.ok(rowForm,
    "/admin/tokens should draw a revoke button for every token it holds, " +
    "each carrying that token's own jti. It drew none for " + tokens.jti +
    ", so either the token is not listed or the button beside it names " +
    "something else — and the second is the defect that a check against the " +
    "handler cannot see.");
  const carried = fieldsFor(rowForm, {});
  assert.strictEqual(carried.action, "revoke",
    "the row button's action should be `revoke`; it is " + carried.action);
  assert.ok(carried.back !== undefined,
    "AND IT MUST CARRY `back`. Every form on a list page carries the reader's " +
    "filter and page in one opaque field, which the POST handler rebuilds — " +
    "so a form that lost it costs the reader their place in the list every " +
    "time they press a button. It carried " + JSON.stringify(carried));

  await press("/realm/" + REALM + "/admin/tokens", carried,
      "revoke one token with the button drawn beside it");
  assert.strictEqual(await introspectActive(tokens.access), false,
    "PRESSING THE ROW BUTTON MUST REACH RFC 7662 INTROSPECTION. There is one " +
    "revocation set serving both this console and /oauth2/revoke; a second " +
    "would look correct from either side and never see the other.");

  // The bulk buttons, each of which selects differently, and the assertion
  // that matters for all of them is the negative one.
  const other = await mintTokens(names.usernameFor("console-token-other"),
                                 "console-client-" + REALM);
  await press("/realm/" + REALM + "/admin/tokens",
      { action: "revoke-subject", subject: tokens.sub, back: "" },
      "revoke everything for one subject");
  assert.strictEqual(await introspectActive(other.access), true,
    "AND A BULK REVOCATION MUST LEAVE SOMEBODY ELSE'S TOKEN ALONE. Each of " +
    "these buttons selects a different way, and a selector that quietly " +
    "matched everything would satisfy every other check on this page.");

  await press("/realm/" + REALM + "/admin/tokens",
      { action: "revoke-all", back: "" }, "revoke everything in this realm");
  assert.strictEqual(await introspectActive(other.access), false,
    "`revoke everything` should now have reached it too.");

  // And back again, one at a time, which is the only way back from
  // `revoke-all` and is why the non-spec restore exists at all.
  await press("/realm/" + REALM + "/admin/tokens",
      { action: "restore", target: other.jti, back: "" },
      "restore one token");
  assert.strictEqual(await introspectActive(other.access), true,
    "`restore` should bring it back — RFC 7009 defines no un-revoke and this " +
    "console says so where the button is, but a mock that could not get back " +
    "to a working credential without a restart is a mock nobody can iterate " +
    "against.");
  log.info("[tokens] OK — the row button carries its own token's jti and its " +
           "`back`, pressing it reaches introspection, and each bulk button " +
           "was shown to leave something alone.");
  log.debug("Leaving theTokensPageRevokesWhatItDraws().");
}

async function mintTokens(username, client) {
  log.debug("Entering mintTokens(). username=" + username);
  const reply = await common.httpJson(realm("/oauth2/token"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=password&username=" + encodeURIComponent(username) +
          "&password=" + encodeURIComponent(username) +
          "&client_id=" + encodeURIComponent(client) + "&scope=openid"
  });
  assert.strictEqual(reply.status, 200,
    "the realm's token endpoint should mint a token for " + username +
    "; it answered " + reply.status + " " + String(reply.raw).slice(0, 200));
  const out = { access: reply.body.access_token,
                jti: claimOf(reply.body.access_token, "jti"),
                sub: claimOf(reply.body.access_token, "sub") };
  log.debug("Leaving mintTokens(). jti=" + out.jti);
  return out;
}

function claimOf(jwt, name) {
  if (!jwt) {
    return "";
  }
  const parts = String(jwt).split(".");
  if (parts.length < 2) {
    return "";
  }
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))[name] || "";
  } catch (e) {
    // A token this service minted always decodes; one that does not is worth
    // reporting as an absent claim rather than as a crash, because the
    // assertion that follows says more about what went wrong.
    return "";
  }
}

async function introspectActive(token) {
  log.debug("Entering introspectActive().");
  const reply = await common.httpJson(realm("/oauth2/introspect"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(token)
  });
  assert.strictEqual(reply.status, 200,
    "introspection should answer 200 whatever it thinks of the token.");
  log.debug("Leaving introspectActive(). active=" + reply.body.active);
  return reply.body.active === true;
}

// ---------------------------------------------------------------------------
// THE REST OF THE CONTROLS, PRESSED AS DRAWN.
//
// One entry per page that has controls this test can supply values for. The
// values are keyed by the FIELD NAME the page draws, so a form that gained a
// box nothing here fills is skipped and said so rather than posted empty —
// which is the honest failure mode for a table like this.
//
// Everything happens under the realm prefix, so all of it goes away with the
// realm.
// ---------------------------------------------------------------------------
async function everyOtherControlIsPressed(created) {
  log.debug("Entering everyOtherControlIsPressed().");
  log.info("=== The remaining controls, pressed as the pages draw them ===");
  const stamp = names.runStamp();
  const pages = [
    { path: "/admin/claims",
      values: { name: "console_claim", value: "yes", set: "access_token",
                original: "console_claim", claims: "[]" } },
    { path: "/admin/userinfo-claims",
      values: { name: "console_userinfo_claim", value: "yes", set: "userinfo",
                original: "console_userinfo_claim", claims: "[]" } },
    { path: "/admin/saml-attributes",
      values: { name: "console_saml_attr", value: "yes", set: "saml2",
                original: "console_saml_attr", claims: "[]" } },
    { path: "/admin/saml2",
      values: { sp: "urn:console:" + stamp + ":sp",
                acs: "https://sp.example/acs/" + stamp,
                value: "https://sp.example/slo/" + stamp } },
    { path: "/admin/saml11",
      values: { rp: "urn:console:" + stamp + ":rp",
                target: "https://rp.example/" + stamp } },
    { path: "/admin/authorization-servers",
      values: { id: "as" + stamp.slice(0, 8), name: "Console AS" } },
    { path: "/admin/federation",
      values: { id: "fed" + stamp.slice(0, 8), name: "Console partner" } },
    { path: "/admin/vc", values: {} },
    { path: "/admin/vc-verifier-config", values: { name: "given_name" } },
    { path: "/admin/spiffe/entries",
      values: { spiffeId: "spiffe://example.org/console/" + stamp.slice(0, 8),
                parentId: "spiffe://example.org/spire/agent/console",
                selectors: "unix:uid:1000" } }
  ];

  let pressed = 0;
  for (const one of pages) {
    // The settings block every page grew on 2026-08-27 posts `set-many` to
    // /admin/config, and it is driven in its own section below — where what is
    // asserted is that the value reaches the configuration and the store,
    // which is the whole point of it and is not something to check twelve
    // times over.
    pressed += await pressEveryFormOn("/realm/" + REALM + one.path, one.values,
        { skip: [/\/admin\/config/] });
  }
  assert.ok(pressed > 15,
    "this walk should have pressed a good many controls; it pressed " +
    pressed + ". A collapse here means the value table has stopped matching " +
    "the field names the pages draw, and every form is being skipped rather " +
    "than failing.");
  log.info("[controls pressed] OK — " + pressed + " controls across " +
           pages.length + " pages, each posted with the fields its own form " +
           "draws, each answering with a notice rather than a refusal.");
  log.debug("Leaving everyOtherControlIsPressed(). " + created.identifier);
}

// ---------------------------------------------------------------------------
// THE DRILL-DOWNS, AND THE THING THAT MAKES A TRAIL A TRAIL.
//
// `upTo()` makes a drill-down's section crumb a LINK, and `listViewOf()` makes
// that link carry the filter and the page the reader came from — so "back"
// lands where they were rather than at the top of an unfiltered list. Three
// places drop that if nobody carries it, and all three are checked here.
//
// The last crumb is never a link, which is the rule that stops a trail teaching
// a reader that its crumbs do nothing.
// ---------------------------------------------------------------------------
async function theDrillDownsCarryTheirTrail(created) {
  log.debug("Entering theDrillDownsCarryTheirTrail().");
  log.info("=== Breadcrumbs, drill-downs, and the reader's place in a list ===");

  // A LIST page: the crumb is one link plus a leaf that is not a link.
  const list = await html("/realm/" + REALM + "/admin/applications");
  const listCrumb = crumbOf(list.html);
  assert.ok(/<span class="leaf"/.test(listCrumb),
    "the last crumb must not be a link — a crumb that reloads the page you " +
    "are on teaches a reader not to trust the ones beside it. The crumb is: " +
    listCrumb);

  // A DRILL-DOWN reached through a FILTERED list: the section crumb becomes a
  // link and carries the filter.
  const filtered = "?q=" + encodeURIComponent(created.identifier) + "&per=10";
  const drill = await html("/realm/" + REALM + "/admin/applications" + filtered +
      "&application=" + encodeURIComponent(created.identifier));
  const crumb = crumbOf(drill.html);
  assert.ok(/<a href="[^"]*\/admin\/applications\?[^"]*q=/.test(crumb),
    "A DRILL-DOWN'S SECTION CRUMB MUST BE A LINK CARRYING THE LIST THE READER " +
    "CAME FROM. That is what makes it a breadcrumb rather than a second copy " +
    "of the nav: the tab for the section a reader is standing IN is exactly " +
    "the tab that says nothing about the page they are standing ON, and the " +
    "original defect was that the active tab was drawn as plain text, so the " +
    "one control pointing back at the list was the one control the shell had " +
    "turned off. The crumb is: " + crumb);
  assert.ok(/<span class="leaf"/.test(crumb),
    "and its own last crumb is still not a link. The crumb is: " + crumb);

  // Every form on that drill-down carries `back`, which the POST handler
  // REBUILDS rather than echoes. A new form here without it silently costs the
  // reader their place every time they use it.
  const withoutBack = formsOn(drill.html).filter(function (form) {
    return form.method === "POST" &&
        !form.controls.some(function (c) { return c.name === "back"; });
  });
  assert.deepStrictEqual(withoutBack.map(function (form) {
    return JSON.stringify(actionValuesIn(form, form.action));
  }), [],
    "EVERY FORM ON A DRILL-DOWN MUST CARRY `back`. The value is one opaque " +
    "field holding the list view the reader came from, and the POST handler " +
    "rebuilds it — so a form that does not carry it sends the reader back to " +
    "an unfiltered page one of every time they change anything. These do " +
    "not: " + withoutBack.map(function (form) {
      return JSON.stringify(actionValuesIn(form, form.action));
    }).join(", "));

  // And pressing one of those forms really does land back in the filtered
  // list, which is the property `back` exists for and the only one that
  // cannot be seen by reading the markup.
  const target = formsOn(drill.html).filter(function (form) {
    return form.method === "POST" &&
        actionValuesIn(form, form.action).indexOf("set") >= 0;
  })[0];
  if (target) {
    const fields = fieldsFor(target, { value: "back-check", attribute: "appName" });
    if (fields) {
      const reply = await postForm(
          "/realm/" + REALM + "/admin/applications", fields);
      assert.ok(/[?&]q=/.test(reply.location),
        "AND THE REDIRECT AFTER PRESSING IT MUST LAND IN THE FILTERED LIST. " +
        "`back` is rebuilt by the handler rather than echoed, so this is the " +
        "half of the arrangement the markup cannot show. It went to " +
        reply.location);
    }
  }
  log.info("[trail] OK — the last crumb is never a link, a drill-down's " +
           "section crumb carries the filter it was reached through, every " +
           "form on it carries `back`, and pressing one lands back in the " +
           "filtered list.");
  log.debug("Leaving theDrillDownsCarryTheirTrail().");
}

function crumbOf(markup) {
  const found = markup.match(/<p class="crumb">([\s\S]*?)<\/p>/);
  return found ? found[1] : "";
}

// ---------------------------------------------------------------------------
// FILTERING AND PAGING, AND THE ONE FIELD THE PAGE-SIZE FORM MUST NOT CARRY.
//
// A filter form is a GET form: it posts its own fields and nothing else, so the
// filter has to be spelt out as hidden inputs — and the PAGE deliberately is
// not, because changing how many rows are shown and staying on page nine is a
// request nobody makes.
// ---------------------------------------------------------------------------
async function filteringAndPagingWork() {
  log.debug("Entering filteringAndPagingWork().");
  log.info("=== Filters and paging on the list pages ===");
  const all = await json("/realm/" + REALM + "/admin/applications");
  assert.ok(all.applicationCount >= 1 || all.shown >= 1,
    "the applications list should have something in it by now; it reports " +
    JSON.stringify({ count: all.applicationCount, shown: all.shown }));

  const narrowed = await json("/realm/" + REALM +
      "/admin/applications?q=nothing-can-match-this-" + names.runStamp());
  assert.strictEqual(narrowed.shown, 0,
    "a filter nothing can match should narrow the list to nothing rather " +
    "than falling back to everything; it shows " + narrowed.shown);
  assert.ok(narrowed.applicationCount === all.applicationCount,
    "and the total held must NOT change with the filter — `count` is what " +
    "this realm holds and `shown` is what matched, and a page that " +
    "conflated them would report the filter as data loss. It says " +
    narrowed.applicationCount + " against " + all.applicationCount);

  const paged = await json("/realm/" + REALM + "/admin/applications?per=1");
  assert.strictEqual(paged.perPage, 1,
    "`per` should change the page size; the page reports " + paged.perPage);
  assert.ok(paged.shown <= 1,
    "and it should really show at most that many; it shows " + paged.shown);

  // The page-size form is a GET form that spells the filter out and leaves the
  // page behind, which is the one asymmetry in this arrangement.
  const withFilter = await html("/realm/" + REALM +
      "/admin/applications?q=console&per=10&page=1");
  const perForm = formsOn(withFilter.html).filter(function (form) {
    return form.method === "GET" &&
        form.controls.some(function (c) { return c.name === "per"; });
  })[0];
  assert.ok(perForm,
    "a list page should draw a page-size form; /admin/applications drew none.");
  const carries = perForm.controls.map(function (c) { return c.name; });
  assert.ok(carries.indexOf("q") >= 0,
    "IT MUST SPELL THE FILTER OUT AS A HIDDEN INPUT. A GET form posts its own " +
    "fields and NOTHING else, so a filter that is only in the URL is dropped " +
    "the moment somebody changes the page size. It carries " +
    JSON.stringify(carries));
  assert.ok(carries.indexOf("page") < 0,
    "AND IT MUST NOT CARRY THE PAGE. Changing how many rows are shown and " +
    "staying on page nine of the old paging is a request nobody makes, and " +
    "the row that was being read is not there any more. It carries " +
    JSON.stringify(carries));
  log.info("[lists] OK — a filter narrows `shown` without changing the total, " +
           "`per` really resizes the page, and the page-size form carries the " +
           "filter and deliberately not the page.");
  log.debug("Leaving filteringAndPagingWork().");
}

// ---------------------------------------------------------------------------
// THE TWO DRAWINGS, WHICH ARE THE PLACE THIS CONSOLE MOST WANTED A SCRIPT AND
// DID NOT GET ONE.
//
// /admin/delegation/map and /admin/federation/map draw graphs. Every graph
// library a person reaches for runs in the browser and would have made these
// the first scripted pages in the console; they are laid out on the SERVER
// instead — dagre computes the layout, the two renderers emit the shapes — and
// the SVG arrives inline as ordinary markup. So `script-src 'none'` is
// untouched and `img-src` is not even reached.
//
// What that costs is pan and zoom, which the pages say out loud rather than
// leaving somebody to wonder why dragging does nothing, and answer with
// `?format=svg` — which is asserted here, because a control that hands the
// document over is the whole compensation for the thing that was given up.
// ---------------------------------------------------------------------------
async function theTwoDrawingsAreServerSide() {
  log.debug("Entering theTwoDrawingsAreServerSide().");
  log.info("=== The delegation and federation pictures ===");
  for (const path of ["/admin/delegation/map", "/admin/federation/map"]) {
    const drawn = await html("/realm/" + REALM + path);
    assert.ok(drawn.html.indexOf("<svg") > 0,
      path + " should carry an inline <svg>: the layout is computed on the " +
      "server precisely so that the picture is ordinary markup.");
    assert.ok(drawn.html.indexOf("<script") < 0,
      path + " HAS A SCRIPT ON IT. These two pages are the strongest " +
      "candidates in this console for one and were refused twice, on the " +
      "same argument made twice from scratch: the test for a script is that " +
      "the page CANNOT work without one, and a diagram that does not move " +
      "can. A script here needs that argument made a third time, not cited.");
    const policy = drawn.headers.get("content-security-policy") || "";
    assert.ok(/script-src\s+'none'/.test(policy),
      path + " must still be served under `script-src 'none'`; it is: " + policy);

    const svg = await page(base + "/realm/" + REALM + path + "?format=svg");
    assert.strictEqual(svg.status, 200,
      path + "?format=svg should answer 200; it answered " + svg.status);
    assert.ok(/image\/svg\+xml/.test(svg.headers.get("content-type") || ""),
      "and it should be served as image/svg+xml, so that something which " +
      "DOES zoom can open it — that is the answer these pages give to the " +
      "pan and zoom they gave up. Its type is " +
      svg.headers.get("content-type"));
    assert.ok(svg.html.trim().indexOf("<svg") === 0 ||
              /^<\?xml/.test(svg.html.trim()),
      "and the body should be the SVG document itself rather than a page " +
      "with one in it; it starts " + svg.html.trim().slice(0, 80));
  }
  log.info("[drawings] OK — both pictures are inline server-rendered SVG " +
           "under `script-src 'none'`, and both hand the document over at " +
           "?format=svg.");
  log.debug("Leaving theTwoDrawingsAreServerSide().");
}

// ---------------------------------------------------------------------------
// A SETTING CHANGED ON THE PAGE FOR THE PROTOCOL IT CONFIGURES.
//
// Since 2026-08-27 every one of config.js's twenty-two groups is drawn on the
// console page for the family it configures, /admin/config keeps the one group
// that belongs to no protocol and is the INDEX of where the rest are. So the
// change is made where a person would make it, and is then looked for in three
// places — on that page, in the configuration table with its SOURCE moved, and
// in the persistence store's own write counters.
//
// The FIRST of those is the one that would otherwise go unchecked, and it is
// the reason this section is on the console side rather than the API side: a
// page can post a section perfectly and then draw the row from somewhere else.
// ---------------------------------------------------------------------------
async function aSettingChangedOnItsProtocolPage() {
  log.debug("Entering aSettingChangedOnItsProtocolPage().");
  log.info("=== A setting, changed on the page for its protocol ===");

  // Which page draws which group is a table in admin.js, published here — so
  // this walk asks the service where to go rather than carrying a second copy
  // of SETTING_HOMES that would go stale the day a group moved.
  const config = await common.httpJson(root("/admin-api/config"));
  assert.strictEqual(config.status, 200, "GET /admin-api/config should answer 200.");
  assert.deepStrictEqual(config.body.homeProblems || [], [],
    "EVERY GROUP OF SETTINGS MUST BE DRAWN ON SOME PAGE. `checkSettingHomes()` " +
    "runs at startup and reports a group with no page, a group with two rows, " +
    "a row naming a group config.js does not declare, and a row naming a path " +
    "that is not in SECTIONS. A setting that is READ by the service and " +
    "appears on no page is worse than one that is missing, because nothing " +
    "about the service's behaviour tells you it is there. It found: " +
    JSON.stringify(config.body.homeProblems));
  assert.ok((config.body.homes || []).length > 15,
    "and it should publish where each group is drawn; it published " +
    (config.body.homes || []).length + " rows.");

  // A runtime integer setting, and the page that draws its group. Both chosen
  // off the service so that this does not go stale when a setting is renamed
  // or a group is moved to another page.
  const chosen = anIntegerSettingWithAProtocolPage(config.body);
  assert.ok(chosen,
    "the configuration should carry at least one runtime integer setting " +
    "whose group is drawn on a page other than /admin/config; it carries none.");
  const wanted = Number(chosen.setting.value) + 1;
  log.info("[settings] Driving " + chosen.setting.key + " on " + chosen.path +
           ": " + chosen.setting.value + " -> " + wanted);

  // The form on that page is the one the console draws for the whole section,
  // and it posts `set-many` to /admin/config. Every field it draws goes back
  // verbatim except the one being changed — which is what a person pressing
  // Save actually sends, and is the case `set-many` is all-or-nothing for.
  const drawn = await html("/realm/" + REALM + chosen.path);
  const section = formsOn(drawn.html).filter(function (form) {
    return form.method === "POST" &&
        form.controls.some(function (c) { return c.name === chosen.setting.key; });
  })[0];
  assert.ok(section,
    chosen.path + " should draw a form carrying " + chosen.setting.key +
    ". /admin-api/config says that is where the `" + chosen.setting.group +
    "` group is drawn, and a page that does not draw it is the drift " +
    "checkSettingHomes() cannot see — it checks the TABLE, not the markup.");
  const fields = fieldsFor(section, {}, true);
  assert.ok(fields, "the section form should be fillable from its own controls.");
  fields[chosen.setting.key] = String(wanted);

  await press("/realm/" + REALM + "/admin/config", fields,
      "save the " + chosen.setting.group + " section on " + chosen.path);

  // 1. Back on the page it was changed on.
  const redrawn = await html("/realm/" + REALM + chosen.path);
  const redrawnValue = formsOn(redrawn.html).reduce(function (found, form) {
    return found || (form.controls.filter(function (c) {
      return c.name === chosen.setting.key;
    })[0] || {}).value;
  }, undefined);
  assert.strictEqual(String(redrawnValue), String(wanted),
    "THE PAGE MUST REDRAW THE VALUE IT WAS JUST GIVEN. This is the half no " +
    "check against /admin-api can make: a page can post a section perfectly " +
    "and then draw the row out of somewhere else, and the reader would see " +
    "their change vanish with the service holding it. It redrew " +
    JSON.stringify(redrawnValue));

  // 2. In the configuration table, with the source moved to this realm.
  const row = settingRow(await json("/realm/" + REALM + "/admin/config"),
      chosen.setting.key);
  assert.strictEqual(Number(row.value), wanted,
    "the configuration table should carry the new value; it carries " + row.value);
  assert.strictEqual(row.source, "realm",
    "and its SOURCE must have moved to `realm` — a setting saved under a " +
    "realm prefix is that realm's, held on the realm row, and a setting saved " +
    "at the root is the process's. A value that changed without the source " +
    "moving would mean a second store. It says " + row.source);

  await aRealmRuntimeSettingIsSettableOnItsPage();

  // 3. And in the store, if there is one.
  await theChangeReachedTheStore();
  log.debug("Leaving aSettingChangedOnItsProtocolPage().");
}

// A runtime integer setting whose group is drawn on a PROTOCOL page rather
// than on /admin/config, plus that page. Chosen off the service's own homes
// table so that this file carries no copy of SETTING_HOMES.
function anIntegerSettingWithAProtocolPage(config) {
  log.debug("Entering anIntegerSettingWithAProtocolPage().");
  const pageOfGroup = {};
  (config.homes || []).forEach(function (home) {
    const path = (home.pages || [])[0];
    if (path && path !== "/admin/config") {
      pageOfGroup[home.group] = path;
    }
  });
  let chosen;
  (config.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      if (chosen || setting.editable !== true || setting.overridden) {
        return;
      }
      if (!Number.isInteger(setting.value) ||
          setting.value < 1 || setting.value > 100000) {
        return;
      }
      if (!pageOfGroup[setting.group]) {
        return;
      }
      chosen = { setting: setting, path: pageOfGroup[setting.group] };
    });
  });
  log.debug("Leaving anIntegerSettingWithAProtocolPage(). " +
            (chosen ? chosen.setting.key : "(none)"));
  return chosen;
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
// THE ONE SETTING THAT IS RESTART-ONLY FOR THE PROCESS AND SETTABLE ON A REALM,
// AND WHY IT IS ASSERTED FROM THE PAGE RATHER THAN FROM THE TABLE.
//
// `oauth2.rfc9700` decides whether the main port is bound as HTTPS, and a
// listener's scheme is settled when the socket is bound — so it is restart-only
// for the process. A realm binds no socket, so the reason does not reach it and
// a realm MAY carry it: one process answers permissively at /oauth2/authorize
// and enforces the BCP at /realm/rfc9700/oauth2/authorize. config.js marks that
// with `realmRuntime`, and it is the only row that carries it.
//
// The console believes the marker: inside a realm it draws the control ENABLED,
// and at the root it draws it DISABLED with the reason in its title. What is
// asserted here is that the SAVE agrees with the drawing — which it did not,
// because setOverride() computed the realm and then called checkOverride()
// without telling it, so the marker could never take effect through that door.
//
// The failure was worse than the rule being absent, and it is worth stating
// because it is what makes this a page-level assertion rather than a table-level
// one: the section's Save posts `set-many`, which is ALL-OR-NOTHING, so
// pressing Save on /realm/<id>/admin/oauth2 was refused every time — including
// when nothing on the page had been changed — and the refusal explained,
// correctly, that a realm may carry the setting it was refusing. Nothing that
// reads the configuration table can see that; it needs the page's own form.
// ---------------------------------------------------------------------------
async function aRealmRuntimeSettingIsSettableOnItsPage() {
  log.debug("Entering aRealmRuntimeSettingIsSettableOnItsPage().");
  log.info("=== The realm-runtime setting, on the page that draws it ===");
  const KEY = "oauth2.rfc9700";

  const atRoot = await html("/admin/oauth2");
  const rootControl = controlNamed(atRoot.html, KEY);
  assert.ok(rootControl,
    "/admin/oauth2 should draw " + KEY + "; it draws no control by that name.");
  assert.strictEqual(rootControl.disabled, true,
    "AT THE ROOT IT MUST BE DRAWN DISABLED. It decides whether the main port " +
    "is bound as HTTPS and a listener's scheme is settled when the socket is " +
    "bound, so the process cannot change it while running — and a console " +
    "that offered an editable box would be offering something its own Save " +
    "refuses.");

  const inRealm = await html("/realm/" + REALM + "/admin/oauth2");
  const realmControl = controlNamed(inRealm.html, KEY);
  assert.ok(realmControl,
    "/realm/" + REALM + "/admin/oauth2 should draw " + KEY + " too.");
  assert.strictEqual(realmControl.disabled, false,
    "AND INSIDE A REALM IT MUST BE DRAWN ENABLED. A realm binds no socket, so " +
    "the reason the process cannot change it does not reach a realm — that is " +
    "the `realmRuntime` marker, and it is the only row in config.js that " +
    "carries it.");

  // And the section's Save must agree with the drawing. The whole section is
  // posted, as a browser posts it, with only this one field changed.
  const section = formsOn(inRealm.html).filter(function (form) {
    return form.method === "POST" &&
        form.controls.some(function (c) { return c.name === KEY && !c.disabled; });
  })[0];
  assert.ok(section, "the realm's page should draw " + KEY + " in a form.");
  const before = settingRow(await json("/realm/" + REALM + "/admin/config"), KEY);
  const fields = fieldsFor(section, {}, true);
  fields[KEY] = String(before.value) === "true" ? "false" : "true";

  await press("/realm/" + REALM + "/admin/config", fields,
      "save a section carrying the one realm-runtime setting — IF THIS IS " +
      "REFUSED, the page draws an editable control its own Save will not " +
      "accept, and because `set-many` is all-or-nothing the WHOLE section " +
      "becomes unsaveable, including when nothing was changed");

  const after = settingRow(await json("/realm/" + REALM + "/admin/config"), KEY);
  assert.strictEqual(String(after.value), fields[KEY],
    "the realm should now carry " + KEY + "=" + fields[KEY] + "; it reads " +
    after.value);
  assert.strictEqual(after.source, "realm",
    "and it must be held as the REALM'S, not as a process-wide override — " +
    "there is nowhere else it could be held, since the process cannot carry " +
    "it at all. It says " + after.source);

  // And it must not have reached the process. This is the half that would
  // matter most if the carve-out were ever widened: a realm setting the
  // scheme-deciding row for everybody is the thing the restart-only rule
  // exists to prevent.
  const processRow = settingRow(
      (await common.httpJson(root("/admin-api/config"))).body, KEY);
  assert.notStrictEqual(processRow.source, "override",
    "AND IT MUST NOT HAVE REACHED THE PROCESS. " + KEY + " is what " +
    "`global.https` derives from, so a realm that could set it for everybody " +
    "would be changing the scheme a socket was bound with from inside a " +
    "request that arrived on it. The default realm's row says source=" +
    processRow.source);

  // Put it back, so the realm is as this file found it — belt and braces,
  // since the realm is removed at the end anyway.
  fields[KEY] = String(before.value);
  await press("/realm/" + REALM + "/admin/config", fields,
      "put the realm-runtime setting back");
  log.info("[realm setting] OK — " + KEY + " is drawn disabled at the root " +
           "and enabled in a realm, and the realm's Save accepts it, holds " +
           "it as the realm's, and does not reach the process.");
  log.debug("Leaving aRealmRuntimeSettingIsSettableOnItsPage().");
}

// One named control off a page, whatever tag it is drawn as, with whether it
// is disabled — which is the property under test above and the one a browser
// acts on by not submitting it.
function controlNamed(markup, name) {
  log.debug("Entering controlNamed(). name=" + name);
  let found;
  formsOn(markup).forEach(function (form) {
    form.controls.forEach(function (control) {
      if (!found && control.name === name) {
        found = control;
      }
    });
  });
  log.debug("Leaving controlNamed(). " + (found ? "found" : "absent"));
  return found;
}

// ---------------------------------------------------------------------------
// AND WHETHER IT WAS WRITTEN DOWN.
//
// The value coming back proves that something is holding it in memory. What
// /admin/persistence promises is that it was WRITTEN — an RFC 2849 file per
// realm, or three Postgres tables — and the store's own account of itself is
// the only thing over HTTP that says so: a write counter, a dirty flag, a
// failure counter and a last-write timestamp.
//
// A service in `memory` mode is REPORTED rather than skipped. That is the
// default and what the containerized stack runs, and "the store is off" and
// "the store did not write" look identical from a distance while only one of
// them is fine.
// ---------------------------------------------------------------------------
async function theChangeReachedTheStore() {
  log.debug("Entering theChangeReachedTheStore().");
  const shown = await json("/admin/persistence");
  const status = shown.status || shown;
  assert.ok(status && status.mode,
    "/admin/persistence should report what the store is actually doing. A " +
    "persistence setting that is SET and a store that is WORKING are two " +
    "different facts, and the gap between them is the whole failure mode " +
    "this feature has.");

  if (!status.enabled) {
    assert.strictEqual(status.mode, "memory",
      "a store that is not enabled should be in `memory` mode; it says " +
      status.mode);
    assert.strictEqual(status.writes, 0,
      "and it must not report having WRITTEN anything — that is the one " +
      "claim that would send somebody looking for a file that is not there. " +
      "It reports " + status.writes);
    log.info("[persistence] The store is OFF (persistence.mode=memory), the " +
             "default and what the containerized stack runs. The value " +
             "round trip above is asserted; that the bytes reach a file is " +
             "asserted in mock-sts's own tests/appconfig_persistence.js, " +
             "which drives the store in process against a temporary " +
             "directory and reads the file back.");
    log.debug("Leaving theChangeReachedTheStore(). Store off.");
    return;
  }

  // A realm's settings live on the realm row, which is written when the
  // registry changes — so the counter must have moved and nothing may be
  // left pending or failed.
  const settled = await settle(status);
  assert.ok(settled.writes > 0,
    "A SETTING SAVED ON THE CONSOLE MUST REACH THE STORE. persistence.mode=" +
    status.mode + ", and the write counter is " + settled.writes + ". The " +
    "flush is scheduled rather than immediate, so this waited for it.");
  assert.strictEqual(settled.pending, false,
    "and nothing should still be waiting to be written; the store says " +
    "pending=" + settled.pending);
  assert.strictEqual(settled.failures, 0,
    "and no write should have FAILED. A failure is recorded rather than " +
    "thrown — a mock that refused to start because a database blinked would " +
    "be the one failure mode a mock must not have — so this counter is the " +
    "only thing that says it did not work. It reports " + settled.failures +
    ": " + settled.lastError);
  assert.strictEqual(settled.coordinates, false,
    "and the store must still say it does not COORDINATE: two processes " +
    "pointed at one database each hold their own directory in memory and " +
    "never see each other's writes.");
  log.info("[persistence] OK — the store is " + settled.mode + " at " +
           (settled.dataDir || JSON.stringify(settled.database)) + ", the " +
           "console's save reached it, and nothing is pending or failed " +
           "after " + settled.writes + " write(s).");
  log.debug("Leaving theChangeReachedTheStore().");
}

async function settle(previous) {
  log.debug("Entering settle().");
  const budget = Math.max(3000, Number(previous.writeDelayMs || 0) * 3);
  const until = Date.now() + budget;
  let status = previous;
  while (Date.now() < until) {
    await new Promise(function (resolve) { setTimeout(resolve, 150); });
    const shown = await json("/admin/persistence");
    status = shown.status || shown;
    if (!status.pending) {
      break;
    }
  }
  log.debug("Leaving settle(). writes=" + status.writes);
  return status;
}

// ---------------------------------------------------------------------------
// THE REFUSALS A PERSON MEETS.
//
// Every check above is about a control that works. These are the ones about a
// control that must NOT — and they are on the console side rather than the API
// side because the failure mode is different here: an API that accepted a bad
// request answers 200 and a caller notices, while a CONSOLE that accepted one
// draws a page that looks exactly like success.
// ---------------------------------------------------------------------------
async function theConsoleRefusesWhatItShould() {
  log.debug("Entering theConsoleRefusesWhatItShould().");
  log.info("=== What the console refuses ===");

  await pressAndBeRefused("/realm/" + REALM + "/admin/applications",
      { action: "create", identifier: "kind-probe", kind: "no-such-kind",
        back: "" },
      /is not one of the kinds/,
      "a kind outside the registry's closed vocabulary");

  await pressAndBeRefused("/realm/" + REALM + "/admin/claims",
      { action: "add", set: "access_token", name: "iss", value: "x", back: "" },
      /iss/,
      "a RESERVED claim name — a custom `iss` would be overwritten by the " +
      "issuer at signing time, so a console that accepted it would be " +
      "storing something it will never send");

  await pressAndBeRefused("/realm/" + REALM + "/admin/claims",
      { action: "add", set: "no-such-set", name: "x", value: "y", back: "" },
      /claim set/i,
      "a claim set this door does not carry");

  await pressAndBeRefused("/realm/" + REALM + "/admin/token-lifetimes",
      { action: "set", "oauth2.accessTokenTtlsS": "600", back: "" },
      /accessTokenTtlsS|sets only/,
      "a MISSPELT lifetime — this page refuses a name outside its four by " +
      "name, which is exactly the answer /admin/config's section save cannot " +
      "give, because a form legitimately posts fields a section never declared");

  await pressAndBeRefused("/realm/" + REALM + "/admin/config",
      { action: "set", key: "global.port", value: "9999", back: "" },
      /cannot be changed while this service is running/,
      "a RESTART-ONLY setting — the whole five-layer arrangement rests on " +
      "only a runtime setting being overridable, which is what makes it safe " +
      "for the persistence store to re-apply saved overrides after every " +
      "module has loaded");

  await pressAndBeRefused("/realm/" + REALM + "/admin/federation",
      { action: "create", id: "fed-no-role", name: "No role", back: "" },
      /role/i,
      "a federation relationship with no ROLE — which direction the " +
      "relationship runs in is the first thing about it and cannot be " +
      "defaulted");

  log.info("[refusals] OK — six controls refused what they should, each with " +
           "a reason drawn on the page the reader is sent back to.");
  log.debug("Leaving theConsoleRefusesWhatItShould().");
}

// ---------------------------------------------------------------------------
// AND THE ONE PAGE THAT IS NOT THE CONSOLE'S OWN: /admin/sts-metadata.
//
// It is built by walking the live Express router, by a module that has to be
// the LAST one server.js loads — so it is the one page here drawn by something
// other than admin.js, through the shell that file exports. Two things are
// checked, and both are about it still being part of this console rather than
// about what it lists, which tests/sts_metadata.js owns.
// ---------------------------------------------------------------------------
async function theMetadataPageIsStillInTheConsole() {
  log.debug("Entering theMetadataPageIsStillInTheConsole().");
  const drawn = await html("/admin/sts-metadata");
  assert.ok(drawn.html.indexOf("navsec") > 0 && /<p class="crumb">/.test(drawn.html),
    "/admin/sts-metadata should be drawn in the console shell with a " +
    "breadcrumb, the same as every other page. It is built by a module " +
    "OUTSIDE admin.js — sts_metadata.js, which must be the last thing " +
    "server.js loads or it would be the reason a route is missing from its " +
    "own list — so it is the one page whose chrome can be lost without any " +
    "of the console's own code changing.");
  assert.ok(drawn.html.indexOf("<script") < 0,
    "and it must have no script on it, like every other page here.");
  log.info("[metadata] OK — /admin/sts-metadata is still drawn in the " +
           "console's shell, by the one module outside admin.js that draws a " +
           "console page.");
  log.debug("Leaving theMetadataPageIsStillInTheConsole().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the mock STS admin console at " + base + "/admin");

  let status;
  try {
    status = await common.httpJson(root("/admin-api/status"));
  } catch (e) {
    log.warn("No STS is listening at " + base + " (" + e.message + "). " +
             "Skipping: this job needs the mock and nothing else.");
    log.debug("Leaving test(). Nothing listening.");
    return;
  }
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + ". A service is " +
    "listening at " + base + " and has no admin console index on it, which " +
    "is almost always the parent project's `sts` submodule pinned at a " +
    "commit older than this feature. A FAILURE and not a skip: a skip here " +
    "reports thirty-eight pages green having drawn none of them.");
  const pages = status.body.pages;
  assert.ok(Array.isArray(pages) && pages.length > 20,
    "the status reply should carry the console's own page list; it carries " +
    JSON.stringify(pages));

  await theGateBehaves();
  await everyPageIsDrawn(pages);
  await noPageNestsAForm(pages);
  await everyControlReachesSomething(pages);
  await theMetadataPageIsStillInTheConsole();

  await theRealmIsCreatedOnTheForm();
  try {
    const created = await theDirectoryPagesWork();
    await theTokensPageRevokesWhatItDraws();
    await everyOtherControlIsPressed(created);
    await theDrillDownsCarryTheirTrail(created);
    await filteringAndPagingWork();
    await theTwoDrawingsAreServerSide();
    await theConsoleRefusesWhatItShould();
    await aSettingChangedOnItsProtocolPage();
  } finally {
    await theRealmIsRemovedOnTheForm();
  }

  // Last, because it closes the console against this file's own session and
  // opens it again — everything above needs the console open.
  await theTwoRolesAreEnforced();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_admin_console")
  .description("Drive the mock STS admin console at /admin over HTTP with no " +
      "browser: the gate, every page, every control, and that a setting " +
      "changed on a protocol page reaches the configuration and the store.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // tests/jwk_pem_encoding.js fails the suite if a job does not declare it.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
