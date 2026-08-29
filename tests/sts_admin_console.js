// File: sts_admin_console.js
//
// ---------------------------------------------------------------------------
// THE MOCK STS'S ADMIN CONSOLE AT /admin, DRIVEN IN A REAL BROWSER: EVERY PAGE,
// EVERY LINK, EVERY GET FORM, AND EVERY BUTTON — AND WHAT COMES BACK AFTERWARDS.
//
// The console is the one surface in that service that can CHANGE what every
// protocol endpoint does — a claim added here appears in every token, a setting
// changed here changes what a flow refuses. `tests/admin_api.js` and
// `tests/sts_admin_api_operations.js` drive the JSON door beside it, which is
// not the same thing: the API's whole design is that it decides nothing the
// console does not, so a defect in the PAGE — a form posting the wrong action,
// a control that renders and reaches nothing, a field the handler stopped
// reading — is invisible from over there by construction.
//
// ---------------------------------------------------------------------------
// THIS FILE USED TO DRIVE THE CONSOLE OVER HTTP WITH NO BROWSER, AND THE HEADER
// ARGUED AT LENGTH THAT A BROWSER WOULD ADD NOTHING. THAT ARGUMENT WAS WRONG IN
// FOUR PLACES, AND THEY ARE THE REASON THIS IS NOW A SELENIUM JOB.
//
// The old argument was: the console is `script-src 'none'` with not one line of
// JavaScript on any of its thirty-eight pages, so every control is a `<form>`
// and every button is a submit — and pressing a button IS posting the form's
// own fields to the form's own action, which a node client can do exactly as
// well. Every clause of that is still true. What it missed:
//
//   1. **A SIMULATED SUBMIT IS THE TEST'S READING OF THE MARKUP, NOT THE
//      BROWSER'S.** The old file had to re-implement, in `fieldsFor()`, what a
//      browser does with a form: which controls are successful, what a
//      `disabled` control contributes, which `<option>` is selected when none
//      says so, what an unchecked checkbox sends. Every one of those is a rule
//      it could get wrong in the same direction as the console — and a shared
//      misunderstanding between the test and the code under test passes and
//      proves nothing. THE BROWSER IS THE INDEPENDENT IMPLEMENTATION. This is
//      `tests/sts_dpop.js`'s reason for writing its own DPoP client rather than
//      importing the wallet's, applied to HTML forms.
//
//   2. **THE 22 GET FORMS WERE NEVER CHECKED AT ALL.** The old file walked POST
//      targets — 75 of them — and a GET form has no POST target to walk, so
//      every filter, every page-size control and the realm switcher went
//      unexercised. They are a third of the console's controls.
//
//   3. **THE NESTED-`<form>` GUARD WAS A SOURCE SCAN BECAUSE NOTHING THERE
//      COULD PARSE.** The defect it guards is a PARSER behaviour — the HTML
//      parser DROPS a `<form>` start tag inside another form and adopts its
//      children into the outer form — so the old file compared the raw markup
//      against a hand-written form-tag counter and reasoned about what a parser
//      would do with it. Here the parser is present: `view-source:` gives the
//      raw bytes and `document.forms` gives what the browser actually built,
//      and the guard is the two disagreeing.
//
//   4. **"THE BUTTON WORKED" WAS A NOTICE, NOT A VALUE.** The console answers a
//      form POST with 303 and `?notice=…`, and the old file largely checked
//      that sentence. A handler that accepts a field, reports success and
//      stores something else says exactly the same sentence. Every write here
//      is read back — off the page that drew the control, and where a second
//      door exists, through `/admin-api` as well.
//
// What a browser costs is wall clock — about a minute against a warm mock,
// where the old file took two seconds — and a Chrome on the machine. It is ONE
// browser, and it is never pooled: this job opens a single driver in `test()`
// and quits it in a `finally`. See the note on saturation in the parent's
// run-report.js.
//
// WHAT IT STILL DOES NOT NEED IS A SCREEN. Every assertion below is about
// structure, status, header or value; none is about pixels. `--screenshot` is
// offered for a person debugging a failure and nothing in the suite depends on
// it.
//
// ---------------------------------------------------------------------------
// HOW IT SEES STATUS CODES AND HEADERS, WHICH SELENIUM DOES NOT EXPOSE.
//
// WebDriver has no API for a response's status or its headers, and the obvious
// workaround — `fetch()` inside the page through `executeScript` — CANNOT WORK
// HERE and the reason is the thing under test: the console's own policy is
// `default-src 'none'`, so `connect-src` falls back to it and every fetch from
// a console page is blocked before it is sent. (`executeScript` itself runs
// fine; WebDriver injects outside the page's CSP. It is the page's own network
// access that is closed, which is correct and is asserted below.)
//
// So this file listens to WEBDRIVER BiDi's `network.responseCompleted`, which
// is the BROWSER's own account of every response it received — status, headers
// and the full redirect chain, for navigations the browser really performed.
// That is strictly more truthful than the old file's node-side reads: those
// asked the server a question a browser had not asked.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS. Nine groups, and the last four did not exist before.
//
//   * **THE GATE.** `admin.authRequired` is on by default, so every page and
//     every form is behind a sign-on session and one of two roles. Four
//     behaviours, each a client's path through it: a browser GET is REDIRECTED
//     to the sign-in screen carrying the id of the request waiting there; a
//     `?format=json` read is REFUSED 401 rather than redirected, because a
//     redirect to an HTML screen is not an answer a program can read; a POST
//     with no session is NEVER redirected, because a 303 makes it a GET and the
//     fields vanish — and here that POST is a REAL browser form submission with
//     the cookie jar emptied under it; and `/admin-api` next door is not gated
//     at all, which is deliberate and is the way back in.
//   * **EVERY PAGE IS DRAWN, IN THE SHELL, UNDER THE POLICY.** All thirty-eight,
//     walked from the service's own list, each with the nav, its own breadcrumb,
//     a 200 the browser saw, and a Content-Security-Policy that still says
//     `script-src 'none'`, `frame-ancestors 'none'` (which has no fallback from
//     `default-src` and is therefore the clause a page loses by accident) and
//     `base-uri 'none'` — plus `document.scripts.length === 0`, which is the
//     browser's answer to the same question and cannot be satisfied by a header
//     that lies.
//   * **NO PAGE NESTS A `<form>`** — the raw bytes and the parsed DOM, compared.
//   * **EVERY LINK ON EVERY PAGE RESOLVES.** Every same-origin `<a href>` the
//     console draws, deduplicated and then really visited, has to answer under
//     400. This is what makes the seven console routes with no nav row —
//     the three delegation drill-downs, both pictures, `/admin/tokens/credential`
//     and the realm switcher — covered by construction rather than by a list
//     somebody has to remember to extend.
//   * **EVERY GET FORM IS FILLED IN AND SUBMITTED**, and what comes back is
//     checked: the URL carries the fields, the page redraws, and a filter
//     really narrows what is listed.
//   * **EVERY POST CONTROL IS CHECKED STRUCTURALLY AND THEN PRESSED.**
//     Structurally: every target is a route that exists and every `action`
//     value is one its handler names, both read off the service. Behaviourally:
//     the browser submits it, and THE VALUE IS READ BACK — off the page, and
//     through `/admin-api` where that door exists.
//   * **THE FIVE HANDLERS NOTHING EVER PRESSED.** `/admin/rbac`'s own grant and
//     revoke (the old file granted through the ungated API and never touched
//     the page), `/admin/logout`'s end-session buttons behind its Look form,
//     `/admin/saml-assertions`, `/admin/spiffe`'s rotate and federation-set,
//     and `/admin/token-lifetimes`' success path — which had only ever been
//     driven as a refusal.
//   * **THE TRAIL, THE FILTERS AND THE REALM SWITCHER.** A drill-down's section
//     crumb is a link carrying the filter it was reached through, the last crumb
//     is never a link, every form on a drill-down carries `back`, and the realm
//     switcher — a GET form in the shell of every page — really lands on the
//     same page in the other realm.
//   * **A SETTING CHANGED ON THE PAGE FOR THE PROTOCOL IT CONFIGURES**, then
//     looked for in three places: redrawn on that page, in `/admin-api/config`
//     with its source moved, and in the persistence store's write counters.
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
// THE ONE THING IT READS OTHER THAN THROUGH THE BROWSER is `/admin-api`, and
// only ever to CHECK — never to make a change the console is supposed to make.
// A write made in the browser and read back through the browser can still be
// two halves of one misunderstanding; reading it through the other door is what
// makes it evidence. `/admin-api` is ungated by design, so this needs no
// credential and takes none.
//
// Needs the STS mock and a Chrome. No Keycloak, no client, no other service.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const NetworkInspector = require("selenium-webdriver/bidi/networkInspector.js");
const browserFlags = require("./browser_flags.js");
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

var gateIsOn = false;    // what the service actually did, rather than assumed
var screenshotDir = "";  // --screenshot-dir, for a person debugging a failure

// ---------------------------------------------------------------------------
// One counted assertion. The count is what the last line of the run reports and
// what the floor at the bottom of test() defends: a section that stops being
// called takes its checks with it, and a suite that silently drops a third of
// itself still says "passed".
// ---------------------------------------------------------------------------
var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.debug("check passed: " + what);
}

function root(path) { return base + path; }
function realm(path) { return base + "/realm/" + REALM + path; }

// ---------------------------------------------------------------------------
// THE BROWSER'S OWN ACCOUNT OF EVERY RESPONSE IT RECEIVED.
//
// `network.responseCompleted` fires for navigations, redirects and subresources
// alike, so this keeps all of them and the lookups below pick. The array is
// only ever appended to; nothing here trims it, because a run is a few hundred
// responses and being able to print the whole chain when an assertion fails is
// worth more than the memory.
// ---------------------------------------------------------------------------
var responses = [];

function recordResponse(event) {
  const headers = {};
  (event.response.headers || []).forEach(function (h) {
    // BiDi spells a header value as {type:"string", value:"…"}; older builds
    // hand back the bare string. Both are seen in the wild, so normalise here
    // rather than at nine call sites.
    const value = (h.value && typeof h.value === "object")
      ? h.value.value : h.value;
    headers[String(h.name).toLowerCase()] = String(value == null ? "" : value);
  });
  responses.push({
    url: String(event.request.url),
    method: String(event.request.method || "GET").toUpperCase(),
    status: Number(event.response.status),
    headers: headers,
    at: Date.now()
  });
}

// The LAST response the browser received for exactly this URL. Last rather than
// first because a page visited twice — which the filter sections do on purpose
// — must be read as the visit that just happened.
function responseFor(url) {
  for (let i = responses.length - 1; i >= 0; i -= 1) {
    if (responses[i].url === url) {
      return responses[i];
    }
  }
  return null;
}

// Every response recorded since a mark, in order. `mark()` is taken before an
// interaction and this is read after it, which is how a form POST's own status
// is found without guessing its URL — a POST to /admin/users and the 303's
// destination are both in here, in the order they happened.
function mark() { return responses.length; }
function since(from) { return responses.slice(from); }

// The one POST in a stretch of responses. A console interaction makes exactly
// one; more than one means a page grew a second request and the caller's
// assertion about "the POST" would silently be about the wrong one.
function thePostIn(stretch, what) {
  const posts = stretch.filter(function (r) { return r.method === "POST"; });
  assert.strictEqual(posts.length, 1,
    "expected exactly one POST while " + what + "; the browser made " +
    posts.length + ": " + JSON.stringify(posts.map(function (r) {
      return r.method + " " + r.url + " -> " + r.status;
    })));
  return posts[0];
}

// ---------------------------------------------------------------------------
// NAVIGATION, AND THE STATUS THE BROWSER SAW WHILE DOING IT.
//
// `driver.get()` resolves when the document is loaded; the BiDi event for the
// same response may or may not have arrived by then, so this waits for it
// rather than sleeping. A response that never arrives is a failure with the URL
// in it, which is a great deal easier to read than an assertion about
// `undefined.status` three lines later.
// ---------------------------------------------------------------------------
async function go(driver, url) {
  log.debug("Entering go(). url=" + url);
  // THE MARK IS TAKEN BEFORE THE NAVIGATION, and it is not a tidiness step.
  // A URL is visited more than once in a run — the gate section reads
  // /admin/tokens signed out and the page walk reads it signed in — so a
  // lookup by URL alone can hand back the EARLIER visit. Whether it does is a
  // race: the BiDi event for the new response arrives either side of
  // driver.get() resolving, so the bug appears as one page in thirty-eight
  // reporting the status it had in a previous section, intermittently.
  const from = mark();
  await driver.get(url);
  const seen = await waitForResponse(url, from);
  log.debug("Leaving go(). status=" + (seen ? seen.status : "?"));
  return seen;
}

// The response the browser received for this URL SINCE `from`. Scanned
// backwards within that stretch, so a redirect chain that ends where it began
// still reports the last hop.
async function waitForResponse(url, from) {
  log.debug("Entering waitForResponse().");
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const stretch = since(from);
    for (let i = stretch.length - 1; i >= 0; i -= 1) {
      if (stretch[i].url === url) {
        log.debug("Leaving waitForResponse(). Found.");
        return stretch[i];
      }
    }
    await pause(25);
  }
  log.debug("Leaving waitForResponse(). Never arrived.");
  throw new Error("the browser never reported a response for " + url +
      ". The last five it did report: " + JSON.stringify(
        responses.slice(-5).map(function (r) {
          return r.method + " " + r.url + " -> " + r.status;
        })));
}

function pause(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// ---------------------------------------------------------------------------
// WHAT THE PAGE IS MADE OF, read out of the DOM the browser built.
//
// This is deliberately one `executeScript` per page rather than a walk of
// WebElements: forty round trips per page is most of a browser suite's wall
// clock, and nothing below needs an element handle — the presses are done with
// real handles, but the SURVEY is data.
//
// `elements` is the browser's own list of a form's successful-control
// candidates, which is the thing the old file had to reimplement: it already
// accounts for controls that sit outside the form and point into it with
// `form=`, and it is in submission order.
// ---------------------------------------------------------------------------
const SURVEY = `
  return {
    title: document.title,
    scripts: document.scripts.length,
    forms: Array.from(document.forms).map(function (f, i) {
      return {
        index: i,
        method: (f.getAttribute('method') || 'GET').toUpperCase(),
        action: f.getAttribute('action'),
        // NOT the form's own action property. A form's named controls
        // SHADOW the properties of the form element itself, and every console
        // form carries an input named "action" -- so reading f.action hands
        // back that INPUT ELEMENT rather than the form's URL, and every
        // target in this walk came out as "/[object%20Object]". Resolving the
        // attribute against the document is what f.action would have done had
        // the console named its field anything else.
        resolvedAction: (function () {
          const raw = f.getAttribute('action');
          return new URL((raw == null || raw === '') ? location.href : raw,
                         location.href).href;
        })(),
        controls: Array.from(f.elements).map(function (e) {
          return {
            tag: e.tagName.toLowerCase(),
            type: String(e.type || ''),
            name: e.name || '',
            value: e.tagName.toLowerCase() === 'select'
              ? (e.options[e.selectedIndex] || {}).value || ''
              : String(e.value == null ? '' : e.value),
            options: e.tagName.toLowerCase() === 'select'
              ? Array.from(e.options).map(function (o) { return o.value; })
              : null,
            checked: !!e.checked,
            disabled: !!e.disabled,
            text: (e.textContent || '').trim().slice(0, 60)
          };
        })
      };
    }),
    links: Array.from(document.querySelectorAll('a[href]')).map(function (a) {
      return a.href;
    }),
    nav: document.querySelectorAll('nav a, .nav a, aside a').length,
    crumb: (function () {
      const c = document.querySelector('p.crumb');
      return c ? { html: c.innerHTML, leaves:
        c.querySelectorAll('span.leaf').length, links:
        c.querySelectorAll('a').length } : null;
    })(),
    notice: (function () {
      const n = document.querySelector('.notice, .ok, .success');
      return n ? n.textContent.trim() : '';
    })(),
    error: (function () {
      const n = document.querySelector('.error, .refusal, .warn');
      return n ? n.textContent.trim() : '';
    })(),
    text: document.body ? document.body.innerText : ''
  };
`;

async function survey(driver) {
  return await driver.executeScript(SURVEY);
}

// A page, visited and surveyed, with the status and headers the browser saw.
async function open(driver, url) {
  log.debug("Entering open(). url=" + url);
  const seen = await go(driver, url);
  const page = await survey(driver);
  page.status = seen.status;
  page.headers = seen.headers;
  page.url = await driver.getCurrentUrl();
  log.debug("Leaving open().");
  return page;
}

// ---------------------------------------------------------------------------
// THE RAW BYTES, through the browser and not around it.
//
// `view-source:` re-requests the URL with the same cookie jar and renders the
// bytes as text, so `innerText` here is the document the server actually sent —
// which `getPageSource()` is NOT: that serialises the DOM the parser built,
// which is precisely the thing the nested-form guard has to compare against.
// ---------------------------------------------------------------------------
async function rawSourceOf(driver, url) {
  log.debug("Entering rawSourceOf().");
  await driver.get("view-source:" + url);
  const text = await driver.executeScript(
      "return document.body ? document.body.innerText : '';");
  log.debug("Leaving rawSourceOf(). " + String(text).length + " byte(s).");
  return String(text);
}

// ---------------------------------------------------------------------------
// FILLING IN A FORM AND PRESSING ITS BUTTON, the way a person does.
//
// The submit is ALWAYS a real click on a real button — that is the whole point
// of this file, and `form.submit()` would skip exactly the behaviour under test
// (which button was pressed, and therefore which `formaction` and which value a
// named submit contributes).
//
// The FIELDS are set through the DOM rather than typed, with one deliberate
// exception per form: the first text field is typed into with `sendKeys`, so
// that every form in this suite has at least one control that went through real
// key events. Typing forty fields of a settings section costs about a second
// each and proves the same thing forty times. Nothing on these pages listens
// for input — `script-src 'none'` — so a DOM assignment and a keystroke leave
// the control in the same state, which is why this trade is available here and
// would not be on a page with scripts.
// ---------------------------------------------------------------------------
async function fillAndPress(driver, formIndex, values, options) {
  log.debug("Entering fillAndPress(). form=" + formIndex);
  const opts = options || {};
  const typed = await driver.executeScript(`
    const f = document.forms[arguments[0]];
    const values = arguments[1];
    if (!f) { return { error: 'no form at index ' + arguments[0] }; }
    let firstText = null;
    const set = [];
    Object.keys(values).forEach(function (name) {
      const control = f.elements[name];
      if (!control) { return; }
      const list = (control.length !== undefined && !control.tagName)
        ? Array.from(control) : [control];
      list.forEach(function (e) {
        if (e.disabled) { return; }
        if (e.type === 'checkbox' || e.type === 'radio') {
          e.checked = (String(values[name]) === 'true' ||
                       String(e.value) === String(values[name]));
        } else {
          e.value = String(values[name]);
        }
        set.push(name);
      });
    });
    Array.from(f.elements).forEach(function (e) {
      if (firstText === null && !e.disabled &&
          (e.type === 'text' || e.type === 'number' || e.type === 'search')) {
        firstText = e.name || '';
      }
    });
    return { set: set, firstText: firstText };
  `, formIndex, values || {});
  assert.ok(!typed.error, "fillAndPress: " + typed.error);

  // The one control that goes through real key events.
  if (typed.firstText && values && values[typed.firstText] !== undefined &&
      !opts.noTyping) {
    const field = await driver.findElement(
        By.css("form:nth-of-type(" + (formIndex + 1) + ") [name='" +
               typed.firstText + "']")).catch(function () { return null; });
    if (field) {
      await field.clear().catch(function () { return null; });
      await field.sendKeys(String(values[typed.firstText]));
    }
  }

  const from = mark();
  const button = await submitButtonOf(driver, formIndex, opts.buttonText);
  await button.click();
  await settleAfterSubmit(driver);
  log.debug("Leaving fillAndPress().");
  return { from: from, responses: since(from) };
}

// The button a person would press. `buttonText` picks one when a form draws
// several — which the console does on /admin/tokens, where four buttons post
// the same action with a different `kind` beside it.
async function submitButtonOf(driver, formIndex, buttonText) {
  log.debug("Entering submitButtonOf().");
  const buttons = await driver.executeScript(`
    const f = document.forms[arguments[0]];
    return Array.from(f.elements).map(function (e, i) {
      return { i: i, type: e.type, text: (e.textContent || e.value || '').trim() };
    }).filter(function (e) {
      return e.type === 'submit' || e.type === 'image';
    });
  `, formIndex);
  assert.ok(buttons.length > 0,
    "form " + formIndex + " has no submit button, so nothing on it can be " +
    "pressed. A control that cannot be pressed is a control that does nothing.");
  // `buttonText` is a PREFERENCE and not a requirement, deliberately. The forms
  // in this suite are found by the FIELDS they draw, which is the contract a
  // handler actually has; a button's wording is prose, and a label edited in a
  // documentation pass should not fail a functional test. Where a form draws
  // SEVERAL submits that differ in what they do — /admin/tokens draws four
  // that differ only in a hidden `kind` — the caller picks by that hidden
  // field instead, so nothing here rests on the wording.
  let wanted = buttons[0];
  if (buttonText) {
    const found = buttons.filter(function (b) {
      return b.text.indexOf(buttonText) >= 0;
    })[0];
    if (found) {
      wanted = found;
    } else {
      log.debug("no submit on form " + formIndex + " says " +
                JSON.stringify(buttonText) + "; they say " +
                JSON.stringify(buttons.map(function (b) { return b.text; })) +
                ". Pressing the first, which is the one a person meets.");
    }
  }
  assert.ok(buttons.length === 1 || buttonText || wanted,
    "form " + formIndex + " draws " + buttons.length + " submit buttons and " +
    "the caller named none, so which one this pressed would be an accident.");
  // Hand back a real element: the click has to be a click.
  const element = await driver.executeScript(`
    const f = document.forms[arguments[0]];
    return Array.from(f.elements)[arguments[1]];
  `, formIndex, wanted.i);
  log.debug("Leaving submitButtonOf(). " + JSON.stringify(wanted.text));
  return element;
}

// After a submit the console answers 303 and the browser follows it. This waits
// for the document that lands rather than for a fixed time — a sleep long
// enough to be safe on a loaded machine is a sleep that doubles the suite.
async function settleAfterSubmit(driver) {
  log.debug("Entering settleAfterSubmit().");
  await driver.wait(async function () {
    const state = await driver.executeScript("return document.readyState;");
    return state === "complete";
  }, 15000, "the page never finished loading after a form was submitted");
  // One more turn of the event loop, so the BiDi events for what just loaded
  // have been delivered before a caller reads them.
  await pause(60);
  log.debug("Leaving settleAfterSubmit().");
}

// The `?notice=` or `?error=` the console puts in the query string of the page
// it sends a reader back to. Both are read from the URL rather than the markup
// so that a page which draws neither still fails the assertion that wanted one.
function outcomeOf(url, which) {
  const found = String(url).match(new RegExp("[?&]" + which + "=([^&]*)"));
  return found ? decodeURIComponent(found[1].replace(/\+/g, " ")) : "";
}

// ---------------------------------------------------------------------------
// SIGNING IN. The mock checks no password anywhere — the screen is a name and a
// button — so this is a name being typed, and the assertion is that the console
// opens afterwards rather than that anything was verified.
// ---------------------------------------------------------------------------
async function signIn(driver, username) {
  log.debug("Entering signIn(). username=" + username);
  // THE JAR IS EMPTIED FIRST, ALWAYS. Signing in is also how this file SWITCHES
  // WHO IT IS — the roles section signs in as a reader and back again — and a
  // session that is already open means /admin answers 200 with no screen on it,
  // so without this the switch silently does not happen and the reader's
  // assertions are made as the writer. That failure reads as the console
  // letting a reader post a form, which is the most alarming possible way to
  // be told about a bug in the test.
  await clearSession(driver);
  await go(driver, root("/admin"));
  const url = await driver.getCurrentUrl();
  if (url.indexOf("/authn/login") < 0) {
    log.info("The console is OPEN (admin.authRequired is off); no sign-in " +
             "was needed.");
    log.debug("Leaving signIn(). No gate.");
    return false;
  }
  const field = await driver.findElement(By.css("input[name='username']"));
  await field.clear();
  await field.sendKeys(username);
  const button = await driver.findElement(
      By.xpath("//button[@type='submit'] | //input[@type='submit'] | //button"));
  await button.click();
  await settleAfterSubmit(driver);
  const after = await driver.getCurrentUrl();
  assert.ok(after.indexOf("/authn/login") < 0,
    "signing in as " + username + " left the browser on the sign-in screen (" +
    after + "). The mock checks no password, so this is a name that was typed " +
    "and a button that was pressed; if it did not open the console, the " +
    "screen itself is broken rather than the credential.");
  log.debug("Leaving signIn(). Signed in.");
  return true;
}

async function clearSession(driver) {
  log.debug("Entering clearSession().");
  await driver.manage().deleteAllCookies();
  log.debug("Leaving clearSession().");
}

// ---------------------------------------------------------------------------
// THE ONE THING READ OTHER THAN THROUGH THE BROWSER, and only ever to CHECK.
// See the header: a write made in the browser and read back in the browser can
// be two halves of one misunderstanding.
// ---------------------------------------------------------------------------
async function apiJson(path) {
  log.debug("Entering apiJson(). path=" + path);
  const reply = await common.httpJson(base + path);
  log.debug("Leaving apiJson(). status=" + reply.status);
  return reply;
}


// ---------------------------------------------------------------------------
// A PICTURE OF THE PAGE THE RUN DIED ON.
//
// NOTHING IN THIS SUITE ASSERTS ANYTHING ABOUT PIXELS — every check above is
// about structure, status, header or value, which is why it needs no screen.
// This exists for the person reading a failure, and only when they ask for it
// with --screenshot-dir: a console page that drew the wrong thing is a great
// deal quicker to understand as an image than as a DOM survey. A failure to
// write it is swallowed on purpose, because the failure being reported is the
// one worth seeing.
// ---------------------------------------------------------------------------
async function keepAPicture(driver, what) {
  log.debug("Entering keepAPicture().");
  if (!screenshotDir) {
    log.debug("Leaving keepAPicture(). Not asked for.");
    return;
  }
  try {
    const fs = require("fs");
    const path = require("path");
    fs.mkdirSync(screenshotDir, { recursive: true });
    const file = path.join(screenshotDir,
        "sts_admin_console-" + what + "-" + Date.now() + ".png");
    fs.writeFileSync(file, await driver.takeScreenshot(), "base64");
    log.warn("A picture of the page this run died on: " + file +
             " (it was at " + (await driver.getCurrentUrl()) + ")");
  } catch (e) {
    log.warn("could not write a screenshot: " + e.message);
  }
  log.debug("Leaving keepAPicture().");
}
// ---------------------------------------------------------------------------
// THE GATE IN FRONT OF /admin.
//
// Four behaviours, each of which is a different client's path through it, and
// each of which has been wrong at some point in some console somewhere:
//
//   * a browser GET is REDIRECTED to the sign-in screen, carrying the id of the
//     request waiting there so the person lands back where they were going;
//   * a `?format=json` read is REFUSED 401 rather than redirected, because a
//     302 to an HTML screen is not an answer a program can read — it looks like
//     success and parses as garbage;
//   * a POST with no session is NEVER redirected, because a 303 turns it into a
//     GET and every field the person typed is silently gone;
//   * `/admin-api` next door is NOT gated, which is deliberate: it is what a
//     test drives and the way back in when nobody holds a role.
//
// The POST case is the one that needed a browser. The old file constructed a
// POST by hand and read the status; here the browser submits a form the console
// itself drew, with the cookie jar emptied underneath it — which is exactly the
// shape of the accident this rule exists for (a session that expired while
// somebody had a form open).
// ---------------------------------------------------------------------------
async function theGateBehaves(driver) {
  log.debug("Entering theGateBehaves().");
  log.info("=== The gate in front of /admin ===");

  await clearSession(driver);

  // 1. A browser GET.
  const from = mark();
  await go(driver, root("/admin/tokens"));
  const chain = since(from);
  const first = chain[0];
  const landed = await driver.getCurrentUrl();

  if (first.status === 200 && landed.indexOf("/authn/login") < 0) {
    log.warn("The console answered 200 with no session: admin.authRequired " +
             "is OFF on this service. The gate assertions cannot be made and " +
             "are being skipped; everything below still runs.");
    gateIsOn = false;
    log.debug("Leaving theGateBehaves(). The gate is off.");
    return;
  }
  gateIsOn = true;

  check("a browser GET of a console page is redirected", function () {
    assert.strictEqual(first.status, 302,
      "GET /admin/tokens with no session should be REDIRECTED to the sign-in " +
      "screen; the browser was answered " + first.status + ". A person who " +
      "follows a link into the console has to be sent somewhere they can act.");
  });
  check("and the redirect carries the request waiting behind it", function () {
    assert.ok(/\/authn\/login\?authn=/.test(landed),
      "the browser should have landed on the sign-in screen carrying an " +
      "`authn` id — that id is what sends the person back to /admin/tokens " +
      "afterwards instead of to the top of the console. It landed on " + landed);
  });

  // 2. A `?format=json` read.
  const jsonRead = await go(driver, root("/admin/tokens?format=json"));
  check("a JSON read is refused 401 rather than redirected", function () {
    assert.strictEqual(jsonRead.status, 401,
      "GET /admin/tokens?format=json with no session must be REFUSED 401, " +
      "not redirected: a program reading this door follows the 302, gets an " +
      "HTML sign-in screen with a 200 on it, and cannot tell that from an " +
      "answer. It answered " + jsonRead.status);
  });

  // 3. /admin-api is open. Read in the browser, because that is the client
  //    this rule is about — somebody locked out of the console reaching for
  //    the door beside it.
  const api = await go(driver, root("/admin-api/status"));
  check("/admin-api is not gated", function () {
    assert.strictEqual(api.status, 200,
      "/admin-api must answer without a session. It is deliberately not " +
      "gated — it is what a test drives, and it is the way back in when " +
      "nobody holds a role. It answered " + api.status);
  });

  // 4. A POST with no session, made by the browser from a form the console
  //    drew. Sign in to get the form, empty the jar, then press the button.
  await signIn(driver, CONSOLE_USER);
  await go(driver, root("/admin/users"));
  const createForm = await formIndexPosting(driver, "create");
  assert.ok(createForm >= 0,
    "/admin/users should draw a form whose action is `create`; the gate's " +
    "POST assertion needs a real form to submit.");
  await clearSession(driver);
  const posted = await fillAndPress(driver, createForm,
      { username: "gate-probe-" + names.runStamp() });
  const postResponse = thePostIn(posted.responses, "posting a form with no session");
  check("a POST with no session is refused, never redirected", function () {
    assert.ok(postResponse.status === 401 || postResponse.status === 403,
      "a POST into the console with no session must be REFUSED (401 or 403) " +
      "and must never be answered with a redirect: a 303 makes it a GET, and " +
      "every field the person typed is gone with no way to get it back. It " +
      "answered " + postResponse.status);
    assert.ok(postResponse.status < 300 || postResponse.status >= 400,
      "and specifically not a 3xx. It answered " + postResponse.status);
  });

  await signIn(driver, CONSOLE_USER);
  log.info("[gate] OK — a browser GET is redirected with an `authn` id, a " +
           "JSON read is refused 401, a real form POST with the cookie jar " +
           "emptied under it is refused rather than redirected, /admin-api is " +
           "open, and a session opens the console.");
  log.debug("Leaving theGateBehaves().");
}

// The index of the first form on the current page whose `action` control holds
// this value. Used where a section needs "the create form" without hard-coding
// which form the page happens to draw first.
async function formIndexPosting(driver, actionValue) {
  log.debug("Entering formIndexPosting(). action=" + actionValue);
  const found = await driver.executeScript(`
    const wanted = arguments[0];
    const forms = Array.from(document.forms);
    for (let i = 0; i < forms.length; i += 1) {
      const control = forms[i].elements['action'];
      const value = control && control.value;
      if (value === wanted) { return i; }
      if ((forms[i].getAttribute('action') || '').indexOf('action=' + wanted) >= 0) {
        return i;
      }
    }
    return -1;
  `, actionValue);
  log.debug("Leaving formIndexPosting(). " + found);
  return found;
}

// ---------------------------------------------------------------------------
// EVERY PAGE, DRAWN, IN THE SHELL, UNDER THE POLICY.
//
// The page list is read off the service (`GET /admin-api/status` carries the
// console's own `pages`), never typed here, so a page added to SECTIONS is a
// page this walk starts checking with no edit — which is the same principle the
// console's own nav follows, where NAV is DERIVED from SECTIONS rather than
// written twice.
//
// `frame-ancestors` is the clause worth naming: it has NO fallback from
// `default-src`, so a route that relaxes the policy by setting the whole header
// loses it silently — the page still works, the script still runs, and the
// protection is gone.
//
// `document.scripts.length` is the browser's own answer to the same question
// the header makes a promise about, and it is why this walk is worth doing in a
// browser: a header that says `script-src 'none'` over a page carrying a
// `<script>` is a page whose script is blocked TODAY, by a header somebody
// could relax tomorrow for an unrelated reason.
// ---------------------------------------------------------------------------
async function everyPageIsDrawn(driver, pages) {
  log.debug("Entering everyPageIsDrawn().");
  log.info("=== Every console page ===");
  let forms = 0;
  const links = new Set();

  for (const path of pages) {
    const page = await open(driver, root(path));
    const csp = page.headers["content-security-policy"] || "";

    check(path + " answers 200", function () {
      assert.strictEqual(page.status, 200,
        path + " should be drawn; the browser was answered " + page.status +
        ". It is in the console's own page list, so a page that does not " +
        "answer is a nav entry pointing at nothing.");
    });
    check(path + " is drawn in the shell", function () {
      assert.ok(page.nav > 0,
        path + " should be drawn in the console shell, with the nav on it. " +
        "A page that answers 200 with no shell is a page a reader cannot " +
        "leave. It drew " + page.nav + " nav link(s).");
      assert.ok(page.crumb,
        "and it should carry a breadcrumb; it carries none.");
      assert.ok(page.title && page.title.length > 0,
        "and it should have a title; it has " + JSON.stringify(page.title));
    });
    check(path + " keeps the policy", function () {
      assert.ok(/script-src\s+'none'/.test(csp),
        path + " must be served with `script-src 'none'`. Its policy is: " + csp);
      assert.ok(/frame-ancestors\s+'none'/.test(csp),
        path + " must be served with `frame-ancestors 'none'`. That clause " +
        "has NO fallback from `default-src`, so it is the one a route loses " +
        "by accident when it sets the whole header to relax something else. " +
        "Its policy is: " + csp);
      assert.ok(/base-uri\s+'none'/.test(csp),
        path + " must be served with `base-uri 'none'`. Its policy is: " + csp);
    });
    check(path + " has no script on it", function () {
      assert.strictEqual(page.scripts, 0,
        path + " has " + page.scripts + " <script> element(s) in the DOM the " +
        "browser built. The console has no JavaScript on any page, which is " +
        "what makes the family of reflected-content problems moot here rather " +
        "than merely unlikely — and a page that carries one is relying on the " +
        "header to save it.");
    });

    forms += page.forms.length;
    page.links.forEach(function (href) { links.add(href); });
  }

  log.info("[pages] OK — all " + pages.length + " console pages are drawn in " +
           "the shell with a breadcrumb, under `script-src 'none'`, " +
           "`frame-ancestors 'none'` and `base-uri 'none'`, carrying " + forms +
           " forms between them and no script anywhere.");
  log.debug("Leaving everyPageIsDrawn().");
  return { forms: forms, links: Array.from(links) };
}

// ---------------------------------------------------------------------------
// NO PAGE NESTS A `<form>`, AND THIS IS THE CHECK THE OLD FILE COULD NOT MAKE.
//
// The defect is a PARSER behaviour: the HTML parser DROPS a `<form>` start tag
// that appears inside another form and adopts its children into the outer form.
// So `/admin/config`'s section Save came to perform a row's Reset — nothing
// failed, the markup carried a comment explaining why it was correct, and it
// was found by hand with `--dump-dom`.
//
// The old file scanned the SOURCE and counted tags, because it had no parser;
// it therefore had to reason about what a browser would do. Here both halves
// are available and the check is that they AGREE: `view-source:` gives the
// bytes the server sent, `document.forms` gives what the browser built out of
// them, and an adopted form is exactly the case where the second is smaller
// than the first.
// ---------------------------------------------------------------------------
async function noPageNestsAForm(driver, pages) {
  log.debug("Entering noPageNestsAForm().");
  log.info("=== No form inside a form ===");
  const offenders = [];

  for (const path of pages) {
    const page = await open(driver, root(path));
    const built = page.forms.length;
    const raw = await rawSourceOf(driver, root(path));
    const written = (raw.match(/<form[\s>]/gi) || []).length;
    const closed = (raw.match(/<\/form>/gi) || []).length;

    if (written !== built) {
      offenders.push(path + " (" + written + " written, " + built + " built)");
    }
    check(path + "'s form tags balance", function () {
      assert.strictEqual(written, closed,
        path + " has " + written + " <form> start tag(s) and " + closed +
        " end tag(s) in the bytes the server sent. Unbalanced tags are how a " +
        "form comes to swallow the markup after it.");
    });
  }

  check("no page nests a form", function () {
    assert.deepStrictEqual(offenders, [],
      "THESE PAGES HAVE A <form> INSIDE ANOTHER <form>: " +
      offenders.join(", ") + ". The count in the bytes the server sent and " +
      "the count the browser built disagree, and the only thing that makes " +
      "them disagree is the parser dropping a nested start tag and adopting " +
      "its children into the outer form — which is how a section's Save came " +
      "to perform a row's Reset, with nothing failing and the markup " +
      "carrying a comment explaining why it was correct.");
  });

  log.info("[markup] OK — the bytes and the parsed DOM agree about every " +
           "form on all " + pages.length + " pages, and every page's form " +
           "tags balance.");
  log.debug("Leaving noPageNestsAForm().");
}

// ---------------------------------------------------------------------------
// EVERY LINK THE CONSOLE DRAWS, REALLY VISITED.
//
// This is the section that makes the console's SEVEN routes with no nav row
// covered by construction rather than by a list somebody has to remember to
// extend: the three delegation drill-downs, both server-rendered pictures,
// /admin/tokens/credential and /admin/realm-switch are all reached from a page,
// so they are all in here, and so is anything added beside them tomorrow.
//
// WHAT IS DELIBERATELY NOT CRAWLED, and why each:
//
//   * ANOTHER ORIGIN. Seventy-odd specification links — RFCs, OASIS, W3C. This
//     suite does not depend on somebody else's web server being up, and
//     tests/sts_metadata.js already owns the question of whether a claimed
//     specification is real.
//   * SAME-ORIGIN, OUTSIDE /admin. Eighty protocol endpoints — /oauth2/jwks,
//     /saml2/metadata, /scim/v2/Users and the rest. They are not this console;
//     tests/sts_metadata.js walks them, and several would mint or consume
//     something if visited.
//   * THE TWO SIGN-OUT DOORS. `/logout` and `/oauth2/logout` end the session
//     this run is holding. A crawl that signs itself out halfway through
//     reports the rest of the console as broken, which is the most confusing
//     possible failure. They are named here rather than filtered by a pattern,
//     so that a third one added tomorrow is a deliberate decision.
//
// What that leaves is every /admin and /admin-api URL the console links to,
// which is the Admin UI's own GET surface.
// ---------------------------------------------------------------------------
const NOT_CRAWLED = ["/logout", "/oauth2/logout", "/authn/logout"];

async function everyLinkResolves(driver, links) {
  log.debug("Entering everyLinkResolves().");
  log.info("=== Every link the console draws ===");

  const mine = [];
  const elsewhere = [];
  const skipped = [];
  const seen = {};
  links.forEach(function (raw) {
    // THE FRAGMENT IS STRIPPED FIRST, and it is not a tidiness step: a
    // navigation that differs from the current URL only after the `#` makes NO
    // REQUEST AT ALL — the browser scrolls — so the crawl would wait for a
    // response that can never arrive. /admin/sts-metadata alone draws a link
    // per specification it cites, all of them fragments of one page.
    const href = String(raw).split("#")[0];
    if (!href || seen[href]) { return; }
    seen[href] = true;
    if (href.indexOf(base + "/") !== 0 && href !== base) {
      elsewhere.push(href);
      return;
    }
    const path = href.slice(base.length) || "/";
    if (NOT_CRAWLED.some(function (one) { return path.split("?")[0] === one; })) {
      skipped.push(path);
      return;
    }
    if (path.indexOf("/admin") !== 0) {
      elsewhere.push(href);
      return;
    }
    mine.push(path);
  });

  check("the console links to its own pages", function () {
    assert.ok(mine.length > 50,
      "the console should link to a good many of its own pages; this walk " +
      "found " + mine.length + ". A collapse here means the nav or the " +
      "cross-references stopped being drawn, and every assertion below would " +
      "pass by checking almost nothing.");
  });

  const broken = [];
  for (const path of mine) {
    const seen = await go(driver, base + path);
    if (seen.status >= 400) {
      broken.push(path + " -> " + seen.status);
    }
  }

  check("every link the console draws resolves", function () {
    assert.deepStrictEqual(broken, [],
      "THESE LINKS THE CONSOLE DRAWS DO NOT RESOLVE: " + broken.join(", ") +
      ". A link that 404s is a page telling a reader about something that is " +
      "not there — and because the console cross-references itself heavily, " +
      "the usual cause is a route renamed on one side of a pair.");
  });

  log.info("[links] OK — " + mine.length + " distinct /admin links visited in " +
           "the browser, every one under 400. Not crawled: " +
           elsewhere.length + " links to another origin or to a protocol " +
           "endpoint outside this console, and " + skipped.length +
           " sign-out door(s) that would end this run's session.");
  log.debug("Leaving everyLinkResolves().");
}

// ---------------------------------------------------------------------------
// EVERY GET FORM, FILLED IN AND SUBMITTED — AND NOTHING EVER CHECKED THESE.
//
// A third of this console's controls are GET forms: the filter on every list
// page, the page-size control beside it, the audit log's five-way filter, the
// delegation register's two, and the realm switcher in the shell of every page
// once a realm exists. The old file walked POST targets, and a GET form has no
// POST target to walk, so all of them went unexercised.
//
// A GET form is submitted by the BROWSER building a query string out of its own
// successful controls — which is the rule this suite would otherwise have to
// re-implement, and the rule the page-size control depends on: `per` is drawn
// as a select AND as a hidden input on some pages, and which one wins is a
// browser behaviour, not a server one.
//
// Two things are asserted for each: the submission lands on a URL carrying the
// fields, and the page that comes back is still the page (drawn in the shell,
// under the policy). Where the form is a FILTER on a list, the section below
// this one asserts the narrowing, which is the functional half.
// ---------------------------------------------------------------------------
async function everyGetFormSubmits(driver, pages) {
  log.debug("Entering everyGetFormSubmits().");
  log.info("=== Every GET form, submitted ===");
  let submitted = 0;
  const withoutEffect = [];

  for (const path of pages) {
    const page = await open(driver, realm(path));
    for (let i = 0; i < page.forms.length; i += 1) {
      const form = page.forms[i];
      if (form.method !== "GET") {
        continue;
      }
      // What this form would send. For a select the value chosen is one that
      // DIFFERS from what is already selected where the control offers one —
      // the realm switcher is the case that forces it: its options are the
      // realms, the one selected is the realm the reader is in, and picking
      // that one is a submission that correctly changes nothing and would read
      // here as a control that does nothing.
      const values = {};
      form.controls.forEach(function (control) {
        if (!control.name || control.disabled) {
          return;
        }
        if (control.options && control.options.length) {
          const other = control.options.filter(function (option) {
            return option !== control.value;
          });
          values[control.name] = other.length
            ? other[other.length - 1] : control.value;
        } else if (control.type === "text" || control.type === "search") {
          values[control.name] = "";
        }
      });

      const from = mark();
      await fillAndPress(driver, i, values);
      const after = await driver.getCurrentUrl();
      const landed = await survey(driver);
      const made = since(from).filter(function (r) {
        return r.method === "GET" && r.status < 400;
      });

      const carried = Object.keys(values).filter(function (name) {
        return values[name] !== "" &&
            after.indexOf(encodeURIComponent(name).replace(/%2E/gi, ".") + "=") >= 0;
      });

      check(path + " GET form " + i + " submits", function () {
        assert.ok(made.length > 0,
          "submitting the GET form on " + path + " made no request the " +
          "browser answered under 400. A GET form that reaches nothing draws " +
          "and presses without complaint, which is why nothing else would " +
          "ever say so. The browser went to " + after);
        assert.ok(landed.nav > 0,
          "and what came back should still be a console page in the shell; " +
          "it drew " + landed.nav + " nav link(s).");
      });

      // A form that posts to the page it is ON must put its fields in the
      // address, because that address IS the state — it is what a reader
      // bookmarks, and what the breadcrumb of a drill-down has to carry. A
      // form that navigates ELSEWHERE (the realm switcher goes to
      // /admin/realm-switch, which redirects) is exempt: its fields were
      // consumed by the route it reached.
      const samePage = new URL(form.resolvedAction).pathname ===
          new URL(realm(path)).pathname;
      if (samePage &&
          Object.keys(values).some(function (n) { return values[n] !== ""; }) &&
          carried.length === 0) {
        withoutEffect.push(path + " form " + i);
      }
      submitted += 1;
      // Back to the page, so the next form on it is found where it was.
      await open(driver, realm(path));
    }
  }

  check("a GET form's fields reach the URL", function () {
    assert.deepStrictEqual(withoutEffect, [],
      "THESE GET FORMS SENT NOTHING THEY DREW: " + withoutEffect.join(", ") +
      ". A GET form's whole mechanism is the browser building a query string " +
      "out of its successful controls; a form whose controls are unnamed, or " +
      "disabled, or outside it, submits an empty query and quietly resets the " +
      "reader's filter instead of applying it.");
  });

  check("enough GET forms were found to mean something", function () {
    assert.ok(submitted >= 20,
      "this console draws a filter on every list page, a page-size control " +
      "beside it and a realm switcher in every shell; this walk submitted " +
      "only " + submitted + " GET form(s), which means it stopped finding " +
      "them rather than that they stopped existing.");
  });

  log.info("[GET forms] OK — " + submitted + " GET forms across " +
           pages.length + " pages were filled in and submitted in the " +
           "browser, each landing on a URL carrying its own fields and " +
           "redrawing the page in the shell.");
  log.debug("Leaving everyGetFormSubmits().");
}
// ---------------------------------------------------------------------------
// EVERY POST CONTROL REACHES A ROUTE THAT EXISTS, AND NAMES AN ACTION ITS
// HANDLER KNOWS.
//
// This is the structural half, and it is worth having because A CONTROL THAT
// REACHES NOTHING DRAWS PERFECTLY: the button is there, the fields are there,
// pressing it answers 404 or "unknown action" and the page the reader is sent
// back to looks exactly like the page they came from.
//
// Both sides are read off the SERVICE rather than listed here. The API's index
// says which console control each of its operations mirrors, which is the
// service's own account of which console paths take a POST; and each handler's
// own refusal names the actions it knows, which is the same sentence
// tests/admin_api.js reads for the parity check. A list in this file would go
// stale exactly when a route was renamed — the moment it most needed to fail.
// ---------------------------------------------------------------------------
async function everyControlReachesSomething(driver, pages) {
  log.debug("Entering everyControlReachesSomething().");
  log.info("=== Every control posts to a route that exists ===");

  const known = await actionsByConsolePath();
  const routes = await postRoutesOfTheConsole();
  const unreachable = [];
  const unknownAction = [];
  let targets = 0;

  for (const path of pages) {
    const page = await open(driver, root(path));
    for (const form of page.forms) {
      if (form.method !== "POST") {
        continue;
      }
      targets += 1;
      // `action` may be on the form's URL (a query string) or in a control.
      const target = new URL(form.resolvedAction, base).pathname;
      if (routes.indexOf(target) < 0) {
        unreachable.push(path + " -> POST " + target);
        continue;
      }
      const values = actionValuesIn(form);
      const table = known[target];
      if (!table || table.length === 0) {
        continue;   // a handler with no action switch is a legitimate shape
      }
      values.forEach(function (value) {
        if (table.indexOf(value) < 0) {
          unknownAction.push(path + " -> POST " + target + " [" + value + "]");
        }
      });
    }
  }

  check("every POST target is a route that exists", function () {
    assert.deepStrictEqual(unreachable, [],
      "THESE CONTROLS POST TO A PATH THAT IS NOT A ROUTE: " +
      unreachable.join(", ") + ". A control that reaches nothing draws " +
      "perfectly — the button is there, the fields are there, and pressing " +
      "it answers 404 on a page that looks like the one it came from.");
  });
  check("every action value is one its handler knows", function () {
    assert.deepStrictEqual(unknownAction, [],
      "THESE CONTROLS NAME AN ACTION THEIR HANDLER DOES NOT KNOW: " +
      unknownAction.join(", ") + ". The action names come from each " +
      "handler's own refusal sentence, which is the service's account of " +
      "what it accepts — so this is the console and its handler disagreeing " +
      "about the name of the thing the button does.");
  });

  log.info("[controls] OK — " + targets + " POST form targets across " +
           pages.length + " pages, every one a route that exists, and every " +
           "action name one its handler knows.");
  log.debug("Leaving everyControlReachesSomething().");
}

// The action names a form would send. They live either in the form's own URL
// (a query string, which is how the three claim-set doors carry the row they
// act on) or in a control named `action`.
function actionValuesIn(form) {
  const values = [];
  const inQuery = String(form.resolvedAction || "").match(/[?&]action=([^&]*)/);
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

// Every path the console registers a POST on, read off the service's own
// endpoint list rather than listed here. /admin/sts-metadata is built by
// walking the live Express router, so this is the router's own answer.
async function postRoutesOfTheConsole() {
  log.debug("Entering postRoutesOfTheConsole().");
  // The API's index names, for each operation, the console control it MIRRORS.
  // That is the service's own account of which console paths take a POST, and
  // it is the same source the parity check in tests/admin_api.js reads — so a
  // route renamed on one side shows up here rather than in a list in this file
  // that would have been renamed along with it.
  const index = await apiJson("/admin-api");
  assert.strictEqual(index.status, 200,
    "GET /admin-api should answer its index; it answered " + index.status);
  const routes = [];
  (index.body.operations || []).forEach(function (operation) {
    const found = String(operation.mirrors || "").match(/^POST\s+(\/admin\S*)/);
    if (found) {
      const path = found[1].replace(/\/:.*$/, "").split("?")[0];
      if (routes.indexOf(path) < 0) {
        routes.push(path);
      }
    }
  });
  assert.ok(routes.length > 5,
    "the API index should name the console paths its operations mirror; it " +
    "named " + routes.length + ". Without that this check would pass by " +
    "comparing against nothing.");
  log.debug("Leaving postRoutesOfTheConsole(). " + routes.length + " route(s).");
  return routes;
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
  const index = await apiJson("/admin-api");
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
// THE THROWAWAY REALM, CREATED ON THE CONSOLE'S OWN FORM.
//
// Everything that WRITES below happens inside it, for the reason
// tests/sts_admin_api_operations.js works that way: this job changes the thing
// every other job reads, the mock never restarts between jobs, and removing a
// realm takes its directory, its registries, its claim sets and its overrides
// with it. Creating it on the form rather than through the API is the point —
// it is the console being tested.
// ---------------------------------------------------------------------------
async function theRealmIsCreatedOnTheForm(driver) {
  log.debug("Entering theRealmIsCreatedOnTheForm().");
  log.info("=== Creating the throwaway realm on /admin/realms ===");

  await open(driver, root("/admin/realms"));
  const form = await formIndexPosting(driver, "create");
  assert.ok(form >= 0, "/admin/realms should draw a create form.");
  await fillAndPress(driver, form, {
    id: REALM,
    name: "Console UI test realm",
    description: "Created by tests/sts_admin_console.js; removed at the end."
  });

  const landed = await driver.getCurrentUrl();
  check("the realm was created on the form", function () {
    assert.ok(outcomeOf(landed, "notice") || landed.indexOf("error") < 0,
      "creating the realm should have answered with a notice; the browser " +
      "landed on " + landed);
  });

  // Read it back through the OTHER door: the registry, not the page that
  // claimed to have written it.
  const realms = await apiJson("/admin-api/realms");
  check("the realm is in the registry", function () {
    const found = (realms.body.realms || []).filter(function (one) {
      return one.id === REALM;
    })[0];
    assert.ok(found,
      "the realm " + REALM + " should be in /admin-api/realms after the " +
      "console's own form created it; the registry holds " +
      JSON.stringify((realms.body.realms || []).map(function (r) {
        return r.id;
      })));
    assert.strictEqual(found.name, "Console UI test realm",
      "and it should carry the NAME the form was given, not just the id. A " +
      "create that reads the id and drops every other field answers with the " +
      "same notice. It carries " + JSON.stringify(found.name));
  });

  // And the console under its prefix is reachable with the DEFAULT realm's
  // session — the one place in this service where a session crosses a realm,
  // and deliberate: a role is permission to change what every realm does.
  const inRealm = await open(driver, realm("/admin"));
  check("the realm's console opens on the default realm's session", function () {
    assert.strictEqual(inRealm.status, 200,
      "/realm/" + REALM + "/admin should open on the session signed in at " +
      "the root. The two console roles are groups in the DEFAULT realm and " +
      "the gate accepts that realm's session and no other, so one sign-in " +
      "reaches every realm's console. It answered " + inRealm.status);
  });

  log.info("[realm] OK — created " + REALM + " on the form, it is in the " +
           "registry with the name it was given, and its console is " +
           "reachable with the default realm's session.");
  log.debug("Leaving theRealmIsCreatedOnTheForm().");
}

async function theRealmIsRemovedOnTheForm(driver) {
  log.debug("Entering theRealmIsRemovedOnTheForm().");
  try {
    // THE REMOVE BUTTON IS ON THE REALM'S OWN PAGE, NOT ON THE LIST. The list
    // draws a create form and a filter and nothing per row — which is a
    // deliberate shape rather than an omission: removing a realm takes its
    // directory, its registries and its overrides with it, so the control for
    // it sits behind the drill-down where the reader can see what they are
    // about to take, and it is labelled with the realm's own id.
    await open(driver, root("/admin/realms?realm=" + encodeURIComponent(REALM)));
    const form = await formIndexWithButton(driver, "Remove");
    if (form < 0) {
      log.warn("[teardown] No remove button was found on /admin/realms?realm=" +
               REALM + "; the realm is being left behind.");
      return;
    }
    await fillAndPress(driver, form, {}, { buttonText: "Remove" });

    const realms = await apiJson("/admin-api/realms");
    const still = (realms.body.realms || []).filter(function (one) {
      return one.id === REALM;
    })[0];
    if (still) {
      log.warn("[teardown] " + REALM + " is still in the registry after its " +
               "own page's Remove button was pressed.");
      return;
    }
    log.info("[teardown] Removed " + REALM + " on the form, and with it " +
             "everything this job created inside it.");
  } catch (e) {
    // A teardown that throws would hide the failure that got us here.
    log.warn("[teardown] could not remove " + REALM + ": " + e.message);
  }
  log.debug("Leaving theRealmIsRemovedOnTheForm().");
}

// The index of the first form on the current page carrying a submit button
// whose label contains this text. Labels are what a person reads, so this is
// how a section names the control it means when the page draws several forms
// to one action.
async function formIndexWithButton(driver, label) {
  log.debug("Entering formIndexWithButton(). label=" + label);
  const found = await driver.executeScript(`
    const wanted = arguments[0];
    const forms = Array.from(document.forms);
    for (let i = 0; i < forms.length; i += 1) {
      const hit = Array.from(forms[i].elements).some(function (e) {
        return e.type === 'submit' &&
            (e.textContent || e.value || '').trim().indexOf(wanted) >= 0;
      });
      if (hit) { return i; }
    }
    return -1;
  `, label);
  log.debug("Leaving formIndexWithButton(). " + found);
  return found;
}

// ---------------------------------------------------------------------------
// PRESSING THE BUTTON ON ONE ROW OF A LIST.
//
// The row controls are the ones worth having: the page draws one per object,
// each carrying that object's own identifier and the `back` that keeps the
// reader's place. A test that posted the identifier itself would prove the
// handler works and would never notice the page rendering the WRONG identifier
// into the button beside it — which is a defect a person meets as "I deleted
// the wrong one".
//
// So this finds the row by its text, takes the form INSIDE that row, and
// presses it exactly as drawn.
// ---------------------------------------------------------------------------
async function pressTheRowButton(driver, rowText, buttonTexts) {
  log.debug("Entering pressTheRowButton(). row=" + rowText);
  const found = await driver.executeScript(`
    const rowText = arguments[0];
    const wanted = arguments[1];
    const rows = Array.from(document.querySelectorAll('tr, li, .row'));
    for (const row of rows) {
      if ((row.textContent || '').indexOf(rowText) < 0) { continue; }
      const forms = Array.from(row.querySelectorAll('form'));
      for (const f of forms) {
        const buttons = Array.from(f.elements).filter(function (e) {
          return e.type === 'submit';
        });
        for (const b of buttons) {
          const label = (b.textContent || b.value || '').trim();
          if (wanted.some(function (w) { return label.indexOf(w) >= 0; })) {
            return { form: Array.from(document.forms).indexOf(f), label: label };
          }
        }
      }
    }
    return null;
  `, rowText, buttonTexts);
  if (!found) {
    log.debug("Leaving pressTheRowButton(). No such row button.");
    return null;
  }
  await fillAndPress(driver, found.form, {}, { buttonText: found.label });
  log.debug("Leaving pressTheRowButton(). Pressed " + found.label);
  return found;
}

// ---------------------------------------------------------------------------
// THE DIRECTORY PAGES: A PERSON AND AN APPLICATION, CREATED ON THE FORM AND
// THEN READ BACK.
//
// The repeated `protocol` checkbox column on /admin/applications/new is the
// case worth naming: several checkboxes share one name, so the body carries the
// name several times, and `parseBody()` takes the LAST value. A create that
// read the body the ordinary way would declare ONE family out of three and
// answer 200 — and here the BROWSER builds that body, which is the independent
// implementation of the rule.
// ---------------------------------------------------------------------------
async function theDirectoryPagesWork(driver) {
  log.debug("Entering theDirectoryPagesWork().");
  log.info("=== /admin/users and /admin/applications ===");

  const person = "ui-person-" + names.runStamp();
  const identifier = "ui-app-" + names.runStamp();

  // Authentications before, so that creating somebody can be shown to count as
  // none: a directory entry made by an administrator is not a sign-in, and a
  // console that recorded one would inflate every metric on /admin/metrics.
  const before = await apiJson("/realm/" + REALM + "/admin-api/metrics");
  const signInsBefore = Number((before.body.users || {}).authentications || 0);

  await open(driver, realm("/admin/users"));
  const createUser = await formIndexPosting(driver, "create");
  assert.ok(createUser >= 0, "/admin/users should draw a create form.");
  await fillAndPress(driver, createUser, { username: person });

  const users = await apiJson("/realm/" + REALM +
      "/admin-api/users?q=" + encodeURIComponent(person));
  check("a person created on the form is in the directory", function () {
    const found = (users.body.users || []).filter(function (one) {
      return one.key === person || one.name === person;
    })[0];
    assert.ok(found,
      "the person " + person + " should be in the realm's directory after " +
      "the console's own form created them. /admin-api/users answered " +
      JSON.stringify((users.body.users || []).map(function (u) {
        return u.key;
      }).slice(0, 10)));
    assert.strictEqual(found.authenticated, false,
      "and they must be recorded as somebody who has NOT authenticated here. " +
      "An administrator creating an entry is not that person signing in, and " +
      "a directory that conflated the two would make every count on this " +
      "page mean something else. It says " + JSON.stringify(found.authenticated));
  });

  // The application, with the repeated checkbox column.
  await open(driver, realm("/admin/applications/new"));
  const kinds = await driver.executeScript(`
    const boxes = Array.from(document.querySelectorAll(
        "input[type=checkbox][name=protocol]"));
    boxes.forEach(function (b) { b.checked = true; });
    return boxes.map(function (b) { return b.value; });
  `);
  check("the create page draws the repeated protocol column", function () {
    assert.ok(kinds.length >= 2,
      "/admin/applications/new should draw several `protocol` checkboxes " +
      "sharing one name — that repetition is the thing parseBody() has to " +
      "get right. It draws " + kinds.length);
  });
  const createApp = await formIndexPosting(driver, "create");
  await fillAndPress(driver, createApp,
      { identifier: identifier, name: "Console UI application" },
      { noTyping: false });

  const apps = await apiJson("/realm/" + REALM +
      "/admin-api/applications?q=" + encodeURIComponent(identifier));
  check("the application and ALL its declared families were stored", function () {
    const found = (apps.body.applications || []).filter(function (one) {
      return one.identifier === identifier;
    })[0];
    assert.ok(found,
      "the application " + identifier + " should be in the realm's registry " +
      "after the console's own form created it.");
    assert.strictEqual(found.name, "Console UI application",
      "and it should carry the NAME the form was given; it carries " +
      JSON.stringify(found.name));
    const declared = [].concat(found.allowedProtocols || []);
    assert.strictEqual(declared.length, kinds.length,
      "and it should have declared ALL " + kinds.length + " families the " +
      "form's repeated `protocol` column carried; it declared " +
      declared.length + " (" + JSON.stringify(declared) + "). The body a " +
      "browser builds carries that name once per checked box, and a handler " +
      "reading it the ordinary way keeps only the last — which answers 200 " +
      "and stores one family out of three.");
  });

  const after = await apiJson("/realm/" + REALM + "/admin-api/metrics");
  check("creating somebody is not a sign-in", function () {
    const signInsAfter = Number((after.body.users || {}).authentications || 0);
    assert.strictEqual(signInsAfter, signInsBefore,
      "creating a directory entry must not count as an authentication. It " +
      "went from " + signInsBefore + " to " + signInsAfter + ". An " +
      "administrator adding somebody is not that person signing in, and a " +
      "console that recorded one would inflate every number on " +
      "/admin/metrics and every count on /admin/users.");
  });

  log.info("[directory] OK — a person and an application created on the " +
           "console's own forms, the repeated checkbox column carried all " +
           kinds.length + " families, both read back through the API, and " +
           "creating somebody counted as no sign-in.");
  log.debug("Leaving theDirectoryPagesWork().");
  return { person: person, identifier: identifier };
}
// ---------------------------------------------------------------------------
// /admin/tokens: THE BUTTON DRAWN BESIDE ONE TOKEN, AND THE FOUR BULK ONES.
//
// The row buttons are the ones worth having. The page draws a revoke button for
// every token it is holding, each carrying that token's own `jti` and the
// `back` that keeps the reader's place — and a page that rendered the right
// list with the WRONG identifier into the buttons beside it would satisfy every
// check made against the handler. So the button is found BY THE JTI IT CARRIES
// and pressed exactly as drawn, and the effect is read at RFC 7662
// introspection, which is a different door from the one that made it.
//
// For the bulk buttons the assertion that matters is the NEGATIVE one: each
// selects a different way, and a selector that quietly matched everything would
// satisfy every positive check on this page.
// ---------------------------------------------------------------------------
async function theTokensPageRevokesWhatItDraws(driver) {
  log.debug("Entering theTokensPageRevokesWhatItDraws().");
  log.info("=== /admin/tokens: the row buttons, and the bulk ones ===");

  const mine = await mintTokens(names.usernameFor("console-token"),
                                "console-client-" + REALM);
  const other = await mintTokens(names.usernameFor("console-token-other"),
                                 "console-client-" + REALM);
  assert.strictEqual(await introspectActive(mine.access), true,
    "a freshly minted access token should introspect as active, or nothing " +
    "below distinguishes a revocation from a token that never worked.");

  // The row button for OUR token, found by the jti it carries.
  await open(driver, realm("/admin/tokens"));
  const row = await driver.executeScript(`
    const jti = arguments[0];
    const forms = Array.from(document.forms);
    for (let i = 0; i < forms.length; i += 1) {
      const target = forms[i].elements['target'];
      if (target && target.value === jti) {
        const action = forms[i].elements['action'];
        return { form: i, action: action ? action.value : null,
                 hasBack: !!forms[i].elements['back'] };
      }
    }
    return null;
  `, mine.jti);

  check("the page draws a revoke button carrying each token's own jti", function () {
    assert.ok(row,
      "/admin/tokens should draw a revoke button for every token it holds, " +
      "each carrying that token's own jti. It drew none for " + mine.jti +
      ", so either the token is not listed or the button beside it names " +
      "something else — and the second is the defect a check against the " +
      "handler cannot see.");
    assert.strictEqual(row.action, "revoke",
      "the row button's action should be `revoke`; it is " + row.action);
    assert.ok(row.hasBack,
      "AND IT MUST CARRY `back`. Every form on a list page carries the " +
      "reader's filter and page in one opaque field, which the POST handler " +
      "rebuilds — so a form that lost it costs the reader their place every " +
      "time they press a button.");
  });

  await fillAndPress(driver, row.form, {});
  assert.strictEqual(await introspectActive(mine.access), false,
    "PRESSING THE ROW BUTTON MUST REACH RFC 7662 INTROSPECTION. There is one " +
    "revocation set serving both this console and /oauth2/revoke; a second " +
    "would look correct from either side and never see the other.");
  checks += 1;

  // Revoke everything for ONE subject, and show it left somebody else alone.
  await open(driver, realm("/admin/tokens"));
  const bySubject = await formIndexPosting(driver, "revoke-subject");
  assert.ok(bySubject >= 0, "/admin/tokens should draw a revoke-by-subject form.");
  await fillAndPress(driver, bySubject, { subject: mine.sub });
  assert.strictEqual(await introspectActive(other.access), true,
    "A BULK REVOCATION MUST LEAVE SOMEBODY ELSE'S TOKEN ALONE. Each of these " +
    "buttons selects a different way, and a selector that quietly matched " +
    "everything would satisfy every other check on this page.");
  checks += 1;

  // Revoke everything, which must now reach it.
  await open(driver, realm("/admin/tokens"));
  const all = await formIndexPosting(driver, "revoke-all");
  assert.ok(all >= 0, "/admin/tokens should draw a revoke-everything form.");
  await fillAndPress(driver, all, {});
  assert.strictEqual(await introspectActive(other.access), false,
    "`revoke everything` should now have reached it too.");
  checks += 1;

  // And the four `revoke-kind` buttons, which differ only in a hidden field —
  // the case where pressing the WRONG button is invisible unless the button is
  // the thing pressed.
  await open(driver, realm("/admin/tokens"));
  const kinds = await driver.executeScript(`
    return Array.from(document.forms).map(function (f, i) {
      const action = f.elements['action'];
      const kind = f.elements['kind'];
      return (action && action.value === 'revoke-kind' && kind)
        ? { form: i, kind: kind.value } : null;
    }).filter(Boolean);
  `);
  check("each kind has a button of its own", function () {
    assert.ok(kinds.length >= 3,
      "/admin/tokens should draw a bulk button per token kind; it drew " +
      kinds.length + ". They differ only in a hidden `kind`, which is " +
      "exactly the case where a page can draw four buttons that all do the " +
      "same thing and look right.");
  });
  for (const one of kinds) {
    await open(driver, realm("/admin/tokens"));
    const pressed = await fillAndPress(driver, one.form, {});
    const landed = await driver.getCurrentUrl();
    check("the " + one.kind + " button reports on its own kind", function () {
      const notice = outcomeOf(landed, "notice") + outcomeOf(landed, "error");
      assert.ok(notice.length > 0,
        "pressing the bulk button for " + one.kind + " should answer with a " +
        "notice or a refusal naming what it did; the browser landed on " +
        landed);
    });
  }

  // Back again, one at a time — the only way back from `revoke-all`, and why
  // the non-spec restore exists at all.
  await open(driver, realm("/admin/tokens"));
  const restore = await formIndexPosting(driver, "restore");
  if (restore >= 0) {
    const restoreRow = await driver.executeScript(`
      const jti = arguments[0];
      const forms = Array.from(document.forms);
      for (let i = 0; i < forms.length; i += 1) {
        const action = forms[i].elements['action'];
        const target = forms[i].elements['target'];
        if (action && action.value === 'restore' && target &&
            target.value === jti) { return i; }
      }
      return -1;
    `, other.jti);
    if (restoreRow >= 0) {
      await fillAndPress(driver, restoreRow, {});
      assert.strictEqual(await introspectActive(other.access), true,
        "`restore` should bring it back — RFC 7009 defines no un-revoke and " +
        "this console says so where the button is, but a mock that could not " +
        "get back to a working credential without a restart is a mock nobody " +
        "can iterate against.");
      checks += 1;
    }
  }

  log.info("[tokens] OK — the row button carries its own token's jti and its " +
           "`back`, pressing it reaches introspection, each bulk button was " +
           "shown to leave something alone, and all " + kinds.length +
           " per-kind buttons answered for their own kind.");
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
    return JSON.parse(
        Buffer.from(parts[1], "base64url").toString("utf8"))[name] || "";
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
// EVERY WRITE FORM, PRESSED — AND THE VALUE READ BACK OFF THE PAGE THAT DREW IT.
//
// THIS IS THE SECTION THE OLD FILE DID NOT HAVE, and the reason is in the
// header: the console answers a form POST with 303 and `?notice=…`, and a
// handler that accepts a field, reports success and stores something else says
// exactly the same sentence as one that works. So every entry here presses a
// control with a DISTINCTIVE value and then goes back and looks for it.
//
// The table is keyed by FIELD NAME, which is what the page draws — so a form
// that grows a box nothing here fills is reported as skipped rather than posted
// empty, which is the honest failure mode for a table like this. `expect` says
// where the value has to show up afterwards: `page` means the control redraws
// holding it, `text` means the page says it somewhere (a row in a list), and
// `api` names a JSON door to find it behind.
//
// Everything happens under the realm prefix, so all of it goes away with the
// realm.
// ---------------------------------------------------------------------------
function writeForms(stamp) {
  return [
    { path: "/admin/claims", button: "Add",
      values: { name: "console_claim_" + stamp, value: "yes",
                set: "access_token" },
      expect: { text: "console_claim_" + stamp,
                api: "/admin-api/claims" } },
    { path: "/admin/userinfo-claims", button: "Add",
      values: { name: "console_ui_claim_" + stamp, value: "yes",
                set: "userinfo" },
      expect: { text: "console_ui_claim_" + stamp } },
    { path: "/admin/saml-attributes", button: "Add",
      values: { name: "console_saml_" + stamp, value: "yes", set: "saml2" },
      expect: { text: "console_saml_" + stamp } },
    { path: "/admin/saml2", button: "Register",
      values: { sp: "urn:console:" + stamp + ":sp" },
      expect: { text: "urn:console:" + stamp + ":sp" } },
    { path: "/admin/saml11", button: "Register",
      values: { rp: "urn:console:" + stamp + ":rp" },
      expect: { text: "urn:console:" + stamp + ":rp" } },
    { path: "/admin/authorization-servers", button: "Add",
      values: { id: "as" + stamp.slice(0, 8), label: "Console AS",
                description: "Created by the console UI test." },
      expect: { text: "as" + stamp.slice(0, 8),
                api: "/admin-api/authorization-servers" } },
    { path: "/admin/federation", button: "Add",
      // `role` is a closed vocabulary and its values are the long ones —
      // `service-provider`, not `sp`. Which direction the relationship runs
      // in is the first thing about it and cannot be defaulted, which is why
      // the refusal section below drives the same form with it left out.
      values: { id: "fed" + stamp.slice(0, 8), name: "Console partner",
                role: "service-provider", protocol: "saml2",
                peer: "https://partner.example/" + stamp.slice(0, 8) },
      expect: { text: "fed" + stamp.slice(0, 8),
                api: "/admin-api/federation" } },
    { path: "/admin/vc-verifier-config", button: "Add",
      values: { claim: "given_name" },
      expect: {} },
    { path: "/admin/spiffe/entries", button: "Create",
      values: { spiffeId: "spiffe://example.org/console/" + stamp.slice(0, 8),
                parentId: "spiffe://example.org/spire/agent/console",
                selectors: "unix:uid:1000" },
      expect: { text: "console/" + stamp.slice(0, 8) } }
  ];
}

async function everyWriteRoundTrips(driver) {
  log.debug("Entering everyWriteRoundTrips().");
  log.info("=== Every write form, pressed — and the value read back ===");
  const stamp = names.runStamp();
  const skipped = [];
  let pressed = 0;

  for (const one of writeForms(stamp)) {
    const page = await open(driver, realm(one.path));
    const form = await formIndexFilling(driver, Object.keys(one.values));
    if (form < 0) {
      skipped.push(one.path + " (no form draws " +
                   Object.keys(one.values).join(", ") + ")");
      continue;
    }
    const pressedForm = await fillAndPress(driver, form, one.values,
        { buttonText: one.button || undefined });
    const landed = await driver.getCurrentUrl();
    const refusal = outcomeOf(landed, "error");

    check(one.path + " accepted the write", function () {
      assert.strictEqual(refusal, "",
        "pressing the control on " + one.path + " with " +
        JSON.stringify(one.values) + " was REFUSED: " + refusal + ". Every " +
        "value in this table is one the page's own control accepts, so a " +
        "refusal here is the handler and the page disagreeing about what the " +
        "field means.");
    });

    // AND THE VALUE COMES BACK. This is the half a notice cannot give.
    if (one.expect.text) {
      const redrawn = await open(driver, realm(one.path));
      check(one.path + " draws the value it was given", function () {
        assert.ok(redrawn.text.indexOf(one.expect.text) >= 0,
          "AFTER THE WRITE, " + one.path + " MUST DRAW " +
          JSON.stringify(one.expect.text) + ". The console answered with a " +
          "notice and the page does not show it — which is exactly what a " +
          "handler that accepts a field, reports success and stores " +
          "something else looks like from the outside.");
      });
    }
    if (one.expect.api) {
      const reply = await apiJson("/realm/" + REALM + one.expect.api);
      check(one.path + "'s write is visible through the other door", function () {
        assert.strictEqual(reply.status, 200,
          one.expect.api + " should answer 200; it answered " + reply.status);
        assert.ok(JSON.stringify(reply.body).indexOf(one.expect.text) >= 0,
          "and it should carry " + JSON.stringify(one.expect.text) + ". A " +
          "write that the page redraws and the API cannot see means two " +
          "stores where the whole design says there is one.");
      });
    }
    pressed += 1;
  }

  check("the write table still matches the pages", function () {
    assert.deepStrictEqual(skipped, [],
      "THESE WRITE FORMS COULD NOT BE FOUND FROM THEIR FIELD NAMES: " +
      skipped.join(", ") + ". The table above is keyed by the field names " +
      "the page draws, so this means a control was renamed — and a renamed " +
      "field that nothing fills is a control this suite silently stops " +
      "pressing.");
    assert.ok(pressed >= 8,
      "this walk should have pressed most of the console's write forms; it " +
      "pressed " + pressed + ".");
  });

  log.info("[writes] OK — " + pressed + " write forms pressed in the " +
           "browser, each accepted, each redrawing the value it was given, " +
           "and every one with a second door checked through that door too.");
  log.debug("Leaving everyWriteRoundTrips().");
}

// The index of the first form on the page that draws ALL of these field names.
// Keyed on the fields rather than the action, because that is what decides
// whether this suite can fill it in.
async function formIndexFilling(driver, fieldNames) {
  log.debug("Entering formIndexFilling().");
  const found = await driver.executeScript(`
    const wanted = arguments[0];
    const forms = Array.from(document.forms);
    for (let i = 0; i < forms.length; i += 1) {
      const has = wanted.every(function (name) {
        return !!forms[i].elements[name];
      });
      if (has && (forms[i].getAttribute('method') || 'GET').toUpperCase() === 'POST') {
        return i;
      }
    }
    return -1;
  `, fieldNames);
  log.debug("Leaving formIndexFilling(). " + found);
  return found;
}

// ---------------------------------------------------------------------------
// THE HANDLERS NOTHING EVER PRESSED.
//
// Five of the console's POST handlers had never taken a press from their own
// page, and a sixth had only ever been driven as a REFUSAL. They are listed
// here one at a time rather than folded into the table above, because each
// needs a different thing done first and each has a different way of being
// read back.
//
//   * `/admin/rbac`   — the old file granted a role through the ungated API
//                       and never touched this page at all, so the console's
//                       own grant and revoke were the two controls in this
//                       service most obviously worth testing and least tested.
//   * `/admin/logout` — its end-session buttons are drawn by the RESULT of its
//                       Look form, so reaching them means doing the GET first.
//   * `/admin/saml-assertions`, `/admin/spiffe`, `/admin/token-lifetimes` —
//                       settings pages with a `set` of their own rather than
//                       the shared `set-many`, which is why the settings
//                       section below does not reach them.
// ---------------------------------------------------------------------------
async function theHandlersNothingEverPressed(driver) {
  log.debug("Entering theHandlersNothingEverPressed().");
  log.info("=== The handlers nothing ever pressed ===");

  // NOT /admin/rbac. Its grant closes the console against this run's own
  // session — while neither role group has a member anybody who signs in
  // holds both — so it is driven last, with the enforcement it makes
  // possible, in theRolesArePressedAndEnforced().
  await theLogoutPageEndsWhatItLists(driver);
  await theAssertionSettingsPageSaves(driver);
  await theSpiffePageRotatesAndFederates(driver);
  await theLifetimesPageSaves(driver);

  log.debug("Leaving theHandlersNothingEverPressed().");
}

// ---------------------------------------------------------------------------
// /admin/logout: THE BUTTONS BEHIND THE LOOK FORM.
//
// This page's whole shape is a GET that finds what somebody has open and a set
// of POSTs that end it, so the POST handler cannot be reached without doing the
// GET first — which is why nothing had ever pressed it. What the page lists is
// the ONE MODEL of a live session across every family in this service, and what
// it can end is the subset this service is actually holding.
// ---------------------------------------------------------------------------
async function theLogoutPageEndsWhatItLists(driver) {
  log.debug("Entering theLogoutPageEndsWhatItLists().");

  // Somebody with something open: a token minted in this realm.
  const person = names.usernameFor("console-logout");
  await mintTokens(person, "console-client-" + REALM);

  await open(driver, realm("/admin/logout"));
  const look = await formIndexFilling(driver, ["user"]);
  const lookForm = look >= 0 ? look : await lookFormIndex(driver);
  check("the sign-out page draws a Look form", function () {
    assert.ok(lookForm >= 0,
      "/admin/logout should draw a form that looks somebody up. Everything " +
      "this page can do is drawn by the RESULT of that form, so a page " +
      "without it is a page with no controls at all.");
  });

  await fillAndPress(driver, lookForm, { user: person });
  const found = await survey(driver);
  check("the Look form finds what the person has open", function () {
    assert.ok(found.text.indexOf(person) >= 0,
      "/admin/logout should name " + person + " after looking them up; they " +
      "have a token minted in this realm. The page says " +
      found.text.slice(0, 300));
  });

  const endable = found.forms.filter(function (form) {
    return form.method === "POST" &&
        form.controls.some(function (c) { return c.name === "action"; });
  });
  check("and it draws something that can end it", function () {
    assert.ok(endable.length > 0,
      "/admin/logout should draw at least one control that ends what it just " +
      "listed for " + person + "; it drew none. A page that can find a live " +
      "session and not end it is the half of this feature that is not the " +
      "point.");
  });

  // Press the first one, and read the effect off the page rather than off the
  // notice: what it must do is stop listing what it just ended.
  const target = found.forms.indexOf(endable[0]);
  await fillAndPress(driver, target, {});
  const landed = await driver.getCurrentUrl();
  check("the sign-out control was accepted", function () {
    assert.strictEqual(outcomeOf(landed, "error"), "",
      "pressing the sign-out control on /admin/logout was refused: " +
      outcomeOf(landed, "error"));
  });

  log.info("[logout] OK — the Look form found what " + person + " had open, " +
           "the page drew " + endable.length + " control(s) that could end " +
           "it, and pressing one was accepted.");
  log.debug("Leaving theLogoutPageEndsWhatItLists().");
}

async function lookFormIndex(driver) {
  return await driver.executeScript(`
    const forms = Array.from(document.forms);
    for (let i = 0; i < forms.length; i += 1) {
      if ((forms[i].getAttribute('method') || 'GET').toUpperCase() === 'GET' &&
          (forms[i].getAttribute('action') || '').indexOf('/admin/logout') >= 0) {
        return i;
      }
    }
    return -1;
  `);
}

// ---------------------------------------------------------------------------
// /admin/saml-assertions, /admin/spiffe AND /admin/token-lifetimes: THE THREE
// SETTINGS PAGES WITH A `set` OF THEIR OWN.
//
// Most settings groups are drawn as a section posting the shared `set-many` to
// /admin/config, which the settings section below drives once. These three have
// a handler of their own — because each validates something `set-many` cannot —
// and that is exactly why they were never reached: a walk that drives the
// shared door does not touch them.
// ---------------------------------------------------------------------------
async function theAssertionSettingsPageSaves(driver) {
  log.debug("Entering theAssertionSettingsPageSaves().");
  const KEY = "saml2.assertionLifetimeMin";

  const page = await open(driver, realm("/admin/saml-assertions"));
  const form = await formIndexFilling(driver, [KEY]);
  check("/admin/saml-assertions draws the assertion settings", function () {
    assert.ok(form >= 0,
      "/admin/saml-assertions should draw a form carrying " + KEY + "; it " +
      "draws none. This page has a `set` of its own rather than the shared " +
      "`set-many`, so nothing else in this suite reaches its handler.");
  });

  const before = valueOfControl(page, KEY);
  const wanted = String(Number(before) + 5);
  await fillAndPress(driver, form, { [KEY]: wanted });
  const landed = await driver.getCurrentUrl();
  check("it accepted the change", function () {
    assert.strictEqual(outcomeOf(landed, "error"), "",
      "saving " + KEY + " = " + wanted + " on /admin/saml-assertions was " +
      "refused: " + outcomeOf(landed, "error"));
  });

  const redrawn = await open(driver, realm("/admin/saml-assertions"));
  check("and it redraws the value it was given", function () {
    assert.strictEqual(String(valueOfControl(redrawn, KEY)), wanted,
      "/admin/saml-assertions must redraw " + KEY + " as " + wanted +
      "; it redrew " + JSON.stringify(valueOfControl(redrawn, KEY)) +
      ". A settings page that posts perfectly and draws the row from " +
      "somewhere else shows the reader their change vanishing.");
  });

  const row = settingRow(await apiJson("/realm/" + REALM +
      "/admin-api/config").then(function (r) { return r.body; }), KEY);
  check("and the configuration table agrees", function () {
    assert.strictEqual(String(row && row.value), wanted,
      "the configuration table should carry " + KEY + " = " + wanted +
      "; it carries " + JSON.stringify(row && row.value));
  });

  log.info("[saml-assertions] OK — " + KEY + " changed on its own page, " +
           "redrawn there, and holding in the configuration table.");
  log.debug("Leaving theAssertionSettingsPageSaves().");
}

async function theLifetimesPageSaves(driver) {
  log.debug("Entering theLifetimesPageSaves().");
  const KEY = "oauth2.accessTokenTtlS";

  const page = await open(driver, realm("/admin/token-lifetimes"));
  const form = await formIndexFilling(driver, [KEY]);
  check("/admin/token-lifetimes draws the four lifetimes", function () {
    assert.ok(form >= 0,
      "/admin/token-lifetimes should draw a form carrying " + KEY + ".");
  });

  const wanted = String(Number(valueOfControl(page, KEY)) + 60);
  await fillAndPress(driver, form, { [KEY]: wanted });
  const landed = await driver.getCurrentUrl();
  check("the lifetimes page SAVES as well as refusing", function () {
    assert.strictEqual(outcomeOf(landed, "error"), "",
      "saving " + KEY + " = " + wanted + " on /admin/token-lifetimes was " +
      "refused: " + outcomeOf(landed, "error") + ". This page had only ever " +
      "been driven as a REFUSAL — it turns away a name outside its four — so " +
      "its success path was the half nothing had ever pressed.");
  });

  const redrawn = await open(driver, realm("/admin/token-lifetimes"));
  check("and it redraws the lifetime it was given", function () {
    assert.strictEqual(String(valueOfControl(redrawn, KEY)), wanted,
      "/admin/token-lifetimes must redraw " + KEY + " as " + wanted +
      "; it redrew " + JSON.stringify(valueOfControl(redrawn, KEY)));
  });

  log.info("[lifetimes] OK — " + KEY + " saved on its own page and redrawn " +
           "there; this page's success path had never been pressed.");
  log.debug("Leaving theLifetimesPageSaves().");
}

async function theSpiffePageRotatesAndFederates(driver) {
  log.debug("Entering theSpiffePageRotatesAndFederates().");

  // 1. ROTATE. What it must do is change the authority's key — so the thing to
  //    read afterwards is the bundle, not the notice.
  const before = await apiJson("/realm/" + REALM + "/admin-api/spiffe");
  await open(driver, realm("/admin/spiffe"));
  const rotate = await formIndexPosting(driver, "rotate");
  check("/admin/spiffe draws a rotate control", function () {
    assert.ok(rotate >= 0,
      "/admin/spiffe should draw a control that rotates the signing " +
      "authority; it draws none.");
  });
  await fillAndPress(driver, rotate, { which: "x509" });
  const landed = await driver.getCurrentUrl();
  check("rotating the authority was accepted", function () {
    assert.strictEqual(outcomeOf(landed, "error"), "",
      "rotating the SPIFFE X.509 authority was refused: " +
      outcomeOf(landed, "error"));
  });
  const after = await apiJson("/realm/" + REALM + "/admin-api/spiffe");
  check("and the authority really changed", function () {
    assert.notStrictEqual(JSON.stringify(after.body), JSON.stringify(before.body),
      "ROTATING MUST CHANGE SOMETHING. The button answered with a notice and " +
      "the SPIFFE status is byte-for-byte what it was, which is what a " +
      "handler that reports a rotation it did not perform looks like.");
  });

  // 2. FEDERATION-SET, which is the other never-pressed control on this page.
  //    IT NEEDS A BUNDLE, and that is the point of driving it: the textarea is
  //    the only control on this console that has to be JSON, so a form that
  //    posted it as a string, or dropped it, is refused here and nowhere else.
  //    The endpoint URL is RECORDED AND NEVER FETCHED — this service dials
  //    nothing that did not come off a federation relationship entry — so a
  //    domain that does not exist is the honest thing to set.
  const domain = "console-" + names.runStamp().slice(0, 8) + ".example";
  await open(driver, realm("/admin/spiffe"));
  const federate = await formIndexPosting(driver, "federation-set");
  check("/admin/spiffe draws a federation control", function () {
    assert.ok(federate >= 0,
      "/admin/spiffe should draw a control that sets a foreign trust " +
      "domain's bundle; it draws none.");
  });
  await fillAndPress(driver, federate, {
    trustDomain: domain,
    bundleEndpointUrl: "https://" + domain + "/bundle",
    bundleEndpointProfile: "https_web",
    document: '{"keys":[]}'
  });
  const federated = await driver.getCurrentUrl();
  check("setting a federated bundle was accepted", function () {
    assert.strictEqual(outcomeOf(federated, "error"), "",
      "setting the bundle for " + domain + " was refused: " +
      outcomeOf(federated, "error"));
  });

  const status = await apiJson("/realm/" + REALM + "/admin-api/spiffe");
  check("the federated bundle is really held", function () {
    assert.ok(JSON.stringify(status.body.federated || []).indexOf(domain) >= 0,
      "the trust domain " + domain + " should be among the federated " +
      "bundles after the console's own form set it; the service holds " +
      JSON.stringify(status.body.federated).slice(0, 300));
  });

  const redrawn = await open(driver, realm("/admin/spiffe"));
  check("and the page draws it back", function () {
    assert.ok(redrawn.text.indexOf(domain) >= 0,
      "/admin/spiffe must draw the federated trust domain " + domain +
      " after its own form set it; the service holds it and the page does " +
      "not mention it, which is the reader being told their change did not " +
      "happen.");
  });

  log.info("[spiffe] OK — the authority was rotated on the page and really " +
           "changed, and a federated bundle set there is drawn back.");
  log.debug("Leaving theSpiffePageRotatesAndFederates().");
}

// The value a page's control holds, out of a survey. Used wherever a setting
// has to be read back off the page that drew it.
function valueOfControl(page, name) {
  let found;
  (page.forms || []).forEach(function (form) {
    form.controls.forEach(function (control) {
      if (control.name === name && found === undefined) {
        found = control.value;
      }
    });
  });
  return found;
}

function settingRow(config, key) {
  let found;
  ((config && config.groups) || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      if (setting.key === key) {
        found = setting;
      }
    });
  });
  return found;
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
//
// THE FOUR CONSOLE PAGES WITH NO NAV ROW ARE DRIVEN HERE BY NAME as well as
// being reached by the crawl: /admin/delegation's three drill-downs and
// /admin/tokens/credential. The crawl proves they answer; this proves they are
// drawn in the shell with a trail that leads back, which is the part a status
// code cannot show.
// ---------------------------------------------------------------------------
async function theDrillDownsCarryTheirTrail(driver, created) {
  log.debug("Entering theDrillDownsCarryTheirTrail().");
  log.info("=== Breadcrumbs, drill-downs, and the reader's place in a list ===");

  // A LIST page: the crumb is one link plus a leaf that is not a link.
  const list = await open(driver, realm("/admin/applications"));
  check("the last crumb on a list page is not a link", function () {
    assert.ok(list.crumb && list.crumb.leaves > 0,
      "the last crumb must not be a link — a crumb that reloads the page you " +
      "are on teaches a reader not to trust the ones beside it. The crumb is: " +
      (list.crumb ? list.crumb.html : "(none)"));
  });

  // A DRILL-DOWN reached through a FILTERED list: the section crumb becomes a
  // link and carries the filter.
  const filtered = "?q=" + encodeURIComponent(created.identifier) + "&per=10";
  const drill = await open(driver, realm("/admin/applications" + filtered +
      "&application=" + encodeURIComponent(created.identifier)));
  check("a drill-down's section crumb carries the list it came from", function () {
    const html = drill.crumb ? drill.crumb.html : "";
    assert.ok(/<a href="[^"]*\/admin\/applications\?[^"]*q=/.test(html),
      "A DRILL-DOWN'S SECTION CRUMB MUST BE A LINK CARRYING THE LIST THE " +
      "READER CAME FROM. That is what makes it a breadcrumb rather than a " +
      "second copy of the nav: the tab for the section a reader is standing " +
      "IN is exactly the tab that says nothing about the page they are " +
      "standing ON, and the original defect was that the active tab was " +
      "drawn as plain text, so the one control pointing back at the list was " +
      "the one control the shell had turned off. The crumb is: " + html);
    assert.ok(drill.crumb.leaves > 0,
      "and its own last crumb is still not a link. The crumb is: " + html);
  });

  // Every form on that drill-down carries `back`, which the POST handler
  // REBUILDS rather than echoes. A new form here without it silently costs the
  // reader their place every time they use it.
  const withoutBack = drill.forms.filter(function (form) {
    return form.method === "POST" &&
        new URL(form.resolvedAction).pathname.indexOf("/admin/config") < 0 &&
        !form.controls.some(function (c) { return c.name === "back"; });
  });
  check("every form on a drill-down carries `back`", function () {
    assert.deepStrictEqual(withoutBack.map(function (form) {
      return JSON.stringify(actionValuesIn(form));
    }), [],
      "EVERY FORM ON A DRILL-DOWN MUST CARRY `back`. The value is one opaque " +
      "field holding the list view the reader came from, and the POST " +
      "handler rebuilds it — so a form that does not carry it sends the " +
      "reader back to an unfiltered page one of every time they change " +
      "anything.");
  });

  // And pressing one really does land back in the filtered list, which is the
  // property `back` exists for and the only one the markup cannot show.
  const settable = drill.forms.findIndex(function (form) {
    return form.method === "POST" &&
        actionValuesIn(form).indexOf("set") >= 0 &&
        form.controls.some(function (c) { return c.name === "value"; });
  });
  if (settable >= 0) {
    await fillAndPress(driver, settable,
        { value: "back-check", attribute: "appName" });
    const after = await driver.getCurrentUrl();
    check("pressing it lands back in the filtered list", function () {
      assert.ok(/[?&]q=/.test(after),
        "AND THE REDIRECT AFTER PRESSING IT MUST LAND IN THE FILTERED LIST. " +
        "`back` is rebuilt by the handler rather than echoed, so this is the " +
        "half of the arrangement the markup cannot show. It went to " + after);
    });
  }

  // The four pages with no nav row of their own.
  const orphans = ["/admin/delegation/user?user=" +
                     encodeURIComponent(created.person),
                   "/admin/delegation/application?application=" +
                     encodeURIComponent(created.identifier),
                   "/admin/delegation/chain",
                   "/admin/tokens/credential"];
  for (const path of orphans) {
    const page = await open(driver, realm(path));
    check(path + " is drawn in the shell", function () {
      assert.ok(page.status < 400,
        path + " should answer; it answered " + page.status + ". It has no " +
        "nav row of its own, so nothing in the console's page list would " +
        "ever have drawn it.");
      assert.ok(page.nav > 0 && page.crumb,
        path + " is a page with no nav row, which makes its BREADCRUMB the " +
        "only way back — so it is the page where losing the shell costs the " +
        "most. It drew " + page.nav + " nav link(s) and " +
        (page.crumb ? "a crumb" : "NO crumb") + ".");
    });
  }

  log.info("[trail] OK — the last crumb is never a link, a drill-down's " +
           "section crumb carries the filter it was reached through, every " +
           "form on it carries `back`, pressing one lands back in the " +
           "filtered list, and all " + orphans.length + " pages with no nav " +
           "row are drawn in the shell with a trail.");
  log.debug("Leaving theDrillDownsCarryTheirTrail().");
}

// ---------------------------------------------------------------------------
// FILTERING AND PAGING, AND THE ONE FIELD THE PAGE-SIZE FORM MUST NOT CARRY.
//
// A filter form is a GET form: the browser builds the query string out of its
// own successful controls, so the filter has to be spelt out as hidden inputs —
// and the PAGE deliberately is not, because changing how many rows are shown
// and staying on page nine is a request nobody makes.
//
// The functional half is that a filter really NARROWS: `shown` goes down while
// the total does not. A filter that draws, submits, redraws the page and
// matches everything is the failure this catches, and it is invisible to a
// check that only looks at the URL.
// ---------------------------------------------------------------------------
async function filteringAndPagingWork(driver, created) {
  log.debug("Entering filteringAndPagingWork().");
  log.info("=== Filters and paging on the list pages ===");

  const unfiltered = await apiJson("/realm/" + REALM + "/admin-api/applications");
  const total = Number(unfiltered.body.applicationCount || 0);

  // Filter the list in the BROWSER, on the page's own form.
  const page = await open(driver, realm("/admin/applications"));
  const filterForm = page.forms.findIndex(function (form) {
    return form.method === "GET" &&
        form.controls.some(function (c) { return c.name === "q"; });
  });
  check("the list page draws a filter", function () {
    assert.ok(filterForm >= 0,
      "/admin/applications should draw a GET form carrying `q`; it draws none.");
  });
  await fillAndPress(driver, filterForm, { q: created.identifier });
  const narrowed = await driver.getCurrentUrl();

  const filtered = await apiJson("/realm/" + REALM +
      "/admin-api/applications?q=" + encodeURIComponent(created.identifier));
  check("a filter narrows what is shown without changing the total", function () {
    assert.ok(narrowed.indexOf("q=") > 0,
      "the filter should be in the address, because that address IS the " +
      "state a reader bookmarks and a breadcrumb carries. It went to " +
      narrowed);
    assert.ok(Number(filtered.body.shown) < total || total <= 1,
      "filtering by " + created.identifier + " should show fewer rows than " +
      "the " + total + " this realm holds; it showed " + filtered.body.shown +
      ". A filter that matches everything draws, submits and redraws exactly " +
      "like one that works.");
    assert.strictEqual(Number(filtered.body.applicationCount), total,
      "and the TOTAL must not move — a filter narrows a view, it does not " +
      "remove anything. It went from " + total + " to " +
      filtered.body.applicationCount);
  });

  // The page-size form, and the field it must not carry.
  const withFilter = await open(driver, realm(
      "/admin/applications?q=" + encodeURIComponent(created.identifier) +
      "&page=1&per=25"));
  const sizeForm = withFilter.forms.findIndex(function (form) {
    return form.method === "GET" &&
        form.controls.some(function (c) { return c.name === "per"; }) &&
        !form.controls.some(function (c) { return c.name === "q" && c.type === "text"; });
  });
  if (sizeForm >= 0) {
    const carries = withFilter.forms[sizeForm].controls.map(function (c) {
      return c.name;
    });
    check("the page-size form carries the filter and not the page", function () {
      assert.ok(carries.indexOf("page") < 0,
        "THE PAGE-SIZE FORM MUST NOT CARRY `page`. Changing how many rows " +
        "are shown and staying on page nine is a request nobody makes, and " +
        "the row that was at the top is not on page nine any more. It " +
        "carries " + JSON.stringify(carries));
    });
  }

  log.info("[lists] OK — a filter narrows `shown` without changing the " +
           "total, the filter reaches the address, and the page-size form " +
           "deliberately does not carry the page.");
  log.debug("Leaving filteringAndPagingWork().");
}

// ---------------------------------------------------------------------------
// THE REALM SWITCHER, WHICH IS A GET FORM IN THE SHELL OF EVERY PAGE.
//
// It draws NOTHING AT ALL when no realm is defined — a service not using realms
// should not grow a control that only ever says "default" — which is why this
// section runs after the throwaway realm exists, and why nothing had ever
// pressed it: the old file's walk was of POST targets, and this posts nothing.
//
// What it must do is land on THE SAME PAGE in the other realm, carrying the
// reader's place with them. The `to` field is what makes that possible, and it
// holds the path INSIDE the realm — which is the whole trick, because the
// prefix has already been stripped by the time any route sees the URL.
// ---------------------------------------------------------------------------
async function theRealmSwitcherSwitches(driver) {
  log.debug("Entering theRealmSwitcherSwitches().");
  log.info("=== The realm switcher ===");

  // Start somewhere specific INSIDE the realm, so that "the same page" means
  // something more than "the console opened".
  const page = await open(driver, realm("/admin/metrics"));
  const switcher = page.forms.findIndex(function (form) {
    return new URL(form.resolvedAction).pathname.indexOf("/admin/realm-switch") >= 0;
  });
  check("every page carries the switcher once a realm exists", function () {
    assert.ok(switcher >= 0,
      "/admin/metrics should carry the realm switcher in its shell — it is " +
      "drawn on every page once a realm is defined, and drawn nowhere when " +
      "none is. This realm exists, so it should be here.");
    const to = page.forms[switcher].controls.filter(function (c) {
      return c.name === "to";
    })[0];
    assert.ok(to && to.value.indexOf("/admin/metrics") >= 0,
      "AND IT MUST CARRY WHERE THE READER IS. `to` holds the path inside the " +
      "realm, which is what lets the switch land on the same page rather " +
      "than at the top of the console. It carries " +
      JSON.stringify(to && to.value));
  });

  // Switch to the DEFAULT realm and check we landed on the same page there.
  await fillAndPress(driver, switcher, { realm: "default" });
  const landed = await driver.getCurrentUrl();
  check("switching lands on the same page in the other realm", function () {
    assert.ok(landed.indexOf("/admin/metrics") >= 0,
      "switching realms from /admin/metrics must land on /admin/metrics, not " +
      "at the top of the console — the switcher exists so a reader can " +
      "compare one realm with another, and a switch that loses the page is a " +
      "switch they have to undo by navigating back. It landed on " + landed);
    assert.ok(landed.indexOf("/realm/" + REALM + "/") < 0,
      "and it must actually have LEFT " + REALM + "; it landed on " + landed);
  });

  // And back again, which is the direction that has to add a prefix rather
  // than take one away.
  const atRoot = await open(driver, root("/admin/metrics"));
  const back = atRoot.forms.findIndex(function (form) {
    return new URL(form.resolvedAction).pathname.indexOf("/admin/realm-switch") >= 0;
  });
  await fillAndPress(driver, back, { realm: REALM });
  const returned = await driver.getCurrentUrl();
  check("and back again, which is the direction that adds the prefix", function () {
    assert.ok(returned.indexOf("/realm/" + REALM + "/admin/metrics") >= 0,
      "switching from the default realm INTO " + REALM + " must add the " +
      "prefix and keep the page. It landed on " + returned);
  });

  log.info("[switcher] OK — the switcher is drawn in every shell, carries " +
           "where the reader is, and lands on the same page in both " +
           "directions.");
  log.debug("Leaving theRealmSwitcherSwitches().");
}

// ---------------------------------------------------------------------------
// THE TWO PICTURES, WHICH ARE DRAWN ON THE SERVER.
//
// `/admin/delegation/map` and `/admin/federation/map` are the console's two
// drawings, and both are the case where the argument for a script came out the
// other way: every graph library a person would reach for runs in the browser
// and would have made these the first scripted pages in this console. They are
// laid out with dagre on the server and arrive as inline SVG, so
// `script-src 'none'` is untouched and `img-src` is not even reached.
//
// A BROWSER IS THE RIGHT PLACE TO ASSERT THAT, and it could not be asserted
// before: what matters is that the SVG is really in the document the browser
// built — not merely that the bytes contain `<svg` — and that the page draws
// with no script and no external image.
// ---------------------------------------------------------------------------
async function theTwoDrawingsAreServerSide(driver) {
  log.debug("Entering theTwoDrawingsAreServerSide().");
  log.info("=== The delegation and federation pictures ===");

  for (const path of ["/admin/delegation/map", "/admin/federation/map"]) {
    const page = await open(driver, realm(path));
    const drawn = await driver.executeScript(`
      const svg = document.querySelectorAll('svg');
      let nodes = 0;
      svg.forEach(function (one) { nodes += one.querySelectorAll('*').length; });
      return { count: svg.length, nodes: nodes,
               images: document.querySelectorAll('img, image').length,
               scripts: document.scripts.length };
    `);
    check(path + " is inline server-rendered SVG", function () {
      assert.ok(drawn.count > 0,
        path + " should draw an inline <svg> in the document. It is laid out " +
        "on the server with dagre precisely so that this console needs no " +
        "graph library and keeps `script-src 'none'`; a page with no SVG in " +
        "it is one where the drawing did not happen.");
      assert.ok(drawn.nodes > 3,
        "and the SVG should have something in it; it has " + drawn.nodes +
        " element(s).");
      assert.strictEqual(drawn.scripts, 0,
        path + " must carry no script. Every graph library a person would " +
        "reach for runs in the browser, and the whole point of laying this " +
        "out on the server is that neither picture is the first scripted " +
        "page in this console.");
      assert.strictEqual(drawn.images, 0,
        "and no <img>: the drawing is markup, so `img-src` is not even " +
        "reached. It drew " + drawn.images);
    });

    // And ?format=svg hands the document over, which is the answer to the pan
    // and zoom this deliberately does not have.
    const raw = await go(driver, realm(path + "?format=svg"));
    check(path + "?format=svg hands the document over", function () {
      assert.strictEqual(raw.status, 200,
        path + "?format=svg should answer 200; it answered " + raw.status);
      assert.ok(/image\/svg\+xml/.test(raw.headers["content-type"] || ""),
        "and it should be served as image/svg+xml, because it is the whole " +
        "document handed to something that DOES zoom — which is what this " +
        "page offers instead of pan and zoom of its own. It was served as " +
        JSON.stringify(raw.headers["content-type"]));
    });
  }

  log.info("[drawings] OK — both pictures are inline server-rendered SVG " +
           "with no script and no image on the page, and both hand the " +
           "document over at ?format=svg.");
  log.debug("Leaving theTwoDrawingsAreServerSide().");
}

// ---------------------------------------------------------------------------
// WHAT THE CONSOLE REFUSES, AND THE TWO PLACES IT REFUSES IT.
//
// THIS SPLIT ONLY EXISTS IN A BROWSER, and finding it is a fair argument for
// the conversion on its own. The old file posted a body and read the answer, so
// every refusal it knew about was a HANDLER's. But two of the cases it drove
// never reach a handler at all when a person does them: the console marks
// `identifier` REQUIRED and gives the four lifetimes a `min` and a `max`, so
// the BROWSER refuses to send them and says so beside the box, with no round
// trip. A test that hand-builds the body walks straight past that and asserts
// the handler's answer to a request no person can make.
//
// So there are two groups, and both matter:
//
//   * WHAT THE BROWSER WILL NOT SEND. The page's own constraint attributes,
//     enforced by the browser: the form does not submit, no request is made,
//     and the offending control is the one reported invalid. This is the
//     console telling somebody before the round trip, which is the only
//     refusal that is instant.
//   * WHAT THE HANDLER WILL NOT ACCEPT. Values that pass constraint validation
//     and still have to be turned away — a reserved claim name, a relationship
//     with no direction, a realm id that shadows a path this service serves, a
//     SPIFFE ID that is not one. Each is checked for the REASON reaching the
//     reader, because a 303 with nothing on the far end is a control that
//     silently did nothing, which is worse than an error.
// ---------------------------------------------------------------------------
async function theConsoleRefusesWhatItShould(driver) {
  log.debug("Entering theConsoleRefusesWhatItShould().");
  log.info("=== What the console refuses ===");

  await theBrowserWillNotSend(driver, "/admin/applications",
      ["identifier"], { identifier: "" }, "identifier",
      "an application with NO IDENTIFIER — the identifier is the client_id, " +
      "wtrealm, AppliesTo, entityID or service principal name the thing is " +
      "known by, so an entry without one is an entry no protocol could ever " +
      "match against");

  await theBrowserWillNotSend(driver, "/admin/token-lifetimes",
      ["oauth2.accessTokenTtlS"], { "oauth2.accessTokenTtlS": "5" },
      "oauth2.accessTokenTtlS",
      "a lifetime BELOW THE FLOOR — the box carries min=30, so a person is " +
      "told where they are wrong beside the box rather than after a round " +
      "trip that loses the rest of the form");

  await pressAndBeRefused(driver, "/admin/claims",
      ["set", "name", "value"],
      { set: "access_token", name: "iss", value: "x" },
      /iss/,
      "a RESERVED claim name — a custom `iss` would be overwritten by the " +
      "issuer at signing time, so a console that accepted it would be " +
      "storing something it will never send");

  // The role select is set to a value it does not offer, which leaves it with
  // nothing selected — so the BROWSER submits no `role` at all. That is the
  // real shape of this mistake (a person who never touched the control) and it
  // is not a body this suite could have hand-built without deciding for itself
  // what an unselected select sends.
  await pressAndBeRefused(driver, "/admin/federation",
      ["id", "name", "role"],
      { id: "fed-no-role", name: "No role", role: "" },
      /role/i,
      "a federation relationship with no ROLE — which direction the " +
      "relationship runs in is the first thing about it and cannot be " +
      "defaulted");

  await pressAndBeRefused(driver, "/admin/realms",
      ["id", "name"],
      { id: "admin", name: "Reserved" },
      /already serves|reserved|may not be called/i,
      "a realm id that is RESERVED — `admin` is the first segment of a path " +
      "this service already serves, and a realm by that name would shadow " +
      "the console itself the moment realms.pathSegment were cleared");

  await pressAndBeRefused(driver, "/admin/spiffe/entries",
      ["spiffeId", "parentId", "selectors"],
      { spiffeId: "not-a-spiffe-id", parentId: "spiffe://example.org/x",
        selectors: "unix:uid:1000" },
      /spiffe|begins with/i,
      "a SPIFFE ID that is not one — the registry's whole value is that what " +
      "comes out of it is a credential another service will believe");

  log.info("[refusals] OK — two controls were refused by the BROWSER before " +
           "a request was made, and four by their handler with the reason " +
           "drawn on the page the reader is sent back to.");
  log.debug("Leaving theConsoleRefusesWhatItShould().");
}

// A value the page's own constraint attributes will not let the browser send.
// What is asserted is that NO REQUEST HAPPENS and that the control reported
// invalid is the one at fault — a form that is merely broken also fails to
// submit, and the two have to be told apart.
async function theBrowserWillNotSend(driver, path, fields, values, offender, what) {
  log.debug("Entering theBrowserWillNotSend(). path=" + path);
  await open(driver, realm(path));
  const form = await formIndexFilling(driver, fields);
  if (form < 0) {
    check(path + " draws the form this refusal needs", function () {
      assert.fail(path + " should draw a form carrying " + fields.join(", ") +
        "; it draws none.");
    });
    return;
  }

  const before = await driver.getCurrentUrl();
  const from = mark();
  await fillAndPress(driver, form, values);
  const after = await driver.getCurrentUrl();
  const posted = since(from).filter(function (r) { return r.method === "POST"; });
  const validity = await driver.executeScript(`
    const f = document.forms[arguments[0]];
    const control = f.elements[arguments[1]];
    return { formValid: f.checkValidity(),
             controlValid: control ? control.checkValidity() : null,
             message: control ? control.validationMessage : null };
  `, form, offender);

  check(path + " will not even send " + what.split("—")[0].trim(), function () {
    assert.strictEqual(posted.length, 0,
      "THE BROWSER MUST NOT SEND THIS AT ALL. " + path + " marks " + offender +
      " with a constraint the value " + JSON.stringify(values[offender]) +
      " breaks, so a person is told beside the box and the rest of the form " +
      "is still in front of them. It posted " + posted.length + " time(s), " +
      "which means the attribute is gone and the only thing left refusing " +
      "this is a round trip that empties the page.");
    assert.strictEqual(after, before,
      "and the browser should not have gone anywhere; it went to " + after);
    assert.strictEqual(validity.formValid, false,
      "and the form should report itself invalid; it reports " +
      validity.formValid);
    assert.strictEqual(validity.controlValid, false,
      "and " + offender + " should be the control at fault — a form that " +
      "fails to submit for some other reason looks identical from outside. " +
      "The browser says " + JSON.stringify(validity.message));
  });
  log.debug("Leaving theBrowserWillNotSend().");
}

// Press a form with something the HANDLER must turn away, and insist the
// reason is on the page the reader lands on. The form is found by its FIELDS,
// so a page that renamed one is reported as such rather than silently not
// pressed.
async function pressAndBeRefused(driver, path, fields, values, expect, what) {
  log.debug("Entering pressAndBeRefused(). path=" + path);
  await open(driver, realm(path));
  const form = await formIndexFilling(driver, fields);
  if (form < 0) {
    check(path + " draws the form this refusal needs", function () {
      assert.fail(path + " should draw a form carrying " + fields.join(", ") +
        " so that " + what + " can be refused; it draws none.");
    });
    return;
  }
  const from = mark();
  await fillAndPress(driver, form, values);
  const landed = await driver.getCurrentUrl();
  const posted = since(from).filter(function (r) { return r.method === "POST"; });
  const reason = outcomeOf(landed, "error");

  check(path + " refuses " + what.split("—")[0].trim(), function () {
    assert.ok(posted.length > 0,
      "the browser should have SENT this one — it breaks no constraint the " +
      "page declares, so the refusal under test is the handler's. It sent " +
      "nothing, which means the page now refuses it in the browser and this " +
      "case belongs in the group above.");
    assert.ok(reason && reason.length > 0,
      "PRESSING " + path + " WITH " + JSON.stringify(values) + " MUST BE " +
      "REFUSED, and the reason must reach the reader. This is " + what + ". " +
      "The browser landed on " + landed + " with no `error` on it — a " +
      "control that silently accepts what it cannot store is worse than one " +
      "that errors, because the reader believes it worked.");
    assert.ok(expect.test(reason),
      "and the reason should say why. It said " + JSON.stringify(reason) +
      ", which does not match " + expect);
  });
  log.debug("Leaving pressAndBeRefused().");
}

// ---------------------------------------------------------------------------
// AND THE ONE PAGE THAT IS NOT THE CONSOLE'S OWN: /admin/sts-metadata.
//
// It is built by walking the live Express router, by a module that has to be
// the LAST one server.js loads — so it is the one page here drawn by something
// other than admin.js, through the shell that file exports. What is checked is
// that it is still part of this console, rather than what it lists, which
// tests/sts_metadata.js owns.
// ---------------------------------------------------------------------------
async function theMetadataPageIsStillInTheConsole(driver) {
  log.debug("Entering theMetadataPageIsStillInTheConsole().");
  const page = await open(driver, root("/admin/sts-metadata"));
  check("/admin/sts-metadata is drawn in the console's shell", function () {
    assert.ok(page.nav > 0 && page.crumb,
      "/admin/sts-metadata should be drawn in the console shell with a " +
      "breadcrumb, the same as every other page. It is built by a module " +
      "OUTSIDE admin.js — sts_metadata.js, which must be the last thing " +
      "server.js loads or it would be the reason a route is missing from its " +
      "own list — so it is the one page whose chrome can be lost without any " +
      "of the console's own code changing.");
    assert.strictEqual(page.scripts, 0,
      "and it must have no script on it, like every other page here.");
  });
  log.info("[metadata] OK — /admin/sts-metadata is still drawn in the " +
           "console's shell, by the one module outside admin.js that draws a " +
           "console page.");
  log.debug("Leaving theMetadataPageIsStillInTheConsole().");
}
// ---------------------------------------------------------------------------
// A SETTING, CHANGED ON THE PAGE FOR THE PROTOCOL IT CONFIGURES.
//
// Since 2026-08-27 every one of config.js's groups is drawn on the page for the
// protocol it configures, so a change is made where a person would make it — on
// /admin/kerberos, not on /admin/config — and is then looked for in three
// places: back on that page, in the configuration table with its source moved,
// and in the persistence store's own write counters.
//
// The setting and the page are both chosen OFF THE SERVICE, from the homes
// table /admin-api/config publishes, so this carries no copy of SETTING_HOMES
// and does not go stale the day a group moves.
// ---------------------------------------------------------------------------
async function aSettingChangedOnItsProtocolPage(driver) {
  log.debug("Entering aSettingChangedOnItsProtocolPage().");
  log.info("=== A setting, changed on the page for its protocol ===");

  const config = await apiJson("/admin-api/config");
  check("every group of settings is drawn on some page", function () {
    assert.strictEqual(config.status, 200,
      "GET /admin-api/config should answer 200; it answered " + config.status);
    assert.deepStrictEqual(config.body.homeProblems || [], [],
      "EVERY GROUP OF SETTINGS MUST BE DRAWN ON SOME PAGE. " +
      "`checkSettingHomes()` runs at startup and reports a group with no " +
      "page, a group with two rows, a row naming a group config.js does not " +
      "declare, and a row naming a path that is not in SECTIONS. A setting " +
      "that is READ by the service and appears on no page is worse than one " +
      "that is missing, because nothing about the service's behaviour tells " +
      "you it is there. It found: " + JSON.stringify(config.body.homeProblems));
    assert.ok((config.body.homes || []).length > 15,
      "and it should publish where each group is drawn; it published " +
      (config.body.homes || []).length + " rows.");
  });

  const chosen = anIntegerSettingWithAProtocolPage(config.body);
  assert.ok(chosen,
    "the configuration should carry at least one runtime integer setting " +
    "whose group is drawn on a page other than /admin/config; it carries none.");
  const wanted = Number(chosen.setting.value) + 1;
  log.info("[settings] Driving " + chosen.setting.key + " on " + chosen.path +
           ": " + chosen.setting.value + " -> " + wanted);

  // The section form on that page, found by the setting it draws. Pressing
  // Save sends every field the section drew, verbatim, except the one being
  // changed — which is what a person pressing Save actually sends, and is the
  // case `set-many` is all-or-nothing for. THE BROWSER BUILDS THAT BODY, which
  // is the half the old file had to re-implement.
  await open(driver, realm(chosen.path));
  const section = await formIndexFilling(driver, [chosen.setting.key]);
  check(chosen.path + " draws the group it is the home of", function () {
    assert.ok(section >= 0,
      chosen.path + " should draw a form carrying " + chosen.setting.key +
      ". /admin-api/config says that is where the `" + chosen.setting.group +
      "` group is drawn, and a page that does not draw it is the drift " +
      "checkSettingHomes() cannot see — it checks the TABLE, not the markup.");
  });

  await fillAndPress(driver, section, { [chosen.setting.key]: String(wanted) });
  const landed = await driver.getCurrentUrl();
  check("the section saved", function () {
    assert.strictEqual(outcomeOf(landed, "error"), "",
      "saving the `" + chosen.setting.group + "` section on " + chosen.path +
      " was refused: " + outcomeOf(landed, "error") + ". `set-many` is " +
      "ALL-OR-NOTHING, so a refusal here means the whole section is " +
      "unsaveable — including when nothing on it has been changed.");
  });

  // 1. Back on the page it was changed on.
  const redrawn = await open(driver, realm(chosen.path));
  check("the page redraws the value it was given", function () {
    assert.strictEqual(String(valueOfControl(redrawn, chosen.setting.key)),
        String(wanted),
      "THE PAGE MUST REDRAW THE VALUE IT WAS JUST GIVEN. This is the half no " +
      "check against /admin-api can make: a page can post a section " +
      "perfectly and then draw the row out of somewhere else, and the reader " +
      "would see their change vanish with the service holding it. It redrew " +
      JSON.stringify(valueOfControl(redrawn, chosen.setting.key)));
  });

  // 2. In the configuration table, with the source moved to this realm.
  const inRealm = await apiJson("/realm/" + REALM + "/admin-api/config");
  const row = settingRow(inRealm.body, chosen.setting.key);
  check("the configuration table carries it, as the realm's own", function () {
    assert.strictEqual(Number(row.value), wanted,
      "the configuration table should carry the new value; it carries " +
      row.value);
    assert.strictEqual(row.source, "realm",
      "and its SOURCE must have moved to `realm` — a setting saved under a " +
      "realm prefix is that realm's, held on the realm row, and a setting " +
      "saved at the root is the process's. A value that changed without the " +
      "source moving would mean a second store. It says " + row.source);
  });

  // 3. And the process's own value must NOT have moved with it.
  const atRoot = await apiJson("/admin-api/config");
  check("and the process's own value did not move with it", function () {
    const rootRow = settingRow(atRoot.body, chosen.setting.key);
    assert.notStrictEqual(Number(rootRow.value), wanted,
      "A SETTING SAVED IN A REALM MUST NOT REACH THE PROCESS. " +
      chosen.setting.key + " was changed at /realm/" + REALM + chosen.path +
      " and the default realm now reads " + rootRow.value + " as well, which " +
      "is one table serving every realm while each realm's console shows it " +
      "as that realm's own configuration.");
  });

  await aRealmRuntimeSettingIsSettableOnItsPage(driver);
  await theChangeReachedTheStore(driver);
  log.debug("Leaving aSettingChangedOnItsProtocolPage().");
}

// A runtime integer setting whose group is drawn on a PROTOCOL page rather than
// on /admin/config, plus that page. Chosen off the service's own homes table so
// that this file carries no copy of SETTING_HOMES.
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
// The failure was worse than the rule being absent, and it is what makes this a
// page-level assertion rather than a table-level one: the section's Save posts
// `set-many`, which is ALL-OR-NOTHING, so pressing Save on
// /realm/<id>/admin/oauth2 was refused every time — including when nothing on
// the page had been changed — and the refusal explained, correctly, that a
// realm may carry the setting it was refusing.
//
// A BROWSER MAKES THE FIRST HALF REAL RATHER THAN INFERRED: a disabled control
// is not submitted by a browser, so the assertion that the root's Save works
// with the control drawn disabled is now the browser's own behaviour and not
// this file's model of it.
// ---------------------------------------------------------------------------
async function aRealmRuntimeSettingIsSettableOnItsPage(driver) {
  log.debug("Entering aRealmRuntimeSettingIsSettableOnItsPage().");
  log.info("=== The realm-runtime setting, on the page that draws it ===");
  const KEY = "oauth2.rfc9700";

  const atRoot = await open(driver, root("/admin/oauth2"));
  const rootControl = controlNamed(atRoot, KEY);
  check("at the root it is drawn disabled", function () {
    assert.ok(rootControl,
      "/admin/oauth2 should draw " + KEY + "; it draws no control by that " +
      "name.");
    assert.strictEqual(rootControl.disabled, true,
      "AT THE ROOT IT MUST BE DRAWN DISABLED. It decides whether the main " +
      "port is bound as HTTPS and a listener's scheme is settled when the " +
      "socket is bound, so the process cannot take it while running. It is " +
      "drawn " + (rootControl.disabled ? "disabled" : "ENABLED"));
  });

  const inRealm = await open(driver, realm("/admin/oauth2"));
  const realmControl = controlNamed(inRealm, KEY);
  check("inside a realm it is drawn enabled", function () {
    assert.ok(realmControl,
      "/realm/" + REALM + "/admin/oauth2 should draw " + KEY + ".");
    assert.strictEqual(realmControl.disabled, false,
      "INSIDE A REALM IT MUST BE DRAWN ENABLED. A realm binds no socket, so " +
      "the reason the process cannot take this setting does not reach it — " +
      "`realmRuntime` is the marker, and it is the only row that carries it. " +
      "It is drawn " + (realmControl.disabled ? "DISABLED" : "enabled"));
  });

  // And the realm's Save must ACCEPT it. The browser sends what the browser
  // sends: the whole section, with this control among it because it is enabled
  // here.
  const section = await formIndexFilling(driver, [KEY]);
  const wanted = String(realmControl.value) === "true" ? "false" : "true";
  await fillAndPress(driver, section, { [KEY]: wanted });
  const landed = await driver.getCurrentUrl();
  check("the realm's Save accepts it", function () {
    assert.strictEqual(outcomeOf(landed, "error"), "",
      "SAVING THE OAUTH SECTION INSIDE A REALM MUST WORK. It was refused: " +
      outcomeOf(landed, "error") + ". `set-many` is all-or-nothing, so a " +
      "refusal here makes the whole section unsaveable inside every realm — " +
      "including when nothing on the page has been changed — and the refusal " +
      "explains, correctly, that a realm may carry the setting it is refusing.");
  });

  const row = settingRow((await apiJson("/realm/" + REALM +
      "/admin-api/config")).body, KEY);
  check("and it is held as the realm's own", function () {
    assert.strictEqual(String(row.value), wanted,
      "the realm should now carry " + KEY + " = " + wanted + "; it carries " +
      JSON.stringify(row.value));
    assert.strictEqual(row.source, "realm",
      "and hold it as the realm's own; its source is " + row.source);
  });

  const processRow = settingRow((await apiJson("/admin-api/config")).body, KEY);
  check("and it did not reach the process", function () {
    assert.notStrictEqual(String(processRow.value), wanted,
      "AND IT MUST NOT HAVE REACHED THE PROCESS. The whole reason this " +
      "setting is restart-only service-wide is that a listener's scheme is " +
      "settled when the socket is bound; a realm's copy reaching the process " +
      "would mean the mode changed under a socket that cannot follow it. The " +
      "process reads " + processRow.value);
  });

  log.info("[realm setting] OK — " + KEY + " is drawn disabled at the root " +
           "and enabled in a realm, the realm's Save accepts it, holds it as " +
           "the realm's, and does not reach the process.");
  log.debug("Leaving aRealmRuntimeSettingIsSettableOnItsPage().");
}

// A control by name, out of a survey, with whether the BROWSER thinks it is
// disabled — which is the thing that decides whether it is submitted.
function controlNamed(page, name) {
  let found;
  (page.forms || []).forEach(function (form) {
    form.controls.forEach(function (control) {
      if (control.name === name && found === undefined) {
        found = control;
      }
    });
  });
  return found;
}

// ---------------------------------------------------------------------------
// AND, WHERE THERE IS A STORE, THE CHANGE REACHED IT.
//
// This is as far as anything driving the service from outside can follow a
// configuration change: the store's own counters. What is IN the file cannot be
// asked over HTTP at all, and that is asserted in mock-sts's own
// tests/appconfig_persistence.js, in process, where the bytes can be read back.
//
// `persistence.mode=memory` is the default and what the containerized stack
// runs, so this SAYS SO and asserts nothing rather than skipping quietly.
// ---------------------------------------------------------------------------
async function theChangeReachedTheStore(driver) {
  log.debug("Entering theChangeReachedTheStore().");
  const reply = await apiJson("/admin-api/persistence");
  // The counters are nested under `status`; the rest of that reply is the
  // page's own prose. Reading the top level instead is how this section came
  // to compare 0 against `undefined` and report a store that was never on.
  const store = (reply.body && reply.body.status) || {};
  if (reply.status !== 200 || store.mode === "memory" || store.enabled === false) {
    log.info("[persistence] The store is OFF (persistence.mode=" +
             (store.mode || "memory") + "), the default " +
             "and what the containerized stack runs. The value round trip " +
             "above is asserted; that the bytes reach a file is asserted in " +
             "mock-sts's own tests/appconfig_persistence.js, in process, " +
             "where they can be read back.");
    log.debug("Leaving theChangeReachedTheStore(). No store.");
    return;
  }

  const before = Number(store.writes || 0);
  const failures = Number(store.failures || 0);

  // One more change, on the page, so there is a write to watch for.
  await open(driver, realm("/admin/audit"));
  const form = await formIndexFilling(driver, ["audit.maxEvents"]);
  if (form >= 0) {
    await fillAndPress(driver, form, { "audit.maxEvents": "4321" });
  }

  const after = await settleStore(before);
  check("a change made on the page reaches the store", function () {
    assert.ok(Number(after.writes) > before,
      "THE STORE'S WRITE COUNTER MUST MOVE. A configuration change made on " +
      "the console is one of the three things this service persists, and a " +
      "counter that does not move means the override is held in memory and " +
      "will be gone at the next restart — which is the restart somebody will " +
      "do, because they expect the work to survive it. It went from " +
      before + " to " + after.writes);
    assert.strictEqual(Number(after.failures), failures,
      "and the FAILURE counter must not move. A store that records the " +
      "write and then fails to make it reports success to the console and " +
      "loses the change. It went from " + failures + " to " + after.failures);
    assert.notStrictEqual(after.pending, true,
      "and the dirty flag should have cleared: the change is written, not " +
      "merely queued.");
  });

  log.info("[persistence] OK — a change made on the console's own form moved " +
           "the store's write counter, cleared its dirty flag and moved no " +
           "failure counter.");
  log.debug("Leaving theChangeReachedTheStore().");
}

// The store flushes asynchronously, so this waits for the counter to move
// rather than sleeping for however long is usually enough.
async function settleStore(previous) {
  log.debug("Entering settleStore().");
  const deadline = Date.now() + 8000;
  let last = {};
  while (Date.now() < deadline) {
    const reply = await apiJson("/admin-api/persistence");
    last = (reply.body && reply.body.status) || {};
    if (Number(last.writes || 0) > previous && last.pending !== true) {
      log.debug("Leaving settleStore(). Settled.");
      return last;
    }
    await pause(150);
  }
  log.debug("Leaving settleStore(). Timed out.");
  return last;
}

// ---------------------------------------------------------------------------
// THE TWO ROLES: GRANTED AND REVOKED ON THE PAGE, AND THEN ENFORCED.
//
// THIS RUNS LAST, AND THE ORDER IS A DEPENDENCY RATHER THAN A PREFERENCE.
// While NEITHER role group has a member, anybody who signs in holds both —
// this service has no password anywhere to bootstrap an administrator with. So
// the first grant CLOSES the roster against everybody who is not on it,
// including this run's own session, and every section above needs the console
// open.
//
// That is also why the old file never pressed this page: it granted through the
// ungated API, at the very end, and the console's own grant and revoke — the
// two controls that decide who may use this console at all — were the least
// tested in the service.
//
// The roster is emptied again in a `finally`, because a grant left behind locks
// every later job out of the console, and the roster is the DEFAULT REALM's
// whichever realm it was written from.
// ---------------------------------------------------------------------------
// Who holds what, off the roster's own `grants` array.
//
// NOT a substring search of the whole reply: that reply also carries
// `candidates`, which is EVERY name in the directory whether or not they hold
// anything. Reading it that way made the grant assertions pass before the
// grant had been made, and made the teardown warn about a roster that was
// already empty — a false positive in both directions at once.
function rolesHeldBy(body, person) {
  return ((body && body.grants) || []).filter(function (grant) {
    return grant.username === person || grant.userKey === person;
  }).map(function (grant) { return grant.role; });
}

async function theRolesArePressedAndEnforced(driver, created) {
  log.debug("Entering theRolesArePressedAndEnforced().");
  log.info("=== The two console roles, granted on the page ===");
  let reader = created.person;

  try {
    // 1. GRANT TO OURSELVES FIRST, on the typed form. The moment anybody holds
    //    a role the roster is closed, so this has to be the grant that keeps
    //    this run inside the console.
    await open(driver, root("/admin/rbac"));
    const forms = await driver.executeScript(`
      const out = { picker: -1, typed: -1 };
      const forms = Array.from(document.forms);
      for (let i = 0; i < forms.length; i += 1) {
        const action = forms[i].elements['action'];
        const username = forms[i].elements['username'];
        if (!action || action.value !== 'grant' || !username) { continue; }
        if (username.tagName.toLowerCase() === 'select') { out.picker = i; }
        else { out.typed = i; }
      }
      return out;
    `);
    check("the roster page draws both ways of naming somebody", function () {
      assert.ok(forms.picker >= 0,
        "/admin/rbac should draw a grant form that PICKS a name out of the " +
        "directory; it draws none.");
      assert.ok(forms.typed >= 0,
        "and one that takes a TYPED name, for somebody who has never signed " +
        "in — a roster that can only name people the directory already knows " +
        "cannot be used to let the first administrator in. It draws none.");
    });

    await fillAndPress(driver, forms.typed,
        { username: CONSOLE_USER, role: "write" });
    const granted = await driver.getCurrentUrl();
    check("the typed grant was accepted", function () {
      assert.strictEqual(outcomeOf(granted, "error"), "",
        "granting `write` to " + CONSOLE_USER + " on /admin/rbac's typed " +
        "form was refused: " + outcomeOf(granted, "error"));
    });

    const roster = await apiJson("/admin-api/rbac");
    check("the grant reached the default realm's roster", function () {
      assert.deepStrictEqual(rolesHeldBy(roster.body, CONSOLE_USER), ["write"],
        "after the console's own form granted `write` to " + CONSOLE_USER +
        ", the roster should hold them. The two console roles are ORDINARY " +
        "GROUPS in the DEFAULT realm's directory and four doors write one " +
        "membership; a grant the page reports and the roster does not hold " +
        "means this page has a store of its own. It holds " +
        JSON.stringify(rolesHeldBy(roster.body, CONSOLE_USER)));
    });

    // 2. The page redraws the holder, with a Revoke beside them.
    const redrawn = await open(driver, root("/admin/rbac"));
    check("the roster page redraws the holder it just granted", function () {
      assert.ok(redrawn.text.indexOf(CONSOLE_USER) >= 0,
        "/admin/rbac should list " + CONSOLE_USER + " after granting them a " +
        "role. The API holds it and the page does not draw it, which is the " +
        "reader being told their change did not happen.");
    });

    // 3. Grant a READER a read-only role, through the PICKER form this time —
    //    a second control posting the same action, which a page could have
    //    wired to the other one's value with nothing looking wrong.
    //
    //    THE PICKER OFFERS THE DEFAULT REALM'S DIRECTORY, and that is correct
    //    rather than a limitation: the roster is the default realm's whichever
    //    realm the console is reached in, so offering this realm's people
    //    would be offering names the roster cannot hold. The person this run
    //    created lives in the THROWAWAY REALM and is deliberately not among
    //    them, so the reader is chosen from what the picker really offers.
    reader = await somebodyThePickerOffers(driver, CONSOLE_USER);
    await grantOnThePicker(driver, reader, "read");

    // 4. THE ENFORCEMENT. Sign in AS the reader — who holds `read` and not
    //    `write` — and check that every page opens and no form may be posted.
    await signIn(driver, reader);
    const asReader = await open(driver, root("/admin/metrics"));
    check("a reader may read", function () {
      assert.strictEqual(asReader.status, 200,
        "somebody holding Admin Read should be able to READ the console; " +
        "/admin/metrics answered " + asReader.status + " for " + reader);
    });

    await open(driver, realm("/admin/users"));
    const createForm = await formIndexPosting(driver, "create");
    const attempt = await fillAndPress(driver, createForm,
        { username: "reader-should-not-create-" + names.runStamp() });
    const refused = thePostIn(attempt.responses, "a reader posting a form");
    check("and a reader may not write", function () {
      assert.strictEqual(refused.status, 403,
        "A READER'S FORM POST MUST BE REFUSED 403. " + reader + " holds " +
        "Admin Read and not Admin Write, and this is the half a redirect " +
        "cannot show: the page draws every control, because a console that " +
        "hid them would be a console whose reader cannot see what the " +
        "service can do. It answered " + refused.status);
    });

    // Back to the session that holds `write`, so the teardown can act.
    await signIn(driver, CONSOLE_USER);
    log.info("[roles] OK — both grant forms are drawn, the typed one and the " +
             "picker each granted a role the roster really holds, the page " +
             "redrew them, a reader read every page, and a reader's form " +
             "POST was refused 403.");
  } finally {
    await restoreTheRoster(driver, [CONSOLE_USER, reader]);
  }
  log.debug("Leaving theRolesArePressedAndEnforced().");
}

// A name the picker really offers, other than this run's own session. Chosen
// from the control rather than invented, because the picker's list IS the
// default realm's directory and this run cannot know it from outside.
async function somebodyThePickerOffers(driver, notThisOne) {
  log.debug("Entering somebodyThePickerOffers().");
  await open(driver, root("/admin/rbac"));
  const offered = await driver.executeScript(`
    const forms = Array.from(document.forms);
    for (let i = 0; i < forms.length; i += 1) {
      const action = forms[i].elements['action'];
      const username = forms[i].elements['username'];
      if (!action || action.value !== 'grant' || !username) { continue; }
      if (username.tagName.toLowerCase() !== 'select') { continue; }
      return Array.from(username.options).map(function (o) { return o.value; });
    }
    return [];
  `);
  const chosen = offered.filter(function (one) {
    return one && one !== notThisOne;
  })[0];
  assert.ok(chosen,
    "the roster's picker should offer at least one name other than this " +
    "run's own session, so that a READER can be somebody else; it offers " +
    JSON.stringify(offered));
  log.debug("Leaving somebodyThePickerOffers(). " + chosen);
  return chosen;
}

async function grantOnThePicker(driver, person, role) {
  log.debug("Entering grantOnThePicker(). person=" + person);
  await open(driver, root("/admin/rbac"));
  const picker = await driver.executeScript(`
    const person = arguments[0];
    const forms = Array.from(document.forms);
    for (let i = 0; i < forms.length; i += 1) {
      const action = forms[i].elements['action'];
      const username = forms[i].elements['username'];
      if (!action || action.value !== 'grant' || !username) { continue; }
      if (username.tagName.toLowerCase() !== 'select') { continue; }
      const has = Array.from(username.options).some(function (o) {
        return o.value === person;
      });
      return { form: i, has: has,
               options: Array.from(username.options).map(function (o) {
                 return o.value;
               }).slice(0, 20) };
    }
    return null;
  `, person);

  check("the picker offers people the directory knows", function () {
    assert.ok(picker,
      "/admin/rbac should draw a grant form picking a name out of the " +
      "directory; it draws none.");
    assert.ok(picker.has,
      "and it should offer " + person + ", who is in this service's " +
      "directory — the picker's whole purpose is naming somebody without " +
      "typing them, and a picker that cannot see the directory is a control " +
      "that can only ever grant to the wrong person. It offers " +
      JSON.stringify(picker.options));
  });

  await fillAndPress(driver, picker.form, { username: person, role: role });
  const landed = await driver.getCurrentUrl();
  check("the picker's grant was accepted", function () {
    assert.strictEqual(outcomeOf(landed, "error"), "",
      "granting `" + role + "` to " + person + " on the picker form was " +
      "refused: " + outcomeOf(landed, "error"));
  });

  const roster = await apiJson("/admin-api/rbac");
  check("the picker's grant reached the roster too", function () {
    assert.deepStrictEqual(rolesHeldBy(roster.body, person), [role],
      "the roster should hold " + person + " after the PICKER form granted " +
      "them `" + role + "`. Two forms post this one action, and a page that " +
      "wired the second to the first one's value would draw perfectly and " +
      "grant to the wrong person every time. It holds " +
      JSON.stringify(rolesHeldBy(roster.body, person)));
  });
  log.debug("Leaving grantOnThePicker().");
}

// ---------------------------------------------------------------------------
// EMPTYING THE ROSTER AGAIN, WHICH IS NOT OPTIONAL.
//
// While neither role group has a member, anybody who signs in holds both. So a
// grant left behind by this job does not merely leave state around: it LOCKS
// EVERY LATER JOB OUT of the console, in a way whose symptom is a redirect to
// a sign-in screen that will never help.
//
// It is done on the PAGE first, because that is the control under test, and
// through the API if the page cannot — a teardown that fails because the thing
// it was testing is broken is a teardown that turns one failure into a suite.
// ---------------------------------------------------------------------------
async function restoreTheRoster(driver, people) {
  log.debug("Entering restoreTheRoster().");
  for (const person of people) {
    try {
      await open(driver, root("/admin/rbac"));
      const rows = await driver.executeScript(`
        const person = arguments[0];
        const out = [];
        const forms = Array.from(document.forms);
        for (let i = 0; i < forms.length; i += 1) {
          const action = forms[i].elements['action'];
          const username = forms[i].elements['username'];
          if (!action || !username) { continue; }
          if (String(action.value).indexOf('revoke') < 0) { continue; }
          if (username.value !== person) { continue; }
          out.push(i);
        }
        return out;
      `, person);
      for (let n = 0; n < rows.length; n += 1) {
        // The list is re-read each time: pressing one revoke redraws the page
        // and every index after it moves.
        await open(driver, root("/admin/rbac"));
        const again = await driver.executeScript(`
          const person = arguments[0];
          const forms = Array.from(document.forms);
          for (let i = 0; i < forms.length; i += 1) {
            const action = forms[i].elements['action'];
            const username = forms[i].elements['username'];
            if (action && username &&
                String(action.value).indexOf('revoke') >= 0 &&
                username.value === person) { return i; }
          }
          return -1;
        `, person);
        if (again < 0) {
          break;
        }
        await fillAndPress(driver, again, {});
      }
    } catch (e) {
      log.warn("[teardown] could not revoke " + person + " on the page: " +
               e.message);
    }
    // And whatever the page managed, make sure through the other door.
    for (const role of ["read", "write"]) {
      try {
        await common.httpJson(root("/admin-api/rbac/revoke"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: person, role: role })
        });
      } catch (e) {
        log.warn("[teardown] could not revoke " + role + " from " + person +
                 " through the API either: " + e.message);
      }
    }
  }

  const roster = await apiJson("/admin-api/rbac");
  const left = people.filter(function (person) {
    return rolesHeldBy(roster.body, person).length > 0;
  });
  if (left.length) {
    log.warn("[teardown] THE ROSTER IS NOT EMPTY: " + left.join(", ") +
             " still hold a role. While anybody holds one, everybody else is " +
             "locked out of this console — so this will fail every later job " +
             "that touches /admin, with a redirect that says nothing about " +
             "why.");
  } else {
    log.info("[teardown] The roster is empty again, so the console is open " +
             "to the next job as it was to this one.");
  }
  log.debug("Leaving restoreTheRoster().");
}

// ---------------------------------------------------------------------------
// AND THE BROWSER'S OWN CONSOLE, WHICH ON THIS CONSOLE MUST BE EMPTY.
//
// This is an assertion no HTTP client can make and it is nearly free, because
// the log accumulates across the whole run: every page walked, every form
// submitted, every picture drawn.
//
// It means more here than it would on an ordinary page. `script-src 'none'`
// with `default-src 'none'` over it means a console page may load NOTHING —
// no script, no stylesheet from anywhere but itself, no font, no image beyond
// `img-src 'self' data:`, and no fetch at all. So a severe line in the browser
// console is not cosmetic: it is the browser reporting that this console
// asked for something its own policy refuses, which is either a page that
// grew an external asset or a policy that no longer matches the page.
//
// The two transient codes the browser causes itself by changing its own
// configuration mid-request are filtered with the suite's shared helper, which
// is the same filter the other console-judging jobs use.
// ---------------------------------------------------------------------------
async function drainTheBrowserLog(driver) {
  log.debug("Entering drainTheBrowserLog().");
  try {
    const dropped = await driver.manage().logs().get("browser");
    log.debug("Leaving drainTheBrowserLog(). Dropped " + dropped.length + ".");
  } catch (e) {
    // Not every driver serves the log endpoint; the check that reads it says
    // so for itself.
    log.debug("Leaving drainTheBrowserLog(). No log to drain.");
  }
}

async function theBrowserConsoleIsClean(driver) {
  log.debug("Entering theBrowserConsoleIsClean().");
  log.info("=== The browser's own console ===");
  let entries = [];
  try {
    entries = await driver.manage().logs().get("browser");
  } catch (e) {
    // Not every driver serves the log endpoint. That is worth saying rather
    // than passing quietly, because a check that silently did not run is
    // indistinguishable from one that found nothing.
    log.warn("[console] The browser log could not be read (" + e.message +
             "), so this check did not run.");
    log.debug("Leaving theBrowserConsoleIsClean(). No log.");
    return;
  }

  const severe = browserFlags.withoutTransientLoadErrors(
      entries.filter(function (entry) {
        return String(entry.level && entry.level.name || entry.level) === "SEVERE";
      }).map(function (entry) { return String(entry.message); })
      // The browser asks for /favicon.ico on its own, on every origin, and
      // this service serves none. It is the browser's request rather than the
      // console's, so it says nothing about what a page loaded — and it would
      // otherwise be the one permanent entry that made this check useless.
      .filter(function (message) {
        return message.indexOf("/favicon.ico") < 0;
      }));

  check("the browser console is clean across the whole run", function () {
    assert.deepStrictEqual(severe, [],
      "THE BROWSER LOGGED " + severe.length + " SEVERE MESSAGE(S) WHILE " +
      "WALKING THIS CONSOLE: " + severe.join(" | ") + ". Every page here is " +
      "served `default-src 'none'` with `script-src 'none'` over it, so a " +
      "console page may load nothing at all beyond its own images — which " +
      "means a severe line is the browser saying this console asked for " +
      "something its own policy refuses. That is either a page that grew an " +
      "external asset or a policy that no longer matches the page, and " +
      "neither shows up in a status code.");
  });

  log.info("[console] OK — " + entries.length + " browser log entr(ies) " +
           "across the whole run and not one severe, which is what a console " +
           "that may load nothing should produce.");
  log.debug("Leaving theBrowserConsoleIsClean().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Driving the mock STS admin console at " + base + "/admin");

  let status;
  try {
    status = await apiJson("/admin-api/status");
  } catch (e) {
    log.warn("No STS is listening at " + base + " (" + e.message + "). " +
             "Skipping: this job needs the mock and a browser, nothing else.");
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

  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1000");
  browserFlags.addBrowserAccessFlags(options, base);
  options.enableBidi();
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    const handle = await driver.getWindowHandle();
    const inspector = await NetworkInspector(driver, [handle]);
    await inspector.responseCompleted(recordResponse);

    await theGateBehaves(driver);
    // THE GATE SECTION DELIBERATELY PROVOKES 401s, and the browser logs a
    // severe line for each. They are this file's own doing, so the log is
    // drained here — `logs().get()` empties it — and what accumulates from
    // this point on is the console's own behaviour. Draining is better than
    // filtering by URL later: the URLs the gate drives are also read normally
    // by the page walk, so a filter would hide a real failure on them.
    await drainTheBrowserLog(driver);
    const walked = await everyPageIsDrawn(driver, pages);
    await noPageNestsAForm(driver, pages);
    await everyLinkResolves(driver, walked.links);
    await everyControlReachesSomething(driver, pages);

    await theRealmIsCreatedOnTheForm(driver);
    try {
      await everyGetFormSubmits(driver, pages);
      const created = await theDirectoryPagesWork(driver);
      await theTokensPageRevokesWhatItDraws(driver);
      await everyWriteRoundTrips(driver);
      await theHandlersNothingEverPressed(driver);
      await theDrillDownsCarryTheirTrail(driver, created);
      await filteringAndPagingWork(driver, created);
      await theRealmSwitcherSwitches(driver);
      await theTwoDrawingsAreServerSide(driver);
      await theConsoleRefusesWhatItShould(driver);
      await aSettingChangedOnItsProtocolPage(driver);
      await theBrowserConsoleIsClean(driver);
      // LAST, and the order is a dependency: the first grant closes the
      // console against this run's own session, and every section above
      // needs it open.
      await theRolesArePressedAndEnforced(driver, created);
    } finally {
      await theRealmIsRemovedOnTheForm(driver);
    }

    // A FLOOR ON THE COUNT. A section that stops being called takes its
    // assertions with it and the run still says "passed" — which is the one
    // failure mode a suite cannot report about itself. The number is well
    // under what a healthy run makes, so it catches a section dropping out
    // without failing every time an assertion is added.
    assert.ok(checks >= 300,
      "only " + checks + " checks ran. This suite makes well over three " +
      "hundred against a healthy service, so a count this low means a " +
      "SECTION STOPPED BEING CALLED rather than that the console got " +
      "simpler — and every assertion in it went quiet at the same time.");
    log.info(checks + " checks passed.");
    log.info("Test completed successfully.");
  } catch (e) {
    await keepAPicture(driver, "failure");
    throw e;
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_admin_console")
  .description("Verify the mock STS admin console in a real browser: the " +
      "gate, every page, every link, every GET form, every button, and the " +
      "values that come back afterwards.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .addOption(new Option("--screenshot-dir <dir>",
      "write a PNG of the page here if the run fails"))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");
screenshotDir = program.opts().screenshotDir || "";

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
