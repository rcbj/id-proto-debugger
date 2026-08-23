// File: scim_page.js
//
// ---------------------------------------------------------------------------
// THE SCIM PAGE, IN A BROWSER — WHICH IS WHERE FIVE THINGS EXIST AND NOWHERE
// ELSE.
//
// `scim_engine.js` asserts what this workflow composes with no server at all;
// `scim_protocol.js` sends every endpoint through the api and reads the result
// back out of the directory. Between them they cover the protocol. So this file
// deliberately does NOT re-drive every endpoint against every assertion — it
// covers only what needs a browser, and each item below is a way this workflow
// can be broken while the protocol is perfect:
//
//   * **THE BROWSER CALL PATH ITSELF.** It is the DEFAULT here and the only one
//     that exists on the static deployments, and no other test exercises it: a
//     `fetch` from the page to a SCIM server, with the CORS, the credentials
//     mode and the readable-header limits that come with it. A page that only
//     ever worked through the api would pass every other test in this suite and
//     be dead on the hosted site.
//
//   * **THE TWO CREDENTIALS THAT ARE COMPUTED WITH WEB CRYPTO.** A DPoP proof
//     is signed in the browser over the exact method and URL; a HOBA key is
//     generated, registered and used to sign there too. Neither exists in
//     `scim_protocol.js` — that file sends a HOBA signature made with node's
//     crypto, which is a different implementation. Web Crypto has its own
//     hazard as well: it needs a SECURE CONTEXT, so this is also where "the key
//     could not be generated" would first appear.
//
//   * **THE TWO SCHEMES THAT ARE BROWSER-ONLY.** A session cookie is attached
//     by the browser and a client certificate is chosen in the handshake, so
//     neither can be tested from node at all. What is checked here is that
//     selecting either LOCKS the call path — a page that let somebody pick
//     "through the api" with a cookie scheme would send a request with no
//     cookie and report the 401 as the server's fault.
//
//   * **THE SCENARIO RUNNER.** The plan and the judgement are asserted without
//     a browser in `scim_engine.js`; what only exists here is the RUN — that
//     the steps go in order, that an id captured by step 3 reaches step 7, that
//     the progress table fills, and that a scenario whose steps EXPECT refusals
//     finishes green.
//
//   * **WHAT THE PAGE REMEMBERS.** The password must never reach localStorage
//     and the access token must reach it only with the box ticked — and
//     clearing the box must PURGE what was already there. Nothing outside a
//     browser can see any of that.
//
// **Services needed:** the client, the mock STS (for a real SCIM server), and
// the api for the backend-path section only. browser_flags.js is called
// because the page fetches loopback addresses from whatever origin the suite is
// pointed at, and a fetch from a public origin to a private one is a Private
// Network Access request Chrome blocks or preflights — the symptom of missing
// that is a status line that never fills and a timeout naming an element
// rather than the network.
//
// **It skips with a REASON when the mock has no SCIM**, which is the ordinary
// state of a checkout whose sts/ gitlink predates those endpoints. A silent
// pass there would be this project's recurring defect.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { waitForPageBundle } = require("./wait_for.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "scim_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var apiUrl = process.env.API_URL || "http://localhost:4000";
// The SCIM service root as THE BROWSER must reach it. Its own variable, and on
// the containerized stack a different answer from the api's view — the browser
// resolves this one, and that distinction has cost this suite a run before on
// the LDAP and SPNEGO workflows.
var scimBaseUrl = process.env.SCIM_BROWSER_URL ||
    process.env.STS_URL + "/scim/v2" || "http://localhost:8081/scim/v2";

var stamp = Date.now().toString(36) +
    Math.floor(Math.random() * 1e6).toString(36);
var prefix = "page" + stamp;

let checks = 0;
let skips = [];

// The credential every SENDING section below runs under. Not this run's
// prefix: a Basic username is recorded as an authentication at the mock and
// gains a directory entry, and a run's provisioning identity is not one of the
// users that run provisioned.
const runnerUsername = "scim-page-runner";

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
// Setting a field the way a person does — value plus the events the page
// listens for. `driver.sendKeys` would be closer still and is far slower on a
// field holding a JSON body; what matters is that the change handler runs, or
// saveState() never sees the value.
//
// NOTE: THE FUNCTION BODY BELOW RUNS IN THE BROWSER. It and everything it
// declares are exempt from the Entering/Leaving convention — there is no bunyan
// in a page, and a log line there is `javascript error: log is not defined`
// from executeScript, which reads as a page fault. See the repo-root CLAUDE.md.
// ---------------------------------------------------------------------------
async function setField(driver, id, value) {
  log.debug("Entering setField(). id=" + id);
  await driver.executeScript(`
    var e = document.getElementById(arguments[0]);
    if (!e) { throw new Error('no such field: ' + arguments[0]); }
    e.value = arguments[1];
    e.dispatchEvent(new Event('input', { bubbles: true }));
    e.dispatchEvent(new Event('change', { bubbles: true }));
  `, id, value);
  log.debug("Leaving setField().");
}

async function setCheckbox(driver, id, on) {
  log.debug("Entering setCheckbox(). id=" + id);
  await driver.executeScript(`
    var e = document.getElementById(arguments[0]);
    if (!e) { throw new Error('no such checkbox: ' + arguments[0]); }
    e.checked = !!arguments[1];
    e.dispatchEvent(new Event('change', { bubbles: true }));
  `, id, on);
  log.debug("Leaving setCheckbox().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). id=" + id);
  const text = await driver.executeScript(`
    var e = document.getElementById(arguments[0]);
    return e ? (e.value !== undefined && e.tagName !== 'SELECT'
      ? String(e.value) : String(e.textContent || '')) : '(no such element)';
  `, id);
  log.debug("Leaving textOf().");
  return text;
}

// Wait on CONTENT rather than on an element. An element that exists and is
// empty is the flake this suite has lost runs to, and an unfilled readonly
// input's `.value` is TRUTHY whitespace — see tests/wait_for.js and
// tests/CLAUDE.md.
//
// AND ON A SETTLED STATUS RATHER THAN A BUSY ONE, which is the half this file
// was missing. Every status field on the page is written TWICE for one action:
// `statusBusy()` puts "Sending POST /Users…" there the moment the button is
// pressed and `statusOk()`/`statusBad()` replace it when the answer arrives.
// The text alone cannot tell the two apart — the CLASS can, `scim-pending`
// against `scim-ok`/`scim-bad` — so a wait that stops at the first non-empty
// text is racing the fetch, and it wins that race almost every time.
//
// It has cost this file twice, in both of the ways this project keeps
// rediscovering:
//
//   * section 2 asserted the create against "Sending POST /scim/v2/Users…",
//     a FAILURE that names the status field rather than what the server said;
//   * section 0 read "Reading the ServiceProviderConfig…", concluded the
//     server was not there and SKIPPED THE WHOLE FILE — with a confident
//     stated reason about the sts/ gitlink predating the SCIM routes, which
//     was not true. A run of this test that quietly did nothing reported
//     PASS in 0.7s.
//
// So `pending` is what the loop waits out, and a timeout says which of the two
// it timed out in: a status still busy after 30s is a request that never came
// back, and a settled one that never matched `wanted` is a different bug.
//
// NOTE: THE FUNCTION BODY BELOW RUNS IN THE BROWSER. It and everything it
// declares are exempt from the Entering/Leaving convention — see the note on
// setField() above.
async function waitForStatus(driver, id, wanted, timeoutMs) {
  log.debug("Entering waitForStatus(). id=" + id);
  const deadline = Date.now() + (timeoutMs || 30000);
  let last = "";
  let pending = false;
  while (Date.now() < deadline) {
    const state = await driver.executeScript(`
      var e = document.getElementById(arguments[0]);
      if (!e) { return { text: '(no such element)', pending: false }; }
      var text = (e.value !== undefined && e.tagName !== 'SELECT')
        ? String(e.value) : String(e.textContent || '');
      return { text: text,
               pending: e.classList.contains('scim-pending') };
    `, id);
    last = state.text;
    pending = state.pending;
    if (!pending && String(last).trim() !== "" &&
        (!wanted || new RegExp(wanted, "i").test(last))) {
      log.debug("Leaving waitForStatus(). " + last.slice(0, 120));
      return last;
    }
    await driver.sleep(250);
  }
  log.debug("Leaving waitForStatus(). Timed out.");
  throw new Error("the status field " + id + " never said " +
      (wanted || "anything") + "; it is still " +
      (pending ? "BUSY" : "settled") + " and says: " +
      String(last).slice(0, 400));
}

// ---------------------------------------------------------------------------
// Press a button and wait for the status field that button writes — with the
// field BLANKED first, which is the half a plain click-then-wait is missing.
//
// Every status here is written twice for one action (busy, then settled), and
// it was also written by the action BEFORE. So a wait that begins the moment
// the click returns can settle on the answer to the previous question and
// never notice: section 6b pressed Run on the negatives scenario, read
// section 6's "11 as planned" summary, and then looked for a step of the new
// plan in a table still showing the old one — reporting "the
// duplicate-userName step is not in the table" about a table that was simply
// one scenario behind, while the scenario it was accusing ran perfectly.
//
// Blanking first makes the wait unambiguous: the only text that can appear in
// that field next belongs to this action. It is done here rather than in
// waitForStatus() because only the caller knows which click it is waiting on.
//
// NOTE: THE FUNCTION BODY BELOW RUNS IN THE BROWSER. It and everything it
// declares are exempt from the Entering/Leaving convention — see the note on
// setField() above.
// ---------------------------------------------------------------------------
async function clearStatus(driver, id) {
  log.debug("Entering clearStatus(). id=" + id);
  await driver.executeScript(`
    var e = document.getElementById(arguments[0]);
    if (e) { e.value = ''; }
  `, id);
  log.debug("Leaving clearStatus().");
}

async function clickAndWait(driver, buttonId, statusId, wanted, timeoutMs) {
  log.debug("Entering clickAndWait(). button=" + buttonId);
  await clearStatus(driver, statusId);
  await driver.findElement(By.id(buttonId)).click();
  const status = await waitForStatus(driver, statusId, wanted, timeoutMs);
  log.debug("Leaving clickAndWait().");
  return status;
}

async function openPage(driver) {
  log.debug("Entering openPage().");
  await driver.get(baseUrl + "/scim.html");
  // The inline onclick handlers call the browserify --standalone global, and a
  // click before that global exists is a SILENT NO-OP. See
  // tests/inline_onclick and the note in tests/CLAUDE.md.
  await waitForPageBundle(driver, "the SCIM page");
  await setField(driver, "scim_base_url", scimBaseUrl);
  log.debug("Leaving openPage().");
}

// ---------------------------------------------------------------------------
// 0. Is there a SCIM server behind this page?
// ---------------------------------------------------------------------------
async function theServerIsThere(driver) {
  log.debug("Entering theServerIsThere().");
  log.info("0. Reaching the server from the browser.");
  const status = await clickAndWait(driver, "btn_scim_spc",
      "scim_discovery_status", null);
  if (!/Read\./i.test(status)) {
    log.debug("Leaving theServerIsThere(). Not reachable.");
    return { present: false, why: 'the browser could not read a ' +
        'ServiceProviderConfig from ' + scimBaseUrl + ': "' + status + '". ' +
        'The SCIM endpoints arrived in rcbj/mock-sts AFTER this ' +
        'repository\'s sts/ gitlink was last moved, so a checkout whose ' +
        'submodule predates them has no /scim/v2 routes; a CORS refusal ' +
        'looks the same from here and is the other possibility.' };
  }
  check('the browser reads the ServiceProviderConfig DIRECTLY — no api',
      function () {
    assert.ok(/Read\./i.test(status),
        'This is the call path the hosted site has and the only one it has. ' +
        'A page that only ever worked through the api would pass every ' +
        'other test in this suite and be dead there. Status: ' + status);
  });
  const capabilities = await driver.executeScript(`
    var rows = document.querySelectorAll('.scim-capability-table tr');
    var out = [];
    for (var i = 0; i < rows.length; i++) {
      out.push(rows[i].cells[0].textContent + '=' +
          rows[i].cells[1].textContent);
    }
    return out;
  `);
  check('the ServiceProviderConfig is TABULATED rather than dumped',
      function () {
    assert.ok(capabilities.length >= 6,
        'The capability table has ' + capabilities.length + ' row(s). What a ' +
        'reader wants from that document is six booleans and two numbers, ' +
        'not a JSON blob.');
    const text = capabilities.join(' ');
    ['patch', 'bulk', 'filter', 'sort', 'etag', 'changePassword',
     'authenticationSchemes'].forEach(function (name) {
      assert.ok(text.indexOf(name) >= 0,
          'The capability table does not mention ' + name + '.');
    });
  });
  log.debug("Leaving theServerIsThere(). Present.");
  return { present: true };
}

// ---------------------------------------------------------------------------
// THE CREDENTIAL THE SENDING SECTIONS RUN UNDER.
//
// The mock refuses an unauthenticated SCIM write (`scim.authRequired`, on by
// default there), so the page has to be carrying something before any section
// below can create anything — which is what a reader of this page does too.
// Basic is chosen for the reason `scim_protocol.js` chooses it: it is the one
// scheme that is a header and nothing else, so a refusal below is about SCIM
// rather than about a token endpoint having a bad day.
//
// It is applied MORE THAN ONCE on purpose. Section 4 walks the whole scheme
// selector and leaves it wherever the loop finished, and sections 5 and 5b
// select their own — so a later section that sends has to put it back rather
// than assume the page is still where section 2 left it. Discovery is not
// covered by it: `scim.authDiscovery` is off at the mock and section 0 asserts
// that the ServiceProviderConfig reads with no credential at all.
// ---------------------------------------------------------------------------
async function useRunCredential(driver, where) {
  log.debug("Entering useRunCredential(). where=" + where);
  await driver.executeScript(`
    var select = document.getElementById('scim_auth_scheme');
    select.value = 'basic';
    select.dispatchEvent(new Event('change'));
  `);
  await setField(driver, "scim_auth_username", runnerUsername);
  await setField(driver, "scim_auth_password", "not-the-reserved-one");
  const applied = await driver.executeScript(`
    return {
      scheme: document.getElementById('scim_auth_scheme').value,
      username: document.getElementById('scim_auth_username').value,
      password: document.getElementById('scim_auth_password').value
    };
  `);
  // Asserted rather than assumed: a selector that silently kept its old value
  // turns every send below into a 401 naming an endpoint, which is a dozen
  // failures for one cause and not one of them says "no credential".
  check('the page is carrying a Basic credential ' + where, function () {
    assert.strictEqual(applied.scheme, 'basic',
        'The scheme selector says "' + applied.scheme + '" after being set ' +
        'to basic.');
    assert.strictEqual(applied.username, runnerUsername,
        'The username field holds "' + applied.username + '".');
    assert.ok(applied.password.length > 0,
        'The password field is empty, and RFC 7617 has no credential ' +
        'without one.');
  });
  log.debug("Leaving useRunCredential().");
}

// ---------------------------------------------------------------------------
// 1. EVERY ENDPOINT IS REACHABLE FROM THE PAGE.
//
// Composed rather than sent, for the ones with side effects: what this checks
// is that the page can BUILD each of the twenty-two, because an endpoint
// missing from the select is one the workflow cannot reach at all. The ones
// worth actually sending are sent below.
// ---------------------------------------------------------------------------
async function everyEndpointComposes(driver) {
  log.debug("Entering everyEndpointComposes().");
  log.info("1. Every endpoint composes from the page.");
  await setField(driver, "scim_op_id",
      "uid=someone,ou=users,dc=example,dc=com");
  const composed = await driver.executeScript(`
    var out = [];
    var select = document.getElementById('scim_op');
    for (var i = 0; i < select.options.length; i++) {
      select.value = select.options[i].value;
      select.dispatchEvent(new Event('change'));
      var body = document.getElementById('scim_op_body');
      var needsBody = document.getElementById('scim_op_body_row')
        .className.indexOf('scim-hidden') < 0;
      if (needsBody) {
        window.scim.generateBodyForOperation();
      }
      var built = window.scim.currentRequest();
      out.push({ id: select.options[i].value,
                 ok: built.ok,
                 method: built.ok ? built.request.method : '',
                 url: built.ok ? built.request.url : built.error,
                 hasBody: built.ok ? (built.request.body !== null) : false });
    }
    return out;
  `);
  check('the operation list offers all twenty-two endpoints', function () {
    assert.strictEqual(composed.length, 22,
        'The select offers ' + composed.length + ' operations and RFC 7644 ' +
        'defines twenty-two. An endpoint missing from the list is one the ' +
        'workflow cannot reach at all.');
  });
  composed.forEach(function (row) {
    check('the page composes ' + row.id, function () {
      assert.ok(row.ok, row.id + ' could not be composed: ' + row.url);
      assert.ok(row.url.indexOf(scimBaseUrl) === 0,
          row.id + ' composed ' + row.url + ', which is not under the ' +
          'service root the Connection pane names.');
    });
  });
  check('the Generate button really fills a body for every operation that '
      + 'takes one', function () {
    const withBodies = composed.filter(function (row) {
      return row.hasBody;
    });
    assert.ok(withBodies.length >= 8,
        'Only ' + withBodies.length + ' operations got a generated body. ' +
        'Nine of the twenty-two carry one (four creates and replaces, two ' +
        'patches, three search/bulk), and a Generate button that produced ' +
        'nothing would leave every one of those unsendable.');
  });
  log.debug("Leaving everyEndpointComposes().");
}

// ---------------------------------------------------------------------------
// 2. A REAL ROUND TRIP FROM THE BROWSER.
// ---------------------------------------------------------------------------
async function theBrowserCreatesAndDeletes(driver) {
  log.debug("Entering theBrowserCreatesAndDeletes().");
  log.info("2. A create, a read and a delete, from the browser.");
  await setField(driver, "scim_gen_seed", prefix + "-seed");
  await setField(driver, "scim_gen_prefix", prefix);
  await setField(driver, "scim_gen_count", "1");
  await driver.executeScript(`
    var select = document.getElementById('scim_op');
    select.value = 'createUser';
    select.dispatchEvent(new Event('change'));
    window.scim.generateBodyForOperation();
  `);
  const bodyText = await textOf(driver, "scim_op_body");
  check('a generated User body carries the enterprise extension', function () {
    assert.ok(bodyText.indexOf('urn:ietf:params:scim:schemas:extension:' +
        'enterprise:2.0:User') >= 0,
        'The generated body has no enterprise extension in it, so the ' +
        'section 4.3 attributes are never sent from this page.');
    assert.ok(bodyText.indexOf('honorificPrefix') >= 0 &&
        bodyText.indexOf('x509Certificates') >= 0,
        'The generated body is not the FULL attribute set. Every optional ' +
        'attribute RFC 7643 section 4.1 defines is meant to be there — a ' +
        'client tested only against userName and emails has tested nothing ' +
        'about the fields it will meet.');
  });
  const status = await clickAndWait(driver, "btn_scim_send",
      "scim_op_status", null, 30000);
  check('the create succeeds from the browser', function () {
    assert.ok(/^201/.test(status),
        'The create said: ' + status);
  });
  const lastId = await textOf(driver, "scim_last_user_id");
  check('the created id is remembered for the next operation', function () {
    assert.ok(lastId && lastId.indexOf('uid=') === 0,
        'The last created id is "' + lastId + '". A debugger where an id ' +
        'has to be copied by hand between two fields on the same page is ' +
        'one nobody uses twice.');
  });
  check('the Exchange pane says the call was made by the BROWSER',
      async function () {
    return null;
  });
  const via = await textOf(driver, "scim_exchange_via");
  check('the Exchange pane names its own limits on a browser call',
      function () {
    assert.ok(/browser/i.test(via),
        'The Exchange pane says: ' + via.slice(0, 200));
    assert.ok(/Location/i.test(via),
        'A browser-direct call cannot read most response headers unless the ' +
        'server names them in Access-Control-Expose-Headers, and Location — ' +
        'which every SCIM create sends — is usually among them. Presenting ' +
        'a partial list as a whole one is a debugger lying with a straight ' +
        'face, so the pane has to say so. It says: ' + via.slice(0, 200));
  });
  // Read it back through the page.
  await driver.executeScript(`
    var select = document.getElementById('scim_op');
    select.value = 'readUser';
    select.dispatchEvent(new Event('change'));
    window.scim.useLastId();
  `);
  const readStatus = await clickAndWait(driver, "btn_scim_send",
      "scim_op_status", null);
  check('reading it back succeeds and the id was reused', function () {
    assert.ok(/^200/.test(readStatus), 'The read said: ' + readStatus);
  });
  const result = await textOf(driver, "scim_op_result");
  check('the resource that comes back carries what was sent', function () {
    assert.ok(result.indexOf(prefix) >= 0,
        'The result pane does not contain the generated userName prefix.');
    assert.ok(result.indexOf('"meta"') >= 0,
        'The resource has no meta, so nothing says when it was created.');
  });
  // And delete it, so the run leaves nothing behind.
  await driver.executeScript(`
    var select = document.getElementById('scim_op');
    select.value = 'deleteUser';
    select.dispatchEvent(new Event('change'));
    window.scim.useLastId();
  `);
  const deleteStatus = await clickAndWait(driver, "btn_scim_send",
      "scim_op_status", null);
  check('the delete succeeds and 204 is reported as a SUCCESS', function () {
    assert.ok(/^204/.test(deleteStatus),
        'A delete answers 204 with no body, and reading an empty body as a ' +
        'failure would make every successful delete look broken. It said: ' +
        deleteStatus);
  });
  log.debug("Leaving theBrowserCreatesAndDeletes().");
}

// ---------------------------------------------------------------------------
// 3. THE OTHER CALL PATH.
// ---------------------------------------------------------------------------
async function theBackendPathAlsoWorks(driver) {
  log.debug("Entering theBackendPathAlsoWorks().");
  log.info("3. The same page, through the api.");
  const backendEnabled = await driver.executeScript(`
    var e = document.getElementById('scim_call_backend');
    return e ? !e.disabled : false;
  `);
  if (!backendEnabled) {
    skip('the backend call path',
        'the backend radio is disabled on this build — which is correct on ' +
        'a static deployment, where there is no api at all.');
    log.debug("Leaving theBackendPathAlsoWorks(). No api.");
    return;
  }
  await driver.executeScript(`
    document.getElementById('scim_call_backend').checked = true;
    document.getElementById('scim_call_browser').checked = false;
  `);
  check('the page reports the api\'s published limits', async function () {
    return null;
  });
  const limits = await textOf(driver, "scim_api_limits");
  check('GET /scim/limits was read and shown', function () {
    assert.ok(/GET, POST, PUT, PATCH, DELETE/.test(limits),
        'The page says what the api will do BEFORE a call fails, so a ' +
        'refusal is a sentence rather than a surprise. It says: ' +
        limits.slice(0, 250));
  });
  await driver.executeScript(`
    var select = document.getElementById('scim_op');
    select.value = 'listUsers';
    select.dispatchEvent(new Event('change'));
    document.getElementById('scim_query_count').value = '1';
  `);
  const status = await clickAndWait(driver, "btn_scim_send",
      "scim_op_status", null);
  check('a list through the api succeeds', function () {
    assert.ok(/^200/.test(status), 'It said: ' + status);
  });
  const via = await textOf(driver, "scim_exchange_via");
  check('the Exchange pane says the api sent it, and shows the WHOLE exchange',
      function () {
    assert.ok(/api/i.test(via) && /headers included/i.test(via),
        'A proxied call is made by the api and can only be reported by the ' +
        'api, which is the whole reason that path exists for a debugger. ' +
        'The pane says: ' + via.slice(0, 250));
  });
  const headers = await textOf(driver, "scim_exchange_request_headers");
  check('the request headers the api actually sent are visible', function () {
    assert.ok(headers.indexOf('Accept') >= 0,
        'The proxied request headers came back empty. A browser withholds ' +
        'the headers it adds; the api does not have to. Got: ' +
        headers.slice(0, 200));
  });
  // Back to the browser path for the rest of the run.
  await driver.executeScript(`
    document.getElementById('scim_call_browser').checked = true;
    document.getElementById('scim_call_backend').checked = false;
  `);
  log.debug("Leaving theBackendPathAlsoWorks().");
}

// ---------------------------------------------------------------------------
// 4. THE SEVEN AUTHENTICATION SCHEMES, FROM THE PAGE.
// ---------------------------------------------------------------------------
async function everySchemeIsOfferedAndExplained(driver) {
  log.debug("Entering everySchemeIsOfferedAndExplained().");
  log.info("4. Authentication schemes.");
  const schemes = await driver.executeScript(`
    var out = [];
    var select = document.getElementById('scim_auth_scheme');
    for (var i = 0; i < select.options.length; i++) {
      select.value = select.options[i].value;
      select.dispatchEvent(new Event('change'));
      var shown = function (id) {
        var e = document.getElementById(id);
        return e ? e.className.indexOf('scim-hidden') < 0 : false;
      };
      out.push({
        id: select.options[i].value,
        what: (document.getElementById('scim_auth_what').textContent || ''),
        spec: (document.getElementById('scim_auth_spec').textContent || ''),
        scopeNote: (document.getElementById('scim_auth_scope_note')
          .textContent || ''),
        backendDisabled: document.getElementById('scim_call_backend').disabled,
        tokenShown: shown('scim_auth_token_row'),
        passwordShown: shown('scim_auth_password_row'),
        dpopShown: shown('scim_dpop_row'),
        hobaShown: shown('scim_hoba_row'),
        digestShown: shown('scim_digest_row'),
        cookieShown: shown('scim_cookie_row'),
        certShown: shown('scim_clientcert_row')
      });
    }
    return out;
  `);
  check('all six RFC 7644 section 2 schemes are offered, plus anonymous',
      function () {
    const ids = schemes.map(function (row) {
      return row.id;
    });
    ['none', 'bearer', 'dpop', 'basic', 'digest', 'hoba', 'cookie',
     'clientcert'].forEach(function (id) {
      assert.ok(ids.indexOf(id) >= 0,
          'The scheme selector does not offer "' + id + '". RFC 7644 ' +
          'section 2 names six ways of authenticating and this workflow is ' +
          'meant to support all of them.');
    });
  });
  schemes.forEach(function (row) {
    check('the "' + row.id + '" scheme explains itself and cites a spec',
        function () {
      assert.ok(row.what.length > 40,
          'The "' + row.id + '" scheme shows no explanation. A scheme that ' +
          'adds nothing to the request in particular has to SAY so, or the ' +
          'page looks like it did not run.');
      assert.ok(row.spec.length > 0,
          'The "' + row.id + '" scheme cites no specification.');
    });
  });
  check('each scheme reveals exactly its own controls', function () {
    const byId = {};
    schemes.forEach(function (row) {
      byId[row.id] = row;
    });
    assert.ok(byId.bearer.tokenShown && !byId.bearer.passwordShown,
        'The Bearer scheme should show the token field and not a password.');
    assert.ok(byId.dpop.tokenShown && byId.dpop.dpopShown);
    assert.ok(byId.basic.passwordShown && !byId.basic.tokenShown);
    assert.ok(byId.digest.passwordShown && byId.digest.digestShown);
    assert.ok(byId.hoba.hobaShown,
        'The HOBA scheme shows no key controls, so there is no way to ' +
        'generate or register one.');
    assert.ok(byId.cookie.cookieShown,
        'The cookie scheme adds nothing to the request, so the page must ' +
        'say what to do instead — which is to sign in at the server.');
    assert.ok(byId.clientcert.certShown);
    assert.ok(!byId.none.tokenShown && !byId.none.passwordShown,
        'The anonymous scheme reveals a credential field.');
  });
  check('only the two OAuth schemes claim to carry scopes', function () {
    schemes.forEach(function (row) {
      const claimsScopes = /carries SCOPES/.test(row.scopeNote);
      const shouldClaim = row.id === 'bearer' || row.id === 'dpop';
      if (row.id === 'none') {
        return;
      }
      assert.strictEqual(claimsScopes, shouldClaim,
          'The "' + row.id + '" scheme ' + (claimsScopes ? 'claims' :
          'does not claim') + ' to carry scopes. Only an OAuth credential ' +
          'has any, and a page that implied otherwise would have somebody ' +
          'concluding a scope restriction works when nothing was restricted.');
    });
  });
  check('the two browser-only schemes LOCK the call path', function () {
    schemes.forEach(function (row) {
      if (row.id === 'cookie' || row.id === 'clientcert') {
        assert.strictEqual(row.backendDisabled, true,
            'Selecting "' + row.id + '" left the api call path available. ' +
            'The api has no cookie jar and would present ITS OWN ' +
            'certificate — so such a call goes out with no credential at ' +
            'all and the 401 reads as the server\'s fault.');
      }
    });
  });
  check('the call path is unlocked again for a header-carried scheme',
      function () {
    const bearer = schemes.filter(function (row) {
      return row.id === 'bearer';
    })[0];
    assert.strictEqual(bearer.backendDisabled, false,
        'The Bearer scheme is a header the api can carry perfectly well, ' +
        'and the lock did not come back off — so once somebody selects a ' +
        'cookie the backend path is dead for the rest of the session.');
  });
  log.debug("Leaving everySchemeIsOfferedAndExplained().");
}

// ---------------------------------------------------------------------------
// 5. THE TWO CREDENTIALS COMPUTED WITH WEB CRYPTO.
//
// Neither exists anywhere else in this suite: scim_protocol.js signs a HOBA
// blob with node's crypto, which is a different implementation, and mints no
// DPoP proof against SCIM at all.
// ---------------------------------------------------------------------------
async function theDpopProofIsMintedInTheBrowser(driver) {
  log.debug("Entering theDpopProofIsMintedInTheBrowser().");
  log.info("5. DPoP, in the browser.");
  const secure = await driver.executeScript("return window.isSecureContext;");
  if (!secure) {
    skip('the DPoP proof',
        'this origin is not a SECURE CONTEXT, so window.crypto.subtle is ' +
        'undefined and no key can be generated. That is the Web Crypto ' +
        'hazard tests/CLAUDE.md records — https or localhost, nothing else.');
    log.debug("Leaving theDpopProofIsMintedInTheBrowser(). Not secure.");
    return;
  }
  await driver.executeScript(`
    var select = document.getElementById('scim_auth_scheme');
    select.value = 'dpop';
    select.dispatchEvent(new Event('change'));
    document.getElementById('scim_auth_token').value = 'a-placeholder-token';
    var op = document.getElementById('scim_op');
    op.value = 'listUsers';
    op.dispatchEvent(new Event('change'));
    document.getElementById('scim_query_count').value = '1';
  `);
  await clickAndWait(driver, "btn_scim_send", "scim_op_status", null,
      30000);
  const proof = await textOf(driver, "scim_dpop_proof");
  check('a DPoP proof is minted with Web Crypto and shown', function () {
    assert.ok(proof.indexOf('"typ"') >= 0 && proof.indexOf('dpop+jwt') >= 0,
        'No DPoP proof was produced. This is the only place in the suite ' +
        'where one is signed in a BROWSER, which is where the page will ' +
        'actually do it. Proof pane: ' + proof.slice(0, 200));
  });
  check('the proof is bound to THIS method and URL', function () {
    assert.ok(proof.indexOf('"htm": "GET"') >= 0 ||
        proof.indexOf('"htm":"GET"') >= 0,
        'The proof does not carry htm=GET, so it is not bound to the ' +
        'method. Proof: ' + proof.slice(0, 300));
    assert.ok(proof.indexOf('/Users') >= 0,
        'The proof does not carry an htu naming the endpoint, so a captured ' +
        'one would be replayable against any other — which is the whole of ' +
        'what RFC 9449 adds.');
    assert.ok(proof.indexOf('"ath"') >= 0,
        'The proof carries no `ath`, so it is not bound to the access ' +
        'token either and the pair can be split.');
  });
  const thumbprint = await textOf(driver, "scim_dpop_thumbprint");
  check('the signing key was generated for this page session', function () {
    assert.ok(/generated/i.test(thumbprint),
        'The key note says: ' + thumbprint);
  });
  log.debug("Leaving theDpopProofIsMintedInTheBrowser().");
}

async function theHobaKeyIsGeneratedAndSigns(driver) {
  log.debug("Entering theHobaKeyIsGeneratedAndSigns().");
  log.info("5b. HOBA, in the browser.");
  const secure = await driver.executeScript("return window.isSecureContext;");
  if (!secure) {
    skip('the HOBA key', 'this origin is not a secure context.');
    log.debug("Leaving theHobaKeyIsGeneratedAndSigns(). Not secure.");
    return;
  }
  await driver.executeScript(`
    var select = document.getElementById('scim_auth_scheme');
    select.value = 'hoba';
    select.dispatchEvent(new Event('change'));
    document.getElementById('scim_hoba_username').value = 'hoba-${prefix}';
  `);
  const status = await clickAndWait(driver, "btn_scim_hoba_generate",
      "scim_hoba_status", null, 60000);
  check('an RSA key is generated in the browser', function () {
    assert.ok(/generated/i.test(status),
        'RFC 7486\'s algorithm registry has one entry that matters — "0", ' +
        'RSA-SHA256 — so an ECDSA key would produce a signature the scheme ' +
        'has no identifier for. Status: ' + status);
  });
  const pem = await textOf(driver, "scim_hoba_public_key");
  check('the public key is a PEM ready to register', function () {
    assert.ok(pem.indexOf('-----BEGIN PUBLIC KEY-----') === 0,
        'The public key pane holds: ' + pem.slice(0, 120));
  });
  const kid = await textOf(driver, "scim_hoba_kid");
  check('a key id is minted per session', function () {
    assert.ok(kid.length > 0,
        'A random key id per session keeps two browsers from overwriting ' +
        'each other\'s registration on a shared mock.');
  });
  const stored = await driver.executeScript(`
    var out = [];
    for (var i = 0; i < localStorage.length; i++) {
      var key = localStorage.key(i);
      var value = localStorage.getItem(key) || '';
      if (value.indexOf('PRIVATE KEY') >= 0 ||
          key.indexOf('hoba_private') >= 0) {
        out.push(key);
      }
    }
    return out;
  `);
  check('the HOBA private key is NEVER written to localStorage', function () {
    assert.deepStrictEqual(stored, [],
        'A signing key reached localStorage under: ' + stored.join(', ') +
        '. A signing key in storage is a signing key in every extension\'s ' +
        'reach, and this one is generated per session on purpose.');
  });
  log.debug("Leaving theHobaKeyIsGeneratedAndSigns().");
}

// ---------------------------------------------------------------------------
// 6. THE SCENARIO RUNNER — the part that only exists at run time.
// ---------------------------------------------------------------------------
async function aScenarioRunsEndToEnd(driver) {
  log.debug("Entering aScenarioRunsEndToEnd().");
  log.info("6. The scenario runner.");
  // Sections 4, 5 and 5b each left the scheme selector somewhere else, and
  // every step of a scenario is a real request.
  await useRunCredential(driver, 'for the scenario runner');
  await setField(driver, "scim_scenario_seed", prefix + "-run");
  await setField(driver, "scim_scenario_prefix", prefix + "run");
  await setField(driver, "scim_scenario_count", "3");
  await driver.executeScript(`
    var select = document.getElementById('scim_scenario');
    select.value = 'provision-team';
    select.dispatchEvent(new Event('change'));
  `);
  const planned = await clickAndWait(driver, "btn_scim_plan",
      "scim_scenario_status", null);
  check('planning SENDS NOTHING and says so', function () {
    assert.ok(/Nothing has been sent/i.test(planned),
        'A plan is a set of assertions to be read before any of them runs. ' +
        'It said: ' + planned);
  });
  const rows = await driver.executeScript(`
    return document.querySelectorAll('#scim_runner_table tbody tr').length;
  `);
  check('the plan is drawn as a table of steps', function () {
    assert.ok(rows >= 10,
        'The runner table has ' + rows + ' row(s). A three-user ' +
        'provision-team is twelve steps.');
  });
  const verdictsBefore = await driver.executeScript(`
    var cells = document.querySelectorAll('.scim-step-verdict');
    var out = [];
    for (var i = 0; i < cells.length; i++) { out.push(cells[i].textContent); }
    return out;
  `);
  check('every step starts as "not run"', function () {
    verdictsBefore.forEach(function (text) {
      assert.strictEqual(text, 'not run',
          'A step shows "' + text + '" before the run started.');
    });
  });
  const summary = await clickAndWait(driver, "btn_scim_run",
      "scim_scenario_status", "as planned", 180000);
  check('the whole scenario runs and every step goes as planned', function () {
    assert.ok(/as planned/.test(summary), 'The run said: ' + summary);
    assert.ok(!/ 0 as planned/.test(summary),
        'Zero steps went as planned: ' + summary);
  });
  const verdicts = await driver.executeScript(`
    var rows = document.querySelectorAll('#scim_runner_table tbody tr');
    var out = [];
    for (var i = 0; i < rows.length; i++) {
      out.push({ step: rows[i].cells[1].textContent.slice(0, 60),
                 result: rows[i].cells[4].textContent,
                 verdict: rows[i].cells[5].textContent });
    }
    return out;
  `);
  check('the progress table filled in, step by step', function () {
    const notRun = verdicts.filter(function (row) {
      return row.verdict === 'not run';
    });
    assert.strictEqual(notRun.length, 0,
        notRun.length + ' step(s) never ran: ' +
        notRun.map(function (row) {
          return row.step;
        }).join('; '));
  });
  check('the failures, if any, name what was expected', function () {
    const failed = verdicts.filter(function (row) {
      return row.verdict !== 'as planned';
    });
    assert.strictEqual(failed.length, 0,
        failed.length + ' step(s) did not go as planned: ' +
        failed.map(function (row) {
          return row.step + ' -> ' + row.result + ' (' + row.verdict + ')';
        }).join(' | '));
  });
  check('an id captured by a create reached a later step', function () {
    // The membership PATCH is addressed by the group id the create returned,
    // and the remove is addressed by a user id. If references did not resolve
    // those steps would have been SKIPPED rather than run.
    const membership = verdicts.filter(function (row) {
      return /Add all/.test(row.step);
    })[0];
    assert.ok(membership, 'The membership step is not in the table.');
    assert.notStrictEqual(membership.verdict, 'skipped',
        'The membership PATCH was skipped, which means the group id ' +
        'captured by the create never reached it — so no scenario with more ' +
        'than one step actually works.');
  });
  log.debug("Leaving aScenarioRunsEndToEnd().");
}

async function aNegativeScenarioFinishesGreen(driver) {
  log.debug("Entering aNegativeScenarioFinishesGreen().");
  log.info("6b. A scenario whose steps expect refusals.");
  await setField(driver, "scim_scenario_seed", prefix + "-neg");
  await setField(driver, "scim_scenario_prefix", prefix + "neg");
  await driver.executeScript(`
    var select = document.getElementById('scim_scenario');
    select.value = 'negatives';
    select.dispatchEvent(new Event('change'));
  `);
  const summary = await clickAndWait(driver, "btn_scim_run",
      "scim_scenario_status", "as planned", 120000);
  const verdicts = await driver.executeScript(`
    var rows = document.querySelectorAll('#scim_runner_table tbody tr');
    var out = [];
    for (var i = 0; i < rows.length; i++) {
      out.push({ step: rows[i].cells[1].textContent.slice(0, 70),
                 expected: rows[i].cells[3].textContent,
                 result: rows[i].cells[4].textContent,
                 verdict: rows[i].cells[5].textContent });
    }
    return out;
  `);
  check('a REFUSAL is recorded as a pass where the plan expected one',
      function () {
    const duplicate = verdicts.filter(function (row) {
      return /same userName/.test(row.step);
    })[0];
    assert.ok(duplicate, 'The duplicate-userName step is not in the table.');
    assert.ok(/409/.test(duplicate.result),
        'The duplicate create answered ' + duplicate.result +
        ' and 409 was expected.');
    assert.strictEqual(duplicate.verdict, 'as planned',
        'A 409 on a duplicate userName is what this scenario EXPECTS, and ' +
        'it is recorded as ' + duplicate.verdict + '. A runner that showed ' +
        'what came back rather than judging it against the plan would call ' +
        'this a failure — and would call a 201 on a duplicate a success, ' +
        'which is exactly backwards.');
  });
  check('the whole negatives scenario finishes green', function () {
    const failed = verdicts.filter(function (row) {
      return row.verdict !== 'as planned';
    });
    assert.strictEqual(failed.length, 0,
        failed.length + ' step(s) of the negatives scenario did not go as ' +
        'planned: ' + failed.map(function (row) {
          return row.step + ' expected ' + row.expected + ', got ' +
              row.result;
        }).join(' | ') + '. Summary: ' + summary);
  });
  log.debug("Leaving aNegativeScenarioFinishesGreen().");
}

// ---------------------------------------------------------------------------
// 6c. THE DISCOVERY PANE'S TWO VIEWS.
//
// A discovery document is read for two different reasons and one rendering
// cannot serve both: nine times in ten what is wanted is "where do Users live
// and does this server do PATCH", and the tenth time it is "show me exactly
// what it said", because somebody is arguing about it. So the pane has a
// Described tab over a table and a Document tab over the bytes, and BOTH are
// kept — the table is a reading of the document, and hiding the original would
// make a disagreement between the two undiscoverable.
//
// The endpoint in that table is the one row that is not merely informative:
// the page composes its requests onto it. See section 6d.
// ---------------------------------------------------------------------------
async function theDiscoveryPaneHasBothViews(driver) {
  log.debug("Entering theDiscoveryPaneHasBothViews().");
  log.info("6c. The discovery pane's Described and Document tabs.");
  await clickAndWait(driver, "btn_scim_resource_types",
      "scim_discovery_status", null);
  const described = await driver.executeScript(`
    var rows = document.querySelectorAll('#scim_capabilities tr');
    var out = [];
    for (var i = 0; i < rows.length; i++) {
      var cells = rows[i].cells, line = [];
      for (var c = 0; c < cells.length; c++) {
        line.push(cells[c].textContent);
      }
      out.push(line.join(' | '));
    }
    return out;
  `);
  check('a ResourceTypes document is TABULATED and not only dumped',
      function () {
    const text = described.join('\n');
    assert.ok(described.length >= 2,
        'The described view has ' + described.length + ' row(s). Finding an ' +
        'endpoint in a nested ListResponse is a scroll and a squint, which ' +
        'is the whole reason this tab exists.');
    assert.ok(/Endpoint/i.test(text),
        'The table has no Endpoint column. /Users and /Groups are ' +
        'CONVENTIONS — RFC 7643 section 6 has each ResourceType publish its ' +
        'own endpoint — and that column is the one this page acts on. Got: ' +
        text.slice(0, 300));
    assert.ok(/User/.test(text) && /Group/.test(text),
        'The table names neither User nor Group. Got: ' + text.slice(0, 300));
  });
  // The other tab, and the panel switch that goes with it.
  await driver.findElement(By.id("scim_tab_discovery_document")).click();
  const tabs = await driver.executeScript(`
    var out = { document: '', described: '', text: '' };
    var panels = document.querySelectorAll('.scim-tabpanel');
    for (var i = 0; i < panels.length; i++) {
      out[panels[i].getAttribute('data-scim-tab')] =
        panels[i].className.indexOf('scim-tabpanel-off') < 0 ? 'on' : 'off';
    }
    out.text = document.getElementById('scim_discovery_output').value || '';
    out.buttonOn = document.getElementById('scim_tab_discovery_document')
      .className.indexOf('scim-tab-on') >= 0;
    return out;
  `);
  check('the Document tab shows the bytes the server actually sent',
      function () {
    assert.strictEqual(tabs.document, 'on',
        'Pressing the Document tab did not show its panel.');
    assert.strictEqual(tabs.described, 'off',
        'Both panels are showing at once, which reads as the tab strip ' +
        'having no effect. Source order decides display between ' +
        '.scim-tabpanel and .scim-tabpanel-off — both selectors are (0,1,0).');
    assert.ok(tabs.buttonOn,
        'The panel switched and the tab strip did not follow it.');
    assert.ok(/"Resources"|"schemas"|endpoint/i.test(tabs.text),
        'The Document panel is empty or does not hold the document. It has ' +
        'to be a TEXTAREA read by .value: assigning textContent to one works ' +
        'exactly once, and a readout that silently stops updating still ' +
        'shows the right text in an inspector. Got: ' +
        String(tabs.text).slice(0, 200));
  });
  await driver.findElement(By.id("scim_tab_discovery_described")).click();
  log.debug("Leaving theDiscoveryPaneHasBothViews().");
}

// ---------------------------------------------------------------------------
// 6d. THE CONFIGURATION PARAMETERS PANE.
//
// One table holding every setting this workflow has, with the SOURCE of each —
// which is the question it exists to answer, because a value somebody typed
// and a value read out of a discovery document behave identically until the
// server changes its mind.
//
// Three things are asserted and each is a way the pane could be decorative
// rather than real:
//
//   * it MIRRORS the fields in the other panes rather than copying them, in
//     both directions. A "central settings pane" that is a second store is a
//     second store to drift;
//   * a discovered endpoint is APPLIED — the request the page would compose
//     changes with it. That is the row the page acts on, and a settings pane
//     implying it applies a value it does not is worse than no pane, because
//     it makes the server's 404 look like a bug here;
//   * NO CREDENTIAL is in it. The password is never written anywhere and the
//     token has its own opt-in one pane up; a settings table that quietly
//     became the fourth place a bearer token is written would defeat that
//     opt-in without changing a word of it.
// ---------------------------------------------------------------------------
async function theConfigurationPaneCentralizesTheSettings(driver) {
  log.debug("Entering theConfigurationPaneCentralizesTheSettings().");
  log.info("6d. The Configuration Parameters pane.");
  const present = await driver.executeScript(`
    var out = { rows: [], missing: [] };
    var wanted = ['baseUrl', 'sslValidate', 'callPath', 'authScheme',
                  'authUsername', 'authRealm', 'userEndpoint',
                  'groupEndpoint', 'patchSupported', 'bulkMaxOperations',
                  'filterSupported', 'challengeSchemes', 'genSeed',
                  'scenarioPrefix'];
    for (var i = 0; i < wanted.length; i++) {
      if (!document.getElementById('scim_cfg_' + wanted[i])) {
        out.missing.push(wanted[i]);
      }
    }
    var controls = document.querySelectorAll('#scim_config input,' +
        ' #scim_config select');
    for (var c = 0; c < controls.length; c++) {
      out.rows.push(controls[c].id);
    }
    return out;
  `);
  check('every parameter this workflow has is in one table', function () {
    assert.deepStrictEqual(present.missing, [],
        'These parameters have no row: ' + present.missing.join(', ') + '. ' +
        'A pane that centralizes SOME of the settings leaves the reader ' +
        'hunting for the rest in exactly the panes it was meant to replace.');
  });
  // The credential check is about VALUES and not about the names somebody
  // happened to choose for the rows — a table with a row called `secret` and
  // one called `apiKey` would pass a name-based check perfectly. So a
  // distinctive credential goes into the Authentication pane first and the
  // whole table is then searched for it. (A name check on its own also has a
  // false positive waiting in it: `changePassword.supported` is a
  // ServiceProviderConfig capability and contains the word `password`.)
  const marker = 'never-in-the-config-pane-' + stamp;
  await driver.executeScript(`
    var select = document.getElementById('scim_auth_scheme');
    select.value = 'basic';
    select.dispatchEvent(new Event('change'));
  `);
  await setField(driver, "scim_auth_password", marker);
  await setField(driver, "scim_auth_token", marker + '-token');
  const leaked = await driver.executeScript(`
    var out = { values: [], named: [] };
    var controls = document.querySelectorAll('#scim_config input,' +
        ' #scim_config select');
    for (var i = 0; i < controls.length; i++) {
      if (String(controls[i].value).indexOf(arguments[0]) >= 0) {
        out.values.push(controls[i].id);
      }
    }
    var forbidden = ['authPassword', 'password', 'authToken', 'token',
                     'hobaPrivateKey', 'privateKey'];
    for (var f = 0; f < forbidden.length; f++) {
      if (document.getElementById('scim_cfg_' + forbidden[f])) {
        out.named.push(forbidden[f]);
      }
    }
    return out;
  `, marker);
  check('no credential is in that table', function () {
    assert.deepStrictEqual(leaked.values, [],
        'The credential typed into the Authentication pane is showing in ' +
        'these configuration rows: ' + leaked.values.join(', ') + '.');
    assert.deepStrictEqual(leaked.named, [],
        'These credential rows exist in the configuration table: ' +
        leaked.named.join(', ') + '. The password is never written anywhere ' +
        'and the access token is governed by its own opt-in checkbox in the ' +
        'Authentication pane — a settings table that became a fourth place ' +
        'one is written would defeat that opt-in without changing a word of ' +
        'it.');
  });
  await setField(driver, "scim_auth_token", "");
  await useRunCredential(driver, 'after the credential check');
  // Two-way: the config table drives the field, and the field drives it back.
  await driver.executeScript(`
    var e = document.getElementById('scim_cfg_authRealm');
    e.value = 'REALM-FROM-THE-CONFIG-PANE';
    e.dispatchEvent(new Event('change'));
  `);
  const forward = await textOf(driver, "scim_auth_realm");
  check('editing a row edits the field it mirrors', function () {
    assert.strictEqual(forward, 'REALM-FROM-THE-CONFIG-PANE',
        'The Authentication pane\'s realm still says "' + forward + '". A ' +
        'settings pane whose values do not reach the request is a settings ' +
        'pane nobody can trust.');
  });
  await setField(driver, "scim_auth_realm", "REALM-FROM-THE-FIELD");
  const back = await driver.executeScript(
      "return document.getElementById('scim_cfg_authRealm').value;");
  check('editing the field edits the row, so there is one value and not two',
      function () {
    assert.strictEqual(back, 'REALM-FROM-THE-FIELD',
        'The configuration row still says "' + back + '", so it is a COPY ' +
        'of the field rather than a view of it — and a copy is a thing to ' +
        'drift.');
  });
  await setField(driver, "scim_auth_realm", "SCIM");
  // The discovered endpoint, and the fact that the page composes onto it.
  // The wanted text is the SUCCESS sentence and not the word "Read": the
  // failure message is "The documents could not all be read", which a /Read/
  // match would settle on happily.
  await clickAndWait(driver, "btn_scim_config_read_all", "scim_config_status",
      "Read\\. Every row", 60000);
  const discovered = await driver.executeScript(`
    return { user: document.getElementById('scim_cfg_userEndpoint').value,
             group: document.getElementById('scim_cfg_groupEndpoint').value,
             patch: document.getElementById('scim_cfg_patchSupported').value,
             schemas: document.getElementById('scim_cfg_schemaIds').value };
  `);
  check('reading the three documents fills the discovered rows', function () {
    // What is asserted is that the row names the type, not the exact string:
    // the endpoint is the SERVER's to choose and a test that pinned it to
    // /Users would be asserting the convention this whole row exists to stop
    // the page assuming. That it is APPLIED is the check below.
    assert.ok(/Users/i.test(discovered.user),
        'The User endpoint row says "' + discovered.user + '" after the ' +
        'ResourceTypes document was read. A discovered row that stays empty ' +
        'is a row nobody will notice is not being applied.');
    assert.ok(/Groups/i.test(discovered.group),
        'The Group endpoint row says "' + discovered.group + '".');
    assert.ok(/^(yes|no)$/.test(discovered.patch),
        'patch.supported says "' + discovered.patch + '" rather than yes or ' +
        'no, so the ServiceProviderConfig was not read into the table.');
    assert.ok(discovered.schemas.indexOf('urn:ietf:params:scim:schemas') >= 0,
        'The schema list is "' + discovered.schemas.slice(0, 120) + '".');
  });
  // Override it, and assert the REQUEST changes — not the table.
  await driver.executeScript(`
    var e = document.getElementById('scim_cfg_userEndpoint');
    e.value = '/people';
    e.dispatchEvent(new Event('change'));
    var op = document.getElementById('scim_op');
    op.value = 'listUsers';
    op.dispatchEvent(new Event('change'));
  `);
  const overridden = await driver.executeScript(`
    var built = window.scim.currentRequest();
    return { url: built.ok ? built.request.url : ('(not built: ' +
                 built.error + ')'),
             endpoints: JSON.stringify(window.scim.endpointsForRequests()),
             marked: !!document.querySelector(
                 '#scim_cfg_row_userEndpoint .scim-config-overridden'),
             was: (document.querySelector(
                 '#scim_cfg_row_userEndpoint .scim-config-was') || {})
                 .textContent || '' };
  `);
  check('an overridden endpoint changes the URL the page would send',
      function () {
    assert.ok(/\/people(\?|$)/.test(overridden.url),
        'The request the page would send is ' + overridden.url + '. /Users ' +
        'is a CONVENTION: a server publishing /people in its ResourceTypes ' +
        'is conformant, and a client that hard codes the convention meets ' +
        'it with a 404 on every operation — a failure that names an id ' +
        'nobody has rather than a path nobody serves.');
    assert.ok(overridden.endpoints.indexOf('/people') >= 0,
        'endpointsForRequests() says ' + overridden.endpoints);
  });
  check('an override is visibly an override, with what the server said beside '
      + 'it', function () {
    assert.ok(overridden.marked,
        'The overridden row is not marked. A parameter that no longer ' +
        'matches the server is the one that will produce the next ' +
        'inexplicable 404, and it has to look different from one that does.');
    assert.ok(/\/Users/.test(overridden.was),
        'The row does not say what the server had said, so the override ' +
        'has replaced the original rather than sitting over it. It says: "' +
        overridden.was + '"');
  });
  // And Restore puts it back — a "you can override this" affordance with no
  // way back is a trap rather than a feature.
  await clickAndWait(driver, "btn_scim_config_restore", "scim_config_status",
      null);
  const restored = await driver.executeScript(
      "return document.getElementById('scim_cfg_userEndpoint').value;");
  check('Restore puts a discovered row back to what the server said',
      function () {
    assert.strictEqual(restored, discovered.user,
        'The endpoint is "' + restored + '" after Restore and the server ' +
        'had said "' + discovered.user + '". An override with no way back ' +
        'is a trap rather than a feature.');
  });
  // Save, reload, and the value has to still be there — the pane's button
  // says Save and this is the whole of what that means.
  await driver.executeScript(`
    var e = document.getElementById('scim_cfg_groupEndpoint');
    e.value = '/teams';
    e.dispatchEvent(new Event('change'));
  `);
  await driver.findElement(By.id("btn_scim_config_save")).click();
  await driver.navigate().refresh();
  await waitForPageBundle(driver, "the SCIM page");
  const survived = await driver.executeScript(
      "return document.getElementById('scim_cfg_groupEndpoint').value;");
  check('a saved parameter survives a reload', function () {
    assert.strictEqual(survived, '/teams',
        'The saved value is "' + survived + '" after a reload, so Save ' +
        'applied it and did not persist it.');
  });
  // Leave the page as the rest of this run expects to find it — the sections
  // after this one send real requests, and a Group endpoint left at /teams
  // would 404 every one of them with a message about an id.
  await driver.executeScript(`
    var e = document.getElementById('scim_cfg_groupEndpoint');
    e.value = arguments[0];
    e.dispatchEvent(new Event('change'));
  `, discovered.group);
  await setField(driver, "scim_base_url", scimBaseUrl);
  log.debug("Leaving theConfigurationPaneCentralizesTheSettings().");
}

// ---------------------------------------------------------------------------
// 7. WHAT THE PAGE REMEMBERS — invisible from anywhere but a browser.
// ---------------------------------------------------------------------------
async function credentialsAreNotRemembered(driver) {
  log.debug("Entering credentialsAreNotRemembered().");
  log.info("7. What the page remembers.");
  await driver.executeScript(`
    var select = document.getElementById('scim_auth_scheme');
    select.value = 'basic';
    select.dispatchEvent(new Event('change'));
  `);
  await setField(driver, "scim_auth_username", "alice");
  await setField(driver, "scim_auth_password", "s3cr3t-never-stored");
  await driver.executeScript("window.scim.saveState();");
  const afterPassword = await driver.executeScript(`
    var out = {};
    for (var i = 0; i < localStorage.length; i++) {
      var key = localStorage.key(i);
      out[key] = localStorage.getItem(key);
    }
    return out;
  `);
  check('the password is NEVER written to localStorage', function () {
    const leaked = Object.keys(afterPassword).filter(function (key) {
      return String(afterPassword[key]).indexOf('s3cr3t-never-stored') >= 0;
    });
    assert.deepStrictEqual(leaked, [],
        'The password reached localStorage under: ' + leaked.join(', ') +
        '. That is the project-wide rule and there is no opt-in for it — ' +
        'there is no case where keeping one here is worth it.');
  });
  check('the username IS remembered, so the rule is about credentials rather '
      + 'than about this pane', function () {
    assert.strictEqual(afterPassword.scim_auth_username, 'alice',
        'Nothing at all was remembered, so the check above passes vacuously.');
  });
  // The token: opt-IN, and clearing the box purges.
  await driver.executeScript(`
    var select = document.getElementById('scim_auth_scheme');
    select.value = 'bearer';
    select.dispatchEvent(new Event('change'));
  `);
  await setField(driver, "scim_auth_token", "token-abc-123");
  await setCheckbox(driver, "scim_save_token", false);
  const withoutBox = await driver.executeScript(
      "window.scim.saveState(); " +
      "return localStorage.getItem('scim_auth_token');");
  check('the access token is NOT stored by default', function () {
    assert.strictEqual(withoutBox, null,
        'The token was stored with the box clear. This is an opt-IN rather ' +
        'than the key-pair panes\' opt-OUT because the trade is different: ' +
        'a bearer token is pasted once and expires anyway.');
  });
  await setCheckbox(driver, "scim_save_token", true);
  const withBox = await driver.executeScript(
      "window.scim.saveState(); " +
      "return localStorage.getItem('scim_auth_token');");
  check('ticking the box stores it', function () {
    assert.strictEqual(withBox, 'token-abc-123',
        'The box was ticked and nothing was stored, so the option does ' +
        'nothing.');
  });
  await setCheckbox(driver, "scim_save_token", false);
  const purged = await driver.executeScript(
      "window.scim.saveState(); " +
      "return localStorage.getItem('scim_auth_token');");
  check('CLEARING the box purges what was already stored', function () {
    assert.strictEqual(purged, null,
        'Yesterday\'s token survived the box being cleared. An opt-out that ' +
        'leaves the credential in storage is not an opt-out — which is why ' +
        'the purge lives in saveState() rather than only in the change ' +
        'handler, so no code path can leave one behind.');
  });
  await driver.navigate().refresh();
  await waitForPageBundle(driver, "the SCIM page");
  const remembered = await textOf(driver, "scim_base_url");
  check('the service root survives a reload', function () {
    assert.strictEqual(remembered, scimBaseUrl,
        'The service root was not remembered, so every reload starts from ' +
        'an empty page.');
  });
  const tokenAfterReload = await textOf(driver, "scim_auth_token");
  check('the token does not come back after a reload with the box clear',
      function () {
    assert.strictEqual(tokenAfterReload, '',
        'The token reappeared: "' + tokenAfterReload + '".');
  });
  log.debug("Leaving credentialsAreNotRemembered().");
}

// ---------------------------------------------------------------------------
// 7b. THE EXCHANGE PANE: the headers, and staying inside the pane.
//
// TWO THINGS, AND THE SECOND ONE IS A REGRESSION TEST FOR A LAYOUT BUG THAT
// COULD NOT BE SEEN UNTIL SOMETHING LONG CAME BACK.
//
// The readouts here used to be `pre` elements with `overflow: auto` and a
// max-height, which is the obvious shape and does not work inside a
// `fieldset`. A pre's min-content width is its longest line; a SCIM response
// is full of percent-encoded DNs, Location URLs and base64 certificates with
// no space in them; and a fieldset carries `min-inline-size: min-content` in
// the UA stylesheet. So the PANE was made wide enough to avoid the overflow
// and the `overflow: auto` never scrolled anything — measured on the page
// before this change, one long id took the Exchange pane to 7511px and the
// document to 7627px in a 1400px viewport.
//
// Section 8's existing "the page does not scroll sideways" check could not see
// it, and that is the point worth keeping: by the time it runs, this file has
// deleted what it created and every readout holds a short body or nothing.
// A geometry check that only ever measures an empty box measures nothing, so
// this one PLANTS the pathological value first.
// ---------------------------------------------------------------------------
const A_LONG_UNBROKEN_ID =
    'uid%3Dalice%2Cou%3Dusers%2Cdc%3Dexample%2Cdc%3Dcom'.repeat(20);

async function theExchangePaneShowsHeadersAndStaysInside(driver) {
  log.debug("Entering theExchangePaneShowsHeadersAndStaysInside().");
  log.info("7b. The Exchange pane.");
  await useRunCredential(driver, 'for the exchange section');
  await driver.executeScript(`
    var select = document.getElementById('scim_op');
    select.value = 'listUsers';
    select.dispatchEvent(new Event('change'));
    document.getElementById('scim_query_count').value = '1';
  `);
  await clickAndWait(driver, "btn_scim_send", "scim_op_status", null);
  const headers = await driver.executeScript(`
    return { request: document.getElementById('scim_exchange_request_headers')
               .value || '',
             response: document.getElementById('scim_exchange_response_headers')
               .value || '' };
  `);
  check('the request headers are shown in WIRE form, not as JSON', function () {
    assert.ok(/^\s*Accept:\s*application\/scim\+json\s*$/m
        .test(headers.request),
        'The request headers box says: ' + headers.request.slice(0, 200) +
        '. What a reader compares these against is a header in an RFC, a ' +
        'curl -v transcript or a server log, and none of those is quoted, ' +
        'braced or comma-separated — a JSON object of headers has to be ' +
        'translated in the head before it can be compared with any of them.');
  });
  check('the response headers are shown too', function () {
    assert.ok(/:/.test(headers.response) && headers.response.trim() !== '',
        'The response headers box is empty. A browser-direct call can only ' +
        'read the seven simple headers unless the server exposes more, and ' +
        'the pane says so — but "restricted" is not "none". It says: ' +
        headers.response.slice(0, 200));
  });
  // Now the pathological body, planted rather than waited for.
  const geometry = await driver.executeScript(`
    var ids = ['scim_exchange_request_headers',
               'scim_exchange_response_headers',
               'scim_exchange_request_body', 'scim_exchange_response_body',
               'scim_op_result', 'scim_discovery_output'];
    for (var i = 0; i < ids.length; i++) {
      document.getElementById(ids[i]).value =
        'Location: http://h/scim/v2/Users/' + arguments[0] + '\\n' +
        JSON.stringify({ id: arguments[0] }, null, 2);
    }
    var box = document.getElementById('scim_exchange_response_body');
    var pane = document.getElementById('pane_exchange');
    return { doc: document.documentElement.scrollWidth,
             win: window.innerWidth,
             paneWidth: Math.round(pane.getBoundingClientRect().width),
             boxRight: Math.round(box.getBoundingClientRect().right),
             paneRight: Math.round(pane.getBoundingClientRect().right),
             scrollW: box.scrollWidth, clientW: box.clientWidth };
  `, A_LONG_UNBROKEN_ID);
  check('a response with no space in it does not push the pane past the page',
      function () {
    assert.ok(geometry.doc <= geometry.win + 2,
        'With one long unbroken id in the readouts the document is ' +
        geometry.doc + 'px wide in a ' + geometry.win + 'px viewport and ' +
        'the Exchange pane is ' + geometry.paneWidth + 'px. That is the ' +
        'fieldset\'s min-inline-size: min-content pulling the pane out to ' +
        'the width of the longest line — every max-width, overflow and ' +
        'word-break inside it is powerless until the pane itself is allowed ' +
        'to shrink.');
    assert.ok(geometry.boxRight <= geometry.paneRight + 2,
        'The readout ends at ' + geometry.boxRight + 'px and its pane at ' +
        geometry.paneRight + 'px, so the text is outside the pane it ' +
        'belongs to.');
  });
  check('it scrolls INSIDE its own box instead', function () {
    assert.ok(geometry.scrollW > geometry.clientW + 50,
        'The readout is ' + geometry.clientW + 'px wide and its content ' +
        'scrolls to ' + geometry.scrollW + 'px — if those were equal the ' +
        'content would have been allowed to size the box, which is the ' +
        'failure this check exists for rather than the fix.');
  });
  // The Expand button: the boxes are deliberately small, so there has to be a
  // way to open one without dragging it.
  const expanded = await driver.executeScript(`
    var box = document.getElementById('scim_exchange_response_body');
    var before = Math.round(box.getBoundingClientRect().height);
    document.getElementById('btn_scim_expand_response_body').click();
    var after = Math.round(box.getBoundingClientRect().height);
    var label = document.getElementById('btn_scim_expand_response_body').value;
    document.getElementById('btn_scim_expand_response_body').click();
    return { before: before, after: after, label: label,
             back: Math.round(box.getBoundingClientRect().height),
             backLabel:
               document.getElementById('btn_scim_expand_response_body').value };
  `);
  check('Expand opens a readout and closes it again', function () {
    assert.ok(expanded.after > expanded.before + 100,
        'Expand took the box from ' + expanded.before + 'px to ' +
        expanded.after + 'px, which is not an expansion.');
    assert.strictEqual(expanded.label, 'Collapse',
        'The button still says "' + expanded.label + '" after expanding, so ' +
        'nothing on screen says how to put it back.');
    assert.strictEqual(expanded.back, expanded.before,
        'Collapsing left the box at ' + expanded.back + 'px rather than the ' +
        expanded.before + 'px it started at.');
    assert.strictEqual(expanded.backLabel, 'Expand');
  });
  log.debug("Leaving theExchangePaneShowsHeadersAndStaysInside().");
}

// ---------------------------------------------------------------------------
// 8a. THE COLLAPSING PANES, AND THE ONE SWITCH OVER ALL OF THEM.
//
// The page uses the same `.dbg-*` chrome as every other workflow here: a
// `div.dbg-pane` holding a `.dbg-legend` title and the `fieldset` that title
// collapses, plus one toggle at the top that does all of them at once.
//
// THREE THINGS, AND EACH FAILS SILENTLY ON ITS OWN.
//
//   * The legend and the fieldset are paired BY CONVENTION —
//     `x_expand_button` drives `x_fieldset` — rather than by an inline
//     onclick repeating the id. A drifted pair is a title that does nothing at
//     all, which looks exactly like a title nobody thought to make clickable.
//     wirePanes() warns about one, and section 9 asserts the console is clean,
//     so this section checks the other half: that a click actually collapses.
//   * setAllPanes() DISCOVERS the fieldsets rather than listing them, so a
//     pane added later is covered by construction. The check therefore counts
//     what it collapsed against the panes on the page — a hard-coded list
//     that had fallen one behind would still pass a "the toggle works" test
//     written against one pane.
//   * The triangle is drawn by `:has(fieldset[style*="display: none"])` in
//     css/debugger.css, which reads the INLINE style. A pane whose markup
//     carries no inline `display` would show an expanded triangle over a pane
//     the toggle had never touched, so the indicator is read from
//     `::before` rather than assumed from the fieldset.
//
// The panes are left EXPANDED at the end: every section after this one
// measures geometry inside them, and a collapsed fieldset has no geometry.
// ---------------------------------------------------------------------------
async function thePanesCollapseAndOneSwitchDoesThemAll(driver) {
  log.debug("Entering thePanesCollapseAndOneSwitchDoesThemAll().");
  log.info("8a. The collapsing panes.");
  const start = await driver.executeScript(`
    var panes = document.querySelectorAll('.dbg-pane fieldset');
    var open = 0;
    for (var i = 0; i < panes.length; i++) {
      if (panes[i].style.display !== 'none') { open += 1; }
    }
    var legends = document.querySelectorAll('.dbg-legend');
    var unpaired = [];
    for (var j = 0; j < legends.length; j++) {
      var id = legends[j].id || '';
      var body = id.replace('_expand_button', '_fieldset');
      if (id.indexOf('_expand_button') === -1 ||
          !document.getElementById(body)) {
        unpaired.push(id || '(no id)');
      }
    }
    return { panes: panes.length, open: open, legends: legends.length,
             unpaired: unpaired,
             toggle: !!document.getElementById('dbg_toggle_all') };
  `);
  check('every pane has a title paired with it, and all of them start open',
      function () {
    assert.ok(start.panes >= 8,
        'Only ' + start.panes + ' collapsing panes are on the page, so this ' +
        'check is close to vacuous — the markup has stopped matching ' +
        '.dbg-pane fieldset.');
    assert.strictEqual(start.legends, start.panes,
        'There are ' + start.legends + ' titles and ' + start.panes +
        ' panes, so one of them is on its own.');
    assert.deepStrictEqual(start.unpaired, [],
        'These titles name no fieldset: ' + start.unpaired.join(', ') + '. ' +
        'The pairing is `x_expand_button` drives `x_fieldset`, and a drifted ' +
        'pair is a title that does nothing at all, with nothing on the ' +
        'page saying so.');
    assert.strictEqual(start.open, start.panes,
        'Only ' + start.open + ' of ' + start.panes + ' panes are open on ' +
        'arrival. The page opens expanded: somebody who has just chosen this ' +
        'workflow has not asked for ten closed boxes.');
    assert.ok(start.toggle, 'There is no dbg_toggle_all on the page.');
  });
  // One title, clicked for real rather than through the module — the handler
  // is added by the bundle, so a click is the only thing that proves it ran.
  const one = await driver.findElement(By.id('connection_expand_button'));
  await one.click();
  const closed = await driver.executeScript(`
    var f = document.getElementById('connection_fieldset');
    var lg = document.getElementById('connection_expand_button');
    return { display: f.style.display,
             triangle: window.getComputedStyle(lg, '::before').content,
             cursor: window.getComputedStyle(lg).cursor };
  `);
  await one.click();
  const reopened = await driver.executeScript(
      "return document.getElementById('connection_fieldset').style.display;");
  check("clicking a pane's title collapses it, and the triangle turns",
      function () {
    assert.strictEqual(closed.display, 'none',
        'The Connection fieldset is display:' + closed.display + ' after a ' +
        'click on its title, so nothing is wired to it.');
    assert.ok(closed.triangle.indexOf('\u25b8') >= 0,
        'The collapsed pane\'s title still draws ' + closed.triangle +
        ' rather than a right-pointing triangle. That indicator is a ' +
        ':has() rule reading the INLINE display, so this is what fails when ' +
        'a pane is collapsed by some other means than the inline style.');
    assert.strictEqual(closed.cursor, 'pointer',
        'The title\'s cursor is ' + closed.cursor + ', so nothing on screen ' +
        'says it can be clicked.');
    assert.notStrictEqual(reopened, 'none',
        'A second click left the pane collapsed, so the title only closes.');
  });
  // And the switch, over all of them at once.
  const afterCollapse = await driver.executeScript(`
    document.querySelector('.dbg-toggle-slider').click();
    var panes = document.querySelectorAll('.dbg-pane fieldset');
    var hidden = 0;
    for (var i = 0; i < panes.length; i++) {
      if (panes[i].style.display === 'none') { hidden += 1; }
    }
    return { hidden: hidden, total: panes.length,
             text: document.querySelector('.dbg-toggle-text').textContent,
             checked: document.getElementById('dbg_toggle_all').checked };
  `);
  const afterExpand = await driver.executeScript(`
    document.querySelector('.dbg-toggle-slider').click();
    var panes = document.querySelectorAll('.dbg-pane fieldset');
    var open = 0;
    for (var i = 0; i < panes.length; i++) {
      if (panes[i].style.display !== 'none') { open += 1; }
    }
    return { open: open, total: panes.length,
             text: document.querySelector('.dbg-toggle-text').textContent };
  `);
  check('the one switch collapses and expands EVERY pane', function () {
    assert.strictEqual(afterCollapse.hidden, afterCollapse.total,
        'The switch collapsed ' + afterCollapse.hidden + ' of ' +
        afterCollapse.total + ' panes. setAllPanes() reads the fieldsets off ' +
        'the DOM precisely so that it cannot fall behind the markup; a ' +
        'shortfall here means it has started working from a list.');
    assert.strictEqual(afterCollapse.checked, false,
        'The switch is still on after collapsing everything.');
    assert.strictEqual(afterCollapse.text, 'Expand all panes',
        'The switch still reads "' + afterCollapse.text + '" over ten ' +
        'collapsed panes, so the only control that can reopen them is ' +
        'labelled as the thing that closed them.');
    assert.strictEqual(afterExpand.open, afterExpand.total,
        'Only ' + afterExpand.open + ' of ' + afterExpand.total +
        ' panes came back.');
    assert.strictEqual(afterExpand.text, 'Collapse all panes');
  });
  log.debug("Leaving thePanesCollapseAndOneSwitchDoesThemAll().");
}

// ---------------------------------------------------------------------------
// 8d. THE FOLDED PROSE, AND THE ONE BLOCK THAT MUST NOT FOLD.
//
// The explanations on this page are the reason the workflow is worth using,
// so they are folded rather than cut — `details.scim-more`, the same shape the
// Kerberos pages use. Two properties, and the second is the one worth a test.
//
// Every fold starts CLOSED: a `details` that shipped `open` is prose back on
// the page, which is the state this change exists to leave behind.
//
// And the sentence saying these endpoints delete accounts is NOT inside one.
// A safety notice that can be collapsed out of sight is a safety notice
// somebody will not have read, so it stays in the warning box with only the
// elaboration folded beneath it. That is asserted by reading the warning's own
// text with its `details` subtracted — a check written against the whole box
// would pass with the sentence moved inside the fold.
// ---------------------------------------------------------------------------
async function theProseFoldsAndTheWarningDoesNot(driver) {
  log.debug("Entering theProseFoldsAndTheWarningDoesNot().");
  log.info("8d. The folded prose.");
  const folds = await driver.executeScript(`
    var all = document.querySelectorAll('details.scim-more');
    var out = { count: all.length, open: [], noSummary: [] };
    for (var i = 0; i < all.length; i++) {
      var summary = all[i].querySelector('summary');
      if (all[i].open) {
        out.open.push((summary ? summary.textContent : '').slice(0, 40));
      }
      if (!summary || !summary.textContent.trim()) {
        out.noSummary.push(i);
      }
    }
    var warning = document.querySelector('.scim-warning');
    var clone = warning.cloneNode(true);
    var inner = clone.querySelectorAll('details');
    for (var j = 0; j < inner.length; j++) {
      inner[j].parentNode.removeChild(inner[j]);
    }
    out.warningOutsideTheFold =
      clone.textContent.replace(/\\s+/g, ' ').trim();
    return out;
  `);
  check('every block of prose is folded, closed, and has a summary',
      function () {
    assert.ok(folds.count >= 8,
        'Only ' + folds.count + ' folded blocks are on the page, so this ' +
        'check is close to vacuous — the prose has gone back to being ' +
        'unfoldable paragraphs, or the class has been renamed.');
    assert.deepStrictEqual(folds.open, [],
        'These folds ship open: ' + folds.open.join(' | ') + '. A `details` ' +
        'with the open attribute is prose back on the page.');
    assert.deepStrictEqual(folds.noSummary, [],
        'Folds at these indexes have no summary text, so they are a ' +
        'triangle with nothing beside it: ' + folds.noSummary.join(', '));
  });
  check('the sentence about deleting accounts is NOT inside a fold',
      function () {
    assert.ok(/create and delete\s+accounts/i
        .test(folds.warningOutsideTheFold),
        'With its folds removed the warning box reads: "' +
        folds.warningOutsideTheFold + '". The sentence saying these ' +
        'endpoints create and delete accounts has moved inside a `details`, ' +
        'and a warning that can be collapsed out of sight is one somebody ' +
        'will not have read.');
  });
  log.debug("Leaving theProseFoldsAndTheWarningDoesNot().");
}

// ---------------------------------------------------------------------------
// 8b. THE TOP ROW IS ONE ROW.
//
// Connection, Authentication and Discovery are not steps — they are the
// settings every pane below them reads — so they sit across the top rather
// than stacked, and the Configuration Parameters pane sits under all three.
// Asserted by GEOMETRY rather than by the presence of a class, because a grid
// that has silently fallen back to one column still has every class it had.
// ---------------------------------------------------------------------------
async function theTopRowIsOneRow(driver) {
  log.debug("Entering theTopRowIsOneRow().");
  log.info("8b. The top row.");
  await driver.manage().window().setRect({ width: 1400, height: 1000 });
  const boxes = await driver.executeScript(`
    var wanted = ['pane_connection', 'pane_auth', 'pane_discovery',
                  'pane_config'];
    var out = {};
    for (var i = 0; i < wanted.length; i++) {
      var e = document.getElementById(wanted[i]);
      if (!e) { out[wanted[i]] = null; continue; }
      var b = e.getBoundingClientRect();
      out[wanted[i]] = { top: Math.round(b.top + window.scrollY),
                         left: Math.round(b.left),
                         width: Math.round(b.width) };
    }
    return out;
  `);
  check('Connection, Authentication and Discovery are on one row', function () {
    ['pane_connection', 'pane_auth', 'pane_discovery'].forEach(function (id) {
      assert.ok(boxes[id], 'There is no ' + id + ' on the page.');
    });
    const tops = ['pane_connection', 'pane_auth', 'pane_discovery']
      .map(function (id) {
        return boxes[id].top;
      });
    assert.ok(Math.max.apply(null, tops) - Math.min.apply(null, tops) <= 4,
        'The three panes start at ' + tops.join(', ') + 'px, so they are ' +
        'stacked rather than side by side — which is what a grid looks like ' +
        'when it has fallen back to one column, with every class still in ' +
        'place.');
    assert.ok(boxes.pane_connection.left < boxes.pane_auth.left &&
        boxes.pane_auth.left < boxes.pane_discovery.left,
        'The three are on one row and out of order: ' +
        boxes.pane_connection.left + ', ' + boxes.pane_auth.left + ', ' +
        boxes.pane_discovery.left + '.');
  });
  check('the Configuration Parameters pane spans the row beneath them',
      function () {
    assert.ok(boxes.pane_config.top > boxes.pane_discovery.top,
        'The configuration pane is not below the top row.');
    assert.ok(boxes.pane_config.width > boxes.pane_connection.width * 2,
        'The configuration pane is ' + boxes.pane_config.width + 'px wide ' +
        'against a top-row pane\'s ' + boxes.pane_connection.width + 'px, so ' +
        'it is in the grid rather than under it.');
  });
  log.debug("Leaving theTopRowIsOneRow().");
}

// ---------------------------------------------------------------------------
// 8c. EVERY FIELD HAS A TOOLTIP, AND NO TOOLTIP CAN EVER TAKE A CLICK.
//
// The tooltips are what let this page's prose come down to a few sentences per
// pane, so a field without one has simply lost its documentation.
//
// THE SECOND HALF IS THE ONE THAT HAS COST RUNS ELSEWHERE IN THIS TREE.
// bootstrap hides `.tooltiptext` with `visibility: hidden` and NOT with
// `display: none`, so the span still occupies layout and the browser will
// report it as the topmost element at a nearby control's position — which
// Selenium raises as `element click intercepted: ... <span
// class="tooltiptext">`, at coordinates that look perfectly correct in a
// screenshot. `pointer-events: none` is what prevents it, in css/common.css
// and again in css/scim.css.
//
// A test that merely clicked the buttons would pass whether or not that rule
// were there, because a tooltip is only over a control while something is
// hovering it. So this one MAKES EVERY TOOLTIP VISIBLE FIRST and then asks the
// browser what is on top of each button — which fails if the rule is removed,
// and is the difference between testing the fix and testing the weather.
// ---------------------------------------------------------------------------
async function tooltipsAreEverywhereAndCannotTakeAClick(driver) {
  log.debug("Entering tooltipsAreEverywhereAndCannotTakeAClick().");
  log.info("8c. Tooltips.");
  const documented = await driver.executeScript(`
    var out = { fields: 0, missing: [], inert: true, notInert: [] };
    var controls = document.querySelectorAll(
        '.scim-pane input, .scim-pane select, .scim-pane textarea');
    for (var i = 0; i < controls.length; i++) {
      var e = controls[i];
      // Buttons carry a title rather than a hover tooltip (a tooltip over the
      // thing you are about to click is the interception hazard below), and a
      // status line is an output rather than a field. The radios are covered
      // by the tooltip on the label they live inside.
      if (e.type === 'button' || e.type === 'radio') { continue; }
      if (e.className.indexOf('scim-status') >= 0) { continue; }
      out.fields += 1;
      // Three shapes, and each is the markup as written rather than a loose
      // search: a wide net here would let a NEIGHBOUR's tooltip stand in for
      // a missing one, which is how this check would come to pass vacuously.
      //   1. the label wrapper or the box header immediately BEFORE it;
      //   2. an ancestor that is itself the tooltip (a checkbox inside its
      //      own label);
      //   3. the configuration table's row, where the tooltip is on the
      //      parameter's name in the first cell.
      var before = e.previousElementSibling;
      var described = !!(before && (before.querySelector('.tooltiptext') ||
          (before.className &&
           String(before.className).indexOf('tooltiptext') >= 0)));
      var wrapper = e.parentNode;
      while (!described && wrapper && wrapper !== document.body) {
        if (wrapper.className &&
            String(wrapper.className).indexOf('tooltip') >= 0 &&
            wrapper.querySelector('.tooltiptext')) {
          described = true;
        }
        if (wrapper.tagName === 'TR' && wrapper.querySelector('.tooltiptext')) {
          described = true;
        }
        wrapper = wrapper.parentNode;
      }
      if (!described && !e.getAttribute('title')) {
        out.missing.push(e.id || e.name || e.tagName);
      }
    }
    var tips = document.querySelectorAll('.tooltiptext');
    for (var t = 0; t < tips.length; t++) {
      if (window.getComputedStyle(tips[t]).pointerEvents !== 'none') {
        out.inert = false;
        out.notInert.push(tips[t].textContent.slice(0, 40));
      }
    }
    out.tips = tips.length;
    return out;
  `);
  check('every field on the page carries a tooltip', function () {
    assert.ok(documented.fields >= 20,
        'Only ' + documented.fields + ' fields were examined, so this check ' +
        'is close to vacuous — the selector has stopped matching.');
    assert.deepStrictEqual(documented.missing, [],
        'These fields have no tooltip and no title: ' +
        documented.missing.join(', ') + '. The tooltips are what let this ' +
        'page\'s prose come down to a few sentences per pane, so a field ' +
        'without one has lost its documentation rather than merely its ' +
        'decoration.');
  });
  check('no tooltip is a pointer target', function () {
    assert.ok(documented.tips >= 20,
        'Only ' + documented.tips + ' tooltips are on the page.');
    assert.ok(documented.inert,
        'These tooltips have pointer-events other than none: ' +
        documented.notInert.join(' | ') + '. bootstrap hides .tooltiptext ' +
        'with visibility:hidden rather than display:none, so the span still ' +
        'occupies layout and becomes the topmost element at a nearby ' +
        'control\'s position — "element click intercepted", at coordinates ' +
        'that look correct in a screenshot.');
  });
  // Now the adversarial half: every tooltip visible at once, and then ask the
  // browser what is on top of each button. Undone at the end, because the
  // stylesheet check that follows measures the page's width.
  const shadowed = await driver.executeScript(`
    var style = document.createElement('style');
    style.id = 'scim-tooltip-stress';
    style.textContent = '.tooltiptext { visibility: visible !important;' +
        ' opacity: 1 !important; }';
    document.head.appendChild(style);
    var out = [];
    var buttons = document.querySelectorAll(
        '.scim-btn, .scim-tab, input[type="checkbox"], select');
    for (var i = 0; i < buttons.length; i++) {
      var e = buttons[i];
      var b = e.getBoundingClientRect();
      if (b.width === 0 || b.height === 0) { continue; }
      e.scrollIntoView({ block: 'center' });
      b = e.getBoundingClientRect();
      var top = document.elementFromPoint(b.left + b.width / 2,
                                          b.top + b.height / 2);
      if (top && top !== e && !e.contains(top) &&
          top.className && String(top.className).indexOf('tooltiptext') >= 0) {
        out.push((e.id || e.value || e.tagName) + ' is under "' +
            top.textContent.slice(0, 40) + '"');
      }
    }
    return out;
  `);
  check('with EVERY tooltip on screen at once, none of them covers a control',
      function () {
    assert.deepStrictEqual(shadowed, [],
        'These controls are behind a tooltip: ' + shadowed.join('; ') + '. ' +
        'This is the state a Selenium click puts the page in — the mouse ' +
        'moves to the control and whatever it passes over on the way lights ' +
        'up — and it is where "element click intercepted" comes from.');
  });
  // And a real click on each of the buttons a test presses, in that state.
  const clicks = [];
  for (const id of ['btn_scim_spc', 'btn_scim_resource_types',
                    'btn_scim_schemas', 'btn_scim_probe_auth',
                    'btn_scim_config_save', 'btn_scim_config_restore',
                    'btn_scim_gen_users', 'btn_scim_plan',
                    'scim_tab_discovery_document',
                    'scim_tab_discovery_described']) {
    try {
      const element = await driver.findElement(By.id(id));
      await driver.executeScript(
          "arguments[0].scrollIntoView({ block: 'center' });", element);
      await element.click();
    } catch (e) {
      clicks.push(id + ': ' + e.message.split("\n")[0]);
    }
  }
  check('and every button a test presses is still clickable in it',
      function () {
    assert.deepStrictEqual(clicks, [],
        'These clicks were refused with every tooltip visible: ' +
        clicks.join('; ') + '.');
  });
  await driver.executeScript(`
    var style = document.getElementById('scim-tooltip-stress');
    if (style) { style.parentNode.removeChild(style); }
  `);
  log.debug("Leaving tooltipsAreEverywhereAndCannotTakeAClick().");
}

// ---------------------------------------------------------------------------
// 8. THE PAGE ITSELF: its stylesheet, and a clean console.
// ---------------------------------------------------------------------------
async function everyStyleClassIsDefined(driver) {
  log.debug("Entering everyStyleClassIsDefined().");
  log.info("8. The page's own stylesheet.");
  const missing = await driver.executeScript(`
    var defined = {};
    for (var s = 0; s < document.styleSheets.length; s++) {
      var rules;
      try { rules = document.styleSheets[s].cssRules; } catch (e) { continue; }
      if (!rules) { continue; }
      for (var r = 0; r < rules.length; r++) {
        var selector = rules[r].selectorText || '';
        var found = selector.match(/\\.scim-[a-zA-Z0-9-]+/g) || [];
        for (var f = 0; f < found.length; f++) {
          defined[found[f].slice(1)] = true;
        }
      }
    }
    var used = {};
    var all = document.querySelectorAll('*');
    for (var i = 0; i < all.length; i++) {
      var classes = (all[i].className || '');
      if (typeof classes !== 'string') { continue; }
      var parts = classes.split(/\\s+/);
      for (var p = 0; p < parts.length; p++) {
        if (parts[p].indexOf('scim-') === 0) { used[parts[p]] = true; }
      }
    }
    var out = [];
    for (var name in used) {
      if (used.hasOwnProperty(name) && !defined[name]) { out.push(name); }
    }
    return out;
  `);
  check('every scim- class the page uses is defined in css/scim.css',
      function () {
    assert.deepStrictEqual(missing, [],
        'These classes are used and undefined: ' + missing.join(', ') + '. ' +
        'This guard exists because the WS-Federation pages once linked the ' +
        'WRONG stylesheet after a rename and rendered completely unstyled — ' +
        'the link resolved, so nothing 404\'d and nothing noticed.');
  });
  const pageWidth = await driver.executeScript(`
    return { doc: document.documentElement.scrollWidth,
             win: window.innerWidth };
  `);
  check('the page does not scroll sideways', function () {
    assert.ok(pageWidth.doc <= pageWidth.win + 2,
        'The document is ' + pageWidth.doc + 'px wide in a ' +
        pageWidth.win + 'px viewport. A SCIM id is a percent-encoded DN — a ' +
        'long unbroken string with no space in it — and bootstrap\'s ' +
        '`code { white-space: nowrap }` plus an auto-layout table is exactly ' +
        'how one of them pushes a pane past the edge.');
  });
  log.debug("Leaving everyStyleClassIsDefined().");
}

async function theConsoleIsClean(driver) {
  log.debug("Entering theConsoleIsClean().");
  log.info("9. The browser console.");
  const entries = await driver.manage().logs().get("browser");
  const severe = entries.filter(function (entry) {
    if (entry.level.name !== "SEVERE") {
      return false;
    }
    // A favicon 404 is the server's business and not this page's, and a
    // deliberate 4xx from the negatives scenario is the POINT of that
    // scenario — Chrome logs every non-2xx fetch as SEVERE, so those are not
    // page errors. What this check is for is a ReferenceError or a failed
    // require, which name neither.
    const text = String(entry.message);
    if (/favicon/.test(text)) {
      return false;
    }
    if (/Failed to load resource/.test(text)) {
      return false;
    }
    return true;
  });
  check('no page error reached the browser console', function () {
    assert.deepStrictEqual(severe.map(function (entry) {
      return entry.message.slice(0, 200);
    }), [],
        'A SEVERE console entry that is not a network status is a script ' +
        'error, and the ones this suite has seen name a page and a line ' +
        'deep inside a bundle rather than themselves.');
  });
  log.debug("Leaving theConsoleIsClean().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1000");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    await openPage(driver);
    const present = await theServerIsThere(driver);
    if (!present.present) {
      log.warn("SKIPPED: " + present.why);
      log.info("Test completed successfully (skipped).");
      return;
    }
    await useRunCredential(driver, 'for the sections that send');
    await everyEndpointComposes(driver);
    await theBrowserCreatesAndDeletes(driver);
    await theBackendPathAlsoWorks(driver);
    await everySchemeIsOfferedAndExplained(driver);
    await theDpopProofIsMintedInTheBrowser(driver);
    await theHobaKeyIsGeneratedAndSigns(driver);
    await aScenarioRunsEndToEnd(driver);
    await aNegativeScenarioFinishesGreen(driver);
    await theDiscoveryPaneHasBothViews(driver);
    await theConfigurationPaneCentralizesTheSettings(driver);
    await credentialsAreNotRemembered(driver);
    await theExchangePaneShowsHeadersAndStaysInside(driver);
    await thePanesCollapseAndOneSwitchDoesThemAll(driver);
    await theProseFoldsAndTheWarningDoesNot(driver);
    await theTopRowIsOneRow(driver);
    await tooltipsAreEverywhereAndCannotTakeAClick(driver);
    await everyStyleClassIsDefined(driver);
    await theConsoleIsClean(driver);
    log.info(checks + " checks passed.");
    if (skips.length) {
      log.warn(skips.length + " section(s) skipped:");
      skips.forEach(function (why) {
        log.warn("  - " + why);
      });
    }
    assert.ok(checks >= 59,
        'Only ' + checks + ' checks ran; a section has stopped being called.');
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("scim_page")
  .description("Verify the SCIM page: the browser call path that the hosted " +
      "site depends on, the DPoP proof and HOBA key it signs with Web " +
      "Crypto, the two schemes that lock the call path, the scenario runner " +
      "end to end, and what it does and does not write to localStorage.")
  .addOption(new Option("-u, --url <url>",
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
