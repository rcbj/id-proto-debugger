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
async function waitForStatus(driver, id, wanted, timeoutMs) {
  log.debug("Entering waitForStatus(). id=" + id);
  const deadline = Date.now() + (timeoutMs || 30000);
  let last = "";
  while (Date.now() < deadline) {
    last = await textOf(driver, id);
    if (String(last).trim() !== "" &&
        (!wanted || new RegExp(wanted, "i").test(last))) {
      log.debug("Leaving waitForStatus(). " + last.slice(0, 120));
      return last;
    }
    await driver.sleep(250);
  }
  log.debug("Leaving waitForStatus(). Timed out.");
  throw new Error("the status field " + id + " never said " +
      (wanted || "anything") + "; it says: " + String(last).slice(0, 400));
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
  await driver.findElement(By.id("btn_scim_spc")).click();
  const status = await waitForStatus(driver, "scim_discovery_status", null);
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
      out.push(rows[i].cells[0].textContent + '=' + rows[i].cells[1].textContent);
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
  await driver.findElement(By.id("btn_scim_send")).click();
  const status = await waitForStatus(driver, "scim_op_status", null, 30000);
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
  await driver.findElement(By.id("btn_scim_send")).click();
  const readStatus = await waitForStatus(driver, "scim_op_status", null);
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
  await driver.findElement(By.id("btn_scim_send")).click();
  const deleteStatus = await waitForStatus(driver, "scim_op_status", null);
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
  await driver.findElement(By.id("btn_scim_send")).click();
  const status = await waitForStatus(driver, "scim_op_status", null);
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
  await driver.findElement(By.id("btn_scim_send")).click();
  await waitForStatus(driver, "scim_op_status", null, 30000);
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
  await driver.findElement(By.id("btn_scim_hoba_generate")).click();
  const status = await waitForStatus(driver, "scim_hoba_status", null, 60000);
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
      if (value.indexOf('PRIVATE KEY') >= 0 || key.indexOf('hoba_private') >= 0) {
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
  await driver.executeScript(`
    var select = document.getElementById('scim_auth_scheme');
    select.value = 'none';
    select.dispatchEvent(new Event('change'));
  `);
  await setField(driver, "scim_scenario_seed", prefix + "-run");
  await setField(driver, "scim_scenario_prefix", prefix + "run");
  await setField(driver, "scim_scenario_count", "3");
  await driver.executeScript(`
    var select = document.getElementById('scim_scenario');
    select.value = 'provision-team';
    select.dispatchEvent(new Event('change'));
  `);
  await driver.findElement(By.id("btn_scim_plan")).click();
  const planned = await waitForStatus(driver, "scim_scenario_status", null);
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
  await driver.findElement(By.id("btn_scim_run")).click();
  const summary = await waitForStatus(driver, "scim_scenario_status",
      "as planned", 180000);
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
  await driver.findElement(By.id("btn_scim_run")).click();
  const summary = await waitForStatus(driver, "scim_scenario_status",
      "as planned", 120000);
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
    await everyEndpointComposes(driver);
    await theBrowserCreatesAndDeletes(driver);
    await theBackendPathAlsoWorks(driver);
    await everySchemeIsOfferedAndExplained(driver);
    await theDpopProofIsMintedInTheBrowser(driver);
    await theHobaKeyIsGeneratedAndSigns(driver);
    await aScenarioRunsEndToEnd(driver);
    await aNegativeScenarioFinishesGreen(driver);
    await credentialsAreNotRemembered(driver);
    await everyStyleClassIsDefined(driver);
    await theConsoleIsClean(driver);
    log.info(checks + " checks passed.");
    if (skips.length) {
      log.warn(skips.length + " section(s) skipped:");
      skips.forEach(function (why) {
        log.warn("  - " + why);
      });
    }
    assert.ok(checks >= 40,
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
