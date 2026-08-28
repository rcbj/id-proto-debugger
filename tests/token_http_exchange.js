// File: token_http_exchange.js
//
// ---------------------------------------------------------------------------
// The HTTP tab on the token exchange pane (oauth2_oidc_2.html): the request and
// the response as they actually went, rather than as the pane described them
// beforehand.
//
// What makes this worth a test of its own is that the interesting half of it
// cannot be observed by the page at all. This workflow's default is to have the
// **api** call the token endpoint — a great many identity providers refuse a
// browser-origin Token Request — so the request that matters is made by
// another process, and the only reason the browser can show it is that the api
// hands back what it saw under `http_exchange` (api/server.js, and its
// buildHttpTrace(), switched on per call by `http_trace: true`). Every link in
// that chain fails SILENTLY if it breaks: the pane keeps rendering, and it
// shows the browser's own call to the api instead — a perfectly
// plausible-looking HTTP exchange with the wrong URL in it. So this asserts
// that the URL shown is the token ENDPOINT, and that the note names the end
// that made the call.
//
// It covers FOUR panes, because a reader meets this exchange in four states.
// The request form has the tab it was composed on — but a successful call
// COLLAPSES that form, so the pane actually on screen afterwards is the Token
// Endpoint Results one, which carries the same exchange under a tab of its
// own. They share one view and one renderer (renderHttpExchange() draws into
// every host a channel has), and a shared renderer whose second host is
// missing draws nothing and says nothing, which is why the second pane is
// asserted here rather than assumed to follow from the first. Three of the
// four are BUILT AS A STRING by oauth2_oidc_2.js rather than being in the
// page, so each one's tab is attached to whatever was just built — including
// on a page LOAD, where the tokens come back from localStorage and the pane
// has to say which generation's exchange to go and look at.
//
// The third and fourth are newer than the rest of this file and are what it
// grew for. The **Currently Viewing** pane draws the exchange KEPT WITH THE
// GENERATION the Token History pane has activated — read back out of
// `token_history`, which is the one path here that can break without either
// live pane noticing, since it is fed by a JSON document rather than by the
// ajax handler that just ran. And the **refresh** panes carry a channel of
// their own; this grant returns no refresh token, so what is asserted here is
// that channel's empty state, and `tests/oidc_authorization_code.js` makes a
// real Refresh Request and asserts the exchange.
//
// WHICH BRINGS UP THE THING THIS FILE REVERSED. It used to assert that
// NOTHING about the exchange reached localStorage — the request repeats a
// client secret and carries an Authorization header built out of it. The
// exchange is now kept, so that assertion became an assertion about
// REDACTION: what is stored is the whole exchange with the credential-bearing
// header and parameter VALUES replaced, the live panes are checked to be
// unredacted, and the client secret is looked for in the raw stored document
// rather than field by field — a secret copied into a field nobody thought to
// check is exactly the failure that is for.
//
// It uses the Client Credentials grant because the pane and the handler are the
// same for every grant this page sends and that one needs no login — the
// exchange it produces is the exchange an authorization code produces, minus a
// browser round trip through Keycloak. `tests/oauth2_authorization_code.js` and
// `tests/oidc_authorization_code.js` cover the code grant's own path to this
// pane.
//
// The second thing it asserts is LAYOUT, and it is asserted with real content
// rather than an empty pane: this pane is one narrow column of a three-column
// row and what it shows is other people's bytes — a 3,000-character header
// value, a JWT with no break opportunity in it, an HTML error page where JSON
// was expected. An empty pane fits inside anything. See
// `docs/sd-jwt-vc-issuance.md` on measuring a pane populated.
// ---------------------------------------------------------------------------
const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'token_http_exchange',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const { addBrowserAccessFlags } = require("./browser_flags.js");
const { clickStable, populateMetadata, getAccessTokenClientCredentials } =
       require("../common/tests.js")({ By, until, Select, waitTime, log, jwt,
       assert });

// Read the whole of the tab: its label, the text of the panel behind it, and
// the two class attributes that say which panel is displayed.
async function readHttpTab(driver) {
  log.debug("Entering readHttpTab().");
  // NOTE: the function below is serialized and evaluated IN THE BROWSER, where
  // there is no bunyan and no `log` — see the repo-root CLAUDE.md. It and
  // everything it declares are exempt from the Entering/Leaving convention.
  const state = await driver.executeScript(function () {
    // textContent rather than innerText: innerText is what a reader SEES,
    // so it is empty for anything inside a collapsed fieldset — and this is
    // read both before the pane has been opened and after a successful call
    // has collapsed it again.
    function textOf(id) {
      var el = document.getElementById(id);
      return el ? el.textContent : null;
    }
    function classOf(id) {
      var el = document.getElementById(id);
      return el ? el.className : null;
    }
    return {
      label: textOf("token_tab_http"),
      formTabClass: classOf("token_tab_form"),
      httpTabClass: classOf("token_tab_http"),
      formPanelClass: classOf("token_tabpanel_form"),
      httpPanelClass: classOf("token_tabpanel_http"),
      panel: textOf("token_http_exchange"),
      tokenEndpoint: (document.getElementById("token_endpoint") || {}).value,
      // Which end this build makes the call from. Read off the page rather
      // than assumed: a static deployment has no api, so oauth2_oidc_2.js
      // disables the back-end radio and the call is made from the browser.
      fromBackEnd: !!(document.getElementById("token_initiateFromBackEnd") ||
          {}).checked,
      backEndOffered: !(document.getElementById("token_initiateFromBackEnd") ||
          {}).disabled,
      // Nothing about the exchange may be persisted: it repeats a client
      // secret, an Authorization header and, on the password grant, a
      // password.
      storage: JSON.stringify(window.localStorage)
    };
  });
  log.debug("Leaving readHttpTab(). label=" + state.label);
  return state;
}

// Everything the panel draws must stay inside the pane's border, and nothing in
// it may make the page scroll sideways.
async function measureHttpPanel(driver) {
  log.debug("Entering measureHttpPanel().");
  // NOTE: browser-side, as above. No `log` in here.
  const geometry = await driver.executeScript(function () {
    var pane = document.getElementById("step3");
    var host = document.getElementById("token_http_exchange");
    if (!pane || !host) {
      return null;
    }
    var paneRect = pane.getBoundingClientRect();
    var outside = [];
    var nodes = host.querySelectorAll("*");
    for (var i = 0; i < nodes.length; i++) {
      var rect = nodes[i].getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) {
        continue;
      }
      if (rect.right > paneRect.right + 1 || rect.left < paneRect.left - 1) {
        outside.push((nodes[i].className || nodes[i].tagName) + " spans " +
            Math.round(rect.left) + "-" + Math.round(rect.right) +
            ", the pane spans " + Math.round(paneRect.left) + "-" +
            Math.round(paneRect.right));
      }
    }
    return {
      outside: outside,
      hostScrollWidth: host.scrollWidth,
      hostClientWidth: host.clientWidth,
      paneHeight: Math.round(paneRect.height),
      bodyScrollWidth: document.body.scrollWidth,
      bodyClientWidth: document.body.clientWidth
    };
  });
  log.debug("Leaving measureHttpPanel(). " +
            (geometry ? geometry.outside.length + " element(s) outside." :
                "no pane."));
  return geometry;
}

// Read the Token Endpoint Results pane's tab: its label, the two panel class
// attributes, the text behind the HTTP tab, and whether the tokens the pane
// exists for survived being wrapped in a tab panel.
async function readResultTab(driver) {
  log.debug("Entering readResultTab().");
  // NOTE: browser-side, as above. No `log` in here — see the repo-root
  // CLAUDE.md. This function and everything it declares are exempt from the
  // Entering/Leaving convention.
  const state = await driver.executeScript(function () {
    function textOf(id) {
      var el = document.getElementById(id);
      return el ? el.textContent : null;
    }
    function classOf(id) {
      var el = document.getElementById(id);
      return el ? el.className : null;
    }
    var access = document.getElementById("token_access_token");
    return {
      present: !!document.getElementById("token_result_tab_http"),
      label: textOf("token_result_tab_http"),
      tokensPanelClass: classOf("token_result_tabpanel_tokens"),
      httpPanelClass: classOf("token_result_tabpanel_http"),
      panel: textOf("token_result_http_exchange"),
      // The pane's own content, after the wrap. A tab that cost the reader
      // the tokens would be a worse pane than the one without a tab.
      accessTokenLength: access && access.value ? access.value.length : 0,
      accessTokenVisible: !!(access && access.offsetParent),
      // How many strips are on it. The pane is rebuilt after every call and
      // the tab is re-attached after every rebuild; two strips driving one
      // panel is what a non-idempotent attach looks like.
      strips: document.querySelectorAll(
          "#token_endpoint_result .dbg-tabs").length
    };
  });
  log.debug("Leaving readResultTab(). label=" + state.label);
  return state;
}

// Read the Currently Viewing pane's tab, which is the third pane carrying one
// and the only one whose exchange did not happen on this page load: it is
// read back out of the activated generation's `token_history` entry.
async function readViewingTab(driver) {
  log.debug("Entering readViewingTab().");
  // NOTE: browser-side, as above. No `log` in here.
  const state = await driver.executeScript(function () {
    function textOf(id) {
      var el = document.getElementById(id);
      return el ? el.textContent : null;
    }
    function classOf(id) {
      var el = document.getElementById(id);
      return el ? el.className : null;
    }
    var access = document.getElementById("cv_access_token");
    return {
      present: !!document.getElementById("cv_tab_http"),
      label: textOf("cv_tab_http"),
      tokensPanelClass: classOf("cv_tabpanel_tokens"),
      httpPanelClass: classOf("cv_tabpanel_http"),
      panel: textOf("cv_http_exchange"),
      accessTokenLength: access && access.value ? access.value.length : 0,
      strips: document.querySelectorAll(
          "#currently-viewing-panel .dbg-tabs").length
    };
  });
  log.debug("Leaving readViewingTab(). label=" + state.label);
  return state;
}

// The generations in `token_history`, and the exchange kept with each. Read as
// the raw string as well, because the assertion that matters most about it is
// that a credential is NOT anywhere in it — and looking for one field at a
// time is how a copy in another field is missed.
async function readStoredHistory(driver) {
  log.debug("Entering readStoredHistory().");
  const raw = await driver.executeScript(
      "return localStorage.getItem('token_history');");
  var parsed = [];
  try {
    parsed = JSON.parse(raw || "[]");
  } catch (e) {
    log.error("token_history is not JSON: " + e.message);
    parsed = [];
  }
  log.debug("Leaving readStoredHistory(). " + parsed.length +
            " generation(s).");
  return { raw: raw || "", entries: parsed };
}

// Nothing the results pane's HTTP panel draws may leave the pane, and it may
// not make the page scroll sideways. Measured with the exchange in it, for the
// reason the pane above is: an empty panel fits inside anything.
async function measureResultPanel(driver) {
  log.debug("Entering measureResultPanel().");
  // NOTE: browser-side, as above. No `log` in here.
  const geometry = await driver.executeScript(function () {
    var host = document.getElementById("token_result_http_exchange");
    var pane = host ? host.closest("fieldset") : null;
    if (!host || !pane) {
      return null;
    }
    var paneRect = pane.getBoundingClientRect();
    var outside = [];
    var nodes = host.querySelectorAll("*");
    for (var i = 0; i < nodes.length; i++) {
      var rect = nodes[i].getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) {
        continue;
      }
      if (rect.right > paneRect.right + 1 || rect.left < paneRect.left - 1) {
        outside.push((nodes[i].className || nodes[i].tagName) + " spans " +
            Math.round(rect.left) + "-" + Math.round(rect.right) +
            ", the pane spans " + Math.round(paneRect.left) + "-" +
            Math.round(paneRect.right));
      }
    }
    return {
      outside: outside,
      hostScrollWidth: host.scrollWidth,
      hostClientWidth: host.clientWidth,
      bodyScrollWidth: document.body.scrollWidth,
      bodyClientWidth: document.body.clientWidth
    };
  });
  log.debug("Leaving measureResultPanel().");
  return geometry;
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  // A fixed window, because part of what is asserted here is geometry.
  options.addArguments("--window-size=1366,768");
  addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    log.info("Starting Test run.");
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    assert(discovery_endpoint,
           "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");

    await driver.get(baseUrl + "/oauth2_oidc_1.html");
    await populateMetadata(driver, discovery_endpoint);

    // Selecting the grant lands on oauth2_oidc_2.html with the exchange pane
    // open. Assert the tab's state BEFORE anything is sent: an empty panel
    // behind a tab is indistinguishable from a tab that does not work, and a
    // test that only ever looks after a successful call cannot tell the
    // difference either.
    await new Select(await driver.findElement(
        By.id("authorization_grant_type")))
        .selectByVisibleText('OAuth2 Client Credential');
    await driver.wait(until.elementLocated(By.id("token_tab_http")), waitTime);
    await driver.wait(until.elementIsVisible(
        driver.findElement(By.id("token_tab_http"))), waitTime);
    const before = await readHttpTab(driver);
    log.info("Before the call: label=" + before.label);
    assert.strictEqual(before.label, "HTTP",
      "Before a Token Request the HTTP tab should be labelled \"HTTP\" and " +
      "reads \"" + before.label + "\".");
    assert.strictEqual(before.formPanelClass, "dbg-tabpanel",
      "The Parameters panel should be the one displayed when the pane opens, " +
      "and its class is \"" + before.formPanelClass + "\".");
    assert.strictEqual(before.httpPanelClass, "dbg-tabpanel dbg-tabpanel-off",
      "The HTTP panel should start hidden, and its class is \"" +
      before.httpPanelClass + "\".");
    assert.ok(/no Token Request has been sent/i.test(before.panel || ""),
      "The HTTP panel should say that nothing has been sent yet. It reads: " +
      JSON.stringify((before.panel || "").slice(0, 200)));

    // The exchange itself. This asserts a token came back, which is what makes
    // everything below an assertion about a REAL exchange rather than about a
    // pane drawn from an error.
    const access_token = await getAccessTokenClientCredentials(driver,
        client_id, client_secret, scope);
    assert.ok(access_token && access_token.indexOf("status:") !== 0,
      "The Client Credentials call did not return a token: " +
      String(access_token).slice(0, 300));

    // A successful call collapses this pane, which is the behaviour the tab
    // was designed around: it is the reason the HTTP tab is never selected by
    // code, and the reason its LABEL carries the status. Re-open the pane the
    // way a reader does — by clicking its title — and then click the tab.
    // clickStable(), because this page rebuilds its panes after every token
    // call and after each write to Operations History — see tests/CLAUDE.md.
    await clickStable(driver, By.id("token_expand_button"),
                      "the exchange pane's title");
    await clickStable(driver, By.id("token_tab_http"), "the HTTP tab");
    const after = await readHttpTab(driver);
    log.info("After the call: label=" + after.label);
    log.info("Panel:\n" + after.panel);

    assert.strictEqual(after.httpPanelClass, "dbg-tabpanel",
      "Clicking the HTTP tab should display its panel; its class is \"" +
      after.httpPanelClass + "\".");
    assert.strictEqual(after.formPanelClass, "dbg-tabpanel dbg-tabpanel-off",
      "Displaying the HTTP panel should hide the Parameters one; its class " +
      "is \"" + after.formPanelClass + "\".");
    assert.ok(/^HTTP · 2\d\d$/.test(after.label || ""),
      "After a successful exchange the tab label should carry the status " +
      "(\"HTTP · 200\"), and it reads \"" + after.label + "\".");

    const panel = after.panel || "";

    // WHICH END made the call, and the URL that proves it. On the api-backed
    // stacks this is the whole point: the request shown must be the api's call
    // to the TOKEN ENDPOINT, not the browser's call to the api. Read off the
    // page rather than assumed, because a static deployment has no api and
    // makes the call from the browser.
    if (after.fromBackEnd) {
      assert.ok(/Sent by the api on this browser's behalf/.test(panel),
        "The call was initiated from the back end, so the panel should say " +
        "the api made it. It reads: " + JSON.stringify(panel.slice(0, 300)));
    } else {
      log.info("This build calls the token endpoint from the browser " +
               "(backEndOffered=" + after.backEndOffered + "), so the " +
               "browser-observed view is the one asserted.");
      assert.ok(/Sent by this browser/.test(panel),
        "The call was initiated from the front end, so the panel should say " +
        "so. It reads: " + JSON.stringify(panel.slice(0, 300)));
    }

    // The five things the tab exists to show, plus the time.
    assert.ok(after.tokenEndpoint,
      "The page has no token endpoint value to compare the panel against.");
    assert.ok(panel.indexOf("POST " + after.tokenEndpoint) !== -1,
      "The panel should show the METHOD and the URL of the token endpoint (" +
      "POST " + after.tokenEndpoint + "). It reads: " +
      JSON.stringify(panel.slice(0, 400)));
    assert.ok(/content-type/i.test(panel),
      "The panel should list the request headers, and no content-type " +
      "appears in it.");
    assert.ok(/application\/x-www-form-urlencoded/i.test(panel),
      "The panel should show the form encoding the Token Request was sent " +
      "with.");
    assert.ok(/grant_type=client_credentials/.test(panel),
      "The panel should show the request BODY, which for this grant carries " +
      "grant_type=client_credentials.");
    assert.ok(/HTTP 2\d\d/.test(panel),
      "The panel should show the response status line.");
    assert.ok(/access_token/.test(panel),
      "The panel should show the response BODY, which carries the " +
      "access_token.");

    // The elapsed time, as a number rather than as the word "ms": a label with
    // nothing in front of it is exactly the failure this line is for.
    const elapsed = panel.match(/:\s*(\d+)\s*ms/);
    assert.ok(elapsed, "The panel should report how long the response took, " +
      "as a number of milliseconds. Its Timing section reads: " +
      JSON.stringify((panel.match(/Timing[\s\S]*/) || [""])[0].slice(0, 200)));
    log.info("Reported elapsed time: " + elapsed[1] + " ms.");
    assert.ok(Number(elapsed[1]) >= 0 && Number(elapsed[1]) < 600000,
      "The reported elapsed time is not a plausible number of " +
      "milliseconds: " + elapsed[1]);

    // ---------------------------------------------------------------------
    // WHAT WAS WRITTEN DOWN, which is the half of this that reversed.
    //
    // Until this build nothing about the exchange was persisted, and this
    // asserted exactly that. It is now kept beside the tokens in
    // `token_history`, so that the Currently Viewing pane can show the call
    // that produced whichever generation the reader activated — and the
    // assertion has to move with it rather than be deleted, because the
    // reason it existed has not gone away. What is stored is a REDACTED copy:
    // the method, the URL, the status, the timing, every non-credential
    // header and the response body verbatim, and every credential-bearing
    // value replaced.
    //
    // The check on the credential is made against the RAW string rather than
    // field by field. A secret that has been copied into a field nobody
    // thought to look at is exactly the failure this is for, and a per-field
    // check cannot see one.
    // ---------------------------------------------------------------------
    const stored = await readStoredHistory(driver);
    log.info("token_history holds " + stored.entries.length +
             " generation(s); " + stored.entries.filter(
                 (e) => !!e.http_exchange).length + " carry an exchange.");
    assert.ok(stored.entries.length > 0,
      "The token call should have written a generation to token_history, " +
      "and it holds none. Everything below reads that generation.");
    const keptExchange =
        stored.entries[stored.entries.length - 1].http_exchange;
    assert.ok(keptExchange,
      "The exchange should now be KEPT with the token set it produced, and " +
      "the newest generation carries none. The Currently Viewing pane's " +
      "HTTP tab has nothing to show without it.");
    log.info("Stored request: " + keptExchange.request.method + " " +
             keptExchange.request.url);
    assert.ok(keptExchange.request.url === after.tokenEndpoint,
      "The stored exchange should name the token ENDPOINT (" +
      after.tokenEndpoint + "), and it names " + keptExchange.request.url +
      ". The api's trace is what carries the endpoint; storing the " +
      "browser's call to the api instead is a plausible-looking exchange " +
      "with the wrong URL in it.");
    assert.ok(keptExchange.response &&
              /^2\d\d$/.test(String(keptExchange.response.status)),
      "The stored exchange should carry the response status.");
    assert.ok(/access_token/.test((keptExchange.response || {}).body || ""),
      "The stored exchange should carry the response BODY verbatim — that " +
      "is what is NOT redacted, and the point of keeping it.");
    assert.ok(/grant_type=client_credentials/.test(
                  keptExchange.request.body || ""),
      "The stored request body should be kept apart from its credentials, " +
      "and grant_type is gone from it: " +
      JSON.stringify(keptExchange.request.body));

    // The credential itself, three ways, against the whole document.
    assert.ok(stored.raw.indexOf(client_secret) === -1,
      "THE CLIENT SECRET IS IN token_history. Redaction is by parameter " +
      "and header NAME (redactExchangeForStorage() in " +
      "client/src/oauth2_oidc_2.js); a value that reaches storage means a " +
      "name is missing from one of those lists, or a body shape neither " +
      "branch parses.");
    assert.ok(!/"[Aa]uthorization"\s*:\s*"Basic /.test(stored.raw),
      "An HTTP Basic Authorization header is in token_history. On a proxied " +
      "call the api builds one out of the client secret and reports it in " +
      "its trace, which is the credential this page had never persisted " +
      "before.");
    assert.ok(!/"[Dd][Pp]o[Pp]"\s*:\s*"ey/.test(stored.raw),
      "A DPoP proof is in token_history.");

    // And the redaction is VISIBLE rather than a silently dropped field: a
    // header that vanished would read as a request that never carried one.
    const redactedSomething = /redacted/.test(stored.raw);
    assert.ok(redactedSomething,
      "Nothing in the stored exchange is marked as redacted. This grant " +
      "sends a client secret one way or the other — in the body under " +
      "the POST auth style, in an Authorization header under the Header " +
      "one — so a stored copy with nothing redacted in it means the " +
      "redaction ran against the wrong shape and found nothing, which " +
      "looks identical to a request that carried no credential.");

    // The live pane is NOT redacted: the two copies are deliberately
    // different, and a redaction that leaked into the live view would take
    // away the bytes this whole tab exists to show.
    assert.ok(!/redacted/.test(panel),
      "The LIVE HTTP tab is showing redacted values. Only the copy written " +
      "to token_history is redacted; the pane shows the exchange as it " +
      "went, for as long as the page is open.");

    // Layout, measured with the exchange in it.
    const geometry = await measureHttpPanel(driver);
    assert.ok(geometry, "The exchange pane (#step3) is not on the page.");
    log.info("Geometry: " + JSON.stringify(geometry));
    assert.deepStrictEqual(geometry.outside, [],
      "Everything the HTTP panel draws must stay inside the pane's border. " +
      "These do not: " + geometry.outside.join("; "));
    assert.ok(geometry.hostScrollWidth <= geometry.hostClientWidth + 1,
      "The HTTP panel scrolls sideways (" + geometry.hostScrollWidth +
      "px of content in " + geometry.hostClientWidth + "px), which means a " +
      "value in it is not wrapping.");
    assert.ok(geometry.bodyScrollWidth <= geometry.bodyClientWidth + 1,
      "The page scrolls sideways with the HTTP panel open (" +
      geometry.bodyScrollWidth + "px of content in " +
      geometry.bodyClientWidth + "px).");

    // Back to the form, and the fields it holds are usable again. The pane is
    // still a form first: hiding it behind a tab that cannot be left would be
    // a worse bug than the one this tab fixes.
    await clickStable(driver, By.id("token_tab_form"),
                      "the Parameters tab");
    const back = await driver.executeScript(function () {
      var field = document.getElementById("token_client_id");
      return {
        formPanelClass: (document.getElementById("token_tabpanel_form") ||
            {}).className,
        clientIdVisible: !!(field && field.offsetParent) };
    });
    assert.strictEqual(back.formPanelClass, "dbg-tabpanel",
      "Clicking the Parameters tab should display its panel again; its " +
      "class is \"" + back.formPanelClass + "\".");
    assert.ok(back.clientIdVisible,
      "The Parameters panel's own fields should be visible again after " +
      "switching back to it.");

    // ---------------------------------------------------------------------
    // The same exchange, on the Token Endpoint Results pane.
    //
    // This is the pane a successful call LEAVES OPEN — the one above collapses
    // itself — so it is where a reader who has just fetched a token actually
    // is. It is built as a string by oauth2_oidc_2.js and its tab is attached
    // to whatever was built, so what is checked first is that the tab is there
    // at all and that the tokens the pane exists for survived being wrapped.
    // ---------------------------------------------------------------------
    const result = await readResultTab(driver);
    log.info("Results pane: label=" + result.label + ", strips=" +
             result.strips + ", access token " + result.accessTokenLength +
             " chars.");
    assert.ok(result.present,
      "The Token Endpoint Results pane has no HTTP tab on it " +
      "(#token_result_tab_http). attachHttpTabToTokenResults() runs after " +
      "every rebuild of that pane in oauth2_oidc_2.js; a pane rebuilt by a " +
      "branch that does not call it comes back without one.");
    assert.strictEqual(result.strips, 1,
      "The results pane carries " + result.strips + " tab strips. It is " +
      "rebuilt after every token call and the tab is re-attached after every " +
      "rebuild, so more than one means the attach stopped being idempotent — " +
      "two strips driving one panel.");
    assert.ok(result.accessTokenLength > 0,
      "The access token is no longer in the results pane after the tab was " +
      "attached. The tokens are put in by value AFTER the pane is built " +
      "(fillGeneratedFields), so a tab that re-parents them out of " +
      "#token_endpoint_result costs the reader the thing the pane is for.");
    assert.ok(result.accessTokenVisible,
      "The access token field is in the pane but not visible. The tokens " +
      "must be the tab that is selected when the pane is drawn.");
    assert.ok(/^HTTP · 2\d\d$/.test(result.label || ""),
      "The results pane's HTTP tab should carry the status of the exchange " +
      "(\"HTTP · 200\"), and it reads \"" + result.label + "\".");
    assert.strictEqual(result.tokensPanelClass, "dbg-tabpanel",
      "The Tokens panel should be the one displayed when the results pane " +
      "is drawn, and its class is \"" + result.tokensPanelClass + "\".");
    assert.strictEqual(result.httpPanelClass, "dbg-tabpanel dbg-tabpanel-off",
      "The results pane's HTTP panel should start hidden, and its class is " +
      "\"" + result.httpPanelClass + "\".");

    await clickStable(driver, By.id("token_result_tab_http"),
                      "the results pane's HTTP tab");
    const resultHttp = await readResultTab(driver);
    log.info("Results pane HTTP panel:\n" + resultHttp.panel);
    assert.strictEqual(resultHttp.httpPanelClass, "dbg-tabpanel",
      "Clicking the results pane's HTTP tab should display its panel; its " +
      "class is \"" + resultHttp.httpPanelClass + "\".");
    assert.strictEqual(resultHttp.tokensPanelClass,
      "dbg-tabpanel dbg-tabpanel-off",
      "Displaying the results pane's HTTP panel should hide the Tokens one; " +
      "its class is \"" + resultHttp.tokensPanelClass + "\".");

    const resultPanel = resultHttp.panel || "";
    assert.ok(resultPanel.indexOf("POST " + after.tokenEndpoint) !== -1,
      "The results pane's HTTP panel should show the method and the URL of " +
      "the token endpoint (POST " + after.tokenEndpoint + "). It reads: " +
      JSON.stringify(resultPanel.slice(0, 400)));
    assert.ok(/HTTP 2\d\d/.test(resultPanel),
      "The results pane's HTTP panel should show the response status line.");
    assert.ok(/access_token/.test(resultPanel),
      "The results pane's HTTP panel should show the response body.");
    assert.ok(/grant_type=client_credentials/.test(resultPanel),
      "The results pane's HTTP panel should show the request body.");

    // ONE view drawn twice, rather than two renderings of one exchange. This
    // is the assertion that keeps the second pane from growing an
    // implementation of its own: the day the two texts differ, something is
    // building a view for one pane that the other does not get.
    assert.strictEqual(resultPanel.replace(/\s+/g, ""),
                       panel.replace(/\s+/g, ""),
      "The two panes show different text for the same exchange. They are fed " +
      "by one renderTokenHttpExchange() call into two hosts, so a difference " +
      "means one of them is being drawn from something else.\n  Form pane: " +
      JSON.stringify(panel.slice(0, 200)) + "\n  Results pane: " +
      JSON.stringify(resultPanel.slice(0, 200)));

    const resultGeometry = await measureResultPanel(driver);
    assert.ok(resultGeometry,
      "The results pane's HTTP host (#token_result_http_exchange) is not on " +
      "the page.");
    log.info("Results pane geometry: " + JSON.stringify(resultGeometry));
    assert.deepStrictEqual(resultGeometry.outside, [],
      "Everything the results pane's HTTP panel draws must stay inside the " +
      "pane's border. These do not: " + resultGeometry.outside.join("; "));
    assert.ok(resultGeometry.hostScrollWidth <=
              resultGeometry.hostClientWidth + 1,
      "The results pane's HTTP panel scrolls sideways (" +
      resultGeometry.hostScrollWidth + "px of content in " +
      resultGeometry.hostClientWidth + "px), which means a value in it is " +
      "not wrapping.");
    assert.ok(resultGeometry.bodyScrollWidth <=
              resultGeometry.bodyClientWidth + 1,
      "The page scrolls sideways with the results pane's HTTP panel open (" +
      resultGeometry.bodyScrollWidth + "px of content in " +
      resultGeometry.bodyClientWidth + "px).");

    // And back, because the tokens are what this pane is for.
    await clickStable(driver, By.id("token_result_tab_tokens"),
                      "the results pane's Tokens tab");
    const resultBack = await readResultTab(driver);
    assert.strictEqual(resultBack.tokensPanelClass, "dbg-tabpanel",
      "Clicking the Tokens tab should display the tokens again; the panel's " +
      "class is \"" + resultBack.tokensPanelClass + "\".");
    assert.ok(resultBack.accessTokenVisible,
      "The access token field should be visible again after switching back " +
      "to the Tokens tab.");

    // ---------------------------------------------------------------------
    // THE CURRENTLY VIEWING PANE, which is the third pane carrying this tab
    // and the only one whose exchange did not happen on this page load.
    //
    // Activating a generation in Token History draws it here out of that
    // generation's `token_history` entry — through the SAME renderer, off a
    // channel of its own. That is the whole reason the exchange is stored at
    // all, and it is the one path that can break without either live pane
    // noticing: the live panes are fed by the ajax handler that just ran,
    // this one by a JSON document written minutes or days ago by a build that
    // may not have been this one.
    //
    // Asserted here rather than assumed from the live panes above, and
    // asserted on CONTENT rather than on the tab existing: a pane that draws
    // its empty sentence is a pane whose read path found nothing, and it
    // looks exactly like one that was never given anything to draw.
    // ---------------------------------------------------------------------
    await clickStable(driver, By.css(
        "#token-history-panel input[type=button][value=Activate]"),
        "the newest generation's Activate button");
    await driver.wait(until.elementLocated(By.id("cv_tab_http")), waitTime);
    await clickStable(driver, By.id("cv_tab_http"),
                      "the Currently Viewing pane's HTTP tab");
    const viewing = await readViewingTab(driver);
    log.info("Currently Viewing: label=" + viewing.label + ", strips=" +
             viewing.strips);
    log.info("Currently Viewing panel:\n" + (viewing.panel || ""));
    assert.ok(viewing.present,
      "The Currently Viewing pane should carry an HTTP tab once a generation " +
      "is activated, and it has none.");
    assert.strictEqual(viewing.strips, 1,
      "The Currently Viewing pane carries " + viewing.strips + " tab " +
      "strips. It is rebuilt on every activation and the tab is attached " +
      "after each rebuild, so two strips driving one panel is what a " +
      "non-idempotent attach looks like.");
    assert.strictEqual(viewing.httpPanelClass, "dbg-tabpanel",
      "Clicking the Currently Viewing pane's HTTP tab should display its " +
      "panel; its class is \"" + viewing.httpPanelClass + "\".");
    assert.ok(/^HTTP · 2\d\d$/.test(viewing.label || ""),
      "The Currently Viewing HTTP tab should carry the stored response's " +
      "status, and it reads \"" + viewing.label + "\".");
    const viewingPanel = viewing.panel || "";
    assert.ok(/No HTTP exchange was kept/.test(viewingPanel) === false,
      "The Currently Viewing pane says no exchange was kept with this " +
      "generation, and one was written a moment ago. The read path " +
      "(storedExchangeForDisplay()) or the entry's http_exchange field is " +
      "the thing to look at.");
    assert.ok(viewingPanel.indexOf("POST " + after.tokenEndpoint) !== -1,
      "The Currently Viewing pane should show the METHOD and URL of the " +
      "stored exchange (POST " + after.tokenEndpoint + "). It reads: " +
      JSON.stringify(viewingPanel.slice(0, 400)));
    assert.ok(/HTTP 2\d\d/.test(viewingPanel),
      "The Currently Viewing pane should show the stored response status.");
    assert.ok(/access_token/.test(viewingPanel),
      "The Currently Viewing pane should show the stored response body.");
    assert.ok(/kept with it at /.test(viewingPanel),
      "The stored exchange should say WHEN it was kept — this pane is the " +
      "one whose exchange did not happen on this page load, and a pane that " +
      "does not say so is indistinguishable from the live ones.");
    assert.ok(/redacted/.test(viewingPanel),
      "The Currently Viewing pane should show the redaction, rather than a " +
      "header that silently vanished — an absent header reads as a request " +
      "that never carried one.");
    assert.ok(viewingPanel.indexOf(client_secret) === -1,
      "THE CLIENT SECRET IS ON SCREEN in the Currently Viewing pane.");

    // Layout, in the narrowest of the three columns.
    const viewingGeometry = await driver.executeScript(function () {
      // NOTE: browser-side. No `log` in here — see the repo-root CLAUDE.md.
      var pane = document.getElementById("currently_viewing_fieldset");
      var host = document.getElementById("cv_http_exchange");
      if (!pane || !host) {
        return null;
      }
      var paneRect = pane.getBoundingClientRect();
      var outside = [];
      var nodes = host.querySelectorAll("*");
      for (var i = 0; i < nodes.length; i++) {
        var rect = nodes[i].getBoundingClientRect();
        if (rect.width === 0 && rect.height === 0) {
          continue;
        }
        if (rect.right > paneRect.right + 1 || rect.left < paneRect.left - 1) {
          outside.push((nodes[i].className || nodes[i].tagName) + " spans " +
              Math.round(rect.left) + "-" + Math.round(rect.right) +
              ", the pane spans " + Math.round(paneRect.left) + "-" +
              Math.round(paneRect.right));
        }
      }
      return {
        outside: outside,
        hostScrollWidth: host.scrollWidth,
        hostClientWidth: host.clientWidth,
        bodyScrollWidth: document.body.scrollWidth,
        bodyClientWidth: document.body.clientWidth };
    });
    assert.ok(viewingGeometry,
      "The Currently Viewing pane's HTTP host is not on the page.");
    log.info("Currently Viewing geometry: " + JSON.stringify(viewingGeometry));
    assert.deepStrictEqual(viewingGeometry.outside, [],
      "Everything the Currently Viewing pane's HTTP panel draws must stay " +
      "inside the pane's border. These do not: " +
      viewingGeometry.outside.join("; "));
    assert.ok(viewingGeometry.hostScrollWidth <=
              viewingGeometry.hostClientWidth + 1,
      "The Currently Viewing pane's HTTP panel scrolls sideways (" +
      viewingGeometry.hostScrollWidth + "px of content in " +
      viewingGeometry.hostClientWidth + "px).");
    assert.ok(viewingGeometry.bodyScrollWidth <=
              viewingGeometry.bodyClientWidth + 1,
      "The page scrolls sideways with the Currently Viewing HTTP panel open.");

    // ---------------------------------------------------------------------
    // THE REFRESH PANES' tab, in the one state this grant can produce.
    //
    // Client Credentials returns no refresh token, so there is no Refresh
    // Request to make here and the refresh channel's own EMPTY state is what
    // this asserts: the tab is on the page, it is wired to its panel, and it
    // says nothing has been sent — which is the state that must not be an
    // empty panel behind a tab. `tests/oidc_authorization_code.js` makes a
    // real refresh call and asserts the exchange itself.
    // ---------------------------------------------------------------------
    await clickStable(driver, By.id("refresh_expand_button"),
                      "the refresh pane's title");
    await clickStable(driver, By.id("refresh_tab_http"),
                      "the refresh pane's HTTP tab");
    const refreshEmpty = await driver.executeScript(function () {
      // NOTE: browser-side. No `log` in here.
      function textOf(id) {
        var el = document.getElementById(id);
        return el ? el.textContent : null;
      }
      function classOf(id) {
        var el = document.getElementById(id);
        return el ? el.className : null;
      }
      return {
        label: textOf("refresh_tab_http"),
        httpPanelClass: classOf("refresh_tabpanel_http"),
        formPanelClass: classOf("refresh_tabpanel_form"),
        panel: textOf("refresh_http_exchange") };
    });
    log.info("Refresh pane HTTP tab: " + JSON.stringify(refreshEmpty));
    assert.strictEqual(refreshEmpty.label, "HTTP",
      "No Refresh Request has been sent, so the refresh pane's HTTP tab " +
      "should be labelled plainly \"HTTP\" and it reads \"" +
      refreshEmpty.label + "\".");
    assert.strictEqual(refreshEmpty.httpPanelClass, "dbg-tabpanel",
      "Clicking the refresh pane's HTTP tab should display its panel; its " +
      "class is \"" + refreshEmpty.httpPanelClass + "\".");
    assert.strictEqual(refreshEmpty.formPanelClass,
                       "dbg-tabpanel dbg-tabpanel-off",
      "Displaying the refresh HTTP panel should hide the Parameters one.");
    assert.ok(/no Refresh Request has been sent/i.test(
                  refreshEmpty.panel || ""),
      "The refresh pane's HTTP panel should say that nothing has been sent " +
      "yet. It reads: " + JSON.stringify((refreshEmpty.panel || "")
          .slice(0, 200)));
    await clickStable(driver, By.id("refresh_tab_form"),
                      "the refresh pane's Parameters tab");

    // ---------------------------------------------------------------------
    // Coming BACK from the token detail page, which is the other branch that
    // builds this pane and the one with nothing to show.
    //
    // This is a real journey rather than a contrived one: the pane's own
    // "Access Token" link leads to token_detail.html, and its Return to
    // debugger link comes back HERE — to
    // oauth2_oidc_2.html?redirectFromTokenDetail=true, which is the only
    // caller of recreateTokenDisplay(). That branch rebuilds the pane out of
    // localStorage — the tokens, but NOT the exchange, which is deliberate
    // and is the distinction this section is about. The exchange is kept per
    // GENERATION in `token_history`, not in the current-token slots those
    // fields come from, so this pane cannot know which of the stored ones the
    // tokens on screen belong to. Its tab therefore has to SAY so and point
    // at the pane that can: an empty panel would read as a tab that stopped
    // working, and "nothing has been sent yet" would be a lie about a page
    // that plainly has tokens on it.
    // ---------------------------------------------------------------------
    await driver.get(baseUrl +
        "/oauth2_oidc_2.html?redirectFromTokenDetail=true");
    await driver.wait(until.elementLocated(By.id("token_result_tab_http")),
                      waitTime);
    const reloaded = await readResultTab(driver);
    log.info("Back from the token detail page: label=" + reloaded.label +
             ", panel=" +
             JSON.stringify((reloaded.panel || "").slice(0, 160)));
    assert.ok(reloaded.accessTokenLength > 0,
      "The page came back from the token detail page with no access token in " +
      "its results pane, so this is not the restored-from-storage state this " +
      "is meant to assert. recreateTokenDisplay() fills those fields from " +
      "localStorage.");
    assert.strictEqual(reloaded.label, "HTTP",
      "On a freshly loaded page nothing has been sent, so the tab should be " +
      "labelled plainly \"HTTP\" and it reads \"" + reloaded.label + "\".");
    assert.ok(/has been sent since this page was loaded/i.test(
                  reloaded.panel || ""),
      "The HTTP tab on a reloaded page should say that nothing has been " +
      "sent on THIS page load. It reads: " +
      JSON.stringify((reloaded.panel || "").slice(0, 250)));
    assert.ok(/Token History/i.test(reloaded.panel || ""),
      "and it should point at Token History, which is where the exchange " +
      "for a given generation now lives. Without that the sentence tells a " +
      "reader the exchange is gone, which stopped being true. It reads: " +
      JSON.stringify((reloaded.panel || "").slice(0, 250)));

    // The generation written earlier is still there, exchange and all: a
    // reload must not lose it, and this is the one assertion that a
    // page-load path cannot pass by drawing something plausible.
    const afterReload = await readStoredHistory(driver);
    log.info("After the reload token_history holds " +
             afterReload.entries.length + " generation(s).");
    assert.ok(afterReload.entries.some((e) => !!e.http_exchange),
      "The stored exchange did not survive the page load. token_history " +
      "now holds " + afterReload.entries.length + " generation(s) and none " +
      "of them carries one.");
    assert.ok(afterReload.raw.indexOf(client_secret) === -1,
      "THE CLIENT SECRET IS IN token_history after the reload.");
    assert.ok(reloaded.strips === 1,
      "The reloaded results pane carries " + reloaded.strips + " tab strips.");

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    testFailed = true;
  } finally {
    await driver.quit();
  }
  if (testFailed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('token_http_exchange')
  .description("Run test.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
  )
  .action((options) => {
    if (!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
