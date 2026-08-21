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
// It covers BOTH panes that show this exchange, because a reader meets them in
// two different states. The request form has the tab the exchange was composed
// on — but a successful call COLLAPSES that form, so the pane actually on
// screen afterwards is the Token Endpoint Results one, which carries the same
// exchange under a tab of its own. They share one view and one renderer
// (renderTokenHttpExchange() draws into every host that exists), and a shared
// renderer whose second host is missing draws nothing and says nothing, which
// is why the second pane is asserted here rather than assumed to follow from
// the first. The results pane is also BUILT AS A STRING by oauth2_oidc_2.js
// in four branches rather than being in the page, so its tab is attached to
// whatever was just built — including on a page LOAD, where the tokens come
// back from localStorage and there is no exchange to show at all. That last
// state is asserted too: it is the one that must say so rather than be empty.
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

    // Nothing about the exchange is persisted. The request repeats the client
    // secret; this page keeps credentials out of storage by design.
    assert.ok(after.storage.indexOf("http_exchange") === -1,
      "The HTTP trace must not be written to localStorage, and something " +
      "named http_exchange is in it.");

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
    // Coming BACK from the token detail page, which is the other branch that
    // builds this pane and the one with nothing to show.
    //
    // This is a real journey rather than a contrived one: the pane's own
    // "Access Token" link leads to token_detail.html, and its Return to
    // debugger link comes back HERE — to
    // oauth2_oidc_2.html?redirectFromTokenDetail=true, which is the only
    // caller of recreateTokenDisplay(). That branch rebuilds the pane out of
    // localStorage, where the tokens are and the exchange is not: a Token
    // Request carries the client secret, so this page keeps it out of storage
    // by design. The tab therefore has to SAY so. An empty panel would read
    // as a tab that stopped working, and "nothing has been sent yet" would be
    // a lie about a page that plainly has tokens on it.
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
      "The HTTP tab on a reloaded page should say that the exchange behind " +
      "the tokens on screen was not kept. It reads: " +
      JSON.stringify((reloaded.panel || "").slice(0, 250)));
    assert.ok(reloaded.strips === 1,
      "The reloaded results pane carries " + reloaded.strips + " tab strips.");

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
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
