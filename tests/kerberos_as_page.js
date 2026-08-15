// File: kerberos_as_page.js
//
// client/public/kerberos.html — the Kerberos AS exchange, in a browser, against
// the mock KDC.
//
// ---------------------------------------------------------------------------
// What this covers that tests/krb5_as_exchange.js does not.
//
// That test drives the same exchange with no browser: the codec straight into the
// KDC through the relay. So this one deliberately does not re-check the protocol.
// It checks the things that only exist once a page and an api are in the path:
//
//   * that the bundle is registered in BOTH client/build.js and client/Dockerfile
//     (a page in only one of the two works in one environment and 404s in the other);
//   * that the api's CORS policy actually lets the page call POST /krb5/kdc — a
//     failure invisible to every node test, and one that appears as a fetch which
//     never resolves rather than as anything naming CORS;
//   * that the two-step flow is discoverable: step 2 is DISABLED until step 1 has
//     learned the salt, because a user who has not run step 1 has no salt and would
//     be guessing;
//   * that the SALT the KDC sent is shown and used, since that is the page's whole
//     reason for having two buttons; and
//   * that the session key is treated as a credential — sessionStorage by default,
//     localStorage only when asked, and purged when the box is unticked.
//
// **Services needed:** the client, the api (for the relay) and the mock STS (which
// carries the KDC). It is therefore a containerized-suite job rather than a
// node-only one, and it skips with a named reason rather than failing when the KDC
// is unreachable — an absent service is an environment fact, not a defect, and the
// four SD-JWT VC tests' history in tests/CLAUDE.md is what that rule comes from.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "kerberos_as_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
// Where the KDC is, and who to ask for. The mock KDC's realm and passwords are
// its own (see the submodule's krb5_principals.js); the defaults here match it.
// Left NULL by default on purpose: with nothing to type, the page's own
// built-in defaults are what get used, which is the only way this test covers
// them. Set KRB5_KDC_HOST to point at something else.
var kdcHost = process.env.KRB5_KDC_HOST || null;
var kdcPort = process.env.KRB5_KDC_PORT || "88";
var stsUrl = process.env.STS_URL || "http://localhost:8081";
var realm = process.env.KRB5_REALM || "EXAMPLE.COM";
var principal = process.env.KRB5_PRINCIPAL || "alice";
var password = process.env.KRB5_PASSWORD || "hunter2";

async function waitForText(driver, id, pattern, timeoutMs, what) {
  // Wait on CONTENT, not on the element: every field here is static markup, so
  // until.elementLocated succeeds while the page is still parsing and says
  // nothing about whether the exchange has happened. See tests/wait_for.js.
  log.debug("Entering waitForText().");
  let last = "";
  try {
    await driver.wait(async function () {
      last = await driver.findElement(By.id(id)).getText();
      return pattern.test(last);
    }, timeoutMs || 40000);
  } catch (e) {
    log.debug("Leaving waitForText().");
    throw new Error(what + " (last text in #" + id + ": " + 
        JSON.stringify(last.slice(0, 300)) + ")");
  }
  log.debug("Leaving waitForText().");
  return last;
}

async function setField(driver, id, value) {
  const field = await driver.findElement(By.id(id));
  await field.clear();
  await field.sendKeys(value);
}

// Is the KDC reachable at all? Asked through the mock STS's own index rather
// than by opening a socket, because that is what a browser test can do — and it
// answers the more useful question of whether the KDC is the one this test
// expects.
async function kdcIsReachable() {
  log.debug("Entering kdcIsReachable().");
  try {
    const response = await fetch(stsUrl + "/krb5/principals");
    if (!response.ok) {
      log.debug("Leaving kdcIsReachable().");
      return {
        ok: false,
        why: stsUrl + "/krb5/principals answered " + response.status
      };
    }
    const body = await response.json();
    if (body.realm !== realm) {
      log.debug("Leaving kdcIsReachable().");
      return {
        ok: false,
        why: "the mock KDC serves realm " + body.realm + ", not " + realm
      };
    }
    const names = (body.principals || 
        []).map(function (p) { return p.principal.split("@")[0]; });
    if (names.indexOf(principal) === -1) {
      log.debug("Leaving kdcIsReachable().");
      return {
        ok: false,
        why: "the mock KDC has no principal named " + principal +
        " (it has " + names.join(", ") + ")"
      };
    }
    log.debug("Leaving kdcIsReachable().");
    return { ok: true, kdcPort: String(body.kdcPort) };
  } catch (e) {
    log.debug("Leaving kdcIsReachable().");
    return {
      ok: false,
      why: "the mock STS at " + stsUrl + " did not answer (" + e.message + ")"
    };
  }
  log.debug("Leaving kdcIsReachable().");
}

// ---------------------------------------------------------------------------
async function thePageIsWiredAndSaysWhatItNeeds(driver) {
  log.debug("Entering thePageIsWiredAndSaysWhatItNeeds().");
  const loaded = await driver.executeScript("return typeof window.kerberos;");
  assert.strictEqual(loaded, "object",
    "the kerberos bundle did not load — check the BUNDLES entry in " +
        "client/build.js AND the " +
    "browserify line in client/Dockerfile. A page registered in only one of " +
        "the two builds fine " +
    "for the static deployments while the containerized page's <script> " +
        "404s, so the failure " +
    "appears in only one environment.");

  // The relay's limits, fetched from the api. If this is absent the page cannot
  // have reached the api at all, which on a browser is usually CORS — and CORS
  // fails as a fetch that never resolves rather than as anything naming CORS.
  const environment = await waitForText(driver, "krb_environment_note", 
      /relay to ports|did not answer/,
    20000, "the page never reported what the api's relay allows");
  assert.ok(/relay to ports/.test(environment),
    "the page could not read GET /krb5/limits from the api: " + environment +
    "\nOn a browser this is usually the api's CORS allowlist (uiUrl) not " +
        "matching the origin the " +
    "page is served from — a failure no node test can see.");
  log.info("the api's relay limits, as the page sees them: " + 
      environment.replace(/\s+/g, " ").slice(0, 160));
  log.debug("Leaving thePageIsWiredAndSaysWhatItNeeds().");
}

async function stepTwoIsGatedOnStepOne(driver) {
  log.debug("Entering stepTwoIsGatedOnStepOne().");
  const disabled = await driver.findElement(By.id("krb_preauth_button")).getAttribute("disabled");
  assert.ok(disabled,
    "step 2 must start DISABLED. Without step 1 there is no salt, and a user " +
        "who guesses one gets " +
    "KDC_ERR_PREAUTH_FAILED — which reads as a wrong password and sends them " +
        "looking in the wrong " +
    "place entirely.");
  log.debug("Leaving stepTwoIsGatedOnStepOne().");
}

async function stepOneDiscoversTheSalt(driver) {
  log.debug("Entering stepOneDiscoversTheSalt().");
  await setField(driver, "krb_realm", realm);
  await setField(driver, "krb_principal", principal);
  if (kdcHost) await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);
  await driver.findElement(By.id("krb_noreauth_button")).click();

  const status = await waitForText(driver, "krb_as_status",
    /PREAUTH_REQUIRED|issued a ticket WITHOUT|refused|could not/, 40000,
    "step 1 produced no result");
  assert.ok(/PREAUTH_REQUIRED/.test(status),
    "a bare AS-REQ for " + principal + " should be answered with " +
        "KDC_ERR_PREAUTH_REQUIRED: " + status);
  assert.ok(/not a failure/.test(status),
    "and the page must say that is the EXPECTED answer rather than " +
        "presenting it as a failure: " +
    status);

  const discovered = await driver.findElement(By.id("krb_discovered_pane")).getText();
  const expectedSalt = realm + principal;
  assert.ok(discovered.indexOf(expectedSalt) !== -1,
    "the salt the KDC sent must be shown — it is not guessable and this is " +
        "the only place it comes " +
    "from. Expected " + expectedSalt + " in: " + discovered.slice(0, 300));
  assert.ok(/not guessable/i.test(discovered),
    "and the pane should say why the salt matters, since that is the point " +
        "of the round trip");

  // It must also be USED, not merely displayed.
  const saltField = await driver.findElement(By.id("krb_salt")).getAttribute("value");
  assert.strictEqual(saltField, expectedSalt,
    "the salt field must be filled from PA-ETYPE-INFO2, not left for the " +
        "user to type");

  const stillDisabled = await driver.findElement(By.id("krb_preauth_button")).getAttribute("disabled");
  assert.ok(!stillDisabled, "step 2 must be enabled once the salt is known");

  // The request that went out is shown, which is the page's claim to be a
  // debugger.
  const request = await driver.findElement(By.id("krb_request_pane")).getText();
  assert.ok(/AS-REQ/.test(request), "the request pane must show what was " +
      "sent: " + request.slice(0, 120));
  assert.ok(/preference order/.test(request),
    "including the etype list, whose ORDER is the negotiation");
  log.debug("Leaving stepOneDiscoversTheSalt().");
}

async function stepTwoGetsATicketAndTreatsItAsACredential(driver) {
  log.debug("Entering stepTwoGetsATicketAndTreatsItAsACredential().");
  // CLEAR FIRST. The field arrives pre-filled from the build's own
  // krb5PasswordDefault (applyBuildDefaults() in client/src/kerberos.js), so
  // sendKeys APPENDS: the KDC was handed "hunter2hunter2" and answered
  // KDC_ERR_PREAUTH_FAILED, whose text names a wrong password, a wrong salt or
  // a clock outside the skew — three things, none of them this.
  await driver.findElement(By.id("krb_password")).clear();
  await driver.findElement(By.id("krb_password")).sendKeys(password);
  await driver.findElement(By.id("krb_preauth_button")).click();

  const status = await waitForText(driver, "krb_as_status",
    /A TGT for|will not decrypt|refused|does not match/, 60000, "step 2 " +
        "produced no result");
  assert.ok(/A TGT for/.test(status),
    "with the right password and the KDC's own salt, a ticket must be " +
        "issued: " + status);

  const cache = await driver.findElement(By.id("krb_cache_pane")).getText();
  assert.ok(cache.indexOf(principal + "@" + realm) !== -1, "the cache must " +
      "name the client: " + cache.slice(0, 200));
  assert.ok(/krbtgt\//.test(cache), "and the service, which for a TGT is " +
      "krbtgt");
  assert.ok(/pre-authent/.test(cache),
    "the ticket must carry pre-authent, since pre-authentication actually " +
        "happened");
  assert.ok(/A CREDENTIAL/.test(cache),
    "and the session key must be labelled as the credential it is, because " +
        "that is not obvious");

  // Where it is kept. sessionStorage by default; localStorage only when asked.
  const inSession = await driver.executeScript("return " +
      "!!sessionStorage.getItem('krb_ccache');");
  const inLocal = await driver.executeScript("return " +
      "!!localStorage.getItem('krb_ccache');");
  assert.strictEqual(inSession, true, "the ticket must be in sessionStorage");
  assert.strictEqual(inLocal, false,
    "and NOT in localStorage while the box is unticked. A session key is " +
        "standing access to whatever " +
    "the ticket can reach, so persisting it must be a choice.");

  // Ticking the box moves it; unticking it must PURGE what was written, on the
  // spot. An opt-out that leaves yesterday's session key behind is not an
  // opt-out.
  await driver.findElement(By.id("krb_save_ccache")).click();
  await driver.findElement(By.id("krb_preauth_button")).click();
  await waitForText(driver, "krb_as_status", /A TGT for/, 60000, 
      "the second exchange produced no ticket");
  assert.strictEqual(await driver.executeScript("return " +
      "!!localStorage.getItem('krb_ccache');"), true,
    "with the box ticked the ticket must be in localStorage");
  await driver.findElement(By.id("krb_save_ccache")).click();
  assert.strictEqual(await driver.executeScript("return " +
      "!!localStorage.getItem('krb_ccache');"), false,
    "unticking the box must PURGE the stored cache immediately, not merely " +
        "stop writing new ones");

  // And Forget clears both.
  await driver.findElement(By.id("krb_forget_button")).click();
  assert.strictEqual(await driver.executeScript(
    "return !!(localStorage.getItem('krb_ccache') || " +
        "sessionStorage.getItem('krb_ccache'));"), false,
    "Forget must clear both stores");
  log.debug("Leaving stepTwoGetsATicketAndTreatsItAsACredential().");
}

async function aWrongPasswordIsDiagnosedAndStoresNothing(driver) {
  log.debug("Entering aWrongPasswordIsDiagnosedAndStoresNothing().");
  await setField(driver, "krb_password", password + "-wrong");
  await driver.findElement(By.id("krb_preauth_button")).click();
  const status = await waitForText(driver, "krb_as_status",
    /PREAUTH_FAILED|will not decrypt|refused/, 60000, "the wrong-password " +
        "case produced no result");
  assert.ok(/PREAUTH_FAILED|will not decrypt/.test(status),
    "a wrong password must be reported: " + status);
  // The diagnosis that matters: at the KDC this is indistinguishable from a
  // wrong SALT, and a page that does not say so sends people to change their
  // password.
  assert.ok(/salt/i.test(status),
    "and the message must mention the salt, because the KDC cannot tell a " +
        "wrong password from a " +
    "wrong salt and the user needs to know that: " + status);
  assert.strictEqual(await driver.executeScript(
    "return !!(localStorage.getItem('krb_ccache') || " +
        "sessionStorage.getItem('krb_ccache'));"), false,
    "and no ticket may be stored");
  log.debug("Leaving aWrongPasswordIsDiagnosedAndStoresNothing().");
}

// The page has to be USABLE without scrolling, and its defaults have to work
// against the mock KDC without anything being typed. Both drift silently — a
// paragraph grows, a field is added — so both are asserted, the way
// tests/navigation.js protects the landing page.
//
// The budget is 640px at 1366x768, the same number and for the same reason
// (CARD_HEIGHT_BUDGET in navigation.js): headless Chrome has no toolbar, so its
// viewport is more generous than a real browser's and measuring only against
// innerHeight would pass a page that a real user has to scroll. Both are
// checked.
async function theConfigurationAndBothControlsFitOnOneScreen(driver) {
  log.debug("Entering theConfigurationAndBothControlsFitOnOneScreen().");
  const BUDGET = 640;
  const was = await driver.manage().window().getRect();
  await driver.manage().window().setRect({ width: 1366, height: 768 });
  await driver.get(baseUrl + "/kerberos.html");
  await driver.wait(until.elementLocated(By.id("krb_preauth_button")), 15000);

  const m = await driver.executeScript(
    "var b = function (id) { var e = document.getElementById(id);" +
    "  return e ? Math.round(e.getBoundingClientRect().bottom) : null; };" +
    "var v = function (id) { var e = document.getElementById(id); return e ? " +
        "e.value : null; };" +
    "return { viewport: window.innerHeight," +
    "         step1: b('krb_noreauth_button')," +
    "         step2: b('krb_preauth_button')," +
    "         hScroll: document.documentElement.scrollWidth > " +
        "window.innerWidth + 1," +
    "         legend: (document.querySelector('fieldset.krb-pane > legend') " +
        "|| {}).textContent," +
    "         realm: v('krb_realm'), principal: v('krb_principal')," +
    "         host: v('krb_kdc_host'), port: v('krb_kdc_port')," +
    "         password: v('krb_password') ? 'set' : '' };");

  try {
    // Both controls, against both limits.
    [["step 1", m.step1], ["step 2", m.step2]].forEach(function (pair) {
      assert.ok(pair[1] !== null, pair[0] + "'s button is missing from the " +
          "page");
      assert.ok(pair[1] <= BUDGET,
        pair[0] + "'s button ends at " + pair[1] + "px, past the " + BUDGET + 
            "px a real browser " +
        "leaves at 1366x768 — the page cannot be used without scrolling to " +
            "find the control. " +
        "Something above it grew; the panes are arranged so the " +
            "configuration and both buttons " +
        "fit, and that arrangement is the thing to preserve.");
      assert.ok(pair[1] <= m.viewport,
        pair[0] + "'s button ends at " + pair[1] + "px in a " + m.viewport + 
            "px viewport");
    });
    assert.ok(!m.hScroll, "the page must not scroll horizontally at 1366x768");

    // The pane's name, which the other workflows share.
    assert.ok(/Configuration Parameters/.test(m.legend || ""),
      "the first pane is the configuration one and is named for it across " +
          "the workflows, got: " +
      m.legend);

    // And the defaults, which are the other half of being usable on arrival.
    // They come from the build's config (client/src/env/*.js), so a build with
    // no api behind it correctly has none — hence the check is "either all set,
    // or deliberately empty".
    if (m.host) {
      assert.strictEqual(m.realm, "EXAMPLE.COM", "the realm should default " +
          "to the mock KDC's");
      assert.strictEqual(m.principal, "alice", "and the principal to an " +
          "account it knows");
      assert.strictEqual(m.port, "88", "and the port");
      assert.strictEqual(m.password, "set",
        "and the password, or the workflow cannot be run without knowing a " +
            "credential that is " +
        "published in the mock's principal table anyway");
      assert.notStrictEqual(m.host, "localhost",
        "the KDC host must NOT default to localhost: the api's relay " +
            "resolves it, and localhost " +
        "there is the api container itself. It is " + m.host + ".");
    } else {
      log.info("[fit] this build ships no Kerberos defaults (no api behind " +
          "it), which is correct " +
        "for a static deployment");
    }
    log.info("[fit] step 1 ends at " + m.step1 + "px and step 2 at " + 
        m.step2 + "px, inside the " +
      BUDGET + "px budget and the " + m.viewport + "px viewport; defaults: " + 
          m.principal + "@" +
      m.realm + " via " + m.host + ":" + m.port);
  } finally {
    await driver.manage().window().setRect(was);
  }
  log.debug("Leaving theConfigurationAndBothControlsFitOnOneScreen().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The Kerberos AS exchange page at " + baseUrl + 
      ".");
  const reachable = await kdcIsReachable();
  if (!reachable.ok) {
    // Named, not silent. An absent service is an environment fact; a test that
    // reported "OK" here would be one that quietly did nothing.
    log.warn("SKIPPED: " + reachable.why + ". This test needs the client, " +
        "the api and the mock STS " +
      "(which carries the KDC on port " + kdcPort + "). Start the stack, or " +
          "run " +
      "./local-run-tests.sh which does.");
    log.info("Test completed successfully.");
    return;
  }
  if (reachable.kdcPort && reachable.kdcPort !== String(kdcPort)) {
    log.warn("the mock STS reports its KDC on port " + reachable.kdcPort + 
        " but this test was told " +
      kdcPort + "; using the reported one.");
    kdcPort = reachable.kdcPort;
  }

  const options = new chrome.Options();
  // --headless=new, never bare --headless: in the image's Chrome 121 the old
  // mode ignores --unsafely-treat-insecure-origin-as-secure, so crypto.subtle
  // stays undefined and the key derivation on this page silently has no crypto.
  options.addArguments("--headless=new", "--no-sandbox", 
      "--disable-dev-shm-usage",
                       "--window-size=1400,1200");
  // This page derives keys with Web Crypto and its fetch reaches the api on a
  // private address; both need these. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    await driver.get(baseUrl + "/kerberos.html");
    await driver.wait(until.elementLocated(By.id("krb_noreauth_button")), 
        20000);
    await theConfigurationAndBothControlsFitOnOneScreen(driver);
    await thePageIsWiredAndSaysWhatItNeeds(driver);
    await stepTwoIsGatedOnStepOne(driver);
    await stepOneDiscoversTheSalt(driver);
    await stepTwoGetsATicketAndTreatsItAsACredential(driver);
    await aWrongPasswordIsDiagnosedAndStoresNothing(driver);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("kerberos_as_page")
  .description("Verify the Kerberos AS exchange page: wiring, CORS, the " +
      "two-step flow, credential handling.")
  .addOption(new Option("-u, --url <url>", 
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
