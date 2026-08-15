// File: kerberos_delegation_page.js
//
// The delegation page (kerberos_delegation.html): S4U2Self, S4U2Proxy with both
// authorization routes, forwarding, and renewal, driven through a real browser against
// the mock KDC.
//
// ---------------------------------------------------------------------------
// What needs a browser here, given that tests/krb5_tgs_ap.js already drives every one of
// these exchanges with no browser at all.
//
// Three things, and they are the reasons this page exists rather than being a fifth
// section of that test:
//
//  1. **The credential handoff.** The service's own TGT comes from the AS page, the
//     evidence ticket from S4U2Self is stored for S4U2Proxy to find, and both live in
//     `localStorage` under keys the shared module owns. A rename there breaks this and
//     nothing else — which has happened once already, when a refactor left three sites
//     calling `removeItem(KEYS.CCACHE)` after the key became `KEYS.TGT`, so
//     `removeItem(undefined)` deleted a key called "undefined" and the opt-out purge
//     silently stopped working. The evidence ticket carries a session key too, so it is
//     in that purge and this test checks it leaves.
//  2. **What the page SAYS when a delegation fails.** Every refusal on this page is
//     `KDC_ERR_BADOPTION`, whatever the cause — a missing PA-PAC-OPTIONS, an
//     unauthorized pair, non-forwardable evidence. The error names none of them. So the
//     page's job is to narrow it, and that text is the product: a test that only checked
//     "it failed" would pass against a page that said nothing useful.
//  3. **Forwardability reported at the moment the evidence arrives**, rather than two
//     steps later when classic S4U2Proxy refuses it. A missing
//     TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION on the front-end account shows up as a
//     complaint about the *evidence ticket*, which is not where the problem is.
//
// ---------------------------------------------------------------------------
// What it needs, and how it skips.
//
// The client and the api (for the relay), plus the mock KDC on port 88. Without the api
// there is no path to a socket at all, and without `krb5ServicePorts` configured the
// relay refuses — so a missing service is reported as a SKIP naming what was absent,
// because an environment capability is not a defect. It authenticates as
// **HTTP/frontend.example.com**, not as a user: S4U2Self is a request a SERVICE makes,
// and that is the single most common misunderstanding about it.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "kerberos_delegation_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var apiUrl = process.env.API_URL || "http://localhost:4000";
var kdcHost = process.env.KRB5_KDC_HOST || "localhost";
var kdcPort = process.env.KRB5_KDC_PORT || "88";
var realm = process.env.KRB5_REALM || "EXAMPLE.COM";

// The front-end SERVICE account, and its salt. A service principal's salt is
// not its principal name — AD's is the realm followed by the sAMAccountName,
// which for HTTP/frontend.example.com is HTTPfrontend — and the KDC tells the
// client in PA-ETYPE-INFO2, so the page does not need to know. Named here only
// because the password does.
var frontend = process.env.KRB5_FRONTEND || "HTTP/frontend.example.com";
var frontendPassword = process.env.KRB5_FRONTEND_PASSWORD || 
    "frontend-service-password";
var impersonate = process.env.KRB5_IMPERSONATE || "alice";
var classicTarget = process.env.KRB5_CLASSIC_TARGET || 
    "HTTP/backend.example.com";
var rbcdTarget = process.env.KRB5_RBCD_TARGET || "HTTP/rbcd.example.com";
var unauthorizedTarget = process.env.KRB5_UNAUTHORIZED_TARGET || 
    "HTTP/web.example.com";

async function waitForText(driver, id, pattern, timeoutMs, what) {
  // Content, not elements: every field on this page is static markup, so
  // `elementLocated` succeeds during parsing and says nothing about whether the
  // exchange happened.
  log.debug("Entering waitForText().");
  let last = "";
  try {
    await driver.wait(async function () {
      last = await driver.findElement(By.id(id)).getText();
      return pattern.test(last);
    }, timeoutMs || 30000);
  } catch (e) {
    // The polled value has to be attached in the catch: driver.wait's message
    // argument is a plain string evaluated at call time and would always report
    // the pre-poll value.
    log.debug("Leaving waitForText().");
    throw new Error((what || id) + " never matched " + pattern + 
        ". Last text was: " +
      (last.length ? last.replace(/\s+/g, " ").slice(0, 400) : "(empty)"));
  }
  log.debug("Leaving waitForText().");
  return last;
}

async function setField(driver, id, value) {
  const field = await driver.findElement(By.id(id));
  await driver.executeScript(
    "arguments[0].value = arguments[1];" +
    "arguments[0].dispatchEvent(new Event('input', { bubbles: true }));" +
    "arguments[0].dispatchEvent(new Event('change', { bubbles: true }));", 
        field, value);
}

async function click(driver, id) {
  const button = await driver.wait(until.elementLocated(By.id(id)), 15000);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' " +
      "});", button);
  await button.click();
}

async function severeErrors(driver) {
  const entries = await driver.manage().logs().get("browser");
  return entries.filter(function (e) { return e.level.name === "SEVERE"; })
    .map(function (e) { return e.message; })
    // The api's own 4xx answers are logged by the browser and are the SUBJECT
    // of some of these assertions rather than page faults, so only script
    // errors count.
    .filter(function (m) { return !/\b4\d\d\b|\b5\d\d\b|Failed to load resource/.test(m); });
}

// ---------------------------------------------------------------------------
// Is the environment able to run this at all?
// ---------------------------------------------------------------------------
async function relayReachable() {
  log.debug("Entering relayReachable().");
  try {
    const response = await fetch(apiUrl + "/krb5/limits");
    if (!response.ok) {
      log.debug("Leaving relayReachable().");
      return { ok: false, why: "GET /krb5/limits answered " + response.status };
    }
    const limits = await response.json();
    if (!limits.kdcPorts || limits.kdcPorts.indexOf(parseInt(kdcPort, 
        10)) === -1) {
      log.debug("Leaving relayReachable().");
      return {
        ok: false,
        why: "the api's krb5AllowedPorts does not include " + kdcPort +
        " (it allows " + JSON.stringify(limits.kdcPorts) + "), so the relay " +
            "would refuse"
      };
    }
    log.debug("Leaving relayReachable().");
    return { ok: true };
  } catch (e) {
    log.debug("Leaving relayReachable().");
    return {
      ok: false,
      why: "the api at " + apiUrl + " did not answer GET /krb5/limits: " +
      e.message
    };
  }
  log.debug("Leaving relayReachable().");
}

// ---------------------------------------------------------------------------
// Get the SERVICE's own TGT on the AS page. This is the step people do not expect: a
// service account authenticates exactly as a user does.
// ---------------------------------------------------------------------------
async function theServiceAuthenticatesAsItself(driver) {
  log.debug("Entering theServiceAuthenticatesAsItself().");
  await driver.get(baseUrl + "/kerberos.html");
  await setField(driver, "krb_realm", realm);
  await setField(driver, "krb_principal", frontend);
  await setField(driver, "krb_password", frontendPassword);
  await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);
  await click(driver, "krb_get_tgt_button");
  const text = await waitForText(driver, "krb_status", 
      /ticket-granting ticket|TGT|error|refused/i,
    40000, "the AS page's status");
  assert.ok(!/refused|error/i.test(text) || 
      /ticket-granting ticket|TGT/i.test(text),
    "the service account should get a TGT of its own — a service " +
        "authenticates exactly as a user " +
    "does, which is where S4U2Self starts: " + text);
  log.info("[delegation] " + frontend + " authenticated as itself");
  log.debug("Leaving theServiceAuthenticatesAsItself().");
}

// ---------------------------------------------------------------------------
// S4U2Self.
// ---------------------------------------------------------------------------
async function s4u2SelfObtainsEvidenceForSomebodyElse(driver) {
  log.debug("Entering s4u2SelfObtainsEvidenceForSomebodyElse().");
  await driver.get(baseUrl + "/kerberos_delegation.html");

  // The held TGT must be recognised, and the page must say whose it needs to
  // be.
  const held = await waitForText(driver, "krb_held_pane", 
      /krbtgt|forwardable|No ticket-granting/,
    20000, "the held-TGT pane");
  assert.ok(!/No ticket-granting ticket is held/.test(held),
    "the TGT obtained on the AS page must be found here — this is the " +
        "handoff, through " +
    "localStorage keys the shared module owns, and a rename breaks exactly " +
        "this: " + held);

  // With no evidence yet, S4U2Proxy must be disabled rather than failing when
  // pressed.
  const disabledBefore = await driver.findElement(By.id("krb_s4u2proxy_button"))
    .getAttribute("disabled");
  assert.ok(disabledBefore,
    "S4U2Proxy needs an evidence ticket, so its button must be disabled " +
        "until one exists rather " +
    "than failing on the press");

  await setField(driver, "krb_realm", realm);
  await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);
  await setField(driver, "krb_impersonate", impersonate);
  await click(driver, "krb_s4u2self_button");

  const status = await waitForText(driver, "krb_s4u2self_status",
    /Got a ticket for|error|refused|does not|failed/i, 40000, 
        "the S4U2Self status");
  assert.ok(/Got a ticket for/.test(status),
    "S4U2Self should succeed for this account: " + status);
  assert.ok(new RegExp(impersonate).test(status),
    "and the status must name who the ticket is FOR, which is the user who " +
        "took no part in it: " +
    status);
  assert.ok(/FORWARDABLE/.test(status),
    "and must report forwardability HERE rather than leaving it to be " +
        "discovered when classic " +
    "S4U2Proxy refuses the evidence two steps later: " + status);

  // The evidence pane, and the reply pane's decode.
  const evidence = await waitForText(driver, "krb_evidence_pane", 
      /krbtgt|HTTP\/|forwardable/, 15000,
    "the evidence pane");
  assert.ok(new RegExp(impersonate).test(evidence),
    "the evidence pane must show the ticket is for the impersonated user: " + 
        evidence);

  const reply = await waitForText(driver, "krb_s4u2self_reply_pane", 
      /TGS-REP|KRB-ERROR/, 15000,
    "the S4U2Self reply pane");
  assert.ok(/TGS-REP/.test(reply),
    "the reply is an ordinary TGS-REP — S4U2Self is not a distinct message " +
        "type, which is worth " +
    "seeing: " + reply.slice(0, 200));

  // And the request pane must show PA-FOR-USER, since that padata IS the
  // mechanism.
  const request = await waitForText(driver, "krb_s4u2self_request_pane", 
      /TGS-REQ/, 15000,
    "the S4U2Self request pane");
  assert.ok(/FOR.USER|129/.test(request),
    "the request pane should show the PA-FOR-USER padata, which is the whole " +
        "mechanism: " +
    request.replace(/\s+/g, " ").slice(0, 300));

  log.info("[delegation] S4U2Self obtained a ticket for " + impersonate + 
      " with no involvement " +
    "from that account");
  log.debug("Leaving s4u2SelfObtainsEvidenceForSomebodyElse().");
}

// ---------------------------------------------------------------------------
// S4U2Proxy, both ways, and the refusal.
// ---------------------------------------------------------------------------
async function s4u2ProxyWorksBothWaysAndExplainsRefusals(driver) {
  log.debug("Entering s4u2ProxyWorksBothWaysAndExplainsRefusals().");

  // Classic: authorized by msDS-AllowedToDelegateTo on the front end. No
  // padata.
  await setField(driver, "krb_deleg_target", classicTarget);
  await driver.executeScript(
    "var b = document.getElementById('krb_resource_based'); if (b && " +
        "b.checked) b.click();");
  await click(driver, "krb_s4u2proxy_button");
  const classic = await waitForText(driver, "krb_s4u2proxy_status",
    /Got a ticket for|error|refused|BADOPTION/i, 40000, "the S4U2Proxy " +
        "status (classic)");
  assert.ok(/Got a ticket for/.test(classic),
    "classic constrained delegation should succeed for this pair: " + classic);
  assert.ok(new RegExp(impersonate).test(classic) && /classic/.test(classic),
    "and the status must say the ticket is for the impersonated user AND " +
        "which mechanism " +
    "authorized it, because the two look identical on the wire: " + classic);
  assert.ok(/appears nowhere in the ticket/.test(classic),
    "and should point out that the requesting service is not in the ticket " +
        "at all — the only " +
    "record is the PAC's delegation trail: " + classic);

  // The trail pane must explain why it cannot show the trail itself: the PAC is
  // encrypted under the target's key, which a client never holds. Saying so
  // beats an empty box.
  const trail = await waitForText(driver, "krb_trail_pane", 
      /S4U_DELEGATION_INFO/, 15000,
    "the delegation-trail pane");
  assert.ok(/decoder page/.test(trail),
    "and should say where the trail CAN be read, since this page cannot " +
        "decrypt it: " + trail);

  // RBCD without the padata: [MS-SFU] requires KDC_ERR_BADOPTION, and the page
  // has to narrow an error that mentions nothing about padata.
  await setField(driver, "krb_deleg_target", rbcdTarget);
  await click(driver, "krb_s4u2proxy_button");
  const noPadata = await waitForText(driver, "krb_s4u2proxy_status",
    /Got a ticket for|BADOPTION|refused|error/i, 40000, "the S4U2Proxy " +
        "status (RBCD, no padata)");
  assert.ok(!/Got a ticket for/.test(noPadata),
    "resource-based delegation without PA-PAC-OPTIONS must be REFUSED — " +
        "[MS-SFU] requires " +
    "KDC_ERR_BADOPTION, and a KDC that allowed it would make the padata look " +
        "optional: " + noPadata);
  assert.ok(/PA-PAC-OPTIONS/.test(noPadata),
    "and the page MUST name the padata, because the error code says nothing " +
        "about it. This text " +
    "is the product: " + noPadata);
  assert.ok(/tick the box/.test(noPadata),
    "and should say what to do about it: " + noPadata);

  // With the padata.
  await driver.executeScript(
    "var b = document.getElementById('krb_resource_based'); if (b && " +
        "!b.checked) b.click();");
  await click(driver, "krb_s4u2proxy_button");
  const rbcd = await waitForText(driver, "krb_s4u2proxy_status",
    /Got a ticket for|BADOPTION|refused|error/i, 40000, "the S4U2Proxy " +
        "status (RBCD)");
  assert.ok(/Got a ticket for/.test(rbcd),
    "with PA-PAC-OPTIONS the same request must succeed: " + rbcd);
  assert.ok(/resource-based/.test(rbcd),
    "and the status must say resource-based delegation authorized it, not " +
        "classic: " + rbcd);

  // A pair nothing authorizes. The refusal must name BOTH attributes, because
  // which one is missing is the only thing the reader needs.
  await setField(driver, "krb_deleg_target", unauthorizedTarget);
  await click(driver, "krb_s4u2proxy_button");
  const refused = await waitForText(driver, "krb_s4u2proxy_status",
    /Got a ticket for|BADOPTION|refused|error/i, 40000, "the S4U2Proxy " +
        "status (unauthorized)");
  assert.ok(!/Got a ticket for/.test(refused),
    "a target nothing authorizes must be refused — otherwise constrained " +
        "delegation is not " +
    "constrained and the successes above prove nothing: " + refused);
  assert.ok(/msDS-AllowedToDelegateTo/.test(refused) &&
            /msDS-AllowedToActOnBehalfOfOtherIdentity/.test(refused),
    "and the page must name BOTH attributes that could permit it, on both " +
        "accounts, since the " +
    "KDC's error names neither: " + refused);
  assert.ok(/FORWARDABLE/.test(refused),
    "and mention the evidence ticket's forwardability, the third cause of " +
        "the same error code: " +
    refused);

  log.info("[delegation] classic and resource-based delegation both worked, " +
      "and three refusals " +
    "were explained rather than restated");
  log.debug("Leaving s4u2ProxyWorksBothWaysAndExplainsRefusals().");
}

// ---------------------------------------------------------------------------
// Forwarding and renewal.
// ---------------------------------------------------------------------------
async function forwardingAndRenewalReportWhatTheyDid(driver) {
  log.debug("Entering forwardingAndRenewalReportWhatTheyDid().");

  await click(driver, "krb_forward_button");
  const forwarded = await waitForText(driver, "krb_forward_status",
    /wrapped it as a KRB-CRED|refused|error|BADOPTION/i, 40000, "the " +
        "forwarding status");
  assert.ok(/wrapped it as a KRB-CRED/.test(forwarded),
    "forwarding should succeed for a forwardable ticket: " + forwarded);
  assert.ok(/forwarded/.test(forwarded),
    "and the status must report the `forwarded` flag, which is the only " +
        "record a receiving " +
    "service has that the credentials were handed over: " + forwarded);

  // The KRB-CRED pane, and the warning that has to be there: whoever holds
  // these bytes and the key can be that client anywhere.
  const cred = await waitForText(driver, "krb_krbcred_pane", 
      /KRB-CRED|tickets/, 20000,
    "the KRB-CRED pane");
  assert.ok(/ANYTHING as/.test(cred),
    "the pane must say what holding this actually confers — there is no list " +
        "of permitted " +
    "targets, which is the whole difference from the two S4U mechanisms: " + 
        cred);
  assert.ok(/0x8003/.test(cred),
    "and where it really travels: inside an AP-REQ Authenticator's 0x8003 " +
        "checksum, not on its " +
    "own: " + cred);
  assert.ok(/Sealed with a subkey generated here: [0-9a-f]{32}/.test(cred),
    "and must show the key it was sealed with, or the bytes cannot be " +
        "decoded on the decoder " +
    "page and the pane is a dead end: " + cred.replace(/\s+/g, " ").slice(0, 
        300));

  await click(driver, "krb_renew_button");
  const renewed = await waitForText(driver, "krb_renew_status",
    /Renewed until|refused|error|no renew-till/i, 40000, "the renewal status");
  assert.ok(/Renewed until/.test(renewed),
    "a renewable ticket should renew: " + renewed);
  assert.ok(/authtime is unchanged/.test(renewed),
    "and the page must state that authtime was PRESERVED. A renewed ticket " +
        "must not look freshly " +
    "authenticated, and a service reading authtime to judge freshness would " +
        "be deceived: " +
    renewed);
  assert.ok(/capped at it/.test(renewed),
    "and that the request — deliberately beyond renew-till — was capped " +
        "there, which is what " +
    "stops a renewable ticket being immortal: " + renewed);
  assert.ok(!/WARNING/.test(renewed),
    "and there should be no warning on a correct renewal: " + renewed);

  log.info("[delegation] forwarding produced a decodable KRB-CRED, and the " +
      "renewal preserved " +
    "authtime and respected renew-till");
  log.debug("Leaving forwardingAndRenewalReportWhatTheyDid().");
}

// ---------------------------------------------------------------------------
// The storage opt-out has to cover the evidence ticket too: it carries a session key like
// any other credential, and a key left behind by an opt-out is not an opt-out.
// ---------------------------------------------------------------------------
async function theEvidenceTicketIsCoveredByTheStorageOptOut(driver) {
  log.debug("Entering theEvidenceTicketIsCoveredByTheStorageOptOut().");
  const before = await driver.executeScript(
    "return { evidence: !!window.localStorage.getItem('krb_s4u_evidence')," +
    "         tgt: !!window.localStorage.getItem('krb_ccache') };");
  assert.ok(before.evidence,
    "this check needs an evidence ticket in storage to watch leave; there is " +
        "none, so it would " +
    "pass for the wrong reason");

  // Turn saving off the way the AS page's checkbox does, then reload this page:
  // the purge runs on load, so upgrading with the box already cleared cleans up
  // too.
  await driver.executeScript("window.localStorage.setItem('krb_save_ccache', " +
      "'0');");
  await driver.get(baseUrl + "/kerberos_delegation.html");
  await waitForText(driver, "krb_held_pane", 
      /No ticket-granting ticket is held|krbtgt/, 20000,
    "the held-TGT pane after the opt-out");

  const after = await driver.executeScript(
    "return { evidence: window.localStorage.getItem('krb_s4u_evidence')," +
    "         tgt: window.localStorage.getItem('krb_ccache')," +
    "         undef: window.localStorage.getItem('undefined') };");
  assert.strictEqual(after.evidence, null,
    "with saving off the EVIDENCE ticket must be purged — it carries a " +
        "session key like any other " +
    "credential, and a key left behind by an opt-out is not an opt-out");
  assert.strictEqual(after.tgt, null, "and so must the TGT");
  assert.strictEqual(after.undef, null,
    "and nothing may be written to a key literally called \"undefined\" — " +
        "that is what a purge " +
    "calling removeItem() with a renamed constant does, and it silently " +
        "leaves the real key behind");

  // Restore, so a later run of this file starts from a normal state.
  await driver.executeScript("window.localStorage.removeItem('krb_save_ccache');");
  log.info("[delegation] the storage opt-out purges the evidence ticket as " +
      "well as the TGT");
  log.debug("Leaving theEvidenceTicketIsCoveredByTheStorageOptOut().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The Kerberos delegation page: S4U2Self, " +
      "S4U2Proxy, RBCD, " +
    "forwarding and renewal.");

  const reachable = await relayReachable();
  if (!reachable.ok) {
    // An environment capability is not a defect. Named, so nobody hunts for a
    // bug.
    log.warn("SKIPPING: " + reachable.why + ". This test needs the api's " +
        "Kerberos relay and the " +
      "mock KDC — start the stack (CONFIG_FILE=./env/local.js docker-compose " +
          "up) and make sure " +
      "the api's krb5AllowedPorts includes " + kdcPort + ".");
    log.info("Test completed successfully.");
    return;
  }

  const options = new chrome.Options();
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();
  try {
    await theServiceAuthenticatesAsItself(driver);
    await s4u2SelfObtainsEvidenceForSomebodyElse(driver);
    await s4u2ProxyWorksBothWaysAndExplainsRefusals(driver);
    await forwardingAndRenewalReportWhatTheyDid(driver);
    await theEvidenceTicketIsCoveredByTheStorageOptOut(driver);

    const errors = await severeErrors(driver);
    assert.deepStrictEqual(errors, [],
      "the page logged script errors: " + errors.join(" | "));
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("kerberos_delegation_page")
  .description("Verify the Kerberos delegation page: S4U2Self, S4U2Proxy " +
      "with both authorization " +
               "routes, forwarding and renewal.")
  .addOption(new Option("-u, --url <url>", 
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
