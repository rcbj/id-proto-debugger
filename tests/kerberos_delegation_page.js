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
const { usernameFor } = require("./random_username.js");
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
// WHO IS IMPERSONATED, generated per run and prefixed with this file's name.
// S4U2Self resolves the named account through the KDC's findOrCreateUser(), so
// an account exists for whatever name is asked for — and the whole point of the
// exchange is that this person is never involved in it, which makes a name
// nothing else in the suite shares exactly the right thing to ask for: a
// principal that turns up in the mock's table having authenticated nowhere is
// traceable to this file rather than to whoever last signed in as alice.
// KRB5_IMPERSONATE pins it.
var impersonate = process.env.KRB5_IMPERSONATE ||
    usernameFor("kerberos-delegation");
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
    // `allowedPorts`, which is what GET /krb5/limits actually answers with —
    // api/server.js builds that object from api/krb5_relay.js's
    // `allowedPorts`. This read `limits.kdcPorts` until 2026-08-17, a field the
    // api has never emitted, so the guard below was `!undefined` on every run
    // and THIS WHOLE FILE SKIPPED EVERY TIME — against a perfectly healthy
    // stack, reporting "SKIPPING: the api's krb5AllowedPorts does not include
    // 88 (it allows undefined)", which reads as a configuration problem and not
    // as a typo in the test. Every section below it, including the ones written
    // for defects found by hand, had never run. A skip that names a plausible
    // cause is the most expensive kind of test that quietly does nothing, so
    // when this file skips, check the field names against the api's response
    // before believing the environment.
    const ports = limits.allowedPorts;
    if (!Array.isArray(ports)) {
      log.debug("Leaving relayReachable().");
      return {
        ok: false,
        why: "GET /krb5/limits answered without an `allowedPorts` array (" +
        JSON.stringify(limits).slice(0, 200) + "). That is the api's own " +
            "field name and it not being there means the response shape " +
            "changed — fix this gate rather than the environment"
      };
    }
    if (ports.indexOf(parseInt(kdcPort, 10)) === -1) {
      log.debug("Leaving relayReachable().");
      return {
        ok: false,
        why: "the api's krb5AllowedPorts does not include " + kdcPort +
        " (it allows " + JSON.stringify(ports) + "), so the relay would refuse"
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
//
// IN TWO STEPS, because that is what the AS page is: a bare AS-REQ first,
// which a
// KDC requiring pre-authentication answers with KDC_ERR_PREAUTH_REQUIRED and —
// the point of the exercise — the account's SALT in PA-ETYPE-INFO2; then the
// real request, encrypted under a key derived with that salt. A service
// principal's salt is not its principal name (AD's is the realm followed by the
// sAMAccountName), which is exactly why it has to come from the KDC rather than
// be guessed here.
//
// This section drove a single `krb_get_tgt_button` and read `krb_status` until
// 2026-08-17 — neither of which the page has ever had; the two buttons are
// `krb_noreauth_button` and `krb_preauth_button`, and the line is
// `krb_as_status`.
// It could not have passed, and it never ran: relayReachable() was skipping the
// whole file (see the note there). Fixing one without the other only moves the
// failure, which is worth knowing if this file is ever quiet again.
// ---------------------------------------------------------------------------
async function theServiceAuthenticatesAsItself(driver) {
  log.debug("Entering theServiceAuthenticatesAsItself().");
  await driver.get(baseUrl + "/kerberos.html");
  await setField(driver, "krb_realm", realm);
  await setField(driver, "krb_principal", frontend);
  await setField(driver, "krb_password", frontendPassword);
  await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);

  // Step 1: no pre-authentication, to be refused and told the salt.
  await click(driver, "krb_noreauth_button");
  const first = await waitForText(driver, "krb_as_status",
    /PREAUTH_REQUIRED|issued a ticket WITHOUT|refused|could not/, 40000,
    "step 1 on the AS page");
  assert.ok(/PREAUTH_REQUIRED/.test(first),
    "a bare AS-REQ for the service account " + frontend + " should be " +
    "answered with KDC_ERR_PREAUTH_REQUIRED, which is where its salt comes " +
    "from: " + first);
  const salt = await driver.findElement(By.id("krb_salt"))
      .getAttribute("value");
  assert.ok(salt && salt.length,
    "the salt field must be filled from the KDC's PA-ETYPE-INFO2. A service " +
    "principal's salt is not its principal name, so without this step 2 " +
    "derives the wrong key and the KDC reports a wrong PASSWORD.");

  // Step 2: the real one.
  await click(driver, "krb_preauth_button");
  const text = await waitForText(driver, "krb_as_status",
      /A TGT for|will not decrypt|refused|does not match/, 60000,
    "step 2 on the AS page");
  assert.ok(/A TGT for/.test(text),
    "the service account should get a TGT of its own — a service " +
        "authenticates exactly as a user " +
    "does, which is where S4U2Self starts: " + text);
  log.info("[delegation] " + frontend + " authenticated as itself (salt " +
      salt + ")");
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
  // WHERE the key can be supplied, not which page it happens to be on today.
  // The wording has moved twice — the decoder page, then a Decryption keys pane
  // on this page, then the decoder page again once that pane was removed — so
  // the assertion is on the PROPERTY (it names somewhere the trail can be read)
  // rather than on one of those spellings.
  assert.ok(/Decoder|decoder page|keytab/.test(trail),
    "and should say where the trail CAN be read, since this page cannot " +
        "decrypt it: " + trail);
  // And the other half of the same pane, which is what the removal of that key
  // pane was for: the rest of the delegated ticket is NOT a dead end. Its
  // contents are on screen already, from the KDC's own report of them, and the
  // note has to distinguish the one field that is missing from the many that
  // are not — otherwise "you cannot read this" reads as though nothing were
  // readable.
  assert.ok(/KDC's own word|report/.test(trail),
    "and must say that everything else the ticket says is already shown, on " +
    "the KDC's word, rather than leaving the reader thinking the whole " +
        "ticket is opaque: " + trail);

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

  // SAVING HAS TO BE ON FIRST, and this section assumed it was. It is OFF by
  // default — the whole workflow keeps its credentials in sessionStorage unless
  // the box is ticked, which is what every section above this one has been
  // exercising — so nothing had ever written to localStorage and the premise
  // below ("there is an evidence ticket to watch leave") could not hold. It
  // said
  // so rather than passing for the wrong reason, which is the only thing that
  // kept this from being a section that quietly did nothing.
  //
  // Turning the preference on is not enough by itself: it is read when a
  // credential is WRITTEN, so tickets already in sessionStorage stay there.
  // Both
  // therefore have to be re-obtained, and this page can do both — a renewal
  // writes the TGT (that is what a renewal is) and S4U2Self writes the evidence
  // ticket. Doing only the second leaves the TGT half of the purge asserting
  // that a key which was never in localStorage is not in localStorage.
  await driver.executeScript("window.localStorage.setItem('krb_save_ccache', " +
      "'1');");
  await driver.get(baseUrl + "/kerberos_delegation.html");
  await waitForText(driver, "krb_held_pane", /krbtgt|No ticket-granting/, 20000,
    "the held-TGT pane after turning saving on");
  await click(driver, "krb_renew_button");
  await waitForText(driver, "krb_renew_status",
    /Renewed until|refused|error|no renew-till/i, 40000,
    "the renewal that rewrites the TGT with saving on");
  await setField(driver, "krb_impersonate", impersonate);
  await click(driver, "krb_s4u2self_button");
  await waitForText(driver, "krb_s4u2self_status",
    /Got a ticket for|error|refused|does not|failed/i, 40000,
    "S4U2Self with saving on");

  const before = await driver.executeScript(
    "return { evidence: !!window.localStorage.getItem('krb_s4u_evidence')," +
    "         tgt: !!window.localStorage.getItem('krb_ccache') };");
  assert.ok(before.evidence,
    "this check needs an evidence ticket in localStorage to watch leave; " +
    "with krb_save_ccache set to '1' and S4U2Self just run there should be " +
    "one, so its absence means the preference is not being honoured on the " +
    "way IN — and the purge below would then pass for the wrong reason");
  assert.ok(before.tgt,
    "and the TGT should be there too, for the same reason");

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

// ---------------------------------------------------------------------------
// The hex tabs: five views of each exchange, and the sweep that reads them.
//
// WHY THIS NEEDS A BROWSER when tests/krb5_field_naming.js already reads the
// markup and the bundles. That test can prove the panes are reachable and that
// something fills them; it cannot see the two things that have actually broken.
//
//  1. **The highlight was invisible.** `krb-hex-on` and the resting section
//     tints are the same specificity, so the tints — written later in
//     css/kerberos.css — took the background and left the hovered bytes with
//     `color: #fff` on a pale tint. Every class was defined, every id right,
//     the strip's text still changed, and the view read as "hovering does
//     nothing, you have to click each field", which is how it was reported.
//     Nothing but a computed style can tell you that, so that is what this
//     checks: the lit cells must be legible, measured as contrast between
//     `color` and `background-color` rather than against a hard-coded #12107c
//     that a re-theme would falsify.
//  2. **The sweep itself.** The name must change as the pointer crosses into a
//     new field, with no click anywhere — the pin is the affordance that lets
//     the pointer LEAVE, not the way the view is read. So this moves it
//     and never clicks a cell.
//
// It also checks what only a live page can: that the per-part panes hold the
// bytes of the part they are named after, that the plaintext pane names fields
// no message ever carried in the clear, and that the Ticket pane and the reply
// pane are not the same bytes — which is what a mis-wired convention would
// produce, and would look entirely plausible.
// ---------------------------------------------------------------------------

// Relative luminance, WCAG's formula, on a computed `rgb(...)`.
function luminanceOf(rgb) {
  const parts = String(rgb).match(/\d+(\.\d+)?/g) || [];
  const channel = function (v) {
    const c = Number(v) / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * channel(parts[0]) + 0.7152 * channel(parts[1]) +
      0.0722 * channel(parts[2]);
}

function contrastOf(a, b) {
  const la = luminanceOf(a);
  const lb = luminanceOf(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

async function selectTab(driver, group, tab) {
  log.debug("Entering selectTab(). " + group + "/" + tab);
  const selector = '.krb-tabs[data-krb-tabs="' + group + '"] ' +
      '.krb-tab[data-krb-tab="' + tab + '"]';
  const button = await driver.findElement(By.css(selector));
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' " +
      "});", button);
  await button.click();
  const shown = await driver.executeScript(
    "var p = document.querySelector('.krb-tabpanel[data-krb-tabs=\"" + group +
        "\"][data-krb-tab=\"" + tab + "\"]');" +
    "return p ? p.className : null;");
  assert.ok(shown !== null && shown.indexOf("krb-tabpanel-off") === -1,
    'clicking the "' + tab + '" tab of group "' + group + '" did not show ' +
    "its panel (className is now " + shown + "). wireTabs() pairs them by " +
    "the group name; a strip that is never wired renders buttons that do " +
    "nothing and leaves every panel display:none.");
  log.debug("Leaving selectTab().");
}

// One hex pane, read: how many byte cells it has and what its strip says at
// rest.
async function readHexPane(driver, hostId) {
  log.debug("Entering readHexPane(). " + hostId);
  const state = await driver.executeScript(
    "var host = document.getElementById(arguments[0]);" +
    "if (!host) { return null; }" +
    "var f = host.querySelector('.krb-hex-field');" +
    "var m = host.querySelector('.krb-hex-meta');" +
    "return { cells: host.querySelectorAll('.krb-hex-b').length," +
    // Only the gutter cells that stand for a BYTE. A short final row is padded
    // with blank ones so the column stays aligned, and those deliberately carry
    // no range — they stand for nothing and must never light up — so counting
    // all of them would report up to fifteen more characters than there are
    // bytes and make the comparison below fail on correct markup.
    "         ascii: host.querySelectorAll('.krb-hex-a[data-krb-range]')" +
        ".length," +
    "         field: f ? f.textContent : null," +
    "         meta: m ? m.textContent : null," +
    "         note: (host.querySelector('.krb-note') || {}).textContent || " +
        "null };", hostId);
  log.debug("Leaving readHexPane().");
  return state;
}

// Move the pointer onto one byte cell of a pane and report what the view did.
// Never clicks: the sweep is the gesture under test.
async function hoverByte(driver, hostId, index) {
  log.debug("Entering hoverByte(). " + hostId + "[" + index + "]");
  const cells = await driver.findElements(
      By.css("#" + hostId + " .krb-hex-b"));
  assert.ok(cells.length > index, hostId + " has only " + cells.length +
      " byte cells, so byte " + index + " cannot be hovered");
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' " +
      "});", cells[index]);
  await driver.actions({ bridge: true }).move({ origin: cells[index] })
      .perform();
  const seen = await driver.executeScript(
    "var host = document.getElementById(arguments[0]);" +
    "var on = host.querySelectorAll('.krb-hex-on');" +
    "var style = on[0] ? getComputedStyle(on[0]) : null;" +
    "return { field: host.querySelector('.krb-hex-field').textContent," +
    "         meta: host.querySelector('.krb-hex-meta').textContent," +
    "         lit: on.length," +
    "         bg: style ? style.backgroundColor : null," +
    "         fg: style ? style.color : null };", hostId);
  log.debug("Leaving hoverByte(). " + seen.field);
  return seen;
}

async function theHexTabsShowTheBytesAndNameThemOnHover(driver) {
  log.debug("Entering theHexTabsShowTheBytesAndNameThemOnHover().");

  // The two exchanges whose LAST attempt succeeded, so all five views are
  // filled. S4U2Proxy is deliberately not among them — the section above ends
  // on a refusal, and what that leaves behind is checked separately below. The
  // renewal pane is not here either: it has the two whole-message tabs and no
  // per-part ones, which is why this list is written out rather than derived
  // from the markup. A list read off the page could not tell "not there" from
  // "not supposed to be there".
  const EXCHANGES = [
    { group: "s4u2self", label: "S4U2Self" },
    { group: "forward", label: "forwarding" }
  ];
  const PARTS = [
    { tab: "hex", host: "_reply_hex", expect: /TGS-REP/ },
    { tab: "hex_ticket", host: "_ticket_hex", expect: /Ticket/ },
    { tab: "hex_encpart", host: "_encpart_hex", expect: /SEQUENCE|enc-part/ },
    { tab: "hex_encreppart", host: "_encreppart_hex", expect: /EncTGSRepPart/ }
  ];

  for (const exchange of EXCHANGES) {
    // The request first, which is the plain two-tab case.
    await selectTab(driver, exchange.group + "_request", "hex");
    const request = await readHexPane(driver,
        "krb_" + exchange.group + "_request_hex");
    assert.ok(request && request.cells > 32,
      exchange.label + "'s request hex tab holds " +
      (request ? request.cells : "no") + " byte cells. A TGS-REQ carrying a " +
      "whole AP-REQ as padata is hundreds of bytes, so this pane is empty — " +
      "which is what an exchange nobody ran looks like. Its note says: " +
      (request ? request.note : "(no pane)"));
    assert.strictEqual(request.cells, request.ascii,
      "the readable column must have one cell per byte, or hovering a byte " +
      "cannot light its character: " + request.cells + " hex cells against " +
      request.ascii + " characters");
    assert.ok(/TGS-REQ/.test(request.field),
      exchange.label + "'s request hex strip should name the message at rest " +
      "(the outermost element's own field name), got: " + request.field);

    let previous = null;
    for (const part of PARTS) {
      const host = "krb_" + exchange.group + part.host;
      await selectTab(driver, exchange.group + "_reply", part.tab);
      const pane = await readHexPane(driver, host);
      assert.ok(pane && pane.cells > 8,
        exchange.label + "'s " + part.tab + " pane (" + host + ") holds " +
        (pane ? pane.cells : "no") + " byte cells. These three come from the " +
        "reply AFTER it is opened — renderMessage() cannot fill them on the " +
        "way past — so an empty one means renderReplyPartsHex() was not " +
        "called or was called with nothing. Its note says: " +
        (pane ? pane.note : "(no pane)"));
      assert.ok(part.expect.test(pane.field),
        exchange.label + "'s " + part.tab + " pane names itself \"" +
        pane.field + "\" at rest, expected " + part.expect + ". The resting " +
        "name is the outermost element's own, so a pane showing the wrong " +
        "bytes says so here — and a Ticket tab holding the whole reply would " +
        "otherwise look entirely plausible.");
      // The parts must not be each other. A convention that derived the same id
      // twice, or a caller passing the reply where the ticket belongs, gives
      // four tabs over one byte string — and every assertion above still
      // passes.
      if (previous !== null) {
        assert.notStrictEqual(pane.cells, previous,
          exchange.label + "'s " + part.tab + " pane has exactly as many " +
          "bytes as the pane before it (" + pane.cells + "). These are " +
          "different byte strings — a reply, the ticket inside it, that " +
          "ticket's envelope, the plaintext — so equal lengths mean two tabs " +
          "are showing the same thing.");
      }
      previous = pane.cells;
    }
  }

  // ---------------------------------------------------------------------
  // A REFUSED exchange must leave the per-part panes empty, and this is the one
  // place that can be checked. S4U2Proxy's last attempt above was a target
  // nothing authorizes, so its reply is a KRB-ERROR: there is no ticket, no
  // enc-part and no plaintext in it. Those three panes are the only ones on any
  // of these pages that cannot be filled by renderMessage() on the way past —
  // they need a reply that has been opened and decrypted — which makes them the
  // only ones that can go STALE. Left unemptied they would show the RBCD
  // success's ticket beside a decoded pane reporting KDC_ERR_BADOPTION: two
  // panes disagreeing about what just happened, which is worse than an empty
  // tab, and completely plausible on screen.
  // ---------------------------------------------------------------------
  await selectTab(driver, "s4u2proxy_reply", "hex");
  const refusedReply = await readHexPane(driver, "krb_s4u2proxy_reply_hex");
  assert.ok(refusedReply.cells > 8 && /KRB-ERROR/.test(refusedReply.field),
    "the refused S4U2Proxy's reply hex tab should hold the KRB-ERROR's own " +
    "bytes and name it: " + JSON.stringify(refusedReply));
  for (const part of ["_ticket_hex", "_encpart_hex", "_encreppart_hex"]) {
    const tab = { _ticket_hex: "hex_ticket", _encpart_hex: "hex_encpart",
        _encreppart_hex: "hex_encreppart" }[part];
    await selectTab(driver, "s4u2proxy_reply", tab);
    const pane = await readHexPane(driver, "krb_s4u2proxy" + part);
    assert.strictEqual(pane.cells, 0,
      "krb_s4u2proxy" + part + " still holds " + pane.cells + " bytes after " +
      "an exchange the KDC REFUSED. Those bytes are from an earlier attempt, " +
      "and they are sitting under a tab beside a decoded pane that says " +
      "KDC_ERR_BADOPTION. renderReplyPartsHex() has to be called with null " +
      "before the send, not only with the reply after it.");
    assert.ok(/Nothing yet/.test(pane.note || ""),
      "and an emptied pane must say so rather than be blank — a blank pane " +
      "and a pane for a zero-byte message look identical: " + pane.note);
  }

  // ---------------------------------------------------------------------
  // The sweep, on the pane whose bytes are the most interesting: the decrypted
  // EncTGSRepPart of the S4U2Self reply. No clicks.
  // ---------------------------------------------------------------------
  await selectTab(driver, "s4u2self_reply", "hex_encreppart");
  const host = "krb_s4u2self_encreppart_hex";
  const first = await hoverByte(driver, host, 12);
  assert.ok(first.lit > 0,
    "hovering a byte lit nothing. The name in the strip and the bytes it " +
    "names are two halves of one answer, and the highlight is the half that " +
    "says WHICH bytes: " + JSON.stringify(first));
  assert.ok(/EncTGSRepPart →/.test(first.field),
    "hovering a byte inside the plaintext must name the field it belongs to, " +
    "not just the message: " + first.field + ". This is the only view in the " +
    "workflow of a message that never crossed the wire in the clear, and the " +
    "names are what make it readable.");
  assert.ok(/offset \d+ \(0x[0-9a-f]{4}\)/.test(first.meta),
    "and the second line must say where and how big: " + first.meta);

  // THE REGRESSION. The lit cells have to be legible — not merely classed.
  const contrast = contrastOf(first.fg, first.bg);
  assert.ok(contrast >= 4.5,
    "the highlighted bytes are " + first.fg + " on " + first.bg + ", a " +
    "contrast ratio of " + contrast.toFixed(2) + ". The highlight is " +
    "therefore invisible or nearly so, which is exactly the failure this " +
    "check exists for: `.krb-hex-on` and the resting tints `.krb-hex-s0..s5` " +
    "have the same specificity, so whichever css/kerberos.css declares LAST " +
    "owns the background — and when the tints took it, the hovered bytes " +
    "kept " +
    "white text over a pale tint. Nothing errors, every class is defined, " +
    "and " +
    "the view reads as one where hovering does nothing and each field has to " +
    "be clicked. See theHoverHighlightWinsOverTheTints() in " +
    "tests/krb5_field_naming.js for the static half.");

  // And the sweep: crossing into another field renames and re-lights, with no
  // click in between. WHICH byte lands in another field depends on the reply,
  // so
  // the pointer walks until the name changes rather than trusting one offset —
  // an assertion pinned to byte 60 would start passing or failing for reasons
  // that have nothing to do with hovering.
  let second = null;
  let secondAt = null;
  let visited = [first.field];
  for (const at of [24, 40, 56, 72, 88, 104]) {
    const seen = await hoverByte(driver, host, at);
    visited.push(seen.field);
    if (seen.field !== first.field) {
      second = seen;
      secondAt = at;
      break;
    }
  }
  assert.ok(second,
    "sweeping the pointer across six bytes of the plaintext never changed " +
    "the " +
    "name in the strip: it said \"" + visited.join("\", \"") + "\". The view " +
    "is read by moving the pointer along the bytes — that is the whole " +
    "gesture — and a strip that only changes on a click makes it a view you " +
    "operate one element at a time with a mouse button.");
  assert.ok(second.lit > 0, "and the highlight must follow the name");
  assert.ok(contrastOf(second.fg, second.bg) >= 4.5,
    "the second field's highlight is not legible either: " + second.fg +
    " on " + second.bg);

  // Leaving the dump goes back to the resting caption, so the last field the
  // pointer touched is not left looking selected.
  await driver.executeScript(
    "document.getElementById(arguments[0]).dispatchEvent(" +
    "new MouseEvent('mouseleave', { bubbles: false }));", host);
  const atRest = await readHexPane(driver, host);
  assert.ok(/^EncTGSRepPart$/.test(atRest.field.trim()),
    "with the pointer off the dump the strip must go back to naming the " +
    "message, got: " + atRest.field);
  assert.ok(/move the pointer/i.test(atRest.meta),
    "and the resting caption should say how the view is read: " + atRest.meta);

  // Then the pin, which is the other half of the gesture: click a byte and the
  // pointer can leave without losing the answer.
  const cells = await driver.findElements(By.css("#" + host + " .krb-hex-b"));
  await driver.actions({ bridge: true }).move({ origin: cells[12] }).click()
      .perform();
  const pinned = await driver.executeScript(
    "var h = document.getElementById(arguments[0]);" +
    "return { field: h.querySelector('.krb-hex-field').textContent," +
    "         meta: h.querySelector('.krb-hex-meta').textContent," +
    "         lit: h.querySelectorAll('.krb-hex-on').length };", host);
  assert.ok(/pinned/.test(pinned.meta),
    "clicking a byte must say it is pinned and how to release it: " +
        pinned.meta);
  // Moved to the byte the sweep above PROVED is in another field. Any other
  // byte
  // would make this vacuous: a pin that did nothing would also leave the name
  // unchanged if the pointer never left the field it was pinned on.
  const movedWhilePinned = await hoverByte(driver, host, secondAt);
  assert.strictEqual(movedWhilePinned.field, pinned.field,
    "a pinned field must survive the pointer moving on — that is what the " +
    "pin is for: " + movedWhilePinned.field);

  // Released by clicking it again, or the view is stuck for good.
  await driver.actions({ bridge: true }).move({ origin: cells[12] }).click()
      .perform();
  const released = await hoverByte(driver, host, secondAt);
  assert.notStrictEqual(released.field, pinned.field,
    "clicking the pinned field again must release it, so the sweep works " +
    "afterwards: still showing " + released.field);

  log.info("[delegation] the hex tabs hold five views of each exchange, and " +
    "the sweep names each field with a legible highlight (contrast " +
    contrast.toFixed(1) + ":1)");
  log.debug("Leaving theHexTabsShowTheBytesAndNameThemOnHover().");
}

// ---------------------------------------------------------------------------
// The Operations History pane's User / principal column, on a live page.
//
// Reported 2026-08-17 as `[object Object]` in that cell. The cause is that
// every page here revives a cached credential before spending it and `revive()`
// returns a PARSED principal, which four rows handed straight to a log that
// renders with `textContent`. tests/krb5_operation_history.js covers both
// halves of the fix without a browser — the log normalizes what it is given,
// and no bundle passes an object — so what is left for a browser is the part
// neither can see: that the value reaching the cell is the WHOLE name, realm
// included.
//
// That distinction matters because the quiet version of this bug renders
// `alice` where the row beside it says `EXAMPLE.COM`. Both static checks pass
// on that: the object never reaches the log, and the log's own normalization
// would produce exactly the same string, since `revive()` splits the realm off
// into its own field and a parsed name carries `realm: null`.
// ---------------------------------------------------------------------------
async function theHistoryNamesTheUserRatherThanAnObject(driver) {
  log.debug("Entering theHistoryNamesTheUserRatherThanAnObject().");
  // The cells are found BY THEIR HEADER rather than by index. op_history.js
  // renders `#`, `Time (UTC)`, then the configured columns, then `Result` — so
  // an index is off by two and stays plausible: reading the wrong column here
  // would compare the operation label against a principal and fail for a reason
  // that names neither.
  const rows = await driver.executeScript(
    "var head = document.querySelectorAll('.krb-op-table thead th');" +
    "var at = {};" +
    "for (var h = 0; h < head.length; h++) {" +
    "  at[head[h].textContent.trim()] = h;" +
    "}" +
    "var out = [];" +
    "var body = document.querySelectorAll('.krb-op-table tbody tr');" +
    "for (var i = 0; i < body.length; i++) {" +
    "  var cells = body[i].querySelectorAll('td');" +
    "  var read = function (label) {" +
    "    var cell = cells[at[label]];" +
    "    return cell ? cell.textContent.trim() : null;" +
    "  };" +
    "  out.push({ operation: read('Call made')," +
    "             principal: read('User / principal')," +
    "             target: read('Target') });" +
    "}" +
    "return { headers: Object.keys(at), rows: out };");
  assert.ok(rows.headers.indexOf("User / principal") !== -1,
    "the Operations History pane has no \"User / principal\" column — its " +
    "headers are " + JSON.stringify(rows.headers) + ". kerberos_history.js " +
    "names it, so either the label changed (and this check is now reading " +
    "nothing) or the pane is not the one being rendered.");
  rows.rows.forEach(function (row) {
    assert.ok(row.principal !== null && row.operation !== null,
      "a row is missing cells the headers promised: " + JSON.stringify(row));
  });
  assert.ok(rows.rows.length >= 4,
    "the Operations History pane shows " + rows.rows.length + " row(s) after " +
    "four exchanges on this page. This check reads the rendered table, so " +
    "too few " +
    "rows means it is reading the wrong thing and everything below it would " +
    "pass by having nothing to look at.");

  rows.rows.forEach(function (row) {
    assert.ok(!/\[object/.test(row.principal),
      "the User / principal cell of the \"" + row.operation + "\" row reads " +
      row.principal + ". That is the reported defect: a parsed principal " +
      "reaching a cell rendered with textContent. It is a whole object's " +
      "worth of information replaced by nine characters, in the one column " +
      "that answers which user the operation acted as.");
    assert.ok(!/\[object/.test(row.target) &&
        !/\[object/.test(row.operation),
      "another cell of the \"" + row.operation + "\" row stringifies an " +
      "object: " + JSON.stringify(row));
  });

  // The rows this page's own exchanges opened, and the realm on them. Renewal
  // and forwarding both act as whoever the TGT was issued to — the front-end
  // SERVICE account here, which is the point of the delegation page — so their
  // principal is that account, fully qualified.
  const named = rows.rows.filter(function (row) {
    return /RENEW|forwarded TGT/.test(row.operation);
  });
  assert.ok(named.length >= 2,
    "expected the renewal and forwarding rows; found " +
    JSON.stringify(rows.rows.map(function (r) { return r.operation; })));
  named.forEach(function (row) {
    assert.strictEqual(row.principal, frontend + "@" + realm,
      "the \"" + row.operation + "\" row names its user as " + row.principal +
      ", expected " + frontend + "@" + realm + ". A bare name with no realm " +
      "is the quiet half of this defect: revive() splits the realm into its " +
      "own field, so a page that logs the parsed name alone loses it, and " +
      "every check that cannot see this cell still passes.");
  });

  log.info("[delegation] the history names its user as " +
    named[0].principal + " rather than an object");
  log.debug("Leaving theHistoryNamesTheUserRatherThanAnObject().");
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
  // --headless=new, never bare --headless: the image's Chrome 121 ignores
  // --unsafely-treat-insecure-origin-as-secure in the old mode, and this page
  // derives keys with Web Crypto. Headless is not optional here either — a
  // test that opens a visible window steals focus on a developer's desktop
  // and has nowhere to draw on a CI runner.
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1400");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await theServiceAuthenticatesAsItself(driver);
    await s4u2SelfObtainsEvidenceForSomebodyElse(driver);
    await s4u2ProxyWorksBothWaysAndExplainsRefusals(driver);
    await forwardingAndRenewalReportWhatTheyDid(driver);
    // After all three exchanges, and before the opt-out section clears storage
    // and reloads: the hex panes are filled by the exchanges above, so this has
    // to run while their replies are still on the page.
    await theHexTabsShowTheBytesAndNameThemOnHover(driver);
    // Before the opt-out section, which reloads the page and runs two more
    // exchanges: this reads the rows the four exchanges above it opened.
    await theHistoryNamesTheUserRatherThanAnObject(driver);
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
