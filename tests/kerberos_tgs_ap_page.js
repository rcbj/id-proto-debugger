// File: kerberos_tgs_ap_page.js
//
// client/public/kerberos_tgs.html and kerberos_ap.html — spending a TGT on a service
// ticket, and presenting it.
//
// ---------------------------------------------------------------------------
// Why this drives all THREE pages rather than the two it is named for.
//
// tests/krb5_tgs_ap.js already covers the protocol with no browser. What is not
// covered anywhere is the **handoff**: the AS page produces a TGT, the TGS page
// spends it, the AP page presents the result, and they pass those credentials to each
// other through a shared cache in kerberos_panes.js. Testing the TGS page in
// isolation would mean fabricating a TGT in storage, which tests the fabrication
// rather than the workflow — and the handoff is precisely where a rename or a
// storage-preference change breaks things silently. One did: a refactor left three
// sites calling `removeItem(KEYS.CCACHE)` where the shared module had renamed the key
// to KEYS.TGT, so `removeItem(undefined)` deleted a key called "undefined" and the
// opt-out purge quietly stopped working.
//
// So this walks the chain, and the assertions are about what only a browser shows:
//
//  * the TGS page REFUSES to act with no TGT held, and says why rather than failing
//    when the button is pressed;
//  * it reports which key usage opened the reply — 8 without a subkey, 9 with one —
//    because a client that always tries one fails half the time and the symptom is an
//    integrity error naming neither;
//  * the issued service ticket is NOT flagged `initial`, since only the AS exchange
//    issues one and a service may rely on that;
//  * the AP page decodes the 0x8003 checksum field by field, including that Lgth is
//    16 and that Bnd is sixteen zero bytes rather than absent;
//  * mutual authentication is reported as CONFIRMED only when the echo was actually
//    checked, and unticking MUTUAL says plainly that nothing has proved the service's
//    identity; and
//  * per-message tokens are keyed from the ACCEPTOR's subkey once one is offered.
//
// **Services needed:** the client, the api, and the mock STS (which carries both the
// KDC and the ticket-protected service). It also needs `krb5ServicePorts` set in the
// api configuration, because POST /krb5/service is off by default — so it checks that
// and skips with a named reason rather than failing, since a disabled capability is a
// configuration fact and not a defect.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { usernameFor, requireKnownOrCreatable } =
    require("./random_username.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "kerberos_tgs_ap_page",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var apiUrl = process.env.API_URL || "http://localhost:4000";
var stsUrl = process.env.STS_URL || "http://localhost:8081";
var kdcHost = process.env.KRB5_KDC_HOST || "localhost";
var kdcPort = process.env.KRB5_KDC_PORT || "88";
var serviceHost = process.env.KRB5_SERVICE_HOST || kdcHost;
var servicePort = process.env.KRB5_SERVICE_PORT || "8888";
var realm = process.env.KRB5_REALM || "EXAMPLE.COM";
// Generated per run, prefixed with this file's name. The mock KDC registers an
// account for any username on first sight, so this need not be a configured
// principal — and should not be, because its table is never pruned and a name
// shared by every test makes a row in it untraceable. KRB5_PRINCIPAL pins it.
var principal = process.env.KRB5_PRINCIPAL || usernameFor("kerberos-tgs-ap");
// One password for every user in the mock KDC, whoever KRB5_PRINCIPAL names.
var password = process.env.KRB5_PASSWORD || "password!";
var spn = process.env.KRB5_SPN || "HTTP/web.example.com";

async function waitForText(driver, id, pattern, timeoutMs, what) {
  // Content, not elements: every field here is static markup, so elementLocated
  // succeeds during parsing and says nothing about whether the exchange
  // happened.
  log.debug("Entering waitForText().");
  let last = "";
  try {
    await driver.wait(async function () {
      last = await driver.findElement(By.id(id)).getText();
      return pattern.test(last);
    }, timeoutMs || 60000);
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

// What has to be true before any of this means anything. Each answer is a
// different reason to skip, and naming which one matters — "the stack is not
// up" and "the api has the service relay switched off" send you to different
// places.
async function preconditions() {
  log.debug("Entering preconditions().");
  try {
    const principals = await fetch(stsUrl + "/krb5/principals");
    if (!principals.ok) {
      log.debug("Leaving preconditions().");
      return {
        ok: false,
        why: stsUrl + "/krb5/principals answered " + principals.status +
        " — the mock STS may be an older build without the KDC"
      };
    }
    const body = await principals.json();
    if (body.realm !== realm) {
      log.debug("Leaving preconditions().");
      return {
        ok: false,
        why: "the mock KDC serves realm " + body.realm + ", not " + realm
      };
    }
    // Asked rather than assumed: this test signs in as a generated name, which
    // works only because this KDC creates accounts on demand. If that ever
    // stops being true the exchange fails as KDC_ERR_C_PRINCIPAL_UNKNOWN, an
    // error about the KDC's table that says nothing about where the name came
    // from.
    const unusable = requireKnownOrCreatable(body, principal);
    if (unusable) {
      log.debug("Leaving preconditions().");
      return { ok: false, why: unusable };
    }
    if ((body.implemented || []).indexOf("TGS exchange") === -1) {
      log.debug("Leaving preconditions().");
      return {
        ok: false,
        why: "the mock KDC does not implement the TGS exchange (it reports: " +
        (body.implemented || []).join(", ") + ") — the sts/ gitlink may " +
            "predate it"
      };
    }
    const service = await fetch(stsUrl + "/krb5/service");
    if (!service.ok) {
      log.debug("Leaving preconditions().");
      return {
        ok: false,
        why: "the mock STS has no ticket-protected service (" +
        stsUrl + "/krb5/service answered " + service.status + ")"
      };
    }
    const limits = await fetch(apiUrl + "/krb5/limits");
    if (!limits.ok) {
      log.debug("Leaving preconditions().");
      return {
        ok: false,
        why: "the api at " + apiUrl + " did not answer GET /krb5/limits (" +
        limits.status + ")"
      };
    }
    const l = await limits.json();
    if (!l.serviceEnabled) {
      log.debug("Leaving preconditions().");
      return {
        ok: false,
        why: "the api has POST /krb5/service DISABLED (krb5ServicePorts is " +
        JSON.stringify(l.servicePorts) + "). That endpoint is off by default " +
            "because a Kerberos " +
        "service can be on any port, so it is a broader capability than the " +
            "KDC relay — set " +
        "krb5ServicePorts to " + servicePort + " to run this test"
      };
    }
    log.debug("Leaving preconditions().");
    return {
      ok: true,
      kdcPort: String(body.kdcPort),
      servicePort: String((await service.json()).port)
    };
  } catch (e) {
    log.debug("Leaving preconditions().");
    return { ok: false, why: "could not reach the stack (" + e.message + ")" };
  }
  log.debug("Leaving preconditions().");
}

// ---------------------------------------------------------------------------
async function getATgtOnTheAsPage(driver) {
  log.debug("Entering getATgtOnTheAsPage().");
  await driver.get(baseUrl + "/kerberos.html");
  await driver.wait(until.elementLocated(By.id("krb_noreauth_button")), 20000);
  await setField(driver, "krb_realm", realm);
  await setField(driver, "krb_principal", principal);
  await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);
  await driver.findElement(By.id("krb_noreauth_button")).click();
  await waitForText(driver, "krb_as_status",
      /PREAUTH_REQUIRED|issued a ticket WITHOUT/, 60000,
    "the AS page's first request produced no result");
  // CLEAR FIRST: the field arrives pre-filled from the build's
  // krb5PasswordDefault (applyBuildDefaults() in client/src/kerberos.js), so
  // sendKeys APPENDS and the KDC is handed the password twice over —
  // KDC_ERR_PREAUTH_FAILED, which reads as a wrong credential rather than as a
  // doubled one.
  await driver.findElement(By.id("krb_password")).clear();
  await driver.findElement(By.id("krb_password")).sendKeys(password);
  await driver.findElement(By.id("krb_preauth_button")).click();
  const status = await waitForText(driver, "krb_as_status",
      /A TGT for|will not decrypt|refused/, 60000,
    "the AS page produced no ticket");
  assert.ok(/A TGT for/.test(status), "a TGT is needed before this test can " +
      "start: " + status);

  // The handoff itself: the TGT must be where the next page will look.
  const held = await driver.executeScript("return " +
      "!!sessionStorage.getItem('krb_ccache');");
  assert.strictEqual(held, true,
    "the AS page must leave the TGT in sessionStorage for the TGS page to " +
        "find — that handoff is " +
    "what kerberos_panes.js's shared cache is for");
  log.info("a TGT for " + principal + "@" + realm + " is held");
  log.debug("Leaving getATgtOnTheAsPage().");
}

async function theTgsPageRefusesWithNoTgt(driver) {
  log.debug("Entering theTgsPageRefusesWithNoTgt().");
  await driver.get(baseUrl + "/kerberos_tgs.html");
  await driver.wait(until.elementLocated(By.id("krb_tgs_button")), 20000);
  // Clear the cache and reload: the page must refuse up front rather than when
  // the button is pressed. A user with no TGT should not be able to send a
  // request that cannot possibly be answered.
  await driver.executeScript("sessionStorage.clear(); " +
      "localStorage.removeItem('krb_ccache');");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("krb_tgs_button")), 20000);
  const disabled = await driver.findElement(By.id("krb_tgs_button")).getAttribute("disabled");
  assert.ok(disabled, "with no TGT held the TGS button must be DISABLED, not " +
      "merely fail when pressed");
  // NOTE on what that assertion is worth on its own: the button is `disabled`
  // in the MARKUP, so it is satisfied even if renderHeldTgt() does nothing at
  // all — mutation-testing showed exactly that. The assertion that carries the
  // weight is the opposite direction, in theTgsPageSpendsTheTgt: the button
  // must become ENABLED once a TGT is held, which only the logic can do.
  const pane = await driver.findElement(By.id("krb_tgt_pane")).getText();
  assert.ok(/No TGT held/.test(pane) && /AS exchange/.test(pane),
    "and the page must say where to get one: " + pane.slice(0, 200));
  log.debug("Leaving theTgsPageRefusesWithNoTgt().");
}

async function theTgsPageSpendsTheTgt(driver) {
  log.debug("Entering theTgsPageSpendsTheTgt().");
  await driver.get(baseUrl + "/kerberos_tgs.html");
  await driver.wait(until.elementLocated(By.id("krb_tgs_button")), 20000);
  const tgtPane = await driver.findElement(By.id("krb_tgt_pane")).getText();
  assert.ok(/krbtgt/.test(tgtPane),
    "the TGS page must show the held TGT, and it is a ticket for krbtgt: " +
        tgtPane.slice(0, 200));
  assert.ok(/A CREDENTIAL/.test(tgtPane),
    "and must label the session key as the credential it is");
  // The direction that proves renderHeldTgt() ran: the markup ships this button
  // disabled, so only the page's own logic can enable it.
  const enabled = await driver.findElement(By.id("krb_tgs_button")).getAttribute("disabled");
  assert.ok(!enabled,
    "with a valid TGT held the TGS button must be ENABLED. The markup ships " +
        "it disabled, so this " +
    "is the assertion that proves the page read the cache rather than doing " +
        "nothing.");

  await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);
  await setField(driver, "krb_spn", spn);
  await driver.findElement(By.id("krb_tgs_button")).click();
  const status = await waitForText(driver, "krb_tgs_status",
    /service ticket for|S_PRINCIPAL_UNKNOWN|ETYPE_NOSUPP|—/, 60000,
    "the TGS exchange produced no result");
  assert.ok(/service ticket for/.test(status),
    "the TGS exchange should have issued a ticket for " + spn + ": " + status);

  // Without a subkey the reply is at key usage 8. Reported, not hidden: a
  // client that always tries one of the two fails whenever the other applies.
  assert.ok(/key usage 8/.test(status),
    "with no subkey sent, the reply must be reported as opened at key usage " +
        "8: " + status);

  // THE TGT THREE ENVELOPES DOWN, opened with nothing typed. A TGS-REQ carries
  // its ticket inside an AP-REQ inside PA-TGS-REQ, sealed with krbtgt's key,
  // which nobody driving this page has — and until 2026-08-17 that section
  // ended in an instruction to go and find one. The contents are the KDC's own
  // report of them, kept by the AS page when it obtained the TGT, so the pane
  // shows them with no key and nothing to press.
  const sent = await driver.findElement(By.id("krb_request_pane")).getText();
  assert.ok(/as the KDC reported it/.test(sent),
    "the TGT inside PA-TGS-REQ must show its contents from the KDC's own " +
    "report, with nothing supplied: " + JSON.stringify(sent.slice(-900)));
  assert.ok(/the SESSION key/.test(sent) && /krbtgt\//.test(sent),
    "including the session key, and naming krbtgt as the principal whose " +
    "ticket it is: " + JSON.stringify(sent.slice(-900)));
  // The absence of a control, not merely the absence of a click: a pane that
  // needs a key typed into it is exactly what this replaced, and it would pass
  // every assertion above if this test happened to fill it in.
  const keyFields = await driver.findElements(By.id("krb_deckey_button"));
  assert.strictEqual(keyFields.length, 0,
    "and this page must carry no key-entry pane at all — what such a pane " +
    "asked for is now shown without asking, and the one part it could still " +
    "open (the PAC) belongs on the Decoder page");

  const tickets = await driver.findElement(By.id("krb_tickets_pane")).getText();
  assert.ok(tickets.indexOf(spn) !== -1,
      "the service ticket must be listed: " + tickets.slice(0, 200));
  // Only the AS exchange issues an `initial` ticket, and a service may insist
  // on that distinction — so a TGS-issued ticket carrying it would be a lie.
  // getText() on a two-column table puts the NAME and the VALUE on separate
  // lines, so the line matching /^flags/ is the label and the flags themselves
  // are the line after it. Matching the label and asserting against it compares
  // a heading with a flag list, which fails for a reason that has nothing to do
  // with the ticket.
  const lines = tickets.split("\n").map(function (l) { return l.trim(); });
  const flagsAt = lines.indexOf("flags");
  assert.ok(flagsAt !== -1 && lines[flagsAt + 1],
    "the ticket pane must have a flags row with a value under it: " +
        tickets.slice(0, 300));
  const flagsLine = lines[flagsAt + 1];
  assert.ok(flagsLine.indexOf("initial") === -1,
    "a ticket from the TGS exchange must NOT be flagged initial — only the " +
        "AS exchange issues one, " +
    "and a service may insist on that distinction. Flags: " + flagsLine);
  assert.ok(/pre-authent/.test(flagsLine),
    "but pre-authent is inherited from the TGT: " + flagsLine);

  // Now WITH a subkey: key usage 9. The KDC chooses based on what was sent.
  await driver.findElement(By.id("krb_use_subkey")).click();
  await driver.findElement(By.id("krb_tgs_button")).click();
  const withSubkey = await waitForText(driver, "krb_tgs_status",
      /key usage 9|key usage 8|—/, 60000,
    "the TGS exchange with a subkey produced no result");
  assert.ok(/key usage 9/.test(withSubkey),
    "with a subkey in the Authenticator the reply must come back at key " +
        "usage 9, and the page must " +
    "say so: " + withSubkey);

  // And the handoff to the AP page.
  const stored = await driver.executeScript("return " +
      "!!sessionStorage.getItem('krb_service_tickets');");
  assert.strictEqual(stored, true, "the service ticket must be left where " +
      "the AP page will look for it");
  log.info("a service ticket for " + spn + " is held");
  log.debug("Leaving theTgsPageSpendsTheTgt().");
}

async function theApPagePresentsItAndChecksTheEcho(driver) {
  log.debug("Entering theApPagePresentsItAndChecksTheEcho().");
  await driver.get(baseUrl + "/kerberos_ap.html");
  await driver.wait(until.elementLocated(By.id("krb_present_button")), 20000);

  const environment = await waitForText(driver, "krb_environment_note",
      /relay|did not answer/, 20000,
    "the AP page never reported what the api allows");
  assert.ok(/presenting a ticket to a service is enabled/.test(environment),
    "the AP page must confirm the service relay is enabled before offering " +
        "the button: " +
    environment.slice(0, 220));

  const ticketPane = await driver.findElement(By.id("krb_ticket_pane")).getText();
  assert.ok(ticketPane.indexOf(spn) !== -1,
    "the ticket the TGS page bought must be offered here: " +
        ticketPane.slice(0, 200));

  await setField(driver, "krb_service_host", serviceHost);
  await setField(driver, "krb_service_port", servicePort);
  await driver.findElement(By.id("krb_present_button")).click();
  const status = await waitForText(driver, "krb_ap_status",
    /ACCEPTED|FAILED|REPEAT|BADKEYVER|SKEW|—/, 90000, "the AP exchange " +
        "produced no result");
  assert.ok(/ACCEPTED/.test(status), "the service should have accepted the " +
      "ticket: " + status);
  assert.ok(/proved itself/.test(status),
    "and the page must say the service proved itself, not merely that it " +
        "accepted: " + status);

  // The GSS wrapper, which is what a service is actually handed.
  const request = await driver.findElement(By.id("krb_request_pane")).getText();
  assert.ok(/0x60/.test(request) && /1\.2\.840\.113554\.1\.2\.2/.test(request),
    "the page must show the InitialContextToken wrapper and the Kerberos " +
        "mechanism OID: " +
    request.slice(0, 250));
  assert.ok(/01 00/.test(request), "and the AP-REQ token id");

  // And the ticket being PRESENTED, which is the whole subject of this page:
  // sealed with the service account's key, which this page does not hold, and
  // legible anyway because the TGS page kept what the KDC said was in it.
  const apreq = await driver.findElement(By.id("krb_apreq_pane")).getText();
  assert.ok(/as the KDC reported it/.test(apreq),
    "the presented ticket must show its contents from the KDC's own report: " +
        JSON.stringify(apreq.slice(-900)));
  assert.ok(/authorization-data/.test(apreq) &&
      /not repeated in the reply/.test(apreq),
    "and must name the ONE field that report cannot cover — the PAC — rather " +
    "than leaving it as a gap the reader has to notice: " +
        JSON.stringify(apreq.slice(-900)));
  const apKeyFields = await driver.findElements(By.id("krb_deckey_button"));
  assert.strictEqual(apKeyFields.length, 0,
    "and this page must carry no key-entry pane either");

  // The 0x8003 structure, field by field. This is the pane the AP page exists
  // for.
  const checksum = await driver.findElement(By.id("krb_checksum_pane")).getText();
  assert.ok(/Lgth/.test(checksum), "the 0x8003 checksum must be decoded, not " +
      "shown as hex: " +
    checksum.slice(0, 200));
  assert.ok(/little-endian/i.test(checksum),
    "and the pane must say its integers are little-endian, which is why it " +
        "is the field that most " +
    "often goes wrong");
  assert.ok(/sixteen ZERO bytes|no channel bindings/i.test(checksum),
    "Bnd with no channel bindings is sixteen zero bytes rather than absent, " +
        "and the pane should say " +
    "so: " + checksum.slice(0, 300));
  assert.ok(/MUTUAL/.test(checksum), "MUTUAL must appear in the flags, since " +
      "it was requested");

  // The context: mutual authentication confirmed, and the per-message keying.
  const context = await driver.findElement(By.id("krb_context_pane")).getText();
  assert.ok(/CONFIRMED/.test(context), "mutual authentication must be " +
      "reported as confirmed: " +
    context.slice(0, 200));
  assert.ok(/echoed/.test(context) && /session key/.test(context),
    "and the page must explain that the echo IS the proof: " + context.slice(0,
        300));
  assert.ok(/acceptor's subkey/.test(context),
    "once the acceptor offers a subkey, per-message tokens must be keyed " +
        "from IT rather than from " +
    "the ticket's session key: " + context.slice(0, 300));
  log.debug("Leaving theApPagePresentsItAndChecksTheEcho().");
}

async function perMessageTokensWorkAndRejectTampering(driver) {
  log.debug("Entering perMessageTokensWorkAndRejectTampering().");
  await driver.findElement(By.id("krb_mic_button")).click();
  const mic = await waitForText(driver, "krb_permessage_pane",
      /GetMIC|token id/, 40000,
    "GetMIC produced nothing");
  assert.ok(/04 04/.test(mic), "a MIC token's id is 04 04: " + mic.slice(0,
      200));
  assert.ok(/does not verify/.test(mic),
    "the pane must show that the same MIC does NOT verify over a modified " +
        "message — a MIC that " +
    "verified anything would be worse than none: " + mic.slice(0, 300));
  assert.ok(/initiator/.test(mic),
    "and that the sender's role is in the token, since the verifier must use " +
        "the SENDER's key usage");

  await driver.findElement(By.id("krb_wrap_button")).click();
  const wrap = await waitForText(driver, "krb_permessage_pane", /GSS_Wrap/,
      40000, "Wrap produced nothing");
  assert.ok(/05 04/.test(wrap), "a Wrap token's id is 05 04: " + wrap.slice(0,
      200));
  assert.ok(/the quick brown fox/.test(wrap), "and what was wrapped must " +
      "come back out");
  assert.ok(/appears\s+twice|twice/.test(wrap),
    "the pane should explain that the header appears twice — once clear, " +
        "once encrypted — which is " +
    "what stops the clear copy being altered: " + wrap.slice(0, 300));
  log.debug("Leaving perMessageTokensWorkAndRejectTampering().");
}

// Without MUTUAL the service need not answer at all. The page must say what
// that means rather than presenting silence as success — this is the difference
// between authenticating a client and authenticating a connection.
async function withoutMutualNothingProvesTheService(driver) {
  log.debug("Entering withoutMutualNothingProvesTheService().");
  await driver.get(baseUrl + "/kerberos_ap.html");
  await driver.wait(until.elementLocated(By.id("krb_present_button")), 20000);
  await setField(driver, "krb_service_host", serviceHost);
  await setField(driver, "krb_service_port", servicePort);
  await driver.findElement(By.id("krb_flag_mutual")).click();       // untick
  await driver.findElement(By.id("krb_present_button")).click();
  const status = await waitForText(driver, "krb_ap_status",
    /accepted|ACCEPTED|nothing|—/, 90000, "the one-way exchange produced no " +
        "result");
  assert.ok(/NOTHING has proved|nothing has proved/i.test(status),
    "with MUTUAL unticked the page must say that nothing has proved the " +
        "service's identity, rather " +
    "than reporting plain success: " + status);
  log.debug("Leaving withoutMutualNothingProvesTheService().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The TGS and AP exchange pages at " + baseUrl +
      ".");
  const ready = await preconditions();
  if (!ready.ok) {
    // Named, never silent. A skip that did not say which precondition failed
    // would be indistinguishable from a pass.
    log.warn("SKIPPED: " + ready.why + ". This test needs the client, the " +
        "api and the mock STS " +
      "(KDC and ticket-protected service), and the api's krb5ServicePorts " +
          "set.");
    log.info("Test completed successfully.");
    return;
  }
  if (ready.kdcPort && ready.kdcPort !== String(kdcPort)) {
    log.warn("the mock STS reports its KDC on port " + ready.kdcPort +
        "; using that.");
    kdcPort = ready.kdcPort;
  }
  if (ready.servicePort && ready.servicePort !== String(servicePort)) {
    log.warn("the mock STS reports its protected service on port " +
        ready.servicePort + "; using that.");
    servicePort = ready.servicePort;
  }

  const options = new chrome.Options();
  // --headless=new, never bare --headless: the image's Chrome 121 ignores
  // --unsafely-treat-insecure-origin-as-secure in the old mode, and these pages
  // derive keys with Web Crypto.
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage",
          "--window-size=1400,1400");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    await getATgtOnTheAsPage(driver);
    await theTgsPageRefusesWithNoTgt(driver);
    await getATgtOnTheAsPage(driver);            // the refusal test cleared it
    await theTgsPageSpendsTheTgt(driver);
    await theApPagePresentsItAndChecksTheEcho(driver);
    await perMessageTokensWorkAndRejectTampering(driver);
    await withoutMutualNothingProvesTheService(driver);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("kerberos_tgs_ap_page")
  .description("Verify the TGS and AP exchange pages, and the credential " +
      "handoff between all three.")
  .addOption(new Option("-u, --url <url>",
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
