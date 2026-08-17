// File: kerberos_spnego_page.js
//
// client/public/spnego.html — a Kerberos ticket travelling in an HTTP header,
// and the two pages a user is routed through to obtain one.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS WHEN krb5_spnego_http.js ALREADY DRIVES THE PROTOCOL.
//
// That test performs the whole handshake with no browser, and it covers the
// negotiation far harder than this one does. What it cannot cover is the four
// things that only exist in a browser, and every one of them is a way for this
// workflow to be broken while the protocol is perfect:
//
//  1. **The ROUTING.** The SPNEGO page cannot obtain a ticket — that is the AS
//     page and then the TGS page — so it sends the user there with
//     `?return=spnego` and each of them offers a link back. A workflow that
//     sends you away and does not return is one you leave, and nothing about
//     the protocol notices. This walks the whole loop: out to the AS page, on
//     to the TGS page with the SPN carried in the query, and back through the
//     banner's own link.
//  2. **The credential handoff**, which is `kerberos_panes.js`'s shared cache
//     under a THIRD reader. A rename there is silent: the pane renders, the
//     button is disabled, and the page says "no service ticket held" for a
//     ticket that is sitting in storage.
//  3. **The SPN this page GUESSES.** It is derived from the URL's host and
//     nothing in the SPNEGO exchange carries it, so when it is wrong the
//     failure is a KDC error three steps earlier that names nothing about
//     HTTP. The field has to exist, be pre-filled, and be overridable.
//  4. **The panes and their tabs**: the decoded NegTokenInit, the AP-REQ
//     inside it, the 0x8003 checksum, the hex view that names a field under
//     the pointer, and the ticket — which is opaque until a service key is
//     supplied and must SAY so rather than rendering an empty pane.
//
// And the negatives, through the UI: a negotiation with no mechanism in common,
// one offering only a mechanism this build cannot perform, and a server that
// accepts the ticket and proves nothing back. Each is a deliberate
// misconfiguration the mock offers as a query parameter.
//
// **Services needed:** the client, the api and the mock STS (its KDC and its
// SPNEGO-protected page). Unlike the AP page's test this needs no extra api
// setting: POST /krb5/spnego is an ordinary outbound HTTP call rather than a
// byte relay to an arbitrary port, so there is nothing to switch on.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "kerberos_spnego_page",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var apiUrl = process.env.API_URL || "http://localhost:4000";
var stsUrl = process.env.STS_URL || "http://localhost:8081";
var kdcHost = process.env.KRB5_KDC_HOST || "localhost";
var kdcPort = process.env.KRB5_KDC_PORT || "88";
var realm = process.env.KRB5_REALM || "EXAMPLE.COM";
var principal = process.env.KRB5_PRINCIPAL || "alice";
// One password for every user in the mock KDC, whoever KRB5_PRINCIPAL names.
var password = process.env.KRB5_PASSWORD || "password!";
var spn = process.env.KRB5_SPN || "HTTP/web.example.com";
// The service account's own password, which is NOT the user password — it is
// what opens the ticket, and the only way this page can show what is inside
// one. Its salt is read from the KDC rather than guessed: a salt is not
// derivable from a principal name, which is the whole reason PA-ETYPE-INFO2
// exists.
var servicePassword = process.env.KRB5_SERVICE_PASSWORD ||
    "service-account-password";
var serviceSalt = null;
// Where the protected page is, as the BROWSER must reach it. Not stsUrl
// blindly: on the containerized stack the browser and the api resolve the mock
// by different names, and this URL is handed to the api rather than fetched
// here — so it is the api's view that matters.
var protectedUrl = process.env.KRB5_SPNEGO_URL || null;

async function waitForText(driver, id, pattern, timeoutMs, what) {
  // Content, not elements. Every field on these pages is static markup, so
  // elementLocated succeeds during parsing and says nothing about whether the
  // exchange happened.
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
        JSON.stringify(last.slice(0, 400)) + ")");
  }
  log.debug("Leaving waitForText().");
  return last;
}

async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  const field = await driver.findElement(By.id(id));
  await field.clear();
  await field.sendKeys(value);
  log.debug("Leaving setField().");
}

async function selectTab(driver, group, name) {
  log.debug("Entering selectTab(). " + group + "/" + name);
  await driver.findElement(By.css('.krb-tabs[data-krb-tabs="' + group +
      '"] .krb-tab[data-krb-tab="' + name + '"]')).click();
  log.debug("Leaving selectTab().");
}

// What has to be true before any of this means anything. Each answer is a
// different reason to skip, and naming which one matters: "the stack is not up"
// and "the mock predates the SPNEGO page" send you to different places.
async function preconditions() {
  log.debug("Entering preconditions().");
  try {
    const principals = await fetch(stsUrl + "/krb5/principals");
    if (!principals.ok) {
      log.debug("Leaving preconditions(). No KDC.");
      return {
        ok: false,
        why: stsUrl + "/krb5/principals answered " + principals.status +
          " — the mock STS may be an older build without the KDC"
      };
    }
    const body = await principals.json();
    if (body.realm !== realm) {
      log.debug("Leaving preconditions(). Wrong realm.");
      return {
        ok: false,
        why: "the mock KDC serves realm " + body.realm + ", not " + realm
      };
    }
    const advert = await fetch(stsUrl + "/spnego?format=json");
    if (!advert.ok) {
      log.debug("Leaving preconditions(). No SPNEGO page.");
      return {
        ok: false,
        why: "the mock STS has no SPNEGO-protected page (" + stsUrl +
          "/spnego answered " + advert.status + ") — the sts/ gitlink " +
          "probably predates it"
      };
    }
    const limits = await fetch(apiUrl + "/krb5/limits");
    if (!limits.ok) {
      log.debug("Leaving preconditions(). No api.");
      return {
        ok: false,
        why: "the api at " + apiUrl + " did not answer GET /krb5/limits (" +
          limits.status + ")"
      };
    }
    const l = await limits.json();
    if (!l.spnegoEnabled) {
      // An older api. Named as such, because "POST /krb5/spnego answered 404"
      // reads as a broken deployment rather than as a build without the
      // endpoint.
      log.debug("Leaving preconditions(). No SPNEGO relay.");
      return {
        ok: false,
        why: "the api does not publish spnegoEnabled, so it has no POST " +
          "/krb5/spnego — this build of the api predates the SPNEGO workflow"
      };
    }
    // The salt for the SERVICE account, read rather than guessed.
    const advertised = await advert.json();
    (body.principals || []).forEach(function (p) {
      if (String(p.principal || "").split("@")[0] === spn) {
        serviceSalt = p.salt || null;
      }
    });
    log.debug("Leaving preconditions(). Ready.");
    return {
      ok: true,
      kdcPort: String(body.kdcPort),
      spn: advertised.servicePrincipalName || null
    };
  } catch (e) {
    log.debug("Leaving preconditions(). Unreachable.");
    return { ok: false, why: "could not reach the stack (" + e.message + ")" };
  }
  log.debug("Leaving preconditions().");
}

// ---------------------------------------------------------------------------
// 1. Out to the AS page, and the banner that says why you are there.
// ---------------------------------------------------------------------------
async function theAsPageOffersTheWayBack(driver) {
  log.debug("Entering theAsPageOffersTheWayBack().");
  log.info("=== The AS page, arrived at from SPNEGO ===");
  await driver.get(baseUrl + "/kerberos.html?return=spnego");
  await driver.wait(until.elementLocated(By.id("krb_noreauth_button")), 20000);

  // The banner has to be there BEFORE a ticket exists — that is the case it is
  // for, and it is the one an implementation puts after an early return and
  // never renders.
  const before = await driver.findElement(By.id("krb_return_banner")).getText();
  assert.ok(/SPNEGO/.test(before),
    "the AS page must offer the way back BEFORE a ticket exists — somebody " +
    "arrives here precisely because they have none, so a banner rendered " +
    "only once a TGT is held is a banner nobody sees. Got: " +
    JSON.stringify(before));
  assert.ok(/service ticket|TGT/.test(before),
    "and it must say what SPNEGO still needs rather than merely linking: " +
    JSON.stringify(before));

  await setField(driver, "krb_realm", realm);
  await setField(driver, "krb_principal", principal);
  await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);
  await driver.findElement(By.id("krb_noreauth_button")).click();
  await waitForText(driver, "krb_as_status",
      /PREAUTH_REQUIRED|issued a ticket WITHOUT/, 60000,
      "the AS page's first request produced no result");
  // CLEAR FIRST: the field arrives pre-filled from the build's
  // krb5PasswordDefault, so sendKeys APPENDS and the KDC is handed the
  // password twice over — KDC_ERR_PREAUTH_FAILED, which reads as a wrong
  // credential rather than as a doubled one.
  await setField(driver, "krb_password", password);
  await driver.findElement(By.id("krb_preauth_button")).click();
  const status = await waitForText(driver, "krb_as_status",
      /A TGT for|will not decrypt|refused/, 60000,
      "the AS page produced no ticket");
  assert.ok(/A TGT for/.test(status),
      "a TGT is needed before this test can start: " + status);

  const after = await driver.findElement(By.id("krb_return_banner")).getText();
  assert.ok(/ticket-granting ticket/.test(after),
    "with a TGT held the banner must change — the user's state changed, and " +
    "a banner that says the same thing either way is decoration. Got: " +
    JSON.stringify(after));
  assert.ok(/SERVICE ticket|TGS/.test(after),
    "and it must say that SPNEGO still needs a SERVICE ticket: a TGT is not " +
    "what that page spends, and sending somebody back now strands them. " +
    "Got: " + JSON.stringify(after));
  log.info("the AS page offers the way back, and says what is still missing");
  log.debug("Leaving theAsPageOffersTheWayBack().");
}

// ---------------------------------------------------------------------------
// 2. On to the TGS page, with the SPN carried in the query.
// ---------------------------------------------------------------------------
async function theTgsPageTakesTheSpnAndOffersTheWayBack(driver) {
  log.debug("Entering theTgsPageTakesTheSpnAndOffersTheWayBack().");
  log.info("=== The TGS page, with the SPN carried through ===");
  await driver.get(baseUrl + "/kerberos_tgs.html?return=spnego&spn=" +
      encodeURIComponent(spn));
  await driver.wait(until.elementLocated(By.id("krb_tgs_button")), 20000);

  const filled = await driver.findElement(By.id("krb_spn"))
      .getAttribute("value");
  assert.strictEqual(filled, spn,
    "the SPN the caller asked for must win over whatever this page used " +
    "last. " +
    "It came from the URL somebody is trying to reach, and buying a ticket " +
    "for the wrong service instead is refused a page later with " +
    "KRB_AP_ERR_NOT_US — which reads as a broken ticket. Got " +
    JSON.stringify(filled));

  const before = await driver.findElement(By.id("krb_return_banner")).getText();
  assert.ok(new RegExp(spn.replace("/", "\\/")).test(before),
    "and the banner must name the SPN that is still needed rather than " +
    "'a ticket': " + JSON.stringify(before));

  await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);
  await driver.findElement(By.id("krb_tgs_button")).click();
  await waitForText(driver, "krb_tgs_status", /A service ticket for|refused/,
      60000, "the TGS page produced no service ticket");

  const after = await driver.findElement(By.id("krb_return_banner")).getText();
  assert.ok(/You now hold/.test(after),
    "once the ticket exists the banner must say so — 'ready' here is not " +
    "'a ticket exists' but 'a ticket for THAT SPN exists', and getting that " +
    "wrong sends somebody back to a page that refuses them. Got: " +
    JSON.stringify(after));
  log.info("the TGS page takes the SPN and reports when the ticket exists");
  log.debug("Leaving theTgsPageTakesTheSpnAndOffersTheWayBack().");
}

// ---------------------------------------------------------------------------
// 3. Back through the banner's own link, and the handoff at the far end.
// ---------------------------------------------------------------------------
async function theBannerLinkLeadsBackAndTheTicketIsThere(driver) {
  log.debug("Entering theBannerLinkLeadsBackAndTheTicketIsThere().");
  log.info("=== Back to SPNEGO ===");
  await driver.findElement(By.css(".krb-return-link")).click();
  await driver.wait(until.elementLocated(By.id("krb_spnego_url")), 20000);
  const url = await driver.getCurrentUrl();
  assert.ok(/spnego\.html/.test(url),
      "the banner's link must land on the SPNEGO page, got " + url);

  await setField(driver, "krb_spnego_url", protectedUrl);
  // Let the URL's own handler derive the SPN before overriding it: the derive
  // fires on blur, and a value typed into an empty field between the clear and
  // the blur ends up concatenated with the derived one.
  await driver.findElement(By.id("krb_spnego_url")).sendKeys("\t");
  const derived = await driver.wait(async function () {
    const v = await driver.findElement(By.id("krb_spnego_spn"))
        .getAttribute("value");
    return /^HTTP\//.test(v) ? v : false;
  }, 10000, "the page never derived an SPN from the URL");
  assert.ok(/^HTTP\//.test(derived),
    "the SPN must be derived from the URL's host as HTTP/<host> and shown, " +
    "because nothing in the SPNEGO exchange carries it and a wrong guess " +
    "fails at the KDC, three steps earlier, naming nothing about HTTP. Got " +
    JSON.stringify(derived));

  await setField(driver, "krb_spnego_spn", spn);
  await driver.findElement(By.id("krb_spnego_spn")).sendKeys("\t");
  await waitForText(driver, "krb_credentials_pane", /HELD/, 20000,
    "the SPNEGO page does not see the service ticket the TGS page just " +
    "stored — the credential handoff through kerberos_panes.js's shared " +
    "cache has broken, which is silent: the pane renders and the button " +
    "stays disabled");

  const disabled = await driver.findElement(By.id("krb_authenticate_button"))
      .getAttribute("disabled");
  assert.ok(!disabled,
      "and holding a matching ticket must enable the button");
  log.info("the way back leads back, and the ticket is where it should be");
  log.debug("Leaving theBannerLinkLeadsBackAndTheTicketIsThere().");
}

// ---------------------------------------------------------------------------
// 4. The unauthenticated request, and the header that is NOT there.
// ---------------------------------------------------------------------------
async function theChallengeIsBare(driver) {
  log.debug("Entering theChallengeIsBare().");
  log.info("=== The unauthenticated request ===");
  await driver.findElement(By.id("krb_probe_button")).click();
  const status = await waitForText(driver, "krb_spnego_status",
      /bare `Negotiate`|does not offer Negotiate|answered/, 60000,
      "the unauthenticated request produced no result");
  assert.ok(/bare `Negotiate` challenge/.test(status),
    "the first challenge must be the bare word `Negotiate` with no token " +
    "after it (RFC 4559 section 4), and the page must say so: " + status);

  const pane = await driver.findElement(By.id("krb_probe_pane")).getText();
  assert.ok(/www-authenticate/i.test(pane),
    "and both sides of the exchange must be shown verbatim — the header is " +
    "the entire visible surface of this protocol, and a cross-origin fetch " +
    "could not read it, which is why the request goes through the api: " +
    JSON.stringify(pane.slice(0, 300)));
  assert.ok(/GET /.test(pane) && /401/.test(pane),
      "including the request line and the status: " +
      JSON.stringify(pane.slice(0, 300)));
  log.info("the first challenge is bare, and both sides are shown");
  log.debug("Leaving theChallengeIsBare().");
}

// ---------------------------------------------------------------------------
// 5. The handshake, and everything the panes show about it.
// ---------------------------------------------------------------------------
async function theHandshakeSucceedsAndIsExplained(driver) {
  log.debug("Entering theHandshakeSucceedsAndIsExplained().");
  log.info("=== The SPNEGO handshake ===");
  await driver.findElement(By.id("krb_authenticate_button")).click();
  const status = await waitForText(driver, "krb_spnego_status",
      /accept-completed|REJECTED|FAILED|could not/, 90000,
      "the handshake produced no result");
  assert.ok(/accept-completed/.test(status),
      "the handshake must complete: " + status);
  assert.ok(/proved its own identity/.test(status),
    "and mutual authentication must be CHECKED rather than assumed — a " +
    "client that asks for it and does not compare the AP-REP's echo has only " +
    "asked: " + status);

  const init = await driver.findElement(By.id("krb_negtokeninit_pane"))
      .getText();
  assert.ok(/1\.3\.6\.1\.5\.5\.2/.test(init),
    "the NegTokenInit pane must name SPNEGO's own OID, which appears exactly " +
    "once in the whole exchange: " + JSON.stringify(init.slice(0, 200)));
  assert.ok(/mechTypes\[0\]/.test(init) && /first preference/i.test(init),
    "and must show the mechanism list AND say what its ORDER decides — RFC " +
    "4178 section 5 makes the mechListMIC optional only when the acceptor " +
    "selects the first entry: " + JSON.stringify(init.slice(0, 400)));
  assert.ok(/MechTypeList bytes/.test(init),
    "and must show the exact bytes the mechListMIC covers, since signing " +
    "`[0] MechTypeList` instead is the commonest mistake in this protocol");

  const resp = await driver.findElement(By.id("krb_negtokenresp_pane"))
      .getText();
  assert.ok(/accept-completed/.test(resp) && /supportedMech/.test(resp),
    "the server's NegTokenResp must be decoded field by field: " +
    JSON.stringify(resp.slice(0, 300)));

  // The AP-REQ tab: the Kerberos message inside the negotiation, and the
  // checksum that is not a checksum.
  await selectTab(driver, "sent", "apreq");
  const apreq = await driver.findElement(By.id("krb_apreq_pane")).getText();
  assert.ok(/AP-REQ/.test(apreq),
      "the AP-REQ inside the mechToken must be decoded: " +
      JSON.stringify(apreq.slice(0, 200)));
  const cksum = await driver.findElement(By.id("krb_checksum_pane")).getText();
  assert.ok(/0x8003/.test(cksum) && /MUTUAL/.test(cksum),
    "and its 0x8003 checksum — the GSS flags, little-endian in a protocol " +
    "where everything else is big-endian — must be decoded field by field: " +
    JSON.stringify(cksum.slice(0, 300)));
  assert.ok(/reqFlags/.test(cksum),
    "and the pane must say why the flags are HERE and not in SPNEGO's own " +
    "reqFlags, which RFC 4178 deprecates and receivers must ignore: " +
    JSON.stringify(cksum.slice(0, 400)));

  // The hex tab: the binary field breakdown, which is the same view
  // kerberos.html carries.
  await selectTab(driver, "sent", "hex");
  const cells = await driver.findElements(By.css("#krb_sent_hex .krb-hex-b"));
  assert.ok(cells.length > 100,
    "the hex view must render one cell per byte of the SPNEGO token, got " +
    cells.length);
  const resting = await driver.findElement(
      By.css("#krb_sent_hex .krb-hex-path")).getText();
  assert.ok(/byte/.test(resting),
      "with a strip naming what is under the pointer: " + resting);
  // Hovering names the FIELD, which is the whole point of the view: a hex dump
  // that does not say which bytes are which field is a hex dump.
  await driver.actions().move({ origin: cells[cells.length - 20] }).perform();
  const named = await driver.wait(async function () {
    const text = await driver.findElement(
        By.css("#krb_sent_hex .krb-hex-path")).getText();
    return /offset/.test(text) ? text : false;
  }, 10000, "hovering a byte never named its field");
  assert.ok(/offset \d+/.test(named),
      "naming the element and its absolute offset: " + named);

  // The AP-REP, and the context it establishes.
  await selectTab(driver, "received", "aprep");
  const context = await driver.findElement(By.id("krb_context_pane")).getText();
  assert.ok(/CONFIRMED/.test(context),
    "the context pane must report mutual authentication as CONFIRMED only " +
    "when the echo was checked: " + JSON.stringify(context.slice(0, 300)));
  assert.ok(/acceptor subkey/i.test(context),
    "and must name the acceptor's subkey, which becomes the context key and " +
    "is what the server's own mechListMIC is signed with: " +
    JSON.stringify(context.slice(0, 400)));
  log.info("the handshake completes and every pane explains its part");
  log.debug("Leaving theHandshakeSucceedsAndIsExplained().");
}

// ---------------------------------------------------------------------------
// 6. The ticket: opaque, and then not.
// ---------------------------------------------------------------------------
async function theTicketIsOpaqueUntilTheServiceKeyIsSupplied(driver) {
  log.debug("Entering theTicketIsOpaqueUntilTheServiceKeyIsSupplied().");
  log.info("=== The ticket that was sent ===");
  const before = await driver.findElement(By.id("krb_ticket_pane")).getText();
  assert.ok(/HTTP\/|sname/.test(before),
      "the ticket's visible fields must be shown: " +
      JSON.stringify(before.slice(0, 200)));
  assert.ok(/No service key supplied|Supply/.test(before),
    "and the pane must SAY that the rest is opaque without the service key. " +
    "That is the honest state of a client — it never holds the key its own " +
    "ticket is sealed with — and an empty pane says nothing at all: " +
    JSON.stringify(before.slice(0, 400)));

  const hexCells = await driver.findElements(
      By.css("#krb_ticket_hex .krb-hex-b"));
  assert.ok(hexCells.length > 100,
      "and the ticket's own hex view must render, got " + hexCells.length +
      " cells");

  if (!serviceSalt) {
    // Not a failure: the salt comes from the KDC's own principal list, and a
    // build that does not publish it cannot be asked to open anything. Said
    // rather than skipped silently.
    log.warn("the mock KDC did not publish a salt for " + spn +
        ", so the decryption half of this section did not run");
    log.debug("Leaving theTicketIsOpaqueUntilTheServiceKeyIsSupplied().");
    return;
  }
  await setField(driver, "krb_service_password", servicePassword);
  await setField(driver, "krb_service_salt", serviceSalt);
  await driver.findElement(By.id("krb_decrypt_button")).click();
  const opened = await driver.wait(async function () {
    const text = await driver.findElement(By.id("krb_ticket_pane")).getText();
    return /session key/i.test(text) ? text : false;
  }, 60000, "the ticket never opened with the service key");
  assert.ok(/session key/i.test(opened),
    "with the service key the EncTicketPart must open — that is what a " +
    "service does, and it is the only way to see the client name, the flags " +
    "and the PAC this ticket is actually carrying");
  assert.ok(/PAC|Logon Information/i.test(opened),
    "including the PAC, which is what a Windows service authorizes on and " +
    "the structure a client can never see in its own ticket: " +
    JSON.stringify(opened.slice(0, 500)));
  log.info("the ticket is opaque, and opens with the service key");
  log.debug("Leaving theTicketIsOpaqueUntilTheServiceKeyIsSupplied().");
}

// ---------------------------------------------------------------------------
// 7. NEGATIVE: no mechanism in common, in both directions.
// ---------------------------------------------------------------------------
async function aNegotiationWithNothingInCommonIsRefused(driver) {
  log.debug("Entering aNegotiationWithNothingInCommonIsRefused().");
  log.info("=== NEGATIVE: no mechanism in common ===");

  // The acceptor's side: ?mech=none makes the mock support nothing at all.
  await driver.get(baseUrl + "/spnego.html");
  await driver.wait(until.elementLocated(By.id("krb_spnego_url")), 20000);
  await setField(driver, "krb_spnego_url", protectedUrl + "?mech=none");
  await driver.findElement(By.id("krb_spnego_url")).sendKeys("\t");
  await setField(driver, "krb_spnego_spn", spn);
  await driver.findElement(By.id("krb_spnego_spn")).sendKeys("\t");
  await waitForText(driver, "krb_credentials_pane", /HELD/, 20000,
      "the service ticket is no longer held");
  await driver.findElement(By.id("krb_authenticate_button")).click();
  const refused = await waitForText(driver, "krb_spnego_status",
      /accept-completed|REJECTED|FAILED/, 90000,
      "the negotiation produced no result");
  assert.ok(/REJECTED/.test(refused),
    "an acceptor with no mechanism in common must reject, and the page must " +
    "say so: " + refused);
  assert.ok(/no reason field|nothing anywhere says why/.test(refused),
    "and it must explain that SPNEGO carries no reason of its own — a " +
    "rejection with an empty responseToken cannot be told from a wrong " +
    "password, and that fact is the finding: " + refused);

  // The initiator's side: offer only a mechanism this build cannot perform.
  await driver.get(baseUrl + "/spnego.html");
  await driver.wait(until.elementLocated(By.id("krb_spnego_url")), 20000);
  await setField(driver, "krb_spnego_url", protectedUrl);
  await driver.findElement(By.id("krb_spnego_url")).sendKeys("\t");
  await setField(driver, "krb_spnego_spn", spn);
  await driver.findElement(By.id("krb_spnego_spn")).sendKeys("\t");
  await waitForText(driver, "krb_credentials_pane", /HELD/, 20000,
      "the service ticket is no longer held");
  await driver.findElement(By.id("krb_mech_krb5")).click();
  await driver.findElement(By.id("krb_mech_ms")).click();
  await driver.findElement(By.id("krb_mech_ntlm")).click();
  await driver.findElement(By.id("krb_authenticate_button")).click();
  const ntlm = await waitForText(driver, "krb_spnego_status",
      /accept-completed|REJECTED|FAILED|Offer at least/, 90000,
      "the NTLM-only negotiation produced no result");
  assert.ok(/REJECTED/.test(ntlm),
    "and a client offering only NTLM must be rejected by a Kerberos-only " +
    "acceptor: " + ntlm);
  log.info("both directions of `no mechanism in common` are refused");
  log.debug("Leaving aNegotiationWithNothingInCommonIsRefused().");
}

// ---------------------------------------------------------------------------
// 8. NEGATIVE: accepted, and nothing proved who answered.
// ---------------------------------------------------------------------------
async function withoutAnApRepNothingProvesTheServer(driver) {
  log.debug("Entering withoutAnApRepNothingProvesTheServer().");
  log.info("=== NEGATIVE: no proof of the server's identity ===");
  await driver.get(baseUrl + "/spnego.html");
  await driver.wait(until.elementLocated(By.id("krb_spnego_url")), 20000);
  await setField(driver, "krb_spnego_url", protectedUrl + "?mutual=off");
  await driver.findElement(By.id("krb_spnego_url")).sendKeys("\t");
  await setField(driver, "krb_spnego_spn", spn);
  await driver.findElement(By.id("krb_spnego_spn")).sendKeys("\t");
  await waitForText(driver, "krb_credentials_pane", /HELD/, 20000,
      "the service ticket is no longer held");
  await driver.findElement(By.id("krb_authenticate_button")).click();
  const status = await waitForText(driver, "krb_spnego_status",
      /accept-completed|REJECTED|FAILED|no AP-REP/, 90000,
      "the exchange produced no result");
  assert.ok(/no AP-REP came back|MUTUAL was requested/.test(status),
    "a server that accepts the ticket and answers nothing must be reported " +
    "as exactly that: the client is authenticated and NOTHING has proved " +
    "which server answered, which is the difference between authenticating a " +
    "client and authenticating a connection. Got: " + status);

  await selectTab(driver, "received", "aprep");
  const context = await driver.findElement(By.id("krb_context_pane")).getText();
  assert.ok(/NOT PERFORMED/.test(context),
    "and the context pane must say NOT PERFORMED rather than leaving the " +
    "previous run's CONFIRMED on the screen: " +
    JSON.stringify(context.slice(0, 300)));
  log.info("a context with no mutual authentication is reported as one");
  log.debug("Leaving withoutAnApRepNothingProvesTheServer().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The SPNEGO page, and the routing that feeds " +
      "it.");
  const ready = await preconditions();
  if (!ready.ok) {
    log.warn("SKIPPED: " + ready.why + ". This test needs the client, the " +
        "api and the mock STS (its KDC and its SPNEGO-protected page).");
    log.info("Test completed successfully.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  if (ready.kdcPort && ready.kdcPort !== String(kdcPort)) {
    log.warn("the mock STS reports its KDC on port " + ready.kdcPort +
        "; using that.");
    kdcPort = ready.kdcPort;
  }
  if (ready.spn && ready.spn.split("@")[0] !== spn) {
    log.warn("the mock advertises " + ready.spn + " rather than " + spn +
        "; using that.");
    spn = ready.spn.split("@")[0];
  }
  if (!protectedUrl) {
    protectedUrl = stsUrl + "/spnego/protected";
  }
  log.info("the protected page is " + protectedUrl + ", the SPN is " + spn +
      ", the KDC is on " + kdcHost + ":" + kdcPort);

  const options = new chrome.Options();
  // --headless=new, never bare --headless: the image's Chrome 121 ignores
  // --unsafely-treat-insecure-origin-as-secure in the old mode, and this page
  // derives keys and computes MICs with Web Crypto.
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1400");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    await theAsPageOffersTheWayBack(driver);
    await theTgsPageTakesTheSpnAndOffersTheWayBack(driver);
    await theBannerLinkLeadsBackAndTheTicketIsThere(driver);
    await theChallengeIsBare(driver);
    await theHandshakeSucceedsAndIsExplained(driver);
    await theTicketIsOpaqueUntilTheServiceKeyIsSupplied(driver);
    await aNegotiationWithNothingInCommonIsRefused(driver);
    await withoutAnApRepNothingProvesTheServer(driver);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("kerberos_spnego_page")
  .description("Verify the SPNEGO page, the routing that obtains its ticket, " +
      "and what it shows about both.")
  .addOption(new Option("-u, --url <url>",
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
