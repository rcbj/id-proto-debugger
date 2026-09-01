// File: kerberos_spnego_signin.js
//
// ---------------------------------------------------------------------------
// KERBEROS AS A WAY OF SIGNING IN, DRIVEN THROUGH THE DEBUGGER.
//
// `/spnego/protected` on the mock STS authenticates a person and then throws
// the identity away: it prints a table saying who the ticket named and stops.
// `/authn/spnego` is the same handshake with the last step added — past it the
// person has a BROWSER SESSION on that service, and `/oauth2/authorize`,
// `wsignin1.0`, a SAML AuthnRequest and `/admin` all read it.
//
// This file drives that door, and then spends what it produced: the debugger's
// own OAuth2/OIDC workflow completes an Authorization Code flow in which
// nobody typed a password anywhere, because a Kerberos ticket is what
// authenticated the person.
//
// ---------------------------------------------------------------------------
// WHAT THIS COVERS THAT NOTHING ELSE DOES.
//
// `tests/krb5_spnego_http.js` drives the handshake itself far harder than this
// file does — eighteen cases, ten of them negatives, with the KDC and the
// acceptor in-process. It is about the ACCEPTOR.
// `tests/kerberos_spnego_page.js` drives the same handshake through the
// debugger's pages against `/spnego/protected`. It is about the PAGE.
//
// Neither of them touches a session, because neither of them goes near the
// door that mints one. That was the whole of the gap: the sign-in shipped on
// 2026-08-26, was hand-verified once against a throwaway instance, and the
// driver that did it was a scratch script in neither repository — which is
// exactly the habit `tests/saml11_sso.js` broke by being promoted.
//
// Six things here are asserted nowhere else:
//
//   * that the door is DISCOVERABLE — `/spnego?format=json` names
//     `signInResource` and says whether it is open, so a client does not have
//     to know the path;
//   * that a ticket accepted there produces a SESSION rather than a page;
//   * that the session then SATISFIES AN APPLICATION — the debugger's
//     authorization request completes with no sign-in screen drawn;
//   * that the tokens say how it was done: `amr` of `pwd` read off the
//     ticket's own `pre-authent` flag, and `acr` of "1";
//   * that a REPLAYED AP-REQ mints nothing, which is the one check here whose
//     absence would be a security bug rather than a fidelity one;
//   * that `krb5.spnegoAuthentication` off answers 403 NAMING THE SETTING and
//     signs nobody in — a mode that ships on has to assert the off state too.
//
// ---------------------------------------------------------------------------
// THE SEAM, SAID OUT LOUD: THE BROWSER DOES NOT ANSWER THE CHALLENGE.
//
// RFC 4559 is a 401 with `WWW-Authenticate: Negotiate` and a repeat of the
// request carrying `Authorization: Negotiate <token>`. A browser answers that
// from GSSAPI, which needs two things this suite cannot assume on the machine
// it is running on: a Kerberos credential cache in the realm, and the host on
// an explicit allow-list (`--auth-server-allowlist` in Chrome,
// `network.negotiate-auth.trusted-uris` in Firefox). Without both, what a
// browser does is show the page and request no ticket at all — which the mock's
// own sign-in page says, and which is why that page has a link to the password
// screen beside it.
//
// So the DEBUGGER is the Kerberos client here, and that is the point rather
// than a workaround. Its pages perform the AS exchange, the TGS exchange and
// the SPNEGO negotiation, and build every byte of the AP-REQ that is sent —
// which is more of the protocol than a browser handing the work to GSSAPI would
// ever show. The HTTP goes through the api's `POST /krb5/spnego` relay, for the
// reason that endpoint exists: a cross-origin fetch cannot read
// `WWW-Authenticate` and a page cannot report its own request headers, so the
// relay is the only thing that can show both halves of both round trips.
//
// WHAT THAT COSTS, EXACTLY: the `Set-Cookie` the door returns arrives at the
// RELAY rather than at the browser, so section 5 lifts the session cookie out
// of the page's own response-headers pane and puts it in the browser before
// driving the application flow. That is one assignment, it is done through
// Selenium's cookie API on the STS's own origin, and it is the only step in
// this file a person doing the same thing by hand would not perform. It is
// called out here rather than buried because a reader is entitled to know
// which link in the chain the test forged.
//
// **AND SINCE 2026-08-27 THE OTHER PATH IS AVAILABLE TOO**, which was not true
// when this file was written. The mock KDC did not advertise PA-ENC-TIMESTAMP
// in its KDC_ERR_PREAUTH_REQUIRED, so no MIT-derived client could obtain a
// ticket from it at all and Chrome's Negotiate had nothing to send; that is
// fixed in `sts/kerberos/krb5_kdc.js`, and `kinit`, `kvno` and `curl
// --negotiate` now complete against it end to end. A second job driving a real
// GSSAPI browser is therefore possible and is deliberately NOT this file: it
// needs `krb5-user` in `tests/Dockerfile` and a per-run `krb5.conf`, so it
// would skip wherever that tooling is absent, and a job that usually skips is
// not the one to put the only coverage of a door in.
//
// ---------------------------------------------------------------------------
// WHAT IT NEEDS. The client, the api (for the SPNEGO relay), and the mock STS
// with its KDC and `/authn/spnego`. It SKIPS with a reason when any of those is
// missing and FAILS when they are there and the door is not — the distinction
// `sts_saml11.js` makes: an environment with no STS has not failed this test,
// and an STS answering without the sign-in door on it is a submodule pinned
// before the feature landed.
//
// It holds the `sts-spnego-signin` JOB_LOCK, because section 7 turns
// `krb5.spnegoAuthentication` off on a shared service and every other Kerberos
// job would read that as its own failure.
// ---------------------------------------------------------------------------

const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const browserFlags = require("./browser_flags.js");
const registry = require("./sts_applications.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "kerberos_spnego_signin",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

var apiUrl = process.env.API_URL || "https://localhost:4000";
var stsUrl = (process.env.STS_URL || "https://localhost:8081")
    .replace(/\/+$/, "");
var kdcHost = process.env.KRB5_KDC_HOST || "localhost";
var kdcPort = process.env.KRB5_KDC_PORT || "88";
var realm = process.env.KRB5_REALM || "EXAMPLE.COM";
// Generated per run with a prefix naming this file. The mock KDC creates a user
// account for any name on first sight, so this need not be configured — and
// should not be: its principal table is never pruned, and a name every Kerberos
// job shares makes a row in it, and a row on /admin/users, untraceable.
// KRB5_PRINCIPAL pins it to re-drive a failed run.
var principal = process.env.KRB5_PRINCIPAL || usernameFor("krb5-spnego-signin");
// One password for every user account in this KDC, whoever the principal is.
var password = process.env.KRB5_PASSWORD || "password!";
// The OAuth client the debugger presents once the session exists. Registered
// before the flow starts, like every other application in this suite — see
// tests/sts_applications.js.
var clientId = process.env.CLIENT_ID || "krb5-spnego-signin-client";

// Filled in by preconditions() from what the service publishes, so this file
// carries no copy of a path or an SPN that could go stale.
var signInUrl = null;
var advertisedSpn = null;
var spn = null;

// ---------------------------------------------------------------------------
// Reading and driving the pages. The same three helpers the other Kerberos page
// jobs use, and for the same reasons — see kerberos_spnego_page.js, where each
// is argued.
// ---------------------------------------------------------------------------
async function waitForText(driver, id, pattern, timeoutMs, what) {
  // Content, not elements: every field on these pages is static markup, so
  // elementLocated succeeds during parsing and says nothing about whether the
  // exchange happened.
  log.debug("Entering waitForText(). id=" + id);
  let last = "";
  try {
    await driver.wait(async function () {
      last = await driver.findElement(By.id(id)).getText();
      return pattern.test(last);
    }, timeoutMs || 60000);
  } catch (e) {
    log.debug("Leaving waitForText(). Timed out.");
    throw new Error(what + " (last text in #" + id + ": " +
        JSON.stringify(last.slice(0, 400)) + ")");
  }
  log.debug("Leaving waitForText().");
  return last;
}

async function setField(driver, id, value) {
  // CLEAR FIRST, ALWAYS. Several of these fields arrive pre-filled from the
  // build's own defaults, and sendKeys APPENDS — which hands the KDC the
  // password twice over and produces KDC_ERR_PREAUTH_FAILED, an error that
  // reads as a wrong credential rather than as a doubled one.
  log.debug("Entering setField(). id=" + id);
  const field = await driver.findElement(By.id(id));
  await field.clear();
  await field.sendKeys(value);
  log.debug("Leaving setField().");
}

// The URL field, set AND BLURRED — and the blur is the whole of why this is a
// helper rather than a setField() call.
//
// The page derives the SPN from the URL's host, and it does that on the field's
// `change` and `blur` events (spnego.js's onUrlChanged). Selenium's sendKeys
// fires neither: it leaves the caret in the field, so `change` has not happened
// yet and the SPN is still whatever the page loaded with — an EMPTY string on a
// build whose krb5SpnegoSpnDefault is empty, which it is on purpose. A test
// that set the URL and read the SPN in the next line therefore reads "", and
// the failure says the page derived nothing when what actually happened is that
// nobody told it the URL had changed.
async function setUrlField(driver, value) {
  log.debug("Entering setUrlField().");
  await setField(driver, "krb_spnego_url", value);
  // Tab out. `change` fires on blur, and blur is what a person does by moving
  // to the next field.
  await driver.findElement(By.id("krb_spnego_url")).sendKeys("\t");
  log.debug("Leaving setUrlField().");
}

// One of the received panes' TABS, selected the way a person selects it.
//
// `krb_body_pane` — where the door's own HTML is shown — lives in a tab panel
// that ships OFF (`krb-tabpanel-off`), and a hidden element's getText() is the
// empty string rather than its content. So a test that read the body without
// selecting the tab would report "the door did not render a sign-in page" for a
// door that rendered one perfectly: a statement about the product, on a pane
// that was merely closed.
async function selectTab(driver, group, name) {
  log.debug("Entering selectTab(). " + group + "/" + name);
  await driver.findElement(By.css('.krb-tabs[data-krb-tabs="' + group +
      '"] .krb-tab[data-krb-tab="' + name + '"]')).click();
  log.debug("Leaving selectTab().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). id=" + id);
  const text = await driver.findElement(By.id(id)).getText();
  log.debug("Leaving textOf().");
  return text;
}

// The management API, which is deliberately not behind the console's gate — see
// the mock's mgmt-api/CLAUDE.md. It is what lets section 7 close the door and
// put it back whatever `admin.authRequired` is doing.
async function adminPost(path, body) {
  log.debug("Entering adminPost(). " + path);
  const response = await fetch(stsUrl + "/admin-api" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body || {})
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    // Not JSON — an HTML error page, or an empty body. The status and the raw
    // text say more than a parse error would.
    log.debug("Leaving adminPost(). Not JSON.");
    throw new Error("POST /admin-api" + path + " answered " + response.status +
        " with something that is not JSON: " + text.slice(0, 300));
  }
  log.debug("Leaving adminPost(). ok=" + parsed.ok);
  return parsed;
}

// ---------------------------------------------------------------------------
// WHAT HAS TO BE TRUE BEFORE ANY OF THIS MEANS ANYTHING.
//
// Each answer is a different reason to skip and naming which one matters: "the
// stack is not up", "this api has no SPNEGO relay" and "this mock has no
// sign-in door" send you to three different places.
// ---------------------------------------------------------------------------
async function preconditions() {
  log.debug("Entering preconditions().");
  try {
    const principalsResponse = await fetch(stsUrl + "/krb5/principals");
    if (!principalsResponse.ok) {
      log.debug("Leaving preconditions(). No KDC.");
      return { ok: false, why: stsUrl + "/krb5/principals answered " +
        principalsResponse.status + " — the mock STS may be an older build " +
        "without the KDC" };
    }
    const table = await principalsResponse.json();
    if (table.realm !== realm) {
      log.debug("Leaving preconditions(). Wrong realm.");
      return { ok: false, why: "the mock KDC serves realm " + table.realm +
        ", not " + realm };
    }
    // Asked rather than assumed: this run signs in as a GENERATED name, which
    // works only because this KDC creates user accounts on demand. Without it
    // the AS exchange fails as KDC_ERR_C_PRINCIPAL_UNKNOWN — an error about the
    // KDC's table that says nothing about where the name came from.
    const policy = table.accountPolicy || {};
    const known = (table.principals || []).some(function (one) {
      return String(one.name || one) === principal;
    });
    if (!known && !policy.anyUsernameAuthenticates) {
      log.debug("Leaving preconditions(). Unusable principal.");
      return { ok: false, why: "this KDC does not create accounts on first " +
        "sight (accountPolicy.anyUsernameAuthenticates is false) and \"" +
        principal + "\" is not in its table, so the AS exchange below would " +
        "fail as KDC_ERR_C_PRINCIPAL_UNKNOWN. Set KRB5_PRINCIPAL to a name " +
        "it knows." };
    }

    const advertResponse = await fetch(stsUrl + "/spnego?format=json");
    if (!advertResponse.ok) {
      log.debug("Leaving preconditions(). No SPNEGO page.");
      return { ok: false, why: "the mock STS has no SPNEGO surface (" +
        stsUrl + "/spnego answered " + advertResponse.status + ") — the sts/ " +
        "gitlink probably predates it" };
    }
    const advert = await advertResponse.json();
    // THE DOOR IS DISCOVERED, NEVER SPELLED HERE. `signInResource` arrived with
    // the sign-in on 2026-08-26; a build without it is one where this whole
    // file has nothing to drive, and saying so names a submodule rather than a
    // 404.
    if (!advert.signInResource) {
      log.debug("Leaving preconditions(). No sign-in door.");
      return { ok: false, why: "the mock STS publishes no `signInResource` " +
        "at " + stsUrl + "/spnego?format=json, so it has no SPNEGO SIGN-IN — " +
        "this is a build from before 2026-08-26, when Kerberos became an " +
        "authentication mechanism there rather than only a protected page. " +
        "Bump the sts/ gitlink. `/spnego/protected` on this build still " +
        "performs the whole handshake, which is what kerberos_spnego_page.js " +
        "drives." };
    }
    signInUrl = stsUrl + advert.signInResource;
    advertisedSpn = advert.servicePrincipalName
        ? String(advert.servicePrincipalName).split("@")[0] : null;

    const limitsResponse = await fetch(apiUrl + "/krb5/limits");
    if (!limitsResponse.ok) {
      log.debug("Leaving preconditions(). No api.");
      return { ok: false, why: "the api at " + apiUrl + " did not answer GET " +
        "/krb5/limits (" + limitsResponse.status + ")" };
    }
    const limits = await limitsResponse.json();
    if (!limits.spnegoEnabled) {
      log.debug("Leaving preconditions(). No SPNEGO relay.");
      return { ok: false, why: "the api does not publish spnegoEnabled, " +
        "so it has no POST /krb5/spnego — this build of the api predates the " +
        "SPNEGO workflow" };
    }

    log.debug("Leaving preconditions(). Ready.");
    return { ok: true, kdcPort: String(table.kdcPort),
             signInEnabled: advert.signInEnabled !== false,
             acceptsAnySpnForHosts: advert.acceptsAnySpnForHosts || [] };
  } catch (e) {
    log.debug("Leaving preconditions(). Unreachable.");
    return { ok: false, why: "could not reach the stack (" + e.message + ")" };
  }
}

// ---------------------------------------------------------------------------
// 1. THE DOOR SAYS WHERE IT IS AND WHETHER IT IS OPEN.
//
// Asserted before anything is driven, because every section below depends on
// both facts and a client that has to be TOLD the path is a client that will
// still be pointed at it after it moves. This is the same property
// `/oauth2/authorize` gets from RFC 8414 metadata, applied to a door that has
// no specification to publish it.
// ---------------------------------------------------------------------------
async function theDoorIsPublishedAndOpen(ready) {
  log.debug("Entering theDoorIsPublishedAndOpen().");
  log.info("=== The sign-in door, as the service publishes it ===");
  assert.ok(/\/authn\//.test(signInUrl),
    "the sign-in resource should be in the authentication service's own path " +
    "space, and the service names " + JSON.stringify(signInUrl) + ". It is " +
    "there rather than under /spnego because what it produces is a SESSION, " +
    "which is authn.js's to own — the endpoint lives in kerberos/ only for a " +
    "require-order reason both files argue.");
  assert.notStrictEqual(signInUrl, stsUrl + "/spnego/protected",
    "the sign-in resource and the protected page must not be the same URL: " +
    "the protected page authenticates and throws the identity away, and a " +
    "test pointed at it would pass every assertion above section 5 while " +
    "proving nothing about a session.");
  assert.ok(ready.signInEnabled,
    "this mock has krb5.spnegoAuthentication off, so the door refuses " +
    "everybody and sections 4 to 6 could not mean anything. Section 7 turns " +
    "it off deliberately and puts it back; arriving with it already off is a " +
    "run somebody else's job left half-finished, or a deployment choice.");
  log.info("the door is at " + signInUrl + " and it is open");
  log.debug("Leaving theDoorIsPublishedAndOpen().");
}

// ---------------------------------------------------------------------------
// 2. THE APPLICATION, AND ITS MECHANISM.
//
// Registered before anything connects, the way every job in this suite now
// does it — and this one has a reason of its own beyond the convention:
// `appAuthnMechanism` is what makes Kerberos an application's OWN way of
// signing people in, and it can only be asserted against an entry that exists.
//
// `spnego` on the entry is HOME REALM DISCOVERY BY CONFIGURATION: an
// authorization request for this client, with no session, goes straight to the
// Kerberos door and the password screen is never drawn. That is the second of
// the three ways in that the mock's spnego_authn.js describes, and it is the
// one a deployment actually uses.
// ---------------------------------------------------------------------------
async function theApplicationNamesKerberosAsItsMechanism() {
  log.debug("Entering theApplicationNamesKerberosAsItsMechanism().");
  log.info("=== The application, before it connects ===");
  const entry = await registry.provision(registry.baseOf(stsUrl), {
    identifier: clientId,
    name: "Kerberos SPNEGO sign-in",
    protocols: ["oauth2", "oidc"],
    fields: {
      oauthClientId: clientId,
      oauthRedirectUri: [baseUrl + "/callback"],
      oauthResponseType: ["code"],
      oauthGrantType: ["authorization_code"],
      oauthScope: ["openid", "profile", "email"],
      oauthTokenEndpointAuthMethod: "none",
      oauthConfidential: "FALSE",
      // THE POINT OF THIS SECTION.
      appAuthnMechanism: "spnego"
    },
    why: "the application whose people authenticate with a Kerberos ticket"
  });
  assert.ok(entry, "the application could not be registered, so nothing " +
    "below would be judged against a configuration at all.");
  assert.strictEqual(registry.valuesOf(entry.fields.appAuthnMechanism)[0],
    "spnego",
    "the entry should name spnego as this application's authentication " +
    "mechanism and holds " +
    JSON.stringify(entry.fields.appAuthnMechanism) + ".");

  // AND IT MUST ACTUALLY DECIDE SOMETHING. An attribute that is written and
  // read by nothing is the failure mode of every declaration in this registry —
  // `appAllowedProtocol` is documented as exactly that — so `appAuthnMechanism`
  // is checked by driving an authorization request with NO session and reading
  // where the service sends it. This is done with fetch rather than a browser
  // because what is being read is one Location header.
  const authorize = stsUrl + "/oauth2/authorize?response_type=code&client_id=" +
      encodeURIComponent(clientId) + "&redirect_uri=" +
      encodeURIComponent(baseUrl + "/callback") +
      "&scope=" + encodeURIComponent("openid profile email") +
      "&state=krb-state&nonce=krb-nonce";
  const first = await fetch(authorize, { redirect: "manual" });
  const location = first.headers.get("location") || "";
  assert.ok(/^3/.test(String(first.status)),
    "an authorization request with no session should redirect to the " +
    "authentication service and answered " + first.status + ".");
  const landing = await fetch(new URL(location, stsUrl).toString(),
                              { redirect: "manual" });
  const landingUrl = landing.headers.get("location") || location;
  assert.ok(/\/authn\/spnego/.test(location) ||
            /\/authn\/spnego/.test(landingUrl),
    "with appAuthnMechanism=spnego on the application entry, an " +
    "authorization request with no session must go to the Kerberos door and " +
    "not to the password screen — that is what the attribute is FOR, and an " +
    "attribute nothing reads is a record of intent rather than a " +
    "configuration. It went to " + JSON.stringify(location) +
    (landingUrl !== location ? " and then " + JSON.stringify(landingUrl) : "") +
    ".");
  log.info("the application names spnego, and an authorization request for " +
      "it goes straight to the Kerberos door");
  log.debug("Leaving theApplicationNamesKerberosAsItsMechanism().");
}

// ---------------------------------------------------------------------------
// 3. THE DOOR, BEFORE ANY TICKET — through the debugger's SPNEGO page.
//
// The unauthenticated GET and its bare `WWW-Authenticate: Negotiate`. This is
// what a browser with no credential cache actually gets, and asserting it here
// is what makes the rest of the file about a handshake rather than about a
// page that happened to render.
// ---------------------------------------------------------------------------
async function theDoorChallengesBeforeAnyTicket(driver) {
  log.debug("Entering theDoorChallengesBeforeAnyTicket().");
  log.info("=== The unauthenticated request to the sign-in door ===");
  await driver.get(baseUrl + "/spnego.html");
  await driver.wait(until.elementLocated(By.id("krb_probe_button")), 20000);

  await setUrlField(driver, signInUrl);
  // The SPN the page derives from the URL's host. Read back rather than set:
  // nothing in the exchange carries an SPN, the client GUESSES it, and a test
  // that types the right answer in never exercises the guess a person depends
  // on. Section 4 buys a ticket for exactly this name.
  spn = await driver.findElement(By.id("krb_spnego_spn")).getAttribute("value");
  assert.ok(spn && /^HTTP\//.test(spn),
    "the page should derive an HTTP service principal from the door's host " +
    "and derived " + JSON.stringify(spn) + ".");

  await driver.findElement(By.id("krb_probe_button")).click();
  const status = await waitForText(driver, "krb_spnego_status",
      /bare `Negotiate`|does not offer Negotiate|answered/, 60000,
      "the unauthenticated request to the sign-in door produced no result");
  assert.ok(/bare `Negotiate` challenge/.test(status),
    "the sign-in door's first answer must be the bare word `Negotiate` with " +
    "no token after it (RFC 4559 section 4) — it is a door, not a page, and " +
    "a 200 here would mean it had signed somebody in without a credential. " +
    "Got: " + status);

  const pane = await textOf(driver, "krb_probe_pane");
  assert.ok(/401/.test(pane) && /www-authenticate/i.test(pane),
    "and both halves must be shown verbatim, which is the whole reason this " +
    "goes through the api relay: " + JSON.stringify(pane.slice(0, 300)));

  // The derived SPN has to be one this service will answer for, or section 4
  // buys a ticket the door cannot open and the failure arrives as
  // KRB_AP_ERR_NOT_US — a message about a ticket, three steps after the
  // decision that caused it.
  const hosts = (await driver.findElement(By.id("krb_spn_note")).getText());
  log.info("the door challenges with a bare Negotiate; the SPN this page " +
      "will buy a ticket for is " + spn +
      (advertisedSpn && advertisedSpn !== spn
        ? " (the service's own canonical name is " + advertisedSpn + ")" : "") +
      ". SPN note: " + JSON.stringify(hosts.slice(0, 160)));
  log.debug("Leaving theDoorChallengesBeforeAnyTicket().");
}

// ---------------------------------------------------------------------------
// 4. THE CREDENTIAL, BUILT BY THE DEBUGGER.
//
// The AS exchange for a TGT, then the TGS exchange for a service ticket for the
// SPN section 3 derived. Two pages, both of them the debugger's, and the
// reason this file is "through the debugger" at all: every byte of the AP-REQ
// the door accepts is built here, in the browser, out of a password.
// ---------------------------------------------------------------------------
async function theDebuggerBuildsTheCredential(driver) {
  log.debug("Entering theDebuggerBuildsTheCredential().");
  log.info("=== The AS exchange: a TGT for " + principal + " ===");
  await driver.get(baseUrl + "/kerberos.html?return=spnego");
  await driver.wait(until.elementLocated(By.id("krb_noreauth_button")), 20000);

  await setField(driver, "krb_realm", realm);
  await setField(driver, "krb_principal", principal);
  await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);

  // THE FIRST REQUEST CARRIES NO PRE-AUTHENTICATION, AND THAT IS THE PROTOCOL
  // RATHER THAN A MISTAKE. A real KDC answers KDC_ERR_PREAUTH_REQUIRED carrying
  // ETYPE-INFO2, which is where the client learns the SALT it needs to turn a
  // password into a key — and the salt is not guessable. A client that treated
  // that error as a failure could not authenticate to Active Directory either.
  await driver.findElement(By.id("krb_noreauth_button")).click();
  const preauth = await waitForText(driver, "krb_as_status",
      /PREAUTH_REQUIRED|issued a ticket WITHOUT/, 60000,
      "the AS page's first request produced no result");
  assert.ok(/PREAUTH_REQUIRED/.test(preauth),
    "this KDC should demand pre-authentication for an ordinary account, " +
    "because the whole `amr` claim section 6 reads depends on the ticket's " +
    "`pre-authent` flag being set — a KDC that issued without it would sign " +
    "the person in claiming no authentication method at all. Got: " + preauth);

  await setField(driver, "krb_password", password);
  await driver.findElement(By.id("krb_preauth_button")).click();
  const tgt = await waitForText(driver, "krb_as_status",
      /A TGT for|will not decrypt|refused/, 60000,
      "the AS page produced no ticket");
  assert.ok(/A TGT for/.test(tgt),
    "a TGT is needed before a service ticket can be bought: " + tgt);
  log.info("the debugger holds a TGT for " + principal + "@" + realm);

  log.info("=== The TGS exchange: a service ticket for " + spn + " ===");
  await driver.get(baseUrl + "/kerberos_tgs.html?return=spnego&spn=" +
      encodeURIComponent(spn));
  await driver.wait(until.elementLocated(By.id("krb_tgs_button")), 20000);
  const filled = await driver.findElement(By.id("krb_spn"))
      .getAttribute("value");
  assert.strictEqual(filled, spn,
    "the SPN carried in the query must win over whatever this page used last " +
    "— buying a ticket for the wrong service is refused a page later with " +
    "KRB_AP_ERR_NOT_US, which reads as a broken ticket. Got " +
    JSON.stringify(filled));
  await setField(driver, "krb_kdc_host", kdcHost);
  await setField(driver, "krb_kdc_port", kdcPort);
  await driver.findElement(By.id("krb_tgs_button")).click();
  const service = await waitForText(driver, "krb_tgs_status",
      /A service ticket for|refused/, 60000,
      "the TGS page produced no service ticket");
  assert.ok(/A service ticket for/.test(service),
    "the KDC should issue a ticket for " + spn + ": " + service);
  log.info("the debugger holds a service ticket for " + spn);
  log.debug("Leaving theDebuggerBuildsTheCredential().");
}

// ---------------------------------------------------------------------------
// 5. THE SIGN-IN, and the session it produces.
//
// The same page and the same button `kerberos_spnego_page.js` presses against
// `/spnego/protected`, pointed one path along. What differs is entirely in the
// ANSWER: a 200 carrying a session cookie rather than a table saying who the
// ticket named.
// ---------------------------------------------------------------------------
async function theTicketSignsThePersonIn(driver) {
  log.debug("Entering theTicketSignsThePersonIn().");
  log.info("=== The sign-in ===");
  await driver.get(baseUrl + "/spnego.html");
  await driver.wait(until.elementLocated(By.id("krb_authenticate_button")),
      20000);
  await setUrlField(driver, signInUrl);
  await setField(driver, "krb_spnego_spn", spn);

  await driver.findElement(By.id("krb_authenticate_button")).click();
  const status = await waitForText(driver, "krb_spnego_status",
      /accept-completed|REJECTED|FAILED|could not/, 90000,
      "the handshake against the sign-in door produced no result");
  assert.ok(/accept-completed/.test(status),
    "the handshake must complete against the sign-in door exactly as it does " +
    "against the protected page — the negotiation is the same code on both " +
    "sides, which is the point of the mock keeping them in one module. Got: " +
    status);

  // WHAT MAKES THIS A SIGN-IN RATHER THAN A HANDSHAKE. Two independent things,
  // and both are asserted because either alone is satisfiable by the wrong
  // implementation: a page that SAYS "signed in" and sets no cookie, or a
  // cookie set by something that authenticated nobody.
  await selectTab(driver, "received", "body");
  const body = await textOf(driver, "krb_body_pane");
  assert.ok(/you are signed in/i.test(body),
    "the door's answer must be the sign-in page rather than the protected " +
    "page's table. `/spnego/protected` renders 'who the ticket named' and " +
    "stops; this one renders a session. Got: " +
    JSON.stringify(body.slice(0, 400)));
  assert.ok(new RegExp("urn:sts-mock:user:" + principal).test(body),
    "and it must name the subject the session carries, which is the " +
    "principal with its realm STRIPPED — leaving the realm on would make " +
    "somebody who typed \"" + principal + "\" at the password screen and the " +
    "same person arriving with a ticket two different subjects to every " +
    "relying party. Got: " + JSON.stringify(body.slice(0, 400)));

  const headers = await textOf(driver, "krb_response_headers_pane");
  assert.ok(/set-cookie/i.test(headers),
    "the door must SET A SESSION COOKIE, which is the whole difference " +
    "between this endpoint and the protected page and the only part of it " +
    "that outlives the request. The response headers pane shows: " +
    JSON.stringify(headers.slice(0, 400)));

  const cookie = (headers.match(/sts_mock_session=([^;\s]+)/) || [])[1];
  assert.ok(cookie,
    "and this test needs the cookie's value to spend it in section 6. The " +
    "response headers pane holds: " + JSON.stringify(headers.slice(0, 400)));

  // THE TOKEN THAT WAS SENT, captured here rather than in section 7, because by
  // then the browser has left this page for the application flow and the pane
  // is gone.
  //
  // READ OUT OF THE DOM RATHER THAN OFF getText(). The rendered text puts the
  // header name and its value on separate lines and follows the value with the
  // next heading — and a heading like "Response" is itself valid base64, so a
  // regex over the flattened text either stops short or swallows it. Asking the
  // pane for the CELL whose content is the Authorization value is exact, and it
  // is the same node a reader is looking at.
  const token = await driver.executeScript(
    "var host = document.getElementById('krb_response_headers_pane');" +
    "if (!host) { return ''; }" +
    "var cells = host.querySelectorAll('*');" +
    "for (var i = 0; i < cells.length; i++) {" +
    "  if (cells[i].children.length) { continue; }" +
    "  var text = (cells[i].textContent || '').trim();" +
    "  if (text.indexOf('Negotiate ') === 0) {" +
    "    return text.slice('Negotiate '.length).replace(/\\s+/g, '');" +
    "  }" +
    "}" +
    "return '';");
  assert.ok(token,
    "the page must show the token it sent — showing both halves of both " +
    "round trips is what that pane is FOR, and section 7 has nothing to " +
    "replay without it. Pane: " + JSON.stringify(headers.slice(0, 300)));
  assert.ok(token.length > 100,
    "the captured token is too short to be an AP-REQ (" + token.length +
    " characters), so section 7 would be replaying nothing.");

  // The ticket flags, which are what section 6's `amr` is read off. Asserted
  // here as well as there because the two are different claims: this one is
  // "the KDC said so", and that one is "the service believed it and told a
  // relying party".
  assert.ok(/pre-authent/.test(body),
    "the ticket should carry `pre-authent` — the flag RFC 4120 section 2.1 " +
    "sets when the KDC verified pre-authentication, and the only evidence " +
    "this service has for the `amr` it is about to claim. Got: " +
    JSON.stringify(body.slice(0, 400)));

  log.info("the ticket signed " + principal + " in, and the session cookie " +
      "is set");
  log.debug("Leaving theTicketSignsThePersonIn(). cookie and token captured.");
  return { cookie: cookie, token: token };
}

// ---------------------------------------------------------------------------
// 6. THE PAYOFF: the session satisfies the debugger's own application flow.
//
// This is what the whole file is for. The person authenticated with a Kerberos
// ticket and typed nothing; the debugger now runs an ordinary OIDC
// Authorization Code flow against the same service, and the mock must complete
// it WITHOUT drawing a sign-in screen — because the session
// `/authn/spnego` minted is the one `/oauth2/authorize` reads.
//
// The cookie is put in the browser here. That is the seam this file's header
// describes: the api relay performed the HTTP, so the `Set-Cookie` arrived
// there rather than in Chrome, and one assignment carries it across. Everything
// after this line is an ordinary browser flow with an ordinary session.
// ---------------------------------------------------------------------------
async function theSessionSatisfiesAnApplication(driver, cookie) {
  log.debug("Entering theSessionSatisfiesAnApplication().");
  log.info("=== The application flow the Kerberos session satisfies ===");

  // A cookie can only be set on the origin the browser is currently on, so the
  // browser goes to the STS's own origin first. Any page there will do; the
  // sign-in door itself is used because it needs no configuration and its 401
  // is harmless.
  await driver.get(stsUrl + "/spnego");
  await driver.manage().addCookie({
    name: "sts_mock_session", value: cookie, path: "/" });
  const planted = await driver.manage().getCookie("sts_mock_session");
  assert.ok(planted && planted.value === cookie,
    "the session cookie did not take in the browser, so the flow below would " +
    "draw a sign-in screen and this section would be testing the password " +
    "path.");

  const authorize = stsUrl + "/oauth2/authorize?response_type=code&client_id=" +
      encodeURIComponent(clientId) + "&redirect_uri=" +
      encodeURIComponent(baseUrl + "/callback") +
      "&scope=" + encodeURIComponent("openid profile email") +
      "&state=krb-signed-in&nonce=krb-nonce-2";
  await driver.get(authorize);
  // WAIT ON THE CODE, NOT ON `/callback`. That path is a HOP rather than a
  // destination: the debugger's callback forwards to oauth2_oidc_2.html
  // carrying the response, so a wait for "/callback" in the URL is a race
  // against a redirect that has usually already happened — it times out on a
  // flow that worked, and the message blames the session cookie. The code is
  // the thing that proves the flow completed, and it survives the hop.
  //
  // Waiting on the URL rather than on an element is still the right shape: a
  // sign-in screen would render elements too, and only the code says nobody
  // was asked for anything.
  await driver.wait(async function () {
    return /[?&]code=/.test(await driver.getCurrentUrl());
  }, Math.max(waitTime, 20000),
    "the authorization request never came back with a code. If the browser " +
    "is sitting on a sign-in screen, the session cookie was not read — which " +
    "is the failure this whole file exists to catch.");
  const landed = await driver.getCurrentUrl();
  assert.ok(/state=krb-signed-in/.test(landed),
    "the authorization response must echo the state it was given: " + landed);
  assert.ok(!/\/authn\/login/.test(landed),
    "and no sign-in screen may have been drawn along the way: " + landed);
  log.info("the authorization request completed with no screen drawn, and " +
      "came back with a code");

  // WHAT THE TOKENS SAY ABOUT HOW IT WAS DONE. The code is exchanged here
  // rather than through the debugger's token pane, because what is being read
  // is the ID Token's `amr` and `acr` — claims about the AUTHENTICATION, which
  // is this file's subject, and the pane's own behaviour is oidc_flows.js's.
  const code = (landed.match(/[?&]code=([^&]+)/) || [])[1];
  const tokenResponse = await fetch(stsUrl + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code: decodeURIComponent(code),
      redirect_uri: baseUrl + "/callback", client_id: clientId
    }).toString()
  });
  const tokens = await tokenResponse.json();
  assert.ok(tokens.id_token,
    "the token endpoint should return an ID Token for a code minted from a " +
    "Kerberos session: " + JSON.stringify(tokens).slice(0, 300));
  const claims = JSON.parse(Buffer.from(
      tokens.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"),
      "base64").toString("utf8"));

  assert.strictEqual(claims.sub, "urn:sts-mock:user:" + principal,
    "the ID Token's subject must be the principal the TICKET named, with the " +
    "realm stripped. Got " + JSON.stringify(claims.sub) + ".");
  assert.deepStrictEqual(claims.amr, ["pwd"],
    "`amr` must be exactly [\"pwd\"], and both halves of that matter. It is " +
    "PRESENT because the ticket carried `pre-authent`, which on this KDC " +
    "means PA-ENC-TIMESTAMP — a timestamp encrypted under a key derived from " +
    "a password, so a password genuinely was proven to the KDC at some point " +
    "in this credential's lineage. And it is ONLY that: nothing here set " +
    "`hwk`, because nothing set `hw-authent`, and a service that claimed two " +
    "factors from one flag would be telling a relying party something no " +
    "part of this chain knows. Got " + JSON.stringify(claims.amr) + ".");
  assert.strictEqual(claims.acr, "1",
    "`acr` must be \"1\" — one factor claimed. \"mfa\" would need both " +
    "`pre-authent` AND `hw-authent`, and \"0\" is what a ticket claiming no " +
    "pre-authentication at all would earn. Got " + JSON.stringify(claims.acr) +
    ".");
  log.info("the ID Token says sub=" + claims.sub + ", amr=" +
      JSON.stringify(claims.amr) + ", acr=" + claims.acr +
      " — read off the ticket's own flags rather than off a screen");
  log.debug("Leaving theSessionSatisfiesAnApplication().");
}

// ---------------------------------------------------------------------------
// 7. NEGATIVE: a replayed AP-REQ mints nothing.
//
// The one check in this file whose absence would be a SECURITY bug rather than
// a fidelity one. Every other refusal here makes the mock less permissive than
// it says it is, which is what it is for; accepting a captured AP-REQ twice is
// a second session for somebody who proved nothing the second time.
//
// **PRESSING THE BUTTON AGAIN IS NOT A REPLAY, AND THAT IS WHY THIS SECTION
// LOOKS THE WAY IT DOES.** The first version of it did exactly that and failed,
// correctly: the page builds a FRESH AP-REQ every time it authenticates — a new
// Authenticator, with a new timestamp — so a second press is a second
// legitimate authentication with the same service ticket, which is ordinary
// Kerberos and must succeed. A replay is the SAME BYTES sent twice.
//
// So the bytes are taken from the page, which shows them: the token it sent is
// in the request half of the exchange pane, verbatim, because showing both
// halves of both round trips is what that pane is FOR. They go back to the door
// through the same api relay the page itself uses, so what is exercised is the
// acceptor and not a second implementation.
// ---------------------------------------------------------------------------
async function aReplayedTicketMintsNothing(token) {
  log.debug("Entering aReplayedTicketMintsNothing().");
  log.info("=== NEGATIVE: the same AP-REQ, sent twice ===");

  // Sent through the api's relay, exactly as the page sends it. The relay
  // builds the `Negotiate ` prefix itself and will only take a base64 token,
  // which is why what is posted is the bare value.
  const replay = await fetch(apiUrl + "/krb5/spnego", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: signInUrl, token: token })
  });
  assert.strictEqual(replay.status, 200,
    "the api's relay should have performed the request and reported it, " +
    "whatever the door answered. It answered " + replay.status + ".");
  const result = await replay.json();
  const status = result.response && result.response.status;
  const headers = (result.response && result.response.headers) || {};
  const cookieHeader = Object.keys(headers).filter(function (name) {
    return /^set-cookie$/i.test(name);
  });

  assert.notStrictEqual(status, 200,
    "a REPLAYED AP-REQ was accepted with HTTP 200. The acceptor's replay " +
    "cache is what has to notice that these exact bytes have been seen " +
    "before — an Authenticator is single-use, and a service that takes one " +
    "twice hands a second session to anybody who captured the first. This is " +
    "the one assertion in this file whose failure is a security bug rather " +
    "than a fidelity one.");
  assert.strictEqual(cookieHeader.length, 0,
    "and it must mint NOTHING: the replayed request came back with " +
    JSON.stringify(cookieHeader) + ". A refusal that still set a session " +
    "cookie would be worse than an acceptance, because the status line says " +
    "one thing and the browser keeps another.");

  // AND THE REFUSAL MUST SAY WHY. A client told only "authentication failed"
  // goes and checks its password; one told "this ticket has been seen" knows
  // its credential was captured, which is a different problem with a different
  // response.
  const body = String((result.response && result.response.body) || "");
  assert.ok(/replay|already|seen before/i.test(body),
    "the refusal should name the replay rather than merely refusing. The " +
    "door answered HTTP " + status + " with: " +
    JSON.stringify(body.slice(0, 400)));
  log.info("the replayed AP-REQ was refused with HTTP " + status +
      ", minted no session, and the refusal names the replay");
  log.debug("Leaving aReplayedTicketMintsNothing().");
}

// ---------------------------------------------------------------------------
// 8. NEGATIVE: the door, closed.
//
// A mode that ships ON has to assert the OFF state too — tests/CLAUDE.md's own
// rule, and here it covers something specific: the refusal must be a 403 NAMING
// THE SETTING and not a 404. A route that answered "no such page" would send
// somebody to look for a deployment problem when what they have is a
// configuration, and every other switchable refusal in that service says which
// setting it was.
//
// This is why the file holds a JOB_LOCK. The setting is process-wide on a
// shared service, and any other Kerberos job running in this window would read
// the closed door as its own failure.
// ---------------------------------------------------------------------------
async function theClosedDoorSignsNobodyIn() {
  log.debug("Entering theClosedDoorSignsNobodyIn().");
  log.info("=== NEGATIVE: krb5.spnegoAuthentication off ===");
  const off = await adminPost("/config/set",
      { key: "krb5.spnegoAuthentication", value: false });
  assert.ok(off.ok,
    "krb5.spnegoAuthentication could not be turned off through the " +
    "management API, so this section cannot run: " +
    JSON.stringify(off.errors || off));
  try {
    const refused = await fetch(signInUrl, { redirect: "manual" });
    assert.strictEqual(refused.status, 403,
      "a closed door must answer 403 and not 404: the route still exists, it " +
      "is still on /admin/sts-metadata, and answering 'no such page' sends " +
      "somebody to look for a deployment problem when what they have is a " +
      "setting. Got " + refused.status + ".");
    const body = await refused.text();
    assert.ok(/krb5\.spnegoAuthentication/.test(body),
      "and the refusal must NAME the setting, which is the difference " +
      "between a person turning it back on and a person reading source. Got: " +
      JSON.stringify(body.slice(0, 300)));
    assert.ok(!/set-cookie/i.test(
        Array.from(refused.headers.keys()).join(",")),
      "and a closed door must sign nobody in.");

    // AND NOTHING ELSE CHANGES. The protected page still performs the whole
    // handshake with the door shut — the mock's own refusal page says so, and
    // a reader who is told that should be able to rely on it.
    const stillThere = await fetch(stsUrl + "/spnego?format=json");
    const advert = await stillThere.json();
    assert.strictEqual(advert.signInEnabled, false,
      "with the setting off the service should say so in the document a " +
      "client discovers the door from, rather than continuing to advertise a " +
      "door that refuses everybody.");
    assert.ok(advert.protectedResource,
      "and the protected page must still be published: turning the sign-in " +
      "off takes the SESSION away and nothing else.");
    log.info("the closed door answers 403, names the setting, mints nothing, " +
        "and the protected page is untouched");
  } finally {
    // RESTORED THROUGH `reset` RATHER THAN BY WRITING THE OLD VALUE BACK. A
    // `set` leaves `source: override` behind on that setting for the mock's
    // own suite to trip over on the next run; `reset` puts it back to what the
    // service's own configuration says. This is in a `finally` because a
    // failed assertion above must not leave the door shut for every other
    // Kerberos job.
    const back = await adminPost("/config/reset",
        { key: "krb5.spnegoAuthentication" });
    if (!back.ok) {
      log.error("could not reset krb5.spnegoAuthentication: " +
          JSON.stringify(back.errors || back) + " — the SPNEGO sign-in door " +
          "may be left CLOSED on this instance, which every other Kerberos " +
          "job will read as its own failure.");
    } else {
      log.info("krb5.spnegoAuthentication is back to the service's own value");
    }
  }
  log.debug("Leaving theClosedDoorSignsNobodyIn().");
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. debugger=" + baseUrl + ", api=" + apiUrl +
      ", sts=" + stsUrl);
  const ready = await preconditions();
  if (!ready.ok) {
    // Named, never silent. A skip that did not say which precondition failed
    // would be indistinguishable from a pass.
    log.warn("SKIPPED: " + ready.why + ". This test needs the client, the " +
        "api (for POST /krb5/spnego) and the mock STS with its KDC and its " +
        "SPNEGO sign-in door.");
    log.info("Test completed successfully (skipped).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  if (ready.kdcPort && ready.kdcPort !== String(kdcPort)) {
    log.warn("the mock STS reports its KDC on port " + ready.kdcPort +
        "; using that.");
    kdcPort = ready.kdcPort;
  }

  // Everything that needs no browser, first: it is cheap, and a failure here
  // explains every browser failure that would have followed it.
  await theDoorIsPublishedAndOpen(ready);
  await theApplicationNamesKerberosAsItsMechanism();

  const options = new chrome.Options();
  // --headless=new, never bare --headless, and headless is not optional here: a
  // CI runner and the tests container have no display, so a windowed session
  // fails at `session not created` naming the page it was about to visit. The
  // old headless implementation also ignores
  // --unsafely-treat-insecure-origin-as-secure, and these pages derive keys
  // with Web Crypto.
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
      "--window-size=1400,1400");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  // The mock serves https on a certificate it generated at startup, and section
  // 6 navigates the browser to that origin directly. Without the pin every one
  // of those navigations meets a certificate interstitial instead of a page.
  browserFlags.addStsTrustFlags(options);
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).setLoggingPrefs(prefs).build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    await theDoorChallengesBeforeAnyTicket(driver);
    await theDebuggerBuildsTheCredential(driver);
    const signedIn = await theTicketSignsThePersonIn(driver);
    // The replay goes FIRST, while the credential is the most recent thing the
    // acceptor has seen: it needs no browser, and running it before the
    // application flow keeps the two negatives about the door together.
    await aReplayedTicketMintsNothing(signedIn.token);
    await theSessionSatisfiesAnApplication(driver, signedIn.cookie);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
      for (const entry of await driver.manage().logs()
                                     .get(logging.Type.BROWSER)) {
        if (entry.level.name === "SEVERE") {
          log.error("browser: " + entry.message.slice(0, 400));
        }
      }
    } catch (e) {
      // The browser is already gone, or never came up. Nothing to add, and the
      // error above is the one that matters.
    }
    testFailed = true;
  } finally {
    await driver.quit();
  }

  // AFTER the browser is gone, because it needs none and because leaving the
  // door shut is the one way this file can break somebody else's job. It runs
  // even when something above failed, for the same reason.
  try {
    await theClosedDoorSignsNobodyIn();
  } catch (error) {
    log.error(error.stack || error.message);
    testFailed = true;
  }

  if (testFailed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("kerberos_spnego_signin")
  .description("Kerberos as a way of signing in: the debugger builds a " +
      "service ticket, the mock STS's /authn/spnego turns it into a session, " +
      "and an ordinary OIDC Authorization Code flow completes on it.")
  .addOption(new Option("-u, --url <url>", "base url of the client under test"))
  .addOption(new Option("-b, --browser", "Display browser."))
  .parse(process.argv);
const cliOptions = program.opts();
if (cliOptions.url) {
  baseUrl = String(cliOptions.url).replace(/\/+$/, "");
}
if (cliOptions.browser) {
  headless = false;
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
