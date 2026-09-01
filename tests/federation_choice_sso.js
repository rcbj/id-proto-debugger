// File: federation_choice_sso.js
//
// ===========================================================================
// ONE APPLICATION, TWO FEDERATION PARTNERS, AND THE PERSON PICKS.
//
// `federation_sso.js` drives an application with ONE federation relationship:
// the browser is sent straight to the partner and no page is drawn in between.
// This file drives an application with TWO, in DIFFERENT PROTOCOLS, and what
// that produces is a page — `/authn/select-idp`, one button per partner and no
// password field.
//
//   browser ──▶ oauth2_oidc_1.html              the application, webapp-sso-1
//             └─▶ /realm/federation-choice-1    an OpenID Provider to it, and
//                 │                             the federation SERVICE
//                 │                             PROVIDER of BOTH relationships
//                 │
//                 ├── choice-saml2 ──┐          SAML 2.0
//                 └── choice-oidc  ──┤          OpenID Connect
//                                    ▼
//                     /realm/federation-choice-2
//                                    the federation IDENTITY PROVIDER, and the
//                                    only place a name is ever typed
//
// ---------------------------------------------------------------------------
// WHAT IS ACTUALLY BEING TESTED, AND WHY "A TOKEN CAME BACK" IS NOT IT
//
// Both relationships work. `federation_sso.js` already proves a SAML 2.0 one
// does and `federation_matrix_sso.js` proves all twenty-five combinations of
// the two protocol layers do. Running either of them again from a page with
// two buttons on it would assert nothing new.
//
// What is new is that a CHOICE was offered and HONOURED, and the assertion
// that catches both halves is arithmetic:
//
//   * after picking the SAML 2.0 button, `choice-saml2` has counted ONE
//     federated sign-in and `choice-oidc` has counted ZERO;
//   * after picking the OpenID Connect button in a second, cookie-less run,
//     `choice-oidc` has counted ONE and `choice-saml2` is STILL at one.
//
// A mock that drew a two-button page and then federated through whichever
// relationship it found first would pass every other assertion in this file
// and fail those two. They are the reason the test signs in TWICE.
//
// ---------------------------------------------------------------------------
// AND THE MUTATION TEST, WHICH IS THE LAST SECTION
//
// Every assertion above would pass just as well against a mock that drew a
// chooser for every federated application, whatever its entry said. So the
// last section REMOVES one of the two values and runs the same authorization
// request: it must then stop drawing a page at all and redirect straight to
// the partner that is left, exactly as `federation_sso.js` asserts. The value
// is put back in a `finally`, because the realms outlive this process.
//
// That is the same shape `federation_sso.js`'s last section has, one level up:
// it removes the tie and expects the local sign-in screen, and this removes
// the SECOND tie and expects the single-partner redirect.
//
// ---------------------------------------------------------------------------
// TWO PROTOCOLS ON PURPOSE, AND NOT TWO OF THE SAME
//
// The two partners are SAML 2.0 and OpenID Connect rather than two SAML ones,
// because the whole claim being made is that what an application's people
// choose between is WHERE they authenticate and not HOW. The two arrive at the
// same `/federation/acs/{id}` by completely different routes — one is a signed
// XML document POSTed by a browser, the other is a code redeemed over a back
// channel — and both end in the same `startSession()`. The chooser prints the
// protocol under each button for exactly this reason, and that label is
// asserted: two buttons that both said "SAML 2.0" would be a page nobody could
// choose from.
//
// ---------------------------------------------------------------------------
// ITS OWN REALMS, AND WHY NOT `federation-realm-1` AND `-2`
//
// `federation_sso.js` asserts its relationship counted EXACTLY ONE sign-in.
// This test signs in twice and creates two relationships. Sharing a realm
// between the two jobs would make each one's arithmetic depend on whether the
// other had run, which under a pool is a flake rather than a failure — the
// same argument `federation_chain_sso.js` makes for taking realms 3, 4 and 5.
//
// NO JOB LOCK: it creates its own realms and asserts only on what it put in
// them.
//
// ---------------------------------------------------------------------------
// ONE THING THE MOCK HAS TO BE CONFIGURED FOR, AND IT IS NOT A HACK
//
// `federation.outboundAllowInsecure`. The OpenID Connect relationship redeems
// its code over a BACK CHANNEL, which `federation_http.js` makes, and that
// module refuses two things by default: an `http://` URL, and a certificate
// nothing here trusts. A client secret and an authorization code travel on
// that request, so both refusals are right — and BOTH apply to this suite.
// Every stack here runs the mock on a self-signed certificate it regenerates
// at every start, so the `https` stacks need this setting exactly as much as
// the `http` ones do; the scheme says nothing about whether it is needed.
// That was the shape of this file's first failure: the SAML 2.0 half passed,
// the OpenID Connect half timed out coming back, and the reason was a 502
// naming a certificate on a page nobody was reading.
//
// It is written WHILE REALM 1 IS AMBIENT, so it lands in that realm's own
// override map rather than process-wide — a mock relaxed process-wide would
// stop checking certificates for every other job in the pool — and it is put
// back with `/admin-api/config/reset` rather than by writing the old value
// back: a `set` leaves `source: override` on the row for ever, and the mock's
// own suite trips over that on the next run against the same container.
//
// The SAML 2.0 half needs no back channel and passes either way, which is
// worth knowing when one half fails and the other does not.
//
// ---------------------------------------------------------------------------
// GATING
//
// `WSTRUST_STS_URL` locates the mock. The job SKIPS with a reason when there is
// none, and with a DIFFERENT reason when the mock predates the feature — read
// off `GET /ldap/applications?format=json`, where `appFederationRelationship`
// must publish `kind: "multi"`. That is the feature's own schema signal: while
// the attribute held one value there was nothing to choose between, and a
// version string would not have said so.
// ===========================================================================

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require("selenium-webdriver/lib/select");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
// Cookie clearing that reaches the IDENTITY PROVIDER's origin and not only the
// page's own. See session_reset.js: WebDriver's Delete All Cookies is scoped to
// the active document, the mock STS is a different HOST from the client on the
// containerized stack, and a session that survives the clear answers the very
// request these tests need to see refused.
const { clearSessionsAt } = require("./session_reset.js");
const { loadPage } = require("./page_load.js");
const { usernameFor } = require("./random_username.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "federation_choice_sso",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const waitForModule = require("./wait_for.js");
waitForModule.configure({ log: log, waitTime: waitTime });
const { waitForPageBundle } = waitForModule;

const { populateMetadata } = require("../common/tests.js")({ By, until, Select,
       waitTime, log, assert });

// The management API helpers, shared with the other three federation jobs.
const admin = require("./federation_admin.js");
admin.configure({ log: log });
const { adminGet, must, tidy } = admin;

const SP_REALM = "federation-choice-1";
const IDP_REALM = "federation-choice-2";
const APPLICATION = "webapp-sso-1";
const REGISTERED_REDIRECT_URI = "https://webapp-sso-1.example.com";

// The two relationships, and everything that differs between them in ONE place
// so that the sections below are written once and run twice.
//
// THREE NAMES FOR ONE PROTOCOL, AND THEY ARE NOT INTERCHANGEABLE. This cost a
// run, and the reason it did is worth keeping:
//
//   protocol      the mock's own id in its federation register — what
//                 `/admin-api/federation/create` is given.
//   label         what the CHOOSER prints under the button. It comes from the
//                 federation register's own PROTOCOLS table
//                 (`federation/federation.js`).
//   screenLabel   what the FAR REALM'S SIGN-IN SCREEN says it is signing
//                 somebody in for. It comes from somewhere else entirely — the
//                 string each protocol module hands `beginAuthentication()` as
//                 `protocol` — and for OpenID Connect the two DISAGREE: the
//                 register says "OpenID Connect" and `oauth-oidc/oauth2.js`
//                 says "OAuth 2.0 / OIDC", because that one screen answers both
//                 protocols and cannot know which.
//
// For SAML 2.0 all three happen to line up, which is exactly why one field
// looked like enough until the OpenID Connect half of this test ran. Asserting
// both is worth more than asserting either: they are two tables in that
// service with nothing keeping them in step, and this is the only job here
// that reads both in one run.
const PARTNERS = [
  { id: "choice-saml2", protocol: "saml2",
    label: "SAML 2.0", screenLabel: "SAML 2.0",
    name: "Realm 2 over SAML 2.0" },
  { id: "choice-oidc", protocol: "oidc",
    label: "OpenID Connect", screenLabel: "OAuth 2.0 / OIDC",
    name: "Realm 2 over OpenID Connect" }
];

function partnerFor(id) {
  return PARTNERS.filter(function (one) { return one.id === id; })[0];
}

// ---------------------------------------------------------------------------
// THE TWO REALMS. A realm is defined at RUNTIME and lives in memory, so there
// is nowhere to declare one and every run creates its own — which also means a
// second run against a live container meets realms that are already there.
// That is not an error: what matters is that the realm exists, not who made it.
// ---------------------------------------------------------------------------
async function createRealms(stsBase) {
  log.debug("Entering createRealms().");
  const before = await adminGet(stsBase, "/realms");
  const known = (before.realms || []).map(function (one) { return one.id; });
  for (const id of [SP_REALM, IDP_REALM]) {
    if (known.indexOf(id) >= 0) {
      log.info("The \"" + id + "\" realm is already defined; reusing it.");
      continue;
    }
    await must(stsBase, "/realms/create", { id: id, name: id },
               "creating the \"" + id + "\" trust realm");
    log.info("Created the \"" + id + "\" trust realm.");
  }
  const after = await adminGet(stsBase, "/realms");
  const ids = (after.realms || []).map(function (one) { return one.id; });
  assert.ok(ids.indexOf(SP_REALM) >= 0 && ids.indexOf(IDP_REALM) >= 0,
    "Both realms should be defined and the service lists: " + ids.join(", ") +
    ". A realm that was created and is not listed means the create answered " +
    "ok for something that did not happen.");
  // Two realms sharing a signing key would be two names for one authorization
  // server, and every assertion below about WHICH realm issued something would
  // be unfalsifiable. The mock derives a `kid` from the key material.
  const kids = (after.realms || []).filter(function (one) {
    return one.id === SP_REALM || one.id === IDP_REALM;
  }).map(function (one) { return one.kid; });
  assert.strictEqual(new Set(kids).size, 2,
    "The two realms publish the same kid (" + kids.join(", ") + "), so they " +
    "are signing with one key and nothing below could tell their tokens apart.");
  log.debug("Leaving createRealms().");
}

// ---------------------------------------------------------------------------
// THE ONE SETTING THIS TEST CHANGES, and it is realm 1's rather than the
// mock's.
//
// The OpenID Connect relationship is the only one of the two with a BACK
// CHANNEL: realm 1 redeems the code at realm 2's token endpoint and reads
// realm 2's JWKS, both through `federation_http.js`, which refuses an
// `http://` URL and refuses a certificate nothing trusts. Every stack in this
// suite runs the mock on a self-signed certificate it regenerates at every
// start, so this is needed on a `https` stack exactly as much as on a plain
// one — reading the scheme and skipping the write is what made the OpenID
// Connect half of this test time out coming back, with the reason on an error
// page nobody was reading.
//
// WHICH REALM THE WRITE LANDED IN is asserted, because that is the half that
// costs somebody else a run: a setting written while a realm is ambient goes
// into that realm's own override map, and one written WITHOUT one lands
// process-wide, where it would stop every other job on this mock from checking
// a certificate. `realm` says which realm answered the read and
// `realmSettings` is that realm's own override list, so the snapshot answers
// both questions at once.
// ---------------------------------------------------------------------------
async function allowInsecureOutbound(spBase) {
  log.debug("Entering allowInsecureOutbound().");
  await must(spBase, "/config/set",
             { key: "federation.outboundAllowInsecure", value: "true" },
             "allowing " + SP_REALM + " to dial " + IDP_REALM + " over the " +
             "mock's own self-signed TLS, which the OpenID Connect " +
             "relationship needs to redeem its code");
  const snapshot = await adminGet(spBase, "/config");
  assert.strictEqual(String(snapshot.realm), SP_REALM,
    "Reading " + SP_REALM + "'s configuration answered for the \"" +
    snapshot.realm + "\" realm, so the write above did not land where this " +
    "test thinks it did either.");
  assert.ok((snapshot.realmSettings || [])
              .indexOf("federation.outboundAllowInsecure") >= 0,
    SP_REALM + " does not list federation.outboundAllowInsecure among its " +
    "OWN settings (it lists: " + (snapshot.realmSettings || []).join(", ") +
    "), so the write went process-wide — which is not this test's to do, and " +
    "would relax the certificate check for every other job on this mock.");
  log.info(SP_REALM + " may dial a partner whose certificate nothing here " +
           "trusts, which is what the OpenID Connect relationship's back " +
           "channel needs.");
  log.debug("Leaving allowInsecureOutbound().");
}

// ---------------------------------------------------------------------------
// THE APPLICATION, NAMING BOTH PARTNERS.
//
// Deleted first and created again so that every counter read below starts at
// zero — a run against a container somebody has already driven would otherwise
// assert on somebody else's arithmetic.
//
// `appFederationRelationship` is given a LIST here, which is the whole feature
// in one field. `appFederationAutoRedirect` is set TRUE explicitly even though
// it defaults that way once a relationship is named: a default is a fact about
// the mock's version rather than about this configuration, and this test reads
// the attribute back.
//
// TRUE is also the interesting value rather than the safe one. It means
// "without the sign-in screen", which with one partner is a redirect and with
// two is the chooser — so this configuration asserts that the setting was read
// as the mock documents it and not as "skip the question".
// ---------------------------------------------------------------------------
async function registerApplication(spBase, callbackUri) {
  log.debug("Entering registerApplication().");
  const existing = await adminGet(spBase,
    "/applications?application=" + encodeURIComponent(APPLICATION));
  if (existing.found) {
    log.info("An earlier run left " + APPLICATION + " behind; removing it so " +
             "this run's counters start at zero.");
    await must(spBase, "/applications/forget", { application: APPLICATION },
               "removing the application left behind by an earlier run");
  }
  await must(spBase, "/applications/create", {
    identifier: APPLICATION,
    name: APPLICATION,
    protocols: ["oauth2", "oidc"],
    fields: {
      oauthClientId: APPLICATION,
      oauthRedirectUri: [REGISTERED_REDIRECT_URI, callbackUri],
      appFederationRelationship: PARTNERS.map(function (one) { return one.id; }),
      appFederationAutoRedirect: "TRUE"
    }
  }, "creating the " + APPLICATION + " application in " + SP_REALM);

  // Read back through the API rather than trusting the create's own answer:
  // the reply is the service's account of what it did, and the ENTRY is what
  // every endpoint will actually read.
  const entry = await adminGet(spBase,
    "/applications?application=" + encodeURIComponent(APPLICATION));
  assert.ok(entry.found, "The application " + APPLICATION + " is not in " +
            SP_REALM + "'s registry after being created there.");
  const fields = entry.fields || {};
  // SORTED, because nothing promises the order values come back in and the
  // claim being made is about the SET. The order they are OFFERED in is a
  // separate assertion, on the page, where it can actually be seen.
  const named = [].concat(fields.appFederationRelationship || []).sort();
  assert.deepStrictEqual(named,
    PARTNERS.map(function (one) { return one.id; }).sort(),
    "The application entry should name both federation relationships and " +
    "names [" + named.join(", ") + "]. With fewer than two there is nothing " +
    "to choose between and every assertion below is about a redirect instead.");
  assert.strictEqual(String(fields.appFederationAutoRedirect), "TRUE",
    "appFederationAutoRedirect reads \"" + fields.appFederationAutoRedirect +
    "\" rather than TRUE, so this test would be asserting the sign-in " +
    "screen's partner buttons rather than the chooser.");
  assert.strictEqual(Number(entry.authentications || 0), 0,
    "The application has " + entry.authentications + " authentication(s) " +
    "recorded before this test has signed anybody in, so the counters below " +
    "are somebody else's.");
  log.info(SP_REALM + " knows " + APPLICATION + " as an application whose " +
           "people sign in at either of " + named.join(" or ") + ".");
  log.debug("Leaving registerApplication().");
  return entry;
}

// ---------------------------------------------------------------------------
// WHAT REALM 2 PUBLISHES, READ FROM REALM 2, for each protocol in turn.
//
// The entityID, the certificate and the endpoints are taken out of the
// identity provider's own documents rather than written down here — they are
// what they are, and fetching them proves that realm is up and answering as
// itself before anything is configured against it.
//
// THE SAML METADATA IS ASKED FOR BY THE SERVICE PROVIDER'S entityID, and
// getting that wrong is the mistake this comment exists to prevent. The mock
// mints per-service-provider identity provider metadata, and the entityID a
// federated AuthnRequest carries is the RELATIONSHIP'S ASSERTION CONSUMER
// SERVICE — `/realm/<sp>/federation/acs/<id>` — not the realm's `/saml2`
// endpoint. A document fetched under the wrong name carries a DIFFERENT
// entityID from the one assertions will arrive with, and `fedPeer` is checked
// against the Issuer, so the flow is then refused with "it was issued by
// somebody else": a failure that names a mismatch and not the fetch that
// caused it.
// ---------------------------------------------------------------------------
async function readSamlPartner(idpBase, spEntityId) {
  log.debug("Entering readSamlPartner().");
  const url = idpBase + "/saml2/metadata/" + encodeURIComponent(spEntityId);
  const response = await fetch(url);
  assert.strictEqual(response.status, 200,
    IDP_REALM + " answered " + response.status + " for its own SAML 2.0 " +
    "metadata at " + url + ".");
  const xml = await response.text();
  const entityId = (xml.match(/entityID="([^"]+)"/) || [])[1] || "";
  const certificate = (xml.match(/<[^>]*X509Certificate>([^<]+)</) || [])[1] ||
                      "";
  const sso = (xml.match(
    /SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"[^>]*Location="([^"]+)"/
  ) || [])[1] || "";
  assert.ok(entityId && certificate && sso,
    IDP_REALM + "'s metadata is missing one of the three things a service " +
    "provider is configured from — entityID=\"" + entityId + "\", " +
    "certificate=" + (certificate ? certificate.length + " characters"
                                  : "(none)") +
    ", HTTP-Redirect SSO=\"" + sso + "\". The document begins: " +
    xml.slice(0, 300));
  assert.ok(sso.indexOf("/realm/" + IDP_REALM + "/") >= 0,
    IDP_REALM + "'s metadata advertises an SSO endpoint outside its own " +
    "realm (" + sso + "), which would send the AuthnRequest to a different " +
    "identity service from the one this test configured.");
  log.info(IDP_REALM + " publishes SAML entityID " + entityId + ".");
  log.debug("Leaving readSamlPartner().");
  return { entityId: entityId, certificate: certificate, sso: sso };
}

async function readOidcPartner(idpBase) {
  log.debug("Entering readOidcPartner().");
  const url = idpBase + "/.well-known/openid-configuration";
  const response = await fetch(url);
  assert.strictEqual(response.status, 200,
    IDP_REALM + " answered " + response.status + " for its own OpenID " +
    "Connect discovery document at " + url + ".");
  const disco = await response.json();
  assert.strictEqual(disco.issuer, idpBase,
    IDP_REALM + " publishes issuer \"" + disco.issuer + "\" rather than \"" +
    idpBase + "\". The mock derives an issuer from the base URL a request " +
    "arrived on, and a realm's base URL carries its prefix — a process-wide " +
    "STS_OAUTH2_ISSUER pin would give both realms one name and the " +
    "relationship's fedPeer check below could not mean anything.");
  for (const name of ["authorization_endpoint", "token_endpoint",
                      "jwks_uri"]) {
    assert.ok(disco[name],
      IDP_REALM + "'s discovery document has no " + name + ", so the OpenID " +
      "Connect relationship cannot be configured against it. It reads: " +
      JSON.stringify(disco).slice(0, 300));
  }
  log.info(IDP_REALM + " publishes OpenID Connect issuer " + disco.issuer + ".");
  log.debug("Leaving readOidcPartner().");
  return disco;
}

// ---------------------------------------------------------------------------
// THE TWO RELATIONSHIPS, IN REALM 1, POINTING AT REALM 2.
//
// Deleted and re-created for the application's reason: the counters are
// asserted to be exact, and one left over from an earlier run carries that
// run's count.
//
// The order is the feature's own and is asserted rather than assumed: CREATE
// (which forces the relationship DISABLED whatever the request said), fill in,
// then ENABLE as a second deliberate act. That is the one place this register
// overrides its input and it is the whole posture of the feature — a partner
// that half-exists and silently accepts assertions is what it is arranged to
// prevent.
// ---------------------------------------------------------------------------
async function createRelationship(spBase, partner, fields, peer) {
  log.debug("Entering createRelationship(). id=" + partner.id);
  await tidy(spBase, "/federation/delete", { id: partner.id },
             "removing the \"" + partner.id + "\" relationship an earlier run " +
             "may have left behind");
  const created = await must(spBase, "/federation/create", {
    id: partner.id,
    role: "service-provider",
    protocol: partner.protocol,
    name: partner.name,
    // CHECKED on the way in: an assertion or an ID Token whose issuer is not
    // this string is refused even when the signature verifies.
    peer: peer
  }, "registering the \"" + partner.id + "\" federation relationship");
  assert.strictEqual(String(created.relationship.fedEnabled), "FALSE",
    "A federation relationship must be created DISABLED whatever the request " +
    "said, and \"" + partner.id + "\" came back with fedEnabled=" +
    created.relationship.fedEnabled + ".");
  assert.ok((created.readiness.missing || []).length,
    "The \"" + partner.id + "\" relationship is reported READY with nothing " +
    "configured on it but an id, a protocol and a peer. A relationship that " +
    "is ready before it has anywhere to send anybody is the assertion this " +
    "test most needs to be able to make.");

  for (const [field, value] of fields) {
    await must(spBase, "/federation/set",
               { id: partner.id, field: field, value: value },
               "setting " + field + " on \"" + partner.id + "\"");
  }
  const enabled = await must(spBase, "/federation/enable", { id: partner.id },
                             "enabling \"" + partner.id + "\"");
  assert.ok(enabled.readiness.ready,
    "The \"" + partner.id + "\" relationship is enabled and not ready: " +
    (enabled.readiness.missing || []).join(", ") + " still to configure. " +
    "Every federated endpoint would refuse rather than half-work, and this " +
    "test would be asserting a page with one usable button on it.");
  log.info("The \"" + partner.id + "\" relationship (" + partner.label +
           ") is enabled and ready.");
  log.debug("Leaving createRelationship().");
  return created;
}

// The relationship as it now stands. Read fresh every time it is asserted on,
// because the interesting values — the counters, the last error — are written
// by the flow rather than by this test.
async function relationshipNow(spBase, id) {
  log.debug("Entering relationshipNow(). id=" + id);
  const view = await adminGet(spBase,
    "/federation?relationship=" + encodeURIComponent(id));
  assert.ok(view.found, "The relationship \"" + id + "\" is no longer " +
            "registered in " + SP_REALM + ".");
  log.debug("Leaving relationshipNow().");
  return view;
}

// Both counters at once, so the assertions below read as the pair they are.
async function counts(spBase) {
  log.debug("Entering counts().");
  const out = {};
  for (const one of PARTNERS) {
    const view = await relationshipNow(spBase, one.id);
    out[one.id] = { authentications: Number(view.authentications || 0),
                    lastUser: String(view.lastUser || ""),
                    lastError: String(view.lastError || "") };
  }
  log.debug("Leaving counts().");
  return out;
}

// ---------------------------------------------------------------------------
// THE APPLICATION IN THE DEBUGGER'S OWN TERMS: fill in oauth2_oidc_1.html and
// stop just short of sending the authorization request.
//
// The request PREVIEW is what is read and asserted, not the hidden fields,
// because the preview is what the page actually navigates to — reading the
// fields would pass on a page that displays one thing and sends another.
// ---------------------------------------------------------------------------
// A field on `oauth2_oidc_1.html` that may be inside a COLLAPSED pane, made
// visible.
//
// Two things make this more than a `click()`. The Configuration Parameters and
// Authorization Request panes collapse themselves once discovery has run, so a
// field in one of them is present and invisible and selecting from it is
// "element not interactable" — and the toggle is a TOGGLE, so a walk that
// arrives with the pane already open must not press it and close it again.
//
// The waits are generous because THIS TEST DRIVES THE PAGE TWICE. A
// single-visit test meets each pane in one state; the second visit here
// re-runs discovery on a page the browser has already cached, which lands the
// collapse and the wait far closer together — and the failure that produces is
// a bare "Waiting until element is visible" naming no pane and no field.
async function reveal(driver, field, expandButtonId) {
  log.debug("Entering reveal(). " + expandButtonId);
  await driver.wait(until.elementLocated(field), waitTime * 3);
  if (await driver.findElement(field).isDisplayed()) {
    log.debug("Leaving reveal(). It was already open.");
    return;
  }
  await driver.findElement(By.id(expandButtonId)).click();
  // Re-FOUND on each poll rather than held: the click redraws the pane, and a
  // handle to the element as it was is then stale.
  await driver.wait(async function () {
    const found = await driver.findElements(field);
    return found.length ? await found[0].isDisplayed() : false;
  }, waitTime * 3,
    "The \"" + expandButtonId + "\" pane did not open, so the field under it " +
    "cannot be filled in.");
  log.debug("Leaving reveal().");
}

async function prepareAuthorizationRequest(driver, spBase, callbackUri) {
  log.debug("Entering prepareAuthorizationRequest().");
  const grant = By.id("authorization_grant_type");
  const clientId = By.id("client_id");

  await reveal(driver, grant, "config_expand_button");
  await new Select(await driver.findElement(grant))
    .selectByVisibleText("OIDC Authorization Code Flow(code)");

  await reveal(driver, clientId, "authz_expand_button");

  await driver.findElement(clientId).clear();
  await driver.findElement(clientId).sendKeys(APPLICATION);
  await driver.findElement(By.id("scope")).clear();
  await driver.findElement(By.id("scope")).sendKeys("openid profile email");
  await driver.findElement(By.id("redirect_uri")).clear();
  await driver.findElement(By.id("redirect_uri")).sendKeys(callbackUri);

  // Typing does not itself redraw the preview.
  await driver.executeScript(
    "oauth2_oidc_1.recalculateAuthorizationRequestDescription();");
  const preview = await driver
    .findElement(By.id("display_authz_request_form_textarea1"))
    .getAttribute("value");
  const nonce = await driver.findElement(By.id("nonce_field"))
    .getAttribute("value");
  const state = await driver.findElement(By.id("state")).getAttribute("value");

  assert.ok(preview.indexOf(spBase + "/oauth2/authorize") >= 0,
    "The page is about to send the authorization request to something other " +
    "than " + SP_REALM + "'s authorization endpoint (" + spBase +
    "/oauth2/authorize). It reads:\n" + preview);
  assert.ok(preview.indexOf("client_id=" + APPLICATION) >= 0,
    "The authorization request does not name " + APPLICATION + ", so nothing " +
    "downstream can look its federation relationships up. It reads:\n" +
    preview);
  log.debug("Leaving prepareAuthorizationRequest().");
  return { nonce: nonce, state: state };
}

// ---------------------------------------------------------------------------
// THE CHOOSER ITSELF: everything that can be asserted about the page before
// anything is clicked.
//
// It is a separate function from the click because it runs on BOTH sign-ins
// and the page must be identical each time — a chooser that offered one
// partner the second time round, because the first had been "used", would be
// a bug nothing else here would catch.
// ---------------------------------------------------------------------------
async function assertChooser(driver, spBase) {
  log.debug("Entering assertChooser().");
  // The buttons are the thing to wait for, not the heading: the heading exists
  // on a page that failed to resolve any partner too.
  await driver.wait(until.elementLocated(By.css("a.fedbtn")), waitTime * 5,
    "No federation partner buttons appeared after the authorization request. " +
    "Neither the chooser nor a sign-in screen drew anything to pick from.");
  const url = await driver.getCurrentUrl();
  assert.ok(url.indexOf("/realm/" + SP_REALM + "/authn/select-idp") >= 0,
    "The browser should be at " + SP_REALM + "'s federation chooser and is " +
    "at " + url + ". An application naming two usable relationships must be " +
    "ASKED which one rather than sent to either.");
  assert.ok(url.indexOf("/realm/" + IDP_REALM + "/") === -1,
    "The browser is already at " + IDP_REALM + " (" + url + "), so " +
    SP_REALM + " picked a partner instead of asking — which is the mock " +
    "deciding which identity provider somebody's employer is.");

  // NO PASSWORD FIELD, AND THIS IS THE ASSERTION THAT THE CHOOSER IS NOT THE
  // SIGN-IN SCREEN WITH ITS FORM HIDDEN. The mock argues that distinction at
  // length; this is what would catch it being undone. An application that
  // federates its authentication has said it does not want a name typed here,
  // and a page carrying `username`/`password`/`kc-login` is one CSS change
  // away from accepting one.
  for (const id of ["username", "password", "kc-login"]) {
    const found = await driver.findElements(By.id(id));
    assert.strictEqual(found.length, 0,
      "The federation chooser carries a \"" + id + "\" element. It is " +
      "supposed to be a page of its own and not the sign-in screen with its " +
      "form suppressed — this application's people do not type a name here.");
  }
  const forms = await driver.findElements(By.css("form"));
  assert.strictEqual(forms.length, 0,
    "The federation chooser carries " + forms.length + " form(s). The " +
    "buttons must be links: a form control would post to the sign-in " +
    "handler, which signs somebody in on a typed name.");

  // ONE BUTTON PER CONFIGURED PARTNER, AND ONLY THOSE. More would mean the
  // generic list at the foot of the sign-in screen had leaked in, which offers
  // every relationship the service has and is a different question entirely.
  const buttons = await driver.findElements(By.css("a.fedbtn"));
  assert.strictEqual(buttons.length, PARTNERS.length,
    "The chooser offers " + buttons.length + " partner(s) and this " +
    "application names " + PARTNERS.length + ". Offering more would mean " +
    "every relationship in the register had leaked onto a page that is " +
    "supposed to be narrowed to this application's own.");

  const offered = [];
  for (const button of buttons) {
    const href = await button.getAttribute("href");
    const text = await button.getText();
    const which = PARTNERS.filter(function (one) {
      return href.indexOf("/federation/login/" + one.id) >= 0;
    })[0];
    assert.ok(which,
      "A button on the chooser points at \"" + href + "\", which is not the " +
      "federated sign-in path of either configured relationship.");
    assert.ok(href.indexOf("/realm/" + SP_REALM + "/") >= 0,
      "The \"" + which.id + "\" button points at \"" + href + "\", which " +
      "does not carry this realm's prefix — following it would start a " +
      "sign-in in a different realm, or in none.");
    // THE RETURN ADDRESS RIDES ALONG. Without it the federated sign-in
    // succeeds and lands the person on a page nobody asked for, which is a
    // failure that looks like the feature working.
    assert.ok(/[?&]returnTo=%2Foauth2%2Fauthorize/.test(href),
      "The \"" + which.id + "\" button carries no returnTo naming the " +
      "authorization request that was interrupted: \"" + href + "\". The " +
      "sign-in would succeed and never come back to the application.");
    // AND THE PROTOCOL IS PRINTED. Two buttons that both said "SAML 2.0"
    // would be a page nobody could choose from, which is the whole reason the
    // two partners in this test speak different protocols.
    assert.ok(text.indexOf(which.label) >= 0,
      "The \"" + which.id + "\" button does not say it speaks " +
      which.label + ". It reads: \"" + text.replace(/\s+/g, " ") + "\".");
    offered.push(which.id);
  }
  offered.sort();
  assert.deepStrictEqual(offered,
    PARTNERS.map(function (one) { return one.id; }).sort(),
    "The chooser offered [" + offered.join(", ") + "] and both configured " +
    "relationships should be there exactly once.");

  // NO ERROR BANNER. Every value on this entry names a usable relationship, so
  // a banner here means one of them stopped being usable and this test is
  // about to assert on a page with a button fewer than it thinks.
  const banners = await driver.findElements(By.css("div.err"));
  for (const banner of banners) {
    const text = await banner.getText();
    assert.fail("The chooser is reporting a problem with this application's " +
                "configuration, so at least one relationship is not usable: " +
                text);
  }
  log.info("The chooser at " + url + " offers exactly " + offered.join(" and ") +
           ", with no password field on it.");
  log.debug("Leaving assertChooser().");
  return offered;
}

async function chooseAndSignIn(driver, which, user) {
  log.debug("Entering chooseAndSignIn(). which=" + which + ", user=" + user);
  const buttons = await driver.findElements(By.css("a.fedbtn"));
  let picked = null;
  for (const button of buttons) {
    const href = await button.getAttribute("href");
    if (href.indexOf("/federation/login/" + which) >= 0) {
      picked = button;
    }
  }
  assert.ok(picked, "There is no button for \"" + which + "\" on the chooser.");
  await driver.executeScript(
    "arguments[0].scrollIntoView({block: 'center'});", picked);
  await picked.click();
  log.info("Picked \"" + which + "\" from the chooser.");

  const username = By.id("username");
  try {
    await driver.wait(until.elementLocated(username), waitTime * 5);
    await driver.wait(until.elementIsVisible(driver.findElement(username)),
                      waitTime);
  } catch (e) {
    const url = await driver.getCurrentUrl();
    const body = await driver.findElement(By.css("body")).getText();
    throw new Error("No sign-in screen appeared after picking \"" + which +
                    "\". The browser is at " + url + " and the page says: " +
                    body.slice(0, 500));
  }
  // AND IT IS THE PARTNER'S SCREEN, NOT THIS REALM'S. The one thing that
  // could go wrong quietly here is the chooser handing the flow back to the
  // service provider's own password box, which would look exactly like the
  // feature working right up to the token.
  const screenUrl = await driver.getCurrentUrl();
  assert.ok(screenUrl.indexOf("/realm/" + IDP_REALM + "/") >= 0,
    "After picking \"" + which + "\" the person should be signing in at " +
    IDP_REALM + ", and the browser is at " + screenUrl + ".");
  assert.ok(screenUrl.indexOf("/realm/" + SP_REALM + "/") === -1,
    "After picking \"" + which + "\" the browser is at one of " + SP_REALM +
    "'s own URLs (" + screenUrl + "), so it asked for the password itself " +
    "instead of federating.");

  // The screen names the protocol it is answering, which is the shape of the
  // whole thing in one string: an OAuth request arrived at realm 1 and a
  // request in THIS protocol left it.
  //
  // `screenLabel`, NOT `label` — see PARTNERS. The chooser's word for a
  // protocol and the far realm's word for it come from different tables and
  // disagree for OpenID Connect.
  const partner = partnerFor(which);
  const screen = await driver.getPageSource();
  assert.ok(screen.indexOf(partner.screenLabel) >= 0,
    IDP_REALM + "'s sign-in screen does not say it is signing somebody in " +
    "for \"" + partner.screenLabel + "\", so " + SP_REALM + " reached it " +
    "over some protocol other than the one \"" + which + "\" is configured " +
    "for.");

  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  const passwords = await driver.findElements(By.id("password"));
  if (passwords.length) {
    await passwords[0].clear();
    await passwords[0].sendKeys("no password is checked here");
  }
  await driver.findElement(By.id("kc-login")).click();
  log.debug("Leaving chooseAndSignIn().");
}

// Best effort by definition: this runs when something has already gone wrong,
// and a browser that will not answer must not replace the original failure
// with one about this function.
async function whereAreWe(driver) {
  log.debug("Entering whereAreWe().");
  let url = "(unknown)";
  let text = "(unreadable)";
  try {
    url = await driver.getCurrentUrl();
    text = await driver.findElement(By.css("body")).getText();
  } catch (e) {
    text = "(the page could not be read: " + e.message + ")";
  }
  log.debug("Leaving whereAreWe(). " + url);
  return "The browser is at " + url + " and the page says: " +
         String(text).replace(/\s+/g, " ").slice(0, 800);
}

function b64uJson(part) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

// ---------------------------------------------------------------------------
// ONE WHOLE SIGN-IN: the authorization request, the chooser, the pick, the
// name typed at realm 2, and the code coming back to the application.
//
// It is a function because the test runs it TWICE — once per partner — and
// the second run is what proves the choice was honoured rather than a partner
// being picked and remembered.
//
// THE COOKIES ARE CLEARED FIRST, and that is not tidiness. Realm 1 issued a
// session on the first run; without clearing it the second authorization
// request would be satisfied by that session and no chooser would be drawn at
// all, so the second half of this test would silently assert nothing.
// ---------------------------------------------------------------------------
async function signInThrough(driver, spBase, callbackUri, which, user) {
  log.debug("Entering signInThrough(). which=" + which);
  await clearSessionsAt(driver, spBase);
  await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                 "authorization_grant_type", { timeout: waitTime * 5 });
  // AND localStorage, WHICH THE COOKIES ABOVE DO NOT COVER. These pages
  // remember which panes are open and what was last typed into them, and this
  // test loads them TWICE — so the second walk would arrive at panes left in
  // the FIRST walk's state, and `reveal()` would be reasoning about a page it
  // did not draw. It is cleared and the page loaded again, because a clear
  // takes effect on the next load rather than on the page holding the values.
  await driver.executeScript("window.localStorage.clear();");
  await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                 "authorization_grant_type", { timeout: waitTime * 5 });
  // Nearly every control on these pages is an inline handler naming a
  // browserify --standalone global, so a click before the bundle has run is a
  // silent no-op rather than an error.
  await waitForPageBundle(driver);
  await populateMetadata(driver, spBase + "/.well-known/openid-configuration");
  const sent = await prepareAuthorizationRequest(driver, spBase, callbackUri);

  await driver.findElement(
    By.css("input[type=\"submit\"][value=\"Authorize\"]")).click();

  await assertChooser(driver, spBase);
  await chooseAndSignIn(driver, which, user);

  // WHAT THE PAGE SAYS, not just that it never arrived. Everything that can
  // go wrong between the password and the callback goes wrong at the mock and
  // is REPORTED BY IT — a back channel that could not be dialled, a signature
  // that did not verify, a relationship that is not enabled — so the browser
  // is sitting on an error page naming the cause while this wait counts down.
  // Without this the failure is a bare TimeoutError and the reason is on a
  // screen nobody reads.
  try {
    await driver.wait(until.urlContains("/oauth2_oidc_2.html"), waitTime * 8);
  } catch (e) {
    throw new Error("The flow never came back to the debugger after the " +
                    "sign-in at " + IDP_REALM + " through \"" + which +
                    "\". " + (await whereAreWe(driver)));
  }
  const returned = new URL(await driver.getCurrentUrl());
  const code = returned.searchParams.get("code");
  assert.ok(code, "No authorization code came back to the application after " +
            "signing in through \"" + which + "\". The browser is at " +
            returned.toString() + ".");
  assert.strictEqual(returned.searchParams.get("state"), sent.state,
    "The state did not come back unchanged from the \"" + which + "\" flow.");
  log.info("The application received an authorization code after federating " +
           "through \"" + which + "\".");
  log.debug("Leaving signInThrough().");
  return sent;
}

// The code, redeemed through the PAGE, because the application is what this
// test stands in for and the Token Request is the application's own call.
async function redeemAndReadIdToken(driver, callbackUri) {
  log.debug("Entering redeemAndReadIdToken().");
  const tokenClientId = By.id("token_client_id");
  await driver.wait(until.elementLocated(tokenClientId), waitTime * 3);
  await driver.wait(until.elementIsVisible(
    driver.findElement(tokenClientId)), waitTime);
  const frontEnd = await driver.findElements(
    By.id("token_initiateFromFrontEnd"));
  assert.ok(frontEnd.length,
    "oauth2_oidc_2.html has no token_initiateFromFrontEnd radio to select.");
  await driver.executeScript(
    "arguments[0].scrollIntoView({block: 'center'});", frontEnd[0]);
  await frontEnd[0].click();
  await driver.findElement(tokenClientId).clear();
  await driver.findElement(tokenClientId).sendKeys(APPLICATION);
  await driver.findElement(By.id("token_scope")).clear();
  await driver.findElement(By.id("token_scope"))
    .sendKeys("openid profile email");
  await driver.findElement(By.id("token_redirect_uri")).clear();
  await driver.findElement(By.id("token_redirect_uri")).sendKeys(callbackUri);
  await driver.findElement(By.className("token_btn")).click();

  const idField = By.id("token_id_token");
  const errorField = By.id("display_token_error_form_textarea1");
  let idToken = "";
  await driver.wait(async function () {
    const fields = await driver.findElements(idField);
    if (fields.length) {
      idToken = await fields[0].getAttribute("value");
      if (idToken && idToken.split(".").length === 3) {
        return true;
      }
    }
    const errors = await driver.findElements(errorField);
    if (errors.length) {
      const text = await errors[0].getAttribute("value");
      if (text && text.trim()) {
        throw new Error(SP_REALM + "'s token endpoint refused the code: " +
                        text);
      }
    }
    return false;
  }, waitTime * 6, "The code never became an ID Token.");
  log.debug("Leaving redeemAndReadIdToken().");
  return b64uJson(idToken.split(".")[1]);
}

// ---------------------------------------------------------------------------
// THE MUTATION TEST. Remove ONE of the two values and the same authorization
// request must stop drawing a page at all.
//
// Without this, every assertion above would pass against a mock that drew a
// chooser for every federated application whatever its entry said — and a test
// that cannot fail when the feature is removed is not testing the feature.
//
// The value is put back in a `finally`: the realms outlive this process, and a
// later run of this same job would otherwise meet an application with one
// partner and skip straight past everything above.
// ---------------------------------------------------------------------------
async function removingOnePartnerRestoresTheRedirect(driver, spBase,
                                                     callbackUri) {
  log.debug("Entering removingOnePartnerRestoresTheRedirect().");
  const dropped = PARTNERS[1].id;
  const kept = PARTNERS[0].id;
  // REMOVE, not set: the attribute holds a list, and the mock refuses a `set`
  // on one by name because it would replace the list with a single value.
  await must(spBase, "/applications/remove",
             { application: APPLICATION,
               attribute: "appFederationRelationship", value: dropped },
             "removing \"" + dropped + "\" from the application's partners");
  try {
    const entry = await adminGet(spBase,
      "/applications?application=" + encodeURIComponent(APPLICATION));
    assert.deepStrictEqual(
      [].concat((entry.fields || {}).appFederationRelationship || []), [kept],
      "The application should now name only \"" + kept + "\" and names [" +
      [].concat((entry.fields || {}).appFederationRelationship || [])
        .join(", ") + "], so the check below would be measuring nothing.");

    // THE MOCK'S OWN ORIGIN, not this page's — and this is the one call site
    // in the file where getting it wrong is invisible on a host run and fatal
    // on the containerized one. Two sign-ins have just happened, so realm 1
    // holds a session; `deleteAllCookies()` alone empties the jar of whatever
    // document is active, which here is the debugger on `client`, and leaves
    // the mock's on `sts` exactly where it was. The mock then answers this
    // authorization request FROM THAT SESSION — correctly — no sign-in screen
    // is drawn at all, and the wait below times out saying realm 2 never
    // appeared. See session_reset.js.
    await clearSessionsAt(driver, spBase);
    await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                   "authorization_grant_type", { timeout: waitTime * 5 });
    await driver.executeScript("window.localStorage.clear();");
    await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                   "authorization_grant_type", { timeout: waitTime * 5 });
    await waitForPageBundle(driver);
    await populateMetadata(driver,
      spBase + "/.well-known/openid-configuration");
    await prepareAuthorizationRequest(driver, spBase, callbackUri);
    await driver.findElement(
      By.css("input[type=\"submit\"][value=\"Authorize\"]")).click();
    // With one partner left the browser goes STRAIGHT to realm 2, so what to
    // wait for is that realm's sign-in screen and not a button.
    await driver.wait(until.elementLocated(By.id("username")), waitTime * 5,
      "Nothing appeared after the authorization request with one partner " +
      "left. It should have been " + IDP_REALM + "'s sign-in screen.");
    const url = await driver.getCurrentUrl();
    assert.ok(url.indexOf("/realm/" + IDP_REALM + "/") >= 0,
      "With one partner left the browser should have gone straight to " +
      IDP_REALM + " and is at " + url + ".");
    assert.ok(url.indexOf("/authn/select-idp") === -1,
      "With ONE partner named the chooser was still drawn (" + url + "), so " +
      "this mock draws it for every federated application and the two-button " +
      "page above was not evidence of anything.");
    log.info("With one partner removed the same request goes straight to " +
             IDP_REALM + " with no page in between: " + url);
  } finally {
    await must(spBase, "/applications/add",
               { application: APPLICATION,
                 attribute: "appFederationRelationship", value: dropped },
               "putting \"" + dropped + "\" back on the application");
  }
  log.debug("Leaving removingOnePartnerRestoresTheRedirect().");
}

// The chooser is reached with a pending-authentication id and nothing else.
// Following it bare must be refused rather than answered with a partner list
// somebody could compose — and this is the cheapest negative in the file.
async function bareChooserIsRefused(spBase) {
  log.debug("Entering bareChooserIsRefused().");
  const url = spBase + "/authn/select-idp";
  const response = await fetch(url, { redirect: "manual" });
  const body = await response.text();
  assert.strictEqual(response.status, 400,
    "The chooser at " + url + " answered " + response.status + " with no " +
    "?authn= id. What it draws comes off a pending record, and a page " +
    "composed without one would be a partner list with a return address " +
    "anybody could supply. It says: " + body.slice(0, 300));
  assert.strictEqual(String(response.headers.get("set-cookie") || ""), "",
    "The bare chooser set a cookie: " + response.headers.get("set-cookie") +
    ".");
  log.info("The chooser with no pending sign-in is refused 400.");
  log.debug("Leaving bareChooserIsRefused().");
}

// Whether this mock is new enough. The signal is the attribute's own KIND in
// the schema that service publishes: while `appFederationRelationship` held
// ONE value there was nothing to choose between, so `multi` is the feature
// rather than a proxy for it.
async function mockCanOfferAChoice(stsBase) {
  log.debug("Entering mockCanOfferAChoice().");
  const response = await fetch(stsBase + "/ldap/applications?format=json",
                               { headers: { Accept: "application/json" } });
  if (response.status !== 200) {
    log.debug("Leaving mockCanOfferAChoice(). " + response.status);
    return false;
  }
  let parsed = null;
  try {
    parsed = JSON.parse(await response.text());
  } catch (e) {
    // Not JSON: an older mock, or something else answering on that port. Both
    // are "cannot offer a choice", and the skip message names the URL.
    log.debug("Leaving mockCanOfferAChoice(). Not JSON.");
    return false;
  }
  const row = ((parsed.schema || {}).attributes || []).filter(function (one) {
    return one.name === "appFederationRelationship";
  })[0];
  const can = !!row && row.kind === "multi";
  log.debug("Leaving mockCanOfferAChoice(). " + can);
  return can;
}

async function test() {
  log.debug("Entering test().");
  const stsUrl = process.env.WSTRUST_STS_URL || "";
  if (!stsUrl) {
    log.info("SKIPPED: WSTRUST_STS_URL is not set, so there is no mock STS to " +
             "build two trust realms in. This test needs that service and " +
             "nothing else.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const stsBase = stsUrl.replace(/\/sts\/?$/, "");
  if (!(await mockCanOfferAChoice(stsBase))) {
    log.info("SKIPPED: the mock STS at " + stsBase + " publishes " +
             "appFederationRelationship as a single-valued attribute, so an " +
             "application cannot name two federation partners and there is " +
             "nothing to choose between. Bump the sts/ submodule.");
    log.debug("Leaving test(). Skipped, the mock is too old.");
    return;
  }
  const spBase = stsBase + "/realm/" + SP_REALM;
  const idpBase = stsBase + "/realm/" + IDP_REALM;
  const callbackUri = baseUrl + "/callback";
  const samlUser = usernameFor("fedchoice-saml");
  const oidcUser = usernameFor("fedchoice-oidc");

  // Whether the setting below was actually written, so the `finally` resets
  // exactly what it turned on: a reset of a setting that is not overridden is
  // refused by the mock, and a `must()` in a `finally` would then replace the
  // real failure with that one.
  let relaxedOutbound = false;
  // process.exit() is synchronous termination, so it would skip both of the
  // `finally` blocks below — orphaning the browser (one headless Chrome is
  // ~15 processes, which is how a run of this suite once left 559 of them on
  // the machine) and leaving the setting above turned on. The failure is
  // recorded here, the two blocks unwind, and the exit is the last thing this
  // function does.
  let testFailed = false;

  try {
    // -------------------------------------------------------------------
    // CONFIGURATION FIRST, with no browser open. Every call is asserted: a
    // setup step that quietly does nothing is worse than none, because the
    // flow below would then be testing whatever the mock happened to be
    // configured with.
    // -------------------------------------------------------------------
    await createRealms(stsBase);
    await allowInsecureOutbound(spBase);
    relaxedOutbound = true;
    await registerApplication(spBase, callbackUri);

    const samlPartner = await readSamlPartner(idpBase,
      spBase + "/federation/acs/" + PARTNERS[0].id);
    await createRelationship(spBase, PARTNERS[0],
      [["fedSsoUrl", samlPartner.sso],
       ["fedSigningCertificate", samlPartner.certificate],
       ["fedPeer", samlPartner.entityId]],
      samlPartner.entityId);

    const oidcPartner = await readOidcPartner(idpBase);
    await createRelationship(spBase, PARTNERS[1],
      [["fedSsoUrl", oidcPartner.authorization_endpoint],
       ["fedTokenUrl", oidcPartner.token_endpoint],
       ["fedJwksUri", oidcPartner.jwks_uri],
       // This service's client_id AT THE PARTNER — ours, issued by them. The
       // mock accepts any client_id, so what this proves is only that the
       // relationship carries one; a partner that checked it would need it to
       // match a registration over there.
       ["fedClientId", SP_REALM + "-at-" + IDP_REALM],
       ["fedClientSecret", "no secret is checked at either end"],
       ["fedScope", "openid profile email"]],
      oidcPartner.issuer);

    // Two relationships, two protocols, one service provider — and they must
    // be genuinely different endpoints or the choice below is cosmetic.
    const samlView = await relationshipNow(spBase, PARTNERS[0].id);
    const oidcView = await relationshipNow(spBase, PARTNERS[1].id);
    assert.notStrictEqual(samlView.fields.fedSsoUrl, oidcView.fields.fedSsoUrl,
      "Both relationships send the browser to the same URL (" +
      samlView.fields.fedSsoUrl + "), so the two buttons on the chooser are " +
      "two spellings of one thing and nothing below distinguishes them.");
    assert.notStrictEqual(samlView.protocol, oidcView.protocol,
      "Both relationships speak " + samlView.protocol + ". This test exists " +
      "to show that what an application's people choose between is WHERE " +
      "they authenticate rather than HOW, which needs two protocols.");

    // Realm 2 is an ORDINARY identity provider that has never heard of
    // federation, and the two realms run one codebase — so this is the
    // assertion that the difference between them is configuration and nothing
    // else.
    const idpRegister = await adminGet(idpBase, "/federation");
    assert.strictEqual((idpRegister.relationships || []).length, 0,
      IDP_REALM + " has " + (idpRegister.relationships || []).length +
      " federation relationship(s) of its own. It is supposed to be an " +
      "ordinary identity provider, which is what makes the flow below a " +
      "federation rather than a chain of them.");

    await bareChooserIsRefused(spBase);

    const before = await counts(spBase);
    for (const one of PARTNERS) {
      assert.strictEqual(before[one.id].authentications, 0,
        "The \"" + one.id + "\" relationship has counted " +
        before[one.id].authentications + " sign-in(s) before this test has " +
        "performed any, so the arithmetic below is somebody else's.");
    }

    const options = new chrome.Options();
    if (headless) {
      // "=new", never bare --headless: the tests image pins Chrome 121, where
      // plain --headless selects the old implementation and
      // --unsafely-treat-insecure-origin-as-secure has no effect in it.
      options.addArguments("--headless=new");
    }
    options.addArguments("--no-sandbox");
    options.addArguments("--disable-dev-shm-usage");
    browserFlags.addBrowserAccessFlags(options, baseUrl);
    const loggingPrefs = new logging.Preferences();
    loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

    const driver = await new Builder()
      .forBrowser("chrome")
      .setChromeOptions(options)
      .setLoggingPrefs(loggingPrefs)
      .build();

    try {
      // ---------------------------------------------------------------
      // SIGN-IN ONE: pick the SAML 2.0 partner.
      // ---------------------------------------------------------------
      log.info("Sign-in one: " + samlUser + " through \"" + PARTNERS[0].id +
               "\" (" + PARTNERS[0].label + ").");
      const sentSaml = await signInThrough(driver, spBase, callbackUri,
                                           PARTNERS[0].id, samlUser);

      // READ BEFORE THE CODE IS REDEEMED, so the count is about the SIGN-IN
      // rather than about the token call.
      const afterSaml = await counts(spBase);
      assert.strictEqual(afterSaml[PARTNERS[0].id].authentications, 1,
        "The \"" + PARTNERS[0].id + "\" relationship counted " +
        afterSaml[PARTNERS[0].id].authentications + " federated sign-in(s) " +
        "and this test picked its button exactly once.");
      // THE ASSERTION THIS WHOLE TEST IS FOR. A mock that drew two buttons and
      // then federated through whichever relationship it found first would
      // pass everything above and fail here.
      assert.strictEqual(afterSaml[PARTNERS[1].id].authentications, 0,
        "The \"" + PARTNERS[1].id + "\" relationship counted " +
        afterSaml[PARTNERS[1].id].authentications + " federated sign-in(s) " +
        "and its button was never pressed. The choice on that page decides " +
        "which partner is used, and a service that ignores it and takes the " +
        "first usable one draws exactly the same page.");
      assert.ok(!afterSaml[PARTNERS[0].id].lastError,
        "The \"" + PARTNERS[0].id + "\" relationship recorded a failure " +
        "during a sign-in that succeeded: " +
        afterSaml[PARTNERS[0].id].lastError);
      assert.ok(afterSaml[PARTNERS[0].id].lastUser.indexOf(samlUser) >= 0,
        "The \"" + PARTNERS[0].id + "\" relationship's last user is \"" +
        afterSaml[PARTNERS[0].id].lastUser + "\" and this test signed in as \"" +
        samlUser + "\".");

      const samlClaims = await redeemAndReadIdToken(driver, callbackUri);
      assert.strictEqual(samlClaims.iss, spBase,
        "The application's ID Token says it was issued by \"" +
        samlClaims.iss + "\". It must be " + SP_REALM + ": the application " +
        "asked " + SP_REALM + " and " + SP_REALM + " is what answered.");
      assert.strictEqual(samlClaims.nonce, sentSaml.nonce,
        "The ID Token carries nonce \"" + samlClaims.nonce + "\", not the one " +
        "the page sent.");
      // NEITHER THE PARTNER REALM NOR THE RELATIONSHIP IS IN IT. The second
      // half is this test's own: the application chose nothing and was told
      // nothing, and a `choice-saml2` appearing in its ID Token would mean the
      // chooser had leaked one layer up.
      assert.ok(JSON.stringify(samlClaims).indexOf(IDP_REALM) === -1,
        "The application's ID Token mentions " + IDP_REALM + ": " +
        JSON.stringify(samlClaims) + ". Which identity service did the " +
        "authenticating is not the application's business.");
      assert.ok(JSON.stringify(samlClaims).indexOf(PARTNERS[0].id) === -1,
        "The application's ID Token names the federation relationship \"" +
        PARTNERS[0].id + "\": " + JSON.stringify(samlClaims) + ". The " +
        "application did not choose it and must not learn about it.");
      assert.ok(String(samlClaims.preferred_username ||
                       samlClaims.sub).indexOf(samlUser) >= 0,
        "The ID Token describes \"" +
        (samlClaims.preferred_username || samlClaims.sub) + "\" and the name " +
        "typed at " + IDP_REALM + " was \"" + samlUser + "\".");
      log.info("Sign-in one complete: an ID Token from " + samlClaims.iss +
               " describing " +
               (samlClaims.preferred_username || samlClaims.sub) + ".");

      // ---------------------------------------------------------------
      // SIGN-IN TWO: the same application, the same page, the OTHER button.
      //
      // This is the half that makes the pair of counters mean something. It
      // also asserts, through assertChooser() running a second time, that the
      // page is identical — a chooser that offered one partner on the second
      // visit would be a bug nothing else here would catch.
      // ---------------------------------------------------------------
      log.info("Sign-in two: " + oidcUser + " through \"" + PARTNERS[1].id +
               "\" (" + PARTNERS[1].label + ").");
      const sentOidc = await signInThrough(driver, spBase, callbackUri,
                                           PARTNERS[1].id, oidcUser);

      const afterOidc = await counts(spBase);
      assert.strictEqual(afterOidc[PARTNERS[1].id].authentications, 1,
        "The \"" + PARTNERS[1].id + "\" relationship counted " +
        afterOidc[PARTNERS[1].id].authentications + " federated sign-in(s) " +
        "and this test picked its button exactly once.");
      assert.strictEqual(afterOidc[PARTNERS[0].id].authentications, 1,
        "The \"" + PARTNERS[0].id + "\" relationship counted " +
        afterOidc[PARTNERS[0].id].authentications + " federated sign-in(s) " +
        "after the SECOND sign-in went through the other partner. It was " +
        "used once and must still read one.");
      assert.ok(!afterOidc[PARTNERS[1].id].lastError,
        "The \"" + PARTNERS[1].id + "\" relationship recorded a failure " +
        "during a sign-in that succeeded: " +
        afterOidc[PARTNERS[1].id].lastError);
      assert.ok(afterOidc[PARTNERS[1].id].lastUser.indexOf(oidcUser) >= 0,
        "The \"" + PARTNERS[1].id + "\" relationship's last user is \"" +
        afterOidc[PARTNERS[1].id].lastUser + "\" and this test signed in as \"" +
        oidcUser + "\".");

      const oidcClaims = await redeemAndReadIdToken(driver, callbackUri);
      assert.strictEqual(oidcClaims.iss, spBase,
        "The second ID Token says it was issued by \"" + oidcClaims.iss +
        "\" rather than by " + SP_REALM + ".");
      assert.strictEqual(oidcClaims.nonce, sentOidc.nonce,
        "The second ID Token carries nonce \"" + oidcClaims.nonce +
        "\", not the one the page sent.");
      assert.ok(JSON.stringify(oidcClaims).indexOf(IDP_REALM) === -1,
        "The second ID Token mentions " + IDP_REALM + ": " +
        JSON.stringify(oidcClaims) + ".");
      assert.ok(String(oidcClaims.preferred_username ||
                       oidcClaims.sub).indexOf(oidcUser) >= 0,
        "The second ID Token describes \"" +
        (oidcClaims.preferred_username || oidcClaims.sub) + "\" and the name " +
        "typed at " + IDP_REALM + " was \"" + oidcUser + "\".");
      // TWO PEOPLE, ONE APPLICATION, TWO PROTOCOLS. The application asked the
      // same question twice and got two answers in the same shape, and the
      // fact that they arrived over completely different wire protocols is
      // nowhere in either of them.
      assert.notStrictEqual(
        String(samlClaims.preferred_username || samlClaims.sub),
        String(oidcClaims.preferred_username || oidcClaims.sub),
        "Both sign-ins describe the same person, so the second flow was " +
        "satisfied by the first one's session rather than by the partner " +
        "whose button was pressed.");
      log.info("Sign-in two complete: an ID Token from " + oidcClaims.iss +
               " describing " +
               (oidcClaims.preferred_username || oidcClaims.sub) + ".");

      // BOTH PEOPLE HAVE A DIRECTORY ENTRY IN REALM 1, a service that never
      // checked a password for either of them, and each is recorded as having
      // arrived through federation.
      for (const user of [samlUser, oidcUser]) {
        const users = await adminGet(spBase,
          "/users?q=" + encodeURIComponent(user));
        assert.ok((users.users || []).some(function (one) {
          return String(one.name) === user || String(one.key) === user;
        }), SP_REALM + " has no directory entry for " + user + ", who has " +
            "just signed in there. It lists: " +
            (users.users || []).map(function (o) { return o.name; })
              .join(", "));
      }

      // The mutation test, last, because it changes the configuration
      // everything above depends on.
      await removingOnePartnerRestoresTheRedirect(driver, spBase, callbackUri);

      log.info("Test completed successfully.");
    } catch (error) {
      log.error(error.stack || error.message);
      testFailed = true;
    } finally {
      await driver.quit();
    }
  } finally {
    // The same argument the driver's own finally is written under, one level
    // out: process.exit() below would skip THIS block too, and the setting
    // would be left on realm 1 by every failing run.
    if (relaxedOutbound) {
      await must(spBase, "/config/reset",
                 { key: "federation.outboundAllowInsecure" },
                 "resetting federation.outboundAllowInsecure in " + SP_REALM);
    }
  }
  if (testFailed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("federation_choice_sso")
  .description("One application mapped to TWO federation relationships in " +
               "different protocols, where the person picks which identity " +
               "provider authenticates them.")
  .addOption(
    new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory()
  )
  .addOption(
    new Option("-b, --browser", "Display browser (only works within device).")
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
