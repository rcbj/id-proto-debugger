// File: federation_matrix_sso.js
//
// ===========================================================================
// EVERY COMBINATION OF THE TWO PROTOCOL LAYERS IN A TWO-TIER FEDERATION, AND
// OF HOW THE FAR END AUTHENTICATES.
//
// `federation_sso.js` drives ONE point of a grid: an application speaking OIDC
// to `federation-realm-1`, which speaks SAML 2.0 on to `federation-realm-2`,
// where a password is typed. This file drives THE WHOLE GRID. It is one script
// run once per point, parameterised by three environment variables, and
// `tests/run-report.js` pushes one job per point so that a failure names its
// own combination in `report.xml` rather than a group that contains it.
//
//   FEDERATION_APP_PROTOCOL   how the APPLICATION asks realm 1        (five)
//   FEDERATION_FED_PROTOCOL   how realm 1 asks realm 2                (five)
//   FEDERATION_MECHANISM      how realm 2 authenticates the person    (two)
//
//   browser ──▶ the debugger, as an application         oidc | oauth2 |
//             │                                         saml2 | saml11 | wsfed
//             └─▶ /realm/federation-matrix-1            an identity provider to
//                 │                                     the application, and a
//                 │                                     federation SERVICE
//                 │                                     PROVIDER
//                 └─▶ /realm/federation-matrix-2        the federation IDENTITY
//                                                       PROVIDER, and the only
//                                                       place a name is typed
//
// ---------------------------------------------------------------------------
// WHY A GRID AT ALL, WHEN ONE POINT OF IT ALREADY PASSES.
//
// Because the two layers are joined by exactly one thing and it is invisible
// from either side. The application tier reaches `authn.js` through
// `beginAuthentication()`, which looks the application up and hands the person
// to `federation_sp.js`; the federation tier comes back through
// `startSession()`. NEITHER HALF KNOWS THE OTHER'S PROTOCOL, which is the
// property federation exists for — and it is also the property that makes a
// single working combination almost worthless as evidence. Twenty-five ways of
// arriving times two ways of authenticating is where the joins actually are:
//
//   * four of the five application protocols reach `mechanismFor()` and the
//     fifth did not until 2026-08-26 (see WS-FEDERATION below), so "does this
//     application tier federate at all" has five different answers;
//   * `ourEntityId()` is one string used as a SAML `<Issuer>`, a WS-Federation
//     `wtrealm` and an OAuth `client_id` — one spelling for four protocols,
//     and a partner keyed off the wrong one of them refuses everything;
//   * the identity-provider-side relationship at realm 2 is found by matching
//     that identifier against `fedApplication`, so every federation protocol
//     has its own way of getting the mechanism wrong;
//   * and `fedAuthnMechanism: webauthn` has to survive whatever protocol asked
//     — a passwordless sign-in is a second screen and a second POST, and the
//     return address has to still be there afterwards.
//
// ---------------------------------------------------------------------------
// THE SEVENTY-FIVE THAT IS FIFTY. SPNEGO IS NOT HERE, DELIBERATELY.
//
// The three mechanisms this grid was asked for were a password, WebAuthn and
// SPNEGO. The mock has all of Kerberos and a REAL SPNEGO acceptor — RFC 4559
// carrying RFC 4178 carrying an AP-REQ, at `/spnego/protected`, verified
// through `krb5_service.accept()` — and it is not an authentication MECHANISM
// there: that endpoint renders a page saying who you are and never calls
// `startSession()`, so no browser session comes out of it and `authn.js` has
// no `spnego` in `MECHANISMS`. Wiring the acceptor to the session is small; the
// open question is where a headless browser gets its ticket, since `mock-sts`
// has no bundler and its own page says a browser will not answer a `Negotiate`
// challenge without an allow-list. So the third mechanism is deferred rather
// than faked, and this grid is 5 x 5 x 2.
//
// ---------------------------------------------------------------------------
// WS-FEDERATION, WHICH THIS GRID CHANGED THE MOCK TO SUPPORT.
//
// The other four application protocols have always reached `authn.js` through
// `beginAuthentication()`. `wsfed.js` did not: it drew a sign-in screen of its
// own and called `startSession()` itself, on the argument that the parameters a
// person needs to see for a `wsignin1.0` are `wtrealm`, `wreply`, `wctx`,
// `wauth` and `whr`, and a screen printing `client_id: (none)` would describe a
// request that does not exist. That argument was right about the screen and
// wrong about the funnel — `beginAuthentication()` takes a `details` array for
// exactly that — and owning the funnel meant three features silently did
// nothing for this profile alone: federation, `fedAuthnMechanism`, and the
// WebAuthn step. It goes through the shared funnel now. Fifteen of the fifty
// points below are the application half of that, and five more are the
// federation half (`wsfed` + `webauthn`, which the old screen could not do).
//
// ---------------------------------------------------------------------------
// ONE PAIR OF REALMS, AND WHY THAT IS SAFE UNDER THE POOL.
//
// `federation-matrix-1` and `federation-matrix-2`, shared by all fifty jobs and
// created by whichever gets there first. Nothing here asserts anything
// REALM-WIDE — not the number of relationships, not the number of users, not
// the contents of the register — because fifty jobs are putting things in those
// realms at once. Every assertion is about objects this point OWNS, named after
// its own combination:
//
//   the application at realm 1     per APP_PROTOCOL, carrying the slug
//   the relationship at realm 1    fedmx-<slug>
//   the partner entry at realm 2   what realm 1 calls itself over FED_PROTOCOL
//   the relationship at realm 2    fedmx-<slug>-idp
//   the person                     usernameFor("fedmx-<slug>")
//
// so the counters this job asserts are EXACTLY ONE on are its own arithmetic
// and nobody else's. That is why there is no JOB_LOCK. It is also why realms 1
// and 2 of the OTHER federation tests are left alone: `federation_sso.js`
// asserts realm 2 has NO relationships at all, which is true there and would be
// false here within a second of the pool starting.
//
// The one thing this leaves behind is `federation.outboundAllowInsecure` on
// realm 1, which the OIDC and OAuth 2.0 federation points need and none of them
// resets — see allowInsecureOutbound(). Fifty jobs turning one realm setting on
// and off around each other is a flake; a setting left on in a realm that
// belongs entirely to this file is not.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS, AND WHY NOT "DID SOMETHING COME BACK".
//
// A federated sign-in that ends with a token proves very little: every
// interesting failure here produces one, because the local password box
// produces one too. So the assertions are about the SHAPE of the flow and the
// STATE left behind, and the two that carry the most weight are the ones that
// would still pass on a mock that federated nothing:
//
//   * realm 1's OWN sign-in screen is never drawn and realm 2's is — asserted
//     on the URL the sign-in screen appears at, which carries the realm;
//   * realm 2 authenticated the person BY THE CONFIGURED MECHANISM — a
//     WebAuthn point must reach the ceremony page, and a password point must
//     not;
//   * realm 1's relationship counted EXACTLY ONE federated sign-in and
//     recorded no error;
//   * realm 1's directory has an entry for somebody whose password was never
//     checked there;
//   * the application's own artifact — an ID Token, an access token, a SAML
//     assertion or a WS-Federation RSTR — says realm 1 issued it and names
//     realm 2 nowhere;
//   * and the TIE ITSELF, by removing it: with `appFederationRelationship`
//     cleared, the same request must stop at realm 1's own sign-in screen.
//     Without that last one every assertion above would pass just as well
//     against a service that federated every sign-in for reasons of its own.
//
// ---------------------------------------------------------------------------
// GATING
//
// `WSTRUST_STS_URL` locates the mock, as it does for every other STS-backed job
// here, and the job SKIPS with a reason when there is none. It skips with a
// DIFFERENT reason when the mock is too old for the two attributes this whole
// grid turns on, which is read off `GET /ldap/applications` and
// `GET /admin-api/federation/schema` — the schemas that service publishes —
// rather than guessed from a version.
//
// **Services needed:** the client, the api and the mock STS. The api is not
// optional the way it is for `federation_sso.js`: the SAML and WS-Federation
// application tiers land their responses on the api's `/saml` and `/wsfed`
// landings.
// ===========================================================================

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require("selenium-webdriver/lib/select");
const chrome = require("selenium-webdriver/chrome");
const { VirtualAuthenticatorOptions, Transport, Protocol } =
  require("selenium-webdriver/lib/virtual_authenticator");
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
var log = bunyan.createLogger({ name: "federation_matrix_sso",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const waitForModule = require("./wait_for.js");
waitForModule.configure({ log: log, waitTime: waitTime });
const { waitForPageBundle, waitForFocus } = waitForModule;

const admin = require("./federation_admin.js");
admin.configure({ log: log });
const { adminGet, must, tidy } = admin;

const { populateMetadata } = require("../common/tests.js")({ By, until, Select,
       waitTime, log, assert });

// ---------------------------------------------------------------------------
// THE POINT OF THE GRID THIS RUN IS.
//
// Defaulted rather than required, and the defaults are deliberately the
// combination `federation_sso.js` already covers: a bare `node
// federation_matrix_sso.js --url ...` is then the shortest thing that can be
// compared against a job known to pass.
// ---------------------------------------------------------------------------
const APP_PROTOCOLS = ["oidc", "oauth2", "saml2", "saml11", "wsfed"];
const FED_PROTOCOLS = ["oidc", "oauth2", "saml2", "saml11", "wsfed"];
const MECHANISMS = ["password", "webauthn"];

const APP_PROTOCOL =
    String(process.env.FEDERATION_APP_PROTOCOL || "oidc").toLowerCase();
const FED_PROTOCOL =
    String(process.env.FEDERATION_FED_PROTOCOL || "saml2").toLowerCase();
const MECHANISM =
    String(process.env.FEDERATION_MECHANISM || "password").toLowerCase();

assert.ok(APP_PROTOCOLS.indexOf(APP_PROTOCOL) >= 0,
  "FEDERATION_APP_PROTOCOL is \"" + APP_PROTOCOL + "\" and must be one of " +
  APP_PROTOCOLS.join(", ") + ".");
assert.ok(FED_PROTOCOLS.indexOf(FED_PROTOCOL) >= 0,
  "FEDERATION_FED_PROTOCOL is \"" + FED_PROTOCOL + "\" and must be one of " +
  FED_PROTOCOLS.join(", ") + ".");
assert.ok(MECHANISMS.indexOf(MECHANISM) >= 0,
  "FEDERATION_MECHANISM is \"" + MECHANISM + "\" and must be one of " +
  MECHANISMS.join(", ") + ".");

// How each protocol is spelled on a page and in a log line. One table, because
// a label built by hand at four call sites is four chances to say "SAML1.1".
const LABELS = {
  oidc: "OIDC Authorization Code",
  oauth2: "OAuth 2.0 Authorization Code",
  saml2: "SAML 2.0",
  saml11: "SAML 1.1",
  wsfed: "WS-Federation"
};

const SP_REALM = "federation-matrix-1";
const IDP_REALM = "federation-matrix-2";

const SLUG = APP_PROTOCOL + "-" + FED_PROTOCOL + "-" + MECHANISM;
// A relationship id is an RDN and a PATH SEGMENT in the mock: lower-case
// letters, digits and hyphens, which is what the slug is made of.
const RELATIONSHIP = "fedmx-" + SLUG;
const IDP_RELATIONSHIP = "fedmx-" + SLUG + "-idp";

// ---------------------------------------------------------------------------
// WHAT THE DEBUGGER CALLS ITSELF TO REALM 1, which is a different KIND of
// string in each of the five protocols and is the identifier realm 1 looks the
// federation relationship up by. Getting this wrong does not fail: it federates
// NOTHING and draws a password box, which is why the tie is removed and put
// back at the end of this test rather than assumed to be doing something.
// ---------------------------------------------------------------------------
function applicationId() {
  log.debug("Entering applicationId().");
  if (APP_PROTOCOL === "oidc" || APP_PROTOCOL === "oauth2") {
    log.debug("Leaving applicationId(). An OAuth client_id.");
    return "fedmx-" + SLUG;
  }
  if (APP_PROTOCOL === "saml2") {
    log.debug("Leaving applicationId(). A SAML 2.0 entityID.");
    return "https://" + SLUG + ".sp.example.com/saml2";
  }
  if (APP_PROTOCOL === "saml11") {
    // SAML 1.1 has no request message, so this rides on `providerId` — see
    // driveSaml(). It is still an entityID-shaped string because that is what
    // the debugger's SP field holds and what becomes the audience.
    log.debug("Leaving applicationId(). A SAML 1.1 relying party id.");
    return "https://" + SLUG + ".sp.example.com/saml11";
  }
  log.debug("Leaving applicationId(). A WS-Federation wtrealm.");
  return "urn:fedmx:" + SLUG + ":rp";
}

const APPLICATION = applicationId();

// What the mock's application registry should be told this entry is FOR. It
// reads this nowhere — an application declared for SAML 2.0 alone is still
// issued an access token — so it records intent, and the test asserts it came
// back rather than that it did anything.
function applicationProtocols() {
  log.debug("Entering applicationProtocols().");
  if (APP_PROTOCOL === "oidc") {
    log.debug("Leaving applicationProtocols(). oauth2 + oidc.");
    return ["oauth2", "oidc"];
  }
  log.debug("Leaving applicationProtocols(). " + APP_PROTOCOL + ".");
  return [APP_PROTOCOL];
}

// ---------------------------------------------------------------------------
// WHAT REALM 1 CALLS ITSELF TO REALM 2.
//
// `federation_sp.js`'s `ourEntityId()` is ONE string used as the SAML
// `<Issuer>`, the WS-Federation `wtrealm` and the OAuth `client_id` fallback,
// and it is the assertion consumer service URL: four names for one thing, on
// purpose, so a partner has one value to be configured with. Two of the five
// protocols here override it —
//
//   oidc / oauth2  a client_id realm 2 issued us, which is what `fedClientId`
//                  is for and what the ID Token's `aud` is checked against.
//                  A URL would work and would be a lie about who issued it.
//   saml11         nothing in that protocol carries a requester identity, so
//                  the relying party is named with Shibboleth's `providerId`
//                  parameter on the inter-site transfer URL. It is the ACS URL
//                  anyway, so the audience realm 2 mints matches what realm 1
//                  calls itself — see readPartnerMetadata().
// ---------------------------------------------------------------------------
function partnerApplicationId(spBase) {
  log.debug("Entering partnerApplicationId().");
  if (FED_PROTOCOL === "oidc" || FED_PROTOCOL === "oauth2") {
    log.debug("Leaving partnerApplicationId(). A client_id at realm 2.");
    return "fedmx-" + SLUG + "-client";
  }
  log.debug("Leaving partnerApplicationId(). Realm 1's ACS URL.");
  return spBase + "/federation/acs/" + RELATIONSHIP;
}

// ---------------------------------------------------------------------------
// THE REALMS. A realm is defined at RUNTIME and lives in memory, so there is
// nowhere to declare one and every run has to make sure its own exist.
//
// FIFTY JOBS RACE HERE and the race is handled rather than locked against:
// read the list, create what is missing, and if the create is refused read the
// list AGAIN — a refusal because somebody else created it a millisecond ago is
// not a failure, and a `must()` here would turn the pool into a coin toss. What
// matters is that the realm exists, not who made it.
// ---------------------------------------------------------------------------
async function createRealms(stsBase) {
  log.debug("Entering createRealms().");
  const before = await adminGet(stsBase, "/realms");
  const known = (before.realms || []).map(function (one) { return one.id; });
  for (const id of [SP_REALM, IDP_REALM]) {
    if (known.indexOf(id) >= 0) {
      continue;
    }
    await tidy(stsBase, "/realms/create", { id: id, name: id },
               "creating the \"" + id + "\" trust realm");
  }
  const after = await adminGet(stsBase, "/realms");
  const ids = (after.realms || []).map(function (one) { return one.id; });
  assert.ok(ids.indexOf(SP_REALM) >= 0 && ids.indexOf(IDP_REALM) >= 0,
    "Both realms should be defined and the service lists: " + ids.join(", ") +
    ". A realm that was created and is not listed means the create answered " +
    "ok for something that did not happen — or that fifty jobs racing to " +
    "create the same two realms lost every one of them, which would be a " +
    "different bug in the same place.");
  // Two realms sharing a signing key would be two names for one identity
  // service, and every assertion below about WHICH realm issued something
  // would be unfalsifiable. The mock derives a `kid` from the key material, so
  // this is one comparison rather than a claim.
  const kids = (after.realms || []).filter(function (one) {
    return one.id === SP_REALM || one.id === IDP_REALM;
  }).map(function (one) { return one.kid; });
  assert.strictEqual(new Set(kids).size, 2,
    "The two realms publish the same kid (" + kids.join(", ") + "), so they " +
    "are signing with one key and nothing below could tell their artifacts " +
    "apart.");
  log.info("Realms " + SP_REALM + " and " + IDP_REALM + " are defined, with " +
           "signing keys of their own.");
  log.debug("Leaving createRealms().");
}

// ---------------------------------------------------------------------------
// THE ONE REALM SETTING THIS FILE CHANGES, and only on the twenty points that
// cannot work without it.
//
// An OIDC or OAuth 2.0 federation is the only one of the five with a BACK
// CHANNEL: realm 1 redeems the code at realm 2's token endpoint, which is
// `federation_http.js`, which is `https` only and refuses a certificate
// nothing trusts unless `federation.outboundAllowInsecure` says otherwise.
// Every stack in this suite runs the mock on a self-signed certificate it
// regenerates at every start, so without this the twenty points fail with a
// 502 naming TLS — a failure that reads as the partner being down.
//
// IT IS NOT PUT BACK, and that is the deliberate half. Fifty jobs setting one
// realm-scoped setting and resetting it around each other is a flake that
// appears only in the pool: a point that reset it while another was mid-redeem
// would fail that one for a reason nothing in its output could name. The realm
// belongs entirely to this file, nothing else reads that setting there, and it
// is left on.
// ---------------------------------------------------------------------------
async function allowInsecureOutbound(spBase) {
  log.debug("Entering allowInsecureOutbound().");
  if (FED_PROTOCOL !== "oidc" && FED_PROTOCOL !== "oauth2") {
    log.debug("Leaving allowInsecureOutbound(). No back channel is used.");
    return;
  }
  await must(spBase, "/config/set",
             { key: "federation.outboundAllowInsecure", value: "true" },
             "allowing realm 1 to dial realm 2 over its own self-signed TLS");
  // WHICH REALM THE WRITE LANDED IN, which is the half worth asserting. A
  // setting written while a realm is ambient goes into that realm's own
  // override map, and one written WITHOUT one lands process-wide — where it
  // would relax the certificate check for every other job on this mock. The
  // snapshot answers both questions at once: `realm` says which realm was
  // ambient for the read, and `realmSettings` is that realm's own override
  // list.
  const snapshot = await adminGet(spBase, "/config");
  assert.strictEqual(String(snapshot.realm), SP_REALM,
    "Reading realm 1's configuration answered for the \"" + snapshot.realm +
    "\" realm, so the write above did not land where this test thinks it " +
    "did either.");
  assert.ok((snapshot.realmSettings || [])
              .indexOf("federation.outboundAllowInsecure") >= 0,
    "Realm 1 does not list federation.outboundAllowInsecure among its OWN " +
    "settings (it lists: " + (snapshot.realmSettings || []).join(", ") +
    "), so the write went process-wide — which is not this test's to do, and " +
    "would relax the certificate check for every other job on this mock. A " +
    FED_PROTOCOL + " federation redeems a code at the partner's token " +
    "endpoint over the mock's own self-signed TLS, so without it every point " +
    "of this row fails with a 502 naming a certificate rather than this " +
    "setting.");
  log.info("Realm 1 may dial realm 2's back channel.");
  log.debug("Leaving allowInsecureOutbound().");
}

// ---------------------------------------------------------------------------
// THE APPLICATION, IN REALM 1, BEFORE IT EVER CONNECTS.
//
// Deleted first and created again, so that the counters this test reads
// afterwards start at zero: a re-run against a container somebody has already
// driven would otherwise assert on an earlier run's arithmetic.
//
// The fields differ per protocol because the registry's identifier attribute
// does — `oauthClientId`, `samlEntityId`, `wsfedRealm` — and getting that wrong
// produces an entry that exists, looks right on the console, and is found by
// nothing.
// ---------------------------------------------------------------------------
function applicationFields(callbackUri) {
  log.debug("Entering applicationFields().");
  const tie = {
    // THE TIE, and both halves are set explicitly even though the
    // auto-redirect defaults to TRUE once a relationship is named: a default
    // is a fact about the mock's version rather than about this
    // configuration, and the last section of this test reads the attribute
    // back before clearing it.
    appFederationRelationship: RELATIONSHIP,
    appFederationAutoRedirect: "TRUE"
  };
  if (APP_PROTOCOL === "oidc" || APP_PROTOCOL === "oauth2") {
    log.debug("Leaving applicationFields(). OAuth.");
    return Object.assign({
      oauthClientId: APPLICATION,
      oauthRedirectUri: [callbackUri]
    }, tie);
  }
  if (APP_PROTOCOL === "saml2" || APP_PROTOCOL === "saml11") {
    log.debug("Leaving applicationFields(). SAML.");
    return Object.assign({
      samlEntityId: APPLICATION,
      // RECORDED AND NOT CHECKED by the mock, which is why it is not read
      // back below as though it decided anything. It is here so the console
      // shows a complete entry for the application this test is standing in
      // for.
      samlAssertionConsumerService: [baseUrl + "/saml"]
    }, tie);
  }
  log.debug("Leaving applicationFields(). WS-Federation.");
  return Object.assign({
    wsfedRealm: APPLICATION,
    wsfedReplyUrl: [baseUrl + "/wsfed"]
  }, tie);
}

async function registerApplication(spBase, callbackUri) {
  log.debug("Entering registerApplication().");
  await tidy(spBase, "/applications/forget", { application: APPLICATION },
             "removing the application left behind by an earlier run");
  await must(spBase, "/applications/create", {
    identifier: APPLICATION,
    name: "federation matrix — " + SLUG,
    protocols: applicationProtocols(),
    fields: applicationFields(callbackUri)
  }, "creating the " + APPLICATION + " application in " + SP_REALM);

  // Read back through the API rather than trusting the create's own answer:
  // the reply is the service's account of what it did, and the ENTRY is what
  // every endpoint will actually read. The single-application reply is FLAT —
  // `found`, `identifier`, `fields`, `authentications` at the top level —
  // rather than wrapping the entry in an `application` member the way the
  // actions do.
  const entry = await adminGet(spBase,
    "/applications?application=" + encodeURIComponent(APPLICATION));
  assert.ok(entry.found, "The application " + APPLICATION + " is not in " +
            SP_REALM + "'s registry after being created there.");
  const fields = entry.fields || {};
  // `[].concat(...)`, NOT a strict comparison. `appFederationRelationship` is
  // a MULTI-valued attribute in the mock's schema — an application may name
  // several partners, which is home realm discovery with a button per partner
  // — so the registry answers with an array whenever more than one value has
  // ever been written and with a bare string otherwise. Both spellings mean
  // the same thing, and a `strictEqual` against the string fails on the array
  // with a message that shows the two as IDENTICAL, because string
  // concatenation renders a one-element array as its element. That message
  // cost an hour here; it is worth the two extra characters.
  const named = [].concat(fields.appFederationRelationship || []);
  assert.ok(named.indexOf(RELATIONSHIP) >= 0,
    "The application entry should name the federation relationship \"" +
    RELATIONSHIP + "\" and names " + JSON.stringify(named) + ". Nothing " +
    "else ties this application to a partner, so a sign-in would reach realm " +
    "1's own password box and every assertion below would be about that " +
    "instead.");
  assert.strictEqual(Number(entry.authentications || 0), 0,
    "The application has " + entry.authentications + " authentication(s) " +
    "recorded before this test has signed anybody in, so the counters below " +
    "are somebody else's.");
  log.info("Realm 1 knows " + APPLICATION + " as a " + LABELS[APP_PROTOCOL] +
           " application that federates to \"" + RELATIONSHIP + "\".");
  log.debug("Leaving registerApplication().");
  return entry;
}

// ---------------------------------------------------------------------------
// WHAT REALM 2 PUBLISHES, READ FROM REALM 2.
//
// Every value realm 1 is configured with comes out of the identity provider's
// own document rather than being written down here. Two reasons and the second
// is the one that matters: they are what they are, and fetching the document
// proves that realm is up and answering AS ITSELF before anything is
// configured against it.
//
// The SAML documents are asked for BY THE NAME REALM 1 WILL USE, because the
// mock mints per-service-provider metadata (`saml2.perApplicationEntityId`) —
// so a document fetched without that name carries a DIFFERENT entityID from
// the one assertions will actually arrive with, and `fedPeer` is checked
// against the Issuer, so the flow would be refused with "it was issued by
// somebody else".
// ---------------------------------------------------------------------------
async function fetchText(url, what) {
  log.debug("Entering fetchText(). " + url);
  const response = await fetch(url);
  const text = await response.text();
  assert.strictEqual(response.status, 200,
    "Realm 2 answered " + response.status + " for " + what + " at " + url +
    ". It begins: " + text.slice(0, 300));
  log.debug("Leaving fetchText(). " + text.length + " characters.");
  return text;
}

async function readSaml2Metadata(idpBase, partnerAppId) {
  log.debug("Entering readSaml2Metadata().");
  const url = idpBase + "/saml2/metadata/" + encodeURIComponent(partnerAppId);
  const xml = await fetchText(url, "its own SAML 2.0 metadata");
  const entityId = (xml.match(/entityID="([^"]+)"/) || [])[1] || "";
  const certificate = (xml.match(/<[^>]*X509Certificate>([^<]+)</) || [])[1] ||
                      "";
  const sso = (xml.match(
    /SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"[^>]*Location="([^"]+)"/
  ) || [])[1] || "";
  assert.ok(entityId && certificate && sso,
    "Realm 2's SAML 2.0 metadata is missing one of the three things a " +
    "service provider is configured from — entityID=\"" + entityId +
    "\", certificate=" +
    (certificate ? certificate.length + " characters" : "(none)") +
    ", HTTP-Redirect SSO=\"" + sso + "\". The document begins: " +
    xml.slice(0, 300));
  log.debug("Leaving readSaml2Metadata().");
  return { entityId: entityId, certificate: certificate, sso: sso };
}

async function readSaml11Metadata(idpBase, partnerAppId) {
  log.debug("Entering readSaml11Metadata().");
  const url = idpBase + "/saml11/metadata/" + encodeURIComponent(partnerAppId);
  const xml = await fetchText(url, "its own SAML 1.1 metadata");
  const entityId = (xml.match(/entityID="([^"]+)"/) || [])[1] || "";
  const certificate = (xml.match(/<[^>]*X509Certificate>([^<]+)</) || [])[1] ||
                      "";
  // The 1.1 descriptor is a SAML 2.0 metadata document (there is no metadata
  // specification for 1.1 — see saml11_sso.js's decision 5), and its
  // SingleSignOnService entries are named by the 1.1 PROFILE URIs. The
  // Browser/POST one is the inter-site transfer service.
  const sso = (xml.match(
    /SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:1\.0:profiles:browser-post"[^>]*Location="([^"]+)"/
  ) || [])[1] || (xml.match(
    /SingleSignOnService[^>]*Location="([^"]*\/saml11\/sso[^"]*)"/
  ) || [])[1] || "";
  assert.ok(entityId && certificate && sso,
    "Realm 2's SAML 1.1 metadata is missing one of the three things a " +
    "relying party is configured from — entityID=\"" + entityId +
    "\", certificate=" +
    (certificate ? certificate.length + " characters" : "(none)") +
    ", inter-site transfer service=\"" + sso + "\". The document begins: " +
    xml.slice(0, 300));
  log.debug("Leaving readSaml11Metadata().");
  return { entityId: entityId, certificate: certificate, sso: sso };
}

// The WS-Federation metadata is at AD FS's own path, because that is where
// every relying party in this ecosystem looks and the specification names no
// path at all. The entityID here is ALSO what the assertion's issuer says, and
// that is not obvious: the mock wraps a SAML **1.1** assertion in the RSTR by
// default, and a SAML 1.1 assertion carries its issuer in an `Issuer`
// ATTRIBUTE rather than an `<Issuer>` element — so `fedPeer` is compared
// against this string and anything else refuses every token.
async function readWsFedMetadata(idpBase) {
  log.debug("Entering readWsFedMetadata().");
  const url = idpBase + "/FederationMetadata/2007-06/FederationMetadata.xml";
  const xml = await fetchText(url, "its own WS-Federation metadata");
  const entityId = (xml.match(/entityID="([^"]+)"/) || [])[1] || "";
  const certificate = (xml.match(/<[^>]*X509Certificate>([^<]+)</) || [])[1] ||
                      "";
  const passive = (xml.match(
    /<[^>]*Address>([^<]*\/wsfed)<\/[^>]*Address>/) || [])[1] || "";
  assert.ok(entityId && certificate && passive,
    "Realm 2's WS-Federation metadata is missing one of the three things a " +
    "service provider is configured from — entityID=\"" + entityId +
    "\", certificate=" +
    (certificate ? certificate.length + " characters" : "(none)") +
    ", PassiveRequestorEndpoint=\"" + passive + "\". The document begins: " +
    xml.slice(0, 300));
  log.debug("Leaving readWsFedMetadata().");
  return { entityId: entityId, certificate: certificate, sso: passive };
}

async function readOidcMetadata(idpBase) {
  log.debug("Entering readOidcMetadata().");
  const url = idpBase + "/.well-known/openid-configuration";
  const text = await fetchText(url, "its own discovery document");
  const document = JSON.parse(text);
  assert.strictEqual(document.issuer, idpBase,
    "Realm 2 publishes issuer \"" + document.issuer + "\" rather than \"" +
    idpBase + "\". The mock derives an issuer from the base URL a request " +
    "arrived on, and a realm's base URL carries its prefix — a process-wide " +
    "STS_OAUTH2_ISSUER pin would override both realms with one name, and " +
    "then \"which realm issued this\" has no answer and `fedPeer` below " +
    "cannot mean anything.");
  assert.ok(document.authorization_endpoint && document.token_endpoint &&
            document.jwks_uri,
    "Realm 2's discovery document is missing one of the three endpoints an " +
    "OAuth federation is configured from: " + JSON.stringify(document));
  log.debug("Leaving readOidcMetadata().");
  return {
    entityId: document.issuer,
    certificate: "",
    sso: document.authorization_endpoint,
    tokenUrl: document.token_endpoint,
    jwksUri: document.jwks_uri,
    userinfoUrl: document.userinfo_endpoint || (idpBase + "/oauth2/userinfo")
  };
}

// ---------------------------------------------------------------------------
// WHAT REALM 1 STAMPS ON WHAT IT ISSUES TO THIS APPLICATION.
//
// Needed because "was this issued by realm 1" is not one question across the
// five protocols and cannot be asked by looking for realm 1's base URL. An
// OAuth issuer IS that base URL; a SAML 2.0 <Issuer> is an entityID the mock
// mints per service provider from it; and a SAML **1.1** issuer is neither —
// `saml11.providerId` defaults to the URN `urn:sts-mock:idp:saml11`, which
// carries no realm and no host at all, so a check for `spBase` inside a 1.1
// assertion looks for something that is not there and never was. The
// WS-Federation token is a SAML 1.1 assertion by default and inherits that.
//
// So it is READ from the document realm 1 publishes for this application, the
// same way the partner's is read from realm 2's. The alternative — writing the
// three shapes down here — is a second copy of `providerIdFor()` that agrees
// with the mock until somebody changes a setting.
// ---------------------------------------------------------------------------
async function readLocalIssuer(spBase) {
  log.debug("Entering readLocalIssuer(). " + APP_PROTOCOL);
  if (APP_PROTOCOL === "oidc" || APP_PROTOCOL === "oauth2") {
    log.debug("Leaving readLocalIssuer(). The realm's own base URL.");
    return spBase;
  }
  let url = spBase + "/FederationMetadata/2007-06/FederationMetadata.xml";
  if (APP_PROTOCOL === "saml2") {
    url = spBase + "/saml2/metadata/" + encodeURIComponent(APPLICATION);
  } else if (APP_PROTOCOL === "saml11") {
    url = spBase + "/saml11/metadata/" + encodeURIComponent(APPLICATION);
  }
  const xml = await fetchText(url, "its own " + LABELS[APP_PROTOCOL] +
                                   " metadata for " + APPLICATION);
  const entityId = (xml.match(/entityID="([^"]+)"/) || [])[1] || "";
  assert.ok(entityId,
    "Realm 1 publishes no entityID in the " + LABELS[APP_PROTOCOL] +
    " metadata it offers " + APPLICATION + " at " + url + ", so there is " +
    "nothing to check the artifact's issuer against. The document begins: " +
    xml.slice(0, 300));
  log.info("Realm 1 issues to this application as " + entityId + ".");
  log.debug("Leaving readLocalIssuer().");
  return entityId;
}

async function readPartnerMetadata(idpBase, partnerAppId) {
  log.debug("Entering readPartnerMetadata(). protocol=" + FED_PROTOCOL);
  let partner = null;
  if (FED_PROTOCOL === "saml2") {
    partner = await readSaml2Metadata(idpBase, partnerAppId);
  } else if (FED_PROTOCOL === "saml11") {
    partner = await readSaml11Metadata(idpBase, partnerAppId);
  } else if (FED_PROTOCOL === "wsfed") {
    partner = await readWsFedMetadata(idpBase);
  } else {
    partner = await readOidcMetadata(idpBase);
  }
  // Whatever the protocol, the address realm 1 is about to be pointed at must
  // be inside realm 2 — otherwise the sign-in leaves for a different identity
  // service from the one this test configured, and the failure appears three
  // hops later as a signature that does not verify.
  assert.ok(String(partner.sso).indexOf("/realm/" + IDP_REALM + "/") >= 0,
    "Realm 2 advertises \"" + partner.sso + "\" as where a " + FED_PROTOCOL +
    " sign-in begins, which is outside its own realm prefix.");
  log.info("Realm 2 is a " + LABELS[FED_PROTOCOL] + " identity provider as " +
           partner.entityId + ", reached at " + partner.sso + ".");
  log.debug("Leaving readPartnerMetadata().");
  return partner;
}

// ---------------------------------------------------------------------------
// THE SERVICE-PROVIDER-SIDE RELATIONSHIP, IN REALM 1, POINTING AT REALM 2.
//
// Deleted and re-created for the reason the application is:
// `fedAuthentications`
// is asserted to be EXACTLY ONE below, and a relationship left over from an
// earlier run carries that run's count.
//
// The order is the feature's own: create — which forces it DISABLED whatever
// the request says — fill in, then enable as a second deliberate act. The
// disabled-on-create rule is asserted rather than skipped past, because it is
// the one place this register overrides its input and the whole posture of the
// feature: a partner that half-exists and silently accepts assertions is the
// failure the register is arranged to prevent.
// ---------------------------------------------------------------------------
function serviceProviderFields(partner, partnerAppId, callbackUri) {
  log.debug("Entering serviceProviderFields().");
  if (FED_PROTOCOL === "saml2") {
    log.debug("Leaving serviceProviderFields(). SAML 2.0.");
    return [["fedSsoUrl", partner.sso],
            ["fedSigningCertificate", partner.certificate],
            ["fedPeer", partner.entityId]];
  }
  if (FED_PROTOCOL === "saml11") {
    // The relying party is named with Shibboleth's `providerId` parameter,
    // because SAML 1.1 has NO REQUEST MESSAGE for realm 1 to identify itself
    // in. `federation_sp.js` appends `&TARGET=...` to whatever is configured
    // here — it checks for an existing `?` — so a query string is the place
    // for it, and it is what realm 2's identity-provider-side relationship is
    // then found by.
    log.debug("Leaving serviceProviderFields(). SAML 1.1.");
    return [["fedSsoUrl", partner.sso + "?providerId=" +
                          encodeURIComponent(partnerAppId)],
            ["fedSigningCertificate", partner.certificate],
            ["fedPeer", partner.entityId]];
  }
  if (FED_PROTOCOL === "wsfed") {
    log.debug("Leaving serviceProviderFields(). WS-Federation.");
    return [["fedSsoUrl", partner.sso],
            ["fedSigningCertificate", partner.certificate],
            ["fedPeer", partner.entityId]];
  }
  // OIDC and OAuth 2.0. `fedTokenUrl` and `fedJwksUri` are the two URLs realm
  // 1 will actually DIAL, and `fedUserinfoUrl` is a third that only the plain
  // OAuth 2.0 path uses — and only when the access token is not a readable
  // JWT. It is configured on both so that neither shape of access token turns
  // this into "there is no way to learn who this is", which is a 500 that
  // names the relationship rather than the token.
  const fields = [["fedSsoUrl", partner.sso],
                  ["fedTokenUrl", partner.tokenUrl],
                  ["fedJwksUri", partner.jwksUri],
                  ["fedUserinfoUrl", partner.userinfoUrl],
                  ["fedClientId", partnerAppId],
                  ["fedPeer", partner.entityId]];
  if (FED_PROTOCOL === "oidc") {
    fields.push(["fedScope", "openid profile email"]);
  }
  log.debug("Leaving serviceProviderFields(). " + FED_PROTOCOL + ".");
  return fields;
}

async function createRelationship(spBase, partner, partnerAppId, callbackUri) {
  log.debug("Entering createRelationship().");
  await tidy(spBase, "/federation/delete", { id: RELATIONSHIP },
             "removing the relationship left behind by an earlier run");
  const created = await must(spBase, "/federation/create", {
    id: RELATIONSHIP,
    role: "service-provider",
    protocol: FED_PROTOCOL,
    name: IDP_REALM + " over " + LABELS[FED_PROTOCOL],
    // CHECKED on the way in: an artifact whose issuer is not this string is
    // refused even when the signature verifies.
    peer: partner.entityId
  }, "registering the " + LABELS[FED_PROTOCOL] + " relationship with realm 2");

  // The reply carries the raw entry, so this asserts the ATTRIBUTE's own
  // spelling (`fedEnabled` holds the string "FALSE") rather than a boolean the
  // view layer derived. Asserting the attribute is the stronger of the two: it
  // is what every endpoint downstream actually reads.
  assert.strictEqual(String(created.relationship.fedEnabled), "FALSE",
    "A federation relationship must be created DISABLED whatever the request " +
    "said, and " + RELATIONSHIP + " came back with fedEnabled=" +
    created.relationship.fedEnabled + ".");
  // What a relationship of THIS protocol needs before it can be enabled, taken
  // from the mock's own readiness report rather than written down here. The
  // SAML family needs a certificate and the OAuth family needs a client_id,
  // and a relationship that is 'ready' with neither is the assertion this test
  // most needs to be able to make.
  const missing = created.readiness.missing || [];
  assert.ok(missing.length > 0,
    "A " + FED_PROTOCOL + " service-provider-side relationship with nothing " +
    "configured reports nothing missing, so it could be enabled while " +
    "pointing at nobody. The gate on this surface is the whole feature.");
  log.info("A new " + FED_PROTOCOL + " relationship is disabled and needs: " +
           missing.join(", ") + ".");

  for (const [field, value] of serviceProviderFields(partner, partnerAppId,
                                                     callbackUri)) {
    await must(spBase, "/federation/set",
               { id: RELATIONSHIP, field: field, value: value },
               "setting " + field + " on " + RELATIONSHIP);
  }
  const enabled = await must(spBase, "/federation/enable",
                             { id: RELATIONSHIP },
                             "enabling " + RELATIONSHIP);
  assert.ok(enabled.readiness.ready,
    "The relationship " + RELATIONSHIP + " is enabled and not ready: " +
    (enabled.readiness.missing || []).join(", ") + " still to configure. " +
    "Every federated endpoint would refuse rather than half-work.");
  log.info("Realm 1 will federate " + APPLICATION + " to realm 2 over " +
           LABELS[FED_PROTOCOL] + ".");
  log.debug("Leaving createRelationship().");
  return created;
}

// ---------------------------------------------------------------------------
// REALM 2'S SIDE: an application entry for realm 1, and an
// IDENTITY-PROVIDER-side relationship pointing at it that carries the
// MECHANISM.
//
// THE APPLICATION ENTRY IS NOT DECORATION. An identity-provider-side
// relationship stores a POINTER to `ou=applications` and nothing else about the
// partner, and it is by matching that pointer against the identifier the
// arriving request presented — an `<Issuer>`, a `wtrealm`, a `providerId`, a
// `client_id` — that the sign-in finds this relationship at all. Get it wrong
// and realm 2 draws its ordinary password box: the flow still completes, and
// the MECHANISM this point exists to exercise was never applied. That is why
// `fedAuthnMechanism` is read back off the entry below, and why the WebAuthn
// points assert they reached the ceremony rather than assuming it.
// ---------------------------------------------------------------------------
function partnerFields(spBase) {
  log.debug("Entering partnerFields().");
  const acs = spBase + "/federation/acs/" + RELATIONSHIP;
  if (FED_PROTOCOL === "oidc" || FED_PROTOCOL === "oauth2") {
    log.debug("Leaving partnerFields(). An OAuth client.");
    return { oauthClientId: partnerApplicationId(spBase),
             oauthRedirectUri: [acs] };
  }
  if (FED_PROTOCOL === "saml2" || FED_PROTOCOL === "saml11") {
    log.debug("Leaving partnerFields(). A SAML relying party.");
    return { samlEntityId: partnerApplicationId(spBase),
             samlAssertionConsumerService: [acs] };
  }
  log.debug("Leaving partnerFields(). A WS-Federation relying party.");
  return { wsfedRealm: partnerApplicationId(spBase), wsfedReplyUrl: [acs] };
}

async function registerPartnerAtIdp(idpBase, spBase, partnerAppId) {
  log.debug("Entering registerPartnerAtIdp().");
  await tidy(idpBase, "/applications/forget", { application: partnerAppId },
             "removing realm 1's entry from an earlier run");
  await must(idpBase, "/applications/create", {
    identifier: partnerAppId,
    name: SP_REALM + " (" + LABELS[FED_PROTOCOL] + " partner)",
    protocols: [FED_PROTOCOL],
    fields: partnerFields(spBase)
  }, "registering realm 1 as a " + LABELS[FED_PROTOCOL] + " partner in " +
     IDP_REALM);
  log.debug("Leaving registerPartnerAtIdp().");
}

async function createIdpRelationship(idpBase, partnerAppId) {
  log.debug("Entering createIdpRelationship().");
  await tidy(idpBase, "/federation/delete", { id: IDP_RELATIONSHIP },
             "removing realm 2's relationship from an earlier run");
  const created = await must(idpBase, "/federation/create", {
    id: IDP_RELATIONSHIP,
    role: "identity-provider",
    protocol: FED_PROTOCOL,
    name: SP_REALM,
    peer: partnerAppId,
    application: partnerAppId
  }, "registering realm 2's identity-provider-side relationship with realm 1");
  assert.strictEqual(String(created.relationship.fedEnabled), "FALSE",
    "The identity-provider-side relationship must be created DISABLED too, " +
    "and it came back with fedEnabled=" + created.relationship.fedEnabled +
    ". Nothing about the direction changes that rule.");

  await must(idpBase, "/federation/set",
             { id: IDP_RELATIONSHIP, field: "fedAuthnMechanism",
               value: MECHANISM },
             "setting the authentication mechanism to " + MECHANISM);
  const enabled = await must(idpBase, "/federation/enable",
                             { id: IDP_RELATIONSHIP },
                             "enabling " + IDP_RELATIONSHIP);
  assert.ok(enabled.readiness.ready,
    "Realm 2's relationship is enabled and not ready: " +
    (enabled.readiness.missing || []).join(", ") + " still to configure.");

  // Read it back off the ENTRY, because the entry is what the sign-in path
  // reads and the reply is only what the action said it did.
  const view = await adminGet(idpBase,
    "/federation?relationship=" + encodeURIComponent(IDP_RELATIONSHIP));
  const fields = view.fields || {};
  assert.strictEqual(fields.fedAuthnMechanism, MECHANISM,
    "Realm 2's relationship says fedAuthnMechanism=\"" +
    fields.fedAuthnMechanism + "\" and should say \"" + MECHANISM + "\". An " +
    "EMPTY value is not `password` — it means the relationship says nothing " +
    "and falls through to the screen, which is exactly the silent fallback " +
    "this point exists to distinguish from a working one.");
  assert.strictEqual(String(view.application), partnerAppId,
    "Realm 2's relationship points at the application \"" + view.application +
    "\" and must point at \"" + partnerAppId + "\" — the identifier realm 1 " +
    "presents over " + LABELS[FED_PROTOCOL] + ". That pointer is the ONLY " +
    "thing connecting an arriving request to this relationship, so a sign-in " +
    "would never find it and would get an ordinary password box instead.");
  log.info("Realm 2 will authenticate realm 1's people by \"" + MECHANISM +
           "\".");
  log.debug("Leaving createIdpRelationship().");
  return view;
}

// The relationship as it now stands. Read fresh every time it is asserted on,
// because the interesting values (the counters, the last error) are written by
// the flow rather than by this test.
async function relationshipNow(base, id) {
  log.debug("Entering relationshipNow(). id=" + id);
  const view = await adminGet(base,
    "/federation?relationship=" + encodeURIComponent(id));
  assert.ok(view.found,
    "The relationship \"" + id + "\" is no longer registered at " + base + ".");
  log.debug("Leaving relationshipNow().");
  return view;
}

// ===========================================================================
// THE BROWSER HALF.
// ===========================================================================

// NB: the JS bindings' setters return undefined, unlike the Java ones, so these
// cannot be chained — and the failure is not "no authenticator" but a
// NotAllowedError blaming TLS certificates.
function authenticatorOptions() {
  log.debug("Entering authenticatorOptions().");
  const vo = new VirtualAuthenticatorOptions();
  vo.setProtocol(Protocol.CTAP2);
  vo.setTransport(Transport.USB);
  vo.setHasResidentKey(true);
  vo.setIsUserConsenting(true);
  vo.setHasUserVerification(true);
  vo.setIsUserVerified(true);
  log.debug("Leaving authenticatorOptions().");
  return vo;
}

async function elementExists(driver, id) {
  log.debug("Entering elementExists(). " + id);
  const found = await driver.findElements(By.id(id));
  log.debug("Leaving elementExists(). " + found.length);
  return found.length > 0;
}

async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  const element = await driver.findElement(By.id(id));
  await driver.executeScript(
    "arguments[0].value = arguments[1];" +
    "arguments[0].dispatchEvent(new Event('input', { bubbles: true }));" +
    "arguments[0].dispatchEvent(new Event('change', { bubbles: true }));",
    element, value);
  log.debug("Leaving setField().");
}

// A button located by its `value`, which is how nearly every control on the
// SAML and WS-Federation pages is identified. Clicked THROUGH THE PAGE rather
// than natively: a native click on a control low on a tall page fires nothing
// at all under pool load, and the failure is silence rather than an error.
async function clickByValue(driver, value) {
  log.debug("Entering clickByValue(). " + value);
  const found = await driver.findElements(
    By.xpath("//input[@value=\"" + value + "\"] | //button[@value=\"" +
             value + "\"]"));
  assert.ok(found.length,
    "There is no control on this page with the value \"" + value + "\".");
  await driver.executeScript(
    "arguments[0].scrollIntoView({block: 'center'}); arguments[0].click();",
    found[0]);
  log.debug("Leaving clickByValue().");
}

// WHERE THE BROWSER ACTUALLY IS, for the waits that can time out mid-flow.
//
// A federated sign-in is six or seven navigations, and a timeout naming only
// the destination it never reached says nothing about which hop stopped. Every
// hop here renders a page that SAYS what it refused — `federation_sp.js`'s
// refusals, the mock's error pages, the debugger's status fields — so the URL
// and the first of the text is usually the whole diagnosis.
async function whereAreWe(driver) {
  log.debug("Entering whereAreWe().");
  let url = "(unknown)";
  let text = "(unreadable)";
  try {
    url = await driver.getCurrentUrl();
    text = await driver.findElement(By.css("body")).getText();
  } catch (e) {
    // Best effort by definition: this runs while something has already gone
    // wrong, and a browser that will not answer must not replace the original
    // failure with one about this function.
    text = "(the page could not be read: " + e.message + ")";
  }
  log.debug("Leaving whereAreWe(). " + url);
  return "The browser is at " + url + " and the page says: " +
         String(text).replace(/\s+/g, " ").slice(0, 800);
}

async function waitForValue(driver, locator, predicate, message, timeout) {
  log.debug("Entering waitForValue().");
  await driver.wait(async function () {
    const found = await driver.findElements(locator);
    if (!found.length) {
      return false;
    }
    const value = await found[0].getAttribute("value");
    return !!value && predicate(value);
  }, timeout || waitTime * 6, message);
  log.debug("Leaving waitForValue().");
}

// ---------------------------------------------------------------------------
// THE APPLICATION TIER, one function per protocol, each stopping at the same
// place: the sign-in request has been sent and the browser is somewhere it did
// not choose.
//
// Every one of them reads what the page is ABOUT TO SEND rather than the hidden
// fields it holds, because a page that displays one thing and sends another is
// exactly the bug a test reading the fields would pass through.
// ---------------------------------------------------------------------------
async function driveOauthTier(driver, spBase, callbackUri) {
  log.debug("Entering driveOauthTier().");
  await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                 "authorization_grant_type", { timeout: waitTime * 5 });
  // A previous job's state in localStorage would otherwise decide which panes
  // oauth2_oidc_2.html draws, which is what the tokens are read out of.
  await driver.executeScript("window.localStorage.clear();");
  await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                 "authorization_grant_type", { timeout: waitTime * 5 });
  // Nearly every control on these pages is an inline handler naming a
  // browserify --standalone global, so a click before the bundle has run is a
  // silent no-op rather than an error.
  await waitForPageBundle(driver);

  // Realm 1's discovery document — which is what makes it an ordinary identity
  // provider to this application. Nothing in it mentions federation, and that
  // is the point rather than an omission.
  await populateMetadata(driver, spBase + "/.well-known/openid-configuration");

  const grant = By.id("authorization_grant_type");
  await driver.wait(until.elementLocated(grant), waitTime);
  // The Configuration Parameters pane is COLLAPSED once discovery has run, so
  // on any visit after the first the dropdown is present and invisible and
  // selecting from it is "element not interactable".
  if (!(await driver.findElement(grant).isDisplayed())) {
    await driver.findElement(By.id("config_expand_button")).click();
    await driver.wait(until.elementIsVisible(driver.findElement(grant)),
                      waitTime);
  }
  await new Select(await driver.findElement(grant)).selectByVisibleText(
    APP_PROTOCOL === "oidc" ? "OIDC Authorization Code Flow(code)"
                            : "OAuth2 Authorization Code Grant");

  const clientId = By.id("client_id");
  await driver.wait(until.elementLocated(clientId), waitTime);
  if (!(await driver.findElement(clientId).isDisplayed())) {
    await driver.findElement(By.id("authz_expand_button")).click();
  }
  await driver.wait(until.elementIsVisible(driver.findElement(clientId)),
                    waitTime);

  await driver.findElement(clientId).clear();
  await driver.findElement(clientId).sendKeys(APPLICATION);
  await driver.findElement(By.id("scope")).clear();
  await driver.findElement(By.id("scope")).sendKeys(
    APP_PROTOCOL === "oidc" ? "openid profile email" : "profile email");
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

  // The preview is a whole request — `GET <url>?` and then one parameter per
  // line — so this looks for the endpoint inside it rather than at the front.
  assert.ok(preview.indexOf(spBase + "/oauth2/authorize") >= 0,
    "The page is about to send the authorization request to something other " +
    "than realm 1's authorization endpoint (" + spBase + "/oauth2/authorize" +
    "). It reads:\n" + preview);
  assert.ok(preview.indexOf("client_id=" + APPLICATION) >= 0,
    "The authorization request does not name " + APPLICATION + ", so nothing " +
    "downstream can look its federation relationship up. It reads:\n" +
    preview);
  log.info("The application will send: " + preview.split("\n")[0]);

  await driver.findElement(
    By.css("input[type=\"submit\"][value=\"Authorize\"]")).click();
  log.debug("Leaving driveOauthTier().");
  return { nonce: nonce, state: state };
}

async function driveSamlTier(driver, spBase) {
  log.debug("Entering driveSamlTier(). version=" + APP_PROTOCOL);
  const metadataUrl = spBase +
    (APP_PROTOCOL === "saml2" ? "/saml2/metadata/" : "/saml11/metadata/") +
    encodeURIComponent(APPLICATION);

  await loadPage(driver, baseUrl + "/saml_request.html", "saml_metadata_url",
                 { timeout: waitTime * 5 });
  await driver.executeScript("window.localStorage.clear();");
  await loadPage(driver, baseUrl + "/saml_request.html", "saml_metadata_url",
                 { timeout: waitTime * 5 });
  await waitForPageBundle(driver);

  await setField(driver, "saml_metadata_url", metadataUrl);
  await clickByValue(driver, "Load Metadata");
  await waitForValue(driver, By.id("saml_metadata_status"),
    function (v) { return v.indexOf("Loaded and parsed") >= 0; },
    "Realm 1's " + LABELS[APP_PROTOCOL] + " metadata at " + metadataUrl +
    " was not loaded and parsed by the page.");

  // THE DESCRIPTOR DECIDES THE VERSION, and it is asserted rather than assumed
  // because everything after it depends on the page having noticed: a page
  // left on 2.0 in front of a 1.1 document builds an <AuthnRequest>, posts it
  // at an inter-site transfer service, and reports the refusal as though the
  // identity provider were at fault.
  const version = await driver.findElement(By.id("saml_version"))
    .getAttribute("value");
  assert.strictEqual(String(version),
                     APP_PROTOCOL === "saml2" ? "2.0" : "1.1",
    "The page is set to SAML " + version + " after loading realm 1's " +
    LABELS[APP_PROTOCOL] + " descriptor, so it will build the wrong kind of " +
    "request entirely.");

  await setField(driver, "saml_sp_entity_id", APPLICATION);
  // HTTP-Redirect for 2.0 and Browser/POST for 1.1 — in both cases the binding
  // that needs no api call of its own, because what this point is about is the
  // two hops behind realm 1 rather than the binding in front of it.
  await setField(driver, "saml_binding",
                 APP_PROTOCOL === "saml2" ? "redirect" : "post");

  // ---------------------------------------------------------------------
  // REQUEST SIGNING OFF, and it is not a shortcut — it is what stops this
  // point testing something else.
  //
  // The page ships with "Digitally sign the AuthnRequest" TICKED, and
  // `callIdp()` refuses to send at all when it is ticked with no SP key pair:
  // the status field says so and the browser never leaves the page, which
  // reads three steps later as an identity provider that drew no sign-in
  // screen. `saml_sso.js` answers that by loading a per-run key pair, because
  // the signature is part of what that test is about — it is not part of what
  // this one is about, realm 1 verifies no request signature, and generating
  // an RSA pair in the browser fifteen times over is seconds per point for
  // nothing. SAML 1.1 has no request to sign and skips this entirely.
  //
  // Clicked rather than assigned: the checkbox has an `onchange` that hides
  // the key-pair pane and rebuilds the request, and a value set without it
  // leaves the page displaying one thing and sending another.
  // ---------------------------------------------------------------------
  if (APP_PROTOCOL === "saml2" &&
      (await elementExists(driver, "saml_sign_request"))) {
    await driver.executeScript(
      "var b = document.getElementById('saml_sign_request');" +
      "if (b && b.checked) { b.click(); }");
    const stillSigning = await driver.findElement(By.id("saml_sign_request"))
      .isSelected();
    assert.ok(!stillSigning,
      "The AuthnRequest is still set to be signed and this point supplies no " +
      "key pair, so callIdp() will refuse to send and the browser will never " +
      "leave this page.");
  }

  await clickByValue(driver, "Call IdP");
  log.debug("Leaving driveSamlTier().");
  return {};
}

async function driveWsFedTier(driver, spBase) {
  log.debug("Entering driveWsFedTier().");
  await loadPage(driver, baseUrl + "/wsfed_request.html",
                 "wsfed_metadata_url", { timeout: waitTime * 5 });
  await driver.executeScript("window.localStorage.clear();");
  await loadPage(driver, baseUrl + "/wsfed_request.html",
                 "wsfed_metadata_url", { timeout: waitTime * 5 });
  await waitForPageBundle(driver);

  await setField(driver, "wsfed_metadata_url", spBase +
                 "/FederationMetadata/2007-06/FederationMetadata.xml");
  await setField(driver, "wsfed_signin_endpoint", spBase + "/wsfed");
  await setField(driver, "wsfed_realm", APPLICATION);
  // The page's default `wreply` is the deployment's own statement about where
  // its landing is, and the static response page is the one value that cannot
  // work — the identity provider POSTs the token, and a POST to a static
  // object is answered 403/405. Assert it here rather than letting the wait
  // below time out saying only that the response page never loaded.
  const reply = await driver.findElement(By.id("wsfed_reply"))
    .getAttribute("value");
  assert.ok(reply,
    "wsfed_reply (wreply) is empty, so realm 1 has nowhere to return the " +
    "token to.");
  assert.ok(!/\/wsfed_response\.html(\?|$)/.test(reply),
    "wreply defaults to the static response page (" + reply + "), which " +
    "cannot receive a POST. This job needs the api's /wsfed landing.");
  if (await elementExists(driver, "wsfed_sign_request")) {
    // Realm 1 verifies no request signature and this point is not about one.
    await driver.executeScript(
      "var b = document.getElementById('wsfed_sign_request');" +
      "if (b && b.checked) { b.click(); }");
  }

  await clickByValue(driver, "Call IdP (Sign In)");
  log.debug("Leaving driveWsFedTier().");
  return {};
}

async function driveApplicationTier(driver, spBase, callbackUri) {
  log.debug("Entering driveApplicationTier(). " + APP_PROTOCOL);
  let sent = null;
  if (APP_PROTOCOL === "oidc" || APP_PROTOCOL === "oauth2") {
    sent = await driveOauthTier(driver, spBase, callbackUri);
  } else if (APP_PROTOCOL === "wsfed") {
    sent = await driveWsFedTier(driver, spBase);
  } else {
    sent = await driveSamlTier(driver, spBase);
  }
  log.debug("Leaving driveApplicationTier().");
  return sent;
}

// ---------------------------------------------------------------------------
// THE SIGN-IN AT REALM 2, BY THE CONFIGURED MECHANISM.
//
// The screen is `authn.js`'s, whichever protocol asked for it and whichever
// realm is showing it — it reuses Keycloak's field ids, which is why every test
// in this suite drives it the same way. It checks no password, so the username
// typed here is the identity every artifact downstream describes.
//
// WHAT MAKES THIS THE ASSERTION AND NOT A STEP: a relationship whose
// `fedAuthnMechanism` never reached the screen produces the ORDINARY password
// box, and the flow then completes perfectly. So a WebAuthn point requires the
// ceremony page and a password point requires its absence, and each says why.
// ---------------------------------------------------------------------------
async function signInAtIdp(driver, user, idpBase) {
  log.debug("Entering signInAtIdp(). mechanism=" + MECHANISM);
  const username = By.id("username");
  try {
    await driver.wait(until.elementLocated(username), waitTime * 6);
    await driver.wait(until.elementIsVisible(driver.findElement(username)),
                      waitTime);
  } catch (e) {
    const url = await driver.getCurrentUrl();
    const body = await driver.findElement(By.css("body")).getText();
    throw new Error("No sign-in screen appeared after the " +
                    LABELS[APP_PROTOCOL] + " request was federated over " +
                    LABELS[FED_PROTOCOL] + ". The browser is at " + url +
                    " and the page says: " + body.slice(0, 600));
  }

  const screenUrl = await driver.getCurrentUrl();
  assert.ok(screenUrl.indexOf("/realm/" + IDP_REALM + "/") >= 0,
    "The person should have been sent to realm 2 to sign in, and the browser " +
    "is at " + screenUrl + ".");
  assert.ok(screenUrl.indexOf("/realm/" + SP_REALM + "/") === -1,
    "The browser is at one of realm 1's own URLs (" + screenUrl + "), so " +
    "realm 1 asked for the credential itself instead of federating. Nothing " +
    "below would notice: the flow completes either way.");
  log.info("Realm 1 sent the browser straight on to realm 2: " + screenUrl);

  // ---------------------------------------------------------------------
  // THE MECHANISM, READ OFF THE SCREEN rather than off the configuration that
  // asked for it.
  //
  // It is the `webauthn_only` box and NOT the absence of a password field:
  // the passwordless screen still draws one. That is deliberate over there and
  // it is exactly the trap worth pinning here — `handleLogin()` reads the
  // RECORD rather than the markup, so a password typed into that field is
  // ignored, and a test asserting the field was gone would fail on a service
  // that is working. What the mechanism actually does to the screen is tick
  // the box AND DISABLE IT, with a hidden input behind it, and say which
  // relationship required it.
  // ---------------------------------------------------------------------
  const passwordless = await driver.findElements(By.id("webauthn_only"));
  assert.ok(passwordless.length,
    "Realm 2's sign-in screen has no webauthn_only control at all, so it is " +
    "not the shared authentication screen and nothing below can tell which " +
    "mechanism ran.");
  const ticked = await passwordless[0].isSelected();
  const changeable = await passwordless[0].isEnabled();
  if (MECHANISM === "webauthn") {
    assert.ok(ticked,
      "Realm 2's relationship configures a PASSWORDLESS security key and the " +
      "screen's passwordless box is not ticked. The mechanism did not reach " +
      "the screen — which means this point is about to sign somebody in with " +
      "a password and would pass every assertion below.");
    assert.ok(!changeable,
      "The passwordless box is ticked and can still be UNTICKED, so the " +
      "mechanism is a suggestion rather than a configuration and a person " +
      "could sign in the other way.");
  } else {
    assert.ok(!ticked,
      "Realm 2's relationship configures a password sign-in and the screen " +
      "arrived with the passwordless box already ticked, so some other " +
      "mechanism is in force here.");
    assert.ok(changeable,
      "The passwordless box is not ticked and is disabled, so something is " +
      "forcing a mechanism this relationship did not configure.");
  }

  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  const passwordBoxes = await driver.findElements(By.id("password"));
  if (passwordBoxes.length) {
    // Typed on both paths, and ignored on both: this service checks no
    // password, and on the passwordless path `handleLogin()` never looks at
    // the field. Filling it in anyway keeps the two paths one code path here.
    await passwordBoxes[0].clear();
    await passwordBoxes[0].sendKeys("no password is checked here");
  }
  await driver.findElement(By.id("kc-login")).click();

  if (MECHANISM === "webauthn") {
    await runTheCeremony(driver, user);
  }
  log.debug("Leaving signInAtIdp().");
}

// ---------------------------------------------------------------------------
// THE WEBAUTHN CEREMONY, WITH RETRIES, and the retries are the point rather
// than defensiveness.
//
// WebAuthn refuses on a page that is not focused and visible, and reports it as
// a bare `NotAllowedError` — indistinguishable from a declined prompt. A
// headless window is neither for its first second or so, which is what
// `waitForFocus()` exists for. Under the POOL that wait is not enough: with
// three or four headless Chromes contending, a window reports
// `document.hasFocus() === true` and `visibilityState === "hidden"` for longer
// than any wait worth having, and this test measured exactly that
// (`last state: true/hidden`, 16s) on the third of three concurrent points.
//
// So focus is treated as what it is — a MITIGATION rather than a
// precondition. The wait is best-effort, the ceremony is attempted anyway, and
// what decides the outcome is whether the browser actually left the WebAuthn
// page. A refusal leaves it there with the mock's own account of what the
// browser said, so a retry is one more click, and the LAST failure is reported
// with that account rather than with "the browser never gave this page focus"
// — which names the mitigation and not the problem.
//
// Three attempts, because two consecutive refusals on a virtual authenticator
// that is present and consenting are not a scheduling accident.
// ---------------------------------------------------------------------------
async function runTheCeremony(driver, user) {
  log.debug("Entering runTheCeremony().");
  // The ceremony page. With no key enrolled for this username it REGISTERS one
  // and with a key it ASSERTS — and this username is minted per run, so it is
  // always the first of those. `wa-go` is the one button either way.
  await driver.wait(until.elementLocated(By.id("wa-go")), waitTime * 6,
    "Realm 2's relationship configures a passwordless security key and no " +
    "WebAuthn ceremony page appeared after the username was submitted.");
  const heading = await driver.findElement(By.css("h1")).getText();
  assert.ok(/Enrol|security key/i.test(heading),
    "The page after the username is not the WebAuthn step; its heading " +
    "reads: " + heading);

  let complaint = "";
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await waitForFocus(driver, waitTime * 4);
    } catch (e) {
      // Swallowed deliberately, and this is the whole design above: an
      // unfocused window makes the ceremony LIKELY to be refused and does not
      // make it impossible, and a refusal is observable one line down with a
      // better message than this timeout carries.
      log.info("The window never reported itself focused and visible on " +
               "attempt " + attempt + "; running the ceremony anyway — a " +
               "refusal is reported below with the browser's own words.");
    }
    const buttons = await driver.findElements(By.id("wa-go"));
    if (!buttons.length) {
      log.debug("Leaving runTheCeremony(). It has already moved on.");
      return;
    }
    await driver.executeScript(
      "arguments[0].scrollIntoView({block: 'center'}); arguments[0].click();",
      buttons[0]);
    // Left the WebAuthn step? Then it completed. The next page is whatever the
    // protocol that asked for this sign-in does next, which is not this
    // function's business.
    let moved = false;
    try {
      await driver.wait(async function () {
        const url = await driver.getCurrentUrl();
        return url.indexOf("/authn/webauthn") === -1;
      }, waitTime * 4);
      moved = true;
    } catch (e) {
      // Still on the ceremony page, so it was refused. The mock re-renders the
      // page with the reason in a `div.err`, which is worth rather more than
      // the timeout that brought us here.
      moved = false;
    }
    if (moved) {
      log.info("A WebAuthn ceremony ran at realm 2 for " + user +
               (attempt > 1 ? " (attempt " + attempt + ")" : "") + ".");
      log.debug("Leaving runTheCeremony(). Completed.");
      return;
    }
    const errors = await driver.findElements(By.css("div.err"));
    complaint = errors.length ? await errors[0].getText() : "(no reason given)";
    log.info("The ceremony did not complete on attempt " + attempt + ": " +
             complaint.replace(/\s+/g, " ").slice(0, 200));
  }
  throw new Error("The WebAuthn ceremony at realm 2 was refused three times " +
                  "for " + user + ". The last reason the page gave was: " +
                  String(complaint).replace(/\s+/g, " ").slice(0, 500));
}

// ---------------------------------------------------------------------------
// WHAT CAME BACK TO THE APPLICATION, one function per application protocol.
//
// Each of them asserts the SAME two things in its own protocol's terms: that
// the artifact was issued by REALM 1, and that nothing in it names realm 2.
// That second one is the property the whole feature exists to have — which
// identity service did the authenticating is not the application's business —
// and it is the one an implementation leaks by accident.
// ---------------------------------------------------------------------------
function b64uJson(part) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

async function collectOauthArtifacts(driver, spBase, callbackUri, sent) {
  log.debug("Entering collectOauthArtifacts().");
  try {
    await driver.wait(until.urlContains("/oauth2_oidc_2.html"), waitTime * 10);
  } catch (e) {
    throw new Error("The flow never came back to the debugger after the " +
                    "sign-in at realm 2. " + (await whereAreWe(driver)));
  }
  const returned = new URL(await driver.getCurrentUrl());
  const code = returned.searchParams.get("code");
  assert.ok(code,
    "No authorization code came back to the application. The browser is at " +
    returned.toString() + ".");
  assert.strictEqual(returned.searchParams.get("state"), sent.state,
    "The state did not come back unchanged.");
  log.info("The application received an authorization code.");
  log.debug("Leaving collectOauthArtifacts().");
  return { code: code, returned: returned };
}

// Redeem the code THROUGH THE PAGE, because the application is what this test
// is standing in for and the Token Request is the application's own call.
// Browser-direct rather than through the api, so this half needs the client and
// the mock and nothing else.
async function redeemThroughThePage(driver, callbackUri) {
  log.debug("Entering redeemThroughThePage().");
  const tokenClientId = By.id("token_client_id");
  await driver.wait(until.elementLocated(tokenClientId), waitTime * 3);
  await driver.wait(until.elementIsVisible(driver.findElement(tokenClientId)),
                    waitTime);
  const frontEnd =
      await driver.findElements(By.id("token_initiateFromFrontEnd"));
  assert.ok(frontEnd.length,
    "oauth2_oidc_2.html has no token_initiateFromFrontEnd radio to select.");
  await driver.executeScript(
    "arguments[0].scrollIntoView({block: 'center'}); arguments[0].click();",
    frontEnd[0]);
  await driver.findElement(tokenClientId).clear();
  await driver.findElement(tokenClientId).sendKeys(APPLICATION);
  await driver.findElement(By.id("token_scope")).clear();
  await driver.findElement(By.id("token_scope")).sendKeys(
    APP_PROTOCOL === "oidc" ? "openid profile email" : "profile email");
  await driver.findElement(By.id("token_redirect_uri")).clear();
  await driver.findElement(By.id("token_redirect_uri")).sendKeys(callbackUri);
  await driver.findElement(By.className("token_btn")).click();

  const wanted = APP_PROTOCOL === "oidc" ? By.id("token_id_token")
                                         : By.id("token_access_token");
  const errorField = By.id("display_token_error_form_textarea1");
  let token = "";
  await driver.wait(async function () {
    const fields = await driver.findElements(wanted);
    if (fields.length) {
      token = await fields[0].getAttribute("value");
      if (token && token.trim()) {
        return true;
      }
    }
    const errors = await driver.findElements(errorField);
    if (errors.length) {
      const text = await errors[0].getAttribute("value");
      if (text && text.trim()) {
        throw new Error("Realm 1's token endpoint refused the code: " + text);
      }
    }
    return false;
  }, waitTime * 8, "The code never became a token.");
  log.debug("Leaving redeemThroughThePage().");
  return token;
}

async function assertOauthArtifact(token, spBase, idpBase, sent, user) {
  log.debug("Entering assertOauthArtifact().");
  if (APP_PROTOCOL === "oidc") {
    const parts = String(token).split(".");
    assert.strictEqual(parts.length, 3,
      "The ID Token is not a three-part JWS; it has " + parts.length +
      " part(s).");
    const claims = b64uJson(parts[1]);
    assert.strictEqual(claims.iss, spBase,
      "The application's ID Token says it was issued by \"" + claims.iss +
      "\". It must be realm 1: the application asked realm 1 and realm 1 is " +
      "what answered — an issuer of \"" + idpBase + "\" would mean the " +
      "federation leaked through to the application.");
    assert.strictEqual(claims.nonce, sent.nonce,
      "The ID Token carries nonce \"" + claims.nonce + "\", not the one the " +
      "page sent.");
    assert.ok([].concat(claims.aud || []).indexOf(APPLICATION) >= 0,
      "The ID Token's aud is " + JSON.stringify(claims.aud) + " and should " +
      "name " + APPLICATION + ".");
    assert.ok(JSON.stringify(claims).indexOf(IDP_REALM) === -1,
      "The application's ID Token mentions " + IDP_REALM + ": " +
      JSON.stringify(claims) + ". Nothing about which identity service did " +
      "the authenticating is the application's business, and this is the one " +
      "property the whole feature exists to have.");
    assert.ok(
      String(claims.preferred_username || claims.sub).indexOf(user) >= 0,
      "The ID Token describes \"" + (claims.preferred_username || claims.sub) +
      "\" and the name typed at realm 2 was \"" + user + "\".");
    log.info("The application holds an ID Token issued by " + claims.iss +
             " describing " + (claims.preferred_username || claims.sub) +
             ", and naming realm 2 nowhere.");
    log.debug("Leaving assertOauthArtifact(). OIDC.");
    return;
  }
  // Plain OAuth 2.0: there is no ID Token, and the ACCESS TOKEN is what the
  // application holds. The mock issues a JWT, so the same two questions can be
  // asked of it — and asking them is worth more here than in the OIDC case,
  // because an access token says a client was authorized rather than that a
  // person signed in, which is the whole of what goes wrong when OAuth 2.0 is
  // used for authentication.
  const parts = String(token).split(".");
  assert.strictEqual(parts.length, 3,
    "The access token is not a three-part JWS; it has " + parts.length +
    " part(s), so nothing below can read who it is about.");
  const claims = b64uJson(parts[1]);
  assert.strictEqual(claims.iss, spBase,
    "The access token says it was issued by \"" + claims.iss + "\" and must " +
    "say realm 1.");
  assert.ok(JSON.stringify(claims).indexOf(IDP_REALM) === -1,
    "The access token mentions " + IDP_REALM + ": " + JSON.stringify(claims) +
    ".");
  assert.ok(String(claims.preferred_username || claims.sub).indexOf(user) >= 0,
    "The access token describes \"" +
    (claims.preferred_username || claims.sub) + "\" and the name typed at " +
    "realm 2 was \"" + user + "\".");
  log.info("The application holds an access token issued by " + claims.iss +
           " describing " + (claims.preferred_username || claims.sub) + ".");
  log.debug("Leaving assertOauthArtifact(). OAuth 2.0.");
}

async function assertSamlArtifact(driver, localIssuer, user) {
  log.debug("Entering assertSamlArtifact().");
  try {
    await driver.wait(until.urlContains("saml_response.html"), waitTime * 12);
  } catch (e) {
    throw new Error("The flow never reached the debugger's SAML response " +
                    "page after the sign-in at realm 2. " +
                    (await whereAreWe(driver)));
  }
  await waitForValue(driver, By.id("saml_resp_xml"),
    function (v) { return v.indexOf("Response") >= 0; },
    "No SAML Response was displayed on the response page.", waitTime * 10);
  const responseXml = await driver.findElement(By.id("saml_resp_xml"))
    .getAttribute("value");
  log.info("SAML Response (first 1200 chars):\n" + responseXml.slice(0, 1200));

  // The "(no <Assertion> ...)" placeholder the page shows for an error or an
  // encrypted response would otherwise false-positive on the bare substring.
  await waitForValue(driver, By.id("saml_assertion_xml"),
    function (v) {
      return v.indexOf("Assertion") >= 0 && v.indexOf("no <Assertion") < 0;
    },
    "No <Assertion> came back to the application — which is what realm 1 " +
    "answering with a status rather than an assertion looks like. See the " +
    "logged Response above.", waitTime * 10);
  const assertionXml = await driver.findElement(By.id("saml_assertion_xml"))
    .getAttribute("value");

  assert.ok(assertionXml.indexOf(localIssuer) >= 0,
    "The assertion the application received does not name realm 1's issuer (" +
    localIssuer + ") anywhere, so it did not come from the identity provider " +
    "this application asked. It reads:\n" + assertionXml.slice(0, 1200));
  // AND IT WAS MINTED FOR THIS APPLICATION. The audience restriction is the
  // per-combination half of the check: a SAML 1.1 issuer is a URN this mock
  // uses in every realm, so the line above alone would pass on an assertion
  // minted for somebody else entirely.
  assert.ok(assertionXml.indexOf(APPLICATION) >= 0,
    "The assertion does not name " + APPLICATION + " as its audience, so it " +
    "was minted for a different relying party. It reads:\n" +
    assertionXml.slice(0, 1200));
  assert.ok(assertionXml.indexOf(IDP_REALM) === -1,
    "The assertion the application received mentions " + IDP_REALM +
    ". Which identity service actually authenticated the person is not the " +
    "application's business, and this is the one property the whole feature " +
    "exists to have. It reads:\n" + assertionXml.slice(0, 1200));
  assert.ok(assertionXml.indexOf(user) >= 0,
    "The assertion does not describe \"" + user + "\", the name typed at " +
    "realm 2. It reads:\n" + assertionXml.slice(0, 1200));
  log.info("The application holds a " + LABELS[APP_PROTOCOL] + " assertion " +
           "issued by realm 1 describing " + user + ", naming realm 2 " +
           "nowhere.");
  log.debug("Leaving assertSamlArtifact().");
}

async function assertWsFedArtifact(driver, localIssuer, user) {
  log.debug("Entering assertWsFedArtifact().");
  try {
    await driver.wait(until.urlContains("wsfed_response.html"), waitTime * 12);
  } catch (e) {
    throw new Error("Realm 1's sign-in response never reached a landing that " +
                    "could forward it to the debugger's WS-Federation " +
                    "response page. " + (await whereAreWe(driver)));
  }
  await waitForValue(driver, By.id("wsfed_resp_status"),
    function (v) { return v.indexOf("wresult loaded.") >= 0; },
    "The wresult was not loaded on the response page.", waitTime * 10);
  const wresult = await driver.findElement(By.id("wsfed_response_xml"))
    .getAttribute("value");
  log.info("wresult (first 1200 chars):\n" + wresult.slice(0, 1200));
  assert.ok(wresult.indexOf("RequestSecurityTokenResponse") >= 0,
    "The wresult is not a WS-Trust RequestSecurityTokenResponse.");
  await waitForValue(driver, By.id("wsfed_token_xml"),
    function (v) {
      return v.indexOf("Assertion") >= 0 &&
             v.indexOf("no <wst:RequestedSecurityToken") < 0;
    },
    "No SAML assertion was extracted from the wresult.", waitTime * 10);
  const tokenXml = await driver.findElement(By.id("wsfed_token_xml"))
    .getAttribute("value");

  assert.ok(tokenXml.indexOf(localIssuer) >= 0,
    "The token the application received does not name realm 1's issuer (" +
    localIssuer + ") anywhere. It reads:\n" + tokenXml.slice(0, 1200));
  assert.ok(tokenXml.indexOf(APPLICATION) >= 0,
    "The token does not name " + APPLICATION + " as its audience, so it was " +
    "minted for a different relying party. It reads:\n" +
    tokenXml.slice(0, 1200));
  assert.ok(tokenXml.indexOf(IDP_REALM) === -1,
    "The token the application received mentions " + IDP_REALM +
    ". It reads:\n" + tokenXml.slice(0, 1200));
  assert.ok(tokenXml.indexOf(user) >= 0,
    "The token does not describe \"" + user + "\", the name typed at realm " +
    "2. It reads:\n" + tokenXml.slice(0, 1200));
  log.info("The application holds a WS-Federation token issued by realm 1 " +
           "describing " + user + ", naming realm 2 nowhere.");
  log.debug("Leaving assertWsFedArtifact().");
}

// ---------------------------------------------------------------------------
// AND THE TIE ITSELF, BY REMOVING IT.
//
// Every assertion above would pass just as well against a service that
// federated every sign-in for reasons of its own. Clearing
// `appFederationRelationship` and sending the same request must therefore reach
// REALM 1'S OWN sign-in screen — the mutation test for the feature this whole
// grid exists to cover, and the one assertion here that fails when the feature
// is deleted.
//
// The attribute is put back in a `finally` for the reason every other test here
// restores what it changed: the realms outlive this process.
// ---------------------------------------------------------------------------
async function clearingTheTieRestoresTheLocalScreen(driver, spBase,
                                                    callbackUri) {
  log.debug("Entering clearingTheTieRestoresTheLocalScreen().");
  // REMOVE, NOT SET. `appFederationRelationship` holds a LIST — an application
  // may name several partners, which is what draws the mock's own home-realm
  // chooser — and the registry refuses a `set` on a list attribute BY NAME:
  // "a set would replace the list with one value and read afterwards as the
  // others having been forgotten". So the tie is taken off by naming the value,
  // and put back the same way.
  await must(spBase, "/applications/remove",
             { application: APPLICATION,
               attribute: "appFederationRelationship",
               value: RELATIONSHIP },
             "clearing the application's federation relationship");
  try {
    const entry = await adminGet(spBase,
      "/applications?application=" + encodeURIComponent(APPLICATION));
    // Array-tolerant for the reason registerApplication() gives at length: the
    // attribute is multi-valued and comes back either way. A `.trim()` on an
    // ARRAY is a TypeError, and one on `["x"]` coerced to a string is truthy —
    // so the string-shaped check here would have passed a cleared entry and
    // failed an uncleared one at random.
    const stillNamed = [].concat((entry.fields || {})
      .appFederationRelationship || []).filter(function (one) {
        return String(one).trim();
      });
    assert.strictEqual(stillNamed.length, 0,
      "The federation relationship was not actually cleared off the entry — " +
      "it still names " + JSON.stringify(stillNamed) + " — so the check " +
      "below would be measuring nothing.");

    await clearSessionsAt(driver, spBase);
    await driveApplicationTier(driver, spBase, callbackUri);
    await driver.wait(until.elementLocated(By.id("username")), waitTime * 6,
      "With the tie removed no sign-in screen appeared at all.");
    const url = await driver.getCurrentUrl();
    assert.ok(url.indexOf("/realm/" + SP_REALM + "/") >= 0,
      "With the tie removed the sign-in screen should be REALM 1's own, and " +
      "the browser is at " + url + ".");
    assert.ok(url.indexOf("/realm/" + IDP_REALM + "/") === -1,
      "With the tie removed the browser still went to realm 2 (" + url +
      "), so something other than appFederationRelationship is federating " +
      "this application and every assertion above is about that instead.");
    log.info("With the tie cleared the same " + LABELS[APP_PROTOCOL] +
             " request stops at realm 1's own sign-in screen: " + url);
  } finally {
    await must(spBase, "/applications/add",
               { application: APPLICATION,
                 attribute: "appFederationRelationship",
                 value: RELATIONSHIP },
               "putting the application's federation relationship back");
  }
  log.debug("Leaving clearingTheTieRestoresTheLocalScreen().");
}

// ---------------------------------------------------------------------------
// Whether this mock is new enough for the two attributes this grid is about,
// read off the SCHEMAS that service publishes rather than off a version string:
// the submodule is bumped by hand, and a job that failed on a stale checkout
// would name a missing element on a sign-in screen three hops from the cause.
// ---------------------------------------------------------------------------
async function mockKnowsTheAttributes(stsBase) {
  log.debug("Entering mockKnowsTheAttributes().");
  const response = await fetch(stsBase + "/ldap/applications",
                               { headers: { Accept: "application/json" } });
  if (response.status !== 200) {
    log.debug("Leaving mockKnowsTheAttributes(). " + response.status);
    return { ok: false, why: "GET /ldap/applications answered " +
                             response.status };
  }
  const text = await response.text();
  if (text.indexOf("appFederationRelationship") === -1) {
    log.debug("Leaving mockKnowsTheAttributes(). No tie attribute.");
    return { ok: false,
             why: "it does not publish appFederationRelationship in its " +
                  "application schema, so it predates the attribute that " +
                  "ties " +
                  "an application to a federation relationship" };
  }
  if (text.indexOf("fedAuthnMechanism") === -1) {
    // The application schema page prints the federation one beside it, so one
    // fetch answers both questions. A mock that has the tie and not the
    // mechanism is the 2026-08-26 checkout, on which the twenty-five WebAuthn
    // points would silently sign in with a password.
    const register = await fetch(stsBase + "/ldap/federations",
                                 { headers: { Accept: "application/json" } });
    const registerText = register.status === 200 ? await register.text() : "";
    if (registerText.indexOf("fedAuthnMechanism") === -1) {
      log.debug("Leaving mockKnowsTheAttributes(). No fedAuthnMechanism.");
      return { ok: false,
               why: "its federation register has no fedAuthnMechanism, so an " +
                    "identity-provider-side relationship cannot say how it " +
                    "authenticates and every point of this grid would sign " +
                    "in with a password" };
    }
  }
  log.debug("Leaving mockKnowsTheAttributes(). Yes.");
  return { ok: true, why: "" };
}

// ---------------------------------------------------------------------------
// ANY POINT WITH WS-FEDERATION ON EITHER SIDE needs a mock new enough to route
// that profile's sign-in through the shared authentication funnel — see the
// header. BOTH sides, and the second is easy to miss:
//
//   * as the APPLICATION tier, an older mock draws WS-Federation's own screen
//     and signs the person in AT REALM 1. The flow completes. It federates
//     nothing, which is exactly the failure this grid exists to catch;
//   * as the FEDERATION protocol, realm 2 receives the `wsignin1.0` and its own
//     screen honours no `fedAuthnMechanism` at all — so the point runs a
//     password sign-in whatever the relationship said, including the five that
//     configured a security key.
//
// Both are detected up front and reported as a SKIP naming the submodule,
// because neither produces an error worth reading otherwise.
// ---------------------------------------------------------------------------
async function mockRoutesWsFedThroughTheFunnel(stsBase) {
  log.debug("Entering mockRoutesWsFedThroughTheFunnel().");
  if (APP_PROTOCOL !== "wsfed" && FED_PROTOCOL !== "wsfed") {
    log.debug("Leaving mockRoutesWsFedThroughTheFunnel(). Not needed.");
    return true;
  }
  // ASKED OF THE ENDPOINT ITSELF rather than of a version or a metadata page,
  // because what matters is exactly what it does: a mock that still owns the
  // screen answers a sign-in request 200 with a form, and one that routes it
  // answers 303 to /authn/login. The DEFAULT realm is probed — this is a
  // question about the build, not about a realm — with a wtrealm nothing has
  // ever heard of, so it configures nothing and leaves no entry behind that
  // matters.
  const probe = await fetch(stsBase + "/wsfed?wa=wsignin1.0&wtrealm=" +
                            encodeURIComponent("urn:fedmx:funnel-probe"),
                            { redirect: "manual" });
  const location = String(probe.headers.get("location") || "");
  const routed = probe.status === 303 && location.indexOf("/authn/login") >= 0;
  log.debug("Leaving mockRoutesWsFedThroughTheFunnel(). " + probe.status +
            " " + (location || "(no location)") + " -> " + routed);
  return routed;
}

// ===========================================================================

async function test() {
  log.debug("Entering test().");
  const stsUrl = process.env.WSTRUST_STS_URL || "";
  if (!stsUrl) {
    log.info("SKIPPED: WSTRUST_STS_URL is not set, so there is no mock " +
             "STS to " +
             "build two trust realms in. This test needs that service, the " +
             "client and the api, and nothing else.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const stsBase = stsUrl.replace(/\/sts\/?$/, "");
  const known = await mockKnowsTheAttributes(stsBase);
  if (!known.ok) {
    log.info("SKIPPED: the mock STS at " + stsBase + " — " + known.why +
             ". Bump the sts/ submodule.");
    log.debug("Leaving test(). Skipped, the mock is too old.");
    return;
  }
  if (!(await mockRoutesWsFedThroughTheFunnel(stsBase))) {
    log.info("SKIPPED: the mock STS at " + stsBase + " still answers a " +
             "wsignin1.0 with a sign-in screen of its own rather than " +
             "routing it through authn.js. This point has WS-Federation " +
             (APP_PROTOCOL === "wsfed"
              ? "as its application tier, which cannot be federated there — " +
                "it would sign in at realm 1 and look like a pass"
              : "as its federation protocol, so realm 2 would honour no " +
                "fedAuthnMechanism and sign the person in with a password " +
                "whatever the relationship configured") +
             ". Bump the sts/ submodule.");
    log.debug("Leaving test(). Skipped, wsfed does not federate there.");
    return;
  }

  const spBase = stsBase + "/realm/" + SP_REALM;
  const idpBase = stsBase + "/realm/" + IDP_REALM;
  const callbackUri = baseUrl + "/callback";
  const user = usernameFor("fedmx-" + SLUG);
  const partnerAppId = partnerApplicationId(spBase);

  log.info("=== " + LABELS[APP_PROTOCOL] + " to " + SP_REALM + ", " +
           LABELS[FED_PROTOCOL] + " on to " + IDP_REALM + ", " + MECHANISM +
           " there ===");

  // ---------------------------------------------------------------------
  // CONFIGURATION FIRST, with no browser open. Everything here is a
  // management API call and every one of them is asserted: a setup step that
  // quietly does nothing is worse than none, because the flow below would
  // then be testing whatever the mock happened to be configured with.
  // ---------------------------------------------------------------------
  await createRealms(stsBase);
  await allowInsecureOutbound(spBase);
  await registerApplication(spBase, callbackUri);
  await registerPartnerAtIdp(idpBase, spBase, partnerAppId);
  const partner = await readPartnerMetadata(idpBase, partnerAppId);
  await createRelationship(spBase, partner, partnerAppId, callbackUri);
  await createIdpRelationship(idpBase, partnerAppId);
  const localIssuer = await readLocalIssuer(spBase);

  // THE ADDRESS THE CONSOLE TELLS AN OPERATOR TO GIVE THE PARTNER must be the
  // one this flow actually uses. They are built by different modules —
  // `admin.js` for the page and `federation_sp.js` for the request — so
  // nothing but a comparison keeps them in step, and the failure when they
  // drift is silent HERE and loud at somebody else's identity service.
  const advertised = await relationshipNow(spBase, RELATIONSHIP);
  assert.strictEqual(advertised.endpoints.assertionConsumerService,
                     spBase + "/federation/acs/" + RELATIONSHIP,
    "The console advertises \"" +
    advertised.endpoints.assertionConsumerService + "\" as the address to " +
    "configure at the partner, and this relationship's own return address is " +
    spBase + "/federation/acs/" + RELATIONSHIP + ". An operator copying the " +
    "first into a real identity provider would configure a URL this service " +
    "does not answer on.");

  const options = new chrome.Options();
  if (headless) {
    // "=new", never bare --headless: the tests image pins Chrome 121, where
    // plain --headless selects the old implementation and
    // --unsafely-treat-insecure-origin-as-secure has no effect in it.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  // The secure-context relaxation, the private-network flags, AND the mock's
  // SPKI pin — the suite runs that service over TLS on a self-signed
  // certificate regenerated at every start, so without the pin the browser
  // meets an interstitial and this test reports a missing sign-in screen.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    if (MECHANISM === "webauthn") {
      // A CTAP2 authenticator inside the browser. It lives only as long as
      // this session, which is why the username is minted per run: the mock
      // remembers an enrolled key per username for the life of its process,
      // and a re-used name would be asked to assert with a key this browser
      // has never held.
      await driver.addVirtualAuthenticator(authenticatorOptions());
    }
    await driver.manage().deleteAllCookies();

    const sent = await driveApplicationTier(driver, spBase, callbackUri);
    await signInAtIdp(driver, user, idpBase);

    // ---------------------------------------------------------------------
    // WHAT THE FLOW LEFT BEHIND AT REALM 1, read before any artifact is
    // redeemed so that the count is about the SIGN-IN rather than about a
    // later token call.
    // ---------------------------------------------------------------------
    if (APP_PROTOCOL === "oidc" || APP_PROTOCOL === "oauth2") {
      const artifacts = await collectOauthArtifacts(driver, spBase,
                                                    callbackUri, sent);
      await assertFederationState(spBase, user);
      const token = await redeemThroughThePage(driver, callbackUri);
      await assertOauthArtifact(token, spBase, idpBase, sent, user);
      log.debug("collectOauthArtifacts() returned code " +
                String(artifacts.code).slice(0, 12) + "…");
    } else if (APP_PROTOCOL === "wsfed") {
      await assertWsFedArtifact(driver, localIssuer, user);
      await assertFederationState(spBase, user);
    } else {
      await assertSamlArtifact(driver, localIssuer, user);
      await assertFederationState(spBase, user);
    }

    await clearingTheTieRestoresTheLocalScreen(driver, spBase, callbackUri);

    log.info("Test completed successfully: " + LABELS[APP_PROTOCOL] + " / " +
             LABELS[FED_PROTOCOL] + " / " + MECHANISM + ".");
  } catch (error) {
    log.error(error.stack || error.message);
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

// The register and the directory at realm 1, after exactly one federated
// sign-in. Its own function because all three application tiers assert it and
// the point of the numbers is that they are EXACTLY ONE: a relationship that
// counted two counted somebody else's, and one that counted none was not the
// relationship this sign-in went through.
async function assertFederationState(spBase, user) {
  log.debug("Entering assertFederationState().");
  const after = await relationshipNow(spBase, RELATIONSHIP);
  assert.strictEqual(Number(after.authentications || 0), 1,
    "Realm 1's relationship counted " + after.authentications +
    " federated sign-in(s) and this test performed exactly one. A zero means " +
    "the person was authenticated somewhere other than through this " +
    "relationship, which a completed flow does not otherwise show.");
  assert.ok(!String(after.lastError || "").trim(),
    "The relationship recorded a failure during a sign-in that succeeded: " +
    after.lastError);
  assert.ok(String(after.lastUser || "").indexOf(user) >= 0,
    "The relationship's last user is \"" + after.lastUser + "\" and this " +
    "test signed in as \"" + user + "\".");

  // The person now has a directory entry in REALM 1 — a service that never
  // checked a credential for them — and it says HOW they got there. The mock
  // files a federated sign-in under the protocol the relationship speaks, so
  // somebody who has never had a password checked here is distinguishable
  // from somebody who has.
  const users = await adminGet(spBase, "/users?q=" + encodeURIComponent(user));
  assert.ok((users.users || []).some(function (one) {
    return String(one.name) === user || String(one.key) === user;
  }), "Realm 1 has no directory entry for " + user + ", who has just signed " +
      "in there. It lists: " +
      (users.users || []).map(function (o) { return o.name; }).join(", "));
  assert.ok((users.protocols || []).some(function (one) {
    return /Federation/i.test(String(one));
  }), "Realm 1 does not record " + user + " as having arrived through " +
      "federation. It says: " + (users.protocols || []).join(", "));
  log.info("Realm 1's relationship counted one sign-in by " + user +
           ", who has a directory entry there and no password.");
  log.debug("Leaving assertFederationState().");
}

const program = new Command();
program
  .name("federation_matrix_sso")
  .description("One point of the federation grid: an application speaking " +
               "FEDERATION_APP_PROTOCOL to federation-matrix-1, which " +
               "federates over FEDERATION_FED_PROTOCOL to " +
               "federation-matrix-2, which authenticates by " +
               "FEDERATION_MECHANISM.")
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
