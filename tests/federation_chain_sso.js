// File: federation_chain_sso.js
//
// ===========================================================================
// N-LAYER FEDERATION: ONE SIGN-IN THROUGH THREE TRUST REALMS AND THREE
// PROTOCOLS, WITH THE MIDDLE REALM AS A PURE IDENTITY BRIDGE.
//
// `tests/federation_sso.js` proves ONE hop: an application asks realm 1, realm
// 1 asks realm 2 over SAML 2.0, and a name is typed at realm 2. This test is
// that shape with the bottom knocked out of it — the realm that receives the
// SAML 2.0 request has no password box of its own to fall back on, because it
// is configured to answer with somebody ELSE'S answer, over a different
// protocol again.
//
//   browser ──▶ oauth2_oidc_1.html               the application, webapp_sso_2
//             └─▶ /realm/federation-realm-3      an OpenID Provider to it, and
//                                                a SAML 2.0 SERVICE PROVIDER
//               └─▶ /realm/federation-realm-4    a SAML 2.0 IDENTITY PROVIDER
//                                                to realm 3, and a
//                                                WS-FEDERATION SERVICE
//                                                PROVIDER to realm 5. It never
//                                                authenticates anybody and has
//                                                no opinion about who they
//                                                are: it is a BRIDGE.
//                 └─▶ /realm/federation-realm-5  the WS-Federation identity
//                                                provider, and the ONLY place
//                                                a name is ever typed
//
// Three protocols, four parties, one sign-in — and every party but the last
// one is lying to the party above it by omission, which is the entire point:
//
//   * the application asked ONE OpenID Provider ONE question. Its ID Token
//     names realm 3 and neither of the other two.
//   * realm 3 sent ONE SAML 2.0 AuthnRequest and got ONE signed Response. It
//     has no idea WS-Federation was involved, and no field anywhere in what it
//     received mentions realm 5.
//   * realm 4 checked no password. It consumed a WS-Federation token and
//     re-asserted its contents as a SAML 2.0 assertion of its own, signed with
//     its OWN key — which is exactly what an identity broker is, and why the
//     word for it in every product that sells one is "bridge".
//
// ---------------------------------------------------------------------------
// THE ATTRIBUTE THIS TEST EXISTS FOR
//
// `fedAuthnMechanism` on realm 4's IDENTITY-PROVIDER-SIDE relationship, with
// `fedAuthnRelationship` beside it. Before those existed, a partner asking
// this service to authenticate somebody got exactly one thing: the sign-in
// screen. `appFederationRelationship` on an APPLICATION entry could redirect a
// sign-in to a partner — that is what `federation_sso.js` covers — but it
// answers a different question ("where do this application's people sign
// in?"), and an application entry is not where somebody configuring the
// far end of a federation is looking.
//
// The four values are `password`, `password-mfa`, `webauthn` and `federation`,
// and the fourth is the one that makes the chain: it names a
// SERVICE-PROVIDER-side relationship in the same realm and the person is sent
// there instead. Nothing bounds the depth. Realm 5 could itself have been
// configured to broker on to a realm 6, and the only thing that would change
// about this file is the number of hops asserted below.
//
// ---------------------------------------------------------------------------
// WHY THREE NEW REALMS AND NOT THE TWO THAT ARE ALREADY THERE
//
// `federation-realm-1` and `-2` belong to `federation_sso.js`, which asserts
// that realm 1's relationship counted EXACTLY ONE sign-in and that realm 2 has
// no relationships of its own. Reusing either would make each test's
// assertions depend on whether the other had run, which is the trap
// tests/CLAUDE.md describes as asserting against somebody else's litter. These
// three are this file's, entirely.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS, AND WHY NOT "DID A TOKEN COME BACK"
//
// Every interesting failure here still ends with an access token — that is
// what makes brokered authentication worth testing at all. So:
//
//   * the browser reaches REALM 5's screen, and that screen says it is
//     answering a WS-FEDERATION request — realm 4's own screen must never be
//     drawn, which is the whole claim. It used to be read off the BUTTON
//     (`wsfed-login`, not `kc-login`), because that profile drew a screen of
//     its own; since 2026-08-26 it goes through the shared funnel like the
//     other three, so what is read is what the screen SAYS it is signing in
//     for. That is the stronger of the two: a button says which module
//     rendered a page, and this says which request it is answering;
//   * realm 4's IdP-side relationship is created DISABLED, and setting the
//     mechanism to `federation` with nothing to broker to reports
//     `fedAuthnRelationship` as MISSING rather than half-working;
//   * each hop verifies the one below it against a CONFIGURED key and a
//     CONFIGURED issuer — realm 3 against realm 4's SAML 2.0 certificate and
//     entityID, realm 4 against realm 5's WS-Federation certificate and
//     entityID — so nothing in this chain is trusted for having turned up;
//   * the application's ID Token says `iss: …/realm/federation-realm-3` and
//     mentions neither realm 4 nor realm 5 anywhere;
//   * all three realms end up with a directory entry for the person, and only
//     realm 5 ever saw a password field;
//   * AND THE MECHANISM ITSELF, four ways, by changing it — `password` must
//     put realm 4's own screen back, a mechanism pointing at a DISABLED
//     relationship must say so on that screen rather than falling silently
//     back to it, and a value that is not one of the four must be named as
//     such. Without those, every assertion above would pass just as well
//     against a mock that chained for reasons of its own.
//
// ---------------------------------------------------------------------------
// GATING
//
// `WSTRUST_STS_URL` locates the mock, as in every other STS-backed job here.
// The job SKIPS with a reason when there is none, and with a DIFFERENT reason
// when the mock predates `fedAuthnMechanism` — read off
// `GET /ldap/federations`,
// the schema that service publishes, rather than guessed from a version.
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
var log = bunyan.createLogger({ name: "federation_chain_sso",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const waitForModule = require("./wait_for.js");
waitForModule.configure({ log: log, waitTime: waitTime });
const { waitForPageBundle } = waitForModule;

const { populateMetadata } = require("../common/tests.js")({ By, until, Select,
       waitTime, log, assert });

// ---------------------------------------------------------------------------
// THE THREE REALMS AND EVERYTHING CREATED IN THEM.
//
// A relationship is ONE DIRECTION, so a federation between two realms is TWO
// records — one in each realm — and this chain has four of them across three
// realms. They are named after what they point AT, because the direction is
// the partner and a relationship named after itself tells a reader nothing.
// ---------------------------------------------------------------------------
const APP_REALM = "federation-realm-3";     // the OpenID Provider
const BRIDGE_REALM = "federation-realm-4";  // the identity bridge
const IDP_REALM = "federation-realm-5";     // where a name is typed

// In realm 3: this service consumes realm 4's SAML 2.0 assertions.
const REL_3_TO_4 = BRIDGE_REALM;
// In realm 4: this service ASSERTS to realm 3 over SAML 2.0. This is the entry
// carrying fedAuthnMechanism, and it is the only one of the four that does.
const REL_4_FROM_3 = APP_REALM;
// In realm 4: this service consumes realm 5's WS-Federation tokens. This is
// what the entry above brokers to.
const REL_4_TO_5 = IDP_REALM;

const APPLICATION = "webapp_sso_2";
// What `webapp_sso_2` would use if it existed. The debugger is what actually
// drives the flow and its callback is registered beside this one, for
// registerApplication()'s reason.
const REGISTERED_REDIRECT_URI = "https://webapp-sso-2.example.com";

// ---------------------------------------------------------------------------
// THE MANAGEMENT API, and it is per REALM here.
//
// `/admin-api` under a realm prefix acts on THAT realm's stores, which is the
// only way to configure three identity services that share a process. The
// console is not an option for any of it: `admin.authRequired` has been on
// since 2026-08-24, so a caller posting JSON is refused 401 rather than
// redirected.
// ---------------------------------------------------------------------------
async function adminGet(base, path) {
  log.debug("Entering adminGet(). " + path);
  const response = await fetch(base + "/admin-api" + path,
                               { headers: { Accept: "application/json" } });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    log.debug("Leaving adminGet(). Not JSON.");
    throw new Error("GET " + base + "/admin-api" + path + " answered " +
                    response.status + " with something that is not JSON: " +
                    text.slice(0, 300));
  }
  log.debug("Leaving adminGet(). " + response.status);
  return parsed;
}

async function adminPost(base, path, body) {
  log.debug("Entering adminPost(). " + path);
  const response = await fetch(base + "/admin-api" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    log.debug("Leaving adminPost(). Not JSON.");
    throw new Error("POST " + base + "/admin-api" + path + " answered " +
                    response.status + " with something that is not JSON: " +
                    text.slice(0, 300));
  }
  log.debug("Leaving adminPost(). ok=" + parsed.ok);
  return parsed;
}

// A management API call that must have worked. The mock answers 400 with an
// `errors` array rather than throwing, so a failure's message is the service's
// own account of what it disliked — worth rather more than "the call failed".
async function must(base, path, body, what) {
  log.debug("Entering must(). " + what);
  const result = await adminPost(base, path, body);
  assert.ok(result.ok, what + " was refused by the mock STS: " +
            JSON.stringify(result.errors || result));
  log.debug("Leaving must().");
  return result;
}

// A call that is allowed to fail because it is a tidy-up: removing something an
// earlier run may or may not have left behind. It is a SEPARATE function rather
// than a flag on must(), because a swallowed failure and an asserted one must
// not be one call site away from each other — see tests/CLAUDE.md on setup
// steps that quietly do nothing.
async function tidy(base, path, body, what) {
  log.debug("Entering tidy(). " + what);
  const result = await adminPost(base, path, body);
  log.debug("Leaving tidy(). " + (result.ok ? "removed" : "there was none"));
  return result.ok;
}

// ---------------------------------------------------------------------------
// THE THREE REALMS.
//
// A realm is defined at RUNTIME and lives in memory, so there is nowhere to
// declare one and every run has to create its own — which also means a second
// run against a live container meets realms that are already there. That is not
// an error: what matters is that the realm exists, not who made it.
// ---------------------------------------------------------------------------
async function createRealms(stsBase) {
  log.debug("Entering createRealms().");
  const before = await adminGet(stsBase, "/realms");
  const known = (before.realms || []).map(function (one) { return one.id; });
  for (const id of [APP_REALM, BRIDGE_REALM, IDP_REALM]) {
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
  for (const id of [APP_REALM, BRIDGE_REALM, IDP_REALM]) {
    assert.ok(ids.indexOf(id) >= 0,
      "The \"" + id + "\" realm should be defined and the service lists: " +
      ids.join(", ") + ". A realm that was created and is not listed means " +
      "the create answered ok for something that did not happen.");
  }
  // Three realms sharing a signing key would be three names for one identity
  // service, and every assertion below about WHICH realm signed something
  // would be unfalsifiable — which matters more here than it does with two,
  // because the middle realm's whole job is to RE-SIGN what it was handed. The
  // mock derives a `kid` from the key material, so this is one comparison
  // rather than a claim.
  const kids = (after.realms || []).filter(function (one) {
    return [APP_REALM, BRIDGE_REALM, IDP_REALM].indexOf(one.id) >= 0;
  }).map(function (one) { return one.kid; });
  assert.strictEqual(new Set(kids).size, 3,
    "The three realms publish " + new Set(kids).size + " distinct signing " +
    "key id(s) (" + kids.join(", ") + "). Two of them are signing with one " +
    "key, so the bridge in the middle would be re-asserting with the same " +
    "key it just verified against and nothing below could tell the hops " +
    "apart.");
  log.info("All three realms are defined, with signing keys of their own.");
  log.debug("Leaving createRealms().");
}

// ---------------------------------------------------------------------------
// THE APPLICATION, IN REALM 3, BEFORE IT EVER CONNECTS.
//
// Deleted first and created again, so that every counter this test reads
// afterwards starts at zero: a run against a container somebody has already
// driven would otherwise assert on somebody else's arithmetic.
//
// TWO REDIRECT URIS. The application is registered with the URI
// `webapp_sso_2` would use if it existed, and with the debugger's own
// callback, which is what actually drives the flow. Both, because the point of
// pre-registering at all is the mode that will one day CHECK the list — and a
// list omitting the URI the flow uses would pass today and fail then, for a
// reason nothing in the failure would name.
// ---------------------------------------------------------------------------
async function registerApplication(appBase, callbackUri) {
  log.debug("Entering registerApplication().");
  await tidy(appBase, "/applications/forget", { application: APPLICATION },
             "removing an application left behind by an earlier run");
  await must(appBase, "/applications/create", {
    identifier: APPLICATION,
    name: APPLICATION,
    // What the application is DECLARED for. The mock reads this nowhere, so
    // this test asserts it came back rather than that it did anything.
    protocols: ["oauth2", "oidc"],
    fields: {
      oauthClientId: APPLICATION,
      oauthRedirectUri: [REGISTERED_REDIRECT_URI, callbackUri],
      // THE FIRST TIE, and it is the one `federation_sso.js` already covers:
      // an application entry naming a relationship federates that
      // application's sign-ins. What is NEW is one layer down, on realm 4's
      // relationship — see createBridgeRelationship().
      appFederationRelationship: REL_3_TO_4,
      appFederationAutoRedirect: "TRUE"
    }
  }, "creating the " + APPLICATION + " application in " + APP_REALM);

  // Read back through the API rather than trusting the create's own answer:
  // the reply is the service's account of what it did, and the ENTRY is what
  // every endpoint will actually read. The single-application reply is FLAT.
  const entry = await adminGet(appBase,
    "/applications?application=" + encodeURIComponent(APPLICATION));
  assert.ok(entry.found, "The application " + APPLICATION + " is not in " +
            APP_REALM + "'s registry after being created there.");
  const fields = entry.fields || {};
  // A LIST, not a string. `appFederationRelationship` is multi-valued in the
  // mock's schema — an application may offer several partners and a person
  // picks between them at `/authn/select-idp` — so the registry answers with
  // an array. This chain names exactly ONE at each layer, and the assertion
  // says so: a second value here would draw the chooser instead of the
  // redirect that every hop below depends on.
  const named = [].concat(fields.appFederationRelationship || []);
  assert.deepStrictEqual(named, [REL_3_TO_4],
    "The application entry should name exactly the federation relationship \"" +
    REL_3_TO_4 + "\" and names [" + named.join(", ") + "].");
  const registered = [].concat(fields.oauthRedirectUri || []);
  assert.ok(registered.indexOf(callbackUri) >= 0,
    "The debugger's own callback (" + callbackUri + ") is not in the " +
    "registered list (" + registered.join(", ") + "), so this application is " +
    "not fully configured for the flow this test is about to drive.");
  assert.strictEqual(Number(entry.authentications || 0), 0,
    "The application has authentications recorded before this test has " +
    "signed anybody in, so the counters below are somebody else's.");
  log.debug("Leaving registerApplication().");
  return entry;
}

// ---------------------------------------------------------------------------
// WHAT REALM 4 PUBLISHES AS A SAML 2.0 IDENTITY PROVIDER, read from realm 4.
//
// Asked for BY THE SERVICE PROVIDER'S entityID, because the mock mints
// per-service-provider identity provider metadata
// (`saml2.perApplicationEntityId`): a document fetched without that name
// carries a DIFFERENT entityID from the one assertions will actually arrive
// with, and `fedPeer` is checked against the Issuer — so the flow would be
// refused with "it was issued by somebody else".
// ---------------------------------------------------------------------------
async function readSaml2Metadata(bridgeBase, spEntityId) {
  log.debug("Entering readSaml2Metadata().");
  const url = bridgeBase + "/saml2/metadata/" + encodeURIComponent(spEntityId);
  const response = await fetch(url);
  assert.strictEqual(response.status, 200,
    "Realm 4 answered " + response.status + " for its own SAML 2.0 metadata " +
    "at " + url + ".");
  const xml = await response.text();
  const entityId = (xml.match(/entityID="([^"]+)"/) || [])[1] || "";
  const certificate = (xml.match(/<[^>]*X509Certificate>([^<]+)</) || [])[1] ||
                      "";
  const sso = (xml.match(
    /SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"[^>]*Location="([^"]+)"/
  ) || [])[1] || "";
  assert.ok(entityId && certificate && sso,
    "Realm 4's SAML 2.0 metadata is missing one of the three things a " +
    "service provider is configured from — entityID=\"" + entityId + "\", " +
    "certificate=" + (certificate ? certificate.length + " characters"
                                  : "(none)") +
    ", HTTP-Redirect SSO=\"" + sso + "\". The document begins: " +
    xml.slice(0, 300));
  assert.ok(sso.indexOf("/realm/" + BRIDGE_REALM + "/") >= 0,
    "Realm 4's metadata advertises an SSO endpoint outside its own realm (" +
    sso + "), which would send the AuthnRequest to a different identity " +
    "service from the one this test configured.");
  log.info("Realm 4 is a SAML 2.0 identity provider as " + entityId + ".");
  log.debug("Leaving readSaml2Metadata().");
  return { entityId: entityId, certificate: certificate, sso: sso };
}

// ---------------------------------------------------------------------------
// WHAT REALM 5 PUBLISHES AS A WS-FEDERATION IDENTITY PROVIDER.
//
// The passive requestor endpoint and the signing certificate come out of the
// federation metadata at AD FS's own path, for readSaml2Metadata()'s second
// reason: fetching the document proves that realm is up and answering as
// itself before anything is configured against it.
//
// THE entityID IS ALSO WHAT THE ASSERTION'S `Issuer` SAYS, which is not
// obvious and is worth pinning here rather than discovering at the assertion
// consumer service. The mock's WS-Federation profile wraps a SAML **1.1**
// assertion in the RSTR by default, and a SAML 1.1 assertion carries its
// issuer in an `Issuer` ATTRIBUTE rather than an `<Issuer>` element — so
// `fedPeer` below is compared against this string, and setting it to anything
// else refuses every token with "it was issued by somebody else".
// ---------------------------------------------------------------------------
async function readWsFedMetadata(idpBase) {
  log.debug("Entering readWsFedMetadata().");
  const url = idpBase + "/FederationMetadata/2007-06/FederationMetadata.xml";
  const response = await fetch(url);
  assert.strictEqual(response.status, 200,
    "Realm 5 answered " + response.status + " for its own WS-Federation " +
    "metadata at " + url + ".");
  const xml = await response.text();
  const entityId = (xml.match(/entityID="([^"]+)"/) || [])[1] || "";
  const certificate = (xml.match(/<[^>]*X509Certificate>([^<]+)</) || [])[1] ||
                      "";
  const passive = (xml.match(
    /<[^>]*Address>([^<]*\/wsfed)<\/[^>]*Address>/) || [])[1] || "";
  assert.ok(entityId && certificate && passive,
    "Realm 5's WS-Federation metadata is missing one of the three things a " +
    "service provider is configured from — entityID=\"" + entityId + "\", " +
    "certificate=" + (certificate ? certificate.length + " characters"
                                  : "(none)") +
    ", PassiveRequestorEndpoint=\"" + passive + "\". The document begins: " +
    xml.slice(0, 300));
  assert.ok(passive.indexOf("/realm/" + IDP_REALM + "/") >= 0,
    "Realm 5's metadata advertises a passive requestor endpoint outside its " +
    "own realm (" + passive + "), which would send the wsignin1.0 to a " +
    "different identity service from the one this test configured.");
  log.info("Realm 5 is a WS-Federation identity provider as " + entityId +
           ", passive endpoint " + passive + ".");
  log.debug("Leaving readWsFedMetadata().");
  return { entityId: entityId, certificate: certificate, sso: passive };
}

// ---------------------------------------------------------------------------
// A SERVICE-PROVIDER-SIDE RELATIONSHIP: the direction that CONSUMES.
//
// Two of the four records here are this shape — realm 3 consuming realm 4's
// SAML 2.0, and realm 4 consuming realm 5's WS-Federation — and they differ
// only in the protocol and in whose metadata filled them in, so they are one
// function. The order is the feature's own: create (which forces it DISABLED
// whatever the request says), fill in, then enable as a second deliberate act.
// ---------------------------------------------------------------------------
async function createServiceProviderSide(base, id, protocol, partner, what) {
  log.debug("Entering createServiceProviderSide(). id=" + id);
  await tidy(base, "/federation/delete", { id: id },
             "removing a relationship left behind by an earlier run");
  const created = await must(base, "/federation/create", {
    id: id,
    role: "service-provider",
    protocol: protocol,
    name: id,
    // CHECKED on the way in: a token whose issuer is not this string is
    // refused even when the signature verifies.
    peer: partner.entityId
  }, "registering " + what);

  // The one place this register overrides its input, and it is the whole
  // posture of the feature. The reply carries the raw entry, so this asserts
  // the ATTRIBUTE's own spelling rather than a boolean the view layer derived
  // — it is what every endpoint downstream actually reads.
  assert.strictEqual(String(created.relationship.fedEnabled), "FALSE",
    "A federation relationship must be created DISABLED whatever the request " +
    "said, and " + id + " came back with fedEnabled=" +
    created.relationship.fedEnabled + ".");
  assert.ok((created.readiness.missing || []).indexOf("fedSigningCertificate")
            >= 0,
    "A " + protocol + " service-provider-side relationship with nothing " +
    "configured should be missing fedSigningCertificate, and the mock says " +
    "it is missing: " + (created.readiness.missing || []).join(", ") + ". " +
    "The signature check is the whole gate on this surface, so a " +
    "relationship that is 'ready' without a certificate is the assertion " +
    "this test most needs to be able to make.");

  for (const [field, value] of [["fedSsoUrl", partner.sso],
                                ["fedSigningCertificate", partner.certificate],
                                ["fedPeer", partner.entityId]]) {
    await must(base, "/federation/set",
               { id: id, field: field, value: value },
               "setting " + field + " on " + id);
  }
  const enabled = await must(base, "/federation/enable", { id: id },
                             "enabling " + id);
  assert.ok(enabled.readiness.ready,
    "The relationship " + id + " is enabled and not ready: " +
    (enabled.readiness.missing || []).join(", ") + " still to configure. " +
    "Every federated endpoint would refuse rather than half-work.");
  log.info(what + " is enabled and ready.");
  log.debug("Leaving createServiceProviderSide().");
  return created;
}

// ---------------------------------------------------------------------------
// THE BRIDGE ITSELF: realm 4's IDENTITY-PROVIDER-side relationship with realm
// 3, carrying the mechanism that sends the person on to realm 5.
//
// THE HALF-CONFIGURED STEP IS ASSERTED RATHER THAN SKIPPED PAST. Setting
// `fedAuthnMechanism` to `federation` and stopping there is a relationship
// that says "authenticate these people somewhere else" and does not say
// where — which must be reported as a MISSING FIELD, exactly as a SAML
// relationship with no certificate is. It is the one state on this path where
// a service that guessed instead of refusing would silently fall back to a
// password box, and a password box at realm 4 is this entire feature not
// working while looking as though it did.
//
// THE APPLICATION ENTRY IS CREATED FIRST and it is not decoration: an
// identity-provider-side relationship stores a POINTER to
// `ou=applications` and nothing else about the partner, and it is by matching
// that pointer against the identifier the SAML 2.0 endpoint was given — realm
// 3's entityID — that the sign-in finds this relationship at all.
// ---------------------------------------------------------------------------
async function createBridgeRelationship(bridgeBase, spEntityId) {
  log.debug("Entering createBridgeRelationship().");
  await tidy(bridgeBase, "/applications/forget", { application: spEntityId },
             "removing realm 3's service provider entry from an earlier run");
  await must(bridgeBase, "/applications/create", {
    identifier: spEntityId,
    name: APP_REALM + " (SAML 2.0 service provider)",
    protocols: ["saml2"],
    fields: { samlEntityId: spEntityId }
  }, "registering realm 3 as a service provider in " + BRIDGE_REALM);

  await tidy(bridgeBase, "/federation/delete", { id: REL_4_FROM_3 },
             "removing the bridge relationship left by an earlier run");
  const created = await must(bridgeBase, "/federation/create", {
    id: REL_4_FROM_3,
    role: "identity-provider",
    protocol: "saml2",
    name: APP_REALM,
    peer: spEntityId,
    application: spEntityId
  }, "registering realm 4's identity-provider-side relationship with realm 3");
  assert.strictEqual(String(created.relationship.fedEnabled), "FALSE",
    "The identity-provider-side relationship must be created DISABLED too, " +
    "and it came back with fedEnabled=" + created.relationship.fedEnabled +
    ". Nothing about the direction changes that rule.");

  // THE HALF-CONFIGURED REFUSAL. Assert it BEFORE the field that completes it.
  const half = await must(bridgeBase, "/federation/set",
    { id: REL_4_FROM_3, field: "fedAuthnMechanism", value: "federation" },
    "setting the authentication mechanism to federation");
  assert.ok((half.readiness.missing || []).indexOf("fedAuthnRelationship") >= 0,
    "A relationship configured to authenticate through another federation " +
    "relationship, with none named, should report fedAuthnRelationship as " +
    "missing. The mock says it is missing: " +
    (half.readiness.missing || []).join(", ") + " — which is empty, so this " +
    "relationship would have been enabled while saying \"send them " +
    "elsewhere\" and not saying where.");

  await must(bridgeBase, "/federation/set",
    { id: REL_4_FROM_3, field: "fedAuthnRelationship", value: REL_4_TO_5 },
    "naming the relationship to broker on to");
  const enabled = await must(bridgeBase, "/federation/enable",
    { id: REL_4_FROM_3 }, "enabling the bridge relationship");
  assert.ok(enabled.readiness.ready,
    "The bridge relationship is enabled and not ready: " +
    (enabled.readiness.missing || []).join(", ") + " still to configure.");

  // And read it back off the entry, because the entry is what the sign-in
  // path reads and the reply is only what the action said it did.
  const view = await adminGet(bridgeBase,
    "/federation?relationship=" + encodeURIComponent(REL_4_FROM_3));
  const fields = view.fields || {};
  assert.strictEqual(fields.fedAuthnMechanism, "federation",
    "The bridge relationship's entry says fedAuthnMechanism=\"" +
    fields.fedAuthnMechanism + "\" and should say \"federation\".");
  assert.strictEqual(fields.fedAuthnRelationship, REL_4_TO_5,
    "The bridge relationship's entry brokers to \"" +
    fields.fedAuthnRelationship + "\" and should broker to \"" + REL_4_TO_5 +
    "\".");
  assert.strictEqual(String(view.application), spEntityId,
    "The bridge relationship points at the application \"" + view.application +
    "\" and must point at realm 3's entityID (" + spEntityId + "): that " +
    "pointer is the ONLY thing that connects an arriving AuthnRequest to " +
    "this relationship, so a sign-in would never find it.");
  log.info("Realm 4 will answer realm 3 by federating on to realm 5.");
  log.debug("Leaving createBridgeRelationship().");
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

// ---------------------------------------------------------------------------
// THE APPLICATION IN THE DEBUGGER'S OWN TERMS: fill in oauth2_oidc_1.html and
// stop just short of sending the authorization request.
//
// The request PREVIEW is what is read and asserted, not the hidden fields,
// because the preview is what the page actually navigates to — reading the
// fields would pass on a page that displays one thing and sends another.
// ---------------------------------------------------------------------------
async function prepareAuthorizationRequest(driver, appBase, callbackUri) {
  log.debug("Entering prepareAuthorizationRequest().");
  const grant = By.id("authorization_grant_type");
  const clientId = By.id("client_id");

  await driver.wait(until.elementLocated(grant), waitTime);
  // The Configuration Parameters pane is COLLAPSED once discovery has run, so
  // on any visit after the first the dropdown is present and invisible and
  // selecting from it is "element not interactable".
  if (!(await driver.findElement(grant).isDisplayed())) {
    await driver.findElement(By.id("config_expand_button")).click();
    await driver.wait(until.elementIsVisible(driver.findElement(grant)),
                      waitTime);
  }
  await new Select(await driver.findElement(grant))
    .selectByVisibleText("OIDC Authorization Code Flow(code)");

  await driver.wait(until.elementLocated(clientId), waitTime);
  if (!(await driver.findElement(clientId).isDisplayed())) {
    await driver.findElement(By.id("authz_expand_button")).click();
  }
  await driver.wait(until.elementIsVisible(driver.findElement(clientId)),
                    waitTime);

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

  // The preview is a whole request — `GET <url>?` and then one parameter per
  // line — so this looks for the endpoint inside it rather than at the front.
  assert.ok(preview.indexOf(appBase + "/oauth2/authorize") >= 0,
    "The page is about to send the authorization request to something other " +
    "than realm 3's authorization endpoint (" + appBase + "/oauth2/authorize" +
    "). It reads:\n" + preview);
  assert.ok(preview.indexOf("client_id=" + APPLICATION) >= 0,
    "The authorization request does not name " + APPLICATION + ", so nothing " +
    "downstream can look its federation relationship up. It reads:\n" +
    preview);
  log.info("The debugger will send: " + preview.split("\n")[0]);
  log.debug("Leaving prepareAuthorizationRequest().");
  return { preview: preview, nonce: nonce, state: state };
}

// ---------------------------------------------------------------------------
// REALM 5'S SIGN-IN SCREEN, WHICH IS NOT THE ONE EVERY OTHER TEST HERE DRIVES.
//
// WS-Federation's passive profile HAD a screen of its own inside `wsfed.js`
// until 2026-08-26, with `wsfed-login` / `wsfed-cancel` buttons rather than the
// Keycloak-shaped `kc-login` / `kc-cancel` that `authn.js`'s screen reuses —
// and that difference is what this test used to read to prove which screen it
// had reached. It goes through the shared funnel now (see
// federation_matrix_sso.js's header), so there is one screen, one button, and
// the thing to read is what the screen SAYS it is answering.
// ---------------------------------------------------------------------------
async function signInAtWsFed(driver, user) {
  log.debug("Entering signInAtWsFed(). user=" + user);
  const username = By.id("username");
  try {
    await driver.wait(until.elementLocated(username), waitTime * 4);
    await driver.wait(until.elementIsVisible(driver.findElement(username)),
                      waitTime);
  } catch (e) {
    const url = await driver.getCurrentUrl();
    const body = await driver.findElement(By.css("body")).getText();
    throw new Error("No sign-in screen appeared at the end of the chain. The " +
                    "browser is at " + url + " and the page says: " +
                    body.slice(0, 500));
  }
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  const passwords = await driver.findElements(By.id("password"));
  if (passwords.length) {
    await passwords[0].clear();
    await passwords[0].sendKeys("no password is checked here");
  }
  // `kc-login`, not `wsfed-login`: WS-Federation reaches the SHARED sign-in
  // screen since 2026-08-26 rather than drawing one of its own. See the note
  // beside the protocol assertion in test().
  await driver.findElement(By.id("kc-login")).click();
  log.debug("Leaving signInAtWsFed().");
}

// ---------------------------------------------------------------------------
// WHERE DOES A FRESH AUTHORIZATION REQUEST STOP?
//
// The mutation tests below all ask that one question, and they ask it by
// driving the browser at realm 3's authorization endpoint DIRECTLY rather than
// through oauth2_oidc_1.html. That is deliberate and it is not a shortcut:
// what each of them is about is a decision the MOCK makes, so putting the page
// in front of it would add a page's worth of ways to fail to an assertion that
// has nothing to do with the page. The happy path above is the one that has to
// go through the debugger, because there the application tier is the point.
//
// Cookies are cleared first — a session left by the previous walk would
// satisfy the request without any screen being drawn at all, and the answer
// would be "nowhere", every time, for all four mechanisms.
// ---------------------------------------------------------------------------
async function whereDoesTheSignInStop(driver, appBase, callbackUri, label) {
  log.debug("Entering whereDoesTheSignInStop(). " + label);
  await clearSessionsAt(driver, appBase);
  const url = appBase + "/oauth2/authorize?response_type=code" +
    "&client_id=" + encodeURIComponent(APPLICATION) +
    "&redirect_uri=" + encodeURIComponent(callbackUri) +
    "&scope=" + encodeURIComponent("openid") +
    "&state=chain-mutation&nonce=chain-mutation";
  await driver.get(url);
  await driver.wait(until.elementLocated(By.id("username")), waitTime * 5,
    "No sign-in screen appeared for the \"" + label + "\" case. Something " +
    "answered the authorization request without asking anybody who they are.");
  const at = await driver.getCurrentUrl();
  const source = await driver.getPageSource();
  // ---------------------------------------------------------------------
  // THE TWO BOXES ARE READ OFF THE DOM AND NOT OFF THE PAGE SOURCE, and that
  // is not a preference. `getPageSource()` returns Chrome's SERIALIZATION of
  // the parsed document, not the bytes the mock sent: a bare `checked
  // disabled` in the markup comes back as `checked="" disabled=""`, so a
  // regex written against what the server actually emits matches nothing and
  // this reads as "the mechanism did not lock the box" for every mechanism.
  // It cost a run. isSelected() and the disabled property are what a person
  // clicking the box would meet, which is the thing being asserted anyway.
  const boxState = async function (id) {
    const found = await driver.findElements(By.id(id));
    if (!found.length) {
      return { present: false, locked: false };
    }
    const ticked = await found[0].isSelected();
    const disabled = await driver.executeScript(
      "return arguments[0].disabled === true;", found[0]);
    return { present: true, locked: !!(ticked && disabled) };
  };
  const mfa = await boxState("use_webauthn");
  const passwordless = await boxState("webauthn_only");
  const where = {
    url: at,
    realm: (at.match(/\/realm\/([^/?]+)/) || [])[1] || "(none)",
    // WHAT THIS SCREEN SAYS IT IS ANSWERING, which is the shared screen's own
    // line built from `beginAuthentication`'s `protocol` argument. It replaced
    // a check on `wsfed-login` when that profile stopped drawing a screen of
    // its own — see the note above signInAtWsFed().
    protocol: (source.match(
      /Signing in for:\s*<code>([^<]+)<\/code>/) || [])[1] || "",
    wsfed: /Signing in for:\s*<code>WS-Federation<\/code>/.test(source),
    local: source.indexOf("kc-login") >= 0,
    mfaLocked: mfa.locked,
    passwordlessLocked: passwordless.locked,
    problem: ((await driver.findElements(By.css("div.err"))).length
      ? await (await driver.findElement(By.css("div.err"))).getText() : "")
  };
  log.info(label + ": stopped in " + where.realm +
           (where.local
              ? " at a sign-in screen answering " +
                (where.protocol || "(an unnamed protocol)")
              : " at something that is not a sign-in screen") +
           (where.problem ? " — \"" + where.problem.slice(0, 90) + "\"" : ""));
  log.debug("Leaving whereDoesTheSignInStop().");
  return where;
}

// ---------------------------------------------------------------------------
// AND THE MECHANISM ITSELF, BY CHANGING IT.
//
// Every assertion in the happy path would pass just as well against a mock
// that chained on to realm 5 for reasons of its own — a hard-coded partner, a
// leftover `appFederationRelationship`, a bug. These four cases are what make
// it fall over when the attribute stops working, and each one fails
// DIFFERENTLY:
//
//   * `password` must put realm 4's own screen back. This is the mutation test
//     for the whole feature: if the chain still reaches realm 5 here, then
//     something other than fedAuthnMechanism is doing the brokering and every
//     assertion above is about that instead.
//   * `password-mfa` and `webauthn` must reach the same screen with a
//     DIFFERENT box ticked and locked. The ceremony itself is not run — a
//     security key needs a virtual authenticator this suite does not stand up
//     for a federation test — but which box the screen locks is the whole of
//     what the mechanism decides before the ceremony starts.
//   * a mechanism pointing at a DISABLED relationship must name that on the
//     screen, and NOT quietly ask for a password: a broker that has stopped
//     brokering looks exactly like one that never was.
//   * a value that is not one of the four must be named as not one of the
//     four, in `readiness.missing` and on the screen. A mock that ignored an
//     unknown value would turn a typo into a silent fallback, which is this
//     feature failing in the one way nobody would look for.
//
// Everything is restored in a `finally`, because the realms outlive this
// process.
// ---------------------------------------------------------------------------
async function theMechanismIsWhatDecides(driver, bridgeBase, appBase,
                                         callbackUri) {
  log.debug("Entering theMechanismIsWhatDecides().");
  const set = async function (field, value, what) {
    await must(bridgeBase, "/federation/set",
               { id: REL_4_FROM_3, field: field, value: value }, what);
  };
  try {
    await set("fedAuthnMechanism", "password",
              "setting the mechanism to password");
    let stop = await whereDoesTheSignInStop(driver, appBase, callbackUri,
                                            "mechanism=password");
    assert.strictEqual(stop.realm, BRIDGE_REALM,
      "With the mechanism set to `password`, realm 4 must ask for the " +
      "password ITSELF and the browser stopped in \"" + stop.realm + "\" (" +
      stop.url + "). If that is realm 5, something other than " +
      "fedAuthnMechanism is brokering this sign-in and every assertion in " +
      "this test is about that instead.");
    assert.ok(stop.local && !stop.wsfed,
      "With the mechanism set to `password` the screen at realm 4 should be " +
      "answering realm 3's SAML 2.0 request rather than a wsignin1.0 it " +
      "brokered onward (sign-in screen present=" + stop.local +
      ", it says it is signing in for \"" + stop.protocol + "\").");
    assert.ok(!stop.mfaLocked && !stop.passwordlessLocked,
      "The plain password screen has a box ticked and locked (mfa=" +
      stop.mfaLocked + ", passwordless=" + stop.passwordlessLocked + "), so " +
      "`password` is not producing the ordinary screen.");

    await set("fedAuthnMechanism", "password-mfa",
              "setting the mechanism to password-mfa");
    stop = await whereDoesTheSignInStop(driver, appBase, callbackUri,
                                        "mechanism=password-mfa");
    assert.strictEqual(stop.realm, BRIDGE_REALM,
      "With the mechanism set to `password-mfa` the sign-in must stay at " +
      "realm 4 and it went to \"" + stop.realm + "\".");
    assert.ok(stop.mfaLocked,
      "With `password-mfa` configured, realm 4's screen must offer the " +
      "second factor TICKED AND LOCKED — a second factor the person can " +
      "untick is not a configured mechanism. The screen at " + stop.url +
      " does not.");
    assert.ok(!stop.passwordlessLocked,
      "`password-mfa` locked the PASSWORDLESS box, which is one factor and " +
      "the opposite of what was asked for.");

    await set("fedAuthnMechanism", "webauthn",
              "setting the mechanism to webauthn");
    stop = await whereDoesTheSignInStop(driver, appBase, callbackUri,
                                        "mechanism=webauthn");
    assert.strictEqual(stop.realm, BRIDGE_REALM,
      "With the mechanism set to `webauthn` the sign-in must stay at realm 4 " +
      "and it went to \"" + stop.realm + "\".");
    assert.ok(stop.passwordlessLocked,
      "With `webauthn` configured, realm 4's screen must offer the " +
      "passwordless security key TICKED AND LOCKED, and the screen at " +
      stop.url + " does not.");
    assert.ok(!stop.mfaLocked,
      "`webauthn` locked the SECOND-FACTOR box as well, which would mean a " +
      "password step this mechanism says there is not.");

    // A value that is not one of the four. The set is ACCEPTED — the register
    // stores what an operator typed and reports what it thinks of it, rather
    // than refusing the write and leaving the entry holding the last good
    // value while the form says otherwise — and readiness is what names it.
    const bad = await must(bridgeBase, "/federation/set",
      { id: REL_4_FROM_3, field: "fedAuthnMechanism", value: "carrier-pigeon" },
      "setting the mechanism to something that is not a mechanism");
    assert.ok((bad.readiness.missing || []).some(function (one) {
      return /fedAuthnMechanism/.test(one) && /carrier-pigeon/.test(one);
    }), "A mechanism of \"carrier-pigeon\" should be reported as not one " +
        "this service has, and readiness says: " +
        JSON.stringify(bad.readiness.missing) + ". An unrecognised value " +
        "that reads as ready is a typo turned into a silent fallback to a " +
        "password box.");
    stop = await whereDoesTheSignInStop(driver, appBase, callbackUri,
                                        "mechanism=carrier-pigeon");
    assert.strictEqual(stop.realm, BRIDGE_REALM,
      "An unrecognised mechanism sent the sign-in to \"" + stop.realm +
      "\" rather than falling back to realm 4's own screen.");
    assert.ok(/carrier-pigeon/.test(stop.problem),
      "An unrecognised mechanism must be NAMED on the screen it falls back " +
      "to, and the screen at " + stop.url + " says \"" + stop.problem + "\". " +
      "A silent fallback here is the feature failing in the one way nobody " +
      "would go looking for.");

    // Back to `federation`, and then break what it points AT.
    await set("fedAuthnMechanism", "federation",
              "putting the mechanism back to federation");
    await must(bridgeBase, "/federation/set",
      { id: REL_4_TO_5, field: "fedEnabled", value: "FALSE" },
      "disabling the relationship the bridge brokers to");
    try {
      stop = await whereDoesTheSignInStop(driver, appBase, callbackUri,
                                          "brokering to a DISABLED partner");
      assert.strictEqual(stop.realm, BRIDGE_REALM,
        "With the onward relationship disabled the sign-in reached \"" +
        stop.realm + "\", so a disabled relationship is still being used.");
      assert.ok(/DISABLED/i.test(stop.problem) &&
                stop.problem.indexOf(REL_4_TO_5) >= 0,
        "A bridge whose onward relationship is DISABLED must say so on the " +
        "screen it falls back to, naming that relationship. The screen at " +
        stop.url + " says \"" + stop.problem + "\". Falling silently back to " +
        "a password box is a broker that has stopped brokering looking " +
        "exactly like one that is working.");
    } finally {
      await must(bridgeBase, "/federation/enable", { id: REL_4_TO_5 },
                 "re-enabling the relationship the bridge brokers to");
    }

    // And the chain is whole again — asserted, because a `finally` that
    // restores something is worth nothing if nothing checks that it did.
    stop = await whereDoesTheSignInStop(driver, appBase, callbackUri,
                                        "restored");
    assert.strictEqual(stop.realm, IDP_REALM,
      "After restoring the mechanism the chain should reach realm 5 again " +
      "and it stopped in \"" + stop.realm + "\".");
    assert.ok(stop.wsfed,
      "The restored chain reached realm 5 and the screen there says it is " +
      "signing in for \"" + stop.protocol + "\" rather than for " +
      "WS-Federation, so the second hop used some other protocol.");
  } finally {
    await adminPost(bridgeBase, "/federation/set",
      { id: REL_4_FROM_3, field: "fedAuthnMechanism", value: "federation" });
    await adminPost(bridgeBase, "/federation/set",
      { id: REL_4_FROM_3, field: "fedAuthnRelationship", value: REL_4_TO_5 });
    await adminPost(bridgeBase, "/federation/enable", { id: REL_4_TO_5 });
  }
  log.debug("Leaving theMechanismIsWhatDecides().");
}

// Whether this mock is new enough to have the attribute this test is about.
// Read off the schema that service publishes rather than off a version string:
// the submodule is bumped by hand, and a job that failed on a stale checkout
// would name a missing element on a sign-in screen three redirects away.
async function mockKnowsTheMechanism(stsBase) {
  log.debug("Entering mockKnowsTheMechanism().");
  const response = await fetch(stsBase + "/ldap/federations",
                               { headers: { Accept: "application/json" } });
  if (response.status !== 200) {
    log.debug("Leaving mockKnowsTheMechanism(). " + response.status);
    return false;
  }
  const text = await response.text();
  const knows = text.indexOf("fedAuthnMechanism") >= 0 &&
                text.indexOf("fedAuthnRelationship") >= 0;
  log.debug("Leaving mockKnowsTheMechanism(). " + knows);
  return knows;
}

// ---------------------------------------------------------------------------
// THE TWO THINGS THAT WEAR `a.fedbtn`, AND WHY THIS FUNCTION EXISTS.
//
// The mock's sign-in screen styles two OFFERS with the same class. The
// federation partners are the ones this test is about: one per usable
// relationship, each leading to `/federation/login/<id>`. Under them sits the
// Kerberos door — `integratedOptionHtml()`'s SPNEGO link, offered to every
// application on every screen with nothing configured anywhere, because the
// mechanism is a property of the person's machine rather than of the relying
// party. A class is what a button LOOKS like and an href is what it DOES, so
// the counting above reads the href.
//
// This is the other half of that: a narrowed selector stops seeing anything
// that arrives under a different href, so everything else wearing the class
// has to be accounted for by name. Anything that is neither a partner nor the
// Kerberos door is a button this screen should not be drawing at all.
// ---------------------------------------------------------------------------
async function assertOnlyOtherButtonIsKerberos(driver, where) {
  log.debug("Entering assertOnlyOtherButtonIsKerberos().");
  const buttons = await driver.findElements(By.css("a.fedbtn"));
  for (const button of buttons) {
    const href = await button.getAttribute("href");
    if (href.indexOf("/federation/login/") >= 0) {
      continue;
    }
    assert.ok(href.indexOf("/authn/spnego") >= 0,
      where + " carries a button styled like a federation partner that " +
      "points at \"" + href + "\". It is neither a partner nor the ambient " +
      "Kerberos door, so it is an offer this screen should not be making.");
  }
  log.debug("Leaving assertOnlyOtherButtonIsKerberos(). " + buttons.length +
            " button(s) on the screen.");
}

function b64uJson(part) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

async function test() {
  log.debug("Entering test().");
  const stsUrl = process.env.WSTRUST_STS_URL || "";
  if (!stsUrl) {
    log.info("SKIPPED: WSTRUST_STS_URL is not set, so there is no mock STS " +
             "to build three trust realms in. This test needs that service " +
             "and nothing else.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const stsBase = stsUrl.replace(/\/sts\/?$/, "");
  if (!(await mockKnowsTheMechanism(stsBase))) {
    log.info("SKIPPED: the mock STS at " + stsBase + " does not publish " +
             "fedAuthnMechanism in its federation schema, so it predates the " +
             "attribute that lets one federation relationship authenticate " +
             "through another. Bump the sts/ submodule.");
    log.debug("Leaving test(). Skipped, the mock is too old.");
    return;
  }
  const appBase = stsBase + "/realm/" + APP_REALM;
  const bridgeBase = stsBase + "/realm/" + BRIDGE_REALM;
  const idpBase = stsBase + "/realm/" + IDP_REALM;
  const callbackUri = baseUrl + "/callback";
  const user = usernameFor("chain");

  // ---------------------------------------------------------------------
  // CONFIGURATION FIRST, with no browser open. Every step is a management API
  // call and every one of them is asserted: a setup step that quietly does
  // nothing is worse than none, because the flow below would then be testing
  // whatever the mock happened to be configured with.
  // ---------------------------------------------------------------------
  await createRealms(stsBase);
  await registerApplication(appBase, callbackUri);

  // Realm 3's identity as a SAML 2.0 service provider IS its assertion
  // consumer service URL, which is how `federation_sp.js` names itself in the
  // <Issuer> it sends. Everything realm 4 knows about realm 3 hangs off this
  // one string.
  const spEntityId = appBase + "/federation/acs/" + REL_3_TO_4;

  const saml2Partner = await readSaml2Metadata(bridgeBase, spEntityId);
  const wsfedPartner = await readWsFedMetadata(idpBase);

  await createServiceProviderSide(appBase, REL_3_TO_4, "saml2", saml2Partner,
    "realm 3's SAML 2.0 relationship with realm 4");
  await createServiceProviderSide(bridgeBase, REL_4_TO_5, "wsfed",
    wsfedPartner, "realm 4's WS-Federation relationship with realm 5");
  await createBridgeRelationship(bridgeBase, spEntityId);

  // ---------------------------------------------------------------------
  // THE SHAPE OF THE REGISTER, before anybody signs in. Three realms, four
  // relationships, and the one at the bottom has none — which is what makes
  // this a CHAIN with an end rather than a loop.
  // ---------------------------------------------------------------------
  const idpRegister = await adminGet(idpBase, "/federation");
  assert.strictEqual((idpRegister.relationships || []).length, 0,
    "Realm 5 has " + (idpRegister.relationships || []).length + " federation " +
    "relationship(s) of its own. It is supposed to be an ordinary identity " +
    "provider that has never heard of federation — the END of the chain, and " +
    "the only party in it that checks anything about a person.");

  const bridgeRegister = await adminGet(bridgeBase, "/federation");
  const roles = (bridgeRegister.relationships || []).map(function (one) {
    return one.role;
  }).sort();
  assert.deepStrictEqual(roles, ["identity-provider", "service-provider"],
    "Realm 4 should hold exactly one relationship in each direction — it " +
    "CONSUMES from realm 5 and ASSERTS to realm 3, and being both at once is " +
    "the whole of what an identity bridge is. It holds: " +
    JSON.stringify((bridgeRegister.relationships || []).map(function (one) {
      return one.id + "/" + one.role;
    })));

  // The registries are per realm, so realm 4 and realm 5 have never heard of
  // the application. Without that these are one identity service with three
  // URL prefixes and nothing below means anything.
  for (const [where, base] of [[BRIDGE_REALM, bridgeBase],
                               [IDP_REALM, idpBase]]) {
    const overThere = await adminGet(base,
      "/applications?application=" + encodeURIComponent(APPLICATION));
    assert.ok(!overThere.found,
      "Realm \"" + where + "\" knows the application " + APPLICATION +
      ", which only " + APP_REALM + " registered. The directory is supposed " +
      "to be per trust realm.");
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

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    log.info("Signing in as " + user + " at " + idpBase + ", for an " +
             "application registered at " + appBase + ", through the bridge " +
             "at " + bridgeBase + ".");
    await driver.manage().deleteAllCookies();
    await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                   "authorization_grant_type", { timeout: waitTime * 5 });
    // A previous job's state in localStorage would otherwise decide which
    // panes oauth2_oidc_2.html draws, which is where the tokens are read from.
    await driver.executeScript("window.localStorage.clear();");
    await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                   "authorization_grant_type", { timeout: waitTime * 5 });
    // Nearly every control on these pages is an inline handler naming a
    // browserify --standalone global, so a click before the bundle has run is
    // a silent no-op rather than an error.
    await waitForPageBundle(driver);

    // Realm 3's discovery document — which is what makes it an ordinary
    // OpenID Provider to the application. Nothing in it mentions federation,
    // and that is the point rather than an omission.
    const discovery = appBase + "/.well-known/openid-configuration";
    await populateMetadata(driver, discovery);
    const metadata = await (await fetch(discovery)).json();
    assert.strictEqual(metadata.issuer, appBase,
      "Realm 3 publishes issuer \"" + metadata.issuer + "\" rather than \"" +
      appBase + "\". The mock derives an issuer from the base URL a request " +
      "arrived on, and a realm's base URL carries its prefix — a " +
      "process-wide STS_OAUTH2_ISSUER pin would override all three realms " +
      "with one name, " +
      "and then \"which realm issued this\" has no answer.");

    const sent = await prepareAuthorizationRequest(driver, appBase,
                                                   callbackUri);

    // ---------------------------------------------------------------------
    // AWAY IT GOES, AND IT DOES NOT STOP FOR TWO WHOLE IDENTITY SERVICES.
    //
    // One click, and the browser passes through realm 3 (which federates on
    // sight of the application entry) and realm 4 (which federates on sight of
    // its own relationship's mechanism) without either drawing a screen.
    // ---------------------------------------------------------------------
    await driver.findElement(
      By.css("input[type=\"submit\"][value=\"Authorize\"]")).click();
    await driver.wait(until.elementLocated(By.id("username")), waitTime * 6,
      "No sign-in screen appeared after the authorization request. None of " +
      "the three realms drew one, so the chain went somewhere unexpected.");
    const screenUrl = await driver.getCurrentUrl();
    assert.ok(screenUrl.indexOf("/realm/" + IDP_REALM + "/") >= 0,
      "The person should have been carried all the way to realm 5 to sign " +
      "in, and the browser is at " + screenUrl + ".");
    assert.ok(screenUrl.indexOf("/realm/" + APP_REALM + "/") === -1,
      "The browser is at one of realm 3's own URLs (" + screenUrl + "), so " +
      "realm 3 asked for the password itself instead of federating.");
    assert.ok(screenUrl.indexOf("/realm/" + BRIDGE_REALM + "/") === -1,
      "The browser stopped at realm 4 (" + screenUrl + "). That realm is " +
      "supposed to be a BRIDGE — it authenticates nobody and has no screen " +
      "to show — so a sign-in screen there is the second hop not happening, " +
      "which is precisely what fedAuthnMechanism exists to do.");
    log.info("One click carried the browser through realm 3 and realm 4 to " +
             "realm 5: " + screenUrl);

    const screen = await driver.getPageSource();
    // THE PROTOCOL OF THE SECOND HOP, in one string — and it used to be a
    // different string. Until 2026-08-26 this asserted on `wsfed-login`, the
    // button on the sign-in screen `wsfed.js` drew for itself, against
    // `kc-login`, which `authn.js`'s screen has always had. That profile goes
    // through the shared funnel now (see federation_matrix_sso.js's header for
    // why: owning a screen meant owning the funnel, and three features that
    // live in the funnel were inert for WS-Federation alone), so BOTH halves of
    // that assertion are now false for a service that is working — there is one
    // screen and its button is `kc-login`.
    //
    // What replaces it is what the shared screen SAYS. It prints the protocol
    // it was reached for, from `beginAuthentication`'s `protocol` argument, and
    // it prints the caller's own parameters from `details` — so `wtrealm` on a
    // screen is still the evidence that a wsignin1.0 is what is being answered.
    // The two together are a stronger statement than the button was: a button
    // is a fact about which module rendered a page, and these are facts about
    // which request it is answering.
    assert.ok(/Signing in for:\s*<code>WS-Federation<\/code>/.test(screen),
      "Realm 5's screen does not say it is signing somebody in for " +
      "WS-Federation, so realm 4 reached it over some other protocol than " +
      "the one its relationship is configured for.");
    assert.ok(/wtrealm/.test(screen),
      "Realm 5's screen does not mention a wtrealm, so it is not answering a " +
      "wsignin1.0 from realm 4.");
    // And realm 5 offers no partners of its own: the three realms run one
    // codebase and differ only in configuration.
    //
    // THE SELECTOR IS THE HREF AND NOT THE CLASS, and that distinction cost a
    // run on 2026-08-27. `a.fedbtn` is a STYLE the mock's sign-in screen puts
    // on the federation partners AND on the ambient Kerberos door beneath
    // them, which is offered on every screen with nothing configured anywhere
    // (`krb5.spnegoLoginButton`, on by default). Counting the class made that
    // one button read as a partner realm 5 does not have. See
    // assertOnlyOtherButtonIsKerberos() for the other half of the check.
    const partnerButtons = await driver.findElements(
      By.css("a.fedbtn[href*=\"/federation/login/\"]"));
    assert.strictEqual(partnerButtons.length, 0,
      "Realm 5's screen offers " + partnerButtons.length + " federation " +
      "partner(s). It is the end of the chain and has no relationships.");
    await assertOnlyOtherButtonIsKerberos(driver, "Realm 5's screen");

    await signInAtWsFed(driver, user);

    // ---------------------------------------------------------------------
    // AND BACK, THROUGH BOTH OF THEM. The browser goes realm 5 → realm 4's
    // assertion consumer service → realm 4's SAML 2.0 SSO endpoint → realm 3's
    // assertion consumer service → realm 3's authorization endpoint → the
    // debugger's callback, and the application sees only the last of those.
    // ---------------------------------------------------------------------
    await driver.wait(until.urlContains("/oauth2_oidc_2.html"), waitTime * 10,
      "The flow never came back to the debugger after the sign-in at realm " +
      "5. There are two assertion consumer services and two auto-submitting " +
      "forms between there and here, and any of them may have refused.");
    const returned = new URL(await driver.getCurrentUrl());
    const code = returned.searchParams.get("code");
    assert.ok(code,
      "No authorization code came back to the application. The browser is at " +
      returned.toString() + ".");
    assert.strictEqual(returned.searchParams.get("state"), sent.state,
      "The state did not come back unchanged.");
    log.info("The application received an authorization code after a " +
             "three-protocol chain.");

    // ---------------------------------------------------------------------
    // WHAT THE FLOW LEFT BEHIND, read before the code is redeemed so that the
    // counts are about the SIGN-IN rather than about the token call.
    //
    // BOTH consuming relationships counted exactly one, which is the arithmetic
    // that says the chain ran once end to end rather than, say, realm 4
    // answering out of a session it already had.
    // ---------------------------------------------------------------------
    for (const [what, base, id] of [
        ["realm 3's SAML 2.0 relationship with realm 4", appBase, REL_3_TO_4],
        ["realm 4's WS-Federation relationship with realm 5", bridgeBase,
         REL_4_TO_5]]) {
      const after = await relationshipNow(base, id);
      assert.strictEqual(Number(after.authentications || 0), 1,
        what + " counted " + after.authentications + " federated sign-in(s) " +
        "and this test performed exactly one.");
      assert.ok(!String(after.lastError || "").trim(),
        what + " recorded a failure during a sign-in that succeeded: " +
        after.lastError);
      assert.ok(String(after.lastUser || "").indexOf(user) >= 0,
        what + "'s last user is \"" + after.lastUser + "\" and this test " +
        "signed in as \"" + user + "\".");
    }
    log.info("Both consuming relationships counted exactly one sign-in, by " +
             user + ", with no refusal recorded.");

    // ---------------------------------------------------------------------
    // AND THE PERSON EXISTS IN ALL THREE, which is the directory half of what
    // a chain does: one name typed once produces an entry at every service it
    // passed through, and only the last of them ever drew a password field.
    // ---------------------------------------------------------------------
    for (const [where, base] of [[APP_REALM, appBase],
                                 [BRIDGE_REALM, bridgeBase],
                                 [IDP_REALM, idpBase]]) {
      const users = await adminGet(base,
        "/users?q=" + encodeURIComponent(user));
      assert.ok((users.users || []).some(function (one) {
        return String(one.name) === user || String(one.key) === user;
      }), "Realm \"" + where + "\" has no directory entry for " + user +
          ", who has just signed in through it. It lists: " +
          (users.users || []).map(function (o) { return o.name; }).join(", "));
    }
    // And the two upstream realms record HOW they got them. A person whose
    // password was never checked there must be distinguishable from one whose
    // was, or a federated directory is indistinguishable from a local one.
    for (const [where, base] of [[APP_REALM, appBase],
                                 [BRIDGE_REALM, bridgeBase]]) {
      const users = await adminGet(base,
        "/users?q=" + encodeURIComponent(user));
      assert.ok((users.protocols || []).some(function (one) {
        return /Federation/i.test(String(one));
      }), "Realm \"" + where + "\" does not record " + user + " as having " +
          "arrived through federation. It says: " +
          (users.protocols || []).join(", ") + ". Neither of these two " +
          "realms ever saw a password for this person.");
    }
    log.info("All three realms hold an entry for " + user + ", and the two " +
             "that never checked a password say so.");

    // ---------------------------------------------------------------------
    // REDEEM THE CODE THROUGH THE PAGE, because the application is what this
    // test is standing in for and the Token Request is the application's own
    // call. Browser-direct rather than through the api, so this job needs the
    // client and the mock and nothing else.
    // ---------------------------------------------------------------------
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
          throw new Error("Realm 3's token endpoint refused the code: " + text);
        }
      }
      return false;
    }, waitTime * 6, "The code never became an ID Token.");

    // ---------------------------------------------------------------------
    // THE ASSERTION THE WHOLE FEATURE IS FOR, AND IT IS STRONGER HERE THAN IT
    // IS ONE LAYER UP.
    //
    // The application asked ONE provider ONE question and got ONE answer.
    // `federation_sso.js` makes the same claim about ONE hidden identity
    // service; this makes it about TWO, one of which spoke a protocol the
    // application does not implement and the other of which authenticated
    // over a third. If any of that leaked, it would leak as a realm name in a
    // claim — an issuer, an `amr`, an `idp` — so the whole payload is searched
    // rather than the fields somebody thought to check.
    // ---------------------------------------------------------------------
    const claims = b64uJson(idToken.split(".")[1]);
    assert.strictEqual(claims.iss, appBase,
      "The application's ID Token says it was issued by \"" + claims.iss +
      "\". It must be realm 3: the application asked realm 3 and realm 3 is " +
      "what answered.");
    assert.strictEqual(claims.nonce, sent.nonce,
      "The ID Token carries nonce \"" + claims.nonce + "\", not the one the " +
      "page sent.");
    assert.ok([].concat(claims.aud || []).indexOf(APPLICATION) >= 0,
      "The ID Token's aud is " + JSON.stringify(claims.aud) + " and should " +
      "name " + APPLICATION + ".");
    assert.ok(JSON.stringify(claims).indexOf(BRIDGE_REALM) === -1,
      "The application's ID Token mentions " + BRIDGE_REALM + ": " +
      JSON.stringify(claims) + ". The bridge is the one party in this chain " +
      "with no business being visible anywhere.");
    assert.ok(JSON.stringify(claims).indexOf(IDP_REALM) === -1,
      "The application's ID Token mentions " + IDP_REALM + ": " +
      JSON.stringify(claims) + ". Which identity service actually checked " +
      "anything is not the application's business, and this is the one " +
      "property the whole feature exists to have.");
    assert.ok(
      String(claims.preferred_username || claims.sub).indexOf(user) >= 0,
      "The ID Token describes \"" + (claims.preferred_username || claims.sub) +
      "\" and the name typed at realm 5 was \"" + user + "\".");
    log.info("The application holds an ID Token issued by " + claims.iss +
             " describing " + (claims.preferred_username || claims.sub) +
             ", naming neither realm 4 nor realm 5.");

    // And the mechanism itself, four ways, by changing it.
    await theMechanismIsWhatDecides(driver, bridgeBase, appBase, callbackUri);

    log.info("Test completed successfully.");
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

const program = new Command();
program
  .name("federation_chain_sso")
  .description("An N-layer federated sign-in across three trust realms of " +
               "one mock STS — OIDC to realm 3, SAML 2.0 on to realm 4, " +
               "WS-Federation on to realm 5 — with realm 4 acting as a pure " +
               "identity bridge between two protocols.")
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
