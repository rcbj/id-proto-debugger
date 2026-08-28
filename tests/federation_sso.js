// File: federation_sso.js
//
// ===========================================================================
// A FEDERATED SIGN-IN, END TO END, THROUGH TWO TRUST REALMS OF ONE MOCK STS.
//
// The debugger's OAuth2 / OIDC workflow stands in for a web application called
// `webapp-sso-test1`. It asks ONE authorization server for ONE code, and the
// fact that a SECOND identity service actually authenticated the person is
// invisible to it — which is the property federation exists for and the thing
// this test is really about.
//
//   browser ──▶ oauth2_oidc_1.html                 the application
//             └─▶ /realm/federation-realm-1        an OpenID Provider to the
//                                                  application, and a SAML 2.0
//                                                  SERVICE PROVIDER of the
//                                                  federation relationship
//               └─▶ /realm/federation-realm-2      the SAML 2.0 identity
//                                                  provider, and the only place
//                                                  a name is ever typed
//
// ---------------------------------------------------------------------------
// WHY TWO REALMS AND NOT TWO CONTAINERS
//
// This test replaces `federation-e2e/` in the mock STS submodule, which built
// the same shape out of THREE CONTAINERS — two identity services and a web
// application of its own — with a compose file, a Dockerfile, a configure
// script, a driver and a hand-written HTTP client behind it. Trust realms make
// all of that scaffolding unnecessary: a realm is a whole logical copy of that
// service (its own signing key, sessions, tokens, applications, federation
// register and directory subtree) reached on the same socket under a path
// prefix, so ONE running mock is two identity services here. The suite already
// starts that mock for thirty other jobs, so this job costs a process nobody
// has to start and a topology nobody has to tear down.
//
// The application tier does not need inventing either: the debugger IS a web
// application that has never heard of federation, which is exactly the third
// party the old test had to build one to get.
//
// WHAT THAT COSTS, said plainly. The old stack had two DNS names and two
// origins, so it could prove that a back-channel URL is dialled by the service
// and a front-channel URL by the browser — the distinction that makes
// federating between containers hard. Here both realms are the same origin, so
// that distinction does not exist and this test cannot make it. The trade is
// deliberate: what it buys back is that this runs in the ordinary suite, on
// every stack, in a few seconds.
//
// It also buys a distinction the old one could not make. Both realms are the
// same ORIGIN, so the browser has one cookie jar for both — and the mock's
// session cookie has one name. A session minted in realm 2 is therefore
// PRESENTED to realm 1 and must not be honoured there, because the session
// store is per realm. That is asserted below: the person who has just signed in
// at realm 2 is, to realm 1, somebody with no session at all until the
// assertion arrives.
//
// ---------------------------------------------------------------------------
// WHAT IS CONFIGURED BEFORE ANYTHING RUNS, AND WHY ALL OF IT
//
// Every other protocol in the mock works with nothing provisioned: point a SAML
// service provider at /saml2 and its metadata is minted on the ask, send any
// client_id to the token endpoint and a token comes back. This test provisions
// anyway — the realms, the application, the relationship — because the mock is
// growing a mode that REQUIRES an application to be configured before it is
// used, and a test written against the permissive path would have to be
// rewritten the day that lands.
//
// Federation is already the exception that has to be configured: a relationship
// is created DISABLED and an assertion is refused unless it verifies against
// the certificate on the entry. That is asserted here rather than assumed —
// `create` answering with `enabled: false` is the one place this register
// overrides its input, and a test that skipped past it would not notice the day
// it stopped.
//
// ---------------------------------------------------------------------------
// WHAT TIES THE APPLICATION TO THE PARTNER
//
// `appFederationRelationship` on the application entry, and
// `appFederationAutoRedirect` beside it. Before those existed a federated
// sign-in was something a PERSON chose, from a button at the foot of the mock's
// sign-in screen — home realm discovery performed by the user, once per
// sign-in, which is not what a deployment with one federated identity provider
// does. With the attribute set, `authn.js` sends the browser straight on to the
// partner and the sign-in screen is never drawn.
//
// The last section of this test CLEARS that attribute and runs the same
// authorization request again, which must then reach realm 1's own sign-in
// screen. Without that, every assertion above it would pass just as well
// against a mock that federated every sign-in for its own reasons — and a
// test that cannot fail when the feature is removed is not testing the feature.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS, AND WHY NOT "DID A TOKEN COME BACK"
//
// A federated sign-in that ends with an access token is not evidence of much:
// every interesting failure here produces one. So the assertions are about the
// SHAPE of the flow and the STATE left behind —
//
//   * the trail crosses realm 1 → realm 2 and returns through
//     /realm/federation-realm-1/federation/acs/{id};
//   * realm 1's OWN sign-in screen is never drawn, and realm 2's is;
//   * realm 2 offers no federation partner of its own — the two realms run one
//     codebase and differ only in configuration;
//   * the application's ID Token says `iss: …/realm/federation-realm-1`, and
//     nothing in it names realm 2;
//   * realm 1's relationship counted EXACTLY ONE sign-in and recorded no
//     refusal;
//   * realm 1's directory has an entry for a person whose password was never
//     checked there, naming the relationship it came from;
//   * an UNSOLICITED assertion at the ACS is refused, recorded, and does not
//     count as a sign-in — which matters more than the rest, because a happy
//     path proves nothing about a surface whose bugs are authentication
//     bypasses;
//   * and the tie itself, by removing it.
//
// ---------------------------------------------------------------------------
// GATING
//
// `WSTRUST_STS_URL` locates the mock, as it does for every other STS-backed job
// here. The job SKIPS with a reason when there is none, and it skips with a
// DIFFERENT reason when the mock is too old to have the two application
// attributes — which is read off `GET /ldap/applications`, the schema that
// service publishes, rather than guessed from a version.
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
var log = bunyan.createLogger({ name: "federation_sso",
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

// The two realms and the names of everything created in them. The realm ids are
// PATH SEGMENTS in the mock (lower-case letters, digits and hyphens), and the
// relationship is named after the partner realm because one relationship is one
// direction and the direction is the partner.
const SP_REALM = "federation-realm-1";
const IDP_REALM = "federation-realm-2";
const RELATIONSHIP = IDP_REALM;
const APPLICATION = "webapp-sso-test1";
// The redirect URI the application is REGISTERED with. It is not the one this
// test drives — see registerApplication() — and that is deliberate rather than
// sloppy.
const REGISTERED_REDIRECT_URI = "https://webapp-sso-test-1.example.com";

// ---------------------------------------------------------------------------
// THE MANAGEMENT API, which is where every one of this test's configuration
// calls goes.
//
// NOT the /admin console: since 2026-08-24 the mock ships `admin.authRequired`
// on, so every console page and form needs a browser session and a role, and a
// caller posting JSON is refused 401 rather than redirected. `/admin-api` is
// deliberately not gated and is the surface that exists for a program.
//
// The action is in the PATH here rather than in the body, which is the one
// difference from driving the console's forms.
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
    throw new Error("GET /admin-api" + path + " answered " + response.status +
                    " with something that is not JSON: " + text.slice(0, 300));
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
    throw new Error("POST /admin-api" + path + " answered " + response.status +
                    " with something that is not JSON: " + text.slice(0, 300));
  }
  log.debug("Leaving adminPost(). ok=" + parsed.ok);
  return parsed;
}

// A management API call that must have worked. The mock answers 400 with an
// `errors` array rather than throwing, so the message a failure produces is the
// service's own account of what it disliked — which is worth rather more than
// "the call failed".
async function must(base, path, body, what) {
  log.debug("Entering must(). " + what);
  const result = await adminPost(base, path, body);
  assert.ok(result.ok, what + " was refused by the mock STS: " +
            JSON.stringify(result.errors || result));
  log.debug("Leaving must().");
  return result;
}

// ---------------------------------------------------------------------------
// THE TWO REALMS.
//
// A realm is defined at RUNTIME and lives in memory, so there is nowhere to
// declare one and every run has to create its own — which also means a second
// run against a live container meets realms that are already there. That is not
// an error and is not treated as one: what matters is that the realm exists,
// not who made it.
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
    ". A realm that was created and is not listed means the create answered ok " +
    "for something that did not happen.");
  // Two realms sharing a signing key would be two names for one authorization
  // server, and every assertion below about WHICH realm issued something would
  // be unfalsifiable. The mock derives a `kid` from the key material, so this is
  // one comparison rather than a claim.
  const kids = (after.realms || []).filter(function (one) {
    return one.id === SP_REALM || one.id === IDP_REALM;
  }).map(function (one) { return one.kid; });
  assert.strictEqual(new Set(kids).size, 2,
    "The two realms publish the same kid (" + kids.join(", ") + "), so they " +
    "are signing with one key and nothing below could tell their tokens apart.");
  log.info("Both realms are defined, with signing keys of their own.");
  log.debug("Leaving createRealms().");
}

// ---------------------------------------------------------------------------
// THE APPLICATION, IN REALM 1, BEFORE IT EVER CONNECTS.
//
// It is DELETED first and created again, so that every counter this test reads
// afterwards starts at zero. A run against a container somebody has already
// driven would otherwise assert on somebody else's arithmetic — see
// tests/CLAUDE.md on asserting against your own litter.
//
// TWO REDIRECT URIS, and the second one needs saying. The application is
// registered with `https://webapp-sso-test-1.example.com`, which is what
// `webapp-sso-test1` would use if it existed; the debugger is what actually
// drives the flow, and its callback is this suite's own. Both are registered,
// because the point of pre-registering at all is the mode that will one day
// check the list — and a list that omits the URI the flow uses would pass today
// and fail then, for a reason nothing in the failure would name.
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
    name: "webapp-sso-test1",
    // What the application IS DECLARED for. The mock reads this nowhere — an
    // application declared for SAML 2.0 alone is still issued an access token —
    // so it records intent, and the test asserts it came back rather than that
    // it did anything.
    protocols: ["oauth2", "oidc"],
    fields: {
      oauthClientId: APPLICATION,
      oauthRedirectUri: [REGISTERED_REDIRECT_URI, callbackUri],
      // THE TIE. Both halves are set explicitly even though the auto-redirect
      // defaults to TRUE once a relationship is named: a default is a fact
      // about the mock's version rather than about this configuration, and the
      // last section of this test reads the attribute back before clearing it.
      appFederationRelationship: RELATIONSHIP,
      appFederationAutoRedirect: "TRUE"
    }
  }, "creating the " + APPLICATION + " application in " + SP_REALM);

  // Read back through the API rather than trusting the create's own answer: the
  // reply is the service's account of what it did, and the entry is what every
  // endpoint will actually read.
  // The single-application reply is FLAT — `found`, `identifier`, `fields`,
  // `authentications` at the top level — rather than wrapping the entry in an
  // `application` member the way the two ACTIONS above do.
  const entry = await adminGet(spBase,
    "/applications?application=" + encodeURIComponent(APPLICATION));
  assert.ok(entry.found, "The application " + APPLICATION + " is not in " +
            SP_REALM + "'s registry after being created there.");
  const fields = entry.fields || {};
  // A LIST since 2026-08-26 — the mock's `appFederationRelationship` is
  // multi-valued, so an application can offer several identity providers and a
  // person picks between them at `/authn/select-idp`. This test names ONE, and
  // the assertion is that the list is exactly that one: a second value here
  // would draw the chooser instead of the redirect every assertion below
  // assumes. `tests/federation_choice_sso.js` is the job that drives two.
  const named = [].concat(fields.appFederationRelationship || []);
  assert.deepStrictEqual(named, [RELATIONSHIP],
    "The application entry should name exactly the federation relationship \"" +
    RELATIONSHIP + "\" and names [" + named.join(", ") + "].");
  const registered = [].concat(fields.oauthRedirectUri || []);
  assert.ok(registered.indexOf(REGISTERED_REDIRECT_URI) >= 0,
    "The application should be registered with " + REGISTERED_REDIRECT_URI +
    " and its list is: " + registered.join(", ") + ".");
  assert.ok(registered.indexOf(callbackUri) >= 0,
    "The debugger's own callback (" + callbackUri + ") is not in the " +
    "registered list, so this application is not fully configured for the " +
    "flow this test is about to drive.");
  assert.strictEqual(Number(entry.authentications || 0), 0,
    "The application has authentications recorded before this test has signed " +
    "anybody in, so the counters below are somebody else's.");

  // AND IT IS REALM 1'S. The embedded directory is per trust realm, so the same
  // identifier is unknown next door — which is the property that makes two
  // realms two identity services rather than one with two URL prefixes.
  log.debug("Leaving registerApplication().");
  return entry;
}

// ---------------------------------------------------------------------------
// WHAT REALM 2 PUBLISHES, READ FROM REALM 2.
//
// The entityID, the certificate and the SSO endpoint are taken out of the
// identity provider's own metadata rather than written down here. Two reasons,
// and the second is the one that matters: they are what they are, and fetching
// the document proves that realm is up and answering as itself before anything
// is configured against it.
//
// The document is asked for BY THE SERVICE PROVIDER'S entityID, which is the
// URL realm 1's federated flow will put in the AuthnRequest's <Issuer>. The
// mock mints per-service-provider identity provider metadata
// (`saml2.perApplicationEntityId`), so a document fetched without that name
// would carry a DIFFERENT entityID from the one the assertions will actually
// arrive with — and `fedPeer` is checked against the Issuer, so the flow would
// be refused with "it was issued by somebody else".
// ---------------------------------------------------------------------------
async function readPartnerMetadata(idpBase, spEntityId) {
  log.debug("Entering readPartnerMetadata().");
  const url = idpBase + "/saml2/metadata/" + encodeURIComponent(spEntityId);
  const response = await fetch(url);
  assert.strictEqual(response.status, 200,
    "Realm 2 answered " + response.status + " for its own SAML 2.0 metadata " +
    "at " + url + ".");
  const xml = await response.text();
  const entityId = (xml.match(/entityID="([^"]+)"/) || [])[1] || "";
  const certificate = (xml.match(/<[^>]*X509Certificate>([^<]+)</) || [])[1] ||
                      "";
  const sso = (xml.match(
    /SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"[^>]*Location="([^"]+)"/
  ) || [])[1] || "";
  assert.ok(entityId && certificate && sso,
    "Realm 2's metadata is missing one of the three things a service provider " +
    "is configured from — entityID=\"" + entityId + "\", certificate=" +
    (certificate ? certificate.length + " characters" : "(none)") +
    ", HTTP-Redirect SSO=\"" + sso + "\". The document begins: " +
    xml.slice(0, 300));
  assert.ok(sso.indexOf("/realm/" + IDP_REALM + "/") >= 0,
    "Realm 2's metadata advertises an SSO endpoint outside its own realm (" +
    sso + "), which would send the AuthnRequest to a different identity " +
    "service from the one this test configured.");
  log.info("Realm 2 publishes entityID " + entityId + " and signs with a " +
           certificate.length + "-character certificate.");
  log.debug("Leaving readPartnerMetadata().");
  return { entityId: entityId, certificate: certificate, sso: sso };
}

// ---------------------------------------------------------------------------
// THE RELATIONSHIP, IN REALM 1, POINTING AT REALM 2.
//
// Deleted and re-created for the same reason the application is: `fedAuthentications`
// is asserted to be EXACTLY ONE below, and a relationship left over from an
// earlier run carries that run's count.
//
// The order here is the feature's own: create (which forces it DISABLED
// whatever the request says), fill in, then enable as a second deliberate act.
// ---------------------------------------------------------------------------
async function createRelationship(spBase, partner) {
  log.debug("Entering createRelationship().");
  const existing = await adminGet(spBase,
    "/federation?relationship=" + encodeURIComponent(RELATIONSHIP));
  if (existing.found) {
    log.info("An earlier run left the \"" + RELATIONSHIP + "\" relationship " +
             "behind; removing it so this run's counters start at zero.");
    await must(spBase, "/federation/delete", { id: RELATIONSHIP },
               "removing the relationship left behind by an earlier run");
  }
  const created = await must(spBase, "/federation/create", {
    id: RELATIONSHIP,
    role: "service-provider",
    protocol: "saml2",
    name: "federation-realm-2",
    // CHECKED on the way in: an assertion whose Issuer is not this string is
    // refused even when the signature verifies.
    peer: partner.entityId
  }, "registering the federation relationship");

  // The one place this register overrides its input, and it is the whole
  // posture of the feature: a partner that half-exists and silently accepts
  // assertions is the failure the register is arranged to prevent.
  // The reply carries the raw entry, so this is the ATTRIBUTE's own spelling
  // (`fedEnabled` holds the string "FALSE") rather than a boolean the view
  // layer derived. Asserting the attribute is the stronger of the two: it is
  // what every endpoint downstream actually reads.
  assert.strictEqual(String(created.relationship.fedEnabled), "FALSE",
    "A federation relationship must be created DISABLED whatever the request " +
    "said, and this one came back with fedEnabled=" +
    created.relationship.fedEnabled + ".");
  assert.ok((created.readiness.missing || []).indexOf("fedSigningCertificate")
            >= 0,
    "A SAML 2.0 service-provider-side relationship with nothing configured " +
    "should be missing fedSigningCertificate, and the mock says it is missing: " +
    (created.readiness.missing || []).join(", ") + ". The signature check is " +
    "the whole gate here, so a relationship that is 'ready' without a " +
    "certificate is the assertion this test most needs to be able to make.");

  for (const [field, value] of [["fedSsoUrl", partner.sso],
                                ["fedSigningCertificate", partner.certificate],
                                ["fedPeer", partner.entityId]]) {
    await must(spBase, "/federation/set",
               { id: RELATIONSHIP, field: field, value: value },
               "setting " + field + " on the relationship");
  }
  const enabled = await must(spBase, "/federation/enable", { id: RELATIONSHIP },
                             "enabling the relationship");
  assert.ok(enabled.readiness.ready,
    "The relationship is enabled and not ready: " +
    (enabled.readiness.missing || []).join(", ") + " still to configure. " +
    "Every federated endpoint would refuse rather than half-work.");
  log.info("The relationship \"" + RELATIONSHIP + "\" is enabled and ready.");
  log.debug("Leaving createRelationship().");
  return created;
}

// The relationship as it now stands. Read fresh every time it is asserted on,
// because the interesting values (the counters, the last error) are written by
// the flow rather than by this test.
async function relationshipNow(spBase) {
  log.debug("Entering relationshipNow().");
  const view = await adminGet(spBase,
    "/federation?relationship=" + encodeURIComponent(RELATIONSHIP));
  assert.ok(view.found, "The relationship \"" + RELATIONSHIP + "\" is no " +
            "longer registered in " + SP_REALM + ".");
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
async function prepareAuthorizationRequest(driver, spBase, callbackUri) {
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
  assert.ok(preview.indexOf(spBase + "/oauth2/authorize") >= 0,
    "The page is about to send the authorization request to something other " +
    "than realm 1's authorization endpoint (" + spBase + "/oauth2/authorize). " +
    "It reads:\n" + preview);
  assert.ok(preview.indexOf("client_id=" + APPLICATION) >= 0,
    "The authorization request does not name " + APPLICATION +
    ", so nothing downstream can look its federation relationship up. It " +
    "reads:\n" + preview);
  log.info("The debugger will send: " + preview.split("\n")[0]);
  log.debug("Leaving prepareAuthorizationRequest().");
  return { preview: preview, nonce: nonce, state: state };
}

// The mock's sign-in screen, whichever realm is showing it. It reuses
// Keycloak's field ids, which is why every test in this suite drives it the
// same way; it checks no password, so the username typed here is the identity
// every token downstream describes.
async function signIn(driver, user) {
  log.debug("Entering signIn(). user=" + user);
  const username = By.id("username");
  try {
    await driver.wait(until.elementLocated(username), waitTime * 4);
    await driver.wait(until.elementIsVisible(driver.findElement(username)),
                      waitTime);
  } catch (e) {
    const url = await driver.getCurrentUrl();
    const body = await driver.findElement(By.css("body")).getText();
    throw new Error("No sign-in screen appeared. The browser is at " + url +
                    " and the page says: " + body.slice(0, 500));
  }
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  const passwords = await driver.findElements(By.id("password"));
  if (passwords.length) {
    await passwords[0].clear();
    await passwords[0].sendKeys("no password is checked here");
  }
  await driver.findElement(By.id("kc-login")).click();
  log.debug("Leaving signIn().");
}

// ---------------------------------------------------------------------------
// A FORGED CALLBACK, which is the assertion that matters most.
//
// A happy path proves almost nothing about a surface whose failures are
// authentication bypasses. What arrives at an assertion consumer service is an
// unauthenticated HTTP request claiming to be a person, and the session it
// would produce is the same one /oauth2/authorize, /saml2/sso and /admin all
// read. So a document that LOOKS right and is not signed must be refused, and
// must be RECORDED as a refusal rather than silently dropped.
//
// The document is built to reach the check that matters. The mock reads the
// Status first (a partner that refused to authenticate somebody sends a
// well-formed Response with no assertion, and reporting that as "no assertion"
// would send somebody hunting a bug in the wrong service), so a probe carrying
// no StatusCode is refused for being a refusal and never reaches the signature
// at all. This one therefore reports SUCCESS, names the configured partner as
// its issuer, carries an assertion, and asserts that the person is
// `administrator` — which is exactly the shape of the attack — and is refused
// 401 on the signature.
//
// It is sent with no cookies (a bare fetch, not the browser) and with a
// RelayState nobody minted, which is precisely the position an attacker is in.
// ---------------------------------------------------------------------------
async function forgedCallbackIsRefused(spBase, partner) {
  log.debug("Entering forgedCallbackIsRefused().");
  const before = await relationshipNow(spBase);
  const now = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const xml =
    "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"" +
    " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"" +
    " ID=\"_forged-response\" Version=\"2.0\" IssueInstant=\"" + now + "\">" +
    "<saml:Issuer>" + partner.entityId + "</saml:Issuer>" +
    "<samlp:Status><samlp:StatusCode" +
    " Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
    "<saml:Assertion ID=\"_forged-assertion\" Version=\"2.0\"" +
    " IssueInstant=\"" + now + "\">" +
    "<saml:Issuer>" + partner.entityId + "</saml:Issuer>" +
    "<saml:Subject><saml:NameID>administrator</saml:NameID></saml:Subject>" +
    "</saml:Assertion></samlp:Response>";
  const url = spBase + "/federation/acs/" + encodeURIComponent(RELATIONSHIP);
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      SAMLResponse: Buffer.from(xml, "utf8").toString("base64"),
      RelayState: "a-handle-nobody-minted"
    }).toString()
  });
  const body = await response.text();
  assert.strictEqual(response.status, 401,
    "An UNSIGNED assertion naming " + partner.entityId + " and claiming to be " +
    "\"administrator\" was answered " + response.status + " at " + url + ". " +
    "That endpoint issues a browser sign-on session, so anything but a refusal " +
    "here is an authentication bypass. The reply begins: " + body.slice(0, 400));
  assert.ok(/signature/i.test(body),
    "The refusal does not name the signature, so it was refused for some " +
    "other reason and the check this probe is aimed at was never reached. It " +
    "says: " + body.slice(0, 400));
  assert.strictEqual(String(response.headers.get("set-cookie") || ""), "",
    "The refused callback set a cookie: " + response.headers.get("set-cookie") +
    ". Nothing about a refused assertion may leave a session behind.");

  const after = await relationshipNow(spBase);
  assert.strictEqual(Number(after.authentications || 0),
                     Number(before.authentications || 0),
    "The refused callback was counted as a sign-in on the relationship (" +
    before.authentications + " before, " + after.authentications + " after).");
  assert.ok(String(after.lastError || "").trim(),
    "The relationship records no last error after refusing a forged " +
    "callback. A refusal nobody can see afterwards is indistinguishable from " +
    "a request that never arrived.");
  log.info("A forged, unsigned assertion was refused 401 and recorded: " +
           String(after.lastError).slice(0, 120));
  log.debug("Leaving forgedCallbackIsRefused().");
}

// ---------------------------------------------------------------------------
// AND THE TIE ITSELF, BY REMOVING IT.
//
// Every assertion above this one would pass just as well against a mock that
// federated every sign-in for reasons of its own. Clearing
// `appFederationRelationship` and running the same authorization request must
// therefore reach realm 1's OWN sign-in screen — the mutation test for the
// feature this test exists to cover.
//
// The attribute is put back afterwards, in a finally, for the same reason every
// other test here restores what it changed: the realms outlive this process.
// ---------------------------------------------------------------------------
async function clearingTheTieRestoresTheLocalScreen(driver, spBase,
                                                    callbackUri) {
  log.debug("Entering clearingTheTieRestoresTheLocalScreen().");
  // REMOVE, NOT SET. The attribute holds a list, so the mock refuses a `set`
  // by name — "a set would replace the list with one value and read afterwards
  // as the others having been forgotten" — and values are added and removed
  // instead. This used to be `/applications/set` with an empty value.
  await must(spBase, "/applications/remove",
             { application: APPLICATION,
               attribute: "appFederationRelationship", value: RELATIONSHIP },
             "clearing the application's federation relationship");
  try {
    const entry = await adminGet(spBase,
      "/applications?application=" + encodeURIComponent(APPLICATION));
    assert.deepStrictEqual(
      [].concat((entry.fields || {}).appFederationRelationship || []), [],
      "The federation relationship was not actually cleared off the entry, so " +
      "the check below would be measuring nothing.");

    await clearSessionsAt(driver, spBase);
    await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                   "authorization_grant_type", { timeout: waitTime * 5 });
    await waitForPageBundle(driver);
    await prepareAuthorizationRequest(driver, spBase, callbackUri);
    await driver.findElement(
      By.css("input[type=\"submit\"][value=\"Authorize\"]")).click();
    await driver.wait(until.elementLocated(By.id("username")), waitTime * 4);
    const url = await driver.getCurrentUrl();
    assert.ok(url.indexOf("/realm/" + SP_REALM + "/") >= 0,
      "With the tie removed the sign-in screen should be REALM 1's own, and " +
      "the browser is at " + url + ".");
    assert.ok(url.indexOf("/realm/" + IDP_REALM + "/") === -1,
      "With the tie removed the browser still went to realm 2 (" + url +
      "), so something other than appFederationRelationship is federating " +
      "this application and every assertion above is about that instead.");
    log.info("With the tie cleared the same request stops at realm 1's own " +
             "sign-in screen: " + url);
  } finally {
    await must(spBase, "/applications/add",
               { application: APPLICATION,
                 attribute: "appFederationRelationship",
                 value: RELATIONSHIP },
               "putting the application's federation relationship back");
  }
  log.debug("Leaving clearingTheTieRestoresTheLocalScreen().");
}

// Whether this mock is new enough to have the two attributes this test is
// about. Read off the schema that service publishes rather than off a version
// string: the submodule is bumped by hand, and a job that failed on a stale
// checkout would name a missing element on a sign-in screen.
async function mockKnowsTheAttributes(stsBase) {
  log.debug("Entering mockKnowsTheAttributes().");
  const response = await fetch(stsBase + "/ldap/applications",
                               { headers: { Accept: "application/json" } });
  if (response.status !== 200) {
    log.debug("Leaving mockKnowsTheAttributes(). " + response.status);
    return false;
  }
  const text = await response.text();
  const knows = text.indexOf("appFederationRelationship") >= 0;
  log.debug("Leaving mockKnowsTheAttributes(). " + knows);
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
    log.info("SKIPPED: WSTRUST_STS_URL is not set, so there is no mock STS to " +
             "build two trust realms in. This test needs that service and " +
             "nothing else.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const stsBase = stsUrl.replace(/\/sts\/?$/, "");
  if (!(await mockKnowsTheAttributes(stsBase))) {
    log.info("SKIPPED: the mock STS at " + stsBase + " does not publish " +
             "appFederationRelationship in its application schema, so it " +
             "predates the attribute that ties an application to a federation " +
             "relationship. Bump the sts/ submodule.");
    log.debug("Leaving test(). Skipped, the mock is too old.");
    return;
  }
  const spBase = stsBase + "/realm/" + SP_REALM;
  const idpBase = stsBase + "/realm/" + IDP_REALM;
  const callbackUri = baseUrl + "/callback";
  const user = usernameFor("federation");

  // ---------------------------------------------------------------------
  // CONFIGURATION FIRST, with no browser open. Everything here is a
  // management API call, and every one of them is asserted: a setup step that
  // quietly does nothing is worse than none, because the flow below would
  // then be testing whatever the mock happened to be configured with.
  // ---------------------------------------------------------------------
  await createRealms(stsBase);
  await registerApplication(spBase, callbackUri);
  const spEntityId = spBase + "/federation/acs/" + RELATIONSHIP;
  const partner = await readPartnerMetadata(idpBase, spEntityId);
  await createRelationship(spBase, partner);

  // ---------------------------------------------------------------------
  // THE ADDRESS THE CONSOLE TELLS AN OPERATOR TO GIVE THE PARTNER must be the
  // one this flow actually uses. They are built by different modules —
  // `admin.js` for the page and `federation_sp.js` for the AuthnRequest's
  // Issuer and AssertionConsumerServiceURL — so nothing but a comparison keeps
  // them in step, and the failure when they drift is silent HERE and loud at
  // somebody else's identity service.
  //
  // It caught exactly that on 2026-08-26: the detail view built its base as
  // `'http://' + req.get('host')`, the one place in that file not going through
  // `baseUrlOf()`, so it printed a URL with NO REALM PREFIX (a 404) and always
  // `http://` (wrong on every stack in this suite, which runs that service over
  // TLS). The flow was correct throughout; only the half a person reads was
  // wrong.
  // ---------------------------------------------------------------------
  const advertised = await relationshipNow(spBase);
  assert.strictEqual(advertised.endpoints.assertionConsumerService, spEntityId,
    "The console advertises \"" +
    advertised.endpoints.assertionConsumerService + "\" as the address to " +
    "configure at the partner, and the AuthnRequest this service sends names " +
    "\"" + spEntityId + "\" as its Issuer and assertion consumer service. An " +
    "operator copying the first into a real identity provider would configure " +
    "a URL this service does not answer on.");
  assert.ok(advertised.endpoints.login.indexOf("/realm/" + SP_REALM + "/") === 0,
    "The console advertises the federated sign-in path as \"" +
    advertised.endpoints.login + "\", which does not open with this realm's " +
    "prefix — so following it would start a sign-in in a different realm, or " +
    "in none.");

  // Realm 2 is an ORDINARY identity provider, and the two realms run one
  // codebase — so this is the assertion that the difference between them is
  // configuration and nothing else.
  const idpRegister = await adminGet(idpBase, "/federation");
  assert.strictEqual((idpRegister.relationships || []).length, 0,
    "Realm 2 has " + (idpRegister.relationships || []).length + " federation " +
    "relationship(s) of its own. It is supposed to be an ordinary identity " +
    "provider that has never heard of federation, which is what makes the " +
    "flow below a federation rather than a chain of two federations.");

  // And the registry is per realm: realm 2 has never heard of this application.
  const overThere = await adminGet(idpBase,
    "/applications?application=" + encodeURIComponent(APPLICATION));
  assert.ok(!overThere.found,
    "Realm 2 knows the application " + APPLICATION + ", which realm 1 " +
    "registered. The directory is supposed to be per trust realm, and if it " +
    "is not then these two realms are one identity service with two URL " +
    "prefixes.");

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
  // certificate regenerated every start, so without the pin the browser meets
  // an interstitial and this test reports a missing sign-in screen.
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
             "application registered at " + spBase + ".");
    await driver.manage().deleteAllCookies();
    await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                   "authorization_grant_type", { timeout: waitTime * 5 });
    // A previous job's state in localStorage would otherwise decide which panes
    // oauth2_oidc_2.html draws, which is what this test reads the tokens out of.
    await driver.executeScript("window.localStorage.clear();");
    await loadPage(driver, baseUrl + "/oauth2_oidc_1.html",
                   "authorization_grant_type", { timeout: waitTime * 5 });
    // Nearly every control on these pages is an inline handler naming a
    // browserify --standalone global, so a click before the bundle has run is a
    // silent no-op rather than an error.
    await waitForPageBundle(driver);

    // Realm 1's discovery document — which is what makes this an ordinary
    // OpenID Provider to the application. Nothing in it mentions federation,
    // and that is the point rather than an omission.
    const discovery = spBase + "/.well-known/openid-configuration";
    await populateMetadata(driver, discovery);
    const metadata = await (await fetch(discovery)).json();
    assert.strictEqual(metadata.issuer, spBase,
      "Realm 1 publishes issuer \"" + metadata.issuer + "\" rather than \"" +
      spBase + "\". The mock derives an issuer from the base URL a request " +
      "arrived on, and a realm's base URL carries its prefix — which is why " +
      "realm creation deliberately does not seed that setting. A process-wide " +
      "STS_OAUTH2_ISSUER pin would override both realms with one name, and " +
      "then \"which realm issued this token\" has no answer and the " +
      "assertions below cannot mean anything.");

    const sent = await prepareAuthorizationRequest(driver, spBase, callbackUri);

    // ---------------------------------------------------------------------
    // AWAY IT GOES. What must happen next is a redirect the application never
    // asked for: realm 1 sees that this client's entry names a federation
    // relationship and sends the browser to realm 2 instead of drawing its own
    // sign-in screen.
    // ---------------------------------------------------------------------
    await driver.findElement(
      By.css("input[type=\"submit\"][value=\"Authorize\"]")).click();
    await driver.wait(until.elementLocated(By.id("username")), waitTime * 5,
      "No sign-in screen appeared after the authorization request. Neither " +
      "realm drew one, so the federated redirect went somewhere unexpected.");
    const screenUrl = await driver.getCurrentUrl();
    assert.ok(screenUrl.indexOf("/realm/" + IDP_REALM + "/") >= 0,
      "The person should have been sent to realm 2 to sign in, and the " +
      "browser is at " + screenUrl + ".");
    assert.ok(screenUrl.indexOf("/realm/" + SP_REALM + "/") === -1,
      "The browser is at one of realm 1's own URLs (" + screenUrl + "), so " +
      "realm 1 asked for the password itself instead of federating.");
    log.info("Realm 1 sent the browser straight on to realm 2: " + screenUrl);

    const screen = await driver.getPageSource();
    // Realm 2 is answering a SAML 2.0 AuthnRequest, and its screen says so.
    // That is the whole shape of the thing in one string: an OAuth request
    // arrived at realm 1 and a SAML request left it.
    assert.ok(/SAML 2\.0/.test(screen),
      "Realm 2's sign-in screen does not say it is signing somebody in for " +
      "SAML 2.0, so realm 1 did not reach it over the federated protocol this " +
      "relationship is configured for.");
    // An identity service with no federation configured must look exactly as it
    // always did — no partner buttons at the foot of its screen.
    //
    // THE SELECTOR IS THE HREF AND NOT THE CLASS, and that distinction cost a
    // run on 2026-08-27. `a.fedbtn` is a STYLE the mock's sign-in screen now
    // puts on two different offers: the federation partners, which are what
    // this assertion is about, and the ambient Kerberos door below them, which
    // `integratedOptionHtml()` draws for every application on every screen
    // with nothing configured anywhere (`krb5.spnegoLoginButton`, on by
    // default). Counting the class made that one button read as a partner
    // realm 2 does not have. A partner button is one that leads to
    // `/federation/login/<relationship>`, which is how the chooser's own
    // assertions in federation_choice_sso.js already tell them apart.
    const partnerButtons = await driver.findElements(
      By.css("a.fedbtn[href*=\"/federation/login/\"]"));
    assert.strictEqual(partnerButtons.length, 0,
      "Realm 2's sign-in screen offers " + partnerButtons.length +
      " federation partner(s). It has no relationships, so it must look byte " +
      "for byte like the screen of a service that has never heard of the " +
      "feature.");
    // And nothing ELSE styled like a partner is on that screen either, bar
    // the Kerberos door. Without this the narrowed selector above would stop
    // seeing a partner button that arrived under some other href.
    await assertOnlyOtherButtonIsKerberos(driver, "Realm 2's sign-in screen");

    await signIn(driver, user);

    // ---------------------------------------------------------------------
    // AND BACK. The browser goes realm 2 → realm 1's assertion consumer
    // service → realm 1's authorization endpoint → the debugger's callback,
    // and the application sees only the last of those.
    // ---------------------------------------------------------------------
    await driver.wait(until.urlContains("/oauth2_oidc_2.html"), waitTime * 8,
      "The flow never came back to the debugger after the sign-in at realm 2.");
    const returned = new URL(await driver.getCurrentUrl());
    const code = returned.searchParams.get("code");
    assert.ok(code,
      "No authorization code came back to the application. The browser is at " +
      returned.toString() + ".");
    assert.strictEqual(returned.searchParams.get("state"), sent.state,
      "The state did not come back unchanged.");
    log.info("The application received an authorization code.");

    // What the flow left behind at realm 1, read before the code is redeemed so
    // that the count is about the SIGN-IN rather than about the token call.
    const after = await relationshipNow(spBase);
    assert.strictEqual(Number(after.authentications || 0), 1,
      "Realm 1's relationship counted " + after.authentications +
      " federated sign-in(s) and this test performed exactly one.");
    assert.ok(!String(after.lastError || "").trim(),
      "The relationship recorded a failure during a sign-in that succeeded: " +
      after.lastError);
    assert.ok(String(after.lastUser || "").indexOf(user) >= 0,
      "The relationship's last user is \"" + after.lastUser + "\" and this " +
      "test signed in as \"" + user + "\".");

    // The person now has a directory entry in REALM 1 — a service that never
    // checked a password for them.
    const users = await adminGet(spBase,
      "/users?q=" + encodeURIComponent(user));
    assert.ok((users.users || []).some(function (one) {
      return String(one.name) === user || String(one.key) === user;
    }), "Realm 1 has no directory entry for " + user + ", who has just signed " +
        "in there. It lists: " +
        (users.users || []).map(function (o) { return o.name; }).join(", "));
    // AND IT SAYS HOW THEY GOT THERE. The mock files a federated sign-in under
    // the protocol the relationship speaks, so a person who has never had a
    // password checked here is distinguishable from one who has.
    assert.ok((users.protocols || []).some(function (one) {
      return /Federation/i.test(String(one));
    }), "Realm 1 does not record " + user + " as having arrived through " +
        "federation. It says: " + (users.protocols || []).join(", "));

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
          throw new Error("Realm 1's token endpoint refused the code: " + text);
        }
      }
      return false;
    }, waitTime * 6, "The code never became an ID Token.");

    // ---------------------------------------------------------------------
    // THE ASSERTION THE WHOLE FEATURE IS FOR.
    //
    // The application asked ONE provider ONE question and got ONE answer, and
    // the fact that a second identity service authenticated the person is
    // nowhere in what it holds.
    // ---------------------------------------------------------------------
    const claims = b64uJson(idToken.split(".")[1]);
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
    assert.ok(String(claims.preferred_username || claims.sub).indexOf(user) >= 0,
      "The ID Token describes \"" + (claims.preferred_username || claims.sub) +
      "\" and the name typed at realm 2 was \"" + user + "\".");
    log.info("The application holds an ID Token issued by " + claims.iss +
             " describing " + (claims.preferred_username || claims.sub) +
             ", and naming realm 2 nowhere.");

    // The negative, and the tie.
    await forgedCallbackIsRefused(spBase, partner);
    await clearingTheTieRestoresTheLocalScreen(driver, spBase, callbackUri);

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
  .name("federation_sso")
  .description("A federated sign-in across two trust realms of one mock STS, " +
               "with the debugger's OAuth2/OIDC workflow standing in for the " +
               "application.")
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
