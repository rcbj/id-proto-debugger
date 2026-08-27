// File: wstrust_delegation_chain.js
//
// ---------------------------------------------------------------------------
// A THREE-TIER DELEGATION CHAIN THAT STARTS AT A BROWSER SIGN-IN AND IS CARRIED
// BY SAML ASSERTIONS: one SAML 2.0 HTTP-POST sign-in, then two WS-Trust hops,
// each made as a DIFFERENT party from a debugger workflow of its own.
//
// It is `tests/oauth2_delegation_chain.js`'s scenario in the other protocol
// family, and it exists because the delegation register and the map drawn from
// it are the same picture for BOTH — the console's whole argument is that
// "alice never touched the back end, so why is there a credential to it in her
// name" is a protocol-independent question. A chain that draws correctly for
// RFC 8693 and comes out as three unconnected boxes for WS-Trust would mean the
// model only ever worked for the family it was written against.
//
// The scenario, in the words of the deployment it is copied from:
//
//   carol_end_user signs in to a WEB APPLICATION over the SAML 2.0 Web Browser
//   SSO profile, HTTP-POST binding. The assertion that comes back names her and
//   is addressed to that application — its <saml:AudienceRestriction> carries
//   the application's own URL, which is the SAML spelling of what an `aud`
//   claim says.
//
//   The web application calls the ENTERPRISE SERVICE BUS. Before it does, it
//   presents that assertion to the STS in a WS-Trust RequestSecurityToken with
//   <wst:OnBehalfOf> (or <wst14:ActAs> — this file runs both, see below) and an
//   <wsp:AppliesTo> naming the bus, and gets back a NEW assertion: the same
//   person, a new audience restriction, `https://esb.example.com`. NOTHING HERE
//   SIMULATES THE CALL TO THE BUS — there is no SOAP service in this suite and
//   inventing one would be testing a fixture.
//
//   The bus does it again, for the back-end SOAP SERVICE PROVIDER,
//   `https://soap1.example.com`. Nothing is forwarded there either. The point
//   is the SHAPE of the third assertion: it names carol_end_user, its audience
//   is the back end, and neither the web application nor the bus is anywhere in
//   it.
//
// ---------------------------------------------------------------------------
// AN AudienceRestriction IS AN `aud` CLAIM, AND THAT IS WHY THIS IS THE SAME
// TEST.
//
// SAML 2.0 §2.5.1.4 says an assertion with an <saml:AudienceRestriction> is one
// the named audience may act on and nobody else may — the same statement RFC
// 7519 §4.1.3 makes with `aud`, and the same statement WS-Trust makes with
// <wsp:AppliesTo>, which is what the STS copies INTO the audience restriction
// of what it issues. So every hop below is a token exchange in the sense the
// OAuth file means it: one credential in, one credential out, the same subject,
// a different audience, and a middle tier that is invisible in the result.
//
// ---------------------------------------------------------------------------
// TWO RUNS, AND THE DIFFERENCE BETWEEN THEM IS THE WHOLE OF WHY WS-TRUST HAS
// TWO ELEMENTS.
//
// WSTRUST_DELEGATION_ELEMENT picks one:
//
//   onbehalfof  <wst:OnBehalfOf> (WS-Trust 1.3 §9.2) asks for a token ABOUT
//               somebody. What comes back names carol_end_user and says nothing
//               about the requester, so the relying party is handed what looks
//               like an ordinary sign-in. IMPERSONATION — and the register is
//               then the only place in the world where the middle tier exists
//               at all, which is exactly the OAuth chain's situation.
//   actas       <wst14:ActAs> (WS-Trust 1.4 §9.3) is COMPOSITE by definition:
//               the token is about the subject AND says a requester is acting.
//               DELEGATION. The mock records the mode accordingly and says, in
//               the row itself, that nothing in the assertion it issues carries
//               the composite fact — a gap in the mock rather than in the
//               profile, and one worth having written down where somebody
//               reading the picture will see it.
//
// Both are run by the suite, as two jobs. They are NOT one job with a loop,
// because each is a full browser story and a failure should name which element
// it was carrying.
//
// ---------------------------------------------------------------------------
// SIX DECISIONS THIS FILE MAKES, EACH OF WHICH CHANGES WHAT IT PROVES.
//
// **EACH HOP IS A NEW WORKFLOW, and the localStorage is CLEARED between them.**
// The same decision the OAuth chain makes and for the same reason: the debugger
// keeps the whole of a workflow in browser storage, so a second RST run
// straight after the first inherits its AppliesTo, its credential and its
// OnBehalfOf token — and a pane that filled in nothing at all would still send
// a well-formed request. Clearing means each hop must be told who it is and
// what it is reaching, which is what a web application and a service bus really
// are: separate programs that were handed a token and know nothing else.
//
// **THE REQUEST PREVIEW IS ASSERTED BEFORE THE BUTTON IS PRESSED.** The page
// draws exactly the SOAP envelope it is about to POST, and every one of the
// four things that distinguishes one hop from the other — the requester's
// UsernameToken, the AppliesTo, the delegation element, and the ID of the
// assertion being delegated WITH — is a field that could be stale from the hop
// before. A test that only read the response could not tell a correct exchange
// from one that re-sent the previous request and got a plausible assertion
// back.
//
// **THE THREE APPLICATIONS ARE PROVISIONED FIRST, THROUGH THE MANAGEMENT API,
// AND EACH DOWNSTREAM ONE REGISTERS THE ADDRESS IT ANSWERS TO.** This service
// accepts an AppliesTo it has never heard of — that is why the WS-Trust test
// beside this one needs no provisioning at all — so an entry appears only when
// something is ACCEPTED, and it appears knowing nothing but the identifier.
// Here the three are created before the browser starts, in the DEFAULT realm,
// each declared for the families it speaks, and each registering its address on
// `wstrustAppliesTo` (the AppliesTo an RST names it by) and `samlEntityId` (the
// audience an assertion carries). The web application registers only the
// second: it is what an assertion is issued TO, and no RST here ever names it.
//
// **AND THAT REGISTRATION IS READ, WHICH IS THE POINT RATHER THAN DECORATION.**
// The register is keyed by the identifier a party PRESENTS, so an act recorded
// for `https://esb.example.com` would draw a box in the map that nothing else
// in the picture mentions — and this chain would come out as two unconnected
// halves, because the address hop 1 reached and the name hop 2 authenticated AS
// are one application under two names. The mock looks the AppliesTo up
// (`applications.forAppliesTo()`, added 2026-08-27 for exactly this) and files
// the act against the application that registered it, keeping the address in
// the sentence beside it. Nothing is REFUSED by any of this: an AppliesTo
// nobody registered is still issued for, and recorded verbatim.
//
// **THE AuthnRequest IS NOT SIGNED, and that is a scope decision rather than an
// oversight.** `tests/saml_sso.js` is where the debugger's request signatures
// are tested, against an identity provider (Keycloak) that actually validates
// them; the mock verifies none, so signing here would prove nothing and would
// make this job depend on the per-run SP key pair that `common/common.sh`
// generates. This file needs `WSTRUST_STS_URL` and nothing else, which is what
// lets `./local-run-tests.sh --delegation-only` bring up three containers and
// run it.
//
// **THE MOCK STS, AND ITS PERMISSIVE (default) REALM.** A service provider
// nobody registered, a user with no password, and an STS that will issue a
// token about anybody to anybody: the mock says so itself in the column where a
// Kerberos row names an attribute (`authorizedBy: 'nothing. WS-Trust puts no
// authorization on <wst:OnBehalfOf> and this service adds none'`). That
// asymmetry is the most useful thing on the delegation page and it is why this
// runs against the mock and not against the Keycloak side-car, which has no
// WS-Trust endpoint at all.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS, IN FIVE LAYERS, BECAUSE ANY ONE OF THEM PASSES ALONE.
//
//   1. THE REGISTRY. Each of the three applications is read back after it is
//      created — declared for the families it speaks, and holding the address
//      it registered. Read through `GET /admin-api/applications` rather than
//      off the create's own reply, because the question is what the registry
//      holds and not what the write said it wrote.
//   2. THE SIGN-IN. A SAML Response arrives over the HTTP-POST binding, it
//      carries an Assertion, that assertion names the user, and its
//      AudienceRestriction is the WEB APPLICATION'S URL. That last one is what
//      makes the rest a delegation rather than a re-issue: the credential the
//      browser ends up with may be acted on by one party, and the two hops that
//      follow exist because the other two parties may not act on it.
//   3. THE WIRE. Each hop answers with an RSTR carrying a SAML 2.0 assertion
//      that parses, names the SAME person, has a NEW AssertionID, and is
//      addressed to the NEXT tier and to nothing else. Each is also checked for
//      the tier it has already left — an assertion still carrying the previous
//      audience would be an STS echoing its input.
//   4. THE REGISTER. `GET /admin-api/delegation` is read for the acts recorded
//      SINCE this job started, and each hop must be there with its parties, its
//      type, its mode, the AssertionID of what this test actually received, and
//      the AssertionID of what it delegated WITH. The target must be the
//      APPLICATION and its explanation must name the ADDRESS that was asked
//      for — the two together are what say the registry lookup happened rather
//      than the RST having named an application.
//   5. THE PICTURE, AND THE LINEAGE. The graph the map is drawn from is checked
//      for the one property that makes this a chain rather than two unrelated
//      requests: **the bus is ONE box that played the TARGET of the first hop
//      and the INTERMEDIARY of the second.** Then /admin/tokens/credential is
//      walked back from the final assertion, which must reach the SIGN-IN
//      assertion three generations away — the credential the browser was given,
//      which no WS-Trust call ever mentions.
//
// Deltas, not totals. The mock's stores survive between jobs and the suite runs
// in a pool, so the newest sequence number is read before the browser starts
// and every assertion below is about acts after it. The two runs of this file
// (OnBehalfOf and ActAs) may therefore overlap in the pool, and they are told
// apart by TYPE as well as by sequence — which is why findAct() filters on it.
//
// THE THREE ENTRIES ARE LEFT BEHIND, deliberately, for the reason the OAuth
// chain leaves its four: they are what the map is a picture OF, and deleting
// them would leave the register pointing at applications the console can no
// longer show.
//
// ---------------------------------------------------------------------------
// AND IT SAVES THE DRAWINGS, WHICH IS HALF OF WHY THE JOB EXISTS.
//
// The register is IN MEMORY and dies with the process, so the picture of this
// chain can only be taken while the run is happening. The SVGs are fetched and
// written to DELEGATION_ARTIFACT_DIR (the run's own report directory, when
// run-report.js spawns this): the map filtered to this person, the whole map,
// one document per chain, everything the bus is part of, and the LINEAGE of the
// final assertion. The console is gated (`admin.authRequired`), so this signs
// in the way a browser does — three steps through /authn/login, exactly as
// tests/admin_api.js and the OAuth chain do it. If the roster has been narrowed
// by some other job the drawings are SKIPPED with a message naming the gate;
// the assertions above do not depend on them, because they read
// /admin-api/delegation, which is not behind it.
// ---------------------------------------------------------------------------
const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const assert = require("assert");
const { DOMParser } = require("@xmldom/xmldom");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const waitFor = require("./wait_for.js");
const { loadPage } = require("./page_load.js");
const common = require("./jwt_vc_json_common.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "wstrust_delegation_chain",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// ---------------------------------------------------------------------------
// WHICH DELEGATION ELEMENT this run carries, and everything that follows from
// it. One variable, read once, because the type recorded, the mode recorded and
// the element that has to appear in the request preview are three statements of
// one choice and they must not be able to disagree.
// ---------------------------------------------------------------------------
const ELEMENT = (process.env.WSTRUST_DELEGATION_ELEMENT || "onbehalfof")
    .toLowerCase();
assert.ok(ELEMENT === "onbehalfof" || ELEMENT === "actas",
  "WSTRUST_DELEGATION_ELEMENT must be \"onbehalfof\" or \"actas\" and is \"" +
  ELEMENT + "\".");

const DELEGATION = ELEMENT === "actas"
  ? { element: "actas",
      // The ids of the checkbox and the textarea on wstrust_tools.html.
      check: "wst_use_actas", field: "wst_actas",
      // What the built request must contain, and what the register must say.
      markup: "ActAs", type: "wstrust-actas", mode: "delegation",
      spelling: "<wst14:ActAs>",
      what: "WS-Trust 1.4 section 9.3 — COMPOSITE: the token is about the " +
            "subject and says the requester is acting" }
  : { element: "onbehalfof",
      check: "wst_use_onbehalfof", field: "wst_onbehalfof",
      markup: "OnBehalfOf", type: "wstrust-onbehalfof",
      mode: "impersonation",
      spelling: "<wst:OnBehalfOf>",
      what: "WS-Trust 1.3 section 9.2 — IMPERSONATION: the token is about " +
            "the subject and says nothing about the requester" };

// WS-Trust 1.4 whatever the element, because 1.4 is the version that HAS
// ActAs and running the two hops under two different versions would make the
// element the only difference this file could not attribute.
const TRUST_VERSION = process.env.WSTRUST_DELEGATION_VERSION || "1.4";

// ---------------------------------------------------------------------------
// THE CAST. Every one of them is overridable and every one of them defaults to
// the name the scenario uses — a delegation picture is read by its labels.
//
// Deliberately NOT process.env.USER for the person: every shell sets that, so a
// standalone run would sign in as whoever started it and the whole register
// would be about them. The mock accepts any username and checks no password,
// refusing only the literal "invalid".
//
// And deliberately NOT `bob_end_user`, which is the OAuth chain's person: these
// two jobs run in the same pool against the same service, and one name would
// put both stories in one filtered picture.
// ---------------------------------------------------------------------------
const USER = process.env.WSTRUST_DELEGATION_USER || "carol_end_user";
const WEBAPP = process.env.WSTRUST_DELEGATION_WEBAPP || "portal1";
const ESB = process.env.WSTRUST_DELEGATION_ESB || "esb";
const PROVIDER = process.env.WSTRUST_DELEGATION_SP || "soap1";

const WEBAPP_URL = process.env.WSTRUST_DELEGATION_WEBAPP_URL ||
    "https://portal1.example.com";
const ESB_URL = process.env.WSTRUST_DELEGATION_ESB_URL ||
    "https://esb.example.com";
const PROVIDER_URL = process.env.WSTRUST_DELEGATION_SP_URL ||
    "https://soap1.example.com";

// ---------------------------------------------------------------------------
// THE THREE APPLICATION OBJECTS, as they are created in the registry before any
// of this runs.
//
// `name` is what the delegation map LABELS the box with (the registry's
// `appName`, which the map's node resolver prefers over the identifier), so
// each one carries the identifier AND what that tier is.
//
// `protocols` is what the entry is DECLARED for, and the three differ:
//
//   * the web application is a SAML 2.0 service provider (it receives the
//     assertion) and a WS-Trust requester;
//   * the bus and the back end are WS-Trust relying parties (an RST names them
//     in its AppliesTo) and SAML 2.0 audiences (the assertion issued for that
//     AppliesTo carries them), which is the pair `wstrust.js` records for a
//     SAML token type and is why both families are declared here.
//
// Declaring a family GRANTS NOTHING in this service — it is a record of intent
// — which is exactly why it is asserted below or nowhere.
//
// `appliesTo` is EMPTY for the web application on purpose and the entry says
// why: it is what an assertion is issued TO and never what one is addressed to
// by an RST. `audience` is its entityID, which IS an address it answers to —
// the sign-in's assertion carries it — so the two attributes are not the same
// question and the web application answers only one of them.
// ---------------------------------------------------------------------------
const APPLICATIONS = [
  { identifier: WEBAPP, name: WEBAPP + " (web application)",
    protocols: ["saml2", "wstrust"],
    audience: WEBAPP_URL, appliesTo: "",
    why: "the browser application the End-User signs in to over SAML 2.0. " +
         "The assertion it receives is addressed to its entityID; no " +
         "RequestSecurityToken here ever names it, so it registers no " +
         "AppliesTo." },
  { identifier: ESB, name: ESB + " (enterprise service bus)",
    protocols: ["wstrust", "saml2"],
    audience: ESB_URL, appliesTo: ESB_URL,
    why: "the service bus the web application's call is forwarded through. " +
         "It is named by an AppliesTo and is the audience of what that " +
         "produces, which is one address under two attributes because they " +
         "are two registrations." },
  { identifier: PROVIDER, name: PROVIDER + " (SOAP service provider)",
    protocols: ["wstrust", "saml2"],
    audience: PROVIDER_URL, appliesTo: PROVIDER_URL,
    why: "the SOAP service at the far end, which never hears from the " +
         "End-User." }
];

// The two hops, built from the cast above so that the address an RST asks for
// and the address an entry registers cannot drift apart.
//
// `as` is the name the requester authenticates with in its WS-Security
// UsernameToken, and it is the ENTRY'S IDENTIFIER rather than its URL: a
// UsernameToken carries a name, and the map keys the box on what was presented.
// That is also what makes the chain join — see assertGraphIsAChain().
const HOPS = [
  { as: WEBAPP, target: ESB, appliesTo: ESB_URL,
    what: "the web application exchanges the sign-in assertion for one the " +
          "service bus may act on" },
  { as: ESB, target: PROVIDER, appliesTo: PROVIDER_URL,
    what: "the service bus exchanges that for one the back end may act on" }
];

// The name this file signs into the console AS, for the drawings alone. A name
// and not a credential — the mock checks no password anywhere — and distinctive
// so that the directory entry and the audit row it leaves say which job made
// them. The ELEMENT is in it because the two runs are two jobs.
const CONSOLE_USER = "wstrust-delegation-" + DELEGATION.element;

// ---------------------------------------------------------------------------
// Where the mock is, and where the pictures go.
// ---------------------------------------------------------------------------
function stsBase() {
  log.debug("Entering stsBase().");
  const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
  log.debug("Leaving stsBase().");
  return stsUrl.replace(/\/sts\/?$/, "");
}

function stsEndpoint() {
  log.debug("Entering stsEndpoint().");
  const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
  log.debug("Leaving stsEndpoint(). " + stsUrl);
  return stsUrl;
}

function artifactDir() {
  log.debug("Entering artifactDir().");
  const dir = process.env.DELEGATION_ARTIFACT_DIR ||
      path.join(__dirname, "report", "delegation");
  log.debug("Leaving artifactDir(). " + dir);
  return dir;
}

// ---------------------------------------------------------------------------
// THE IDENTITY PROVIDER'S METADATA, WHICH IS A DIGEST AND IS COMPUTED HERE
// RATHER THAN GUESSED.
//
// The mock publishes SAML 2.0 metadata PER SERVICE PROVIDER — a distinct
// identity provider entityID and its own SSO, SLO and artifact endpoints, the
// way Okta and Ping do — and the path segment is the service provider's own
// entityID where that is safe in a URL path and `app-` plus twelve hex
// characters of its SHA-256 where it is not. Ours is a URL, so it is the
// digest, and this is the same expression `local-run-tests.sh` computes for
// `tests/saml_sso.js`.
//
// It does NOT have to exist first. That service accepts any entityID and mints
// the document on the ask, which is why the provisioning below is about the
// delegation register and not about being allowed to sign in.
// ---------------------------------------------------------------------------
function samlMetadataUrl() {
  log.debug("Entering samlMetadataUrl().");
  const slug = "app-" + crypto.createHash("sha256")
      .update(WEBAPP_URL, "utf8").digest("hex").slice(0, 12);
  const url = stsBase() + "/saml2/metadata/" + slug;
  log.debug("Leaving samlMetadataUrl(). " + url);
  return url;
}

// ---------------------------------------------------------------------------
// The management API — unprotected, deliberately, which is what lets the
// assertions run whatever the console's gate is doing.
// ---------------------------------------------------------------------------
async function delegationJson(query) {
  log.debug("Entering delegationJson(). query=" + query);
  const url = stsBase() + "/admin-api/delegation" + (query || "");
  const r = await common.httpJson(url);
  assert.ok(r.ok,
    "GET " + url + " should answer 200 and answered " + r.status + ". " +
    "That endpoint is the mock's delegation register and is NOT behind the " +
    "console's gate, so a refusal here is the service being too old for this " +
    "test (bump the sts/ submodule) rather than a permission: " +
    String(r.raw).slice(0, 200));
  log.debug("Leaving delegationJson(). held=" + r.body.held);
  return r.body;
}

// THE APPLICATIONS REGISTRY, and this is a HAND-WRITTEN COPY that is staying
// that way. Since 2026-08-27 the shared implementation is
// `tests/sts_applications.js` and every other job in the suite calls it; this
// file and `oauth2_delegation_chain.js` are two of the three it was written
// FROM. What keeps this one here is what it asserts that the shared one does
// not: `provision()` checks CONTAINMENT, and the interesting assertion below is
// that the web application's `wstrustAppliesTo` is EMPTY — an absence, which a
// containment check cannot see. See tests/CLAUDE.md.
async function applicationsApi(action, body) {
  log.debug("Entering applicationsApi(). action=" + action);
  const url = stsBase() + "/admin-api/applications/" + action;
  const r = await common.httpJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  log.debug("Leaving applicationsApi(). status=" + r.status);
  return r;
}

async function applicationEntry(identifier) {
  log.debug("Entering applicationEntry(). identifier=" + identifier);
  const url = stsBase() + "/admin-api/applications?q=" +
      encodeURIComponent(identifier) + "&per=100";
  const r = await common.httpJson(url);
  assert.ok(r.ok, "GET " + url + " should answer 200 and answered " + r.status +
            ": " + String(r.raw).slice(0, 200));
  const found = (r.body.applications || []).filter(function (one) {
    return one.identifier === identifier;
  });
  log.debug("Leaving applicationEntry(). " + found.length + " match(es).");
  return found.length ? found[0] : null;
}

// A schema attribute's values, whichever shape the registry hands them back in.
// A `multi` attribute is a list and a `single` one is a string, and both of the
// attributes this test writes are multi.
function valuesOf(value) {
  log.debug("Entering valuesOf().");
  if (value === undefined || value === null || value === "") {
    log.debug("Leaving valuesOf(). Nothing.");
    return [];
  }
  log.debug("Leaving valuesOf().");
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

// ---------------------------------------------------------------------------
// ONE APPLICATION, created or reconciled, and then READ BACK.
//
// `POST /admin-api/applications/create` takes the whole entry in one call and
// REFUSES an identifier that is already there, which is right — an identifier
// names one application whatever protocol brought it — and is a state this test
// meets in three ordinary ways: a second run against a mock that has not
// restarted, the OTHER element's run of this same file, and a run against a
// service where some earlier job has already presented one of these names,
// since a sighting creates the entry too. So a refusal for that reason is
// RECONCILED rather than treated as a failure: every value this test needs is
// added to the entry that is there, through `add`, which reports "nothing
// changed" for a value already present and is therefore safe to repeat.
//
// What is NOT tolerated is a refusal for any other reason. A create that failed
// because `wstrustAppliesTo` is not in the schema — the shape this would take
// against a mock STS from before the attribute was readable — must fail the job
// HERE, naming the attribute and the submodule, rather than three screens later
// as a delegation act whose target is a URL.
// ---------------------------------------------------------------------------
async function provisionApplication(app) {
  log.debug("Entering provisionApplication(). " + app.identifier);
  const fields = {};
  if (app.audience) {
    fields.samlEntityId = [app.audience];
  }
  if (app.appliesTo) {
    fields.wstrustAppliesTo = [app.appliesTo];
  }
  if (app.why) {
    // The sentence goes ON the entry rather than only in this file: the
    // console's applications page prints it, and a box in a delegation map
    // that links to an entry saying what that tier IS is the difference
    // between a picture and a diagram of three names.
    fields.description = [app.why];
  }
  const created = await applicationsApi("create", {
    identifier: app.identifier,
    name: app.name,
    protocols: app.protocols,
    fields: fields,
  });
  if (created.ok && created.body && created.body.ok) {
    log.info("[registry] created " + app.identifier + " — " + app.why);
  } else {
    const errors = (created.body && created.body.errors) ||
        [String(created.raw)];
    const alreadyThere = errors.some(function (one) {
      return /already in this registry/i.test(String(one));
    });
    assert.ok(alreadyThere,
      "POST /admin-api/applications/create refused " + app.identifier +
      " for a reason that is not \"it is already here\": " +
      JSON.stringify(errors) + ". If it names `wstrustAppliesTo` or " +
      "`samlEntityId` as unknown, this mock STS predates what this test " +
      "needs — bump the sts/ submodule.");
    log.info("[registry] " + app.identifier + " is already in the registry, " +
             "so this run reconciles it rather than creating it. A second " +
             "run, the other delegation element's job, or an earlier " +
             "sighting all arrive here.");
    for (let i = 0; i < app.protocols.length; i++) {
      const declared = await applicationsApi("add", {
        application: app.identifier,
        attribute: "appAllowedProtocol",
        value: app.protocols[i],
      });
      assert.ok(declared.ok && declared.body && declared.body.ok,
        "declaring " + app.protocols[i] + " on the existing " +
        app.identifier + " was refused: " + String(declared.raw).slice(0, 200));
    }
    const attributes = [];
    if (app.audience) {
      attributes.push({ attribute: "samlEntityId", value: app.audience });
    }
    if (app.appliesTo) {
      attributes.push({ attribute: "wstrustAppliesTo", value: app.appliesTo });
    }
    for (let i = 0; i < attributes.length; i++) {
      const added = await applicationsApi("add", {
        application: app.identifier,
        attribute: attributes[i].attribute,
        value: attributes[i].value,
      });
      assert.ok(added.ok && added.body && added.body.ok,
        "registering " + attributes[i].attribute + "=" +
        attributes[i].value + " on the existing " + app.identifier +
        " was refused: " + String(added.raw).slice(0, 200) + ". A refusal " +
        "naming the attribute as unknown or not editable means this mock " +
        "STS predates what this test needs — bump the sts/ submodule.");
    }
  }

  // Read back through the LIST rather than trusting the write's own reply.
  const entry = await applicationEntry(app.identifier);
  assert.ok(entry, "the registry has no application called " + app.identifier +
            " after this test created it.");
  app.protocols.forEach(function (protocol) {
    assert.ok((entry.allowedProtocols || []).indexOf(protocol) >= 0,
      app.identifier + " should be declared for " + protocol +
      " and its entry declares " + JSON.stringify(entry.allowedProtocols) +
      ". Declaring a family grants nothing in this service — it is a record " +
      "of intent — so this is asserted here or nowhere.");
  });
  const entityIds = valuesOf(entry.fields && entry.fields.samlEntityId);
  const appliesTos = valuesOf(entry.fields && entry.fields.wstrustAppliesTo);
  assert.ok(entityIds.indexOf(app.audience) >= 0,
    app.identifier + " should register " + app.audience + " on " +
    "samlEntityId — the audience an assertion for it carries — and its entry " +
    "holds " + JSON.stringify(entityIds) + ".");
  if (app.appliesTo) {
    assert.ok(appliesTos.indexOf(app.appliesTo) >= 0,
      app.identifier + " should register " + app.appliesTo + " on " +
      "wstrustAppliesTo and its entry holds " + JSON.stringify(appliesTos) +
      ". Without it the RequestSecurityToken aimed at that address is " +
      "recorded against the address rather than against this application, " +
      "and the map draws a box for a URL instead of a chain.");
  } else {
    assert.strictEqual(appliesTos.length, 0,
      app.identifier + " is a browser application and no " +
      "RequestSecurityToken here names it, so it should register no " +
      "AppliesTo. Its entry registers " + JSON.stringify(appliesTos) + ".");
  }
  log.info("[registry] " + app.identifier + ": declared for " +
           (entry.allowedProtocols || []).join(", ") + ", entityID " +
           entityIds.join(", ") + ", AppliesTo " +
           (appliesTos.length ? appliesTos.join(", ") : "(none, by design)"));
  log.debug("Leaving provisionApplication().");
  return entry;
}

async function provisionApplications() {
  log.debug("Entering provisionApplications().");
  log.info("=== Provisioning the three applications in the default realm ===");
  const entries = [];
  for (let i = 0; i < APPLICATIONS.length; i++) {
    entries.push(await provisionApplication(APPLICATIONS[i]));
  }
  log.debug("Leaving provisionApplications(). " + entries.length + ".");
  return entries;
}

// ---------------------------------------------------------------------------
// READING AN ASSERTION. With a parser rather than with a regular expression,
// because three of the four things asserted about one are STRUCTURE — an
// audience is an <saml:Audience> inside an <saml:AudienceRestriction> inside
// the <saml:Conditions>, and a document with the right string in the wrong
// place is exactly the failure worth catching.
// ---------------------------------------------------------------------------
function firstText(element, localName) {
  log.debug("Entering firstText(). localName=" + localName);
  const found = element.getElementsByTagNameNS("*", localName);
  const text = found && found.length ? (found[0].textContent || "").trim() : "";
  log.debug("Leaving firstText().");
  return text;
}

function readAssertion(xml, what) {
  log.debug("Entering readAssertion(). " + what);
  assert.ok(xml && xml.indexOf("<") >= 0,
    what + " is not XML at all. It reads: " + String(xml).slice(0, 200));
  const doc = new DOMParser().parseFromString(String(xml), "text/xml");
  const assertions = doc.getElementsByTagNameNS("*", "Assertion");
  assert.ok(assertions && assertions.length,
    what + " carries no <saml:Assertion>. It reads: " +
    String(xml).slice(0, 400));
  const element = assertions[0];
  const conditions = element.getElementsByTagNameNS("*", "Conditions");
  const restrictions = element
      .getElementsByTagNameNS("*", "AudienceRestriction");
  const audiences = [];
  for (let i = 0; restrictions && i < restrictions.length; i++) {
    const named = restrictions[i].getElementsByTagNameNS("*", "Audience");
    for (let j = 0; named && j < named.length; j++) {
      audiences.push((named[j].textContent || "").trim());
    }
  }
  const read = {
    id: element.getAttribute("ID") || element.getAttribute("AssertionID") || "",
    subject: firstText(element, "NameID") ||
             firstText(element, "NameIdentifier"),
    issuer: firstText(element, "Issuer"),
    audiences: audiences,
    hasConditions: !!(conditions && conditions.length),
    signed: !!(element.getElementsByTagNameNS("*", "Signature") || []).length,
    xml: String(xml),
  };
  log.debug("Leaving readAssertion(). id=" + read.id);
  return read;
}

// One assertion, against what this hop said it would produce. The audience is
// asserted BOTH ways — the tier it reaches is in it, and the tier it came from
// is not — because an STS that echoed its input would satisfy the first alone.
function assertAssertion(read, expected) {
  log.debug("Entering assertAssertion(). " + expected.what);
  assert.ok(read.id,
    expected.what + " carries no AssertionID. Everything the register says " +
    "about it, and the whole of its lineage, is keyed on that identifier.");
  assert.strictEqual(read.subject, USER,
    expected.what + " names \"" + read.subject + "\" as its subject rather " +
    "than " + USER + ". A delegated token that describes somebody else is " +
    "not a delegation.");
  assert.ok(read.hasConditions,
    expected.what + " carries no <saml:Conditions>, so it has no audience " +
    "restriction and any service would be entitled to act on it.");
  assert.deepStrictEqual(read.audiences, [expected.audience],
    expected.what + " should be addressed to " + expected.audience +
    " and to nothing else, and its AudienceRestriction holds " +
    JSON.stringify(read.audiences) + ". An AudienceRestriction is the SAML " +
    "spelling of an `aud` claim: it is what says this credential may be " +
    "acted on by that party and by no other.");
  if (expected.notAudience) {
    assert.ok(read.audiences.indexOf(expected.notAudience) < 0,
      expected.what + " is still addressed to " + expected.notAudience +
      ", which is the tier it has already left. An assertion carrying both " +
      "would mean the STS widened the audience rather than replacing it.");
  }
  if (expected.notId) {
    assert.notStrictEqual(read.id, expected.notId,
      expected.what + " has the same AssertionID as the assertion that was " +
      "handed IN (" + expected.notId + "), so this STS echoed its input " +
      "rather than issuing anything.");
  }
  log.info("[assertion] " + expected.what + ": " + read.id + ", subject " +
           read.subject + ", audience " + read.audiences.join(", ") +
           (read.signed ? ", signed" : ", UNSIGNED"));
  log.debug("Leaving assertAssertion().");
}

// ---------------------------------------------------------------------------
// PAGE PLUMBING. The same four helpers tests/wstrust.js uses, for the same
// reasons: a value set through the DOM has to fire input+change or the page
// neither stores it nor rebuilds the request from it.
// ---------------------------------------------------------------------------
async function setField(driver, id, value) {
  log.debug("Entering setField(). id=" + id);
  await driver.wait(until.elementLocated(By.id(id)), waitTime);
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]);" +
    " if(e){ e.value=arguments[1];" +
    " e.dispatchEvent(new Event('input'));" +
    " e.dispatchEvent(new Event('change')); }",
    id, value
  );
  log.debug("Leaving setField().");
}

async function setChecked(driver, id, on) {
  log.debug("Entering setChecked(). id=" + id);
  await driver.wait(until.elementLocated(By.id(id)), waitTime);
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]);" +
    " if(e && e.checked!==arguments[1]){ e.checked=arguments[1];" +
    " e.dispatchEvent(new Event('change')); }",
    id, !!on
  );
  log.debug("Leaving setChecked().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). id=" + id);
  const value = await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(!e) return '';" +
    " return (e.value !== undefined && e.value !== null && e.value !== '')" +
    " ? e.value : (e.textContent || '');",
    id
  );
  log.debug("Leaving textOf().");
  return value;
}

// A button, by its label. SCROLLED and then clicked through the DOM rather than
// natively: these two pages are tall, the suite runs in a pool, and a native
// click on a control low on a long page has been seen to land on nothing at all
// under load. The handlers here are inline `onclick`s, so a scripted click
// fires exactly what a real one would — provided the bundle has loaded, which
// is what waitForPageBundle() above every call site is for.
async function clickByValue(driver, value) {
  log.debug("Entering clickByValue(). value=" + value);
  const locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  const button = await driver.findElement(locator);
  await driver.wait(until.elementIsVisible(button), waitTime);
  await driver.executeScript(
    "arguments[0].scrollIntoView({ block: 'center' }); arguments[0].click();",
    button);
  log.debug("Leaving clickByValue().");
}

// Poll a field's value until the predicate passes.
async function waitForValue(driver, id, predicate, message, timeout) {
  log.debug("Entering waitForValue(). id=" + id);
  await driver.wait(until.elementLocated(By.id(id)), waitTime);
  await driver.wait(async function () {
    try {
      const value = await textOf(driver, id);
      return predicate(value || "");
    } catch (e) {
      // The page can be mid-navigation, which is not a failure of the
      // predicate. Swallowed on purpose: the wait's own timeout is what says
      // the value never arrived.
      return false;
    }
  }, timeout || waitTime, message);
  log.debug("Leaving waitForValue().");
}

// ---------------------------------------------------------------------------
// HOP 0 — THE SIGN-IN. SAML 2.0 Web Browser SSO, HTTP-POST binding, at the mock
// STS, for the web application's entityID. What comes back is the credential
// the whole chain rests on.
// ---------------------------------------------------------------------------
async function signInOverSaml(driver) {
  log.debug("Entering signInOverSaml().");
  log.info("=== " + WEBAPP + ": SAML 2.0 HTTP-POST sign-in as " + USER +
           " ===");
  // The mock renders in milliseconds; the POST round trip through the api's ACS
  // does not, and a cold browser is slower than either. One generous timeout
  // rather than a branch — it costs nothing when nothing is slow.
  const loginWait = Math.max(waitTime, 15000);

  await loadPage(driver, baseUrl + "/saml_request.html", "saml_sp_entity_id",
                 { timeout: waitTime });
  await waitFor.waitForPageBundle(driver, "saml_request.html's bundle");

  log.info("Load the identity provider's metadata: " + samlMetadataUrl());
  await setField(driver, "saml_metadata_url", samlMetadataUrl());
  await clickByValue(driver, "Load Metadata");
  await waitForValue(driver, "saml_metadata_status",
    function (v) { return v.indexOf("Loaded and parsed") >= 0; },
    "the identity provider's metadata was not loaded and parsed from " +
    samlMetadataUrl() + ". The mock mints that document for any entityID " +
    "asked of it, so a failure here is the browser not reaching the STS — a " +
    "certificate it does not trust, most likely; see browser_flags.js.",
    loginWait);

  // The service provider is the WEB APPLICATION, and its entityID is the URL
  // the assertion must come back addressed to.
  await setField(driver, "saml_sp_entity_id", WEBAPP_URL);
  // Unsigned — see the header. The mock verifies no request signature, so
  // signing here would prove nothing and would make this job depend on the
  // per-run SP key pair.
  await setChecked(driver, "saml_sign_request", false);
  // The binding under test, and the one the scenario names.
  await setField(driver, "saml_binding", "post");
  const binding = await textOf(driver, "saml_binding");
  assert.strictEqual(binding, "post",
    "the HTTP-POST binding is not selectable on this page (the selector " +
    "holds \"" + binding + "\").");

  log.info("Call the identity provider over the HTTP-POST binding.");
  await clickByValue(driver, "Call IdP");

  // The mock's sign-in screen, which reuses Keycloak's field ids so that a test
  // does not have to know which screen it is looking at. It checks no password;
  // the username typed here is the identity the assertion then describes.
  const username = By.id("username");
  await driver.wait(until.elementLocated(username), loginWait,
    "the identity provider never showed its sign-in screen (no #username " +
    "field).");
  await driver.wait(until.elementIsVisible(driver.findElement(username)),
                    loginWait);
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(USER);
  const passwords = await driver.findElements(By.id("password"));
  if (passwords.length) {
    await passwords[0].clear();
    await passwords[0].sendKeys(USER);
  }
  const buttons = ["kc-login", "saml2-login"];
  let clicked = null;
  for (let i = 0; i < buttons.length; i++) {
    const found = await driver.findElements(By.id(buttons[i]));
    if (found.length) {
      clicked = buttons[i];
      await found[0].click();
      break;
    }
  }
  assert.ok(clicked,
    "the sign-in screen carries none of the submit buttons this test knows (" +
    buttons.join(", ") + "). The username field was there, so this is a new " +
    "identity provider rather than a broken page.");

  log.info("Wait for the SAML response page.");
  await driver.wait(until.urlContains("saml_response.html"), loginWait,
    "the identity provider's POST never reached the assertion consumer " +
    "service, so the browser never arrived at saml_response.html. That ACS " +
    "is served by the api, which this job therefore needs.");
  await waitForValue(driver, "saml_resp_xml",
    function (v) { return v.indexOf("Response") >= 0; },
    "the SAMLResponse was never rendered.", loginWait);
  await waitForValue(driver, "saml_assertion_xml",
    function (v) {
      return v.indexOf("Assertion") >= 0 && v.indexOf("no <Assertion") < 0;
    },
    "the SAMLResponse carried no <Assertion>, which is what a SAML error " +
    "status looks like on this page.", loginWait);

  const xml = await textOf(driver, "saml_assertion_xml");
  const read = readAssertion(xml, "the sign-in assertion");
  assertAssertion(read, {
    what: "the sign-in assertion",
    audience: WEBAPP_URL,
  });
  log.debug("Leaving signInOverSaml(). " + read.id);
  return read;
}

// ---------------------------------------------------------------------------
// ONE WS-TRUST HOP. A new workflow — the storage is cleared first — configured
// as the requester this hop is, carrying the assertion it was handed, and aimed
// at the tier it is reaching.
//
// THE PREVIEW IS ASSERTED BEFORE THE BUTTON IS PRESSED. Everything that makes
// this hop different from the one before it is a field that could be stale, and
// the page draws exactly what it is about to send.
// ---------------------------------------------------------------------------
async function exchange(driver, hop, held) {
  log.debug("Entering exchange(). as=" + hop.as);
  log.info("=== " + hop.as + ": WS-Trust Issue with " + DELEGATION.spelling +
           ", AppliesTo " + hop.appliesTo + " — " + hop.what + " ===");
  const sendWait = Math.max(waitTime, 15000);

  // A NEW WORKFLOW. Cleared from the page rather than by deleting cookies: this
  // is localStorage, it is per-origin, and the debugger keeps every field of
  // the workflow in it. Without this, hop 2 would inherit hop 1's AppliesTo,
  // its UsernameToken and its delegated assertion, and a hop that set nothing
  // at all would still send a well-formed request.
  await loadPage(driver, baseUrl + "/wstrust_tools.html", "wst_sts_url",
                 { timeout: waitTime });
  await waitFor.waitForPageBundle(driver,
      "wstrust_tools.html's bundle (before clearing the workflow)");
  await driver.executeScript("window.localStorage.clear();");
  await loadPage(driver, baseUrl + "/wstrust_tools.html", "wst_sts_url",
                 { timeout: waitTime });
  await waitFor.waitForPageBundle(driver, "wstrust_tools.html's bundle");
  const leftBehind = await textOf(driver, "wst_applies_to");
  assert.notStrictEqual(leftBehind, hop.appliesTo,
    "after the clear the AppliesTo field already reads " + hop.appliesTo +
    ", so the workflow was not reset and every field this hop sets would be " +
    "indistinguishable from one left behind.");

  await setField(driver, "wst_sts_url", stsEndpoint());
  // The version first, so its option-gating (ActAs is 1.4, Bearer is 1.3+) is
  // applied before anything that depends on it is set.
  await setField(driver, "wst_trust_version", TRUST_VERSION);
  await setField(driver, "wst_operation", "issue");
  await setField(driver, "wst_token_type", "saml2");
  await setField(driver, "wst_applies_to", hop.appliesTo);

  // WHO IS ASKING. The requester authenticates as itself — the web application,
  // then the bus — and this is the identity the register records as the
  // INTERMEDIARY of the act. The mock checks no password, refusing only the
  // literal "invalid".
  await setField(driver, "wst_cred_mode", "usernametoken");
  await setField(driver, "wst_username", hop.as);
  await setField(driver, "wst_password", hop.as);

  // WHOSE TOKEN IT IS ASKING FOR, and what it is delegating with. The assertion
  // the previous step produced goes into the element this run is carrying.
  await setChecked(driver, DELEGATION.check, true);
  await setField(driver, DELEGATION.field, held.xml);
  // And the OTHER element is left off, explicitly rather than by default: a
  // request carrying both is attributed to OnBehalfOf by this STS, so a stray
  // ActAs would silently turn the ActAs run into an OnBehalfOf one.
  const other = DELEGATION.element === "actas"
      ? "wst_use_onbehalfof" : "wst_use_actas";
  await setChecked(driver, other, false);

  // Routing. "back" sends through the api's proxy (POST /wstrust); "front"
  // makes the browser call the STS directly, which the mock's permissive CORS
  // headers allow. run-report.js chooses, because a target with no api has only
  // the second.
  const route = (process.env.WSTRUST_ROUTE || "back").toLowerCase();
  await setChecked(driver, "wst_initiateFromBackEnd", route !== "front");
  await setChecked(driver, "wst_initiateFromFrontEnd", route === "front");

  // --- what it is about to send ------------------------------------------
  await waitForValue(driver, "wst_generated_request",
    function (v) { return v.indexOf("RequestSecurityToken") >= 0; },
    "the page never built a RequestSecurityToken to preview.", sendWait);
  const request = await textOf(driver, "wst_generated_request");
  assert.ok(request.indexOf(DELEGATION.markup) >= 0,
    "the request this hop is about to send carries no <" +
    DELEGATION.markup + ">, so it would be an ordinary Issue rather than a " +
    "delegation. It reads: " + request.slice(0, 600));
  assert.ok(request.indexOf(hop.appliesTo) >= 0,
    "the request does not name " + hop.appliesTo + " in its AppliesTo, so " +
    "the assertion it comes back with would be addressed somewhere else. It " +
    "reads: " + request.slice(0, 600));
  assert.ok(request.indexOf(held.id) >= 0,
    "the request does not carry the assertion this hop was handed (" +
    held.id + ") — so it is delegating with something else, most likely a " +
    "token left in the previous workflow's storage. It reads: " +
    request.slice(0, 600));
  assert.ok(request.indexOf("<wsse:Username>" + hop.as + "<") >= 0 ||
            request.indexOf(">" + hop.as + "</wsse:Username>") >= 0,
    "the request does not present " + hop.as + " in its UsernameToken, so " +
    "the register would record somebody else as the middle tier. It reads: " +
    request.slice(0, 600));
  log.info("[request] " + hop.as + " -> " + hop.appliesTo + ", " +
           DELEGATION.spelling + " " + held.id + ", over the " + route +
           " route.");

  log.info("Send the RequestSecurityToken.");
  await clickByValue(driver, "Send Request");
  await driver.wait(until.urlContains("wstrust_response.html"), sendWait,
    "the page never navigated to the WS-Trust response page.");
  await waitForValue(driver, "wst_resp_status",
    function (v) {
      return v.indexOf("response loaded") >= 0 ||
             v.indexOf("could not parse") >= 0;
    },
    "the WS-Trust response was not rendered.", sendWait);

  const responseXml = await textOf(driver, "wst_response_xml");
  log.info("RSTR (first 800 chars):\n" + (responseXml || "").slice(0, 800));
  assert.ok(responseXml &&
            responseXml.indexOf("RequestSecurityTokenResponse") >= 0,
    "the STS did not answer with a RequestSecurityTokenResponse. It said: " +
    String(responseXml).slice(0, 600));
  const tokenXml = await textOf(driver, "wst_token_xml");
  const read = readAssertion(tokenXml, "the assertion issued for " +
                             hop.appliesTo);
  assertAssertion(read, {
    what: "the assertion issued to " + hop.as + " for " + hop.appliesTo,
    audience: hop.appliesTo,
    notAudience: held.audiences[0],
    notId: held.id,
  });
  log.debug("Leaving exchange(). " + read.id);
  return read;
}

// ---------------------------------------------------------------------------
// THE REGISTER. One act per hop, found among the acts recorded SINCE this job
// started — never among all of them, because the mock's stores survive between
// jobs and the suite runs in a pool. The TYPE is part of the filter as well as
// the sequence, because the OTHER run of this file (the other delegation
// element) may be in the pool at the same moment, with the same person, the
// same applications and the same two addresses.
// ---------------------------------------------------------------------------
function findAct(acts, hop) {
  log.debug("Entering findAct(). as=" + hop.as);
  const found = acts.filter(function (row) {
    return row.type === DELEGATION.type &&
           row.intermediary && row.intermediary.presented === hop.as &&
           row.target && row.target.application === hop.target;
  });
  assert.strictEqual(found.length, 1,
    "the delegation register should hold exactly ONE " + DELEGATION.type +
    " act recorded by this job in which " + hop.as + " reached " + hop.target +
    " (asked for as " + hop.appliesTo + "), and it holds " + found.length +
    ". A zero here with an act whose target IS that address means the " +
    "AppliesTo was not resolved through the registry — see " +
    "applications.forAppliesTo(). What it holds since this job started: " +
    JSON.stringify(acts.map(function (row) {
      return row.type + " " + (row.initial.presented || "?") + " -> " +
             (row.intermediary.presented || "?") + " -> " +
             (row.target.application || "?");
    })) + ".");
  log.debug("Leaving findAct(). seq=" + found[0].seq);
  return found[0];
}

function assertActRecords(act, hop, issued, held) {
  log.debug("Entering assertActRecords(). as=" + hop.as);
  assert.strictEqual(act.protocol, "WS-Trust",
    "the act was filed under protocol \"" + act.protocol + "\".");
  assert.strictEqual(act.type, DELEGATION.type,
    "this run carries " + DELEGATION.spelling + " (" + DELEGATION.what +
    "), and the register filed the act as \"" + act.type + "\".");
  assert.strictEqual(act.mode, DELEGATION.mode,
    "the act's mode is \"" + act.mode + "\" and should be \"" +
    DELEGATION.mode + "\". Mode is the axis that says whether the far end " +
    "can see the middle tier, and getting it wrong is worse than getting the " +
    "type wrong.");
  assert.strictEqual(act.outcome, "issued",
    "the act was recorded with outcome \"" + act.outcome + "\".");
  assert.strictEqual(act.initial.presented, USER,
    "the act names \"" + act.initial.presented + "\" as the identity being " +
    "acted for, rather than " + USER + ".");
  assert.strictEqual(act.intermediary.presented, hop.as,
    "the act names \"" + act.intermediary.presented + "\" as the middle tier " +
    "rather than " + hop.as + ". That is whoever the WS-Security header " +
    "presented, which is the one party in this request that authenticated.");
  assert.strictEqual(act.intermediary.application, hop.as,
    "the act does not link the middle tier to the registry entry called " +
    hop.as + " (it says \"" + act.intermediary.application + "\"), so the " +
    "map draws it as a person rather than as the application it is.");
  assert.strictEqual(act.target.application, hop.target,
    "the act says the request reached \"" + act.target.application +
    "\" rather than " + hop.target + ". It asked for the AppliesTo " +
    hop.appliesTo + ", which that application registers, so the register " +
    "should name the APPLICATION — a row naming the address is the lookup " +
    "not happening, and it draws a box in the map that nothing else in the " +
    "picture mentions.");
  // AND THE ROW SAYS WHICH ADDRESS RESOLVED. Without this the two facts are
  // indistinguishable on the page: an act filed against `esb` because the RST
  // named `esb`, and one filed against `esb` because the address it named is
  // registered there. The second is what happened and only the sentence can
  // say so.
  assert.ok(String(act.target.what || "").indexOf(hop.appliesTo) >= 0,
    "the act's target names " + hop.target + " and its explanation does not " +
    "mention the AppliesTo that was actually requested (" + hop.appliesTo +
    "). It says: \"" + act.target.what + "\".");
  const produced = (act.produced || []).filter(function (one) {
    return one.kind === "SAML 2.0 assertion";
  });
  assert.strictEqual(produced.length, 1,
    "the act should record ONE SAML 2.0 assertion as what it produced, and " +
    "records " + JSON.stringify(act.produced) + ".");
  assert.strictEqual(produced[0].identifier, issued.id,
    "the register says this act produced the assertion whose ID is \"" +
    produced[0].identifier + "\", and the assertion this test received is \"" +
    issued.id + "\". The row and the wire are describing different tokens.");
  // AND WHAT IT WAS DELEGATED WITH, which is the join /admin/tokens/credential
  // walks: the identifier one act produced is the identifier the next act
  // consumed. A row that recorded only the requester's WS-Security credential
  // would leave the lineage of this assertion stopping one generation in.
  const consumed = (act.consumed || []).filter(function (one) {
    return String(one.identifier || "") === held.id;
  });
  assert.strictEqual(consumed.length, 1,
    "the act should record the assertion it was handed (" + held.id + ") as " +
    "what it consumed, and it records " + JSON.stringify(act.consumed) +
    ". Without that identifier nothing joins this hop to the one before it, " +
    "and the credential's lineage stops here.");
  log.info("[register] act " + act.seq + ": " + act.typeLabel + " — " +
           act.initial.presented + " -> " + act.intermediary.presented +
           " -> " + act.target.application + ", consuming " + held.id +
           ", producing " + produced[0].identifier);
  log.debug("Leaving assertActRecords().");
}

// ---------------------------------------------------------------------------
// THE PICTURE'S MODEL. The nodes and edges /admin/delegation/map draws, read
// from the same JSON that page is built from — which is the only way a drawing
// can be checked from outside without parsing an SVG.
// ---------------------------------------------------------------------------
function assertGraphIsAChain(graph) {
  log.debug("Entering assertGraphIsAChain().");
  const nodeOf = function (id) {
    log.debug("Entering nodeOf(). id=" + id);
    const found = (graph.nodes || []).filter(function (n) {
      return n.id === id;
    });
    assert.strictEqual(found.length, 1,
      "the picture should hold exactly one box called \"" + id +
      "\" and holds " + found.length + ". Its boxes are: " +
      JSON.stringify((graph.nodes || []).map(function (n) { return n.id; })) +
      ".");
    log.debug("Leaving nodeOf().");
    return found[0];
  };
  // MATCHED ON THE ELEMENT AS WELL AS THE TWO ENDS, and that is the whole of
  // why this helper takes a type. The map keys an edge by (from, to, relation,
  // TYPE), the register survives between jobs, and the OnBehalfOf run and the
  // ActAs run of this same file use the same person and the same three
  // applications on purpose — so `carol_end_user -acts-for-> portal1` is TWO
  // lines in that picture, one per element, and a match on the ends alone
  // returns whichever run recorded first. That is how this passed for the
  // ActAs job and failed for the OnBehalfOf one in the same pool: the mode
  // asserted below was the other job's.
  const edgeOf = function (from, to, relation) {
    log.debug("Entering edgeOf(). " + from + " -> " + to);
    const between = (graph.edges || []).filter(function (e) {
      return e.from === from && e.to === to && e.relation === relation;
    });
    const found = between.filter(function (e) {
      return e.type === DELEGATION.type;
    });
    assert.ok(found.length,
      "the picture should draw a \"" + relation + "\" line from " + from +
      " to " + to + " for " + DELEGATION.spelling + " (" + DELEGATION.type +
      "), and draws " + between.length + " line(s) between them, none of " +
      "them this run's element. Its lines are: " +
      JSON.stringify((graph.edges || []).map(function (e) {
        return e.from + " -" + e.relation + "/" + e.type + "-> " + e.to;
      })) + ".");
    log.debug("Leaving edgeOf().");
    return found[0];
  };

  HOPS.forEach(function (hop) {
    // Each act draws two lines and they say different things: who is acting for
    // whom, and what the credential that came out is FOR.
    const actsFor = edgeOf(USER, hop.as, "acts-for");
    assert.strictEqual(actsFor.mode, DELEGATION.mode,
      "the line from " + USER + " to " + hop.as + " is drawn as \"" +
      actsFor.mode + "\" and this run's element is " + DELEGATION.spelling +
      ", which is " + DELEGATION.mode + ".");
    const reaches = edgeOf(hop.as, hop.target, "reaches");
    assert.strictEqual(reaches.subject, USER,
      "the line from " + hop.as + " to " + hop.target + " should be " +
      "labelled with whose name the credential carries (" + USER + ") and " +
      "carries \"" + reaches.subject + "\".");
  });

  // THE ONE PROPERTY THAT MAKES THIS A CHAIN RATHER THAN TWO REQUESTS. The
  // middle of the second hop is the far end of the first, and the picture must
  // have ONE box for it: two would be two unrelated pictures that happen to be
  // about the same service, which is exactly what a delegation map exists to
  // disprove. It is also the assertion that fails when the AppliesTo lookup is
  // missing, because then the first hop lands on a box called
  // `https://esb.example.com` and this one is never reached at all.
  const middle = nodeOf(ESB);
  assert.ok(middle.roles.target >= 1,
    "the picture does not show " + ESB + " as the target of anything, so the " +
    "first hop's arrow lands somewhere else — at the ADDRESS, if the " +
    "registry lookup did not happen.");
  assert.ok(middle.roles.intermediary >= 1,
    "the picture does not show " + ESB + " as an intermediary, so the second " +
    "hop was made by somebody else.");
  log.info("[picture] " + ESB + " is one box that was reached " +
           middle.roles.target + " time(s) and acted as an intermediary " +
           middle.roles.intermediary + " time(s) — the two hops meet there.");

  // And the person is one box too: both hops are about the same identity.
  const person = nodeOf(USER);
  assert.ok(person.roles.initial >= 2,
    "the picture should show " + USER + " as the identity behind BOTH hops " +
    "and shows " + person.roles.initial + ".");
  log.debug("Leaving assertGraphIsAChain().");
}

// ---------------------------------------------------------------------------
// A browser sign-on session for the CONSOLE, which only the drawings and the
// lineage need. The three-step dance is the one a browser does and is copied
// from tests/admin_api.js, which explains it at length.
//
// Returns the cookie, or null when the gate is off (a legitimate state — the
// setting is switchable — reported rather than treated as a pass) or when the
// roster has been narrowed by some other job and this user holds nothing.
// ---------------------------------------------------------------------------
async function signInToTheConsole() {
  log.debug("Entering signInToTheConsole().");
  const base = stsBase();
  const gated = await fetch(base + "/admin/delegation", { redirect: "manual" });
  if (gated.status !== 302) {
    log.info("[console] admin.authRequired is off (GET /admin/delegation " +
             "answered " + gated.status + " with no redirect), so the " +
             "drawings need no session.");
    log.debug("Leaving signInToTheConsole(). The gate is off.");
    return null;
  }
  const where = gated.headers.get("location") || "";
  const authn = (where.match(/[?&]authn=([^&]+)/) || [])[1];
  if (!authn) {
    log.warn("[console] a gated GET was sent to \"" + where + "\", which " +
             "carries no authn id, so there is nothing to sign in FOR. The " +
             "drawings are skipped; the assertions do not need them.");
    log.debug("Leaving signInToTheConsole(). No authn id.");
    return null;
  }
  const body = "authn_id=" + encodeURIComponent(authn) +
      "&username=" + encodeURIComponent(CONSOLE_USER) +
      "&password=" + encodeURIComponent(CONSOLE_USER);
  const signedIn = await fetch(base + "/authn/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body,
    redirect: "manual",
  });
  const setCookie = signedIn.headers.get("set-cookie") || "";
  const session = (setCookie.match(/(sts_mock_session=[^;]+)/) || [])[1];
  if (!session) {
    log.warn("[console] signing in at /authn/login answered " +
             signedIn.status + " and set no session cookie (\"" + setCookie +
             "\"). The drawings are skipped.");
    log.debug("Leaving signInToTheConsole(). No cookie.");
    return null;
  }
  log.info("[console] signed in as " + CONSOLE_USER + " for the drawings.");
  log.debug("Leaving signInToTheConsole(). Holding a session.");
  return session;
}

// One document off the console, written to a file. Returns the bytes, or null
// when the console refused — which is reported and is not a failure, for the
// reason the header gives.
async function saveDrawing(session, urlPath, filename, what) {
  log.debug("Entering saveDrawing(). " + filename);
  const url = stsBase() + urlPath;
  const r = await fetch(url, session ? { headers: { Cookie: session } } :
      undefined);
  if (r.status === 401 || r.status === 403) {
    log.warn("[drawing] the console refused " + url + " with " + r.status +
             ". That is its own gate (admin.authRequired) and its roster: " +
             "some other job has granted a console role to somebody else, so " +
             "`admin.openWhenEmpty` no longer makes this session an " +
             "administrator. " + what + " was not saved.");
    log.debug("Leaving saveDrawing(). Refused.");
    return null;
  }
  const text = await r.text();
  assert.strictEqual(r.status, 200,
    "GET " + url + " should answer 200 and answered " + r.status + ": " +
    text.slice(0, 200));
  fs.mkdirSync(artifactDir(), { recursive: true });
  const file = path.join(artifactDir(), filename);
  fs.writeFileSync(file, text);
  log.info("[drawing] " + what + " -> " + file + " (" + text.length +
           " bytes)");
  log.debug("Leaving saveDrawing().");
  return text;
}

// One console page, as JSON. The console answers `?format=json` on every page
// and refuses it with 401 rather than redirecting when there is no session,
// which is the whole reason signInToTheConsole() exists. Null when the gate
// turned it down — the caller reports that and moves on.
async function consoleJson(session, urlPath, what) {
  log.debug("Entering consoleJson(). " + urlPath);
  const url = stsBase() + urlPath;
  const r = await common.httpJson(url,
      session ? { headers: { Cookie: session } } : undefined);
  if (r.status === 401 || r.status === 403) {
    log.warn("[console] " + url + " was refused with " + r.status + ". That " +
             "is the console's own gate and its roster — some other job has " +
             "granted a console role to somebody else, so this session is no " +
             "longer an administrator. " + what + " was not checked.");
    log.debug("Leaving consoleJson(). Refused.");
    return null;
  }
  assert.strictEqual(r.status, 200,
    "GET " + url + " should answer 200 and answered " + r.status + ": " +
    String(r.raw).slice(0, 200));
  log.debug("Leaving consoleJson(). Read it.");
  return r.body;
}

// ---------------------------------------------------------------------------
// THE ASSERTION'S ANCESTRY, at /admin/tokens/credential.
//
// The one thing in this scenario that no single register can answer, and the
// reason it is asserted HERE rather than in a test of its own: it needs a
// credential with two generations of exchange behind it, and the only two jobs
// in this suite that produce one are this file and the OAuth chain.
//
// The page walks by IDENTIFIER — what one act produced is what the next act
// consumed — so the three AssertionIDs this test actually received off the wire
// are the assertion. A lineage that agreed about the SHAPE (three generations,
// two exchanges) and named different assertions would be a page describing
// somebody else's chain.
//
// AND THE ORIGIN IS THE SIGN-IN, which is the part that is worth the trouble:
// the head of the line was issued by an ordinary SAML 2.0 Web Browser SSO and
// nobody exchanged anything to get it. That is the credential the browser was
// handed, and no WS-Trust message in this test ever mentions it.
// ---------------------------------------------------------------------------
async function assertTheLineage(session, ids) {
  log.debug("Entering assertTheLineage().");
  log.info("=== The assertion's ancestry, at /admin/tokens/credential ===");
  const lineage = await consoleJson(session,
      "/admin/tokens/credential?id=" + encodeURIComponent(ids[0]) +
      "&format=json", "the final assertion's lineage");
  if (!lineage) {
    log.debug("Leaving assertTheLineage(). The console refused it.");
    return;
  }
  const walked = (lineage.generations || []).map(function (one) {
    return String(one.identifier || "");
  });
  assert.deepStrictEqual(walked, ids,
    "the lineage of " + ids[0] + " should be the three assertions this test " +
    "received, newest first (" + JSON.stringify(ids) + "), and the page " +
    "walked " + JSON.stringify(walked) + ". A short walk means an act did " +
    "not record what it consumed; a walk naming other identifiers means the " +
    "join found somebody else's credential.");
  assert.deepStrictEqual(lineage.origins || [], [ids[2]],
    "the head of the line should be the SIGN-IN assertion (" + ids[2] +
    "), which nothing was exchanged to get, and the page calls " +
    JSON.stringify(lineage.origins) + " the origin.");
  log.info("[lineage] " + walked.join(" <- ") + ", origin " + ids[2] +
           " — the assertion the browser was handed.");
  log.debug("Leaving assertTheLineage().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    // "=new", not bare --headless: the tests image pins Chrome 121, where the
    // old headless implementation ignores
    // --unsafely-treat-insecure-origin-as-secure. See tests/browser_flags.js.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  // /tmp rather than the container's 64MB /dev/shm.
  options.addArguments("--disable-dev-shm-usage");
  // This also puts the mock STS's key in front of Chrome as an SPKI pin, which
  // this test needs and most do not: the browser fetches the identity
  // provider's SAML metadata from that https origin directly. Without it the
  // sign-in half meets a certificate interstitial instead of a metadata
  // document, and what the log says is that the metadata never parsed. It is
  // NOT called again below — addBrowserAccessFlags() is the caller of
  // addStsTrustFlags(), and the six tests that call it themselves are the ones
  // that build their options by hand.
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
    log.info("The STS is " + stsEndpoint() + ", carrying " +
             DELEGATION.spelling + " (" + DELEGATION.what + ").");
    log.info("The chain: " + USER + " signs in to " + WEBAPP + " (" +
             WEBAPP_URL + ") over SAML 2.0 HTTP-POST; " + WEBAPP +
             " exchanges that assertion for " + ESB_URL + " (" + ESB +
             "); " + ESB + " exchanges that for " + PROVIDER_URL + " (" +
             PROVIDER + ").");

    await provisionApplications();

    // The baseline, BEFORE anything is issued. Everything asserted below is a
    // delta against it: this mock's register survives between jobs and the
    // suite runs in a pool.
    const before = await delegationJson("?per=1");
    const baselineSeq = Number(before.newestSeq || 0);
    log.info("[register] " + before.held + " act(s) already held; this job's " +
             "assertions are about acts after seq " + baselineSeq + ".");

    // --- hop 0: the browser sign-in ----------------------------------------
    const signIn = await signInOverSaml(driver);

    // --- hops 1 and 2: the two WS-Trust exchanges --------------------------
    const first = await exchange(driver, HOPS[0], signIn);
    const second = await exchange(driver, HOPS[1], first);

    log.info("=== The assertion the back end would receive ===");
    log.info(second.xml);

    // --- the register and the picture --------------------------------------
    const after = await delegationJson("?q=" + encodeURIComponent(USER) +
                                       "&per=200");
    const mine = (after.acts || []).filter(function (row) {
      return Number(row.seq) > baselineSeq;
    });
    assert.ok(mine.length >= 2,
      "this job made two WS-Trust exchanges and the register holds " +
      mine.length + " act(s) recorded since it started. A delegation " +
      "performed and not recorded is one this service cannot account for.");
    const acts = HOPS.map(function (hop) {
      return findAct(mine, hop);
    });
    assertActRecords(acts[0], HOPS[0], first, signIn);
    assertActRecords(acts[1], HOPS[1], second, first);
    assert.ok(Number(acts[1].seq) > Number(acts[0].seq),
      "the register puts the second hop (seq " + acts[1].seq + ") before the " +
      "first (seq " + acts[0].seq + ").");

    // The graph of what matched — this person's acts — which is what
    // /admin/delegation/map draws for the same filter.
    assertGraphIsAChain(after.graph || {});

    // --- where the final assertion came from --------------------------------
    // The console is the only door to the lineage page: it has no form and
    // therefore no operation on /admin-api (the mock's rule 7), so the session
    // is obtained here and the drawings below reuse it.
    const session = await signInToTheConsole();
    await assertTheLineage(session, [second.id, first.id, signIn.id]);

    // --- the drawings ------------------------------------------------------
    const filter = "?q=" + encodeURIComponent(USER);
    const suffix = "-" + DELEGATION.element;
    const svg = await saveDrawing(session,
        "/admin/delegation/map" + filter + "&format=svg",
        "wstrust-delegation-map-" + USER + suffix + ".svg",
        "the delegation map, filtered to " + USER);
    if (svg) {
      // A drawing that draws nothing is the failure worth catching: the page
      // answers 200 with an empty diagram when the graph is empty, and an SVG
      // file nobody opened would never say so.
      assert.ok(svg.indexOf("<svg") >= 0,
        "the map answered 200 with something that is not an SVG document: " +
        svg.slice(0, 200));
      // Searched with the MARKUP REMOVED rather than in the raw document: a box
      // label is wrapped into several <tspan>s and capped at 30 characters, so
      // a name can be split across elements even when it is drawn whole.
      // Stripping the tags rejoins it, and it also reaches the <title> the
      // renderer puts on every shape, which carries the label uncut.
      const drawn = svg.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
      const joined = svg.replace(/<[^>]*>/g, "");
      [USER, WEBAPP, ESB, PROVIDER].forEach(function (name) {
        assert.ok(drawn.indexOf(name) >= 0 || joined.indexOf(name) >= 0,
          "the drawing does not mention \"" + name + "\", so the picture is " +
          "missing a box the graph says is in it. What it draws: " +
          drawn.slice(0, 400));
      });
      log.info("[drawing] the map names " + USER + ", " + WEBAPP + ", " + ESB +
               " and " + PROVIDER + ".");
      await saveDrawing(session, "/admin/delegation/map?format=svg",
          "wstrust-delegation-map-all" + suffix + ".svg",
          "the delegation map, everything this service has recorded");
      await saveDrawing(session,
          "/admin/delegation/map" + filter + "&format=json",
          "wstrust-delegation-map-" + USER + suffix + ".json",
          "the graph the map is drawn from");
      for (let i = 0; i < acts.length; i++) {
        await saveDrawing(session,
            "/admin/delegation/chain?chain=" +
            encodeURIComponent(acts[i].chainKey) + "&format=svg",
            // Named for the two APPLICATIONS rather than for the address: an
            // address is a URI and a URI has slashes in it, which is a path
            // this file cannot be written to.
            "wstrust-delegation-chain-" + HOPS[i].as + "-to-" +
                HOPS[i].target + suffix + ".svg",
            "the chain " + HOPS[i].as + " -> " + HOPS[i].target +
                " (asked for as " + HOPS[i].appliesTo + ")");
      }
      await saveDrawing(session,
          "/admin/delegation/application?application=" +
          encodeURIComponent(ESB) + "&format=svg",
          "wstrust-delegation-application-" + ESB + suffix + ".svg",
          "everything " + ESB + " is part of — the tier in the middle");
      // AND THE LINEAGE, which is the picture the delegation map cannot draw:
      // every generation behind the final assertion, back through both
      // exchanges to the browser sign-in that started it.
      await saveDrawing(session,
          "/admin/tokens/credential?id=" + encodeURIComponent(second.id) +
          "&format=svg",
          "wstrust-credential-lineage-" + PROVIDER + suffix + ".svg",
          "where the final assertion came from — every generation behind it");
    }

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
      const blogs = await driver.manage().logs().get("browser");
      if (blogs && blogs.length) {
        log.error("Browser console:\n" +
                  blogs.map(function (e) {
                    return e.level.name + ": " + e.message;
                  }).join("\n"));
      }
    } catch (e2) {
      // Best effort: the browser may already be gone, and the failure above is
      // the one worth reporting.
      log.debug("The post-mortem could not be collected: " + e2.message);
    }
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
  .name("wstrust_delegation_chain")
  .description("Run test.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
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
