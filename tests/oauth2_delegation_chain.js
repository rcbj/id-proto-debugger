// File: oauth2_delegation_chain.js
//
// ---------------------------------------------------------------------------
// A THREE-TIER DELEGATION CHAIN: one sign-in, then two RFC 8693 hops, each made
// as a DIFFERENT client from a debugger workflow of its own.
//
// This is the enterprise shape nothing else in this suite draws end to end.
// `oauth2_token_exchange.js` performs ONE exchange, in the same workflow that
// obtained the subject token, and confirms the result by introspection — which
// is the right test of the pane. What it cannot show is the thing an exchange
// exists for: the token that comes OUT of one hop is the token that goes INTO
// the next, made by a different party, and after two hops the far end is
// holding a credential for a person who never spoke to it. That is one act per
// hop in the mock's delegation register, and TWO acts that share a party is the
// first arrangement in this repository that has a middle.
//
// The scenario, in the words of the deployment it is copied from:
//
//   bob_end_user signs in to webapp1 through the OIDC Authorization Code flow,
//   asking for `openid email profile offline_access apigw1`. The last scope
//   names the API gateway the resulting access token will be presented to —
//   and this issuer READS that name as the audience, so it is what the token
//   comes back ADDRESSED to rather than a scope the token carries.
//
//   apigw1 receives that token on an API call. NOTHING HERE SIMULATES THAT CALL
//   — there is no resource server in this suite and inventing one would be
//   testing a fixture. The gateway does what a gateway does next: it exchanges
//   the token it was given for one addressed to the service it is about to
//   forward to, `esb1`, and the scope it asks for names that service.
//
//   esb1 does it again, for `sp1`. Nothing is forwarded there either. The
//   point is the SHAPE of the third token: it names bob_end_user, it carries
//   `sp1`, and neither webapp1 nor apigw1 is anywhere in it.
//
// ---------------------------------------------------------------------------
// FIVE DECISIONS THIS FILE MAKES, EACH OF WHICH CHANGES WHAT IT PROVES.
//
// **EACH HOP IS A NEW WORKFLOW, and the localStorage is CLEARED between them.**
// That is what the request asked for and it is also the only honest way to
// drive it: the debugger keeps the whole workflow in browser storage, so an
// exchange run straight after a sign-in inherits that sign-in's client_id, its
// token endpoint and its access token, and a pane that filled in nothing at all
// would still send a well-formed request. Clearing means each hop must re-run
// discovery and be told who it is, which is what apigw1 and esb1 really are:
// separate applications that were handed a token and know nothing else. It also
// means the SUBJECT TOKEN is pasted rather than inherited — the field defaults
// to "the most recent access token", and after a clear there is no such thing.
//
// **THE REQUEST PREVIEW IS ASSERTED BEFORE THE BUTTON IS PRESSED.** The pane
// draws exactly what it is about to POST, and every one of the four things that
// distinguishes one hop from the other — the client, the scope, the audience,
// the subject token — is a field that could be stale from the hop before. A
// test that only reads the response cannot tell a correct exchange from one
// that re-ran the previous exchange and got a plausible token back. This is the
// lesson `tests/oidc_flows.js` records about response_type, applied to the one
// other pane in this workflow with four fields that all look alike.
//
// **THE FOUR APPLICATIONS ARE PROVISIONED FIRST, THROUGH THE MANAGEMENT API,
// AND EACH DOWNSTREAM ONE REGISTERS AN AUDIENCE.** This service accepts a
// client_id it has never heard of — that is the whole reason the first version
// of this test needed no provisioning — so an entry appears only when something
// is ACCEPTED, and it appears knowing nothing but the identifier. Here the four
// are created before the browser starts, each declared for `oauth2` and `oidc`
// and each named for the tier it is, and the three that a token can be
// ADDRESSED to register the URI it is addressed BY on `oauthAudience`:
// apigw1 → https://apigw1.example.com, esb1 → https://esb1.example.com,
// sp1 → https://sp1.example.com. webapp1 registers none, and that absence is
// the point rather than an omission: a browser application is what a token is
// issued TO, never what one is addressed to, so an audience on it would be a
// resource nobody can reach.
//
// **`audience` IS SENT AS WELL AS `scope`, AND IT IS THE REGISTERED URI RATHER
// THAN THE CLIENT_ID.** The scenario names the downstream application in the
// SCOPE (`…offline_access esb1`), and RFC 8693 section 2.1 has a parameter that
// means exactly "the service this token is for": `audience`. Both are sent —
// the scope because that is what the deployment being copied puts there, the
// audience because it is what an authorization server would enforce against and
// what lands in `aud` — and what goes in the audience is the RESOURCE URI,
// because that is what an audience is: the service, not the client that calls
// it. The `aud` of each issued token is asserted against it.
//
// **AND A SCOPE THAT NAMES AN APPLICATION IS READ AS AN AUDIENCE, WHICH IS WHY
// NO TOKEN HERE CARRIES THE NEXT TIER IN ITS SCOPE.** The mock gained that
// reading on 2026-08-26 alongside the registry attribute above: a scope value
// that is the `oauthClientId` of another application in the registry becomes
// the audience and comes OFF the scope list, because the one fact in
// `scope=openid email profile offline_access apigw1` that says which party the
// token is for belongs in the claim that means exactly that. So webapp1's
// token is addressed to `apigw1` — the scope value VERBATIM, beside this
// service's own `/resource`, which the `openid` scope keeps so that UserInfo
// is still reachable — and its scope claim is the base four and nothing else.
// The two exchanges send `audience` as well, and that parameter WINS the `aud`
// (an audience a client asked for is never widened by one this service
// derived), but the scope list is trimmed just the same: `esb1` and `sp1` are
// audiences, not permissions.
//
// So every assertion below reads THE NEXT TIER OUT OF `aud`, and asserts it is
// NOT in the scope. Reading it out of the scope is what this file did until
// that change, and the failure that produced named the scope claim rather than
// the reading that had moved underneath it.
//
// **AND THAT IS WHY THE REGISTRY MATTERS RATHER THAN BEING DECORATION.** The
// register is keyed by the identifier an application PRESENTS — a client_id —
// so an act recorded for `https://esb1.example.com` would draw a box in the map
// that nothing else in the picture mentions, and this two-hop chain would come
// out as two unconnected halves: the URL hop 1 reached and the client_id hop 2
// exchanged AS are one application under two names. The mock now looks the
// audience up on `oauthAudience` (`applications.forAudience()`, added
// 2026-08-26 with the attribute) and files the act against the application that
// registered it, keeping the requested URI in the sentence beside it. So the
// picture stays one chain, and the attribute is READ rather than merely
// declared — which is what the assertions below check: the act's target is
// `esb1`, the token's `aud` is the URI, and the row says which audience
// resolved. Nothing is REFUSED by any of this: an audience nobody registered is
// still exchanged for, and recorded verbatim.
//
// **IMPERSONATION, NOT DELEGATION, and the difference is visible in the
// register.** No actor token is sent, so what comes back names bob_end_user and
// says nothing about apigw1 or esb1 — RFC 8693 section 1.1's impersonation, and
// the mock files it as `oauth-impersonation` in `mode: impersonation`. That is
// the mode the scenario describes and it is also the interesting one to draw:
// the middle tiers are invisible in every token they produce, so the issuer's
// own register is the ONLY place the chain exists at all. Sending an actor
// token instead (the pane's Delegation radio, an `act` claim, `mode:
// delegation`) would be a different test and a different picture; it is not
// this one, and the assertions below name the mode so that a switch flipped by
// accident fails here rather than quietly changing what the map shows.
//
// **THE MOCK STS, AND ITS PERMISSIVE (default) REALM.** Three clients that need
// no registration, a user with no password, and a token endpoint that will
// exchange anything for anything: the mock says so itself in every row it
// records (`authorizedBy: 'nothing. RFC 8693 leaves the policy to the
// authorization server and this one has none'`). Keycloak would need three
// clients, a user and a token-exchange permission per pair provisioned before
// any of this ran. The RFC 9700 realm would be a different test again — a
// compliant server has opinions about a public client, about PKCE and about a
// scope that grows — and pointing this file at one is deliberately not
// supported: it is gated on WSTRUST_STS_URL, the permissive instance.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS, IN FOUR LAYERS, BECAUSE ANY ONE OF THEM PASSES ALONE.
//
//   1. THE REGISTRY. Each of the four applications is read back after it is
//      created: declared for both protocol families, and holding the audience
//      it registered — or holding NONE, for webapp1, which is the assertion
//      that keeps "issued tokens" and "addressed by tokens" apart. Read through
//      `GET /admin-api/applications` rather than off the create's own reply,
//      because the question is what the registry holds and not what the write
//      said it wrote.
//   2. THE WIRE. Each hop returns HTTP 200 with an access token that decodes,
//      names bob_end_user, carries the scopes that are scopes, and is
//      ADDRESSED to the next tier — the client_id for the sign-in, whose only
//      statement of it was a scope, and the requested URI for each exchange,
//      which sent `audience` outright. Each token is also checked for the tier
//      it has already left, in the audience and in the scope alike. The final
//      token is printed in full, with its claims, which is the artifact the
//      scenario is about.
//   3. THE SERVER'S OWN READING. The final token is introspected (RFC 7662) at
//      the mock, so the audience and the scope are confirmed by the issuer
//      rather than by this test decoding a string it was handed.
//   4. THE REGISTER AND THE PICTURE. `GET /admin-api/delegation` is read for
//      the acts recorded SINCE this job started, and each hop must be there
//      with its parties, its mode and the jti of the token this test actually
//      received. Its target must be the APPLICATION and its explanation must
//      name the AUDIENCE that was asked for — the two together are what say the
//      registry lookup happened rather than the exchange having named a
//      client_id. Then the graph the map is drawn from is checked for the one
//      property that makes this a chain rather than two unrelated exchanges:
//      **esb1 is one box that played the TARGET of the first hop and the
//      INTERMEDIARY of the second.** Two boxes there would mean two pictures.
//
// Deltas, not totals. The mock's stores survive between jobs and the suite runs
// in a pool, so the newest sequence number is read before the browser starts
// and every assertion below is about acts after it. See `tests/CLAUDE.md`.
//
// THE FOUR ENTRIES ARE LEFT BEHIND, and that is deliberate rather than a
// missing teardown. They are what the delegation map is a picture OF — a box
// labelled `esb1 (enterprise service bus)` that links to a registry entry is
// the drawing this job exists to produce — and deleting them after the SVGs
// were taken would leave the register pointing at applications the console can
// no longer show. Nothing else in the suite reads them: no other job uses these
// four identifiers, and the one job that counts what this service holds
// (`admin_api.js`) is EXCLUSIVE, so it cannot be running while these are
// created. That is why this script is not in JOB_LOCKS despite writing to a
// shared store — and it is the sentence to revisit if a second job ever starts
// asserting on the registry as a whole.
//
// ---------------------------------------------------------------------------
// AND IT SAVES THE DRAWINGS, WHICH IS WHY THE JOB EXISTS AT ALL.
//
// `/admin/delegation/map` lays out that graph on the server and answers
// `?format=svg` with the document alone. The register is IN MEMORY and dies
// with the process, so the picture of this chain can only be taken while the
// run is happening — by the time anybody reads the report the mock has been
// torn down. So the SVGs are fetched and written to DELEGATION_ARTIFACT_DIR
// (the run's own report directory, when run-report.js spawns this): the whole
// map, this user's acts alone, and one document per chain. The console is gated
// (`admin.authRequired`), so this signs in the way a browser does — three steps
// through /authn/login, exactly as `tests/admin_api.js` does it, and for the
// same reason: `?format=svg` is refused rather than redirected to a sign-in
// screen a program cannot read. If the roster has been narrowed by some other
// job the drawings are SKIPPED with a message naming the gate; the assertions
// above do not depend on them, because they read `/admin-api/delegation`, which
// is not behind it.
// ---------------------------------------------------------------------------
const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require("selenium-webdriver/lib/select");
const chrome = require("selenium-webdriver/chrome");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const waitFor = require("./wait_for.js");
const common = require("./jwt_vc_json_common.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "oauth2_delegation_chain",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata } = require("../common/tests.js")({ By, until, Select,
       waitTime, log, jwt, assert });

// ---------------------------------------------------------------------------
// THE CAST. Every one of them is overridable, and every one of them defaults to
// the name the scenario uses — a delegation picture is read by its labels, so
// the boxes are called what the deployment calls them.
//
// Deliberately NOT process.env.USER for the person: every shell sets that, so a
// standalone run would sign in as whoever started it and the whole register
// would be about them. The mock accepts any username and checks no password.
// ---------------------------------------------------------------------------
const USER = process.env.DELEGATION_USER || "bob_end_user";
const WEBAPP = process.env.DELEGATION_WEBAPP_CLIENT_ID || "webapp1";
const GATEWAY = process.env.DELEGATION_GATEWAY_CLIENT_ID || "apigw1";
const ESB = process.env.DELEGATION_ESB_CLIENT_ID || "esb1";
const PROVIDER = process.env.DELEGATION_SP_CLIENT_ID || "sp1";

// The scopes every tier asks for, plus the one naming the tier after it. The
// base set is the scenario's and is carried unchanged through all three hops:
// `offline_access` is in it because the first hop is the only one that can get
// a refresh token, and an exchange that dropped it would be narrowing the grant
// for a reason nobody chose.
const BASE_SCOPE = "openid email profile offline_access";
const scopeFor = function (nextTier) {
  return BASE_SCOPE + " " + nextTier;
};

// ---------------------------------------------------------------------------
// THE FOUR APPLICATION OBJECTS, as they are created in the registry before any
// of this runs, and the audience each downstream one answers to.
//
// `name` is what the delegation map LABELS the box with (the registry's
// `appName`, which delegationNodeLook() prefers over the identifier), so each
// one carries the identifier AND what that tier is — a picture whose boxes read
// `apigw1 (API gateway)` says the scenario, and one whose boxes read `apigw1`
// makes the reader remember it.
//
// `audience` is EMPTY for webapp1 on purpose and the entry below says why: it
// is a browser application, so it is what a token is issued TO and never what
// one is addressed to. An audience on it would name a resource nobody can
// reach.
//
// Every value is overridable, so a run against a differently-provisioned
// service can be pointed at its own names without editing this file.
// ---------------------------------------------------------------------------
const APPLICATIONS = [
  { identifier: WEBAPP, name: WEBAPP + " (web application)", audience: "",
    why: "the browser application the End-User signs in to. It is issued " +
         "tokens and is never the audience of one, so it registers none." },
  { identifier: GATEWAY, name: GATEWAY + " (API gateway)",
    audience: process.env.DELEGATION_GATEWAY_AUDIENCE ||
        "https://apigw1.example.com",
    why: "the API gateway the browser application's token is presented to." },
  { identifier: ESB, name: ESB + " (enterprise service bus)",
    audience: process.env.DELEGATION_ESB_AUDIENCE ||
        "https://esb1.example.com",
    why: "the service bus the gateway forwards to." },
  { identifier: PROVIDER, name: PROVIDER + " (service provider)",
    audience: process.env.DELEGATION_SP_AUDIENCE ||
        "https://sp1.example.com",
    why: "the service at the far end, which never hears from the End-User." }
];

// The protocol families each of the four is DECLARED for. Both, for every one
// of them: an OpenID Connect relying party IS an OAuth 2.0 client — the
// registry says so itself where oauthClientId serves three families — and the
// workflow this test drives uses both halves, an OIDC sign-in and then OAuth
// 2.0 token exchanges with no browser anywhere near them.
const DECLARED_PROTOCOLS = ["oauth2", "oidc"];

// The audience of one tier, by identifier. Used to build the hops, so the URI
// the exchange asks for and the URI the entry registers cannot drift apart.
function audienceOf(identifier) {
  log.debug("Entering audienceOf(). identifier=" + identifier);
  const found = APPLICATIONS.filter(function (one) {
    return one.identifier === identifier;
  });
  log.debug("Leaving audienceOf().");
  return found.length ? found[0].audience : "";
}

// The name this file signs into the console AS, for the drawings alone. A name
// and not a credential — the mock checks no password anywhere — and distinctive
// so that the directory entry and the audit row it leaves say which job made
// them.
const CONSOLE_USER = "delegation-chain-test";

// ---------------------------------------------------------------------------
// Where the mock is, and where the pictures go.
// ---------------------------------------------------------------------------
function stsBase() {
  log.debug("Entering stsBase().");
  const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
  log.debug("Leaving stsBase().");
  return stsUrl.replace(/\/sts\/?$/, "");
}

function artifactDir() {
  log.debug("Entering artifactDir().");
  const dir = process.env.DELEGATION_ARTIFACT_DIR ||
      path.join(__dirname, "report", "delegation");
  log.debug("Leaving artifactDir(). " + dir);
  return dir;
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

// ---------------------------------------------------------------------------
// THE APPLICATIONS REGISTRY, through the management API — the same door the
// console's own forms go through, which is what makes this provisioning and not
// a fixture.
//
// THIS IS A HAND-WRITTEN COPY AND IT IS STAYING THAT WAY. Since 2026-08-27 the
// shared implementation is `tests/sts_applications.js`, and every other job in
// the suite that presents an identifier to the mock calls it — this file and
// `wstrust_delegation_chain.js` are two of the three it was written FROM. What
// it does not do is what keeps this one here: `provision()` asserts CONTAINMENT
// (everything this job needs is on the entry), and the assertion below that
// matters most is an ABSENCE — webapp1 must be the audience of NOTHING, and an
// entry that acquired one would still pass a containment check. Change this and
// change that module only if the two can be made to agree without losing it.
//
// `POST /admin-api/applications/create` takes the whole entry in one call:
// the identifier, a name, the declared protocol families and the attribute
// values. It REFUSES an identifier that is already there, which is right — an
// identifier names one application whatever protocol brought it — and is a
// state this test meets in two ordinary ways: a second run against a mock that
// has not restarted, and a run against a service where some earlier job has
// already presented one of these client_ids, since a sighting creates the entry
// too. So a refusal for that reason is RECONCILED rather than treated as a
// failure: every value this test needs is added to the entry that is there,
// through `add`, which reports "nothing changed" for a value already present
// and is therefore safe to repeat.
//
// What is NOT tolerated is a refusal for any other reason. A create that failed
// because `oauthAudience` is not in the schema — the shape this would take
// against a mock STS from before 2026-08-26 — must fail the job HERE, naming
// the attribute and the submodule, rather than three screens later as a
// delegation act whose target is a URL.
// ---------------------------------------------------------------------------
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

// One application, created or reconciled, and then READ BACK — because the
// reply to a create is this service describing what it just wrote, and the
// question worth asking is what the registry holds.
async function provisionApplication(app) {
  log.debug("Entering provisionApplication(). " + app.identifier);
  const fields = { oauthClientId: app.identifier };
  if (app.audience) {
    fields.oauthAudience = [app.audience];
  }
  const created = await applicationsApi("create", {
    identifier: app.identifier,
    name: app.name,
    protocols: DECLARED_PROTOCOLS,
    fields: fields,
  });
  if (created.ok && created.body && created.body.ok) {
    log.info("[registry] created " + app.identifier + " — " + app.why +
             (app.audience ? " Audience: " + app.audience + "." : ""));
  } else {
    const errors = (created.body && created.body.errors) ||
        [String(created.raw)];
    const alreadyThere = errors.some(function (one) {
      return /already in this registry/i.test(String(one));
    });
    assert.ok(alreadyThere,
      "POST /admin-api/applications/create refused " + app.identifier +
      " for a reason that is not \"it is already here\": " +
      JSON.stringify(errors) + ". If it names `oauthAudience`, this mock STS " +
      "predates that attribute (added 2026-08-26) — bump the sts/ submodule.");
    log.info("[registry] " + app.identifier + " is already in the registry, " +
             "so this run reconciles it rather than creating it.");
    for (let i = 0; i < DECLARED_PROTOCOLS.length; i++) {
      const added = await applicationsApi("add", {
        application: app.identifier,
        attribute: "appAllowedProtocol",
        value: DECLARED_PROTOCOLS[i],
      });
      assert.ok(added.ok && added.body && added.body.ok,
        "declaring " + DECLARED_PROTOCOLS[i] + " on the existing " +
        app.identifier + " was refused: " + String(added.raw).slice(0, 200));
    }
    if (app.audience) {
      const added = await applicationsApi("add", {
        application: app.identifier,
        attribute: "oauthAudience",
        value: app.audience,
      });
      assert.ok(added.ok && added.body && added.body.ok,
        "registering the audience " + app.audience + " on the existing " +
        app.identifier + " was refused: " + String(added.raw).slice(0, 200) +
        ". A refusal naming `oauthAudience` as unknown or not editable means " +
        "this mock STS predates that attribute — bump the sts/ submodule.");
    }
  }

  // Read back through the LIST rather than trusting the write's own reply.
  const entry = await applicationEntry(app.identifier);
  assert.ok(entry, "the registry has no application called " + app.identifier +
            " after this test created it.");
  DECLARED_PROTOCOLS.forEach(function (protocol) {
    assert.ok((entry.allowedProtocols || []).indexOf(protocol) >= 0,
      app.identifier + " should be declared for " + protocol +
      " and its entry declares " + JSON.stringify(entry.allowedProtocols) +
      ". Declaring a family grants nothing in this service — it is a record " +
      "of intent — so this is asserted here or nowhere.");
  });
  const registered = valuesOf(entry.fields && entry.fields.oauthAudience);
  if (app.audience) {
    assert.ok(registered.indexOf(app.audience) >= 0,
      app.identifier + " should register the audience " + app.audience +
      " on oauthAudience and its entry holds " + JSON.stringify(registered) +
      ". Without it the exchange aimed at that URI is recorded against the " +
      "URI rather than against this application, and the map draws a box for " +
      "a URL instead of a chain.");
  } else {
    assert.strictEqual(registered.length, 0,
      app.identifier + " is a browser application and should be the audience " +
      "of nothing, and its entry registers " + JSON.stringify(registered) +
      ".");
  }
  log.info("[registry] " + app.identifier + ": declared for " +
           (entry.allowedProtocols || []).join(", ") + ", audience " +
           (registered.length ? registered.join(", ") : "(none, by design)"));
  log.debug("Leaving provisionApplication().");
  return entry;
}

// The registry's own view of one application. Read through the list with the
// identifier as the query rather than by constructing a drill-down URL, so this
// asks the management API the question its own console page asks.
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
// A `multi` attribute is a list and a `single` one is a string, and this test
// reads one of each.
function valuesOf(value) {
  log.debug("Entering valuesOf().");
  if (value === undefined || value === null || value === "") {
    log.debug("Leaving valuesOf(). Nothing.");
    return [];
  }
  log.debug("Leaving valuesOf().");
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

async function provisionApplications() {
  log.debug("Entering provisionApplications().");
  log.info("=== Provisioning the four applications in the registry ===");
  const entries = [];
  for (let i = 0; i < APPLICATIONS.length; i++) {
    entries.push(await provisionApplication(APPLICATIONS[i]));
  }
  log.debug("Leaving provisionApplications(). " + entries.length + ".");
  return entries;
}

// ---------------------------------------------------------------------------
// A browser sign-on session for the CONSOLE, which only the drawings need. The
// three-step dance is the one a browser does and is copied from
// tests/admin_api.js, which explains it at length.
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
// turned it down — the caller reports that and moves on, exactly as the
// drawings do.
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
// THE CREDENTIAL'S ANCESTRY, at /admin/tokens/credential.
//
// The one thing in this whole scenario that no single register can answer, and
// the reason it is asserted HERE rather than in a test of its own: it needs a
// credential with two generations of exchange behind it, and this job is the
// only place in the suite that produces one.
//
// It walks the delegation register by IDENTIFIER — the jti of the token that
// came out of an exchange is the jti of the token handed into the next — so the
// three jtis this test actually received off the wire are the assertion. A
// lineage that agreed about the SHAPE (three generations, two exchanges) and
// named different tokens would be a page describing somebody else's chain.
// ---------------------------------------------------------------------------
async function assertTheLineage(session, expected) {
  log.debug("Entering assertTheLineage().");
  log.info("=== The credential's ancestry, at /admin/tokens/credential ===");
  const lineage = await consoleJson(session,
      "/admin/tokens/credential?id=" + encodeURIComponent(expected.jtis[0]) +
      "&format=json",
      "the final token's lineage");
  if (!lineage) {
    log.debug("Leaving assertTheLineage(). The console refused.");
    return null;
  }
  assert.strictEqual(lineage.identifier, expected.jtis[0],
    "the lineage page answered about \"" + lineage.identifier +
    "\" rather than about the token this test asked for.");
  assert.strictEqual(lineage.held, true,
    "the issued register does not hold the token this test was just handed. " +
    "It is capped, but not so small that a token minted seconds ago has been " +
    "dropped — this is the register not recording an exchanged token at all.");
  assert.strictEqual(lineage.counts.generations, expected.jtis.length,
    "the final token should have " + expected.jtis.length + " generations " +
    "behind it — itself, the gateway's token and the sign-in's — and the " +
    "page reports " + lineage.counts.generations + ".");
  assert.strictEqual(lineage.counts.exchanges, expected.jtis.length - 1,
    "there were " + (expected.jtis.length - 1) + " exchanges and the lineage " +
    "reports " + lineage.counts.exchanges + ".");

  // THE IDENTIFIERS, IN ORDER. Generation 0 is the token asked about and the
  // last is the origin, so this is the chain read backwards — and it is
  // compared against what the BROWSER received rather than against the page's
  // own account of itself.
  const walked = lineage.generations.map(function (row) {
    return row.identifier;
  });
  assert.deepStrictEqual(walked, expected.jtis,
    "the lineage walks " + JSON.stringify(walked) + " and the tokens this " +
    "test actually received, newest first, are " +
    JSON.stringify(expected.jtis) + ".");

  // THE ORIGIN. The last generation must be an issuance rather than an
  // exchange, must be the token webapp1 obtained, and must name the grant that
  // produced it — which is the fact the whole page exists to reach.
  const origin = lineage.generations[lineage.generations.length - 1];
  assert.strictEqual(origin.producedByExchange, false,
    "the oldest generation was itself produced by an exchange, so it is not " +
    "the origin and the walk stopped early.");
  assert.ok(origin.credential,
    "the origin generation names an identifier the issued register does not " +
    "hold, so the page cannot say what started the line.");
  assert.strictEqual(origin.credential.client_id, expected.originClient,
    "the line starts at a token held by \"" + origin.credential.client_id +
    "\" rather than by " + expected.originClient + ".");
  assert.strictEqual(origin.credential.grant, "authorization_code",
    "the origin should be the Authorization Code grant this test signed in " +
    "with, and the register says \"" + origin.credential.grant + "\".");
  const oldest = expected.jtis[expected.jtis.length - 1];
  assert.deepStrictEqual(lineage.origins, [oldest],
    "the page reports its origins as " + JSON.stringify(lineage.origins) + ".");
  assert.strictEqual(lineage.truncated, false,
    "the walk reported itself truncated, so what it drew is not the whole " +
    "line.");
  assert.strictEqual((lineage.walls || []).length, 0,
    "a generation stopped at a credential this register cannot name: " +
    JSON.stringify(lineage.walls) + ". Every hop here consumed a token this " +
    "service issued, so each one has a jti to follow.");

  // AND THE PICTURE HAS THE PARTY THE DELEGATION MAP CANNOT HAVE. webapp1
  // appears in no delegation act — it exchanged nothing — so its box exists on
  // this page and on no other, which is the whole of what "back to the original
  // issuance" buys.
  const boxes = (lineage.graph.nodes || []).map(function (node) {
    return node.id;
  });
  expected.parties.forEach(function (party) {
    assert.ok(boxes.indexOf(party) >= 0,
      "the lineage picture has no box for " + party + ". It draws: " +
      JSON.stringify(boxes) + ".");
  });
  const relations = (lineage.graph.edges || []).map(function (edge) {
    return edge.from + " -" + edge.relation + "-> " + edge.to;
  });
  const issuance = USER + " -issued-for-> " + expected.originClient;
  assert.ok(relations.indexOf(issuance) >= 0,
    "the origin should be drawn as an ISSUANCE from " + USER + " to " +
    expected.originClient + " — an ordinary grant and not a delegation, " +
    "which is what keeps it the console's neutral colour. The lines are: " +
    JSON.stringify(relations) + ".");
  log.info("[lineage] " + lineage.counts.generations + " generations, " +
           lineage.counts.exchanges + " exchanges, " +
           lineage.counts.parties + " parties; the line starts at " +
           expected.originClient + "'s " + origin.credential.grant + " token.");
  log.debug("Leaving assertTheLineage().");
  return lineage;
}

// THE LINK ITSELF, which is what makes the page reachable. Asserted against the
// tokens page's own MARKUP rather than against its JSON: the requirement is
// that the identifier in that table is a link, and JSON has no links in it.
async function assertTheTokensPageLinksIt(session, jti) {
  log.debug("Entering assertTheTokensPageLinksIt().");
  const url = stsBase() + "/admin/tokens?per=100";
  const r = await common.httpJson(url,
      session ? { headers: { Cookie: session } } : undefined);
  if (r.status === 401 || r.status === 403) {
    log.warn("[console] the tokens page was refused with " + r.status +
             ", so the link on it was not checked.");
    log.debug("Leaving assertTheTokensPageLinksIt(). Refused.");
    return;
  }
  assert.strictEqual(r.status, 200,
    "GET " + url + " should answer 200 and answered " + r.status + ".");
  const html = String(r.raw);
  assert.ok(html.indexOf("/admin/tokens/credential") >= 0,
    "no identifier on the tokens page links to a credential's lineage.");
  assert.ok(html.indexOf("id=" + jti) >= 0,
    "the tokens page does not link the token this test just obtained (" + jti +
    ") to its lineage. Its identifier column is where that link lives.");
  log.info("[console] the tokens page links " + jti + " to its lineage.");
  log.debug("Leaving assertTheTokensPageLinksIt().");
}

// ---------------------------------------------------------------------------
// THE TWO CHOOSERS ON /admin/delegation ARE A SEARCH, AND THIS IS THE ONE PLACE
// IN THE SUITE THAT CAN SAY SO.
//
// They were a `<select>` holding every application and every person until
// 2026-08-26. That control cannot be typed into and cannot be narrowed, and on
// a register that has been running for a week it is a list nobody can find
// anything in — so it is a text box now, a scrolling pane of at most twenty
// matches, and a link per match that IS the selection.
//
// This job is where it is checked because this job is the one that PUTS FOUR
// KNOWN NAMES IN THAT REGISTER. Every other console assertion in the suite is
// about a page whose content is whatever the run happened to produce; here
// `apigw1`, `esb1` and `sp1` are in the acts by construction and
// `bob_end_user` is the person behind all of them, so a search for one of them
// has an answer this file can state rather than infer.
//
// FOUR THINGS, and the last is the one that would catch the control being
// quietly put back:
//
//   * the search NARROWS — a term matching one tier finds it and does not find
//     the others, which is the whole feature and is the assertion that fails if
//     the box is drawn and ignored;
//   * a term nothing matches draws NO results rather than the whole list, which
//     is the other way a search that is really a decoration behaves;
//   * the pane holds AT MOST TWENTY, which is the cap the page's own line
//     promises;
//   * and there is no `<select>` for either party any more. That is the
//     regression guard: a select and a search box look alike in a diff three
//     months from now, and a page that grew the select back would pass every
//     other assertion here.
//
// It is SKIPPED, with the reason named, when the console refuses — the same
// arrangement the drawings have, and for the same reason: the gate's roster can
// be narrowed by another job in the pool, and nothing above this depends on the
// console at all.
// ---------------------------------------------------------------------------

// The result links one pane drew, in order. Read out of the PANE's own markup
// rather than off the whole page, because the page carries the same hrefs in
// its tables: a count taken over the document would be the acts table's links
// plus the chooser's, which is a number that cannot fail.
function chooserHits(html, route) {
  log.debug("Entering chooserHits(). route=" + route);
  const out = [];
  const panes = String(html).split('<div class="chooser">');
  for (let i = 1; i < panes.length; i++) {
    const pane = panes[i].split("</div>")[0];
    if (pane.indexOf('href="' + route + "?") < 0) {
      continue;
    }
    pane.split("<li").slice(1).forEach(function (row) {
      const text = (row.split("</a>")[0] || "").split(">").pop();
      if (text) {
        out.push(text);
      }
    });
  }
  log.debug("Leaving chooserHits(). " + out.length + " hit(s).");
  return out;
}

async function delegationPage(session, query) {
  log.debug("Entering delegationPage(). query=" + query);
  const url = stsBase() + "/admin/delegation" + query;
  const r = await common.httpJson(url,
      session ? { headers: { Cookie: session } } : undefined);
  log.debug("Leaving delegationPage(). status=" + r.status);
  return r;
}

async function assertTheChoosersSearch(session) {
  log.debug("Entering assertTheChoosersSearch().");
  const first = await delegationPage(session,
      "?appq=" + encodeURIComponent(GATEWAY));
  if (first.status === 401 || first.status === 403) {
    log.warn("[console] /admin/delegation was refused with " + first.status +
             ", so the choosers were not checked. The gate's roster has been " +
             "narrowed by something else in the pool.");
    log.debug("Leaving assertTheChoosersSearch(). Refused.");
    return;
  }
  assert.strictEqual(first.status, 200,
    "GET /admin/delegation?appq=" + GATEWAY + " should answer 200 and " +
    "answered " + first.status + ".");
  const searched = String(first.raw);

  // THE SELECT IS GONE, both of them, and this is first because everything
  // below would also pass on a page that drew a search box beside the old one.
  assert.ok(searched.indexOf('<select id="application"') < 0,
    "/admin/delegation still draws a <select id=\"application\">. The " +
    "chooser is a search now — a box, a scrolling pane of at most 20 matches " +
    "and a link per match — and a select holding every application is the " +
    "control it replaced.");
  assert.ok(searched.indexOf('<select id="user"') < 0,
    "/admin/delegation still draws a <select id=\"user\">, which is the " +
    "person chooser before it became a search.");
  assert.ok(searched.indexOf('name="appq"') >= 0 &&
            searched.indexOf('name="userq"') >= 0,
    "/admin/delegation draws neither search box (appq, userq), so neither " +
    "pivot can be reached at all.");

  const hits = chooserHits(searched, "/admin/delegation/application");
  assert.ok(hits.indexOf(GATEWAY) >= 0,
    "searching the application chooser for \"" + GATEWAY + "\" does not " +
    "find it. The pane drew: " + JSON.stringify(hits) + ".");
  assert.ok(hits.indexOf(ESB) < 0 && hits.indexOf(PROVIDER) < 0,
    "searching for \"" + GATEWAY + "\" also drew " + ESB + " or " +
    PROVIDER + ", so the box is being drawn and ignored. The pane drew: " +
    JSON.stringify(hits) + ".");
  assert.ok(hits.length <= 20,
    "the application pane drew " + hits.length + " results, and the page's " +
    "own line under it promises at most 20.");
  log.info("[console] the application search for \"" + GATEWAY + "\" drew " +
           hits.length + " result(s), " + GATEWAY + " among them and neither " +
           ESB + " nor " + PROVIDER + ".");

  // A term nothing can match. The name is deliberately one no run creates: an
  // empty pane IS the assertion, so a term that matched something would make
  // this pass by accident.
  const none = await delegationPage(session,
      "?appq=" + encodeURIComponent("zzz-no-such-application-zzz"));
  assert.strictEqual(none.status, 200,
    "GET /admin/delegation with a search matching nothing should still " +
    "answer 200 and answered " + none.status + ".");
  const empty = chooserHits(String(none.raw), "/admin/delegation/application");
  assert.strictEqual(empty.length, 0,
    "a search for a name nothing can match drew " + empty.length +
    " result(s): " + JSON.stringify(empty) + ". A search that answers with " +
    "the whole list is a decoration.");

  // And the person chooser, which is the same control over a different
  // catalogue and a different link.
  const person = await delegationPage(session,
      "?userq=" + encodeURIComponent(USER));
  assert.strictEqual(person.status, 200,
    "GET /admin/delegation?userq=" + USER + " answered " + person.status +
    ".");
  const people = chooserHits(String(person.raw), "/admin/delegation/user");
  assert.ok(people.some(function (one) { return one.indexOf(USER) >= 0; }),
    "searching the person chooser for \"" + USER + "\" does not find them, " +
    "and this job signed them in. The pane drew: " + JSON.stringify(people) +
    ".");
  assert.ok(people.length <= 20,
    "the person pane drew " + people.length + " results against a cap of 20.");
  log.info("[console] the person search for \"" + USER + "\" drew " +
           people.length + " result(s).");
  log.debug("Leaving assertTheChoosersSearch().");
}

// ---------------------------------------------------------------------------
// A NEW WORKFLOW. The storage is cleared on the debugger's own origin, then
// discovery is run again — which is the whole of what a fresh application knows
// when it is handed a token: where the authorization server is, and nothing
// about whoever was here before.
// ---------------------------------------------------------------------------
async function startNewWorkflow(driver, discoveryEndpoint, who, previous) {
  log.debug("Entering startNewWorkflow(). who=" + who);
  log.info("=== Starting a new debugger workflow as " + who + " ===");
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await waitFor.waitForPageBundle(driver,
      "oauth2_oidc_1.html's bundle (before clearing the workflow)");
  // Cleared from the page rather than by deleting cookies: this is
  // localStorage, it is per-origin, and the debugger keeps every field of the
  // workflow in it.
  await driver.executeScript("window.localStorage.clear();");
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await waitFor.waitForPageBundle(driver, "oauth2_oidc_1.html's bundle");

  // THE CLEAR IS ASSERTED, and it is asserted through the page's own re-seed
  // rather than through an empty store: a page loaded with no `initialized`
  // flag writes its unconfigured defaults back, so "empty" is a state that
  // never survives to be observed. What CAN be observed is that those defaults
  // are what is there — a client_id that is the markup's placeholder and not
  // the previous hop's, and a token endpoint that points at nothing. The
  // second half is what populateMetadata() then waits to see replaced, so
  // between them the two say the workflow was reset AND discovery re-ran.
  const seeded = await driver.executeScript(
      "return { client_id: window.localStorage.getItem('client_id')," +
      "         token_endpoint:" +
      "             window.localStorage.getItem('token_endpoint') };");
  assert.ok(!previous || seeded.client_id !== previous,
    "the workflow was cleared and storage still holds client_id=\"" +
    seeded.client_id + "\", which is the client of the workflow before this " +
    "one. Every field this hop sets would then be indistinguishable from one " +
    "left behind.");
  assert.ok(String(seeded.token_endpoint || "")
      .indexOf("https://localhost/oauth2/") === 0,
    "after the clear the token endpoint in storage is \"" +
    seeded.token_endpoint + "\" rather than the page's unconfigured " +
    "placeholder, so the previous workflow's discovery is still in force and " +
    "this hop would inherit it instead of performing its own.");
  await populateMetadata(driver, discoveryEndpoint);
  log.debug("Leaving startNewWorkflow().");
}

// The mock's sign-in screen, which reuses Keycloak's field ids. It checks no
// password; the username typed here is the identity every token then describes.
async function signIn(driver, user) {
  log.debug("Entering signIn(). user=" + user);
  const username = By.id("username");
  try {
    await driver.wait(until.elementLocated(username), waitTime * 3);
    await driver.wait(until.elementIsVisible(driver.findElement(username)),
                      waitTime);
  } catch (e) {
    const url = await driver.getCurrentUrl();
    throw new Error("The authorization server never showed its sign-in " +
                    "screen, so the authorization request was refused. The " +
                    "browser is at: " + url);
  }
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  const passwordFields = await driver.findElements(By.id("password"));
  if (passwordFields.length) {
    await passwordFields[0].clear();
    await passwordFields[0].sendKeys(user);
  }
  await driver.findElement(By.id("kc-login")).click();
  log.debug("Leaving signIn().");
}

// ---------------------------------------------------------------------------
// HOP 0 — webapp1 signs bob_end_user in and redeems the code. The tokens it
// returns are the ones the scenario says to keep.
// ---------------------------------------------------------------------------
async function authenticateTheUser(driver, clientId, scope) {
  log.debug("Entering authenticateTheUser().");
  log.info("=== " + clientId + ": OIDC Authorization Code flow as " + USER +
           ", scope \"" + scope + "\" ===");
  const grantType = By.id("authorization_grant_type");
  const clientIdField = By.id("client_id");

  await driver.wait(until.elementLocated(grantType), waitTime);
  if (!(await driver.findElement(grantType).isDisplayed())) {
    // The Configuration Parameters pane is collapsed once discovery has run, so
    // on any visit after the first the dropdown is present and not
    // interactable.
    await driver.findElement(By.id("config_expand_button")).click();
    await driver.wait(until.elementIsVisible(driver.findElement(grantType)),
                      waitTime);
  }
  await new Select(await driver.findElement(grantType))
      .selectByVisibleText("OIDC Authorization Code Flow(code)");

  // PKCE, because webapp1 is a public client: it has no secret here, and RFC
  // 9700 wants one from every client anyway. The mock does not require it
  // outside its compliant realm, which is exactly why it is asked for
  // explicitly rather than left to a default.
  await driver.wait(until.elementLocated(By.id("usePKCE-yes")), waitTime);
  await driver.findElement(By.id("usePKCE-yes")).click();

  await driver.wait(until.elementLocated(clientIdField), waitTime);
  if (!(await driver.findElement(clientIdField).isDisplayed())) {
    await driver.findElement(By.id("authz_expand_button")).click();
  }
  await driver.wait(until.elementIsVisible(driver.findElement(clientIdField)),
                    waitTime);
  await driver.findElement(clientIdField).clear();
  await driver.findElement(clientIdField).sendKeys(clientId);
  await driver.findElement(By.id("scope")).clear();
  await driver.findElement(By.id("scope")).sendKeys(scope);
  await driver.findElement(By.id("redirect_uri")).clear();
  await driver.findElement(By.id("redirect_uri")).sendKeys(baseUrl +
      "/callback");

  // What the page is ABOUT TO SEND, read from the preview it navigates to
  // rather than from the fields it was typed into. Typing does not always fire
  // the handlers that rebuild it, so it is asked for.
  await driver.executeScript(
      "oauth2_oidc_1.recalculateAuthorizationRequestDescription();");
  const preview = await waitFor.waitForFilled(driver,
      "display_authz_request_form_textarea1",
      "oauth2_oidc_1.html should draw the authorization request it is about " +
      "to send");
  assert.ok(preview.indexOf("client_id=" + clientId) >= 0,
    "the authorization request the page is about to send does not name " +
    clientId + ". It reads: " + preview);
  scope.split(" ").forEach(function (one) {
    assert.ok(preview.indexOf(one) >= 0,
      "the authorization request does not carry the scope \"" + one +
      "\", which is what the next tier is named in. It reads: " + preview);
  });
  assert.ok(preview.indexOf("response_type=code") >= 0,
    "the authorization request is not the Authorization Code flow. It " +
    "reads: " + preview);
  assert.ok(preview.indexOf("code_challenge=") >= 0,
    "PKCE was selected and the authorization request carries no " +
    "code_challenge, so the radio did not take. This mock does not require " +
    "PKCE outside its compliant realm, so nothing downstream would fail. It " +
    "reads: " + preview);
  log.info("[" + clientId + "] the authorization request carries " +
           "client_id=" + clientId + ", response_type=code, a PKCE " +
           "challenge and every requested scope.");

  await driver.findElement(
      By.css("input[type=\"submit\"][value=\"Authorize\"]")).click();
  await signIn(driver, USER);

  await driver.wait(until.urlContains("/oauth2_oidc_2.html"), waitTime * 5);
  await waitFor.waitForPageBundle(driver, "oauth2_oidc_2.html's bundle");
  const code = await waitFor.waitForFilled(driver, "code",
      "the authorization code should come back and reach the Token " +
      "Request's code field");
  log.info("[" + clientId + "] an authorization code came back.");

  // Redeemed BROWSER-DIRECT rather than through the api proxy, so this job
  // needs the client and the mock and nothing else — the same reasoning
  // tests/oidc_flows.js records. Clicked rather than set, because the flag is
  // only assigned by the radio's own click handler.
  const frontEnd =
      await driver.findElements(By.id("token_initiateFromFrontEnd"));
  assert.ok(frontEnd.length,
      "oauth2_oidc_2.html has no token_initiateFromFrontEnd radio.");
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                             frontEnd[0]);
  await frontEnd[0].click();
  assert.ok(await frontEnd[0].isSelected(),
    "the browser-direct radio did not take, so the Token Request would go " +
    "through the api.");

  await driver.findElement(By.id("token_client_id")).clear();
  await driver.findElement(By.id("token_client_id")).sendKeys(clientId);
  await driver.findElement(By.id("token_scope")).clear();
  await driver.findElement(By.id("token_scope")).sendKeys(scope);
  await driver.findElement(By.id("token_redirect_uri")).clear();
  await driver.findElement(By.id("token_redirect_uri")).sendKeys(baseUrl +
      "/callback");
  await driver.findElement(By.className("token_btn")).click();

  const accessToken = await waitFor.waitForValue(driver, "token_access_token",
      function (v) { return v.split(".").length === 3; },
      "the token endpoint should return an access token for " + clientId);
  const idToken = await waitFor.waitForValue(driver, "token_id_token",
      function (v) { return v.split(".").length === 3; },
      "the token endpoint should return an ID token — the scope carries " +
      "`openid`");
  // `offline_access` was asked for, so a refresh token is part of "the set of
  // tokens" the scenario says to keep. It is the ONE artifact of this workflow
  // that no exchange below can produce: RFC 8693 issues no refresh token here.
  const refreshToken = await waitFor.waitForFilled(driver,
      "token_refresh_token",
      "the token endpoint should return a refresh token — the scope carries " +
      "`offline_access`");
  log.info("[" + clientId + "] holding access_token, id_token and " +
           "refresh_token.");
  log.debug("Leaving authenticateTheUser().");
  return { access_token: accessToken, id_token: idToken,
           refresh_token: refreshToken };
}

// ---------------------------------------------------------------------------
// ONE HOP — the Token Exchange pane, driven as a client that has just been
// handed somebody else's token and knows nothing else.
// ---------------------------------------------------------------------------
async function exchangeAs(driver, hop) {
  log.debug("Entering exchangeAs(). client=" + hop.clientId);
  log.info("=== " + hop.clientId + ": RFC 8693 exchange for " + hop.audience +
           ", scope \"" + hop.scope + "\" ===");
  await driver.get(baseUrl + "/oauth2_oidc_2.html");
  await waitFor.waitForPageBundle(driver, "oauth2_oidc_2.html's bundle");

  const fieldset = By.id("tokenexchange_fieldset");
  await driver.wait(until.elementLocated(fieldset), waitTime);
  const shown = await driver.executeScript(
      "var e = document.getElementById('tokenexchange_fieldset');" +
      "return e ? window.getComputedStyle(e).display : 'missing';");
  if (shown !== "block") {
    await driver.executeScript(
        "document.getElementById('tokenexchange_expand_button').click();");
  }
  const subject = By.id("tokenexchange_subject_token");
  await driver.wait(until.elementIsVisible(driver.findElement(subject)),
                    waitTime);

  // The endpoint came from the discovery this workflow just ran. Asserted
  // rather than typed, because a pane that had to be told where the token
  // endpoint is would mean the new workflow never discovered anything.
  const endpoint = await waitFor.waitForFilled(driver,
      "tokenexchange_token_endpoint",
      "the exchange pane's token endpoint should be filled from the " +
      "discovery document this workflow fetched");
  log.info("[" + hop.clientId + "] exchanging at " + endpoint);

  // Browser-direct, for the reason the Token Request above is.
  const frontEnd = await driver.findElements(
      By.id("tokenexchange_initiateFromFrontEnd"));
  assert.ok(frontEnd.length,
      "oauth2_oidc_2.html has no tokenexchange_initiateFromFrontEnd radio.");
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                             frontEnd[0]);
  await frontEnd[0].click();
  assert.ok(await frontEnd[0].isSelected(),
    "the browser-direct radio did not take for the exchange.");

  // Impersonation: no actor token. Asserted rather than assumed — the two
  // radios are what decides whether the token that comes back carries an `act`
  // claim, and the register files the act under a different type for each.
  assert.ok(await driver.findElement(
      By.id("tokenexchange_impersonation")).isSelected(),
    "the Impersonation radio is not selected, so an actor token would be " +
    "expected and this hop would be recorded as a delegation rather than an " +
    "impersonation.");

  const set = async function (id, value) {
    log.debug("Entering set(). id=" + id);
    const field = await driver.findElement(By.id(id));
    await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                               field);
    await field.clear();
    if (value !== "") {
      // sendKeys("") is not "type nothing" — it is an argument Selenium
      // rejects, and clear() has already emptied the field.
      await field.sendKeys(value);
    }
    log.debug("Leaving set().");
  };
  await set("tokenexchange_subject_token", hop.subjectToken);
  await set("tokenexchange_client_id", hop.clientId);
  await set("tokenexchange_client_secret", "");
  await set("tokenexchange_audience", hop.audience);
  await set("tokenexchange_scope", hop.scope);

  // WHAT THE PANE IS ABOUT TO POST. Every field above could have been left over
  // from the previous hop and the response would still look right.
  await driver.executeScript(
      "oauth2_oidc_2.recalculateTokenExchangeRequestDescription();");
  const request = await waitFor.waitForFilled(driver,
      "display_tokenexchange_request_form_textarea1",
      "the exchange pane should draw the request it is about to send");
  assert.ok(request.indexOf(
      "grant_type=urn:ietf:params:oauth:grant-type:token-exchange") >= 0,
    "the request is not an RFC 8693 exchange. It reads: " + request);
  assert.ok(request.indexOf("client_id=" + hop.clientId) >= 0,
    "the exchange is about to be made as somebody else — it should name " +
    hop.clientId + ". It reads: " + request);
  assert.ok(request.indexOf("audience=" + hop.audience) >= 0,
    "the exchange does not name " + hop.audience + " as the audience, so the " +
    "token that comes back would be addressed to nothing in particular and " +
    "the register would record a chain with no target. It reads: " + request);
  assert.ok(request.indexOf("scope=" + hop.scope) >= 0,
    "the exchange does not ask for the scope \"" + hop.scope + "\". It " +
    "reads: " + request);
  assert.ok(request.indexOf("subject_token=" + hop.subjectToken) >= 0,
    "the subject token being exchanged is not the token this hop was handed. " +
    "That is the previous hop's token still in the pane, and the exchange " +
    "would succeed and mean nothing.");
  assert.ok(request.indexOf("actor_token") < 0,
    "an actor token is about to be sent on an impersonation. It reads: " +
    request);
  log.info("[" + hop.clientId + "] the request names the client, the " +
           "audience, the scope and the subject token it was handed.");

  const button = await driver.findElement(By.id("tokenexchange_btn"));
  await driver.executeScript(
      "arguments[0].scrollIntoView({block:'center'}); arguments[0].click();",
      button);

  const result = await waitFor.waitForValue(driver,
      "tokenexchange_result_textarea",
      function (v) { return v.indexOf("HTTP Status:") >= 0; },
      "the exchange should produce a result");
  assert.ok(result.indexOf("HTTP Status: 200") >= 0,
    "the exchange as " + hop.clientId + " did not answer 200: " + result);
  const parsed = parseEmbeddedJson(result);
  assert.ok(parsed !== null,
    "the exchange response could not be parsed as JSON: " + result);
  assert.ok(parsed.access_token,
    "the exchange returned no access_token: " + JSON.stringify(parsed));
  assert.strictEqual(parsed.issued_token_type,
    "urn:ietf:params:oauth:token-type:access_token",
    "RFC 8693 section 2.2.1 requires issued_token_type, and this response " +
    "says \"" + parsed.issued_token_type + "\".");
  log.info("[" + hop.clientId + "] exchanged. issued_token_type=" +
           parsed.issued_token_type + ", token_type=" + parsed.token_type);
  log.debug("Leaving exchangeAs().");
  return parsed;
}

// The JSON object embedded in a result textarea, after its "Response Body:"
// preamble.
function parseEmbeddedJson(text) {
  log.debug("Entering parseEmbeddedJson().");
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) {
    log.debug("Leaving parseEmbeddedJson(). No object in it.");
    return null;
  }
  try {
    log.debug("Leaving parseEmbeddedJson().");
    return JSON.parse(text.substring(start, end + 1));
  } catch (e) {
    log.debug("Leaving parseEmbeddedJson(). Not JSON.");
    return null;
  }
}

function claimsOf(token, what) {
  log.debug("Entering claimsOf(). what=" + what);
  const decoded = jwt.decode(token, { complete: true });
  assert.notStrictEqual(decoded, null,
    what + " could not be decoded as a JWT.");
  log.debug("Leaving claimsOf().");
  return decoded.payload;
}

// ---------------------------------------------------------------------------
// THE AUDIENCE, READ THE ONE WAY IT CAN BE. `aud` is a string where there is
// one party and an array where there are several (RFC 7519 section 4.1.3), and
// this chain produces BOTH shapes on purpose: the sign-in's token is addressed
// to the gateway AND to this service's own /resource, because the `openid`
// scope asks for UserInfo, while each exchange names one URI and gets a
// string. So every reader here goes through this rather than comparing a claim
// that is sometimes a list — a `claims.aud === x` would pass on the exchanges
// and fail on the sign-in, saying nothing about either.
// ---------------------------------------------------------------------------
function audienceList(claims) {
  log.debug("Entering audienceList().");
  const aud = claims && claims.aud;
  if (aud === undefined || aud === null) {
    log.debug("Leaving audienceList(). None.");
    return [];
  }
  log.debug("Leaving audienceList().");
  return (Array.isArray(aud) ? aud : [aud]).map(String);
}

function assertAddressedTo(claims, party, what) {
  log.debug("Entering assertAddressedTo(). party=" + party);
  assert.ok(audienceList(claims).indexOf(party) >= 0,
    what + " is not addressed to " + party + ". Its audience is " +
    JSON.stringify(claims && claims.aud) + ", and the audience is where this " +
    "issuer puts the party a token is for — a scope naming an application " +
    "becomes one, and an exchange's `audience` parameter is one outright.");
  log.debug("Leaving assertAddressedTo().");
}

function assertNotAddressedTo(claims, party, what, why) {
  log.debug("Entering assertNotAddressedTo(). party=" + party);
  assert.ok(audienceList(claims).indexOf(party) < 0,
    what + " is addressed to " + party + " (" +
    JSON.stringify(claims && claims.aud) + "). " + why);
  log.debug("Leaving assertNotAddressedTo().");
}

// What every token in this chain must be true of, wherever in the chain it is.
function assertTokenDescribes(token, expect) {
  log.debug("Entering assertTokenDescribes(). what=" + expect.what);
  const claims = claimsOf(token, expect.what);
  assert.strictEqual(claims.username, USER,
    expect.what + " names " + claims.username + " rather than " + USER +
    ". An exchange must carry the SUBJECT forward: a token naming the client " +
    "that exchanged it is the middle tier acting as itself, which is a " +
    "different thing entirely.");
  const scopes = String(claims.scope || "").split(/\s+/).filter(Boolean);
  expect.scope.split(" ").forEach(function (one) {
    assert.ok(scopes.indexOf(one) >= 0,
      expect.what + " does not carry the scope \"" + one + "\". It carries: " +
      JSON.stringify(claims.scope) + ".");
  });
  if (expect.audience) {
    assertAddressedTo(claims, expect.audience, expect.what);
  }
  if (expect.clientId) {
    assert.strictEqual(claims.client_id, expect.clientId,
      expect.what + " was issued to client \"" + claims.client_id +
      "\" rather than to " + expect.clientId + ".");
  }
  // Impersonation: nothing about the middle tier travels in the token, which is
  // the property that makes the register the only place the chain exists.
  assert.ok(claims.act === undefined,
    expect.what + " carries an `act` claim (" + JSON.stringify(claims.act) +
    "). That is RFC 8693 delegation, and no actor token was sent — so either " +
    "the pane sent one or the server invented one.");
  log.info("[token] " + expect.what + ": sub=" + claims.sub + ", username=" +
           claims.username + ", client_id=" + claims.client_id + ", aud=" +
           JSON.stringify(claims.aud) + ", scope=\"" + claims.scope + "\", " +
           "jti=" + claims.jti);
  log.debug("Leaving assertTokenDescribes().");
  return claims;
}

// ---------------------------------------------------------------------------
// The issuer's own reading of the final token. Decoding a string proves what
// this test was handed; introspection proves what the authorization server
// thinks it issued, which is the reading a resource server would get.
// ---------------------------------------------------------------------------
async function introspect(token, clientId) {
  log.debug("Entering introspect().");
  const url = stsBase() + "/oauth2/introspect";
  const r = await common.httpJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(token) +
          "&token_type_hint=access_token" +
          "&client_id=" + encodeURIComponent(clientId),
  });
  assert.ok(r.ok, "POST " + url + " should answer 200 and answered " +
            r.status + ": " + String(r.raw).slice(0, 200));
  log.debug("Leaving introspect(). active=" + r.body.active);
  return r.body;
}

// ---------------------------------------------------------------------------
// THE REGISTER. One act per hop, found among the acts recorded SINCE this job
// started — never among all of them, because the mock's stores survive between
// jobs and the suite runs in a pool.
// ---------------------------------------------------------------------------
function findAct(acts, hop) {
  log.debug("Entering findAct(). intermediary=" + hop.clientId);
  const found = acts.filter(function (row) {
    return row.intermediary && row.intermediary.application === hop.clientId &&
           row.target && row.target.application === hop.target;
  });
  assert.strictEqual(found.length, 1,
    "the delegation register should hold exactly ONE act recorded by this " +
    "job in which " + hop.clientId + " reached " + hop.target + " (asked for " +
    "as " + hop.audience + "), and it holds " + found.length + ". A zero " +
    "here with an act whose target IS that URI means the audience was not " +
    "resolved through the registry — see applications.forAudience(). What it " +
    "holds since this job started: " +
    JSON.stringify(acts.map(function (row) {
      return row.type + " " + (row.initial.presented || "?") + " -> " +
             (row.intermediary.application || "?") + " -> " +
             (row.target.application || "?");
    })) + ".");
  log.debug("Leaving findAct(). seq=" + found[0].seq);
  return found[0];
}

function assertActRecords(act, hop, claims) {
  log.debug("Entering assertActRecords(). client=" + hop.clientId);
  assert.strictEqual(act.protocol, "OAuth 2.0",
    "the act was filed under protocol \"" + act.protocol + "\".");
  assert.strictEqual(act.type, "oauth-impersonation",
    "no actor token was sent, so RFC 8693 section 1.1 makes this an " +
    "IMPERSONATION, and the register filed it as \"" + act.type + "\".");
  assert.strictEqual(act.mode, "impersonation",
    "the act's mode is \"" + act.mode + "\". Mode is the axis that says " +
    "whether the far end can see the middle tier, and getting it wrong is " +
    "worse than getting the type wrong.");
  assert.strictEqual(act.outcome, "issued",
    "the act was recorded with outcome \"" + act.outcome + "\".");
  assert.strictEqual(act.initial.presented, USER,
    "the act names \"" + act.initial.presented + "\" as the identity being " +
    "acted for, rather than " + USER + ".");
  assert.strictEqual(act.intermediary.application, hop.clientId,
    "the act names \"" + act.intermediary.application + "\" as the middle " +
    "tier rather than " + hop.clientId + ".");
  assert.strictEqual(act.target.application, hop.target,
    "the act says the exchange reached \"" + act.target.application +
    "\" rather than " + hop.target + ". The exchange asked for the audience " +
    hop.audience + ", which that application registers on `oauthAudience`, " +
    "so the register should name the APPLICATION — a row naming the URI is " +
    "the lookup not happening, and it draws a box in the map that nothing " +
    "else in the picture mentions.");
  // AND THE ROW SAYS WHICH AUDIENCE RESOLVED. Without this the two facts are
  // indistinguishable on the page: an act filed against `esb1` because the
  // exchange asked for `esb1`, and one filed against `esb1` because the URI it
  // asked for is registered there. The second is what happened and only the
  // sentence can say so.
  assert.ok(String(act.target.what || "").indexOf(hop.audience) >= 0,
    "the act's target names " + hop.target + " and its explanation does not " +
    "mention the audience that was actually requested (" + hop.audience +
    "). It says: \"" + act.target.what + "\".");
  // An impersonation names no identity in the middle: the client IS the whole
  // of it. This is the assertion that would catch an actor token creeping in.
  assert.strictEqual(act.intermediary.presented, "",
    "the act names \"" + act.intermediary.presented + "\" as an identity in " +
    "the middle. An impersonation has none — the client performing the " +
    "exchange is the whole of the middle.");
  const produced = (act.produced || []).filter(function (one) {
    return one.kind === "access_token";
  });
  assert.strictEqual(produced.length, 1,
    "the act should record ONE access token as what it produced, and records " +
    JSON.stringify(act.produced) + ".");
  assert.strictEqual(produced[0].identifier, claims.jti,
    "the register says this act produced the token whose jti is \"" +
    produced[0].identifier + "\", and the token this test received is \"" +
    claims.jti + "\". The row and the wire are describing different tokens.");
  log.info("[register] act " + act.seq + ": " + act.typeLabel + " — " +
           act.initial.presented + " -> " + act.intermediary.application +
           " -> " + act.target.application + ", producing " +
           produced[0].identifier);
  log.debug("Leaving assertActRecords().");
}

// ---------------------------------------------------------------------------
// THE PICTURE'S MODEL. The nodes and edges /admin/delegation/map draws, read
// from the same JSON that page is built from — which is the only way a drawing
// can be checked from outside without parsing an SVG.
// ---------------------------------------------------------------------------
function assertGraphIsAChain(graph, hops) {
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
  const edgeOf = function (from, to, relation) {
    log.debug("Entering edgeOf(). " + from + " -> " + to);
    const found = (graph.edges || []).filter(function (e) {
      return e.from === from && e.to === to && e.relation === relation;
    });
    assert.ok(found.length,
      "the picture should draw a \"" + relation + "\" line from " + from +
      " to " + to + ", and draws none. Its lines are: " +
      JSON.stringify((graph.edges || []).map(function (e) {
        return e.from + " -" + e.relation + "-> " + e.to;
      })) + ".");
    log.debug("Leaving edgeOf().");
    return found[0];
  };

  hops.forEach(function (hop) {
    // Each act draws two lines and they say different things: who is acting for
    // whom, and what the credential that came out is FOR.
    const actsFor = edgeOf(USER, hop.clientId, "acts-for");
    assert.strictEqual(actsFor.mode, "impersonation",
      "the line from " + USER + " to " + hop.clientId + " is drawn as \"" +
      actsFor.mode + "\".");
    const reaches = edgeOf(hop.clientId, hop.target, "reaches");
    assert.strictEqual(reaches.subject, USER,
      "the line from " + hop.clientId + " to " + hop.target + " should be " +
      "labelled with whose name the credential carries (" + USER + ") and " +
      "carries \"" + reaches.subject + "\".");
  });

  // THE ONE PROPERTY THAT MAKES THIS A CHAIN RATHER THAN TWO EXCHANGES. The
  // middle of the second hop is the far end of the first, and the picture must
  // have ONE box for it: two would be two unrelated pictures that happen to
  // share a name, which is exactly what a delegation map exists to disprove.
  const middle = nodeOf(hops[1].clientId);
  assert.ok(middle.roles.target >= 1,
    "the picture does not show " + hops[1].clientId + " as the target of " +
    "anything, so the first hop's arrow lands somewhere else.");
  assert.ok(middle.roles.intermediary >= 1,
    "the picture does not show " + hops[1].clientId + " as an intermediary, " +
    "so the second hop was made by somebody else.");
  log.info("[picture] " + hops[1].clientId + " is one box that was reached " +
           middle.roles.target + " time(s) and acted as an intermediary " +
           middle.roles.intermediary + " time(s) — the two hops meet there.");

  // And the person is one box too: both chains start at the same identity.
  const person = nodeOf(USER);
  assert.ok(person.roles.initial >= 2,
    "the picture should show " + USER + " as the identity behind BOTH hops " +
    "and shows " + person.roles.initial + ".");
  log.debug("Leaving assertGraphIsAChain().");
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
    const base = stsBase();
    const discovery = process.env.DELEGATION_DISCOVERY_ENDPOINT ||
        (base + "/.well-known/openid-configuration");
    log.info("The authorization server is " + base + ", discovered at " +
             discovery + ".");
    log.info("The chain: " + USER + " signs in to " + WEBAPP + ", " + GATEWAY +
             " exchanges for " + audienceOf(ESB) + " (" + ESB + "), and " +
             ESB + " exchanges for " + audienceOf(PROVIDER) + " (" +
             PROVIDER + ").");

    // The baseline, BEFORE anything is minted. Everything asserted below is a
    // delta against it: this mock's register survives between jobs and the
    // suite runs in a pool.
    const before = await delegationJson("?per=1");
    const baselineSeq = Number(before.newestSeq || 0);
    log.info("[register] " + before.held + " act(s) already held; this job's " +
             "acts are the ones after seq " + baselineSeq + ".");

    // --- the four applications, before anything connects -------------------
    // Deliberately BEFORE the browser: an entry created after a client_id has
    // already been accepted is a different thing — the registry would have
    // written it from the sighting, and this test would then be editing an
    // entry rather than provisioning one. It also has to be before the first
    // exchange, because the audience lookup that keeps the chain connected
    // reads what is registered at the moment the act is recorded.
    await provisionApplications();

    // --- hop 0: the sign-in ------------------------------------------------
    await startNewWorkflow(driver, discovery, WEBAPP, null);
    const first = await authenticateTheUser(driver, WEBAPP, scopeFor(GATEWAY));
    const firstClaims = assertTokenDescribes(first.access_token, {
      what: WEBAPP + "'s access token",
      // The BASE alone. The request named the gateway in the scope list, and
      // this issuer reads a scope naming an application as the audience — so
      // what the token carries is the scope MINUS that name. See the header.
      scope: BASE_SCOPE,
      // The scope value VERBATIM, which is what a derived audience is
      // addressed to. `aud` is an array here, because an `openid` request
      // keeps this service's own /resource beside it for UserInfo.
      audience: GATEWAY,
      clientId: WEBAPP,
    });
    assert.ok(String(firstClaims.scope).split(/\s+/).indexOf(GATEWAY) < 0,
      "the token " + WEBAPP + " obtained carries \"" + GATEWAY + "\" in its " +
      "scope as well as in its audience (scope=\"" + firstClaims.scope +
      "\", aud=" + JSON.stringify(firstClaims.aud) + "). A scope naming an " +
      "application is that token's AUDIENCE; carrying it in both places says " +
      "the gateway is a permission as well as a party.");

    // --- hop 1: the API gateway -------------------------------------------
    //
    // `audience` is what the exchange ASKS FOR and what lands in the token's
    // `aud`: the downstream tier's registered resource URI. `target` is the
    // application that URI resolves to in the registry, which is what the
    // delegation act must be filed against — the two being different strings is
    // the whole of what oauthAudience buys, so they are separate members here
    // rather than one that has to mean both.
    const hops = [
      { clientId: GATEWAY, audience: audienceOf(ESB), target: ESB,
        scope: scopeFor(ESB), subjectToken: first.access_token },
      // subjectToken filled in below, from what hop 1 produced.
      { clientId: ESB, audience: audienceOf(PROVIDER), target: PROVIDER,
        scope: scopeFor(PROVIDER), subjectToken: "" },
    ];

    await startNewWorkflow(driver, discovery, GATEWAY, WEBAPP);
    const second = await exchangeAs(driver, hops[0]);
    const secondClaims = assertTokenDescribes(second.access_token, {
      what: GATEWAY + "'s exchanged access token",
      // Trimmed the same way, even though this hop sent `audience` outright:
      // the parameter decides the `aud`, and the scope list loses the name
      // regardless. Both halves are asserted below.
      scope: BASE_SCOPE,
      audience: audienceOf(ESB),
      clientId: GATEWAY,
    });
    assert.notStrictEqual(second.access_token, first.access_token,
      "the exchange handed back the token it was given.");
    assertNotAddressedTo(secondClaims, GATEWAY,
      GATEWAY + "'s exchanged access token",
      "The gateway asked for a token for the NEXT tier; one still addressed " +
      "to the gateway is one the gateway could keep presenting to itself.");
    assert.ok(String(secondClaims.scope).split(/\s+/).indexOf(ESB) < 0,
      "the exchanged token carries \"" + ESB + "\" in its scope (\"" +
      secondClaims.scope + "\") as well as in its audience. An exchange that " +
      "sent `audience` is the other branch of that reading, and it trims the " +
      "scope list too.");

    // --- hop 2: the ESB ----------------------------------------------------
    hops[1].subjectToken = second.access_token;
    await startNewWorkflow(driver, discovery, ESB, GATEWAY);
    const third = await exchangeAs(driver, hops[1]);
    const thirdClaims = assertTokenDescribes(third.access_token, {
      what: ESB + "'s exchanged access token",
      scope: BASE_SCOPE,
      audience: audienceOf(PROVIDER),
      clientId: ESB,
    });
    assertNotAddressedTo(thirdClaims, GATEWAY, "the final access token",
      "The gateway is two hops behind it.");
    assertNotAddressedTo(thirdClaims, WEBAPP, "the final access token",
      "The browser application is where the chain started and is not a " +
      "party a token can be addressed to at all.");
    assert.ok(String(thirdClaims.scope).split(/\s+/).indexOf(PROVIDER) < 0,
      "the final access token carries \"" + PROVIDER + "\" in its scope " +
      "(\"" + thirdClaims.scope + "\") as well as in its audience.");

    // The artifact the scenario is about, in full.
    log.info("=== The final access token, after two hops ===");
    log.info(third.access_token);
    log.info("=== Its claims ===");
    log.info(JSON.stringify(thirdClaims, null, 2));
    log.info("CONFIRMED: the access token " + ESB + " received is addressed " +
             "to " + audienceOf(PROVIDER) + " (" + PROVIDER + "), it names " +
             USER + ", and " + USER + " never asked for it.");

    // --- the issuer's own reading -----------------------------------------
    const introspection = await introspect(third.access_token, PROVIDER);
    assert.strictEqual(introspection.active, true,
      "the authorization server reports the final token as not active: " +
      JSON.stringify(introspection));
    // The AUDIENCE is where the far end is named, so that is what the issuer
    // is asked to agree about. Introspecting for the scope alone would now
    // confirm a set of permissions that says nothing about which party the
    // token is for, which is the fact the whole chain is about.
    assertAddressedTo(introspection, audienceOf(PROVIDER),
      "the introspection of the final token");
    const introspectedScopes = String(introspection.scope || "")
        .split(/\s+/).filter(Boolean);
    assert.ok(introspectedScopes.indexOf(PROVIDER) < 0,
      "introspection reports the final token's scope as \"" +
      introspection.scope + "\", which carries " + PROVIDER + " — so the " +
      "signed token and the server that signed it disagree about whether " +
      "that name is a scope or an audience.");
    BASE_SCOPE.split(" ").forEach(function (one) {
      assert.ok(introspectedScopes.indexOf(one) >= 0,
        "introspection reports the final token's scope as \"" +
        introspection.scope + "\", which has lost \"" + one + "\". Two " +
        "exchanges must not narrow the grant by themselves.");
    });
    assert.strictEqual(introspection.username, USER,
      "introspection says the final token belongs to \"" +
      introspection.username + "\" rather than to " + USER + ".");
    log.info("[introspection] the authorization server agrees: active, " +
             "aud=" + JSON.stringify(introspection.aud) + ", scope=\"" +
             introspection.scope + "\", username=" + introspection.username +
             ".");

    // --- the register and the picture --------------------------------------
    const after = await delegationJson("?q=" + encodeURIComponent(USER) +
                                       "&per=200");
    const mine = (after.acts || []).filter(function (row) {
      return Number(row.seq) > baselineSeq;
    });
    assert.ok(mine.length >= 2,
      "this job made two exchanges and the register holds " + mine.length +
      " act(s) recorded since it started. A delegation performed and not " +
      "recorded is one this service cannot account for.");
    const acts = hops.map(function (hop) {
      return findAct(mine, hop);
    });
    assertActRecords(acts[0], hops[0], secondClaims);
    assertActRecords(acts[1], hops[1], thirdClaims);
    assert.ok(Number(acts[1].seq) > Number(acts[0].seq),
      "the register puts the second hop (seq " + acts[1].seq + ") before the " +
      "first (seq " + acts[0].seq + ").");

    // The graph of what matched — this person's acts — which is what
    // /admin/delegation/map draws for the same filter.
    assertGraphIsAChain(after.graph || {}, hops);

    // --- where the final token came from -----------------------------------
    // The console is the only door to this one: the lineage page has no form
    // and therefore no operation on /admin-api (the mock's rule 7), so the
    // session is obtained here rather than with the drawings below and both
    // use it.
    const session = await signInToTheConsole();
    await assertTheTokensPageLinksIt(session, thirdClaims.jti);
    // The two pivots on the delegation page, which are a SEARCH rather than a
    // list since 2026-08-26. Here rather than beside the drawings because it
    // needs the same session and no picture: it reads the page's markup.
    await assertTheChoosersSearch(session);
    await assertTheLineage(session, {
      // Newest first, which is the order the page walks: the token esb1 was
      // handed, the one apigw1 exchanged for it, and the one bob_end_user's
      // sign-in produced.
      jtis: [thirdClaims.jti, secondClaims.jti, firstClaims.jti],
      originClient: WEBAPP,
      // webapp1 is the party that exists on THIS picture and on no other: it
      // exchanged nothing, so no delegation act names it and the map cannot
      // draw it. Reaching it is the whole of "back to the original issuance".
      parties: [USER, WEBAPP, GATEWAY, ESB, PROVIDER],
    });

    // --- the drawings ------------------------------------------------------
    const filter = "?q=" + encodeURIComponent(USER);
    const svg = await saveDrawing(session,
        "/admin/delegation/map" + filter + "&format=svg",
        "delegation-map-" + USER + ".svg",
        "the delegation map, filtered to " + USER);
    if (svg) {
      // A drawing that draws nothing is the failure worth catching: the page
      // answers 200 with an empty diagram when the graph is empty, and an SVG
      // file nobody opened would never say so.
      assert.ok(svg.indexOf("<svg") >= 0,
        "the map answered 200 with something that is not an SVG document: " +
        svg.slice(0, 200));
      // Searched with the MARKUP REMOVED rather than in the raw document: a
      // box label is wrapped into several <tspan>s and capped at 30
      // characters, so a name can be split across elements even when it is
      // drawn whole. Stripping the tags rejoins it, and it also reaches the
      // <title> the renderer puts on every shape, which carries the label
      // uncut.
      const drawn = svg.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
      // And the same text with the tags removed rather than replaced, which is
      // what rejoins a label the renderer split between two <tspan>s.
      const joined = svg.replace(/<[^>]*>/g, "");
      [USER, GATEWAY, ESB, PROVIDER].forEach(function (name) {
        assert.ok(drawn.indexOf(name) >= 0 || joined.indexOf(name) >= 0,
          "the drawing does not mention \"" + name + "\", so the picture is " +
          "missing a box the graph says is in it. What it draws: " +
          drawn.slice(0, 400));
      });
      log.info("[drawing] the map names " + USER + ", " + GATEWAY + ", " +
               ESB + " and " + PROVIDER + ".");
      await saveDrawing(session, "/admin/delegation/map?format=svg",
          "delegation-map-all.svg",
          "the delegation map, everything this service has recorded");
      await saveDrawing(session,
          "/admin/delegation/map" + filter + "&format=json",
          "delegation-map-" + USER + ".json",
          "the graph the map is drawn from");
      for (let i = 0; i < acts.length; i++) {
        await saveDrawing(session,
            "/admin/delegation/chain?chain=" +
            encodeURIComponent(acts[i].chainKey) + "&format=svg",
            // Named for the two APPLICATIONS rather than for the audience:
            // the audience is a URI and a URI has slashes in it, which is a
            // path this file cannot be written to.
            "delegation-chain-" + hops[i].clientId + "-to-" +
                hops[i].target + ".svg",
            "the chain " + hops[i].clientId + " -> " + hops[i].target +
                " (asked for as " + hops[i].audience + ")");
      }
      await saveDrawing(session,
          "/admin/delegation/application?application=" +
          encodeURIComponent(ESB) + "&format=svg",
          "delegation-application-" + ESB + ".svg",
          "everything " + ESB + " is part of — the tier in the middle");
      // AND THE LINEAGE, which is the picture the delegation map cannot draw:
      // every generation behind the final token, back through both exchanges to
      // the sign-in that started it.
      await saveDrawing(session,
          "/admin/tokens/credential?id=" +
          encodeURIComponent(thirdClaims.jti) + "&format=svg",
          "credential-lineage-" + PROVIDER + ".svg",
          "where the final token came from — every generation behind it");
    }

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
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
  .name("oauth2_delegation_chain")
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
