// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
// AND EACH DOWNSTREAM ONE REGISTERS AN AUDIENCE.** In DEVELOPMENT mode this
// service accepts a client_id it has never heard of — that is the whole reason
// the first version of this test needed no provisioning — so an entry appears
// only when something is ACCEPTED, and it appears knowing nothing but the
// identifier. In PRODUCT mode an unknown client_id is refused outright, and
// the provisioning below is what makes the chain possible at all rather than
// what makes it describable (see THE TWO MODES, below). Either way the four
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
// token is addressed to `apigw1` — the scope value VERBATIM. It used to sit
// beside this service's own `/resource`, kept for UserInfo, with the base four
// on its scope claim; since iya-sts 2f9825f (2026-09-13) it is `apigw1` alone
// and the claim is gone, for the reason OIDC_SCOPES_OFF_AN_API_TOKEN gives.
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
// resolved. In development nothing is REFUSED by any of this: an audience
// nobody registered is still exchanged for, and recorded verbatim. In product
// an unregistered target is `invalid_target`, which is one more reason the
// registry has to be right before the first hop.
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
// **THE TWO MODES OF iya-sts, AND THE SERVICE SAYS WHICH ONE IT IS IN.** The
// job runs against that service only (it is gated on WSTRUST_STS_URL), and
// asks it — `GET /admin-api/mode`, the same answer the console's mode page
// draws — rather than reading a flag of its own, because a flag set beside a
// run is a second statement of a fact the service already publishes, and the
// two drift the day somebody switches a realm. Keycloak would need the same
// provisioning as product mode and is not a target.
//
//   DEVELOPMENT. Clients that need no secret, a person whose password is not
//   checked, and a token endpoint that exchanges anything for anything: the
//   delegation policy is ASKED and its answer RECORDED on the act ("WOULD
//   HAVE BEEN REFUSED in product: …") but the token is issued regardless.
//   The provisioning below is then about DESCRIBING the chain — what the
//   register files each act against — and everything else is left as it
//   always was.
//
//   PRODUCT. Every one of those becomes a refusal, so the provisioning step
//   grows into the configuration a deployment would actually hold, and only
//   in that mode:
//     * bob_end_user is a directory entry with a password, which the sign-in
//       screen VERIFIES (DELEGATION_USER_PASSWORD, or one generated per run);
//     * webapp1 is a PUBLIC client (`none`), so PKCE is required of it, with
//       the debugger's callback REGISTERED, the code and refresh grants, and
//       the base scopes DECLARED on `oauthAllowedScope`;
//     * apigw1 and esb1 are CONFIDENTIAL — the token-exchange grant is not a
//       public client's — each with a secret generated for this run, which
//       the exchange pane sends; sp1 holds one too, because introspection
//       authenticates its caller in product;
//     * all four list the debugger's origin on `appCorsOrigin`, since every
//       call here is made browser-direct;
//     * and THE DELEGATION POLICY IS SATISFIED RATHER THAN SWITCHED OFF.
//       Each middle tier may IMPERSONATE (`appDelegationSemantics`), does so
//       when the request names no semantics (`appDefaultDelegationSemantics`
//       — the pane sends none), and may reach the tier after it
//       (`appAllowedToDelegateTo`): apigw1 → esb1, esb1 → sp1. That is rule
//       10 of the policy for an impersonation — "the actor must reach R" —
//       and nothing wider: apigw1 is NOT allowed to reach sp1.
//   What is asserted does not weaken in product. Where the mode changes an
//   answer — the act's `authorizedBy` names the rule that ALLOWED it rather
//   than what would have refused it — the product answer is asserted.
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
// in a pool, so the time of the newest act is read before the browser starts
// and every assertion below is about acts after it. See `tests/CLAUDE.md`.
// TIME and not the act's `seq`, which is what this read until it met a
// service running request workers: `seq` is a counter per PROCESS there
// (iya-sts common/delegation.js says so), two workers each number their own
// acts from 1, and "after the newest seq" then excluded this job's acts
// altogether. The register sorts its merged rows by time for the same
// reason — time is the one ordering every process shares.
//
// THE FOUR ENTRIES ARE LEFT BEHIND, and that is deliberate rather than a
// missing teardown. They are what the delegation map is a picture OF — a box
// labelled `esb1 (enterprise service bus)` that links to a registry entry is
// the drawing this job exists to produce — and deleting them after the SVGs
// were taken would leave the register pointing at applications the console can
// no longer show. Nothing else in the suite reads them: no other job uses these
// four identifiers, and no job in this suite counts what this service holds
// any more — the one that did, the mock's own `admin_api.js`, was EXCLUSIVE
// and left here on 2026-08-28. That is why this script is not in JOB_LOCKS
// despite writing to a
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
// (`admin.authRequired`), so this signs in the way a browser does — the walk
// in `console_signin.js`, shared with the WS-Trust chain because both jobs
// need it and a second copy is a second thing to forget when it changes. The
// reason it has to happen at all: `?format=svg` is refused rather than
// redirected to a sign-in screen a program cannot read. If the roster has been
// narrowed by some other
// job the drawings are SKIPPED with a message naming the gate; the assertions
// above do not depend on them, because they read `/admin-api/delegation`, which
// is not behind it.
//
// THAT IS THE SERVER-DRAWN CONSOLE. Since iya-sts #446 `/admin` is a static
// application drawing every page from `/admin-api`, and against it the job
// reads what it can reach there instead — the lineage drawing, and the graphs
// of the maps as JSON — and says which drawings it could not; see
// consoleIsStatic() and saveStaticDrawings().
// ---------------------------------------------------------------------------
const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require("selenium-webdriver/lib/select");
const chrome = require("selenium-webdriver/chrome");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const waitFor = require("./wait_for.js");
const common = require("./jwt_vc_json_common.js");
// THE MANAGEMENT API'S ACCESS TOKEN, FOR A RUN THAT DID NOT PRELOAD IT.
// run-report.js starts every job with `--require tools/attach-admin-token.js`;
// a hand run (`node oauth2_delegation_chain.js -u …` with STS_ADMIN_API_TOKEN
// exported) does not, and would then meet a 401 on its first /admin-api call
// naming no token. Requiring it here is a no-op after the preload — one file,
// one module cache entry — and a no-op with no token at all, which is the
// ungated service that file describes.
require("./tools/attach-admin-token.js");
// THE SHARED REGISTRY MODULE, FOR EVERYTHING BUT THE FOUR ENTRIES' CREATION.
// The four applications above are still created by this file's own code — the
// note at provisionApplication() says why, and the reason has not changed: the
// assertion that matters most here is an ABSENCE, and `provision()` checks
// containment. A DELEGATED PERMISSION has no such wrinkle, and neither do the
// attributes a product service needs added to those entries afterwards, nor
// the person with a password, nor the mode — so writing a second copy of
// `delegate()`, `provision()`, `ensurePerson()` or `isProduct()` here would be
// exactly the hand-written copy that module exists to stop.
const registry = require("./sts_applications.js");
const { loadUrl } = require("./page_load.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
// THE MOCK STS'S CONSENT SCREEN, which since 2026-09-01 stands between a
// signed-in person and an authorization response the first time a given
// username, client_id and scope meet. A SHARED MODULE for sts_applications.js's
// reason: every job here that signs somebody in meets the same hop, and a
// hand-written copy per job is a chance per job to write the wait wrong.
const consentScreen = require("./consent_screen.js");
const consoleSignin = require("./console_signin.js");
var log = bunyan.createLogger({ name: "oauth2_delegation_chain",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
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
// would be about them. A development service accepts any username and checks
// no password; a product one verifies the password below against the entry
// provisionPerson() writes.
// ---------------------------------------------------------------------------
const USER = process.env.DELEGATION_USER || "bob_end_user";

// THE PERSON'S PASSWORD, which only a PRODUCT service reads. Generated per
// process unless given, and deliberately not derivable from anything: the
// entry outlives the run on a kept deployment, and a password anybody could
// work out from this file would be an account anybody could sign in to. The
// fixed prefix and suffix are there for a password policy's character
// classes, the random middle is the secret.
const USER_PASSWORD = process.env.DELEGATION_USER_PASSWORD ||
    ("Chain-" + crypto.randomBytes(15).toString("base64url") + "-9a!");

// THE CLIENT SECRETS, ONE PER CONFIDENTIAL TIER, PRODUCT ONLY. Generated per
// process and written onto the entry by provisionForProduct() — `set`, so a
// second run against a kept service REPLACES the last run's secret rather
// than needing to know it. 48 random bytes, the size the service mints its
// own (oauth2.registeredSecretBytes), which is long enough for HS512.
const clientSecrets = {};

function clientSecretOf(identifier) {
  log.debug("Entering clientSecretOf(). " + identifier);
  if (!clientSecrets[identifier]) {
    clientSecrets[identifier] = crypto.randomBytes(48).toString("base64url");
  }
  log.debug("Leaving clientSecretOf().");
  return clientSecrets[identifier];
}
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
// WHAT AN ACCESS TOKEN FOR ANOTHER API CARRIES OF THAT BASE: NOTHING
// (iya-sts 2f9825f, 2026-09-13).
//
// Every token in this chain is addressed to the NEXT tier — the gateway, the
// ESB, the provider — and never to the mock's own resource server. Until that
// commit the mock appended its own resource beside the API so the same token
// could call UserInfo, and the token carried the whole base scope. RFC 9068
// section 2.2.3 says every scope on a JWT access token MUST have meaning for
// the resources in its `aud`, and `openid email profile offline_access` mean
// nothing to `apigw1`; the mock now takes Entra ID's answer and leaves them
// off. They are still GRANTED — the ID Token is minted and the refresh token
// keeps the whole scope — so the grant is not narrowed; it is carried where it
// means something. With nothing left, the token has no `scope` claim at all
// (section 2.2.3 again: granted nothing, no claim).
//
// So what the three tokens are held to is the ABSENCE of every base scope,
// which is the stronger statement: a token that still carried `openid` would
// be a regression to the ambiguous token that commit removed.
// ---------------------------------------------------------------------------
const OIDC_SCOPES_OFF_AN_API_TOKEN = BASE_SCOPE;

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
// and not a credential in development, which checks no password; where the
// console needs a role, console_signin.js gives the account a password of its
// own (see signInToTheConsole() below). Distinctive so that the directory
// entry and the audit row it leaves say which job made them.
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
// The management API — NOT behind the console's gate, which is what lets the
// assertions run whatever that gate is doing. It takes an access token of its
// own (iya-sts since 2026-09-09), and this file never handles one:
// tools/attach-admin-token.js, which run-report.js preloads, puts the run's
// STS_ADMIN_API_TOKEN on every call to `/admin-api`.
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
  await provisionDelegatedPermissions();
  // After the entries exist: appAllowedToDelegateTo names another
  // application, which has to be there to be named. Product needs the whole
  // configuration; development needs the delegation policy's half of it.
  if (await isProductMode()) {
    await provisionForProduct();
  } else {
    await provisionPolicy();
  }
  log.debug("Leaving provisionApplications(). " + entries.length + ".");
  return entries;
}

// ---------------------------------------------------------------------------
// AND THE THREE RELATIONSHIPS BETWEEN THEM, WHICH THE FOUR ENTRIES ABOVE DO
// NOT STATE.
//
// The entries say what each tier IS. They say nothing about who may reach
// whom — and that is the whole subject of this file, so leaving it to the
// service's permissiveness was leaving the interesting half unconfigured. Each
// resource now exposes an API (`read` and `write`, the suite-wide default) and
// each tier is GRANTED those permissions on the tier it forwards to:
//
//   webapp1 -> apigw1     https://apigw1.example.com/{read,write}
//   apigw1  -> esb1       https://esb1.example.com/{read,write}
//   esb1    -> sp1        https://sp1.example.com/{read,write}
//
// **IT CHANGES NOTHING ABOUT WHAT THIS TEST SENDS, AND THAT IS DELIBERATE.**
// The three hops still name the next tier's BARE client_id in `scope` and the
// two exchanges still send its URI in `audience`, exactly as the header at the
// top of this file describes, because that is the shape the deployment being
// copied has. A scope naming a client_id is the DEFAULT permission — the whole
// API, unnamed — and it is not going away. What the grants add is a register
// that agrees with the chain instead of one that has never heard of it, and
// the ability to turn `oauth2.delegatedPermissionsEnforced` on without
// re-provisioning anything.
//
// **THE BASE URI IS THE AUDIENCE EACH TIER ALREADY REGISTERED**, which is what
// keeps the two configurations from describing two different APIs: the second
// hop asks for `https://esb1.example.com`, so the permissions esb1 exposes
// have to hang off that and not off a URI invented for them. `delegate()`
// normalises it — a permission identifier is a plain concatenation, so the
// separator has to be there — and registers the normalised spelling as an
// audience beside the one already on the entry, so a token addressed to either
// resolves back to the application rather than to a URL.
//
// webapp1 exposes NOTHING, and that is the same assertion the entries make
// about its audience: a browser application is what a token is issued to and
// never what one is addressed to, so an API on it would be one nobody can
// reach. It appears here only as a client.
// ---------------------------------------------------------------------------
const DELEGATIONS = [
  { client: WEBAPP, resource: GATEWAY,
    why: "the browser application presents its token to the gateway" },
  { client: GATEWAY, resource: ESB,
    why: "the gateway forwards to the service bus" },
  { client: ESB, resource: PROVIDER,
    why: "the service bus forwards to the service at the far end" }
];

async function provisionDelegatedPermissions() {
  log.debug("Entering provisionDelegatedPermissions().");
  log.info("=== Granting the three delegated permission pairs ===");
  for (let i = 0; i < DELEGATIONS.length; i++) {
    const pair = DELEGATIONS[i];
    await registry.delegate(stsBase(), {
      client: pair.client,
      resource: pair.resource,
      // Read from the same table the hops read, so the API the permissions
      // hang off and the audience the exchange asks for cannot drift apart.
      baseUri: audienceOf(pair.resource),
      why: pair.why
    });
  }
  // WHO MAY ACT FOR WHOM, which is not the permission register above: iya-sts
  // asks its delegation policy (#186) about every RFC 8693 exchange. The two
  // exchanging tiers each hand the subject on to the next — the gateway to
  // the bus, the bus to the provider — and webapp1 exchanges nothing.
  await registry.allowHop(stsBase(), { actor: GATEWAY, target: ESB,
    why: "the gateway exchanges the sign-in's token for the bus" });
  await registry.allowHop(stsBase(), { actor: ESB, target: PROVIDER,
    why: "the bus exchanges that for the provider" });
  // WEBAPP1 EXPOSES NOTHING, asserted rather than assumed — `delegate()`
  // checks containment, and an application that acquired an API would pass
  // every check above while being the one arrangement this cast is built to
  // exclude. The same reasoning as the empty-audience assertion on its entry.
  const register = await registry.permissionsRegister(stsBase());
  const exposed = (register.permissions || []).filter(function (one) {
    return one.resource === WEBAPP;
  });
  assert.strictEqual(exposed.length, 0,
    WEBAPP + " is a browser application and should expose no API, and the " +
    "permission register says it exposes [" +
    exposed.map(function (one) { return one.id || one.name; }).join(", ") +
    "]. It is issued tokens and is never the audience of one, so a " +
    "permission on it is one no client could ever be granted for a reason " +
    "anybody would want.");
  log.info("[permissions] " + DELEGATIONS.length + " pair(s) granted, and " +
           WEBAPP + " exposes nothing.");
  log.debug("Leaving provisionDelegatedPermissions().");
}

// ---------------------------------------------------------------------------
// WHICH MODE THE SERVICE IS IN, ASKED OF THE SERVICE.
//
// `GET /admin-api/mode` answers `isProduct` for the realm the request is in —
// the default realm here — and it is the document the console's mode page is
// drawn from, so it is the service's own statement rather than a reading of
// one setting. A service from before that operation (404) is asked for
// `global.mode` through `GET /admin-api/config` instead, which is what
// sts_applications.js's isProduct() reads; anything else is a failure, because
// guessing the mode would run the wrong half of this file and report its
// refusals as the service's.
// ---------------------------------------------------------------------------
let productMode = null;

async function isProductMode() {
  log.debug("Entering isProductMode().");
  if (productMode !== null) {
    log.debug("Leaving isProductMode(). Cached: " + productMode);
    return productMode;
  }
  const url = stsBase() + "/admin-api/mode";
  const r = await common.httpJson(url, {
    headers: { Accept: "application/json" }
  });
  if (r.status === 404) {
    productMode = await registry.isProduct(stsBase());
    log.info("[mode] " + url + " is not there (an older service), so " +
             "global.mode was read instead: " +
             (productMode ? "product" : "development") + ".");
    log.debug("Leaving isProductMode(). From global.mode.");
    return productMode;
  }
  assert.ok(r.ok && r.body && typeof r.body.isProduct === "boolean",
    "GET " + url + " should answer 200 with `isProduct`, and answered " +
    r.status + ": " + String(r.raw).slice(0, 200) + ". A 401 is the " +
    "management API without its access token — STS_ADMIN_API_TOKEN, which " +
    "tools/attach-admin-token.js presents.");
  productMode = r.body.isProduct;
  log.info("[mode] the service says it is in " + r.body.mode + " mode" +
           (productMode ? ", so this run provisions what product refuses " +
            "without, and asserts what product answers." : "."));
  log.debug("Leaving isProductMode(). " + productMode);
  return productMode;
}

// The debugger's own origin: where every browser-direct call here comes FROM,
// and therefore what each application must list on `appCorsOrigin` before a
// product service answers it.
function debuggerOrigin() {
  log.debug("Entering debuggerOrigin().");
  const origin = new URL(baseUrl).origin;
  log.debug("Leaving debuggerOrigin(). " + origin);
  return origin;
}

// ---------------------------------------------------------------------------
// WHAT PRODUCT MODE NEEDS ON EACH ENTRY, AS ONE TABLE.
//
// Written as the attributes the service's own `editable` table names, so the
// shared provision() can reconcile them on an entry an earlier run left behind
// and then assert they are all there. The client SECRET is the one attribute
// not in it: it is a credential, which the registry does not hand back for a
// containment check to read, so it is written by itself (setClientSecret()).
//
// Each member below is a refusal the product service gave without it:
//   appCorsOrigin            the discovery fetch and every token call are made
//                            from the debugger's origin, and the allowlist is
//                            the only way one is answered;
//   oauthRedirectUri         exact matching against a REGISTERED address;
//   oauthTokenEndpointAuthMethod / oauthConfidential
//                            `none` alone makes webapp1 public (PKCE, no
//                            secret); the two secret methods make the middle
//                            tiers and sp1 confidential;
//   oauthGrantType           what each tier actually uses, and no more;
//   oauthAllowedScope        the scopes it may be issued (STS-OAUTH-0578);
//   appDelegationSemantics, appDefaultDelegationSemantics,
//   appAllowedToDelegateTo   the delegation policy's rules 7 and 10 for an
//                            impersonation.
// ---------------------------------------------------------------------------
const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const SECRET_METHODS = ["client_secret_basic", "client_secret_post"];

// The tier each middle tier forwards to, read off the same DELEGATIONS table
// the permission grants are made from, so the policy and the permissions
// cannot describe two different chains.
function forwardsTo(identifier) {
  log.debug("Entering forwardsTo(). " + identifier);
  const found = DELEGATIONS.filter(function (pair) {
    return pair.client === identifier;
  });
  log.debug("Leaving forwardsTo().");
  return found.length ? found[0].resource : "";
}

function productFieldsFor(identifier) {
  log.debug("Entering productFieldsFor(). " + identifier);
  const fields = {
    appCorsOrigin: [debuggerOrigin()],
    oauthAllowedScope: BASE_SCOPE.split(" ")
  };
  if (identifier === WEBAPP) {
    fields.oauthTokenEndpointAuthMethod = ["none"];
    fields.oauthRedirectUri = [baseUrl + "/callback"];
    fields.oauthGrantType = ["authorization_code", "refresh_token"];
    fields.oauthResponseType = ["code"];
    log.debug("Leaving productFieldsFor(). The public client.");
    return fields;
  }
  fields.oauthConfidential = "TRUE";
  fields.oauthTokenEndpointAuthMethod = SECRET_METHODS;
  if (forwardsTo(identifier)) {
    fields.oauthGrantType = [TOKEN_EXCHANGE_GRANT];
  }
  Object.assign(fields, policyFieldsFor(identifier));
  log.debug("Leaving productFieldsFor(). A confidential client.");
  return fields;
}

// ---------------------------------------------------------------------------
// THE DELEGATION POLICY'S HALF OF THAT TABLE, WHICH IS NOT PRODUCT'S ALONE.
//
// A service with the policy's SEMANTICS (iya-sts #186) chooses delegation or
// impersonation for an exchange that names neither, by the actor's default
// and then the realm's — and the realm's default is DELEGATION. So against
// such a service, in either mode, a middle tier with no default of its own is
// issued a token carrying `act: { sub: "apigw1" }`, and the act is filed as a
// delegation: a different scenario, which assertTokenDescribes() refuses by
// name. The scenario here is impersonation, so the tiers SAY so, in both
// modes; development then records the act as allowed rather than as "would
// have been refused", and product issues it at all.
//
// A service from before the semantics existed — the sts/ gitlink this suite
// pins, which impersonates whenever no actor token is sent — has none of
// these attributes, and its `editable` table says so; provisionPolicy() asks
// that table rather than a version, and writes nothing there.
// ---------------------------------------------------------------------------
function policyFieldsFor(identifier) {
  log.debug("Entering policyFieldsFor(). " + identifier);
  const next = identifier === WEBAPP ? "" : forwardsTo(identifier);
  if (!next) {
    log.debug("Leaving policyFieldsFor(). Not a middle tier.");
    return {};
  }
  log.debug("Leaving policyFieldsFor(). Impersonating towards " + next + ".");
  return {
    appDelegationSemantics: ["impersonation"],
    appDefaultDelegationSemantics: "impersonation",
    appAllowedToDelegateTo: [next]
  };
}

// Development's half: the policy fields alone, on a service that has them.
async function provisionPolicy() {
  log.debug("Entering provisionPolicy().");
  if (!(await registry.registryEditable(stsBase(),
                                        "appDefaultDelegationSemantics"))) {
    log.info("[policy] this service has no delegation semantics to " +
             "configure (it predates them), and impersonates whenever no " +
             "actor token is sent.");
    log.debug("Leaving provisionPolicy(). Nothing to write.");
    return;
  }
  for (let i = 0; i < APPLICATIONS.length; i++) {
    const identifier = APPLICATIONS[i].identifier;
    const fields = policyFieldsFor(identifier);
    if (!Object.keys(fields).length) {
      continue;
    }
    await registry.provision(stsBase(), {
      identifier: identifier,
      name: APPLICATIONS[i].name,
      protocols: DECLARED_PROTOCOLS,
      fields: fields,
      why: "the delegation policy's rules for " + identifier
    });
  }
  log.info("[policy] " + GATEWAY + " impersonates towards " +
           forwardsTo(GATEWAY) + ", and " + ESB + " towards " +
           forwardsTo(ESB) + ", by their own default.");
  log.debug("Leaving provisionPolicy().");
}

// The run's secret, written onto the entry. `set` rather than part of the
// create, so a second run against a kept service replaces the first run's
// secret instead of needing to know it.
async function setClientSecret(identifier) {
  log.debug("Entering setClientSecret(). " + identifier);
  const wrote = await registry.adminPost(stsBase(), "/applications/set", {
    application: identifier, attribute: "oauthClientSecret",
    value: clientSecretOf(identifier)
  });
  assert.ok(wrote && wrote.ok,
    "setting a client secret on " + identifier + " was refused: " +
    JSON.stringify(wrote).slice(0, 300) + ". Product mode refuses a " +
    "confidential client that presents none.");
  log.debug("Leaving setClientSecret().");
}

// THE AUTHENTICATION METHODS ARE MADE EXACTLY THESE, which is the one place
// containment is not enough. `none` may not be held beside another method —
// public and confidential are exclusive, and the registry refuses the mixture
// by name — and an entry created without a method is created PUBLIC: the four
// are created above with nothing but their identifiers and audiences, which
// is what development needs, and they come back holding `none`. So whatever
// the entry holds that this tier does not use is removed first, and only then
// does provision() add what it does use.
async function settleAuthMethods(identifier, wanted) {
  log.debug("Entering settleAuthMethods(). " + identifier);
  const entry = await registry.entryOf(stsBase(), identifier);
  const held = registry.valuesOf(entry && entry.fields &&
      entry.fields.oauthTokenEndpointAuthMethod);
  const extra = held.filter(function (one) {
    return wanted.indexOf(one) < 0;
  });
  for (let i = 0; i < extra.length; i++) {
    const removed = await registry.adminPost(stsBase(),
        "/applications/remove", {
          application: identifier,
          attribute: "oauthTokenEndpointAuthMethod",
          value: extra[i]
        });
    assert.ok(removed && removed.ok,
      "removing the authentication method " + extra[i] + " from " +
      identifier + " was refused: " + JSON.stringify(removed).slice(0, 300));
  }
  if (extra.length) {
    log.info("[registry] " + identifier + " held " + extra.join(", ") +
             ", which it does not authenticate with here; removed.");
  }
  log.debug("Leaving settleAuthMethods(). Removed " + extra.length + ".");
}

async function provisionForProduct() {
  log.debug("Entering provisionForProduct().");
  log.info("=== Product mode: the person, the clients' credentials and " +
           "the delegation policy ===");
  await registry.ensurePerson(stsBase(), USER, USER_PASSWORD);
  log.info("[directory] " + USER + " holds a password this run knows" +
           (process.env.DELEGATION_USER_PASSWORD ? " (DELEGATION_USER_" +
            "PASSWORD)." : " (generated; set DELEGATION_USER_PASSWORD to " +
            "choose it)."));
  for (let i = 0; i < APPLICATIONS.length; i++) {
    const identifier = APPLICATIONS[i].identifier;
    const fields = productFieldsFor(identifier);
    await settleAuthMethods(identifier, fields.oauthTokenEndpointAuthMethod);
    await registry.provision(stsBase(), {
      identifier: identifier,
      name: APPLICATIONS[i].name,
      protocols: DECLARED_PROTOCOLS,
      fields: fields,
      why: "product mode's configuration for " + identifier
    });
    if (identifier !== WEBAPP) {
      await setClientSecret(identifier);
    }
  }
  log.info("[policy] " + GATEWAY + " may impersonate towards " +
           forwardsTo(GATEWAY) + ", and " + ESB + " towards " +
           forwardsTo(ESB) + "; " + WEBAPP + " is public and signs in with " +
           "PKCE.");
  log.debug("Leaving provisionForProduct().");
}

// ---------------------------------------------------------------------------
// WHICH CONSOLE THIS SERVICE HAS, because there are two and they are read in
// different places.
//
// Until iya-sts #446 (2026-10-05) `/admin` was drawn on the SERVER: a page
// behind a sign-in, answering `?format=json` and `?format=svg`, which is what
// every console read below was written against. Since then it is a STATIC
// APPLICATION — every `/admin/*` path answers the same document, which loads
// `/admin/console.js`, signs in in the browser and draws each page from its
// `/admin-api` operation. Against that console the reads here would get the
// shell back with a 200, and console_signin.js reports a gate that does not
// redirect as one switched OFF — so the job would go on to fail saying the
// tokens page links nothing, which is a sentence about a page that no longer
// exists on the server.
//
// So the job asks which one it is talking to, by the one thing that tells
// them apart — the shell names its script — and reads the static console's
// data where the console itself reads it: the management API, whose `GET`
// operations each say which console page they mirror. Either kind of console
// may be in either mode; a development service pinned before #446 keeps the
// server-drawn reads exactly as they were.
// ---------------------------------------------------------------------------
let staticConsole = null;

async function consoleIsStatic() {
  log.debug("Entering consoleIsStatic().");
  if (staticConsole !== null) {
    log.debug("Leaving consoleIsStatic(). Cached: " + staticConsole);
    return staticConsole;
  }
  const url = stsBase() + "/admin/tokens";
  const r = await fetch(url, { redirect: "manual" });
  const text = await r.text();
  staticConsole = r.status === 200 && text.indexOf("/admin/console.js") >= 0;
  log.info("[console] " + (staticConsole ?
      "/admin is the static application (iya-sts #446): its pages are " +
      "read through the /admin-api operations they mirror." :
      "/admin is drawn on the server: its pages are read as they are."));
  log.debug("Leaving consoleIsStatic(). " + staticConsole);
  return staticConsole;
}

// One management API document, for the static console's reads. A refusal is
// a failure here rather than a skip: this API is not behind the console's
// gate or its roster, so the only thing that can refuse it is a missing
// access token, and that is the run's configuration, not another job's.
async function managementJson(urlPath, what) {
  log.debug("Entering managementJson(). " + urlPath);
  const url = stsBase() + urlPath;
  const r = await common.httpJson(url, {
    headers: { Accept: "application/json" }
  });
  assert.ok(r.ok && r.body && typeof r.body === "object",
    "GET " + url + " (" + what + ") should answer 200 with JSON and " +
    "answered " + r.status + ": " + String(r.raw).slice(0, 200));
  log.debug("Leaving managementJson().");
  return r.body;
}

// ---------------------------------------------------------------------------
// A browser sign-on session for the CONSOLE, which only the drawings and the
// lineage need. The walk itself is `console_signin.js` — five hops and two
// cookies since the mock made `/admin` a relying party of its own
// authorization server — and it is shared with `wstrust_delegation_chain.js`
// because both jobs read pages off that console and neither should carry a
// copy of somebody else's sign-in flow.
//
// Returns the Cookie header, or null when the gate is off (a legitimate state
// — the setting is switchable — reported rather than treated as a pass) or
// when the walk did not complete.
//
// WITH THE CONSOLE'S READ ROLE, WHERE THE CONSOLE NEEDS ONE (iya-sts #103).
// Product mode never opens the console to whoever signs in, and a development
// roster stops being open to anyone once somebody holds a role — and a
// signed-in person with no role is refused 403 on every page, so the maps and
// the lineage below were simply not drawn. `{ grant: "read" }` asks
// console_signin.js to grant it, and it does so ONLY where
// `GET /admin-api/rbac` says the console is not open to anyone: granting where
// it is would close that window for every other job in the pool. Reading is
// all this job does there.
// ---------------------------------------------------------------------------
async function signInToTheConsole() {
  log.debug("Entering signInToTheConsole().");
  const session = await consoleSignin.signInToTheConsole(stsBase(),
      CONSOLE_USER, log, { grant: "read" });
  log.debug("Leaving signInToTheConsole(). " +
      (session ? "Holding a session." : "No session."));
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
             "this session holds no console role — the read role " +
             "console_signin.js grants where the console is shut (iya-sts " +
             "#103) did not land, or the roster closed after it looked; its " +
             "[console] lines above say which. " + what + " was not saved.");
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

// ---------------------------------------------------------------------------
// THE DRAWINGS THE STATIC CONSOLE LEAVES WITHIN REACH.
//
// The server still draws every picture, but since iya-sts #446 the delegation
// map, the per-chain and per-application drawings are the CONSOLE's own
// operations (`/admin-api/console/…`), which take `admin:console` — a scope
// issued only to the console's own public client, signed in in a browser with
// a DPoP key. A job holding the management API's token cannot have one, so
// those SVGs are not saved here, and the log says so rather than leaving a
// report directory that is quietly missing them.
//
// What the management API does draw is the LINEAGE — `GET /admin-api/tokens/
// credential?format=svg` — which is the one picture holding every party of
// this chain, webapp1 included. It is saved and held to naming all five. And
// the GRAPHS the two missing maps are drawn from are saved as JSON beside it,
// because the picture can be redrawn from them and the facts cannot be
// recovered once the run is gone.
// ---------------------------------------------------------------------------
async function saveStaticDrawings(jti) {
  log.debug("Entering saveStaticDrawings().");
  const svg = await saveDrawing(null,
      "/admin-api/tokens/credential?id=" + encodeURIComponent(jti) +
      "&format=svg",
      "credential-lineage-" + PROVIDER + ".svg",
      "where the final token came from — every generation behind it");
  assert.ok(svg && svg.indexOf("<svg") >= 0,
    "the lineage drawing is not an SVG document: " +
    String(svg).slice(0, 200));
  // The markup removed, and removed-and-joined, for the reason the
  // server-drawn map's check gives: a label can be split across <tspan>s.
  const drawn = svg.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
  const joined = svg.replace(/<[^>]*>/g, "");
  [USER, WEBAPP, GATEWAY, ESB, PROVIDER].forEach(function (name) {
    assert.ok(drawn.indexOf(name) >= 0 || joined.indexOf(name) >= 0,
      "the lineage drawing does not mention \"" + name + "\", so the " +
      "picture is missing a box the graph says is in it. What it draws: " +
      drawn.slice(0, 400));
  });
  log.info("[drawing] the lineage names " + USER + ", " + WEBAPP + ", " +
           GATEWAY + ", " + ESB + " and " + PROVIDER + ".");
  await saveDrawing(null,
      "/admin-api/delegation?q=" + encodeURIComponent(USER) + "&per=200",
      "delegation-map-" + USER + ".json",
      "the graph the delegation map is drawn from");
  await saveDrawing(null,
      "/admin-api/delegation/application?application=" +
      encodeURIComponent(ESB),
      "delegation-application-" + ESB + ".json",
      "everything " + ESB + " is part of — the tier in the middle");
  log.warn("[drawing] the delegation map, chain and application SVGs are " +
           "the static console's own operations (/admin-api/console, " +
           "admin:console, iya-sts #446), which the management API's token " +
           "does not reach; their graphs were saved as JSON instead.");
  log.debug("Leaving saveStaticDrawings().");
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
             "is the console's own gate and its roster — this session holds " +
             "no console role, and the [console] lines above say why. " +
             what + " was not checked.");
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
//
// Under the static console the same document is `GET /admin-api/tokens/
// credential`, which the console's page is drawn from — so the assertions
// below are unchanged and only the address moves.
// ---------------------------------------------------------------------------
async function assertTheLineage(session, expected) {
  log.debug("Entering assertTheLineage().");
  log.info("=== The credential's ancestry, at /admin/tokens/credential ===");
  const id = encodeURIComponent(expected.jtis[0]);
  const lineage = (await consoleIsStatic()) ?
      await managementJson("/admin-api/tokens/credential?id=" + id,
                           "the final token's lineage") :
      await consoleJson(session,
          "/admin/tokens/credential?id=" + id + "&format=json",
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
//
// ONE ROW IS ONE ISSUANCE AND NOT ONE CREDENTIAL, which is what makes this two
// steps rather than one. The mock's tokens table groups the credentials that
// came back in a single reply — an access token, a refresh token and an ID
// Token are one row saying so — and a grouped row's identifier column names
// the SET, with the members and their own lineage links one click away on the
// set page. A token exchange here answers with two credentials, so this
// chain's final token is always in a grouped row: looking for its jti in the
// table alone finds nothing and says the console has stopped linking
// lineages, which is a sentence about a page that is working.
//
// It is also PAGED, at a hundred issuances by default and three hundred at
// most, over a register that has held every credential this whole suite
// issued. So the row is located through `?format=json` — the same document the
// table is rendered from, published beside it for exactly this — and the
// MARKUP is what is then asserted.
async function assertTheTokensPageLinksIt(session, jti) {
  log.debug("Entering assertTheTokensPageLinksIt().");
  const url = stsBase() + "/admin/tokens?per=300";
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

  // Straight into the table when the issuance produced one credential.
  if (html.indexOf("id=" + jti) >= 0) {
    log.info("[console] the tokens page links " + jti + " to its lineage.");
    log.debug("Leaving assertTheTokensPageLinksIt(). Ungrouped.");
    return;
  }

  const view = await consoleJson(session, "/admin/tokens?per=300&format=json",
      "the tokens table's own document, to find the row this token is in");
  if (!view) {
    log.debug("Leaving assertTheTokensPageLinksIt(). The console refused.");
    return;
  }
  const set = (view.sets || []).filter(function (one) {
    return (one.members || []).some(function (member) {
      return member.jti === jti;
    });
  })[0];
  assert.ok(set,
    "the token this test just obtained (" + jti + ") is in no row of the " +
    "tokens table's first page, which holds " + (view.sets || []).length +
    " of " + view.matched + " issuance(s). Newest is first there, so a token " +
    "minted seconds ago being off it is the register having stopped " +
    "recording rather than the page being long.");
  const setKey = set.setKey || ("set:" + set.setId);
  assert.ok(html.indexOf(encodeURIComponent(setKey)) >= 0,
    "the tokens page does not carry the issuance this test's token came " +
    "back in (" + setKey + "). A grouped row's identifier column is the " +
    "link to it.");

  const setUrl = stsBase() + "/admin/tokens/set?id=" +
      encodeURIComponent(setKey);
  const onSet = await common.httpJson(setUrl,
      session ? { headers: { Cookie: session } } : undefined);
  assert.strictEqual(onSet.status, 200,
    "GET " + setUrl + " should answer 200 and answered " + onSet.status + ".");
  assert.ok(String(onSet.raw).indexOf("id=" + jti) >= 0,
    "the set page for the issuance this test's token came back in does not " +
    "link that token (" + jti + ") to its lineage. That page is where a " +
    "grouped row's members and their identifiers live, so the link is " +
    "either there or nowhere.");
  log.info("[console] the tokens page links the issuance " + setKey +
           ", and that page links " + jti + " to its lineage.");
  log.debug("Leaving assertTheTokensPageLinksIt(). Through the set.");
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
// THE SAME TWO CHECKS AGAINST THE STATIC CONSOLE, where the markup they read
// is drawn in the BROWSER from `/admin-api` and no longer exists on the
// server to be read.
//
// What each check was FOR is still asked, of the document the page is drawn
// from:
//
//   * the tokens table holds this token — the issuance it came back in is a
//     row of `GET /admin-api/tokens`, and opening that row
//     (`GET /admin-api/tokens/set`) lists the token itself, which is what the
//     page then links to its lineage;
//   * the choosers are a SEARCH — `appq` and `userq` narrow the
//     `applicationChooser` and `userChooser` the delegation register answers
//     with, a term nothing matches answers none, and neither pane holds more
//     than twenty.
//
// What is NOT asked is the regression guard about the `<select>`: that is a
// claim about markup, and the markup is the static application's now, which
// iya-sts's own console tests hold. Said in the log rather than passed in
// silence.
// ---------------------------------------------------------------------------
async function assertTheTokensListHoldsIt(jti) {
  log.debug("Entering assertTheTokensListHoldsIt().");
  const view = await managementJson("/admin-api/tokens?per=300",
      "the tokens table's own document, to find the row this token is in");
  const set = (view.sets || []).filter(function (one) {
    return (one.members || []).some(function (member) {
      return member.jti === jti;
    });
  })[0];
  assert.ok(set,
    "the token this test just obtained (" + jti + ") is in no row of the " +
    "tokens table's first page, which holds " + (view.sets || []).length +
    " of " + view.matched + " issuance(s). Newest is first there, so a token " +
    "minted seconds ago being off it is the register having stopped " +
    "recording rather than the page being long.");
  const setKey = set.setKey || ("set:" + set.setId);
  const opened = await managementJson("/admin-api/tokens/set?id=" +
      encodeURIComponent(setKey), "the issuance this token came back in");
  const members = JSON.stringify(opened);
  assert.ok(opened.found !== false && members.indexOf(jti) >= 0,
    "opening the issuance " + setKey + " does not list the token this test " +
    "obtained (" + jti + "), so the console's row for it would link to a " +
    "set without it: " + members.slice(0, 300));
  log.info("[console] the tokens table holds the issuance " + setKey +
           ", and opening it lists " + jti + ".");
  log.debug("Leaving assertTheTokensListHoldsIt().");
}

// The labels one chooser drew, read off the delegation register's answer.
function chooserLabels(chooser) {
  log.debug("Entering chooserLabels().");
  const labels = ((chooser && chooser.entries) || []).map(function (one) {
    return String(one.label || one.key || "");
  });
  log.debug("Leaving chooserLabels(). " + labels.length + ".");
  return labels;
}

async function assertTheChoosersSearchApi() {
  log.debug("Entering assertTheChoosersSearchApi().");
  const searched = await managementJson("/admin-api/delegation?per=1&appq=" +
      encodeURIComponent(GATEWAY), "the application chooser, searched");
  const hits = chooserLabels(searched.applicationChooser);
  assert.ok(hits.indexOf(GATEWAY) >= 0,
    "searching the application chooser for \"" + GATEWAY + "\" does not " +
    "find it. The pane holds: " + JSON.stringify(hits) + ".");
  assert.ok(hits.indexOf(ESB) < 0 && hits.indexOf(PROVIDER) < 0,
    "searching for \"" + GATEWAY + "\" also found " + ESB + " or " +
    PROVIDER + ", so the term is being ignored. The pane holds: " +
    JSON.stringify(hits) + ".");
  assert.ok(hits.length <= 20,
    "the application pane holds " + hits.length + " results against a cap " +
    "of 20.");
  const none = await managementJson("/admin-api/delegation?per=1&appq=" +
      encodeURIComponent("zzz-no-such-application-zzz"),
      "the application chooser, searched for nothing");
  const empty = chooserLabels(none.applicationChooser);
  assert.strictEqual(empty.length, 0,
    "a search for a name nothing can match found " + empty.length +
    " result(s): " + JSON.stringify(empty) + ". A search that answers with " +
    "the whole list is a decoration.");
  const person = await managementJson("/admin-api/delegation?per=1&userq=" +
      encodeURIComponent(USER), "the person chooser, searched");
  const people = chooserLabels(person.userChooser);
  assert.ok(people.some(function (one) {
    return one.indexOf(USER) >= 0;
  }),
    "searching the person chooser for \"" + USER + "\" does not find them, " +
    "and this job signed them in. The pane holds: " + JSON.stringify(people) +
    ".");
  assert.ok(people.length <= 20,
    "the person pane holds " + people.length + " results against a cap of " +
    "20.");
  log.info("[console] the choosers search: \"" + GATEWAY + "\" finds " +
           hits.length + " application(s) and neither " + ESB + " nor " +
           PROVIDER + ", nothing finds none, and \"" + USER + "\" finds " +
           people.length + " person(s). Whether the page still draws a " +
           "<select> is the static console's markup and is not read here.");
  log.debug("Leaving assertTheChoosersSearchApi().");
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
  await loadUrl(driver, baseUrl + "/oauth2_oidc_1.html");
  await waitFor.waitForPageBundle(driver,
      "oauth2_oidc_1.html's bundle (before clearing the workflow)");
  // Cleared from the page rather than by deleting cookies: this is
  // localStorage, it is per-origin, and the debugger keeps every field of the
  // workflow in it.
  await driver.executeScript("window.localStorage.clear();");
  await loadUrl(driver, baseUrl + "/oauth2_oidc_1.html");
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

// The service's sign-in screen, which reuses Keycloak's field ids. The
// username typed here is the identity every token then describes. A
// development service checks no password, so the username goes in that field
// as it always did; a product one verifies `password` against the entry
// provisionForProduct() wrote.
async function signIn(driver, user, password) {
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
    await passwordFields[0].sendKeys(password || user);
  }
  await driver.findElement(By.id("kc-login")).click();
  // AND THE CONSENT SCREEN, if there is one. It is PASSED rather than asserted:
  // a scope already agreed to in this run, or one carried as a global consent
  // on the application's entry, draws no screen at all. What asserts the screen
  // itself is the mock repository's own tests/vendored/sts_consent.js.
  await consentScreen.passInBrowser(driver, By);
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
  // 9700 wants one from every client anyway. A product service REQUIRES it of
  // a public client; a development one does not outside its compliant realm,
  // which is exactly why it is asked for explicitly rather than left to a
  // default.
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
    "code_challenge, so the radio did not take. A development service does " +
    "not require PKCE outside its compliant realm, so nothing downstream " +
    "would fail there; a product one refuses the request. It reads: " +
    preview);
  log.info("[" + clientId + "] the authorization request carries " +
           "client_id=" + clientId + ", response_type=code, a PKCE " +
           "challenge and every requested scope.");

  await driver.findElement(
      By.css("input[type=\"submit\"][value=\"Authorize\"]")).click();
  await signIn(driver, USER, (await isProductMode()) ? USER_PASSWORD : null);

  // WHERE THE BROWSER STOPPED, when it never comes back. A product service
  // refuses on a page of its own — a wrong password on the sign-in screen, an
  // unregistered redirect URI or an undeclared scope on an error page — and a
  // bare "waiting for URL" timeout names none of them, so the address and the
  // words on the page go into the failure.
  try {
    await driver.wait(until.urlContains("/oauth2_oidc_2.html"),
                      waitTime * 5);
  } catch (e) {
    const stoppedAt = await driver.getCurrentUrl();
    const said = await driver.executeScript(
        "return document.body ? document.body.innerText : '';");
    log.debug("Leaving authenticateTheUser(). Never came back.");
    throw new Error("the sign-in for " + clientId + " never came back to " +
                    "oauth2_oidc_2.html (" + e.message + "). The browser is " +
                    "at " + stoppedAt + ", which says: " +
                    String(said || "").replace(/\s+/g, " ").slice(0, 600));
  }
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
  await loadUrl(driver, baseUrl + "/oauth2_oidc_2.html");
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
  // The tier's secret in product, where the token-exchange grant belongs to a
  // confidential client; none in development, which never asked for one and
  // still does not. The pane then authenticates with HTTP Basic, its default.
  await set("tokenexchange_client_secret", hop.clientSecret || "");
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
  // THE CLIENT, and in product its CREDENTIAL. The pane names the client in
  // the body, or in an HTTP Basic credential when its header style is chosen
  // and a secret is set, and draws the secret elided either way; which style
  // it uses is the pane's choice and not this test's subject, so either
  // spelling counts. What is held per mode is whether a secret goes at all:
  // product's token-exchange grant is a confidential client's, and a secret
  // that silently went missing should fail HERE and not as a 401 from the
  // token endpoint; development sent none and still sends none.
  const basic = "Authorization: Basic base64(" + hop.clientId +
      ":<client_secret>)";
  assert.ok(request.indexOf("client_id=" + hop.clientId) >= 0 ||
            request.indexOf(basic) >= 0,
    "the exchange is about to be made as somebody else — it should name " +
    hop.clientId + ". It reads: " + request);
  const sendsSecret = request.indexOf("client_secret=<client_secret>") >= 0 ||
      request.indexOf(basic) >= 0;
  assert.strictEqual(sendsSecret, !!hop.clientSecret,
    hop.clientSecret ?
      "the exchange as " + hop.clientId + " carries no client secret, and " +
      "the token-exchange grant is a confidential client's in product. It " +
      "reads: " + request :
      "the exchange as " + hop.clientId + " carries a client secret nobody " +
      "set in this workflow. It reads: " + request);
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
// this chain produced BOTH shapes until iya-sts 2f9825f (2026-09-13): the
// sign-in's token was addressed to the gateway AND to this service's own
// /resource, for UserInfo, while each exchange names one URI and gets a
// string. It is one audience everywhere now, and every reader still goes
// through this rather than comparing a claim that may be a list — a
// `claims.aud === x` is a check that silently stops passing the day a second
// audience comes back.
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
  String(expect.scope || "").split(" ").filter(Boolean).forEach(function (one) {
    assert.ok(scopes.indexOf(one) >= 0,
      expect.what + " does not carry the scope \"" + one + "\". It carries: " +
      JSON.stringify(claims.scope) + ".");
  });
  // What must be ABSENT from the claim, which since iya-sts 2f9825f is the
  // half of this that says the most — see OIDC_SCOPES_OFF_AN_API_TOKEN.
  String(expect.withoutScope || "").split(" ").filter(Boolean)
    .forEach(function (one) {
      assert.ok(scopes.indexOf(one) < 0,
        expect.what + " carries the scope \"" + one + "\" (scope=" +
        JSON.stringify(claims.scope) + ", aud=" + JSON.stringify(claims.aud) +
        "). It is addressed to another resource server, and RFC 9068 " +
        "section 2.2.3 says every scope on it must mean something THERE — " +
        "the mock leaves OpenID Connect scopes off such a token and keeps " +
        "them on the ID Token and the refresh token instead.");
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
//
// The caller is the far end, sp1 — the resource server a token for it would
// be presented to. A development service lets it name itself; a product one
// AUTHENTICATES every introspection request (401 invalid_client otherwise),
// so there it presents the secret provisionForProduct() gave it, as HTTP
// Basic.
// ---------------------------------------------------------------------------
async function introspect(token, clientId) {
  log.debug("Entering introspect().");
  const url = stsBase() + "/oauth2/introspect";
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  let body = "token=" + encodeURIComponent(token) +
      "&token_type_hint=access_token";
  if (await isProductMode()) {
    headers.Authorization = "Basic " + Buffer.from(
        encodeURIComponent(clientId) + ":" +
        encodeURIComponent(clientSecretOf(clientId))).toString("base64");
  } else {
    body += "&client_id=" + encodeURIComponent(clientId);
  }
  const r = await common.httpJson(url, {
    method: "POST",
    headers: headers,
    body: body,
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

// `expect` carries what only one mode can be held to: { product, subjectJti }.
function assertActRecords(act, hop, claims, expect) {
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
  // WHAT DECIDED IT, which is the one part of the row the MODE changes. A
  // development service asks the delegation policy, issues regardless and
  // writes what would have refused it; a product one ENFORCES it, so an act
  // that was issued there is an act the policy ALLOWED, and the row says so
  // by name — the actor, the subject and the application it reached. That is
  // the product answer, asserted as such: provisionForProduct() configured
  // exactly this permission and no wider one, and a row allowing it for any
  // other reason would be a policy this test did not write.
  if (expect && expect.product) {
    assert.strictEqual(act.policed, true,
      "a product service ENFORCES the delegation policy on a token exchange, " +
      "and this act says it was not policed.");
    const allowed = "the issuance policy allowed impersonation by \"" +
        hop.clientId + "\" for \"" + USER + "\" to \"" + hop.target + "\"";
    assert.ok(String(act.authorizedBy || "").indexOf(allowed) === 0,
      "the act should say the policy allowed this impersonation — \"" +
      allowed + " …\" — and says: \"" + act.authorizedBy + "\". A row " +
      "saying \"WOULD HAVE BEEN REFUSED\" is the development reading, and " +
      "one naming other parties is a policy this test did not provision.");
    assert.strictEqual(act.reason, "",
      "an issued act carries a refusal reason: \"" + act.reason + "\".");
    // AND WHAT IT CONSUMED, which in product is a token this service signed
    // and VERIFIED — the previous hop's, by jti. That is the link the lineage
    // page walks, asserted at its source.
    const consumed = (act.consumed || []).filter(function (one) {
      return one.kind === "subject_token";
    });
    assert.ok(consumed.length === 1 &&
              consumed[0].identifier === expect.subjectJti,
      "the act should record consuming the subject token " +
      expect.subjectJti + " (the token this hop was handed), and records " +
      JSON.stringify(act.consumed) + ".");
    assert.ok(/verified/.test(String(consumed[0].note || "")),
      "a product service verifies the subject token before it exchanges " +
      "it, and the act's note on it is \"" + consumed[0].note + "\".");
  }
  log.info("[register] act " + act.seq + ": " + act.typeLabel + " — " +
           act.initial.presented + " -> " + act.intermediary.application +
           " -> " + act.target.application + ", producing " +
           produced[0].identifier +
           (expect && expect.product ? "; " + act.authorizedBy : ""));
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
  // THE MODE FIRST, before there is a browser to build: product changes how
  // the browser has to present itself (below). Asked here, outside the try
  // that quits the driver, because there is no driver yet to orphan — a
  // service that cannot say which mode it is in fails the job on the spot.
  let product = false;
  try {
    product = await isProductMode();
  } catch (e) {
    log.error("could not ask the service which mode it is in: " + e.message);
    log.debug("Leaving test(). No mode.");
    process.exit(1);
  }
  const options = new chrome.Options();
  if (headless) {
    // "=new", not bare --headless: the tests image pinned Chrome 121, where the
    // old headless implementation ignores
    // --unsafely-treat-insecure-origin-as-secure. See tests/browser_flags.js.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  // /tmp rather than the container's 64MB /dev/shm.
  options.addArguments("--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  // A product service refuses a person's first sign-in from a browser that
  // says it is headless (the risk of an automated client); see
  // addDesktopUserAgent(). Development scores it and refuses nothing.
  if (product) {
    browserFlags.addDesktopUserAgent(options);
  }
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
    // suite runs in a pool. The newest act's time, by the service's own
    // clock — see "Deltas, not totals" in the header for why not its seq.
    const before = await delegationJson("?per=1");
    const newest = (before.acts || [])[0];
    const baselineAt = newest ? Number(newest.at || 0) : 0;
    log.info("[register] " + before.held + " act(s) already held; this job's " +
             "acts are the ones recorded after " +
             (baselineAt ? new Date(baselineAt).toISOString() : "none") +
             ".");

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
      // NONE of it. The request named the gateway in the scope list, and this
      // issuer reads a scope naming an application as the audience — so the
      // name comes off the scope; and a token for the gateway carries no
      // OpenID Connect scope either. See OIDC_SCOPES_OFF_AN_API_TOKEN.
      withoutScope: OIDC_SCOPES_OFF_AN_API_TOKEN,
      // The scope value VERBATIM, which is what a derived audience is
      // addressed to. One audience: the mock no longer keeps its own
      // /resource beside it for UserInfo.
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
    //
    // THE EXCHANGE'S SCOPE DOES NOT NAME THE NEXT TIER (iya-sts 2f9825f,
    // 2026-09-13). The sign-in above names the gateway in its scope because
    // that is the only way it says which API it wants. An exchange says so
    // with `audience`, and naming the tier's client_id in the scope as well
    // is two names for one resource that the mock cannot prove are the same:
    // RFC 9068 section 2.2.3 has it refuse `audience=https://esb1.example.com`
    // beside `scope=... esb1` with invalid_scope (STS-OAUTH-0245), "this
    // request addresses X while its scope names Y". So each hop asks for the
    // base scope and lets `audience` carry the target — which is also the
    // spelling RFC 8693 section 2.1 gives that parameter the job of.
    //
    // `clientSecret` is product's: there the token-exchange grant is a
    // confidential client's, and each middle tier presents the secret
    // provisionForProduct() wrote. Empty in development, as it always was.
    const hops = [
      { clientId: GATEWAY, audience: audienceOf(ESB), target: ESB,
        scope: BASE_SCOPE, subjectToken: first.access_token,
        clientSecret: product ? clientSecretOf(GATEWAY) : "" },
      // subjectToken filled in below, from what hop 1 produced.
      { clientId: ESB, audience: audienceOf(PROVIDER), target: PROVIDER,
        scope: BASE_SCOPE, subjectToken: "",
        clientSecret: product ? clientSecretOf(ESB) : "" },
    ];

    await startNewWorkflow(driver, discovery, GATEWAY, WEBAPP);
    const second = await exchangeAs(driver, hops[0]);
    const secondClaims = assertTokenDescribes(second.access_token, {
      what: GATEWAY + "'s exchanged access token",
      // Trimmed the same way, even though this hop sent `audience` outright:
      // the parameter decides the `aud`, and the scope list loses the name
      // and the OpenID Connect scopes regardless. Both halves are asserted
      // below.
      withoutScope: OIDC_SCOPES_OFF_AN_API_TOKEN,
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
      withoutScope: OIDC_SCOPES_OFF_AN_API_TOKEN,
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
    // The issuer must agree with the token it signed about the base scopes
    // too: none of them on a token for the provider. Two exchanges still do
    // not narrow the GRANT — that lives on the refresh token, which this
    // chain does not present — so what is asserted is agreement, not loss.
    OIDC_SCOPES_OFF_AN_API_TOKEN.split(" ").forEach(function (one) {
      assert.ok(introspectedScopes.indexOf(one) < 0,
        "introspection reports the final token's scope as \"" +
        introspection.scope + "\", which carries \"" + one + "\" — but the " +
        "token is addressed to " + audienceOf(PROVIDER) + " and the signed " +
        "token leaves OpenID Connect scopes off. The token and the server " +
        "that signed it disagree.");
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
      return Number(row.at || 0) > baselineAt;
    });
    assert.ok(mine.length >= 2,
      "this job made two exchanges and the register holds " + mine.length +
      " act(s) recorded since it started. A delegation performed and not " +
      "recorded is one this service cannot account for.");
    const acts = hops.map(function (hop) {
      return findAct(mine, hop);
    });
    assertActRecords(acts[0], hops[0], secondClaims,
                     { product: product, subjectJti: firstClaims.jti });
    assertActRecords(acts[1], hops[1], thirdClaims,
                     { product: product, subjectJti: secondClaims.jti });
    // In ORDER, by time for the reason the baseline is: the two hops may be
    // answered by two workers, whose sequence numbers are not comparable.
    assert.ok(Number(acts[1].at) > Number(acts[0].at),
      "the register puts the second hop (seq " + acts[1].seq + ", at " +
      acts[1].at + ") before the first (seq " + acts[0].seq + ", at " +
      acts[0].at + ").");

    // The graph of what matched — this person's acts — which is what
    // /admin/delegation/map draws for the same filter.
    assertGraphIsAChain(after.graph || {}, hops);

    // --- where the final token came from -----------------------------------
    // On a server-drawn console that console is the only door to this one:
    // the lineage page has no form and therefore no operation on /admin-api
    // (the mock's rule 7), so the session is obtained here rather than with
    // the drawings below and both use it. The static console (iya-sts #446)
    // needs no session here at all — its pages are drawn from /admin-api,
    // and that is where they are read; see consoleIsStatic().
    const onStatic = await consoleIsStatic();
    const session = onStatic ? null : await signInToTheConsole();
    if (onStatic) {
      await assertTheTokensListHoldsIt(thirdClaims.jti);
      await assertTheChoosersSearchApi();
    } else {
      await assertTheTokensPageLinksIt(session, thirdClaims.jti);
      // The two pivots on the delegation page, which are a SEARCH rather
      // than a list since 2026-08-26. Here rather than beside the drawings
      // because it needs the same session and no picture: it reads the
      // page's markup.
      await assertTheChoosersSearch(session);
    }
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
    // The static console's are fewer, and saveStaticDrawings() says which and
    // why. Every server-drawn drawing hangs off the map below, so on the
    // static console that one read is not made and the rest follow it.
    if (onStatic) {
      await saveStaticDrawings(thirdClaims.jti);
    }
    const filter = "?q=" + encodeURIComponent(USER);
    const svg = onStatic ? null : await saveDrawing(session,
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
