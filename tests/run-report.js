#!/usr/bin/env node
//
// run-report.js — lightweight test runner + report generator for the
// Selenium tests in this directory.
//
// Selenium WebDriver itself produces no reports; these test files are bare
// Node scripts that exit non-zero on failure. This runner executes each one
// (continuing past failures, unlike runTests() in common/common.sh which
// aborts on the first), captures exit code / output / timing, and writes a
// timestamped run directory tests/report/<timestamp>/ containing:
//
//   report.html        — human-readable report
//   report.xml         — JUnit XML (for CI dashboards)
//   logs/NN-<test>.log — full stdout+stderr per test (the <test> half
//                        is the job name slugged and TRUNCATED; NN is
//                        what makes it unique)
//
// Each test's stdout and stderr are streamed live to the console AND written
// to its log file as they are produced (a tee), so the complete output is
// captured even for long-running tests that print hundreds of lines.
//
// It reproduces the env-var wiring from runTests() so the existing test
// files run unchanged. Provide the same config vars in the environment
// (DEBUGGER_BASE_URL, CLIENT_CREDENTIALS_*, AUTHORIZATION_CODE_PUBLIC_*, etc.)
// that runTests() expects.
//
// Usage:
//   node tests/run-report.js          # run the suite, write reports
//   node tests/run-report.js --demo   # write a SAMPLE report (no tests run)
//
const { spawn, execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const bunyan = require("bunyan");

// The runner's own progress lines. They used to be console.log, which made this
// the last thing in this directory writing outside bunyan — every test it
// spawns already logs bunyan JSON, so the runner's plain lines were the odd
// ones out.
//
// Note what this changes and what it does not. These lines now come out as JSON
// like everything else, so pipe the run through `npx bunyan` for the old look.
// The REPORT is unaffected: report.html, report.xml and logs/NN-<test>.log are
// written with fs.writeFileSync and are what CI reads. And the live echo of
// each child's output further down stays process.stdout.write — it forwards
// another process's bytes as they arrive, in arbitrary chunks, so wrapping it
// would interleave JSON records with fragments of the child's own lines and
// make both unreadable.
//
// The level is guarded because this runner is started without CONFIG_FILE set
// (it sets one per job for the tests it spawns), so a bare require would throw.
const log = bunyan.createLogger({
  name: "run-report",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to info
      // loses only the configured verbosity.
      return "info";
    }
  })()
});

const TESTS_DIR = __dirname;
const REPORT_DIR = path.join(TESTS_DIR, "report");
// Each run gets its own timestamped subdirectory so history is preserved.
// Filesystem-safe ISO stamp, e.g. 2026-05-30T17-45-00
const RUN_ID = new Date().toISOString().replace(/:/g, "-").replace(/\..+$/, "");
const RUN_DIR = path.join(REPORT_DIR, RUN_ID);
const LOGS_DIR = path.join(RUN_DIR, "logs");
const BASE_URL = process.env.DEBUGGER_BASE_URL || "http://localhost:3000";
const env = process.env;

// ---------------------------------------------------------------------------
// Coverage (opt-in), the THIRD domain.
//
// COVERAGE.md describes two: the browser bundles (Istanbul, shipped by the page
// to the client server) and the api process (c8). Neither of them sees THIS
// container, and about thirty jobs here never touch a browser at all — they
// load the real client/src and api modules in-process through
// module_paths.requireSharedModule() and drive them against the RFCs' own
// vectors. Every branch those jobs cover was reported as UNCOVERED, because the
// only instrumented copy of the module was the one running in Chrome.
//
// The cost of that was not a low number; it was a low number that pointed the
// wrong way. On the 2026-08-23 report, 336 of the api's 474 own-code missing
// branches and roughly 2,935 of the frontend's 10,092 sat in modules that
// already had a node test — api/krb5_frame.js read 29.7% while
// api_krb5_relay.js asserts every one of its malformed-frame rejections by
// name. Anybody writing tests off that report would have written the ones that
// already existed.
//
// The mechanism is node's own: NODE_V8_COVERAGE names a directory, and the
// child writes raw V8 coverage into it as it exits. No wrapper binary in the
// spawn path, nothing for a test to opt into, and it applies to EVERY job
// rather than only the browserless ones — a page test that also loads a shared
// module in-process (pki_page.js does, with client/src/x509.js) contributes
// what it ran there too. c8 renders the pile at the end of the run, in this
// container, where the paths those files were loaded from still resolve.
// ---------------------------------------------------------------------------
const COVERAGE = String(process.env.COVERAGE || "") === "true";
const NODE_COVERAGE_DIR = process.env.NODE_COVERAGE_DIR || "/coverage/node";
const NODE_COVERAGE_TMP = path.join(NODE_COVERAGE_DIR, "tmp");
// Flipped off by prepareNodeCoverage() when the directory cannot be made — a
// COVERAGE=true run with no ./coverage mounted, say. Collecting coverage is
// never worth failing a test run over, so that case degrades to an ordinary
// run with a warning rather than to a suite that dies before the first job.
let nodeCoverageOn = COVERAGE;

// How long the run actually took, which stopped being the sum of the job times
// the day the jobs started overlapping. Set by main() before the reports are
// written; 0 on a --demo run, where the report says so itself.
let runWallMs = 0;

// ---------------------------------------------------------------------------
// unit or browser.
//
// Reported, not scheduled: a unit job is spawned, timed, logged and counted
// exactly as it was before this existed. The label is there so the report says
// which half of the suite a failure came from, and so `classname` in the JUnit
// XML separates the two for a CI dashboard.
//
// It is DERIVED rather than listed. A hand-kept list of browserless scripts is
// a list that goes stale on the next test added, silently and in the direction
// that mislabels rather than fails — so the classification asks the only
// question that decides it: does the script require selenium-webdriver? An
// unreadable script is called a browser job, because that is the label that
// costs nothing if it is wrong.
// ---------------------------------------------------------------------------
const SELENIUM_REQUIRE = /require\(\s*["']selenium-webdriver/;

function jobTypeOf(script) {
  log.debug("Entering jobTypeOf(). script=" + script);
  let source;
  try {
    source = fs.readFileSync(path.join(TESTS_DIR, script), "utf8");
  } catch (e) {
    // Not readable from here (a script this image did not COPY, say). The job
    // will fail to spawn and say so; the label is not the interesting part.
    log.debug("Leaving jobTypeOf(). Unreadable, calling it browser.");
    return "browser";
  }
  const type = SELENIUM_REQUIRE.test(source) ? "browser" : "unit";
  log.debug("Leaving jobTypeOf(). " + type);
  return type;
}


// ---------------------------------------------------------------------------
// HOW MANY JOBS RUN AT ONCE, and what stops two of them colliding.
//
// These jobs are independent processes: each spawns its own browser, writes its
// own log, returns its own result, and nothing in buildJobs() declares an order
// between any two of them. The loop that ran them was sequential all the same,
// and the price was the whole suite's wall clock — on the 2026-08-23 run, 196
// jobs and 20.6 minutes, of which the MEDIAN job is 3.2 seconds and the ten
// longest are 54% of the total. A pool is most of that time back.
//
// Size is TEST_CONCURRENCY, and it defaults to one less than this machine's
// cores, held between 2 and 4. The cap is not politeness: the longest jobs here
// are CPU-bound in-browser crypto (SLH-DSA and RSA on the Digital Signature
// page) rather than waiting on a network, a GitHub Actions runner has 2 to 4
// cores, and on the containerized stack every OTHER service — Keycloak,
// Postgres, two mock STS instances, two walt.id containers, the WS-Fed
// side-car — is on that same machine. The floor is 2 rather than 1 so that a
// two-core runner still overlaps the waiting, which is what most of a browser
// job is.
//
// TEST_CONCURRENCY=1 restores the old behaviour EXACTLY, live streamed output
// included. That is the first thing to try when a job fails here and passes on
// its own. Note what changes above 1: a child's output is buffered and written
// as one block when it finishes, because interleaving the lines of four
// browsers makes all four unreadable. The per-job LOG FILE is still written as
// the bytes arrive, so `tail -f report/latest/logs/NN-*.log` follows a running
// job either way.
//
// WHAT MUST NOT OVERLAP is declared below in one table rather than at the ~200
// call sites, because it is a property of the SERVICE a script drives and not
// of the script. The mock STS keeps its /admin configuration in memory and it
// SURVIVES BETWEEN JOBS — that is the hazard the sequential loop hid, and it
// surfaces as somebody else's assertion failing about a claim set, not as a
// collision.
//
//   * A lock name means "no two of these run at the same time". `sts-vc` is the
//     mock's credential and verifier configuration (/admin/vc and
//     /admin/vc-verifier-config: the claims a credential carries and the ones
//     the Verifier asks for, which sd_jwt_vc_presentation.js pins and the rest
//     of that family reads off the wire). `waltid` is the same argument for
//     walt.id's own issuer and verifier containers. `sts-rfc9700` is the mock's
//     RFC 9700 TRUST REALM, which rfc9700_flows.js reconfigures through
//     /realm/rfc9700/admin-api/config/set — the name is kept from when that was
//     a second mock INSTANCE, and what changed is that the state is a realm
//     override now, so this serialises those jobs against each other and no
//     longer against anything driving the permissive server. `sts-tls` is the
//     mock's client TRUSTSTORE, which pki_mutual_tls.js fills and empties on a
//     live process.
//   * EXCLUSIVE means the job runs alone, before the pool starts, instead of
//     draining it later. There are NONE at present, and the mechanism is kept
//     rather than deleted because the shape of job that needs it is a standing
//     one: a job that reads a TOTAL off the mock — a count of every artifact
//     the process is holding — or that changes something the process has only
//     one of, which a trust realm therefore cannot contain (the SPIFFE signing
//     authority; the console's roster in the default realm). Any other job
//     minting a token between such a job's two reads flips its answer, and the
//     failure names the other job. The four that used to be here —
//     admin_api.js, sts_admin_api_operations.js, sts_admin_console.js and
//     sts_metadata.js — drove the mock's own /admin and /admin-api surface
//     and were removed from this suite on 2026-08-28; they live in the mock
//     STS's own suite now (see the note in docs/mock-sts.md), which is the
//     tree that changes them.
//
//     A SECOND SHAPE NEEDED IT FOR ONE DAY, and the record is worth keeping
//     because the shape will recur. `sts_userinfo_protected.js` and
//     `sts_jws_verification.js` walk every algorithm the mock advertises,
//     SLH-DSA among them — and the mock was one process whose signing was
//     synchronous, so for the duration of one of those signatures it answered
//     NOBODY: not another HTTP caller, not the KDC on port 88. Stalls of 14.6,
//     15.4, 17.8 and 23.3 SECONDS were measured in the containerized run of
//     2026-08-29, and each failed some unrelated job in a way that named
//     anything but the cause — a Kerberos reply that never came, a Populate
//     button never drawn, a login screen that never arrived, a refresh whose
//     socket the mock closed on its way back. A named lock could not express
//     that: the set they collided with was the suite, so listing it would have
//     been listing the suite.
//
//     They were marked EXCLUSIVE as an interim measure and are NOT any more.
//     The cause was the mock blocking and the fix landed over there on
//     2026-08-30 (rcbj/mock-sts#6): a front process owning the sockets and the
//     state, with the signing handed to a pool of stateless children. Its
//     `workers.count` defaults to 2 and nothing here has to set it. **A JOB
//     THAT MAKES A SHARED SERVICE BLOCK IS STILL THIS TABLE'S PROBLEM** — that
//     is why this paragraph stays — but it is no longer these two jobs'
//     problem, and marking them alone now would cost the parallelism of two
//     jobs out of 281 for nothing.
//
// A script that is not in the table runs unlocked, which is the right default:
// nearly every test here mints an identity of its own (random_username.js, and
// the `stamp` prefixes in scim_page.js and ldap_page.js) and asserts on what it
// created rather than on a total. A NEW test that configures a shared service
// belongs in this table, and the symptom of forgetting is a failure in a job
// that has nothing to do with it.
// ---------------------------------------------------------------------------
const EXCLUSIVE = "*";
const JOB_LOCKS = {
  // The mock's credential + verifier configuration.
  "sd_jwt_vc_issuance.js": "sts-vc",
  "sd_jwt_vc_presentation.js": "sts-vc",
  "ldp_vc_issuance.js": "sts-vc",
  "ldp_vc_presentation.js": "sts-vc",
  "ldp_vc_refresh.js": "sts-vc",
  "jwt_vc_json_issuance.js": "sts-vc",
  "jwt_vc_json_presentation.js": "sts-vc",
  "vc_did.js": "sts-vc",
  "oid4vci_request_encryption.js": "sts-vc",
  "dpop_workflow.js": "sts-vc",
  "metadata_schema_validation.js": "sts-vc",
  // walt.id's issuer-api2 and verifier-api2.
  "sd_jwt_vc_waltid.js": "waltid",
  "sd_jwt_vc_presentation_waltid.js": "waltid",
  "jwt_vc_json_issuance_waltid.js": "waltid",
  "jwt_vc_json_presentation_waltid.js": "waltid",
  // The mock's RFC 9700 TRUST REALM — `.../realm/rfc9700` — which
  // rfc9700_flows.js reconfigures through POST
  // /realm/rfc9700/admin-api/config/set (oauth2.redirectUris, which an RFC 9700
  // server compares by exact string match and which therefore differs per run).
  //
  // It used to be a second mock INSTANCE, and the lock name is kept rather than
  // renamed because what it protects is the same state under a new address.
  // What CHANGED is worth knowing: that state is a realm override now, so it is
  // genuinely separate from the default realm's configuration — this lock
  // serialises these jobs against each other, and no longer against anything
  // driving the permissive server.
  "rfc9700_flows.js": "sts-rfc9700",
  "rfc9700_client.js": "sts-rfc9700",
  // The mock's TLS client truststore, which is process state over there.
  "pki_mutual_tls.js": "sts-tls",
  "api_tls_probe.js": "sts-tls",
  // The mock's SPIFFE configuration and registry. `spiffe_protocol.js` sets
  // `spiffe.adminIds` (the only route from "I can fetch an identity" to "I can
  // drive the registry" that does not already require an administrator),
  // shortens `spiffe.svidTtl` to watch a rotation, and turns
  // `spiffe.autoCreateEntries` off — deleting the invented entry — to run a
  // client's "I have no identity" path. Each is restored per setting, but not
  // instantly, so nothing else may be reading that trust domain meanwhile:
  // a job fetching an SVID inside that window gets an EMPTY LIST, which reads
  // as a Workload API that stopped issuing.
  "spiffe_protocol.js": "sts-spiffe",
  "spiffe_page.js": "sts-spiffe",
  "api_spiffe.js": "sts-spiffe",
  // The mock's SAML 1.1 identity provider settings. `sts_saml11.js` turns
  // `saml11.signAssertion` and `saml11.signResponse` OFF one at a time to check
  // that an unsigned document is recognised as one, flips `defaultProfile` to
  // artifact, and turns `autocreateApplications` off so a relying party nobody
  // registered is refused. Every one of those is restored, and none of them
  // instantly — so a browser round trip running inside that window gets an
  // UNSIGNED assertion, or a profile it did not ask for, or a 400 for a relying
  // party it just named. `saml11_sso.js` asserts a valid signature and the
  // confirmation method for its binding, so it would fail naming the signature
  // or the profile and nothing would say which other job did it.
  //
  // The three binding jobs therefore serialise against each other as well,
  // which is the cost of a single-name lock and is worth it here: the
  // alternative is a flake that appears only in the pool and passes on its own.
  // `saml11_options.js` is deliberately absent — it needs no identity provider
  // at all, so nothing it does can collide with this.
  "sts_saml11.js": "sts-saml11",
  // SAML 2.0 ENCRYPTION SHARES THE SAML 2.0 LOCK, and it has to: it turns
  // `saml2.encryptAssertion` and the two algorithm rows on for service
  // providers of its own, and it flips `saml2EncryptLogoutNameId` — but it
  // also drives /saml2/slo, which ENDS WHATEVER SESSION the cookie jar it
  // shares with a concurrent binding job is holding. A saml_sso.js round trip
  // running inside that window loses its session mid-flow and fails naming the
  // sign-in screen, with nothing to say which other job did it.
  "sts_saml_encryption.js": "saml2",
  "saml11_sso.js": "sts-saml11",
  // The mock's SPNEGO SIGN-IN, which is `krb5.spnegoAuthentication` — a
  // process-wide setting on a shared service. `kerberos_spnego_signin.js` turns
  // it OFF to assert that a closed door answers 403 naming the setting and
  // signs nobody in, then resets it; inside that window every other Kerberos
  // job that reaches `/authn/spnego` would be refused and would report it as
  // its own failure.
  //
  // It also holds the KDC's REPLAY CACHE against a second sign-in, which is
  // why the lock covers the two page jobs rather than only this one: each of
  // them spends an AP-REQ, and this file's replay negative asserts that a
  // second one is refused. Two jobs presenting tickets for the same SPN in the
  // same window cannot make that assertion mean anything.
  //
  // `kerberos_as_page.js` is deliberately absent: an AS exchange spends no
  // service ticket and never touches the sign-in door, so nothing it does can
  // collide with this.
  "kerberos_spnego_signin.js": "sts-spnego-signin",
  "kerberos_spnego_page.js": "sts-spnego-signin",
  "kerberos_tgs_ap_page.js": "sts-spnego-signin",
  // And the MIT-client job, for both of the same reasons: it turns
  // `krb5.spnegoAuthentication` off to assert the closed door, and it asserts
  // that a REPLAYED AP-REQ is refused — which a concurrent job spending its
  // own tickets against the same acceptor would disturb.
  "krb5_mit_client.js": "sts-spnego-signin",
  // The mock's SSF configuration. `ssf_protocol.js` turns
  // `ssf.pushAllowInsecure` ON (its own RFC 8935 listener is plain http) and
  // flips both deliberate defects — `ssf.legacySubClaim` and
  // `ssf.breakSetSignature` — one at a time. Each is restored, and not
  // instantly: a job polling that transmitter inside that window gets a SET
  // whose signature does not verify, which `ssf_page.js` would report as its
  // own failure with nothing to say which other job did it.
  //
  // It also DELETES the streams it made, and a stream is named by an id the
  // other job does not know — so what actually collides is the settings and
  // the transmitter's queue rather than the streams themselves.
  "ssf_protocol.js": "sts-ssf",
  "ssf_page.js": "sts-ssf",
  // `ssf_engine.js` is deliberately absent: it needs no transmitter at all,
  // so nothing it does can collide with this. `api_ssf.js` is absent for a
  // different reason — it drives the api's own receiver and never touches
  // the mock.
};

const CONCURRENCY = (function () {
  const asked = parseInt(process.env.TEST_CONCURRENCY || "", 10);
  if (Number.isFinite(asked) && asked > 0) {
    return asked;
  }
  const cores = (os.cpus() || []).length || 1;
  return Math.max(2, Math.min(4, cores - 1));
})();

// The lock a job holds while it runs, or null. A job may name its own (`lock`
// on the descriptor) for a case the table cannot see; otherwise it is the
// script's.
function lockOf(job) {
  log.debug("Entering lockOf().");
  const lock = job.lock || JOB_LOCKS[job.script] || null;
  log.debug("Leaving lockOf(). " + (lock || "none"));
  return lock;
}

// Mirror of the *active* (non-commented) test invocations in
// common/common.sh runTests(). Each job maps the suite's config vars onto the
// generic names (AUDIENCE, CLIENT_ID, ...) each test script reads.
function buildJobs() {
  log.debug("Entering buildJobs().");
  const jobs = [];

  // Basic navigation: landing page -> OAuth2/OIDC debugger -> Home -> SAML ->
  // Home.
  jobs.push({
    name: "Navigation (landing page → OAuth2/OIDC → Home → SAML → Home)",
    script: "navigation.js",
    env: {},
  });

  // What the STATIC deployments leave out (client/static_site.js). Kerberos is
  // DER over port 88, so every page of it goes through the api's relay and
  // idptools.com has no api: the static build drops those pages and greys their
  // landing card. Every part of that fails silently when it drifts — an
  // exclusion naming a renamed file removes nothing, a card that stops matching
  // its marker stays a live link to a page the build just deleted, and a
  // surviving page linking to a dropped one is a 404 no test clicks. This is
  // also the only check that the exclusion has NOT escaped into
  // client/Dockerfile, which must still build all five for the container.
  // Node only — no browser, no services — so it never skips.
  jobs.push({
    name: "Static deployment exclusions (the dropped pages, the greyed " +
        "landing card, no dead links)",
    script: "static_site_exclusions.js",
    env: {},
  });

  // What crosses `sudo` on the way to compose. docker_compose() in
  // common/common.sh runs compose under sudo, which empties the environment,
  // so a variable a compose file reads reaches it only if
  // COMPOSE_FORWARDED_VARS names it. Every failure of that is silent:
  // `${NAME:-}` substitutes to the empty string with no warning and a bare
  // `- NAME` passes nothing, so a setting the launchers document is simply
  // ignored and the run reports success. That is what TEST_CONCURRENCY did
  // on the containerized stack for as long as its passthrough existed — the
  // pool sized itself from the container's cores no matter what was asked
  // for, and the wall clock was the only evidence. Node only — no browser,
  // no services — so it never skips.
  jobs.push({
    name: "Compose environment forwarding (what survives sudo: " +
        "TEST_CONCURRENCY, TEST_JOB_TIMEOUT_MS, STS_LOG_LEVEL)",
    script: "compose_env_forwarding.js",
    env: {},
  });

  jobs.push({
    name: "OAuth2 Client Credentials",
    script: "oauth2_client_credentials.js",
    env: {
      AUDIENCE: env.CLIENT_CREDENTIALS_AUDIENCE,
      DISCOVERY_ENDPOINT: env.CLIENT_CREDENTIALS_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.CLIENT_CREDENTIALS_CLIENT_ID,
      CLIENT_SECRET: env.CLIENT_CREDENTIALS_CLIENT_SECRET,
      SCOPE: env.CLIENT_CREDENTIALS_SCOPE,
    },
  });

  // The HTTP tab on the token exchange pane: the request and the response as
  // they actually went. It runs the Client Credentials grant because the pane,
  // the handler and the trace are the same for every grant this page sends and
  // that one needs no login — and it takes the same four variables as the job
  // above for exactly that reason.
  jobs.push({
    name: "Token exchange HTTP tab (request, response, headers, timing)",
    script: "token_http_exchange.js",
    env: {
      DISCOVERY_ENDPOINT: env.CLIENT_CREDENTIALS_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.CLIENT_CREDENTIALS_CLIENT_ID,
      CLIENT_SECRET: env.CLIENT_CREDENTIALS_CLIENT_SECRET,
      SCOPE: env.CLIENT_CREDENTIALS_SCOPE,
    },
  });

  for (const PKCE_ENABLED of ["true", "false"]) {
    jobs.push({
      name: `OAuth2 Authorization Code (public, PKCE=${PKCE_ENABLED})`,
      script: "oauth2_authorization_code.js",
      env: {
        AUDIENCE: env.AUTHORIZATION_CODE_PUBLIC_AUDIENCE,
        DISCOVERY_ENDPOINT: env.AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT,
        CLIENT_ID: env.AUTHORIZATION_CODE_PUBLIC_CLIENT_ID,
        CLIENT_SECRET: env.AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET,
        SCOPE: env.AUTHORIZATION_CODE_PUBLIC_SCOPE,
        USER: env.AUTHORIZATION_CODE_PUBLIC_USER,
        PKCE_ENABLED,
      },
    });
  }

  jobs.push({
    name: "OAuth2 Implicit",
    script: "oauth2_implicit.js",
    env: {
      AUDIENCE: env.IMPLICIT_AUDIENCE,
      DISCOVERY_ENDPOINT: env.IMPLICIT_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.IMPLICIT_CLIENT_ID,
      SCOPE: env.IMPLICIT_SCOPE,
      USER: env.IMPLICIT_USER,
    },
  });

  jobs.push({
    name: "OAuth2 Resource Owner Password Credentials",
    script: "oauth2_resource_owner_password_credentials_grant.js",
    env: {
      AUDIENCE: env.RESOURCE_OWNER_CREDENTIAL_AUDIENCE,
      DISCOVERY_ENDPOINT: env.RESOURCE_OWNER_CREDENTIAL_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.RESOURCE_OWNER_CREDENTIAL_CLIENT_ID,
      CLIENT_SECRET: env.RESOURCE_OWNER_CREDENTIAL_CLIENT_SECRET,
      SCOPE: env.RESOURCE_OWNER_CREDENTIAL_SCOPE,
      USER: env.RESOURCE_OWNER_CREDENTIAL_USER,
    },
  });

  for (const PKCE_ENABLED of ["true", "false"]) {
    jobs.push({
      name: `OIDC Authorization Code (public, PKCE=${PKCE_ENABLED})`,
      script: "oidc_authorization_code.js",
      env: {
        AUDIENCE: env.OIDC_AUTHORIZATION_CODE_PUBLIC_AUDIENCE,
        DISCOVERY_ENDPOINT: env.OIDC_AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT,
        CLIENT_ID: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_ID,
        CLIENT_SECRET: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET,
        // matches runTests(): the OIDC scope is prefixed with the std scopes
        SCOPE: `openid profile email offline_access ${env.OIDC_AUTHORIZATION_CODE_PUBLIC_SCOPE || ""}`.trim(),
        USER: env.OIDC_AUTHORIZATION_CODE_PUBLIC_USER,
        PKCE_ENABLED,
      },
    });
  }

  // Every OIDC authentication flow against the mock STS, with DPoP and without:
  // six flows times two, twelve jobs from one script.
  //
  // The STS is the OP for two reasons: it advertises and implements all seven
  // response types, and it is in this project's control, so a failure is a
  // failure in the debugger. That also means these need no identity provider —
  // the gate is the STS, like the WS-Trust jobs.
  //
  // Both halves of the DPoP axis earn their place. `on` is not simply "and it
  // still works": for the four code-bearing flows it requires dpop_jkt on the
  // authorization request and cnf.jkt on the exchanged token, and for the two
  // Implicit ones it requires the opposite — nothing bound, and the pane saying
  // why, since those flows never reach a token endpoint. `off` is what keeps
  // the Bearer path, which is what the specifications describe first, from
  // quietly becoming un-runnable.
  if (env.WSTRUST_STS_URL) {
    const OIDC_FLOWS = [
      ["oidc_authorization_code_flow", "OIDC Authorization Code Flow (code)"],
      ["oidc_implicit_flow", "OIDC Implicit Flow (id_token token)"],
      ["oidc_implicit_flow_id_token", "OIDC Implicit Flow (id_token)"],
      ["oidc_hybrid_code_id_token", "OIDC Hybrid (code id_token)"],
      ["oidc_hybrid_code_token", "OIDC Hybrid (code token)"],
      ["oidc_hybrid_code_id_token_token", "OIDC Hybrid (code id_token token)"],
    ];
    for (const [OIDC_FLOW, label] of OIDC_FLOWS) {
      for (const OIDC_DPOP of ["off", "on"]) {
        jobs.push({
          name: `${label} — mock STS, DPoP ${OIDC_DPOP}`,
          script: "oidc_flows.js",
          // The client id, scope and username are the script's own, and the
          // script is what REGISTERS the client: it puts it in the mock's
          // application registry before the browser starts, with the redirect
          // URI, response type and scope this job is about to send. That
          // sentence used to read "the mock registers no clients … so there is
          // nothing for the suite to provision", which described what the mock
          // REQUIRES and was the reason the entry it left behind knew the
          // client_id and nothing else. See tests/sts_applications.js.
          env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL, OIDC_FLOW, OIDC_DPOP },
        });
      }
    }
  }

  // ---------------------------------------------------------------------
  // THE SAME MATRIX A SECOND TIME, WITH BOTH SIDES IN RFC 9700 MODE.
  //
  // The twelve jobs above run the debugger and the mock STS both permissive,
  // which is what almost every identity provider this tool is pointed at
  // actually is. These run the other pairing: the debugger's RFC 9700
  // compliance checkbox on, and an STS started with STS_OAUTH2_RFC9700=true.
  //
  // The two passes ask different questions and neither substitutes for the
  // other. Permissive asks whether the debugger still works against a server
  // that implements none of this — the reason the checkbox exists and is off
  // by default. Compliant asks whether, when the server DOES enforce the BCP,
  // the client meets it: exact registered redirect URIs, PKCE it can verify,
  // https throughout, no response type that would put an access token in the
  // address bar. A client that quietly sent the wrong thing in the permissive
  // pass is indistinguishable from one that did not.
  //
  // `refused` is a job of its own and is the important one. A compliance mode
  // that issues a token on the happy path looks finished and can be worth
  // nothing: what it is FOR is refusing the Implicit Grant, refusing the
  // password grant, refusing a code presented twice — and being REVERSIBLE,
  // which a test that only ever switches the mode on can never see.
  //
  // Gated on RFC9700_STS_URL, which names a TRUST REALM on the same mock STS
  // the twelve permissive jobs use — `.../realm/rfc9700` — rather than a second
  // instance. It used to be a second one: `oauth2.rfc9700` binds the main port
  // as HTTPS over there and is therefore restart-only, so one process could not
  // serve both passes. It can now, because that flag is the one setting in that
  // service marked `realmRuntime`: restart-only for the PROCESS and settable on
  // a REALM, since a realm binds no socket. common/common.sh's
  // configureStsRfc9700Realm() creates it and is what leaves this variable
  // unset — and therefore these five jobs unscheduled — when the mock is too
  // old to have it. See docs/rfc9700.md.
  if (env.RFC9700_STS_URL) {
    const RFC9700_JOBS = [
      ["refused", "the refusals, and that the mode is reversible"],
      ["oidc_authorization_code_flow", "OIDC Authorization Code Flow (code)"],
      ["authorization_grant", "OAuth2 Authorization Code Grant"],
      ["oidc_hybrid_code_id_token", "OIDC Hybrid (code id_token)"],
      ["client_credential", "OAuth2 Client Credentials"],
    ];
    for (const [RFC9700_FLOW, label] of RFC9700_JOBS) {
      jobs.push({
        name: `RFC 9700 — ${label} (debugger AND mock STS both compliant)`,
        script: "rfc9700_flows.js",
        // WSTRUST_STS_URL is what the script reads, as every other STS-backed
        // job does; RFC9700_STS_URL is what SELECTS the compliant REALM.
        // Naming them differently here is what keeps a permissive STS from
        // being handed to a job that would then pass while proving nothing —
        // the script refuses one by name, but the wiring should not offer it.
        // It matters more now than it did when the two were separate
        // containers: the permissive and the compliant server are the same
        // process, told apart only by a path prefix, so a URL that lost its
        // prefix would reach a running, healthy, permissive server rather than
        // nothing at all.
        env: { WSTRUST_STS_URL: env.RFC9700_STS_URL, RFC9700_FLOW },
      });
    }
  }

  // The client half of RFC 9700 with no browser and no services, so it never
  // skips: the requirement catalogue, the MODE-OFF CONTRACT (which every job
  // above is blind to, because they all turn the mode on), each of the four
  // check functions driven directly, and the always-on posture — no open
  // redirector, 303 rather than 307, no framing, no browser messaging, no
  // token in a URL — asserted over the source that holds it.
  jobs.push({
    name: "RFC 9700 client model (the catalogue, the mode-off contract, the " +
        "rules, the always-on posture)",
    script: "rfc9700_client.js",
    env: {},
  });

  // The same twelve against KEYCLOAK, which asks the other half of the
  // question: whether any of it interoperates with a real OP. Gated on the
  // client configureKeycloak() provisions for it (OIDC_ALL_FLOWS_PUBLIC) — one
  // client with standardFlowEnabled AND implicitFlowEnabled, since Keycloak
  // gates the response types on that pair, and without "always use DPoP" so
  // that both halves of the DPoP axis run against it.
  //
  // Note what differs from the mock and is passed in rather than assumed:
  // Keycloak's `sub` is a UUID (OIDC_EXPECT_SUB), which is a different string
  // from the name typed at the login screen (OIDC_LOGIN_USER). The DPoP jobs
  // also need the server started with --features=dpop; the test checks the
  // metadata advertises DPoP and says so by name rather than failing at the
  // last assertion.
  if (env.OIDC_ALL_FLOWS_PUBLIC_DISCOVERY_ENDPOINT) {
    const OIDC_FLOWS_KC = [
      ["oidc_authorization_code_flow", "OIDC Authorization Code Flow (code)"],
      ["oidc_implicit_flow", "OIDC Implicit Flow (id_token token)"],
      ["oidc_implicit_flow_id_token", "OIDC Implicit Flow (id_token)"],
      ["oidc_hybrid_code_id_token", "OIDC Hybrid (code id_token)"],
      ["oidc_hybrid_code_token", "OIDC Hybrid (code token)"],
      ["oidc_hybrid_code_id_token_token", "OIDC Hybrid (code id_token token)"],
    ];
    for (const [OIDC_FLOW, label] of OIDC_FLOWS_KC) {
      for (const OIDC_DPOP of ["off", "on"]) {
        jobs.push({
          name: `${label} — Keycloak, DPoP ${OIDC_DPOP}`,
          script: "oidc_flows.js",
          env: {
            DISCOVERY_ENDPOINT: env.OIDC_ALL_FLOWS_PUBLIC_DISCOVERY_ENDPOINT,
            CLIENT_ID: env.OIDC_ALL_FLOWS_PUBLIC_CLIENT_ID,
            // No offline_access: it is refused on the Implicit flows, and a
            // refresh token is not what any of these twelve are about.
            SCOPE: `openid profile email ${env.OIDC_ALL_FLOWS_PUBLIC_SCOPE ||
                ""}`.trim(),
            OIDC_LOGIN_USER: env.OIDC_ALL_FLOWS_PUBLIC_USERNAME,
            OIDC_EXPECT_SUB: env.OIDC_ALL_FLOWS_PUBLIC_USER,
            OIDC_FLOW,
            OIDC_DPOP,
          },
        });
      }
    }
  }

  // The UserInfo endpoint through all three of oauth2_oidc_2.html's "UserInfo
  // Data" links — the token set the flow produced, the one the refresh call
  // produced, and the one selected from Token History. The three differ only in
  // which access token they carry, which is exactly the failure a single call
  // cannot see: every token in the run belongs to the same user, so a link
  // carrying the wrong one still returns a correct-looking answer.
  //
  // Runs against both OPs, like the flow matrix. Unlike it, this one exercises
  // the UserInfo page's DEFAULT configuration, which on a build that HAS the
  // api initiates the call from it — so these two jobs need the api service as
  // well as the OP. On a backend-less target (the deployed static sites) the
  // page disables that option and calls the OP from the browser instead; the
  // test reads which build it is off the page rather than being told here,
  // because it is the page's own state that decides what pressing the button
  // does.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OIDC UserInfo through all three token sets — mock STS",
      script: "oidc_userinfo.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }
  if (env.OIDC_ALL_FLOWS_PUBLIC_DISCOVERY_ENDPOINT) {
    jobs.push({
      name: "OIDC UserInfo through all three token sets — Keycloak",
      script: "oidc_userinfo.js",
      env: {
        DISCOVERY_ENDPOINT: env.OIDC_ALL_FLOWS_PUBLIC_DISCOVERY_ENDPOINT,
        CLIENT_ID: env.OIDC_ALL_FLOWS_PUBLIC_CLIENT_ID,
        SCOPE: `openid profile email ${env.OIDC_ALL_FLOWS_PUBLIC_SCOPE ||
            ""}`.trim(),
        OIDC_LOGIN_USER: env.OIDC_ALL_FLOWS_PUBLIC_USERNAME,
      },
    });
  }

  // DPoP is OPTIONAL on the OAuth2 / OIDC workflow: off by default, on when the
  // pane asks for it, and — the case this exists for — not decided by the
  // SD-JWT VC workflow's own switch, which is what used to make it mandatory
  // here.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OIDC DPoP is optional (RFC 9449: off by default, on when asked, " +
          "never inherited)",
      script: "oidc_dpop_optional.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // Token Revocation (RFC 7009). Uses the OIDC public client with the
  // offline_access scope so a refresh token is issued and can be revoked
  // alongside the access token.
  jobs.push({
    name: "OAuth2 Token Revocation (RFC 7009)",
    script: "oauth2_token_revocation.js",
    env: {
      AUDIENCE: env.OIDC_AUTHORIZATION_CODE_PUBLIC_AUDIENCE,
      DISCOVERY_ENDPOINT: env.OIDC_AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_ID,
      CLIENT_SECRET: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET,
      SCOPE: `openid profile email offline_access ${env.OIDC_AUTHORIZATION_CODE_PUBLIC_SCOPE || ""}`.trim(),
      USER: env.OIDC_AUTHORIZATION_CODE_PUBLIC_USER,
      PKCE_ENABLED: "true",
      // The Token Introspection Endpoint is called as the confidential client,
      // which is permitted to introspect (the public/PKCE client is not).
      INTROSPECTION_CLIENT_ID: env.AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_ID,
      INTROSPECTION_CLIENT_SECRET: env.AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_SECRET,
    },
  });

  // Token Introspection (RFC 7662). Signs in via the OIDC Authorization Code
  // flow, then exercises all six "Introspect Token" links on the debugger
  // (initial access/refresh, refresh-call access/refresh, and Token History
  // access/refresh), confirming each reports the token as active.
  //
  // A single confidential client (TOKEN_INTROSPECTION, created in
  // common/common.sh) is used for BOTH the sign-in and the introspection
  // calls. Keycloak only returns active=true when the introspecting client is
  // in an access token's audience AND is the client a refresh token was issued
  // to, so the same client must own the tokens and introspect them. It carries
  // a self-audience mapper so its own access tokens introspect as active.
  jobs.push({
    name: "OAuth2 Token Introspection (RFC 7662)",
    script: "token_introspection.js",
    env: {
      AUDIENCE: env.TOKEN_INTROSPECTION_AUDIENCE,
      DISCOVERY_ENDPOINT: env.TOKEN_INTROSPECTION_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.TOKEN_INTROSPECTION_CLIENT_ID,
      CLIENT_SECRET: env.TOKEN_INTROSPECTION_CLIENT_SECRET,
      SCOPE: `openid profile email offline_access ${env.TOKEN_INTROSPECTION_SCOPE || ""}`.trim(),
      USER: env.TOKEN_INTROSPECTION_USER,
      // Confidential client, so no PKCE — it authenticates with its secret.
      PKCE_ENABLED: "false",
      // Introspect as the same confidential client that obtained the tokens: it
      // is in its own access tokens' audience and owns its refresh tokens, so
      // Keycloak reports active=true for both.
      INTROSPECTION_CLIENT_ID: env.TOKEN_INTROSPECTION_CLIENT_ID,
      INTROSPECTION_CLIENT_SECRET: env.TOKEN_INTROSPECTION_CLIENT_SECRET,
    },
  });

  // The JWKS page — the "Review JWKS meta data" link on both debugger pages,
  // and until 2026-08-23 the one page in this tree that no test had ever
  // opened. It was found by the COVERAGE report rather than by a failure, and
  // the way it hid is worth keeping: the bundle is built by client/build.js,
  // browserified by client/Dockerfile, and named in that file's COVERAGE list,
  // so every check that guards the build was satisfied. It was simply ABSENT
  // from the frontend report — not at 0%, absent — because Istanbul reports on
  // files that were loaded, and nothing loaded this one.
  //
  // Four things need a browser here and nothing else covers any of them: the
  // fetch is the PAGE'S OWN (jQuery straight to the identity provider, no api
  // in the path, so CORS and Private Network Access apply and it is what makes
  // the page work on the static deployments); the PEM column is a per-key try,
  // so a key this encoder does not cover — an OKP key, increasingly common —
  // must not empty the table; every string in the table came out of a fetched
  // document, member NAMES included; and one branch writes into a <textarea>,
  // where a value carrying "</textarea>" closes the element early and the rest
  // is parsed as markup.
  //
  // Only the live-fetch section needs the mock STS, and it skips with a named
  // reason without it. Everything else drives the page's own exported
  // functions with fixtures — in the browser, which is what keeps the Istanbul
  // instrumentation counting.
  jobs.push({
    name: "JWKS page (the page's own fetch, the per-key PEM, nothing " +
        "fetched reaching the DOM as markup)",
    script: "jwks_page.js",
    env: {
      STS_URL: env.STS_URL || "https://localhost:8081",
      JWKS_BROWSER_URL: env.JWKS_BROWSER_URL ||
          (env.STS_URL || "https://localhost:8081") + "/oauth2/jwks",
    },
  });

  // Token Exchange (RFC 8693). The requesting confidential client obtains a
  // subject token via the auth code flow, exchanges it for a token aimed at the
  // target audience client, and the issued token is confirmed via
  // introspection.
  jobs.push({
    name: "OAuth2 Token Exchange (RFC 8693)",
    script: "oauth2_token_exchange.js",
    env: {
      DISCOVERY_ENDPOINT: env.TOKEN_EXCHANGE_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.TOKEN_EXCHANGE_CLIENT_ID,
      CLIENT_SECRET: env.TOKEN_EXCHANGE_CLIENT_SECRET,
      SCOPE: "openid profile email",
      USER: env.TOKEN_EXCHANGE_USER,
      PKCE_ENABLED: "false",
      // The target client whose audience the exchanged token is aimed at.
      AUDIENCE_CLIENT_ID: env.TOKEN_EXCHANGE_TARGET_CLIENT_ID,
      // Introspect as the target (audience) client. As of Keycloak 26.2 the
      // introspection endpoint returns {"active": false} unless the
      // authenticated client is present in the token's "aud" claim, and the
      // exchanged token is aimed solely at the target client's audience.
      INTROSPECTION_CLIENT_ID: env.TOKEN_EXCHANGE_TARGET_CLIENT_ID,
      INTROSPECTION_CLIENT_SECRET: env.TOKEN_EXCHANGE_TARGET_CLIENT_SECRET,
    },
  });

  // A THREE-TIER DELEGATION CHAIN, which is the job above's exchange done
  // TWICE, by two different clients, out of two workflows of its own — the
  // shape an API gateway and an enterprise service bus actually produce. The
  // token one hop issues is the token the next hop presents, so after two hops
  // the far end holds a credential for somebody who never spoke to it, and the
  // only place that chain exists is the issuer's own delegation register: no
  // actor token is sent, so nothing about the middle tiers travels in any
  // token. It asserts the wire, the mock's reading of the final token
  // (introspection), the two acts the register recorded — matched by the jti of
  // the tokens this test actually received — and the GRAPH the delegation map
  // is drawn from, where the whole point is that the middle tier is ONE box
  // that was reached by the first hop and did the second.
  //
  // IT PROVISIONS THE FOUR APPLICATIONS FIRST, through POST
  // /admin-api/applications/create: each declared for `oauth2` and `oidc`, and
  // the three a token can be ADDRESSED to registering the URI it is addressed
  // by on `oauthAudience` (apigw1 → https://apigw1.example.com, and so on).
  // webapp1 registers none, which the test asserts — a browser application is
  // issued tokens and is never the audience of one. That attribute is READ:
  // each hop asks for the downstream tier's URI, and the mock resolves it back
  // to the application that registered it when it records the act, which is
  // what keeps the picture one chain instead of two halves joined by nothing.
  // It needs a mock STS from 2026-08-26 or later; an older one refuses the
  // create by name, which is what the job then fails with.
  //
  // Then it SAVES THE PICTURES. That register is in memory and dies with the
  // process, so the only moment the map of this chain can be drawn is while the
  // run is happening; the SVGs land in this run's own report directory. See
  // docs/test-suite-map.md.
  //
  // The mock only. It needs three clients nobody registered, a user with no
  // password and a token endpoint that will exchange anything for anything —
  // Keycloak would need all of that provisioned first, and the compliant realm
  // has opinions about a public client and about a scope that grows, which is a
  // different test.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OAuth2 delegation chain (OIDC sign-in, then two RFC 8693 hops " +
          "as two more clients)",
      script: "oauth2_delegation_chain.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        // Where the delegation map's SVGs are written. The run's own directory,
        // so the picture sits beside the report that says the job passed.
        DELEGATION_ARTIFACT_DIR: path.join(RUN_DIR, "delegation"),
      },
    });
  }

  // ---------------------------------------------------------------------
  // THE SAME CHAIN IN THE OTHER PROTOCOL FAMILY: a SAML 2.0 HTTP-POST sign-in,
  // then two WS-Trust hops carrying assertions.
  //
  // TWO JOBS, one per delegation element, and they are not one job with a loop
  // because each is a full browser story and a failure should name which
  // element it was carrying:
  //
  //   OnBehalfOf  WS-Trust 1.3 section 9.2 — the assertion names the person and
  //               says nothing about the requester. IMPERSONATION, and the
  //               register is then the only place the middle tier exists at
  //               all, which is the OAuth chain's situation exactly.
  //   ActAs       WS-Trust 1.4 section 9.3 — composite by definition.
  //               DELEGATION. What the mock issues carries nothing about the
  //               requester either, and the row it records says so; that gap is
  //               in the mock rather than in the profile.
  //
  // WHY IT IS WORTH RUNNING BESIDE THE OAUTH ONE. An <saml:AudienceRestriction>
  // is an `aud` claim — SAML 2.0 section 2.5.1.4 and RFC 7519 section 4.1.3
  // make the same statement — and <wsp:AppliesTo> is what an STS copies into
  // one. So each hop is a token exchange in the sense RFC 8693 means it, and
  // the delegation register and its map are supposed to be ONE model for both
  // families. A chain that draws correctly for OAuth and comes out as
  // unconnected boxes for WS-Trust would mean the model only ever worked for
  // the family it was written against — which is what this job would catch, at
  // the assertion that says the bus is ONE box.
  //
  // It provisions three applications through the management API first, in the
  // default realm, each registering the address it answers to on
  // `wstrustAppliesTo` and `samlEntityId`. That registration is READ: the mock
  // resolves an AppliesTo back to the application that declared it when it
  // records the act (`applications.forAppliesTo()`), which is what keeps the
  // picture one chain instead of two halves joined by nothing.
  //
  // THE MOCK ONLY, and it needs the api as well: the identity provider POSTs
  // its response to the assertion consumer service, which is the api's
  // /samlacs. So it is skipped on a backend-less target, where that endpoint
  // does not exist — the same gate the HTTP-Artifact binding is under.
  //
  // NO JOB LOCK, and the two runs may overlap in the pool: each asserts on acts
  // recorded after its own baseline sequence AND of its own delegation type,
  // and the three registry entries they share are provisioned idempotently.
  if (env.WSTRUST_STS_URL) {
    const wstrustChainBackend = env.SAML_BACKEND_AVAILABLE !== "false";
    for (const element of ["onbehalfof", "actas"]) {
      const chainJob = {
        name: "WS-Trust delegation chain (SAML 2.0 POST sign-in, then two " +
            (element === "actas" ? "ActAs" : "OnBehalfOf") + " hops)",
        script: "wstrust_delegation_chain.js",
        env: {
          WSTRUST_STS_URL: env.WSTRUST_STS_URL,
          WSTRUST_DELEGATION_ELEMENT: element,
          // Backend routing where there is a backend — the same choice the
          // WS-Trust jobs below make, and made here rather than left to the
          // test's default so that the report and the wire agree.
          WSTRUST_ROUTE: wstrustChainBackend ? "back" : "front",
          // Where the delegation map's SVGs are written. The run's own
          // directory, so the pictures sit beside the report that says the job
          // passed. The same directory the OAuth chain writes to; every file
          // this job produces is named `wstrust-…` and carries the element, so
          // the two jobs and the two elements cannot overwrite each other.
          DELEGATION_ARTIFACT_DIR: path.join(RUN_DIR, "delegation"),
        },
      };
      if (!wstrustChainBackend) {
        chainJob.skip = "This target has no API backend (POST /wstrust, and " +
            "the /samlacs the identity provider POSTs its response to). A " +
            "static deployment CAN receive that POST where the Lambda@Edge " +
            "landing is deployed — see infra/CLAUDE.md — and this job has " +
            "never been run against one, so it is skipped rather than " +
            "reported against an arrangement nobody has checked.";
      }
      jobs.push(chainJob);
    }
  }

  // ---------------------------------------------------------------------
  // A FEDERATED SIGN-IN, across two TRUST REALMS of the one mock STS.
  //
  // The debugger's OAuth2/OIDC workflow stands in for an application called
  // `webapp-sso-test1`, registered in `federation-realm-1`; that realm is an
  // OpenID Provider to it and a SAML 2.0 SERVICE PROVIDER of a federation
  // relationship with `federation-realm-2`, which is where a name is actually
  // typed.
  //
  // THE MOCK ONLY, and it needs nothing else — no Keycloak, no api, no second
  // container. It replaces `federation-e2e/` in the sts/ submodule, which
  // built the same topology out of three containers because trust realms did
  // not exist when it was written; the mock's realms make two identity
  // services out of one process, and the debugger supplies the application
  // tier that test had to build for itself.
  //
  // NO JOB LOCK. It creates its own two realms and asserts only on what it
  // put in them — its own application, its own relationship, its own
  // username — so it collides with nothing, and nothing else in this suite
  // touches those realms. It creates them on every run because a realm lives
  // in memory and there is nowhere to declare one, and it deletes and
  // re-creates the application and the relationship inside them so that the
  // counters it asserts on start at zero on a re-run.
  // ---------------------------------------------------------------------
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "Federated sign-in (OIDC to federation-realm-1, SAML 2.0 on to " +
          "federation-realm-2)",
      script: "federation_sso.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // ---------------------------------------------------------------------
  // N-LAYER FEDERATION, which is the job above with the bottom knocked out
  // of it: the realm that receives the SAML 2.0 request has no password box
  // of its own and answers by federating AGAIN, over WS-Federation, to a
  // third realm. Three protocols, four parties, one sign-in — and the middle
  // realm is a pure identity BRIDGE that authenticates nobody.
  //
  // THE MOCK ONLY, like the job above, and for the same reason: three trust
  // realms of one process are three identity services, and the debugger is
  // the application tier.
  //
  // NO JOB LOCK, and the argument is the one above PLUS one more. It creates
  // realms 3, 4 and 5 — deliberately not 1 and 2, which belong to
  // federation_sso.js and whose counters that test asserts are EXACTLY ONE.
  // Sharing a realm between the two would make each job's arithmetic depend
  // on whether the other had run, which in a pool is a flake rather than a
  // failure.
  // ---------------------------------------------------------------------
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "N-layer federated sign-in (OIDC to federation-realm-3, SAML 2.0 " +
          "on to federation-realm-4, WS-Federation on to federation-realm-5)",
      script: "federation_chain_sso.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // ---------------------------------------------------------------------
  // ONE APPLICATION, TWO FEDERATION PARTNERS, AND THE PERSON PICKS.
  //
  // The two jobs above drive an application with ONE relationship, where the
  // browser is sent straight to the partner and no page is drawn in between.
  // This one drives an application naming TWO, in DIFFERENT PROTOCOLS — a
  // SAML 2.0 relationship and an OpenID Connect one, both to
  // `federation-choice-2` — which is what makes the mock draw its chooser at
  // `/authn/select-idp`: one button per partner and no password field.
  //
  // WHY IT SIGNS IN TWICE. Both relationships work, and the jobs above and
  // the grid below already prove that. What is new is that a choice was
  // OFFERED and HONOURED, and the assertion that catches both halves is
  // arithmetic: after picking the SAML button, that relationship has counted
  // one sign-in and the OpenID Connect one has counted zero — then the other
  // way round in a second, cookie-less run. A mock that drew a two-button
  // page and federated through whichever relationship it found first would
  // pass everything else in that file.
  //
  // THE MOCK ONLY, like the two above.
  //
  // NO JOB LOCK, and its own realms — `federation-choice-1` and `-2` — for
  // federation_chain_sso.js's reason exactly: this job asserts EXACT counts
  // on two relationships and performs two sign-ins, so sharing a realm with
  // anything else would make its arithmetic depend on what else had run.
  // ---------------------------------------------------------------------
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "Federation partner choice (one application, SAML 2.0 AND OIDC " +
          "relationships from federation-choice-1 to federation-choice-2)",
      script: "federation_choice_sso.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // ---------------------------------------------------------------------
  // THE FEDERATION GRID: every combination of the two protocol layers in a
  // two-tier federation, and of how the far end authenticates.
  //
  //   five application protocols  x  five federation protocols
  //                               x  two authentication mechanisms
  //
  // FORTY-NINE JOBS AND NOT FIFTY. The fiftieth point of the grid — an OIDC
  // application, a SAML 2.0 federation and a password — is `federation_sso.js`
  // above, which drives exactly that and asserts several things this
  // parameterised script deliberately does not (its realms are its own, so it
  // can assert that realm 2 has NO federation relationships at all and that
  // realm 1's registry has never heard of its application). Running the same
  // point twice would buy nothing and would put a second job's arithmetic in
  // the same realms.
  //
  // ONE JOB PER POINT, rather than five jobs of fifteen or three of
  // twenty-five. A grid job that walks its combinations inside one browser is
  // faster — one Chrome start instead of fifty — and reports a GROUP: the
  // first failure ends its group, `report.xml` names the group rather than the
  // combination, and a re-run to reproduce one point runs fourteen others
  // first. One job per point costs wall clock that the pool takes most of back
  // and buys a report where the failing row IS the combination.
  //
  // SPNEGO IS NOT A THIRD MECHANISM here, deliberately, and the script's
  // header says why at length. HALF of that argument retired with the
  // 2026-08-27 sts/ bump: the acceptor IS an authentication mechanism in the
  // mock now — `/authn/spnego` calls `startSession()`, an application can
  // carry `appAuthnMechanism: spnego` and a relationship
  // `fedAuthnMechanism: spnego` — so the wiring is no longer what is
  // missing. What is still missing is the browser end: where a HEADLESS
  // Chrome gets a ticket, and the allow-listed host it will answer a
  // `Negotiate` challenge for. Twenty-five points stay deferred rather than
  // faked, on that reason alone.
  //
  // NO JOB LOCK, and the argument is `federation_sso.js`'s with one more line.
  // All forty-nine share `federation-matrix-1` and `federation-matrix-2`, and
  // every object each of them asserts on is named after its own combination —
  // its application, its two relationships, its partner entry, its username —
  // so the counters it reads are its own arithmetic and nobody else's. What
  // that costs is stated in the script: nothing here may assert anything
  // REALM-WIDE, because forty-nine jobs are putting things in those realms at
  // once. Realms 1 to 5 belong to the two jobs above and are left alone.
  //
  // THE MOCK ONLY, plus the client and the api — the api is not optional the
  // way it is for the two jobs above, because the SAML and WS-Federation
  // application tiers land their responses on its `/saml` and `/wsfed`
  // landings.
  // ---------------------------------------------------------------------
  if (env.WSTRUST_STS_URL) {
    const FEDERATION_GRID_LABELS = {
      oidc: "OIDC",
      oauth2: "OAuth 2.0",
      saml2: "SAML 2.0",
      saml11: "SAML 1.1",
      wsfed: "WS-Federation",
    };
    const FEDERATION_GRID_MECHANISMS = {
      password: "username + password",
      webauthn: "WebAuthn",
    };
    // The point federation_sso.js already drives, skipped here rather than
    // duplicated. See the note above.
    const COVERED_ELSEWHERE = "oidc/saml2/password";
    for (const app of Object.keys(FEDERATION_GRID_LABELS)) {
      for (const fed of Object.keys(FEDERATION_GRID_LABELS)) {
        for (const mech of Object.keys(FEDERATION_GRID_MECHANISMS)) {
          if (app + "/" + fed + "/" + mech === COVERED_ELSEWHERE) {
            continue;
          }
          jobs.push({
            name: "Federation grid — " + FEDERATION_GRID_LABELS[app] +
                " application, " + FEDERATION_GRID_LABELS[fed] +
                " federation, " + FEDERATION_GRID_MECHANISMS[mech] +
                " at the far end",
            script: "federation_matrix_sso.js",
            env: {
              WSTRUST_STS_URL: env.WSTRUST_STS_URL,
              FEDERATION_APP_PROTOCOL: app,
              FEDERATION_FED_PROTOCOL: fed,
              FEDERATION_MECHANISM: mech,
            },
          });
        }
      }
    }
  }

  // Device Authorization Grant (RFC 8628). Requests a device/user code,
  // approves the device at the Keycloak verification URI, then polls for the
  // access token.
  jobs.push({
    name: "OAuth2 Device Authorization Grant (RFC 8628)",
    script: "oauth2_device_authorization.js",
    env: {
      DISCOVERY_ENDPOINT: env.DEVICE_AUTHORIZATION_GRANT_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.DEVICE_AUTHORIZATION_GRANT_CLIENT_ID,
      CLIENT_SECRET: env.DEVICE_AUTHORIZATION_GRANT_CLIENT_SECRET,
      SCOPE: "openid profile email",
      USER: env.DEVICE_AUTHORIZATION_GRANT_USER,
    },
  });

  // OIDC Dynamic Client Registration (OpenID Connect Registration 1.0 /
  // RFC 7591 / RFC 7592). Creates a client using an initial access token, then
  // reads, updates, and deletes it via the client configuration endpoint.
  jobs.push({
    name: "OIDC Dynamic Client Registration",
    script: "oidc_dynamic_client_registration.js",
    env: {
      DISCOVERY_ENDPOINT: env.DYNAMIC_CLIENT_REGISTRATION_DISCOVERY_ENDPOINT,
      INITIAL_ACCESS_TOKEN: env.DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN,
    },
  });

  // JWT Tools page. First obtains a real OIDC ID Token via the Authorization
  // Code grant (public client), pastes it into the Encoded JWT field and
  // confirms the decoded Payload matches the token. Then, from the debugger,
  // opens the Tools pane, follows the JWT Tools link, adds
  // string/number/boolean claims and checks RFC compliance, and exercises
  // signing + X.509 verification and JWE encryption + decryption, including the
  // PEM/JWK format toggle and the key-download buttons.
  jobs.push({
    name: "JWT Tools (ID Token decode, compose, sign/verify, encrypt/decrypt)",
    script: "jwt_tools.js",
    env: {
      AUDIENCE: env.OIDC_AUTHORIZATION_CODE_PUBLIC_AUDIENCE,
      DISCOVERY_ENDPOINT: env.OIDC_AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_ID,
      CLIENT_SECRET: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET,
      SCOPE: `openid profile email offline_access ${env.OIDC_AUTHORIZATION_CODE_PUBLIC_SCOPE || ""}`.trim(),
      USER: env.OIDC_AUTHORIZATION_CODE_PUBLIC_USER,
      PKCE_ENABLED: "true",
    },
  });

  // Encoding / Hashing Tools page. A fully client-side page needing no IdP:
  // opens it from the debugger Tools pane, confirms the on-load defaults, then
  // exercises every button — Base64 Encode/Decode (verifying the decoded value
  // round-trips to the original), URI Encode/Decode, the one-way CRC-32
  // Checksum, SHA-1/SHA-2 hashing across all seven digest sizes, the FIPS 202
  // pane (four SHA-3 sizes, both SHAKEs at two output lengths each, and the
  // legacy Keccak option that is NOT its SHA-3 namesake) and the SP 800-185
  // pane, driven with six of that document's own published sample values.
  // Everything but SP 800-185 is validated against node's OpenSSL; those four
  // functions exist in no browser and in no node API, so a published vector is
  // the only reference here that is not the code under test.
  //
  // It runs with NO secure-origin override, deliberately: this page hashed
  // with crypto.subtle until FIPS 202 arrived (Web Crypto has no SHA-3), and
  // running without the flag is what keeps it off Web Crypto on the
  // containerized origin, which is not a secure context. See the note in the
  // script.
  jobs.push({
    name: "Encoding / Hashing Tools (Base64, URI, CRC-32, SHA-2, SHA-3 / " +
        "SHAKE, SP 800-185)",
    script: "encoding_tools.js",
    env: {},
  });

  // The same page's hashing, in node with no browser, against things that are
  // NOT this code: node's own OpenSSL for all eleven fixed-output functions
  // and both SHAKEs at five lengths, `openssl mac`'s KMAC128/KMAC256 as a
  // second implementation of the keyed half, fifteen sample values
  // transcribed from SP 800-185, and TupleHash and ParallelHash re-derived
  // here from that document's own left_encode / right_encode / encode_string
  // definitions. Separate from the browser job above for the reason
  // crypto_engines.js is separate from encryption_tools.js: a digest is
  // exactly where being wrong looks like being right, so only a reference
  // outside this tree can say the bytes are correct. It also asserts the
  // division that lets it exist (hash_tools.js reaches no DOM and no Web
  // Crypto) and that the page and the registry still offer the same
  // functions. No browser and no services, so it never skips.
  jobs.push({
    name: "Hashing engine (FIPS 180-4 / 202 vs OpenSSL, SP 800-185 vectors " +
        "and KMAC vs OpenSSL, in node)",
    script: "hash_engine.js",
    env: {},
  });

  // Digital Signature page. A fully client-side page needing no IdP. For every
  // pane it sets a value, generates a key, produces a signature/MAC, confirms
  // it validates, and exercises the keystore downloads. Asymmetric: SLH-DSA (12
  // sets); RSA (v1.5 & PSS × every hash × 2048/3072); ECC (ECDSA over
  // P-256/384/521/secp256k1 × every hash, EdDSA, Schnorr, BLS); ML-DSA
  // (44/65/87); BBS over BLS12-381 in BOTH ciphersuites — KeyGen (deterministic
  // from the key material, with key_info bound in), sign/verify over a message
  // LIST, every way the draft says that must fail (changed, reordered, dropped,
  // added message; changed header), derived proofs with selective disclosure,
  // unlinkability, replay and substituted-disclosure refusals, and the draft's
  // own test vectors driven through the page. Symmetric MACs: keyed-hash
  // (HMAC/KMAC/BLAKE), block-cipher (CMAC/CBC-MAC/ GMAC), universal-hash
  // (Poly1305/SipHash) — compute + verify + tamper check. JWS: every
  // registered algorithm through all three serializations, the JSON payload
  // check that pane exists for, detached and RFC 7797 unencoded payloads, the
  // unprotected header and where it may not go, and an algorithm the verifier
  // did not choose being refused. XML Signature: all three signature types,
  // four canonicalization methods (with the assertion that WithComments
  // really changes the digest, which needs a document containing a comment),
  // every DigestMethod, RSA / RSASSA-PSS / ECDSA over four curves / HMAC, both
  // XPath transforms — which only a browser can run, since they are evaluated
  // by the DOM's own XPath engine — and every KeyInfo form.
  jobs.push({
    name: "Digital Signature (asymmetric sigs incl. BBS, JWS and XML " +
        "Signature + symmetric MACs — generate, sign/MAC, validate, " +
        "download)",
    script: "digital_signature.js",
    env: {},
  });

  // The Encryption / Decryption page, its sibling. Nine panes, one per
  // mechanism, and like the page above it needs no IdP and no api: AES in
  // every mode and key size, ChaCha20-Poly1305, the legacy 3DES/DES,
  // password-based encryption through PBKDF2 / scrypt / HKDF / PBES2, RSA in
  // both paddings both directly and hybrid, ECIES over five curves, ML-KEM at
  // three parameter sets alone and hybridised with X25519, ElGamal and DHIES
  // over both RFC 3526 groups, and JWE compact serialization. Drives every
  // round trip, every refusal (a modified ciphertext, a changed AAD, the wrong
  // key, the wrong password, an over-long direct-mode message, a key of the
  // wrong length), the keystore downloads, and the Tools-pane links that reach
  // the page.
  jobs.push({
    name: "Encryption / Decryption (AES, ChaCha20-Poly1305, 3DES/DES, RSA, " +
        "ECIES, ML-KEM, ElGamal/DHIES, JWE, password-based — encrypt, " +
        "decrypt, refuse, download)",
    script: "encryption_tools.js",
    env: {},
  });

  // The same page's cryptography, in node with no browser, against things
  // that are NOT this code: RFC 8439's ChaCha20/Poly1305/AEAD vectors, RFC
  // 4493's AES-CMAC vectors, the SipHash reference vectors, NIST SP 800-38A's
  // AES-mode vectors, the FIPS 81 DES vector, node's own OpenSSL in both
  // directions for thirteen ciphers and for RSA-OAEP, node's ECDH for the
  // P-256 agreed secret, FIPS 203's key sizes for ML-KEM, and a Miller-Rabin
  // check that RFC 3526's transcribed primes really are safe primes. It is
  // deliberately separate from the browser job above: a round trip through the
  // page agrees with itself whatever the implementation does, so only these
  // can say the bytes are right. Also asserts that the three modules under
  // test reach no DOM, which is what lets this job exist at all.
  jobs.push({
    name: "Encryption engines (RFC 8439 / 4493 / SP 800-38A / FIPS 81 & 203 " +
        "vectors, cross-checked against OpenSSL, in node)",
    script: "crypto_engines.js",
    env: {},
  });

  // The Digital Signature page's STATEFUL hash-based signature pane, in node
  // with no browser, and the job with the most to prove of any in this
  // directory: LMS/HSS and XMSS/XMSS^MT are the only signature schemes in
  // this application implemented FROM THE SPECIFICATIONS rather than taken
  // from a library, because no LMS or XMSS exists in @noble, in Web Crypto or
  // in node. Every interesting mistake in a hash-based signature produces a
  // scheme that signs and verifies against itself perfectly and interoperates
  // with nothing, so every vector here comes from outside this tree: RFC 8554
  // Appendix F's two HSS cases and RFC 9858 Appendix A's three, LM-OTS key
  // generation vectors that give I, q and SEED, ONE VERIFICATION VECTOR FOR
  // EACH OF THE 21 XMSS PARAMETER SETS in the IANA registry, and key
  // generation and XMSS^MT vectors generated deterministically from the XMSS
  // reference implementation — nothing publishes an XMSS^MT vector, and these
  // are the only thing that can pin SP 800-208 section 6.2's PRF_keygen and
  // the four-byte padding of the 192-bit sets, both invisible to a verifier.
  // Plus eight signatures that must NOT verify. Then the state: that an index
  // advances, that an exhausted key refuses, and that two messages signed from
  // one index both verify, which is the failure SP 800-208 exists to prevent.
  // And then MUTATION TESTING: seven deliberate breakages, each of which the
  // vector aimed at it must notice — because every other check here is of the
  // form "this vector reproduces" and none of them says that any particular
  // line is load bearing. `HBS_ALL_KEYGEN=1` adds five single-tree key
  // generation vectors and about 160 seconds; they gate no rule, since the
  // cheap XMSS^MT vectors cover every hash function and padding length on
  // every run and the job asserts that. No browser and no services, so it
  // never skips; about 40 seconds.
  jobs.push({
    name: "Hash-based signatures (RFC 8554 / 9858 / 8391 and SP 800-208 " +
        "vectors, in node)",
    script: "hbs_signatures.js",
    env: {},
  });

  // The Digital Signature page's JWS pane, in node, for the same reason the
  // job above exists: a round trip through the page agrees with itself
  // whatever the implementation does, and the defects that matter in a JWS are
  // the self-consistent ones — an ECDSA signature left in DER where RFC 7518
  // §3.4 wants R || S, a PSS salt that is not the hash length, a payload
  // re-serialized between validating it and signing it. So every registered
  // algorithm (HS/RS/PS/ES, EdDSA over both curves, ES256K, and the unsecured
  // `none`) is cross-checked against node's own OpenSSL in BOTH directions and
  // against `jsonwebtoken`, and then the rules no vector can express: RFC
  // 7515's crit MUST, RFC 7797's period rule, RFC 8725's "the verifier decides
  // the algorithm", and what an Unsecured JWS is allowed to be.
  jobs.push({
    name: "JWS engine (RFC 7515/7518/7797/8037/8812 — every registered " +
        "algorithm cross-checked against OpenSSL and jsonwebtoken, in node)",
    script: "jws_engine.js",
    env: {},
  });

  // The post-quantum engines, in node, and the third job of this shape. Its
  // reason for existing is sharper than the two above: almost nothing else in
  // the world can read these bytes yet, so a pane that signs and verifies its
  // own ML-DSA is exactly as convincing when the domain separation is wrong.
  // So it asserts against things that are not this code —
  // draft-connolly-cfrg-xwing-kem's own three test vectors for X-Wing
  // (keygen, derandomized encapsulation and decapsulation), the
  // domain-separation labels of both composite drafts against the HEX those
  // drafts print, draft-ietf-cose-falcon Table 1's sizes (which is what holds
  // the padded-versus-variable-length Falcon trap closed), and node's own
  // SHA3 for the KEM combiner's input order. Then the properties no vector
  // expresses: that a composite signature needs BOTH halves, that a context
  // string genuinely separates contexts, that a pre-hashed signature does not
  // verify as a pure one, and that RFC 9964's AKP rules are obeyed — `pub`
  // and `priv` rather than `x` and `d`, and an ML-DSA `priv` that is the
  // 32-byte seed.
  jobs.push({
    name: "Post-quantum engines (X-Wing draft vectors, FIPS 203/204/205 and " +
        "draft composite labels, RFC 9964 AKP keys, in node)",
    script: "pqc_engines.js",
    env: {},
  });

  // SAML Assertion Tool. Another fully client-side page needing no IdP: compose
  // an assertion for each SAML version (2.0 / 1.1 / 1.0) with its
  // version-specific structure, toggle the optional elements, add typed +
  // URI-prefixed custom attributes, run the spec-compliance check, then sign it
  // with an enveloped XML Signature (whose placement and Reference URI differ
  // per version), verify it, reject a tampered copy, and round-trip it through
  // XML Encryption. Also checks the Tools pane on the SAML Test Tools page
  // links here. Operations History pane on the SAML request page: records every
  // attempted IdP call (AuthnRequest / Single Logout / metadata load) with its
  // binding, SAML version, entity IDs, and result. Needs no IdP — the failure
  // paths come from the page's own pre-flight checks and the dispatch is aimed
  // at a URL on the site itself. RFC 8414 (OAuth 2.0 Authorization Server
  // Metadata): the document the STS mock serves at
  // /.well-known/oauth-authorization-server (all 23 members, host-derived
  // issuer, verifiable signed_metadata, resolvable jwks_uri) and the Metadata
  // Source selector on oauth2_oidc_1.html that retrieves it. Needs the STS
  // mock, like the WS-Trust jobs.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OAuth2 Authorization Server Metadata (RFC 8414 endpoint + " +
          "debugger Metadata Source)",
      script: "oauth2_metadata_rfc8414.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // The mock authorization server the STS service hosts: every endpoint its
  // RFC 8414 document advertises answers, with real RS256 tokens that verify
  // against the advertised JWKS. No browser — it drives the endpoints directly.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OAuth2 Authorization Server endpoints (the STS mock's authorize " +
          "/ token / introspect / revoke / register)",
      script: "oauth2_sts_endpoints.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // The shared in-browser JWE implementation, tested directly: every alg/enc
  // pair round-trips, and the Concat KDF is checked against an implementation
  // written from RFC 7518 section 4.6 that shares no code with it. Needs no
  // services — node's Web Crypto is enough — so it is never skipped.
  jobs.push({
    name: "JOSE JWE module (RFC 7516/7518: RSA-OAEP, ECDH-ES, Concat KDF)",
    script: "jose_jwe_encryption.js",
    env: {},
  });

  // Every algorithm menu on every page offers exactly what the engine behind it
  // can do — read out of the HTML and compared with jws.js / jose_jwe.js /
  // dpop.js. No browser, so it costs milliseconds. It exists because the
  // engines here grow and the hand-written <option> lists did not: on
  // 2026-08-28 the JWT Tools signing menu offered 13 of 27 algorithms, the
  // Encryption page's JWE pane 3 of 6 content encryptions, and the DPoP pane 2
  // of 23 — none of which was visible from either side, because every menu was
  // correct on the day it was typed.
  jobs.push({
    name: "Algorithm menus match their engines (jws.js, jose_jwe.js, dpop.js)",
    script: "algorithm_menus.js",
    env: {},
  });

  // And every option in those menus actually WORKS, in a browser. The menu
  // check proves an option exists; this proves choosing it does something. The
  // two are not the same claim, and the gap between them is exactly what a
  // widened menu creates: on 2026-08-28 the JWT Tools signing menu was
  // widened to the engine's twenty-seven algorithms and fourteen of them
  // answered "No key was supplied", because the page's key panes are PEM-based
  // and the post-quantum keys have no PEM form. This job found that; the menu
  // is back to what the page can perform.
  jobs.push({
    name: "Algorithm panes work in the browser (JWT Tools signing, " +
        "Encryption JWE round trips)",
    script: "algorithm_panes.js",
    env: {},
  });

  // The Configuration Parameters pane on both OAuth2/OIDC pages, measured at
  // seven viewport widths: nothing in it crosses the pane's content edge, and
  // each field fills its own table cell rather than sitting at bootstrap's
  // fixed `input, textarea { width: 206px }`. The second assertion is the one
  // that earns the job — the same markup and stylesheet serve a ~854px pane on
  // page 1 and a ~419px one on page 2 (three flex columns there), so a field
  // pinned to a fixed width looks perfectly fine on the first page while
  // hanging 25px, and at a narrower window 136px, outside the second. Needs
  // the client alone — no IdP, no api, no STS, and every field it measures is
  // in the served HTML rather than drawn by the bundle — so it is never
  // skipped and runs against a deployed static site unchanged.
  jobs.push({
    name: "Configuration Parameters pane layout (both OAuth2/OIDC pages, " +
        "seven viewport widths)",
    script: "oauth2_config_pane_layout.js",
    env: {},
  });

  // The "save this key pair in browser localStorage" opt-out on the SAML and
  // WS-Trust request pages, exercised in BOTH states. Worth a browser test
  // because the failure mode is silent and reassuring: if the guard in
  // saveState() broke, the box would still untick and the note would still
  // appear while the private key went on being written. Only reading storage
  // shows it. Needs the client alone — no IdP, no STS — so it is never skipped.
  jobs.push({
    name: "Key pair localStorage opt-out (SAML, WS-Trust, WS-Fed, SD-JWT VC " +
        "— checked and unchecked)",
    script: "keypair_storage_optout.js",
    env: {},
  });

  // The inertness of this app's XML parsing — the invariant behind CodeQL's
  // js/xss-through-dom reports on every DOMParser call in client/src (alert
  // #147 and eleven siblings). Those are a modelling artefact: parseFromString
  // with 'application/xml' yields an inert, detached document, and nothing
  // renders it as markup. Sanitizing the input would be the wrong fix —
  // XML-DSIG signs the exact octets that get canonicalized, so rewriting them
  // breaks the signature. What CAN be done is keep the premise true, which is
  // what this asserts. Node only, never skipped.
  jobs.push({
    name: "XML parsing is inert (no DOMParser HTML mode, no markup sink on " +
        "the XML path)",
    script: "xml_parse_inert.js",
    env: {},
  });

  // The authored pages' attribute values, which is a check on THE STATIC BUILD
  // as much as on the markup. A double-quoted value ends at the next double
  // quote, so a title that quotes something ends early and the rest of the tag
  // becomes junk attributes — legal input that every browser recovers from,
  // differently. Chrome's recovery kept encryption_tools.html working locally;
  // the minifier on the deploy path dropped the closing tags around the field
  // and `enc_pbe_tag` did not exist on the hosted site, so AES-GCM had no tag
  // to verify and the encryption job spent 150 seconds waiting for a box that
  // was never going to fill. Nothing in that failure named the page, the
  // attribute or the minifier, and the same job was green against a local
  // stack — which is why this reads the SOURCE rather than a browser. Node
  // only, never skipped.
  jobs.push({
    name: "Page markup (no attribute value closed early, which is what makes " +
        "the minifier drop the tags around it)",
    script: "page_markup_well_formed.js",
    env: {},
  });

  // The scheme allowlist applied before the app navigates anywhere
  // (client/src/url_safety.js). Every URL it guards is caller-supplied — a
  // typed IdP endpoint, or one out of fetched metadata — and reaches
  // window.location.assign() or a form action, where `javascript:` is script
  // execution in this origin. The cases that earn the test are the ones the URL
  // parser normalises: `java\tscript:` and a leading control character are both
  // the javascript: protocol by the time the browser acts. Node only, never
  // skipped.
  jobs.push({
    name: "URL safety (only http/https reaches a navigation sink)",
    script: "url_safety_schemes.js",
    env: {},
  });

  // The JWK -> SPKI PEM encoder the JWKS page displays (client/src/jwk_pem.js).
  // It exists so the page does not have to require `jwk-to-pem`, which reaches
  // `elliptic` — GHSA-848j-6mx2-7j84, an ECDSA flaw that can expose a private
  // key, and one with NO patched version in existence. That trade is only sound
  // if the replacement encodes correctly, so this checks the DER against node's
  // own SPKI parser, and additionally fails if any file in client/src takes a
  // require that would put elliptic back into a bundle. Node only, never
  // skipped.
  //
  // It carries two more source checks of the same kind, both about things that
  // reach a bundle and break it: no BigInt literal in client/src (envify's
  // esprima cannot parse one, and the build then fails against a file nobody
  // touched), and no `require`/`process` in coverage_beacon.js — the one file
  // there that is APPENDED to finished bundles rather than browserified, so a
  // require in it is an uncaught ReferenceError on every instrumented page.
  // That last one is invisible to this suite's own launchers, which never
  // append the beacon; only ./run-coverage.sh does, and it failed 12 tests and
  // shipped an empty frontend report on 2026-08-14 for exactly that.
  jobs.push({
    name: "JWK to PEM encoder (SPKI DER correctness; elliptic, BigInt " +
        "literals and require() stay out of the bundles)",
    script: "jwk_pem_encoding.js",
    env: {},
  });

  // Every test in this suite that builds a Selenium driver must start Chrome
  // headless, and must do so BY DEFAULT rather than when asked. A test written
  // by copying a neighbour easily picks up browser_flags.js — which handles the
  // secure-context and private-network hazards and says nothing about headless
  // mode — while missing the flag itself; kerberos_delegation_page.js did
  // exactly that and opened a window on every run. On a desktop that steals
  // focus for the length of the run; on a CI runner or in a container there is
  // no display at all, so the session fails to start and names the page the
  // test was about to visit. Reads this directory's sources: node only, no
  // browser, never skipped.
  jobs.push({
    name: "Browser tests are headless (every driver-building test, by " +
        "default)",
    script: "browser_tests_headless.js",
    env: {},
  });

  // No test may call process.exit() while a WebDriver session is open.
  // process.exit() is synchronous termination, so it SKIPS the finally that
  // quits the driver — and an unquit session leaves a whole headless Chrome
  // (~15 OS processes) resident. Thirty-nine files in this directory were
  // written that way; on 2026-08-26 one failing job left 11 Chrome processes
  // behind and a run of this suite left 559, which exhausted the machine's
  // memory and cost a reboot. The detached spawn and group kill in runJob()
  // above are the backstop for a suite run; this is what protects somebody
  // running `node tests/foo.js` by hand, which is how a browser test gets
  // written. It also asserts that runJob() still does its half. Parses this
  // directory's sources with acorn: node only, no browser, never skipped.
  jobs.push({
    name: "No process.exit() while a driver is open (and the runner still " +
        "reaps process groups)",
    script: "driver_quit_reachable.js",
    env: {},
  });

  // The page-load guard the browser tests navigate through (tests/page_load.js)
  // against a socket that behaves like a CDN edge on a bad day. A connection
  // that is established and then dropped is the failure driver.get() does NOT
  // report: it resolves, getCurrentUrl() returns the URL that was asked for,
  // and the tab holds Chromium's error page — so the test waits out its whole
  // budget for a field that was never there and fails naming one of OUR ids.
  // That is `WS-Trust 1.2 - Issue` on 2026-08-15 and `WS-Trust 1.4 - Validate`
  // on 2026-08-20, both against a deployed site, both with the neighbouring
  // cases loading the same page seconds either side. The property most likely
  // to rot is the one that says when NOT to retry: a page that loaded without
  // the field is a product failure and is raised on the first attempt. Its
  // targets are sockets it opens on loopback, so it needs no service and is
  // never skipped.
  jobs.push({
    name: "Page-load retry (a dropped connection is retried and named; a " +
        "page that loaded is not)",
    script: "page_load_retry.js",
    env: {},
  });

  // The WebAuthn decoder (client/src/cbor.js, cose.js, webauthn.js) against
  // REAL ceremonies — ES256 and RS256, registration and assertion — produced by
  // the WebDriver virtual authenticator and committed as
  // tests/webauthn_vectors.json. Two oracles neither of which is ours: the
  // browser's own getPublicKey(), which our COSE -> JWK -> SPKI chain must
  // reproduce byte for byte, and node's crypto, which verifies the same
  // signatures independently. Then the negatives, each failing exactly one
  // named check — including a UV-clear assertion that must be rejected on the
  // FLAG while its signature stays valid, because reporting that as a bad
  // signature would send the user after the wrong thing. Node only, no browser,
  // no network, never skipped.
  jobs.push({
    name: "WebAuthn decoder (CBOR, COSE_Key, authenticator data, assertion " +
        "verification)",
    script: "webauthn_decode.js",
    env: {},
  });

  // The wallet's WebAuthn decoder and the STS's, over the same real ceremonies,
  // required to reach the same verdict on each. The two share no code —
  // different CBOR readers, different COSE mappings, and different signature
  // paths, since node takes an ECDSA signature as DER while Web Crypto demands
  // raw r‖s — so a mistake in one is not mirrored in the other. One
  // implementation agreeing with itself is not a result; two independent
  // readings of section 7.2 agreeing is. Same arrangement as
  // bbs2023_cryptosuite.js. Node only, never skipped.
  jobs.push({
    name: "WebAuthn: the wallet's decoder and the STS's agree " +
        "(cross-implementation)",
    script: "webauthn_cross_impl.js",
    env: {},
  });

  // The WebAuthn Analyzer PAGE, driven against the same real ceremonies. It
  // covers what the node test above cannot: that the decoded values reach the
  // screen. Those are different failures — a pane left empty by a renamed
  // element id decodes perfectly and shows nothing — and only this one catches
  // the second. Needs the client and nothing else: the page performs no
  // ceremony, so there is no authenticator, no IdP and no network involved.
  jobs.push({
    name: "WebAuthn Analyzer page (decode and verify pasted artifacts)",
    script: "webauthn_analyzer_page.js",
    env: {},
  });

  // The WebAuthn Lab page, running REAL ceremonies against the WebDriver
  // virtual authenticator — a CTAP2 authenticator inside the browser, so no
  // hardware, no touch and no flake. Registration, assertion, the counter
  // advancing across two assertions, and the no-credential path reported rather
  // than hung. Note what is NOT here: a UV-required ceremony against an
  // authenticator that cannot verify is refused by the BROWSER, so the relying
  // party never sees a UV-clear assertion and that check cannot be exercised
  // from this page; it lives in webauthn_decode.js, where the material can be
  // manufactured. Needs the client and nothing else.
  jobs.push({
    name: "WebAuthn Lab page (real ceremonies against a virtual authenticator)",
    script: "webauthn_lab_page.js",
    env: {},
  });

  // WebAuthn as the SECOND FACTOR of an OIDC Authorization Code sign-in against
  // the mock STS — the join between the two protocols, and the reason the
  // workflow was built against this service. A relying party asks for step-up
  // with acr_values, a real ceremony happens against the virtual authenticator,
  // and the ID token records it as amr ["pwd","hwk"] with acr "mfa". The last
  // section is the one that matters: a sign-in WITHOUT the second factor must
  // report ["pwd"] and acr "1", because a service that stamped hwk on every
  // token would pass every other check here. Needs the STS (no Keycloak, no
  // hardware), so it is gated on WSTRUST_STS_URL like the rest.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "WebAuthn as OIDC second factor (amr/acr earned, not decorative)",
      script: "webauthn_oidc_mfa.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // The browser extension, side-loaded for real, watching a ceremony on an
  // origin that is not the debugger's — which is the only way to debug somebody
  // else's relying party, and the reason the extension exists. Two claims are
  // checked: that both halves arrive (the REQUEST half especially, which no
  // relying party shows anybody and pasting a response can never produce), and
  // that the extension changes NOTHING about the ceremony it watches. Nobody
  // reviews an unpacked extension on our behalf, so that second one is the
  // whole of the read-only guarantee.
  //
  // Needs the STS, and needs the extension built (buildBrowserExtension() in
  // common/common.sh, called by the launchers before compose). It will NOT run
  // against branded Google Chrome, which refuses to side-load an unpacked
  // extension; the image pins Chrome for Testing, which allows it.
  if (env.WSTRUST_STS_URL) {
    const browser = extensionCapableBrowser();
    const extensionJob = {
      name: "WebAuthn browser extension (observes a third party, " +
          "changes nothing)",
      script: "webauthn_extension.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    };
    if (browser.capable && browser.bin) {
      // Use the binary we probed, not whatever Selenium would pick.
      extensionJob.env.CHROME_BIN = browser.bin;
      // And, when Selenium Manager fetched the browser, the chromedriver it
      // fetched with it: a Chrome for Testing 152 driven by the host's
      // chromedriver for 151 fails on a version mismatch, which reads as a
      // broken extension rather than as two halves of different releases.
      if (browser.driver) {
        extensionJob.env.CHROMEDRIVER_BIN = browser.driver;
      }
    }
    if (!browser.capable) {
      extensionJob.skip =
        "this browser cannot side-load an unpacked extension: " +
        (browser.version || "no chrome/chromium found on PATH") +
         ". Branded Google Chrome refuses " +
        "the flags and reports it only on stderr, so the job would fail with " +
            "every assertion timing " +
        "out and nothing naming the cause. Selenium Manager could not fetch " +
        "a Chrome for Testing either, so this host has no capable browser " +
        "and " +
        "no way to reach one — check the network, or point CHROME_BIN at a " +
        "Chrome-for-Testing or Chromium build.";
    }
    jobs.push(extensionJob);
  }

  // The wallet's DID module (client/src/did.js): did:jwk, did:key and did:web,
  // reading a DID document, and the DIF Well Known DID Configuration check that
  // proves a DID and an origin are the same entity. Everything here fails
  // silently when it is wrong — a multicodec written as a fixed-width number
  // instead of a varint produces DIDs that decode here and nowhere else, a
  // compressed EC point decompressed with the wrong square root gives the other
  // valid point on the curve, and a Domain Linkage Credential with a typ header
  // or an iat claim is exactly what a JWT library produces by default. It found
  // a real bug on its first run: P-384's and P-521's field primes were
  // truncated. Node only, never skipped.
  jobs.push({
    name: "DID module (did:jwk/key/web, document reading, DIF domain linkage)",
    script: "did_document.js",
    env: {},
  });

  // DPoP's own arithmetic (client/src/dpop.js): the RFC 7638 JWK Thumbprint
  // that becomes cnf.jkt, the htu normalization, the ath hash, and the shape of
  // the proof itself. Every one of those fails SILENTLY when it is wrong — a
  // proof with a wrong thumbprint or a wrong htu is perfectly well formed and
  // simply matches nothing, so the server's refusal reads as "your key is
  // wrong" rather than "your encoding is wrong". The oracle is not a second
  // implementation but the RFCs' own published values: RFC 9449 prints an EC
  // key and the jkt of the token bound to it, RFC 7638 section 3.1 does the
  // same for RSA. Node only, never skipped.
  jobs.push({
    name: "DPoP arithmetic (RFC 7638 thumbprints against the RFCs' own " +
        "vectors, htu/ath/jti)",
    script: "dpop_vectors.js",
    env: {},
  });

  // The wallet's DID module (client/src/did.js): did:jwk, did:key and did:web,
  // reading a DID document, and the DIF Well Known DID Configuration check that
  // proves a DID and an origin are the same entity. Everything here fails
  // silently when it is wrong — a multicodec written as a fixed-width number
  // instead of a varint produces DIDs that decode here and nowhere else, a
  // compressed EC point decompressed with the wrong square root gives the other
  // valid point on the curve, and a Domain Linkage Credential with a typ header
  // or an iat claim is exactly what a JWT library produces by default. It found
  // a real bug on its first run: P-384's and P-521's field primes were
  // truncated. Node only, never skipped.
  jobs.push({
    name: "DID module (did:jwk/key/web, document reading, DIF domain linkage)",
    script: "did_document.js",
    env: {},
  });

  // DPoP's own arithmetic (client/src/dpop.js): the RFC 7638 JWK Thumbprint
  // that becomes cnf.jkt, the htu normalization, the ath hash, and the shape of
  // the proof itself. Every one of those fails SILENTLY when it is wrong — a
  // proof with a wrong thumbprint or a wrong htu is perfectly well formed and
  // simply matches nothing, so the server's refusal reads as "your key is
  // wrong" rather than "your encoding is wrong". The oracle is not a second
  // implementation but the RFCs' own published values: RFC 9449 prints an EC
  // key and the jkt of the token bound to it, RFC 7638 section 3.1 does the
  // same for RSA. Node only, never skipped.
  jobs.push({
    name: "DPoP arithmetic (RFC 7638 thumbprints against the RFCs' own " +
        "vectors, htu/ath/jti)",
    script: "dpop_vectors.js",
    env: {},
  });

  // The wallet's DID module (client/src/did.js): did:jwk, did:key and did:web,
  // reading a DID document, and the DIF Well Known DID Configuration check that
  // proves a DID and an origin are the same entity. Everything here fails
  // silently when it is wrong — a multicodec written as a fixed-width number
  // instead of a varint produces DIDs that decode here and nowhere else, a
  // compressed EC point decompressed with the wrong square root gives the other
  // valid point on the curve, and a Domain Linkage Credential with a typ header
  // or an iat claim is exactly what a JWT library produces by default. It found
  // a real bug on its first run: P-384's and P-521's field primes were
  // truncated. Node only, never skipped.
  jobs.push({
    name: "DID module (did:jwk/key/web, document reading, DIF domain linkage)",
    script: "did_document.js",
    env: {},
  });

  // DPoP's own arithmetic (client/src/dpop.js): the RFC 7638 JWK Thumbprint
  // that becomes cnf.jkt, the htu normalization, the ath hash, and the shape of
  // the proof itself. Every one of those fails SILENTLY when it is wrong — a
  // proof with a wrong thumbprint or a wrong htu is perfectly well formed and
  // simply matches nothing, so the server's refusal reads as "your key is
  // wrong" rather than "your encoding is wrong". The oracle is not a second
  // implementation but the RFCs' own published values: RFC 9449 prints an EC
  // key and the jkt of the token bound to it, RFC 7638 section 3.1 does the
  // same for RSA. Node only, never skipped.
  jobs.push({
    name: "DPoP arithmetic (RFC 7638 thumbprints against the RFCs' own " +
        "vectors, htu/ath/jti)",
    script: "dpop_vectors.js",
    env: {},
  });

  // The Kerberos v5 encryption framework (common/krb5/krb5_primitives.js and
  // krb5_crypto.js) against the RFCs' own published values: RFC 3961's n-fold,
  // RFC 3962's AES string-to-key and CBC ciphertext stealing, RFC 8009's SHA-2
  // KDF and sample encryptions, plus RFC 1320/1321/2202 for the MD4, MD5 and
  // HMAC-MD5 that etype 23 needs and Web Crypto does not have.
  //
  // This is the one test in the Kerberos workflow that cannot be replaced by a
  // test against the mock KDC, and the reason is worth keeping: every error in
  // this layer produces the SAME symptom — one opaque integrity failure at the
  // far end, indistinguishable from a wrong password — and two implementations
  // written from the same misreading agree with each other perfectly. A wrong
  // n-fold, a wrong key usage number, an omitted CTS block swap or a MAC over
  // the ciphertext where the specification says plaintext all round-trip
  // happily and interoperate with nothing. It is mutation-tested: six
  // deliberate defects were each confirmed to fail it.
  // Node only, never skipped.
  jobs.push({
    name: "Kerberos v5 crypto (RFC 3961/3962/8009 vectors, CTS, etypes 17/18/19/20/23)",
    script: "krb5_crypto_vectors.js",
    env: {},
  });

  // The Kerberos v5 DER codec and message structures (common/krb5/krb5_asn1.js
  // and krb5_messages.js) against RFC 4120's grammar.
  //
  // A codec that round-trips its own output proves nothing — every field could
  // be under the wrong context tag and it would still pass — so a third of these
  // assertions are byte-exact expectations that pin each tag NUMBER, and another
  // third are the compatibility behaviours only a real deployment produces: an
  // AS-REP enc-part tagged EncTGSRepPart (RFC 4120 section 5.4.2 requires a
  // client to accept it), a NEGATIVE checksum type (-138, which S4U2Self uses),
  // a KRB-ERROR carrying the salt in its e-data, and a relayed Ticket whose
  // original bytes must survive re-encoding. The rest is the negative half: this
  // codec parses bytes pasted into a web page and bytes returned by a host the
  // user named, so refusing malformed and oversized input is part of the job.
  //
  // Mutation-testing it found a real defect: three writers had `addresses`
  // hard-coded to null, so a captured message carrying them could be decoded and
  // never re-encoded. Node only, never skipped.
  jobs.push({
    name: "Kerberos v5 DER codec (RFC 4120 messages, byte-exact tags, compatibility cases)",
    script: "krb5_codec.js",
    env: {},
  });

  // What the Kerberos decoder page SHOWS (common/krb5/krb5_describe.js), plus the
  // keytab reader that lets it show the inside of a ticket (krb5_keytab.js).
  //
  // The page is a renderer with no protocol knowledge in it — the split follows
  // webauthn.js / webauthn_panes.js — so everything it displays is checkable here
  // with no browser. Three behaviours are the ones worth having a test for, and
  // all three are judgement rather than arithmetic: a capture arrives as hex, as
  // base64 or with the TCP length prefix still attached (and the prefix must be
  // stripped AND reported, since leaving it makes the ASN.1 parse fail on byte
  // zero); a failure to decrypt is CONTENT rather than an error, because most of a
  // Kerberos message is encrypted under keys the reader does not have; and
  // `problems` must hold things that are WRONG (a lower-case realm, an RC4-only
  // etype list, a clock five minutes out) and NOT things that are merely absent —
  // KDC_ERR_PREAUTH_REQUIRED specifically is not a problem, it is where the salt
  // comes from.
  //
  // It found a real defect on its first run: an AS-REP was reported as "does not
  // parse" because the describer read `doc.kind` from inside the literal defining
  // `doc`. A parse failure blamed on the message when the fault is in the tool is
  // the worst outcome this page can have. Node only, never skipped.
  jobs.push({
    name: "Kerberos v5 decoder output (input forms, decryption reporting, findings, keytabs)",
    script: "krb5_describe_output.js",
    env: {},
  });

  // The Kerberos Decoder PAGE (client/public/kerberos_decoder.html). The content
  // it shows is already covered without a browser by krb5_describe_output.js, so
  // this job covers only what needs one:
  //
  //  * that the bundle loaded at all — a page registered in client/build.js but
  //    not in client/Dockerfile builds fine for the static deployments while the
  //    containerized page's <script> 404s, so the failure appears only here and
  //    only as a page that does nothing;
  //  * that a hostile value in a KDC's realm or e-text renders as TEXT. This page
  //    displays bytes a stranger pasted in, is built entirely with createElement
  //    and textContent, and the check is mutation-tested: swapping one
  //    textContent for innerHTML fails it;
  //  * that decryption works on Web Crypto, which is a different implementation
  //    from the node path the other tests exercise;
  //  * and that the page persists NOTHING, because everything it is given — a
  //    password, a keytab, a session key out of a decrypted ticket — is a
  //    credential.
  //
  // Needs only the site: this page talks to no KDC and has no back end. That is
  // not enough to put it on the deployed static sites, though — see below.
  //
  // NONE of the Kerberos PAGES exist on a static deployment. Kerberos is DER
  // over port 88, so the workflow needs the api's relay and idptools.com has no
  // api; client/static_site.js drops all five pages from that build and greys
  // out their landing card, the decoder included (it needs no network, but it
  // has no card of its own and the only route to it is a link on kerberos.html,
  // which is not there either). Without this gate those jobs run against a 404
  // and fail naming an element on a page that was never deployed. The three
  // KDC-backed ones already skip when the KDC is unreachable — this reason is
  // the accurate one for a static target, and it reaches the decoder job, which
  // has nothing else to skip on. remote-run-tests.sh sets the variable per
  // target; unset (every containerized and local run) means they are there.
  // KERBEROS_AVAILABLE is the current name; KERBEROS_PAGES_AVAILABLE is the
  // one it replaced and is still honoured, because it may be set in a CI
  // environment or a shell that predates the rename. See the sweep at the end
  // of this function for why the name had to change.
  const kerberosOff =
    (env.KERBEROS_AVAILABLE || env.KERBEROS_PAGES_AVAILABLE) === "false";

  // The same gate for LDAP, and it is a SEPARATE variable rather than a reuse
  // of the one above. The two protocols are absent from a static deployment for
  // the same underlying reason — both are binary over a raw TCP socket, so both
  // need the api and a static site has none — but they are absent
  // independently: a remote target could perfectly well be api-backed with an
  // LDAP directory reachable and no KDC, or the reverse. Deriving one from the
  // other would turn "not this protocol" into a set of skipped or failing jobs
  // about a protocol that is there.
  //
  // Unset — which is every containerized and every local run — means the page
  // is there. remote-run-tests.sh sets it false per target, because
  // client/static_site.js leaves ldap.html, its bundle and css/ldap.css out of
  // dist/ and greys the landing card; without the gate the page job runs
  // against a 404 and fails naming an element on a page nobody deployed.
  //
  // It reaches BOTH LDAP jobs, and that is a change from how this started.
  // `api_ldap.js` used to be left running on the argument that it would skip
  // with a better reason of its own — "the api answered 404 for GET
  // /ldap/limits" being more specific than a blanket "LDAP is off here". That
  // is true of the sentence and wrong about the report: on a static target the
  // 404 is not a discovery, it is the known and intended state of a deployment
  // that has no api at all, and a line saying an endpoint was missing invites
  // somebody to go and look for it. Both jobs now skip for the reason that is
  // actually true — this workflow is not on this target — which is the same
  // choice the Kerberos sweep below makes. A target that IS api-backed sets
  // LDAP_AVAILABLE=true and gets both jobs, including that 404 message, back.
  const ldapOff = env.LDAP_AVAILABLE === "false";
  const ldapPagesSkip = ldapOff
    ? "the LDAP page is not on this deployment: RFC 4511 is BER over a TCP " +
      "socket, so every button on that page is a call to the api and a " +
      "static site has none — client/static_site.js leaves the page, its " +
      "bundle and css/ldap.css out of the build and greys out the landing " +
      "card. Run it against the containerized stack (./docker-run-tests.sh) " +
      "or a local dev server, or set LDAP_AVAILABLE=true for a remote target " +
      "that IS api-backed."
    : null;
  const ldapProtocolSkip = ldapOff
    ? "LDAP is not on this deployment: RFC 4511 is BER over a TCP socket, so " +
      "every operation is a call to the api and a static site has none. This " +
      "job would reach the api at the site's own origin and be answered by " +
      "the object store, so its 404 would name a missing endpoint rather " +
      "than the absent backend it really is. Run it against the " +
      "containerized stack (./docker-run-tests.sh) or a local dev server, or " +
      "set LDAP_AVAILABLE=true for a remote target that IS api-backed."
    : null;
  // SCIM's gate is NOT the LDAP one and must not be derived from it, even
  // though both workflows lean on the same mock. The difference is the whole
  // shape of this page: SCIM is ordinary HTTPS with a JSON body, so
  // `scim.html` calls a SCIM server DIRECTLY from the browser and is on the
  // static deployments — it carries no `data-not-on-static` marker and
  // client/static_site.js does not drop it. What a static target loses is the
  // api call path, which the page reports for itself in the callPath row of
  // its Configuration Parameters pane.
  //
  // So there are two different gates rather than one:
  //
  //   * `scim_protocol.js` needs the api (it drives POST /scim) and the mock's
  //     directory, exactly as the LDAP protocol job does, so it rides
  //     LDAP_AVAILABLE — the same fact, that this target has a backend.
  //   * `scim_page.js` needs neither and runs against a static target, because
  //     the browser call path is the one that exists there. Its own
  //     backend-path section skips itself when the api is absent, which is the
  //     right granularity: the rest of that file is still worth running.
  //
  // Both additionally skip THEMSELVES, with a reason, when the mock STS has no
  // /scim/v2 routes at all — the ordinary state of a checkout whose sts/
  // gitlink predates them. That is deliberately not a gate here: the reason is
  // discovered by asking the server, and it names the submodule rather than
  // the deployment.
  // ------------------------------------------------------------------------
  // SPIFFE's gate is its OWN variable, `SPIFFE_AVAILABLE`, and deriving it
  // from LDAP_AVAILABLE would be the mistake tests/CLAUDE.md records about
  // deriving LDAP's from the Kerberos one. Both workflows are missing from a
  // static deployment for the same underlying reason — a browser cannot speak
  // either protocol, so both need the api — but they are missing
  // INDEPENDENTLY: a remote target could perfectly well be api-backed with a
  // directory reachable and no SPIRE server, or the reverse, and deriving
  // would turn "not this protocol" into a set of skipped jobs about a
  // protocol that is there.
  //
  // It defaults to the LDAP answer only because that is the same question
  // asked of a deployment — "does this target have an api at all" — and a
  // target that is api-backed but has no SPIFFE server sets it false.
  //
  // THE ENGINE JOB IS DELIBERATELY NOT GATED. It needs no api, no mock and no
  // browser: it reads the grammar, the bundle rules, the catalogue against
  // the vendored protos and a certification request against OpenSSL. Gating
  // it would silence the one SPIFFE job that says something true on every
  // target, including the static ones.
  // ------------------------------------------------------------------------
  const spiffeOff = env.SPIFFE_AVAILABLE === "false" ||
    (env.SPIFFE_AVAILABLE === undefined && ldapOff);
  const spiffeSkip = spiffeOff
    ? "SPIFFE is not on this deployment: two of its three surfaces are gRPC " +
      "— HTTP/2 with a binary framing and its status in the trailers — which " +
      "a browser cannot produce at all, so both live in the api and a static " +
      "site has none. client/static_site.js leaves spiffe.html, its bundle " +
      "and css/spiffe.css out of the build and greys the landing card. The " +
      "SPIFFE ENGINE job still runs here and still means something, because " +
      "it needs nothing. Run the rest against the containerized stack " +
      "(./docker-run-tests.sh) or a local dev server, or set " +
      "SPIFFE_AVAILABLE=true for a remote target that IS api-backed."
    : null;
  const scimProtocolSkip = ldapOff
    ? "the SCIM protocol job drives POST /scim on the debugger's api, and a " +
      "static site has no api at all. The SCIM PAGE still runs against such " +
      "a target — SCIM is ordinary HTTPS with a JSON body, so the browser " +
      "calls the server directly — and it is only this backend-path job that " +
      "cannot. Run it against the containerized stack " +
      "(./docker-run-tests.sh) or a local dev server, or set " +
      "LDAP_AVAILABLE=true for a remote target that IS api-backed."
    : null;

  // ------------------------------------------------------------------------
  // SHARED SIGNALS' GATE IS THE SCIM ONE'S SHAPE AND NOT THE LDAP ONE'S, and
  // it is worth saying which of the two it is: SSF's management API, its
  // status, subject, verification and poll endpoints are all ordinary HTTPS
  // with a JSON body, so `ssf.html` calls a transmitter DIRECTLY from the
  // browser and is on the static deployments — it carries no
  // `data-not-on-static` marker and client/static_site.js does not drop it.
  //
  // So the gate covers only the api job. Everything else runs against a
  // static target:
  //
  //   * `api_ssf.js` needs the api, so it rides the same fact LDAP's gate
  //     does — that this target has a backend.
  //   * `ssf_engine.js` needs nothing at all and is never gated.
  //   * `ssf_protocol.js` needs a TRANSMITTER rather than an api, and skips
  //     itself with a reason when there is none.
  //   * `ssf_page.js` needs neither an api nor a browser-side backend: the
  //     browser call path is the one a static site has, and its own callPath
  //     section asserts that the api option is switched OFF there rather than
  //     merely marked — which is the half no other job can see.
  //
  // WHAT A STATIC TARGET REALLY LOSES IS PUSH DELIVERY, and that is RFC 8935
  // rather than a property of this deployment: a browser cannot be an HTTP
  // server, so it cannot be the far end of a push, and with no api there is
  // nothing to host an endpoint on its behalf. POLL delivery needs none of
  // that, and the page says so itself.
  // ------------------------------------------------------------------------
  const ssfApiSkip = ldapOff
    ? "the api's Shared Signals job drives POST /ssf/call and the push " +
      "receiver at POST /ssf/receiver, and a static site has no api at all. " +
      "The SSF ENGINE, PROTOCOL and PAGE jobs still run against such a " +
      "target — SSF's management API is ordinary HTTPS with a JSON body, so " +
      "the browser calls the transmitter directly — and what is genuinely " +
      "lost there is PUSH delivery, because a browser cannot be an HTTP " +
      "server and there is no api to host an endpoint for it. Run this " +
      "against the containerized stack (./docker-run-tests.sh) or a local " +
      "dev server, or set LDAP_AVAILABLE=true for a remote target that IS " +
      "api-backed."
    : null;

  const kerberosPagesSkip = kerberosOff
    ? "the Kerberos pages are not on this deployment: the workflow needs the " +
      "api's port-88 relay, which a static site has not got, so " +
      "client/static_site.js leaves all five pages out of the build and " +
      "greys out the landing card. Run them against the containerized stack " +
      "(./docker-run-tests.sh) or a local dev server."
    : null;

  {
    const decoderJob = {
      name: "Kerberos Decoder page (wiring, hostile input as text, in-browser decryption)",
      script: "kerberos_decoder_page.js",
      env: {},
    };
    if (kerberosPagesSkip) decoderJob.skip = kerberosPagesSkip;
    jobs.push(decoderJob);
  }

  // The Kerberos relay (api/krb5_relay.js, api/krb5_frame.js) behind POST
  // /krb5/kdc. This is the most important test in phase 2, for a specific reason:
  // api/ssrf_guard.js is installed on the shared AXIOS instance, and a raw
  // `net.connect` walks past all of it — so the relay is a SECOND enforcement of
  // the same address policy for a transport the guard has never seen.
  //
  // It is also a broader primitive than anything this service had before: it
  // carries caller-supplied bytes to a caller-supplied host and port. An HTTP
  // fetcher aimed at port 22 gets nothing; a byte relay aimed at port 22 is a port
  // scanner with a payload of the caller's choosing. Four things bound it and all
  // four are tested: the shared address policy, resolve-then-connect-to-the-literal,
  // a port allowlist (new with this endpoint), and a message-shape pre-flight that
  // runs before any socket opens.
  //
  // The assertion that earns its keep most is the same one api_connect_timeout.js
  // makes for the HTTP side: a host that CONNECTS AND THEN SAYS NOTHING must be
  // given until callTimeout, not killed at connectTimeout. That fails against an
  // implementation expressing both deadlines with one timer, which is the natural
  // way to write it. Mutation-tested: eight deliberate defects, all caught.
  // Node only, never skipped.
  jobs.push({
    name: "Kerberos relay (address policy on raw sockets, port allowlist, pre-flight, limits)",
    script: "api_krb5_relay.js",
    env: {},
  });

  // The AS exchange end to end: the wallet-side codec (common/krb5) against the
  // mock KDC (the sts/ submodule), over a real socket, through the api's relay. It
  // starts the KDC in-process on an ephemeral port, so it needs no docker and no
  // running service.
  //
  // This is the first test that puts a CLIENT and a KDC on opposite ends of a wire
  // and makes them agree — a different claim from the vector tests, because the two
  // disagree in ways neither can detect alone: a key usage number one folds in and
  // the other does not, a salt one derives from the principal name and the other
  // from configuration, a nonce one echoes and the other regenerates. It is still
  // NOT proof of interoperability: both ends are this repository's code, and the
  // interoperability evidence is the MIT krb5 / Samba AD exchange in phase 4.
  //
  // Most of it is the negative half, which is the product: KDC_ERR_ETYPE_NOSUPP to
  // an RC4-only client against a hardened account (the 2026 case), a locked
  // account, an expired password, a wrong salt reported as PREAUTH_FAILED with
  // ETYPE-INFO2 re-sent so the client can find out, and a clock outside the
  // tolerance. Mutation-tested: nine deliberate defects in the KDC, all caught —
  // including a regenerated nonce, a pre-authent flag set when no pre-authentication
  // happened, and a computer account salted like a user.
  // Node only, never skipped.
  jobs.push({
    name: "Kerberos AS exchange (the codec against the mock KDC: the two-message dance, refusals)",
    script: "krb5_as_exchange.js",
    env: {},
  });

  // The rest of the protocol: TGS then AP, with mutual authentication and
  // per-message tokens. The client is common/krb5; the KDC and the protected service
  // are the sts/ submodule's, started in-process on ephemeral ports so this needs no
  // docker and no running service.
  //
  // The AS test gets a TGT, which is the easy half. This one is a ticket being
  // PRESENTED to something that decrypts it, checks it, and proves itself back —
  // until something does that, "the ticket looks right" is the strongest claim
  // available about any of it.
  //
  // Four things here fail in ways nothing else catches: a TGS-REQ carries the TGT
  // inside a PA-TGS-REQ whose value is an entire AP-REQ, whose Authenticator
  // checksums the ENCODED request body (re-encode it and the checksum covers
  // something else); the TGS-REP is at key usage 8 or 9 depending on whether a subkey
  // was sent, and both paths are exercised; the 0x8003 checksum is not a checksum and
  // its integers are LITTLE-endian; and mutual authentication is an ECHO that has to
  // be CHECKED, not merely requested.
  //
  // It found a real bug on its first run: KerberosTime carries no fractional seconds,
  // so the wire ctime is truncated to the second and the client was comparing the
  // AP-REP's echo against a millisecond-precision Date — accusing a correct service
  // of not being itself.
  //
  // The negatives are the point: a replayed Authenticator, a ticket for the wrong
  // service, a stale key version, a request body swapped after signing, a clock
  // outside the tolerance, a checksum that is not 0x8003, and a forged echo.
  // Mutation-tested: the KDC's checksum check, the service's replay cache, its
  // ticket-is-for-me check, and the 0x8003 byte order — all caught.
  //
  // Phases 4 and 5 grew it well beyond its name, because each addition needs the live
  // exchange rather than a fixture:
  //
  //  * **the PAC the KDC actually minted**, in BOTH kinds of ticket. In a TGT the service
  //    key and the krbtgt key are the same key, so a KDC using the wrong one for the
  //    server signature passes every TGT test ever written and issues service tickets no
  //    Windows service accepts. Only the service ticket separates them.
  //  * **cross-realm referrals**, chased end to end: a referral is an ordinary successful
  //    TGS-REP whose `sname` is not what was asked for, and a client that does not compare
  //    those two presents a ticket-granting ticket to a web server. The PAC is re-signed by
  //    the target realm, and the test proves the OLD signatures no longer verify — if they
  //    did, nothing had been re-signed.
  //  * **S4U2Self and S4U2Proxy, authorized both ways**: classic constrained delegation
  //    (`msDS-AllowedToDelegateTo` on the front end) and RBCD (`msDS-AllowedToActOn-
  //    BehalfOfOtherIdentity` on the back end), with the asymmetries that make RBCD the
  //    easier path — and five refusals, without which the successes prove nothing.
  //  * **renewals**, which preserve authtime and cap at renew-till. That test contains the
  //    only deliberate sleep in the file: KerberosTime has one-second resolution and the
  //    test runs inside one second, so without a clock boundary a KDC that reset authtime
  //    on renewal produced an identical value and the mutation went undetected.
  //
  // Thirty-three further mutations were used to develop those sections and all thirty-three
  // fail them. Four were caught only after the test was strengthened, each a real gap: a
  // realm-aware principal lookup that needed a client NATIVE to the second realm, a PAC
  // domain SID nothing asserted, the delegation flag that is invisible where it is set, and
  // a vacuous authtime comparison that compared a value with itself.
  // Node only, never skipped.
  jobs.push({
    name: "Kerberos TGS + AP, the PAC, cross-realm referrals, S4U delegation and renewals",
    script: "krb5_tgs_ap.js",
    env: {},
  });

  // The Kerberos codec exists TWICE — common/krb5 for the browser and the api, and
  // a vendored copy in the sts/ submodule for the KDC, because compose builds that
  // service with `context: ./sts` and a Docker build cannot COPY from outside its
  // context. This is the test that makes that safe.
  //
  // A file comparison alone would not be enough. The failure mode of a vendored
  // wire codec is not "one copy is broken" — it is that BOTH copies are
  // self-consistent and disagree only with each other, each one's own tests
  // passing, and the symptom is an integrity failure indistinguishable from a wrong
  // password. So the copies are cross-checked behaviourally: messages built by one
  // and read by the other, and — the assertion nothing else can make — one copy
  // ENCRYPTS and the other DECRYPTS. Then the files are compared too, which catches
  // drift before it has consequences and names the one command that fixes it
  // (common/krb5/sync-to-mock-sts.sh).
  //
  // Proved against five real drift scenarios, each caught by a different assertion:
  // a key usage number, a MAC over the ciphertext instead of the plaintext, a
  // context tag, a comment-only edit, and a reader silently dropping a field.
  // With the submodule uninitialised it says so and passes — an uninitialised
  // submodule is an EMPTY DIRECTORY, and reporting that as a codec failure sends
  // somebody looking in the wrong place. Node only, never skipped.
  jobs.push({
    name: "Kerberos codec sync (common/krb5 against the mock STS's vendored copy, cross-wise)",
    script: "krb5_codec_sync.js",
    env: {},
  });

  // SPNEGO's codec (common/krb5/krb5_spnego.js), byte by byte. Node only, no
  // browser and no services, and it never skips.
  //
  // Every value it asserts is derived by hand from RFC 4178 section 4 and from
  // the OIDs' own registrations rather than from what the encoder produces,
  // because a reader and a writer sharing one misunderstanding agree perfectly
  // with each other and with nothing else. Four things earn it its keep: the
  // OID coder (SPNEGO is the first thing here that has to write one — Kerberos's
  // own ASN.1 contains no OBJECT IDENTIFIER at all, and Microsoft's mis-typed
  // Kerberos OID differs from the real one in a single arc); that the
  // mechListMIC covers `MechTypeList` and NOT `[0] MechTypeList`, which is two
  // bytes and the commonest mistake in this protocol; that a `[3]` is a MIC in
  // RFC 4178 and negHints in [MS-SPNG]'s NegTokenInit2, told apart by what is
  // inside rather than by the direction of travel; and that negState is
  // ENUMERATED rather than INTEGER, which encode identically apart from the tag
  // so a coder using the wrong one round-trips against itself perfectly and is
  // refused by a strict peer.
  jobs.push({
    name: "SPNEGO codec (RFC 4178's NegTokenInit and NegTokenResp, byte by byte)",
    script: "krb5_spnego_codec.js",
    env: {},
  });

  // SPNEGO over HTTP end to end: RFC 4559 carrying RFC 4178 carrying RFC 4121
  // carrying an AP-REQ. Node only — the mock KDC and the mock's Express app are
  // started in-process on ephemeral ports — so it never skips.
  //
  // The NEGATIVES are the substantial half, deliberately: an acceptor that
  // authenticates a good client looks finished and is worth very little. Ten of
  // them, and the two that nothing else could catch are a mechListMIC computed
  // over the `[0]`-tagged list (the ticket is perfect and the request is
  // refused) and an edited mechanism list (everything else about the request is
  // valid, which is exactly why the MIC is the only thing that can notice —
  // that is the downgrade RFC 4178 section 5 exists to stop). The rest: no
  // mechanism in common in both directions, a list with no token answered
  // accept-incomplete rather than reject, a tampered MIC, a replayed AP-REQ, a
  // ticket for another service, a TGT presented as one, a Basic Authorization
  // header, bytes that are not a token, and a continuation with nothing to
  // continue. Each asserts WHICH check fired, not merely that something was
  // refused — and the ones carrying a KRB-ERROR assert the error code inside
  // the responseToken, because SPNEGO's negState has no reason field at all and
  // an acceptor that swallows the mechanism's error leaves a rejection
  // indistinguishable from a wrong password.
  jobs.push({
    name: "SPNEGO over HTTP (the handshake, and the ten negatives that make an acceptor worth anything)",
    script: "krb5_spnego_http.js",
    env: {},
  });

  // The Ticket Cache & History pane, on all five Kerberos pages. Node only:
  // the pane is markup and needs a browser, but what it STORES is a hundred
  // session keys and that is checkable without one. The assertion that matters
  // is that unticking krb_save_ccache purges the whole list —
  // enforceStoragePreference() names each key it removes, so a key added later
  // is forgotten there by
  // default, and the symptom would be an opt-out that quietly keeps a hundred
  // credentials. The rest is where an activated ticket LANDS (a service ticket
  // in the TGT slot is accepted silently and fails a page later) and the
  // static wiring: every page includes the partial, mounts it once, mounts
  // only the slots it holds, and the decoder mounts it read-only.
  jobs.push({
    name: "Kerberos ticket cache & history (credential store, slots, the " +
        "opt-out purge, and the wiring on all five pages)",
    script: "krb5_ticket_history.js",
    env: {},
  });

  // The Operations History pane, on all five Kerberos pages. Node only, and
  // deliberately: the half of this that a browser test could not catch is the
  // static one. A row is opened when an operation starts and closed by the
  // status line that operation named, so a page that opens a row against a line
  // it never writes a terminal status to leaves every one of those operations
  // reading "Sent" — a legitimate-looking value meaning "the far end never
  // answered". The pane renders, the row is there, and nothing looks wrong. So
  // this checks, per bundle, that every line an operation is opened against has
  // both a success and a failure path; that all five pages include the partial
  // AND mount it against the partial's own ids (a page that includes it and
  // never mounts shows an empty div, which looks exactly like a workflow that
  // has done nothing); and that the classes op_history.js renders with this
  // workflow's prefix are defined in css/kerberos.css, since its defaults are
  // the saml-* ones and these pages do not load that stylesheet.
  jobs.push({
    name: "Kerberos operations history (the log, and the wiring on all five " +
        "pages)",
    script: "krb5_operation_history.js",
    env: {},
  });

  // The byte ranges the hex tab on the AS exchange page colours with. Node
  // only, no browser: the arithmetic is in common/krb5/krb5_ranges.js precisely
  // so it can be checked without one, and an offset that is relative rather
  // than absolute does not crash — it highlights the wrong bytes, plausibly.
  jobs.push({
    name: "Kerberos byte ranges (absolute offsets for the hex view)",
    script: "krb5_ranges_offsets.js",
    env: {},
  });

  // The NAMES on those bytes, and the wiring that puts the view on a page.
  // Node only, and the same reasoning: a tag mapped to the wrong field does not
  // crash, it says `till` while highlighting `rtime`. Half the file is static —
  // a hex pane nothing fills, or a tab strip nothing wires, renders empty,
  // which is what a page looks like before an exchange has been run.
  jobs.push({
    name: "Kerberos field names (RFC 4120 names on the hex view's bytes)",
    script: "krb5_field_naming.js",
    env: {},
  });

  // Delegation, run TWICE — once per KDC — because that is the only way a
  // divergence between the mock and Active Directory becomes visible.
  //
  // tests/krb5_tgs_ap.js already drives S4U against the mock, and harder: it
  // forges tickets and swaps keys, which no real domain controller can be asked
  // to do. But it only ever asks the mock, and the mock was written from the
  // same reading of [MS-SFU] as the client it checks — so a shared misreading
  // shows up in neither. These two jobs run ONE set of assertions against both,
  // so the same assertion failing on one and passing on the other is the
  // finding.
  //
  // The mock half needs nothing (in-process KDC on an ephemeral port). The
  // Windows half needs a domain controller and is skipped without one, on the
  // same terms as krb5_real_dc.js: it costs money and no launcher starts it.
  {
    const delegationIdps = [
      { key: "mock", label: "mock KDC", skip: null, env: {} },
      {
        key: "windows",
        label: "real Windows KDC",
        skip: env.KRB5_DC_JSON ? null :
          "no real Windows KDC to delegate against (KRB5_DC_JSON unset). " +
          "The four delegation accounts are provisioned by " +
          "infra/terraform-krb5 and described in the bootstrap's dc.json; " +
          "./infra/krb5-test.sh fetches it and sets this. Not free tier, so " +
          "nothing starts it automatically.",
        env: {
          KRB5_DELEG_TARGET: "windows",
          KRB5_DC_JSON: env.KRB5_DC_JSON,
          KRB5_DC_HOST: env.KRB5_DC_HOST,
          KRB5_DC_PORT: env.KRB5_DC_PORT,
        },
      },
    ];
    for (const idp of delegationIdps) {
      const job = {
        name: "Kerberos delegation — S4U2Self, classic S4U2Proxy, RBCD [" +
          idp.label + "]",
        script: "krb5_delegation_interop.js",
        env: Object.assign({ KRB5_DELEG_TARGET: idp.key }, idp.env),
      };
      if (idp.skip) { job.skip = idp.skip; }
      jobs.push(job);
    }
  }

  // What a real Windows KDC sent, asserted offline. This is the job that keeps
  // the expensive one's evidence alive: tests/krb5_real_dc.js needs a domain
  // controller on EC2 and therefore runs almost never, so its exchange was
  // recorded once (tests/captures/windows-server-2025.json) and is re-checked
  // here on every run with no AWS, no network and no services.
  //
  // It has already earned its place. The capture showed that Windows Server
  // 2025 sends NO s2kparams in ETYPE-INFO2 — it relies on the RFC 3962 default
  // — while the mock KDC always sends one and krb5_as_exchange.js asserts it is
  // there. A client that required the field would pass this whole suite and
  // fail against every real domain, reporting a wrong password. Never skipped:
  // the capture is committed.
  jobs.push({
    name: "Kerberos vectors from a REAL Windows KDC (recorded; salt, refusals, keytab, PAC)",
    script: "krb5_windows_vectors.js",
    env: {},
  });

  // The one Kerberos job that talks to software this project did not write.
  //
  // Every other job in this section — the codec, the crypto vectors, the PAC
  // layout, the AS and TGS exchanges — runs against the mock KDC in the
  // rcbj/mock-sts submodule. The mock was written from the same reading of RFC
  // 4120 and [MS-PAC] as the client it checks, so the two agree by construction
  // and a shared misreading is invisible to all of them. This job is the answer
  // to that, and it is the open risk docs/kerberos.md names.
  //
  // It needs a real Windows Server domain controller, which is what
  // infra/terraform-krb5 stands up and infra/krb5-test.sh drives:
  // apply -> wait for the forest -> run this -> destroy, with the teardown on an
  // EXIT trap so a failed test still removes the instance. The stack is NOT free
  // tier and is not left running, so nothing here starts it — the job is skipped
  // unless KRB5_DC_HOST names one that already exists.
  //
  // The skip names the script rather than the variable, because the variable on
  // its own reads as something a launcher forgot to export, and it is not: no
  // launcher sets it, on purpose.
  {
    const realDcSkip = env.KRB5_DC_HOST ? null :
      "no real Windows KDC to test against (KRB5_DC_HOST unset). This one " +
      "job drives a domain controller on EC2, which costs money and is not " +
      "free tier, so no launcher starts it. Run ./infra/krb5-test.sh, which " +
      "applies infra/terraform-krb5, runs this test and tears the stack down " +
      "again whatever the result.";
    const job = {
      name: "Kerberos against a REAL Windows KDC (AS-REQ, TGS-REQ, ktpass keytab, PAC, AP-REQ)",
      script: "krb5_real_dc.js",
      env: {
        KRB5_DC_HOST: env.KRB5_DC_HOST,
        KRB5_DC_PORT: env.KRB5_DC_PORT,
        KRB5_REALM: env.KRB5_REALM,
        KRB5_USER: env.KRB5_USER,
        KRB5_PASSWORD: env.KRB5_PASSWORD,
        KRB5_SPN: env.KRB5_SPN,
        KRB5_KEYTAB_B64: env.KRB5_KEYTAB_B64,
      },
    };
    if (realDcSkip) { job.skip = realDcSkip; }
    jobs.push(job);
  }

  // The Windows PAC (common/krb5/krb5_pac.js and krb5_ndr.js), which is the structure
  // a Windows service actually authorizes on: a Kerberos ticket proves who you are and
  // says nothing about your group memberships, so "authentication worked and access was
  // denied" is nearly always a question about this.
  //
  // It is also the worst case for self-consistency testing, and the reason this job
  // exists separately from the codec one. The logon information is NDR — [MS-RPCE]'s RPC
  // marshalling, with referent-id pointers and alignment padding — so a reader and a
  // writer that share ONE misunderstanding agree perfectly with each other and with
  // nothing else in the world. Read FILETIME as an 8-aligned 64-bit integer in both
  // halves and every field still round-trips; the two just insert and skip four bytes of
  // padding no real KDC ever wrote. So the assertions are byte offsets counted out of
  // [MS-PAC] section 2.5's field list BY HAND, structures with more than one element
  // (an ExtraSids array defers all its SID pointers past the END of the array, so a
  // reader that follows each as it goes is right for one element and wrong for two), and
  // the four signatures checked SEPARATELY — including the case that matters: altering
  // the PAC's contents breaks the server and extended KDC signatures and leaves the KDC
  // signature verifying, because that one covers only the server signature's bytes. That
  // is the shape of CVE-2022-37967.
  //
  // Eighteen mutations were used to develop it and all eighteen fail it, two of which
  // were real bugs it found: a signed/unsigned comparison that made SE_GROUP_LOGON_ID
  // unmatchable, and a consistency check reading a field one line before it was
  // assigned. Node only, never skipped.
  jobs.push({
    name: "Kerberos PAC (MS-PAC: the NDR layout at hand-derived offsets, and all four signatures)",
    script: "krb5_pac_layout.js",
    env: {},
  });

  // The Kerberos AS exchange PAGE. krb5_as_exchange.js already drives the same
  // exchange with no browser, so this job covers only what needs one: that the
  // bundle is registered in BOTH client/build.js and client/Dockerfile, that the
  // api's CORS allowlist actually lets the page call POST /krb5/kdc (a failure no
  // node test can see, and one that appears as a fetch which never resolves rather
  // than as anything naming CORS), that step 2 is DISABLED until step 1 has learned
  // the salt, that the salt the KDC sent is shown AND used, and that the session key
  // is treated as the credential it is — sessionStorage by default, localStorage
  // only when asked, purged when the box is unticked.
  //
  // Needs the client, the api and the mock STS (which carries the KDC). It SKIPS
  // with a named reason when the KDC is unreachable, because an absent service is an
  // environment fact rather than a defect.
  //
  // Mutation-tested against the built bundle: step 2 enabled from the start, the
  // cache always going to localStorage, the salt field left unfilled, and the purge
  // removed — the last needing BOTH purge paths removed to fail, which is the
  // belt-and-braces arrangement CLAUDE.md prescribes for key material.
  const asPageJob = {
    name: "Kerberos AS exchange page (wiring, CORS, the two-step flow, credential handling)",
    script: "kerberos_as_page.js",
    env: {
      STS_URL: env.STS_URL || "https://localhost:8081",
      // "sts", not "localhost": this value is TYPED INTO THE PAGE and the address is
      // resolved by the API's relay, which runs in the api container — where localhost is
      // the api itself, listening on nothing. The mock KDC's port 88 is not published to
      // the host by any compose file, so the compose service name is the only address
      // that reaches it.
      KRB5_KDC_HOST: env.KRB5_KDC_HOST || "sts",
      KRB5_KDC_PORT: env.KRB5_KDC_PORT || "88",
    },
  };
  if (kerberosPagesSkip) asPageJob.skip = kerberosPagesSkip;
  jobs.push(asPageJob);

  // The TGS and AP exchange pages, and — the part nothing else covers — the CREDENTIAL
  // HANDOFF between all three. The AS page produces a TGT, the TGS page spends it, the
  // AP page presents the result, and they pass those through a shared cache in
  // kerberos_panes.js. Testing the TGS page in isolation would mean fabricating a TGT
  // in storage, which tests the fabrication rather than the workflow — and the handoff
  // is exactly where a rename breaks things silently. One did: a refactor left three
  // sites calling removeItem(KEYS.CCACHE) after the shared module renamed the key to
  // KEYS.TGT, so removeItem(undefined) deleted a key called "undefined" and the
  // storage opt-out quietly stopped purging a session key.
  //
  // Browser-only assertions: the TGS button is ENABLED once a TGT is held (the markup
  // ships it disabled, so that direction is the one proving the page read the cache);
  // the page reports key usage 8 without a subkey and 9 with one; the issued ticket is
  // NOT flagged `initial`; the AP page decodes the 0x8003 checksum field by field
  // including that its integers are little-endian and that Bnd is sixteen ZERO bytes
  // rather than absent; mutual authentication reads CONFIRMED only when the echo was
  // checked; per-message tokens are keyed from the ACCEPTOR's subkey; and unticking
  // MUTUAL says plainly that nothing has proved the service's identity.
  //
  // Needs the client, the api, the mock STS (KDC and protected service) AND the api's
  // krb5ServicePorts set — POST /krb5/service is off by default. It skips with a named
  // reason for each of those, because a disabled capability is a configuration fact
  // rather than a defect.
  const tgsApPageJob = {
    name: "Kerberos TGS + AP pages (the credential handoff, 0x8003, mutual auth, per-message tokens)",
    script: "kerberos_tgs_ap_page.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "https://localhost:8081",
      KRB5_KDC_HOST: env.KRB5_KDC_HOST || "sts",
      KRB5_KDC_PORT: env.KRB5_KDC_PORT || "88",
      KRB5_SERVICE_HOST: env.KRB5_SERVICE_HOST || "sts",
      KRB5_SERVICE_PORT: env.KRB5_SERVICE_PORT || "8888",
    },
  };
  if (kerberosPagesSkip) tgsApPageJob.skip = kerberosPagesSkip;
  jobs.push(tgsApPageJob);

  // The SPNEGO page, and the two pages a user is ROUTED THROUGH to feed it.
  // krb5_spnego_http.js already drives the protocol harder than this does with
  // no browser, so this job covers only what needs one:
  //
  //  * **the routing loop**, which is the whole reason this is a workflow. The
  //    SPNEGO page cannot obtain a ticket — that is the AS page and then the
  //    TGS page — so it sends the user out with `?return=spnego` and each of
  //    them offers a link back. This walks the loop: out, on to the TGS page
  //    with the SPN carried in the query, and back through the banner's own
  //    link. Nothing about the protocol notices when that breaks.
  //  * **the banner BEFORE a ticket exists**, which is the case it is for and
  //    the one an implementation puts after an early return and never renders.
  //    That happened here once already.
  //  * **the credential handoff** under a third reader of kerberos_panes.js's
  //    shared cache. A rename there is silent: the pane renders, the button
  //    stays disabled, and the page says "no service ticket held" for a ticket
  //    that is sitting in storage.
  //  * **the SPN the page guesses** from the URL's host, which nothing in the
  //    SPNEGO exchange carries — when it is wrong the failure is a KDC error
  //    three steps earlier naming nothing about HTTP, so the field has to
  //    exist, be pre-filled and be overridable.
  //  * **the panes**: the decoded NegTokenInit and what its mechanism ORDER
  //    decides, the AP-REQ inside it, the 0x8003 checksum, the hex view naming
  //    a field and its absolute offset under the pointer, and the ticket —
  //    which is opaque until a service key is supplied and must SAY so rather
  //    than rendering an empty pane. Supplying the key opens the EncTicketPart
  //    and the PAC, which is the structure a client can never see in its own
  //    ticket.
  //
  // And three negatives through the UI, each a deliberate misconfiguration the
  // mock offers as a query parameter: an acceptor with no mechanism in common,
  // a client offering only a mechanism this build cannot perform, and a server
  // that accepts the ticket and proves nothing back.
  //
  // Needs the client, the api and the mock STS (its KDC and its
  // SPNEGO-protected page). Unlike the AP page it needs no extra api setting —
  // POST /krb5/spnego is an ordinary outbound HTTP call rather than a byte
  // relay to an arbitrary port. It skips with a named reason for each missing
  // piece, including an api or a mock that predates the workflow.
  const spnegoPageJob = {
    name: "SPNEGO page (the routing loop, the handshake, the ticket, and three refusals)",
    script: "kerberos_spnego_page.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "https://localhost:8081",
      KRB5_KDC_HOST: env.KRB5_KDC_HOST || "sts",
      KRB5_KDC_PORT: env.KRB5_KDC_PORT || "88",
      // The URL the API — not the browser — fetches, so it is the api's view of
      // the mock that matters. On the containerized stack that is the compose
      // name; STS_URL is browser-facing and follows a different rule (see
      // tests/CLAUDE.md on WSFED_STS_METADATA_URL), which is why this is its
      // own variable rather than derived.
      KRB5_SPNEGO_URL: env.KRB5_SPNEGO_URL ||
        (env.KRB5_SPNEGO_HOST ? "http://" + env.KRB5_SPNEGO_HOST +
          "/spnego/protected" : "https://sts:8081/spnego/protected"),
    },
  };
  if (kerberosPagesSkip) spnegoPageJob.skip = kerberosPagesSkip;
  jobs.push(spnegoPageJob);

  // ---------------------------------------------------------------------
  // KERBEROS AS A WAY OF SIGNING IN, which is the door the job above does not
  // touch.
  //
  // `/spnego/protected` authenticates a person and throws the identity away.
  // `/authn/spnego` is the same handshake with the last step added: past it
  // there is a browser SESSION on that service, and `/oauth2/authorize`,
  // `wsignin1.0`, a SAML AuthnRequest and `/admin` all read it. Nothing in
  // either repository drove that door until 2026-08-27 — it shipped on
  // 2026-08-26, was hand-verified once against a throwaway instance, and the
  // driver that did it was a scratch script nobody kept.
  //
  // The job drives the debugger's own AS, TGS and SPNEGO pages to build the
  // service ticket, spends it at the door, and then runs an ordinary OIDC
  // Authorization Code flow on the session that comes back — with `amr` and
  // `acr` read off the TICKET'S OWN FLAGS, which is the one place in that
  // service where those claims are derived from a credential rather than from
  // what somebody ticked on a screen.
  //
  // THE BROWSER DOES NOT ANSWER THE CHALLENGE, and the file's header says so
  // at length: RFC 4559 is answered from GSSAPI, which needs a credential cache
  // and an `--auth-server-allowlist` entry that this suite cannot assume. The
  // debugger is the Kerberos client instead, which shows more of the protocol
  // than a browser handing the work to GSSAPI ever would.
  //
  // Same gate and same three variables as the page job above, plus the OAuth
  // client it registers before the flow starts.
  const spnegoSignInJob = {
    name: "SPNEGO sign-in (a Kerberos ticket becomes a session, and an OIDC " +
        "flow completes on it)",
    script: "kerberos_spnego_signin.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "https://localhost:8081",
      KRB5_KDC_HOST: env.KRB5_KDC_HOST || "sts",
      KRB5_KDC_PORT: env.KRB5_KDC_PORT || "88",
      KRB5_REALM: env.KRB5_REALM || "EXAMPLE.COM",
    },
  };
  if (kerberosPagesSkip) spnegoSignInJob.skip = kerberosPagesSkip;
  jobs.push(spnegoSignInJob);

  // ---------------------------------------------------------------------
  // THE MOCK KDC, DRIVEN BY MIT KERBEROS ITSELF.
  //
  // Every other Kerberos job here — including the two above — drives that KDC
  // with a client this project wrote, and not one of them can answer the
  // question this one exists for: does any of it interoperate with a real
  // Kerberos? The answer was NO until 2026-08-27, for as long as the mock KDC
  // had existed, and nothing noticed: its KDC_ERR_PREAUTH_REQUIRED named the
  // salt without naming the METHOD, so `kinit` could not authenticate and no
  // browser could ever have signed in with Kerberos. Both ends of every test
  // shared the assumption, so every test passed.
  //
  // NO BROWSER. It is `kinit`, `klist`, `kvno`, `kdestroy` and
  // `curl --negotiate`, and it writes its own krb5.conf and credential cache
  // under the system temp directory — so it needs no root, does not touch
  // /etc/krb5.conf, and cannot disturb a Kerberos setup the machine already
  // has.
  //
  // It SKIPS with a named reason where MIT Kerberos is absent or curl was
  // built without GSS-API, which is most developer machines.
  // `tests/Dockerfile` installs `krb5-user`, so the containerized suite always
  // runs it — which is where this needs to be true.
  // **NOT gated on `kerberosPagesSkip`**, and that is deliberate rather than an
  // omission. That gate is about a deployment having the Kerberos PAGES — the
  // api's port-88 relay and the five pages a static build drops — and this job
  // uses neither: it talks to the mock's KDC over its own socket and to its
  // HTTP doors with curl. Gating it there would skip the one job that can find
  // an interoperability defect on precisely the targets where the mock is
  // still reachable. Its own preconditions() decides, and says which of the
  // four things was missing.
  jobs.push({
    name: "Kerberos with the REAL client (kinit, klist, kvno, kdestroy, " +
        "curl --negotiate against the mock KDC)",
    script: "krb5_mit_client.js",
    env: {
      STS_URL: env.STS_URL || "https://localhost:8081",
      // KRB5_TEST_* AND NOT KRB5_KDC_HOST, which every job above carries —
      // the same split SPIFFE_TEST_* draws against SPIFFE_*, and the one
      // this variable's own note further up already names as the mistake to
      // avoid. Those jobs TYPE the address into a page and the api's relay
      // resolves it, so `sts` is right on both stacks. This one has no page
      // and no relay: `kinit` opens the socket out here, in the test's own
      // process, where on a host launcher `sts` resolves to nothing and MIT
      // answers `Cannot contact any KDC for realm 'EXAMPLE.COM'` — which is
      // exactly what it did on 2026-08-27, the first run after this job
      // existed, against a KDC that was up. So the default is this
      // process's view, and run-tests-in-container.sh overrides it to the
      // compose name for the bridge stack, as it does STS_URL.
      KRB5_TEST_KDC_HOST: env.KRB5_TEST_KDC_HOST || "localhost",
      KRB5_TEST_KDC_PORT: env.KRB5_TEST_KDC_PORT || "88",
      KRB5_REALM: env.KRB5_REALM || "EXAMPLE.COM",
    },
  });

  // ---------------------------------------------------------------------------
  // LDAP. Two jobs, and the split between them is the same one the Kerberos
  // family has: the protocol has no browser in it, and the page has no protocol
  // in it.
  //
  // `api_ldap.js` drives the eight POST /ldap/* endpoints against the mock's
  // embedded directory over a real TCP socket, with no browser. It covers the
  // ten operations the workflow exists for and, more usefully, the three things
  // a happy-path test would pass without: that an LDAP RESULT CODE IS NOT AN
  // HTTP ERROR (a noSuchObject is a completed round trip whose answer was no,
  // and answering 500 for it would put the most useful half of this workflow
  // behind an error page); that a one-level search is not silently answered as
  // a subtree one (a wrong scope returns a SUPERSET, so every assertion about
  // the contents still holds and only the count differs — it has already
  // happened once in the mock, where ldapjs spells the scopes `single` and
  // `subtree` rather than `one` and `sub`); and that membership is a modify on
  // the GROUP, asserted from both ends, because an implementation that got one
  // direction right and the other backwards looks correct until somebody asks
  // the other question.
  //
  // It also checks the two properties of the mock directory that the debugger
  // teaches: a bind succeeds with any password except the literal `invalid`, so
  // result code 49 stays reachable; and deleting a user does NOT remove it from
  // the groups that list it, because referential integrity is a directory
  // feature and not a protocol rule. And the auto-created user: authenticating
  // to the mock through ANY protocol grows an entry under ou=users, which is one
  // hook on admin_stats.recordAuthentication() and therefore cheap to break.
  //
  // Every name it creates is unique per run — the mock's directory lives for the
  // life of its process, so a fixed uid would be entryAlreadyExists on the
  // second run and the test would only pass against a freshly started service.
  //
  // It also runs bind, add a user, add a group, join the group and modify the
  // user AGAINST THE SECOND SOCKET, LDAPS on 636, and then reads the result back
  // over 389. The mock registers one set of handlers on two ldapjs server objects
  // — that library chooses a net.Server or a tls.Server at construction, so TLS
  // cannot be a flag on one server — and the defect that invites is a handler on
  // one instance and not the other, which presents as an operation that works in
  // the clear and fails over TLS and is read as a TLS fault. The cross-socket read
  // is the assertion: everything else in that section would pass equally against
  // two separate directories sharing a base DN. It also pins that TLS did not make
  // the password checked (every bind still succeeds, "invalid" is still 49) and
  // that the api still VERIFIES certificates by default — every LDAPS call passes
  // rejectUnauthorized: false, so without that negative an api which had stopped
  // verifying would look identical.
  //
  // Needs the api and the mock STS. No browser. LDAP_URL is the API's view of
  // the directory rather than this test's or the browser's, which on the
  // containerized stack are three different names — it is its own variable for
  // the same reason KRB5_SPNEGO_URL is. There is deliberately NO LDAPS_URL here:
  // the test builds it from LDAP_URL's host and the port the mock says its LDAPS
  // socket actually bound, so a host run that moved it to 1636 needs no change on
  // this side. Setting LDAPS_URL in the environment still overrides the whole of
  // it, and the LDAPS section skips with its own reason when 636 never bound —
  // which is the ordinary outcome of a host run that is not root.
  const ldapProtocolJob = {
    name: "LDAP protocol (bind, add, modify, delete, search, compare, the " +
        "same five over LDAPS, and what a result code is)",
    script: "api_ldap.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "https://localhost:8081",
      LDAP_URL: env.LDAP_URL || "ldap://sts:389",
      LDAP_BASE_DN: env.LDAP_BASE_DN || "dc=example,dc=com",
      LDAP_BIND_DN: env.LDAP_BIND_DN || "cn=admin,dc=example,dc=com",
      LDAP_PASSWORD: env.LDAP_PASSWORD || "password!",
    },
  };
  if (ldapProtocolSkip) ldapProtocolJob.skip = ldapProtocolSkip;
  jobs.push(ldapProtocolJob);

  // The PAGE, which covers the four things that only exist in a browser and
  // every one of which is a way for this workflow to be broken while the
  // protocol is perfect:
  //
  //  * the DNs the shorthand panes BUILD from four fields. Nothing in the
  //    protocol notices a wrong composition — the operation simply happens
  //    somewhere else and succeeds — so the page previews both and the test
  //    reads the preview as well as the outcome.
  //  * that membership is a modify on the GROUP, asserted against the request
  //    the page built rather than only against the result. Putting the change
  //    on the user looks right until somebody reads the group.
  //  * that the four search presets FILL THE FIELDS rather than running a
  //    hidden query. The filter is the thing worth reading, especially the one
  //    nobody guesses: the groups a user is in are found by searching the
  //    GROUPS for a `member` value naming the user, because there is no
  //    attribute on the user to read.
  //  * that a refusal is shown as a RESULT and logged as a Failure, while a
  //    row that stays `Sent` means the api never answered — the two states
  //    people most often confuse.
  //
  // Plus the one credential rule nothing else can see: the password is never
  // written to localStorage, while every other field on the page is. And the
  // stylesheet check tests/navigation.js makes for the pages it walks, repeated
  // here because it cannot walk to this one (see the gate below).
  const ldapPageJob = {
    name: "LDAP page (the DNs it builds, the presets, the modify that is " +
        "membership, and what it remembers)",
    script: "ldap_page.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "https://localhost:8081",
      LDAP_URL: env.LDAP_URL || "ldap://sts:389",
      LDAP_BASE_DN: env.LDAP_BASE_DN || "dc=example,dc=com",
      LDAP_BIND_DN: env.LDAP_BIND_DN || "cn=admin,dc=example,dc=com",
      LDAP_PASSWORD: env.LDAP_PASSWORD || "password!",
    },
  };
  if (ldapPagesSkip) ldapPageJob.skip = ldapPagesSkip;
  jobs.push(ldapPageJob);

  // ------------------------------------------------------------------------
  // SCIM 2.0 — three jobs, split by what each one NEEDS rather than by what it
  // covers. That split is the point: a failure in the first names a field, a
  // failure in the second names a server, and a failure in the third names a
  // page. Collapsing them would make every SCIM defect present as the same
  // thing.
  // ------------------------------------------------------------------------

  // THE ENGINES, with no server and no browser. It needs NOTHING — not the
  // api, not the mock, not Chrome — so it is never gated and never skipped,
  // and it is the one SCIM job that runs on every target including the static
  // ones. It asserts the endpoint catalogue against RFC 7644's own list, the
  // generator against every optional attribute RFC 7643 section 4.1 defines,
  // the Digest credential against the arithmetic node's crypto produces (which
  // is what the mock uses), the length-prefixed HOBA blob, and every refusal
  // the api's SCIM proxy can produce.
  //
  // It is FIRST of the three deliberately: a broken request builder makes the
  // other two fail in ways that look like a broken server.
  jobs.push({
    name: "SCIM engines (the endpoint catalogue against RFC 7644, every " +
        "optional attribute RFC 7643 defines, the Digest and HOBA " +
        "credentials, the scenario planner, and the api proxy's refusals)",
    script: "scim_engine.js",
    env: {},
  });

  // THE PROTOCOL, through the api at the mock, then read back out of the
  // DIRECTORY the mock wrote to. That second read is why this job exists at
  // all: a SCIM 201 says the request was accepted, and only the directory says
  // what was stored — so a field accepted and silently dropped, which is the
  // most common real defect in a provisioning integration, is visible here and
  // nowhere else.
  //
  // It also exercises all six RFC 7644 section 2 authentication schemes and
  // the scope policy. Two of the six skip with a reason rather than passing
  // vacuously: a session cookie needs a browser that has signed in, and a
  // client certificate is chosen in a TLS handshake the api would make with
  // its OWN key.
  //
  // SCIM_BASE_URL is the API's view of the mock rather than this test's — the
  // same distinction LDAP_URL draws above, and on the containerized stack a
  // different answer. It is its own variable for exactly that reason.
  const scimProtocolJob = {
    name: "SCIM protocol (every endpoint through the api, every optional " +
        "attribute checked in the directory, and all six authentication " +
        "schemes)",
    script: "scim_protocol.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "https://localhost:8081",
      SCIM_BASE_URL: env.SCIM_BASE_URL || "https://sts:8081/scim/v2",
      LDAP_URL: env.LDAP_URL || "ldap://sts:389",
      LDAP_BASE_DN: env.LDAP_BASE_DN || "dc=example,dc=com",
      LDAP_BIND_DN: env.LDAP_BIND_DN || "cn=admin,dc=example,dc=com",
      LDAP_PASSWORD: env.LDAP_PASSWORD || "password!",
    },
  };
  if (scimProtocolSkip) scimProtocolJob.skip = scimProtocolSkip;
  jobs.push(scimProtocolJob);

  // THE PAGE, which covers only what needs a browser — and unlike the LDAP
  // page job it is NOT gated on the api, because the browser call path is the
  // one the static deployments have and the one no other job exercises. Five
  // things live here and nowhere else: that browser-direct call, the DPoP
  // proof and the HOBA key signed with Web Crypto (scim_protocol.js signs with
  // node's crypto, a different implementation), the two schemes that lock the
  // call path because the api can carry neither, the scenario runner actually
  // running, and what does and does not reach localStorage.
  //
  // SCIM_BROWSER_URL is the BROWSER's view of the mock — a third answer again,
  // and the one that has cost this suite a run before on the LDAP and SPNEGO
  // workflows.
  jobs.push({
    name: "SCIM page (the browser call path the hosted site depends on, the " +
        "credentials signed with Web Crypto, the scenario runner, and what " +
        "it remembers)",
    script: "scim_page.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "https://localhost:8081",
      SCIM_BROWSER_URL: env.SCIM_BROWSER_URL ||
          (env.STS_URL || "https://localhost:8081") + "/scim/v2",
    },
  });

  // ------------------------------------------------------------------------
  // SHARED SIGNALS (SSF 1.0) — four jobs, split by what each one NEEDS rather
  // than by what it covers, which is the division the SCIM three make and for
  // the same reason: a failure in the first names a RULE, in the second a
  // TRANSMITTER, in the third the api's own contract, and in the fourth a
  // PAGE. Collapsing them would make every SSF defect present as the same
  // thing.
  //
  // SSF_TRANSMITTER_URL is the BROWSER's view of the transmitter, and it is
  // its own variable for the reason SCIM_BROWSER_URL is: the test's view, the
  // api's view and the browser's view of the same service are three different
  // answers on the containerized stack, and confusing them has cost this
  // suite a run before on the LDAP and SPNEGO workflows.
  // ------------------------------------------------------------------------

  // THE ENGINES, with no transmitter and no browser. It needs NOTHING — not
  // the api, not the mock, not Chrome — so it is never gated and never
  // skipped, and it is the one SSF job that runs on every target including
  // the static ones.
  //
  // It is FIRST of the four deliberately: the defects this protocol actually
  // produces are never crashes — a subject identifier with an extra member, an
  // `exp` on a SET, `events_requested` read back as `events_delivered`, a
  // delivery method spelt `push` rather than `urn:ietf:rfc:8935` — and every
  // one of them produces a workflow that works perfectly against itself. A
  // broken one makes the three below fail in ways that look like a broken
  // transmitter.
  //
  // It also signs a SET with one algorithm from every family jws.js offers,
  // POST-QUANTUM INCLUDED, which is where the ML-DSA and SLH-DSA paths
  // through this workflow's own envelope are exercised at all.
  jobs.push({
    name: "SSF engines (all eight RFC 9493 subject formats and the complex " +
        "subject, the RFC 8417 envelope signed with every algorithm family " +
        "including the post-quantum ones, stream configurations, both " +
        "deliveries, and every refusal the api's proxy and push receiver " +
        "make)",
    script: "ssf_engine.js",
    env: {},
  });

  // THE PROTOCOL, against a real transmitter, with no browser. Its value is
  // that the mock has its OWN RFC 9493 grammar — written independently, the
  // argument common/pq_jose.js makes over there applied to a grammar — so
  // this job drives ONE reading of that specification against ANOTHER over
  // the wire. If both ends shared an implementation, a misunderstanding they
  // shared would be one neither could see.
  //
  // It is almost entirely NEGATIVES, which is the rule tests/CLAUDE.md states
  // for the mock-driving family, and it hosts an RFC 8935 endpoint OF ITS OWN
  // so that push delivery is exercised end to end — SSF_RECEIVER_HOST is the
  // name the TRANSMITTER has to reach this test by, which on the
  // containerized stack is the tests container's compose name.
  jobs.push({
    name: "SSF protocol (discovery, the two scopes, the whole stream " +
        "lifecycle, every subject format across the wire against a " +
        "separately written grammar, what a pause keeps that a disable " +
        "drops, poll and push end to end, and both deliberate defects)",
    script: "ssf_protocol.js",
    env: {
      WSTRUST_STS_URL: env.WSTRUST_STS_URL || "https://localhost:8081",
      SSF_RECEIVER_HOST: env.SSF_RECEIVER_HOST || "localhost",
    },
  });

  // THE api's OWN SURFACE. Four things live here and in no other job: the
  // body parser for `application/secevent+jwt` (without which every push is
  // reported as an empty body, a failure that reads as a transmitter sending
  // nothing), the three outcomes as HTTP STATUSES, the address policy still
  // covering this endpoint, and the push receiver a browser cannot be.
  const ssfApiJob = {
    name: "SSF api (the limits document, every refusal as a 400, the address " +
        "policy, the push receiver a browser cannot be, and the body parser " +
        "for application/secevent+jwt)",
    script: "api_ssf.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
    },
  };
  if (ssfApiSkip) ssfApiJob.skip = ssfApiSkip;
  jobs.push(ssfApiJob);

  // THE PAGE. It is NOT gated on the api, for the reason the SCIM page job is
  // not: the browser call path is the one a static deployment has, and this
  // job's callPath section is the only place the disabled BackEnd option is
  // asserted to be SWITCHED OFF rather than merely marked. Three more things
  // live here alone: that the bundle ran at all, the two histories, and the
  // extended OAuth2 / OIDC hand-off — which carries the whole token set
  // rather than only a bearer token, because an access token this service
  // issues is opaque to a client and the identity is in the ID Token.
  jobs.push({
    name: "SSF page (the bundle, discovery, a stream, a subject refused by " +
        "name, a verification event by poll, signing and pushing one in the " +
        "JavaScript engine, both histories, and the hand-off carrying the " +
        "whole token set)",
    script: "ssf_page.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      SSF_TRANSMITTER_URL: env.SSF_TRANSMITTER_URL ||
          env.WSTRUST_STS_URL || "https://localhost:8081",
    },
  });

  // ------------------------------------------------------------------------
  // SPIFFE — four jobs, split by what each one NEEDS rather than by what it
  // covers, which is the same division the SCIM three make and for the same
  // reason: a failure in the first names a rule, in the second a server, in
  // the third the api's own contract, and in the fourth a page. Collapsing
  // them would make every SPIFFE defect present as the same thing.
  //
  // SPIFFE_WORKLOAD_ADDRESS and SPIFFE_SERVER_ADDRESS are the API's view of
  // the two gRPC surfaces rather than this test's or the browser's — the same
  // distinction LDAP_URL and KRB5_KDC_HOST draw, and on the containerized
  // stack a different answer. They are their own variables for exactly that
  // reason. Note the `spiffe_protocol.js` job is the exception: it drives the
  // api's client IN PROCESS, so for that one job the address is this test's
  // own view — which on the containerized stack happens to be the same name,
  // and on a host run is loopback rather than `sts`.
  // ------------------------------------------------------------------------

  // THE ENGINES, with no server and no browser. It needs NOTHING — not the
  // api, not the mock, not Chrome — so it is never gated and never skipped,
  // and it is the one SPIFFE job that runs on every target including the
  // static ones. It asserts the ID grammar against the specification's own
  // rules, the trust bundle reader against documents wrong in one way each,
  // the 49-method catalogue against the vendored protos BOTH WAYS ROUND, and
  // those protos against the mock STS's copies byte for byte — which is the
  // only thing standing between this debugger and a wire that agrees with the
  // mock and interoperates with nothing.
  //
  // It is FIRST of the four deliberately: a broken address rule or a wrong
  // catalogue makes the other three fail in ways that look like a broken
  // server.
  jobs.push({
    name: "SPIFFE engines (the ID grammar against the specification, the " +
        "trust bundle reader, the 49-method catalogue against the vendored " +
        "protos, those protos against the mock's copies, every address and " +
        "socket refusal by its code, and a PKCS#10 request checked with " +
        "OpenSSL)",
    script: "spiffe_engine.js",
    env: {},
  });

  // THE PROTOCOL: all forty-nine methods against the mock, through the api's
  // own client, driven in process. It acquires FOUR identities in order —
  // nothing, a workload, an administrator, an agent — because this surface
  // authorizes every method against what the caller IS, and forty of the
  // forty-two SPIRE Server API methods are unreachable without the third.
  //
  // It holds the `sts-spiffe` lock: making the Workload API's own SVID an
  // administrator means setting `spiffe.adminIds` on a shared process, and it
  // also shortens `spiffe.svidTtl` to watch a rotation and turns
  // `spiffe.autoCreateEntries` off to run a client's "I have no identity"
  // path. Every one is read first and put back per setting in a `finally` —
  // never with reset-all, which would also undo whatever a concurrent job had
  // pinned.
  //
  // It is the slowest of the four at about forty seconds, and thirty of those
  // are one assertion: the mock puts a FLOOR of thirty seconds under a
  // Workload API stream's re-send, so watching an SVID rotate cannot be made
  // cheaper by shortening its lifetime.
  const spiffeProtocolJob = {
    name: "SPIFFE protocol (all 49 methods against the mock as four " +
        "different entities — nothing, a workload, an administrator and an " +
        "agent — with every authorization refusal asserted as the answer it " +
        "is, and an SVID rotation watched on a held stream)",
    script: "spiffe_protocol.js",
    env: {
      STS_URL: env.STS_URL || "https://localhost:8081",
      SPIFFE_WORKLOAD_ADDRESS: env.SPIFFE_TEST_WORKLOAD_ADDRESS ||
          env.SPIFFE_WORKLOAD_ADDRESS || "localhost:8092",
      SPIFFE_SERVER_ADDRESS: env.SPIFFE_TEST_SERVER_ADDRESS ||
          env.SPIFFE_SERVER_ADDRESS || "localhost:8181",
      // Empty by default and NOT derived from the setting's own default: the
      // mock ships with spiffe.serverSocketEnabled OFF, so a path guessed
      // from it would be a section that silently skips while claiming to
      // cover the `local` entity — the only route to Debug.GetInfo.
      SPIFFE_SERVER_SOCKET: env.SPIFFE_SERVER_SOCKET || "",
      SPIFFE_TRUST_DOMAIN: env.SPIFFE_TRUST_DOMAIN || "example.org",
    },
  };
  if (spiffeSkip) spiffeProtocolJob.skip = spiffeSkip;
  jobs.push(spiffeProtocolJob);

  // THE API'S OWN CONTRACT, over HTTP. What lives here and nowhere else is
  // the STATUS-CODE RULE, which is the most consequential decision that
  // endpoint makes: a refusal by the api is a 400, a network failure is a
  // 502, and a gRPC status from the far end — PERMISSION_DENIED,
  // UNAUTHENTICATED, UNIMPLEMENTED — is a **200** with the code, because
  // those are SPIFFE answering and are the most interesting thing this
  // workflow shows.
  const apiSpiffeJob = {
    name: "SPIFFE api endpoints (the status-code rule: a refusal is a 400, a " +
        "network failure is a 502, and a gRPC status from the far end is a " +
        "200 with the code)",
    script: "api_spiffe.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "https://localhost:8081",
      SPIFFE_WORKLOAD_ADDRESS: env.SPIFFE_WORKLOAD_ADDRESS || "sts:8092",
      SPIFFE_SERVER_ADDRESS: env.SPIFFE_SERVER_ADDRESS || "sts:8181",
      SPIFFE_BUNDLE_URL: env.SPIFFE_BUNDLE_URL ||
          (env.API_STS_URL || "https://sts:8081") + "/spiffe/bundle",
      SPIFFE_TRUST_DOMAIN: env.SPIFFE_TRUST_DOMAIN || "example.org",
    },
  };
  if (spiffeSkip) apiSpiffeJob.skip = spiffeSkip;
  jobs.push(apiSpiffeJob);

  // THE PAGE, which covers only what needs a browser. Four things live here
  // and nowhere else: that all forty-nine methods reach the two pickers (the
  // whole claim this workflow makes is a claim about those dropdowns); the
  // hand-off that takes an SVID from a surface which authenticates nobody and
  // PRESENTS it on one that requires mutual TLS; the PKCS#10 request built
  // with Web Crypto, which is a different implementation from the node one
  // the engine job checks against OpenSSL; and the key-material opt-out,
  // which must REMOVE a stored private key rather than only stop writing one.
  const spiffePageJob = {
    name: "SPIFFE page (all 49 methods in its pickers, the SVID hand-off " +
        "from an unauthenticated surface to a mutual-TLS one, the " +
        "certification request built in the browser, the three offline " +
        "readers, and what it remembers)",
    script: "spiffe_page.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "https://localhost:8081",
      SPIFFE_WORKLOAD_ADDRESS: env.SPIFFE_WORKLOAD_ADDRESS || "sts:8092",
      SPIFFE_SERVER_ADDRESS: env.SPIFFE_SERVER_ADDRESS || "sts:8181",
      SPIFFE_BUNDLE_URL: env.SPIFFE_BUNDLE_URL ||
          (env.API_STS_URL || "https://sts:8081") + "/spiffe/bundle",
      SPIFFE_TRUST_DOMAIN: env.SPIFFE_TRUST_DOMAIN || "example.org",
    },
  };
  if (spiffeSkip) spiffePageJob.skip = spiffeSkip;
  jobs.push(spiffePageJob);

  // The DELEGATION page: S4U2Self, S4U2Proxy with both authorization routes, forwarding
  // and renewal. tests/krb5_tgs_ap.js already drives every one of those exchanges with no
  // browser, so this job covers only what needs one:
  //
  //  * **the credential handoff** — the service's own TGT comes from the AS page and the
  //    evidence ticket from S4U2Self is stored for S4U2Proxy to find, under keys the
  //    shared module owns. A rename there breaks this and nothing else, which has happened
  //    once already. The evidence ticket carries a session key, so the storage opt-out has
  //    to purge it too, and this checks it leaves — including that nothing lands under a
  //    key literally called "undefined", which is what a purge using a renamed constant
  //    writes while leaving the real key in place.
  //  * **what the page SAYS when a delegation fails.** Every refusal here is
  //    KDC_ERR_BADOPTION whatever the cause — missing PA-PAC-OPTIONS, an unauthorized
  //    pair, non-forwardable evidence — and the error names none of them. So the page's
  //    job is to narrow it, and that text IS the product: a test asserting only "it
  //    failed" would pass against a page that said nothing useful. Three refusals are
  //    checked for naming their actual cause, including both attributes on both accounts.
  //  * **forwardability reported when the evidence ARRIVES**, not two steps later when
  //    classic S4U2Proxy refuses it — a missing TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
  //    surfaces as a complaint about the evidence ticket, which is not where it is.
  //
  // It authenticates as HTTP/frontend.example.com rather than as a user, because S4U2Self
  // is a request a SERVICE makes and that is the commonest misunderstanding about it.
  // Needs the client, the api's relay and the mock KDC; without them it SKIPS naming what
  // was absent, since an environment capability is not a defect.
  //
  // Its env is the same three values the AS, TGS/AP and SPNEGO jobs carry, and
  // it carried NONE of them until 2026-08-23 — which cost a run the moment the
  // containerized stack stopped skipping this job. `sts`, not `localhost`, for
  // the reason spelled out on the AS job above: that address is TYPED INTO THE
  // PAGE and resolved by the relay inside the api container, where localhost is
  // the api itself and port 88 is nothing. It stayed invisible because the two
  // stacks disagree about localhost — under local-tests.yml every service is on
  // host networking, so the api's loopback IS the host the mock KDC listens on
  // and the default worked; on the bridge stack it is not, and the page
  // reported `Could not talk to ::1:88` from a KDC that was up. The compose
  // name is right on both, since local-tests.yml gives the api an
  // `extra_hosts` entry mapping sts to 127.0.0.1.
  const delegationPageJob = {
    name: "Kerberos delegation page (S4U2Self, S4U2Proxy, RBCD, forwarding, renewal)",
    script: "kerberos_delegation_page.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      KRB5_KDC_HOST: env.KRB5_KDC_HOST || "sts",
      KRB5_KDC_PORT: env.KRB5_KDC_PORT || "88",
    },
  };
  if (kerberosPagesSkip) delegationPageJob.skip = kerberosPagesSkip;
  jobs.push(delegationPageJob);

  // The layout of all six pages at 1366x768: does each one put the control it
  // exists for on the first screen, and do the two CSS rules that height rests
  // on still match anything?
  //
  // It is a job of its own rather than an assertion inside the five page tests
  // above because those SKIP without a KDC, and a layout regression has nothing
  // to do with a KDC. It needs the site and nothing else — the buttons it
  // measures are in the served markup, not rendered by a bundle — so on a run
  // where the stack is half up this is still a real check. It does skip on a
  // static target for the same reason the others do: the pages are not there.
  //
  // Both of the CSS facts it asserts were found broken on 2026-08-17 and
  // neither made a page look wrong: bootstrap's `legend { line-height: 40px }`
  // was back on every pane (the override still said `.krb-pane > legend`, and
  // the panes had moved to `.dbg-pane`), and `.krb-field`'s 4px bottom margin
  // was losing to `input[type="text"]`'s 10px on specificity. Between them they
  // were most of ~1,300px across the workflow.
  const kerberosDensityJob = {
    name: "Kerberos pages fit one screen (six pages, 1366x768, pane chrome)",
    script: "kerberos_page_density.js",
    env: {},
  };
  if (kerberosPagesSkip) kerberosDensityJob.skip = kerberosPagesSkip;
  jobs.push(kerberosDensityJob);

  // The api's outbound address policy (api/ssrf_guard.js): the service fetches
  // URLs its caller supplies, so it must refuse loopback and private
  // destinations or it is an SSRF probe into whatever network it runs in. Node
  // only — no browser, no services — so it is never skipped.
  jobs.push({
    name: "API SSRF guard (outbound calls to loopback / private ranges " +
        "are refused)",
    script: "api_ssrf_guard.js",
    env: {},
  });

  // The api's outbound limits: api/connect_timeout.js plus callTimeout,
  // connectionTimeout, maxContentLength and maxRedirects in api/env/*.js. axios
  // defaults to no timeout, no size cap and 21 redirects, so without these a
  // caller-named host that goes quiet holds a request open for minutes, one
  // that streams fills the heap, and one that redirects can walk the service
  // elsewhere. The interesting half is that a connection which SUCCEEDED must
  // not be cut off by the connect budget — an AbortSignal-based implementation
  // gets that wrong. Node only, so never skipped.
  jobs.push({
    name: "API outbound call policy (timeouts, caps, User-Agent, keep-alive)",
    script: "api_connect_timeout.js",
    env: {},
  });

  // The SD-JWT VC issuance workflow (OID4VCI + RFC 9901): the mock Credential
  // Issuer the STS service hosts, the three vc-issuance pages, and the
  // ?sdjwtvc=1 hand-off through oauth2_oidc_1.html / oauth2_oidc_2.html. Needs
  // both the STS mock (which is the credential issuer) and Keycloak (which
  // authorizes the issuance), so it is gated on the STS like the other
  // STS-backed jobs.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "VC Issuance — SD-JWT VC (OID4VCI credential issuance end to end)",
      script: "sd_jwt_vc_issuance.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // The BBS signatures the debugger produces, checked by a DIFFERENT BBS
  // implementation (@digitalbazaar/bbs-signatures) AND by the draft's own
  // published test vectors (vendored as tests/bbs_vectors.json). No browser and
  // no services, so it never skips. It is the foundation the bbs-2023
  // cryptosuite and the Digital Signature page's BBS pane both stand on: BBS
  // has several places where a signer and verifier can share a mistake and
  // agree perfectly with each other and with nobody else. Covers both
  // ciphersuites, KeyGen, and the fact that neither suite accepts the other's
  // signature.
  {
    jobs.push({
      name: "BBS signatures (cross-checked against an independent " +
          "implementation and the draft's vectors)",
      script: "bbs_crypto.js",
      env: {},
    });
  }

  // The third credential format through both workflows: ldp_vc secured by a
  // bbs-2023 Data Integrity proof. Registered unconditionally like the
  // jwt_vc_json pair — a gated job that does not register is the quietest way
  // for a format to go untested.
  {
    jobs.push({
      name: "VC Issuance — ldp_vc / bbs-2023 (embedded Data Integrity proof)",
      script: "ldp_vc_issuance.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    // Refreshing one (OID4VCI 14.5's two calls, and the 14.3 route that is all
    // that remains after the pre-authorized grant). Registered separately from
    // issuance because it drives a different call site — issuance step 4's —
    // over the same wallet module, and because holder binding for this format
    // is credentialSubject.id rather than cnf.jwk, which is what distinguishes
    // a replacement from a second credential.
    // Section 10 in the direction the response-encryption support did not
    // cover: the ISSUER publishes the key and the wallet encrypts to it. Needs
    // only the STS mock, so it is registered unconditionally.
    jobs.push({
      name: "OID4VCI Credential Request encryption (section 10, " +
          "issuer-published keys)",
      script: "oid4vci_request_encryption.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Refresh — ldp_vc / bbs-2023 (OID4VCI 14.5 refresh_token + " +
          "re-request)",
      script: "ldp_vc_refresh.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Presentation — ldp_vc / bbs-2023 (statement disclosure, " +
          "unlinkable)",
      script: "ldp_vc_presentation.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
        OID4VP_VERIFIER_URL: env.OID4VP_VERIFIER_URL || "",
      },
    });
    // The issuer named by a DID, for both formats that can carry one. It runs
    // against the IdentityCredentialDid / IdentityCredentialLdpVcDid
    // configurations, which exist so that ONE run covers both routes: those two
    // name the issuer by did:web while their plain siblings keep the https
    // identifier, so the specification's own key resolution
    // (/.well-known/jwt-vc-issuer, which is all draft-ietf-oauth-sd-jwt-vc
    // defines) goes on being exercised beside the DID extension. A server-wide
    // switch could only ever test one of the two.
    //
    // The chain it checks is advertisement -> resolution -> domain linkage ->
    // credential -> signature, and the last link is the one that matters: a DID
    // that resolves to the wrong key looks like success until something tries
    // to verify with it. Needs only the STS mock. The mock STS's own index of
    // itself: GET /admin/sts-metadata lists every endpoint it registers,
    // with its methods, and every specification it implements. The list is
    // read from the running Express router rather than kept by hand, and this
    // job is what makes that worth something — it fails if a route is
    // registered and undescribed (the page understates what is callable) or
    // described and not registered (the page advertises a 404, which is what
    // a rename produces).
    // Needs only the STS mock. did-tools.html, the general-purpose DID verifier
    // reached from the VC Tools pane on every page of both workflows. The DIDs
    // it works on are GENERATED by the mock STS (GET /did/generate), which
    // hands back a DID together with a credential signed by the key that DID
    // publishes — so the page's verdict can be checked against a known-good
    // answer instead of against "the document parsed". Its two negatives are
    // the point: a document that resolves perfectly but did not sign the held
    // credential must not read as verified, and an origin that vouches for a
    // different DID must not read as linked. Needs the STS and the client; no
    // Keycloak, no walt.id.
    jobs.push({
      name: "DID Tools page (resolve, verify a signing key, verify a " +
          "domain linkage)",
      script: "did_tools.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    // THE MOCK'S OWN /admin AND /admin-api SURFACE IS NOT TESTED FROM HERE.
    // Four jobs used to sit at this point — sts_metadata.js (the metadata
    // page), admin_api.js (the management API's shape, its OpenAPI document
    // and its parity with the console), sts_admin_api_operations.js (every
    // documented operation driven for real) and sts_admin_console.js (the
    // console walked in a browser). All four asserted things about the mock
    // STS rather than about this debugger, and the mock's own suite drives
    // them now, in the tree where a change to that console is made. They were
    // removed here on 2026-08-28; see docs/mock-sts.md.
    jobs.push({
      name: "VC Issuance — issuer named by DID (did:web, domain linkage, " +
          "both formats)",
      script: "vc_did.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // ---------------------------------------------------------------------
  // POSTGRES PERSISTENCE, AND THE ONLY JOB HERE THAT OWNS THE SERVICE IT
  // DRIVES.
  //
  // Registered OUTSIDE the WSTRUST_STS_URL guard above, deliberately: it does
  // not use the shared mock and would be wrong to. Persistence is a claim
  // about what happens across a RESTART, so this job starts its own Postgres
  // and its own mock, restarts it, and reads what came back — and the shared
  // instance must stay in memory mode, which mock-sts's own
  // docker-compose.yml argues at length ("a test that persisted would be a
  // test whose second run started from the first run's leavings").
  //
  // It holds NO JOB_LOCK for the same reason: its database, its ports and its
  // processes are all its own, and it removes them in a `finally`.
  //
  // It SKIPS, with a named reason, when there is no docker and no
  // STS_TEST_POSTGRES_URL, or when there is no COMPLETE mock STS tree to run —
  // which is what the containerized suite looks like, since the tests image
  // carries about thirty sts modules and no node_modules. On a host stack it
  // runs in about twenty seconds.
  // ---------------------------------------------------------------------
  {
    jobs.push({
      name: "STS persistence (postgres) — what survives a restart, what must " +
          "not, that two processes do not see each other, that the " +
          "connection is TLS by postgres's own account, and that a missing " +
          "database is not fatal",
      script: "sts_persistence_postgres.js",
      env: {
        // Passed through so a caller with a database of their own is used
        // instead of a throwaway container. Empty means "start one".
        STS_TEST_POSTGRES_URL: env.STS_TEST_POSTGRES_URL || "",
        MOCK_STS_DIR: env.MOCK_STS_DIR || "",
      },
    });
  }

  // The cryptosuite ABOVE the primitive: JSON-LD canonicalization, the base
  // proof, and selective disclosure. The STS issues with one BBS implementation
  // and the wallet derives with the other, so neither marks its own homework.
  {
    jobs.push({
      name: "bbs-2023 cryptosuite (ldp_vc issue, derive, verify across two " +
          "implementations)",
      script: "bbs2023_cryptosuite.js",
      env: {},
    });
  }

  // The metadata schema check on vc-issuance-1.html, both panes. Its rule
  // half needs no browser and no services and never skips; its wiring half
  // drives the page, so it needs only the client — which every run has.
  // Registered unconditionally for the same reason as the four below.
  {
    jobs.push({
      name: "Metadata schema validation (OID4VCI and RFC 8414 panes, " +
          "positive and negative)",
      script: "metadata_schema_validation.js",
      env: {},
    });
  }

  // These four are registered UNCONDITIONALLY, unlike their SD-JWT siblings. A
  // gated job that does not register simply is not in the report, which is the
  // quietest possible way for a credential format to go untested — the run says
  // "all green" and nothing says the format was never exercised. Each of these
  // instead runs and FAILS with what is missing and how to supply it. The SAME
  // issuance workflow in the other credential format this issuer offers:
  // jwt_vc_json, a W3C VC secured as a JWT. Its own job rather than a flag on
  // the one above, because that suite is built around Disclosures and this
  // format has none — a flag would leave most of it skipped and the run would
  // read as though selective disclosure had been declined rather than being
  // unavailable. Skips itself when the issuer offers no such configuration.
  {
    jobs.push({
      name: "VC Issuance — jwt_vc_json (W3C VC secured as a JWT)",
      script: "jwt_vc_json_issuance.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // The SD-JWT VC PRESENTATION workflow (OID4VP 1.0 + RFC 9901 section 4.3):
  // the mock Verifier the STS service hosts, the four vc-presentation pages,
  // and the presentation itself — an SD-JWT+KB whose Key Binding JWT is signed
  // over the request's nonce. Needs only the STS (issuer AND verifier), so no
  // identity provider is involved. Carries its own negatives: a replayed
  // presentation, a KB-JWT signed by the wrong key, an invented Disclosure, one
  // removed after signing, and a claim the verifier asked for withheld.
  if (env.WSTRUST_STS_URL) {
    // The SERVER half of DPoP, over HTTP with no browser: all twelve RFC 9449
    // section 4.3 proof checks, the cnf.jkt binding on access and refresh
    // tokens, the dpop_jkt code binding, jti replay detection, and the nonce
    // handshake in both of its shapes. It is almost entirely negatives, because
    // a DPoP server that issues bound tokens and accepts good proofs looks
    // finished and can be worth nothing — the value is all in what it refuses.
    // Needs only the STS.
    jobs.push({
      name: "DPoP server checks (RFC 9449: the twelve proof checks, binding, " +
          "replay, nonces)",
      script: "sts_dpop.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    // The SIGNED and ENCRYPTED UserInfo response (OIDC Core section 5.3.2),
    // over HTTP with no browser. It is a CROSS-IMPLEMENTATION check and that is
    // why it earns a job of its own: the mock produces every shape with node's
    // OpenSSL and each one is opened with the DEBUGGER's engines
    // (client/src/jws.js and client/src/jose_jwe.js, which are Web Crypto), so
    // the failures it can see are the self-consistent ones a round trip through
    // either side alone cannot — a CBC-HMAC key split the wrong way round, a
    // Concat KDF that stops after one round, a tag taken as the whole HMAC.
    // It drives every algorithm the metadata ADVERTISES rather than a list of
    // its own, so an algorithm advertised and not implemented fails here.
    // Needs only the STS.
    // The UserInfo PAGE reading a protected response, in a browser — the half
    // sts_userinfo_protected.js cannot reach. A response the engines can open
    // and the page cannot render is an empty box, and nothing in node sees it.
    // Four shapes, one algorithm per family, and the distinctions the report
    // has to draw: "decrypted" is never "verified", a nested JWS whose outer
    // header omits cty is a finding, and iss/aud/sub are checked by name.
    jobs.push({
      name: "UserInfo page reads signed, encrypted and nested responses " +
          "(OIDC Core 5.3.2, in the browser)",
      script: "oidc_userinfo_protected_page.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "Client-supplied JWS verification (every advertised algorithm " +
          "for client assertions and OID4VCI proofs)",
      script: "sts_jws_verification.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    // Every algorithm the mock ADVERTISES for a JWS the client signs is
    // actually accepted — client assertions and OID4VCI proofs of possession.
    // An advertised list is a promise, and nothing checked either of them
    // until this job existed: on its first run it found the eleven
    // post-quantum algorithms advertised for client authentication and
    // unverifiable, because client_auth.js handed an AKP JWK to node's
    // createPublicKey() and dropped it as unreadable.
    jobs.push({
      name: "UserInfo signed and encrypted responses (OIDC Core 5.3.2, " +
          "every advertised alg/enc, opened with the debugger's engines)",
      script: "sts_userinfo_protected.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    // And DPoP through the PAGES, which is the part neither of the two above
    // can reach: that the wallet really sends the proofs, that the token which
    // comes back is really bound (checked against the token's own cnf.jkt, not
    // against what the pane says), and that Holder of Key really binds the
    // credential to the DPoP key. Driven with the pre-authorized code grant, so
    // no IdP is needed.
    jobs.push({
      name: "DPoP through the VC Issuance pages (the pane, the real binding, " +
          "Holder of Key)",
      script: "dpop_workflow.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Presentation — SD-JWT VC (OID4VP: selective disclosure, " +
          "positive and negative)",
      script: "sd_jwt_vc_presentation.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // The PRESENTATION half of the same format: a Verifiable Presentation JWT
  // instead of an SD-JWT+KB, with holder binding done by that JWT's own
  // signature rather than by a Key Binding JWT. Carries its own negatives — a
  // VP JWT signed by the wrong key, a replay, a tampered credential, and an
  // SD-JWT answering a jwt_vc_json query (which matters because a Combined
  // Serialization also splits into three dot-separated parts).
  {
    jobs.push({
      name: "VC Presentation — jwt_vc_json (Verifiable Presentation JWT, " +
          "positive and negative)",
      script: "jwt_vc_json_presentation.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
        OID4VP_VERIFIER_URL: env.OID4VP_VERIFIER_URL || "",
      },
    });
  }

  // The same SD-JWT VC issuance workflow, driven against walt.id's issuer-api2
  // instead of our mock: a real, independently written OpenID4VCI 1.0
  // Credential Issuer. This is the interoperability check — same pages, same
  // buttons, someone else's implementation on the other end — so it is gated on
  // that container being up rather than on the STS.
  if (env.WALTID_ISSUER_URL) {
    jobs.push({
      name: "VC Issuance — SD-JWT VC against walt.id (OID4VCI " +
          "interoperability)",
      script: "sd_jwt_vc_waltid.js",
      env: {
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL,
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  // The SD-JWT VC PRESENTATION workflow driven against walt.id's verifier-api2
  // — an independently written OpenID4VP 1.0 verifier with DCQL — instead of
  // our own mock. The credential it presents is ISSUED BY walt.id in the same
  // run through our issuance pages, so neither end of the exchange is ours.
  // Gated on that container being up, like the issuer's interoperability job;
  // it also needs the walt.id issuer and Keycloak, because that is where the
  // credential comes from.
  if (env.WALTID_VERIFIER_URL) {
    jobs.push({
      name: "VC Presentation — SD-JWT VC against walt.id (OID4VP " +
          "interoperability)",
      script: "sd_jwt_vc_presentation_waltid.js",
      env: {
        WALTID_VERIFIER_URL: env.WALTID_VERIFIER_URL,
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL || "",
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  // jwt_vc_json against walt.id: the interoperability half of the two jobs
  // above. Both skip with instructions when walt.id offers no jwt_vc_json
  // configuration, which is the state until its container is restarted onto the
  // configuration in waltid/config/credential-issuer-metadata.conf.
  //
  // The presentation one has a second, deliberate skip: walt.id's own
  // jwt_vc_json profiles bind the holder with a SUBJECT DID where our mock uses
  // cnf.jwk, and a wallet cannot sign a Verifiable Presentation JWT for a key
  // it has never held. That is reported as an interoperability finding rather
  // than failed, because neither implementation is wrong.
  {
    jobs.push({
      name: "VC Issuance — jwt_vc_json against walt.id (OID4VCI " +
          "interoperability)",
      script: "jwt_vc_json_issuance_waltid.js",
      env: {
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL,
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  {
    jobs.push({
      name: "VC Presentation — jwt_vc_json against walt.id (OID4VP " +
          "interoperability)",
      script: "jwt_vc_json_presentation_waltid.js",
      env: {
        WALTID_VERIFIER_URL: env.WALTID_VERIFIER_URL,
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL || "",
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  // Operations History pane on the WS-Trust pages: records every attempted STS
  // call (timestamp, WS-Trust version, operation, user, result), dispatched as
  // "Sent" and resolved from the RSTR — or the SOAP Fault — on the response
  // page. Needs the STS mock (WSTRUST_STS_URL), like the other WS-Trust jobs.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "WS-Trust Operations History (attempted STS calls: version, " +
          "operation, user, result)",
      script: "wstrust_operation_history.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  jobs.push({
    name: "SAML Operations History (attempted IdP calls: binding, version, " +
        "entity IDs, result)",
    script: "saml_operation_history.js",
    env: {},
  });

  jobs.push({
    name: "SAML Assertion Tool (compose 1.0/1.1/2.0, XML-DSIG sign + verify, " +
        "XML-Enc round-trip)",
    script: "saml_tools.js",
    env: {},
  });

  // The SAML Request Decoder (saml_authnrequest.html): read an AuthnRequest
  // off the wire on all three bindings, check the signature in both of the
  // two completely different places it can live, and decrypt. No identity
  // provider — every fixture is built in the test by the same modules the
  // page uses — so this one is never skipped.
  //
  // The assertion worth knowing about is the REDIRECT TAMPER case. A
  // redirect-binding signature covers the query string as SENT, so a decoder
  // that rebuilds those octets in its own order reports INVALID on a good
  // signature, and in a browser that is indistinguishable from a wrong
  // certificate. Checking only that a good signature verifies would pass with
  // the octets rebuilt any which way.
  jobs.push({
    name: "SAML Request Decoder (three bindings, query-string + enveloped " +
        "signature, XML-Enc decrypt)",
    script: "saml_authnrequest_page.js",
    env: {},
  });

  // The SAML Response Decoder (saml_response_decoder.html): the same page on
  // the other half of the exchange, and a bigger job than its mirror because a
  // response carries three things a request does not — a status, one or more
  // assertions, and a signature in TWO places that mean different things. No
  // identity provider: every fixture is built in the test by the same modules
  // the page uses, so this one is never skipped either.
  //
  // Two assertions are worth knowing about. THE SAML 1.1 STATUS: 2.0 writes
  // the code as a URI ending `:status:Success` and 1.1 writes it as a QName
  // (`samlp:Success`), so a reader written for either reports the other's
  // SUCCESS AS A FAILURE — which is exactly what the SAML Response page did to
  // every 1.1 sign-in until 2026-08-25, and the case here asserts the verdict
  // rather than that a table rendered. And THE TWO SIGNATURES: a response
  // signed at one level only must report the other as absent BY NAME, because
  // a decoder that collapsed them into one "signed: VALID" would pass every
  // other check in that file while telling somebody their unsigned assertion
  // is safe.
  //
  // It also drives the Expand / Collapse All switch on all four pages that
  // carry one. That control is inline script rather than a bundle export, so
  // that it works before browserify's global exists — which is also why
  // nothing else in this suite would notice it silently doing nothing.
  jobs.push({
    name: "SAML Response Decoder (SAML 1.1 + 2.0, three bindings, message " +
        "and assertion signatures, EncryptedAssertion decrypt)",
    script: "saml_response_decoder_page.js",
    env: {},
  });
  
 // SAML 2.0 SP-initiated SSO across all three bindings: load IdP metadata, sign
  // the AuthnRequest (redirect = query-string sig; post = enveloped XML-DSIG;
  // artifact = redirect send + SOAP ArtifactResolve back-channel), log in at
  // Keycloak (which validates the request signature), and confirm the
  // ACS-captured SAMLResponse / assertion / NameID render on the response page.
  // The Artifact binding needs the server-side SOAP ArtifactResolve
  // back-channel, so it can't run on a backendless (static) deployment.
  // remote-run-tests.sh sets SAML_BACKEND_AVAILABLE=false for those targets;
  // skip it there rather than fail.
  const samlBackendAvailable = env.SAML_BACKEND_AVAILABLE !== "false";
  // ---------------------------------------------------------------------
  // TWO IDENTITY PROVIDERS ANSWER THIS PROFILE, and every SSO job below is
  // pushed once per IdP — the same arrangement the WS-Federation pair further
  // down have had, and here for the same reason: a mock that is quietly more
  // permissive than the real thing passes every test written against it alone.
  //
  //   * **Keycloak is somebody else's implementation**, and the only
  //     interoperability evidence here. It VALIDATES the AuthnRequest
  //     signature against the certificate common.sh registered for this run,
  //     so a request the debugger builds sloppily fails there.
  //   * **The mock STS grew this profile in 2026-08**, and it covers what
  //     Keycloak cannot: it answers the HTTP Artifact binding with a real SOAP
  //     back channel in a service that starts in seconds, it refuses a
  //     ProtocolBinding it does not implement BY NAME, and it needs NOTHING
  //     PROVISIONED — any entityID is accepted and a metadata document is
  //     minted for anything asked for. It also publishes its metadata PER
  //     SERVICE PROVIDER, which is what SAML_STS_METADATA_URL names.
  //
  // Each is gated on its own metadata URL, so an environment with one and not
  // the other runs half of these and skips the other half naming which.
  const samlIdps = [
    {
      key: "keycloak",
      label: "Keycloak",
      skip: (env.SAML_METADATA_URL || env.SAML_METADATA_FILE) ? null :
        "the Keycloak SAML realm is not provisioned (SAML_METADATA_URL and " +
        "SAML_METADATA_FILE both unset).",
      env: {
        SAML_IDP: "keycloak",
        SAML_METADATA_URL: env.SAML_METADATA_URL,
        // When set (remote-run-tests.sh), the metadata is uploaded from this
        // local file instead of fetched from the URL — see loadIdpMetadata().
        SAML_METADATA_FILE: env.SAML_METADATA_FILE,
        SAML_SP_ENTITY_ID: env.SAML_SP_ENTITY_ID,
        SAML_USER: env.SAML_USER,
        SAML_SLO_URL: env.SAML_SLO_URL,
        // Where the MOCK is, which this half is not. Passed to both halves and
        // self-selecting: the service provider is registered only when the
        // identity provider this job was given is on that origin.
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
      },
    },
    {
      key: "sts",
      label: "mock STS",
      skip: env.SAML_STS_METADATA_URL ? null :
        "the mock STS is not reachable by the browser for SAML 2.0 " +
        "(SAML_STS_METADATA_URL unset). The launchers set it wherever the STS " +
        "is reachable — the containerized stack by compose DNS name, the host " +
        "and live-site runs over loopback.",
      env: {
        SAML_IDP: "sts",
        SAML_METADATA_URL: env.SAML_STS_METADATA_URL,
        // The SAME service provider entityID Keycloak's client is provisioned
        // for. It can be, and that is the point rather than a shortcut: the two
        // runs describe the same service provider to two identity providers,
        // which is what a federation looks like — and since 2026-08-27 each
        // half REGISTERS it with the identity provider it is about to speak to,
        // so both stores hold an entry rather than one holding an entry and the
        // other holding whatever a sighting inferred. The mock still requires
        // none of it and still accepts any entityID; what changed is that its
        // entry now knows the ACS and the signing certificate too.
        SAML_SP_ENTITY_ID: env.SAML_SP_ENTITY_ID,
        SAML_USER: env.SAML_STS_USER || env.SAML_USER || "saml",
        // Where a LogoutResponse is to be returned to. Only saml_logout.js
        // reads it, and only to put it on the application entry: a
        // LogoutRequest carries no return address, so this is a fact the
        // service provider has to have DECLARED somewhere.
        SAML_SLO_URL: env.SAML_STS_SLO_URL || env.SAML_SLO_URL,
        // And its management API, so the service provider is in the registry
        // before the first AuthnRequest rather than created by it. The comment
        // above about there being nothing to provision described what the mock
        // REQUIRES; it is still true, and it is exactly why the entry the
        // sighting would have made knows nothing but the entityID.
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
      },
    },
  ];

  for (const idp of samlIdps) {
    for (const SAML_BINDING of ["redirect", "post", "artifact"]) {
      const job = {
        name: `SAML 2.0 SSO — HTTP-${SAML_BINDING === 'post' ?
            'POST' : SAML_BINDING === 'artifact' ?
            'Artifact' : 'Redirect'} binding (${idp.label})`,
        script: "saml_sso.js",
        env: Object.assign({ SAML_BINDING }, idp.env),
      };
      if (idp.skip) {
        job.skip = idp.skip;
      } else if (SAML_BINDING === "artifact" && !samlBackendAvailable) {
        // The gate is about the TARGET rather than the IdP: resolving an
        // artifact is a server-side SOAP call the SP has to make, so it needs
        // the api backend whichever identity provider minted the artifact.
        job.skip = "HTTP-Artifact needs the API backend (server-side SOAP ArtifactResolve); unavailable on the static deployment.";
      }
      jobs.push(job);
    }
  }

  // ---------------------------------------------------------------------
  // SAML **1.1**, which since 2026-08-25 is a working profile on this page
  // rather than a reference-only entry in a dropdown. THREE kinds of job, and
  // the distinction between them is worth reading before adding a fourth.
  //
  // 1. `saml11_sso.js` — the DEBUGGER's SAML 1.1 service provider, driven
  //    through its pages by a browser, once per binding. `saml_sso.js`'s
  //    sibling and deliberately its mirror image.
  // 2. `saml11_options.js` — which of the SP / Request settings apply to SAML
  //    1.1 and which are switched off. No identity provider at all.
  // 3. `sts_saml11.js` — the mock STS's SAML 1.1 identity provider, driven
  //    directly over HTTP with a relying party it writes itself, and almost
  //    entirely NEGATIVES. It sits with `sts_dpop.js` and `vc_did.js`, which
  //    is the family it belongs to.
  //
  // **THERE IS NO KEYCLOAK HALF OF ANY OF THEM, and there will not be one.**
  // Every other browser-SSO job in this section is pushed once per identity
  // provider, because a mock that is quietly more permissive than the real
  // thing passes every test written against it alone. That argument still
  // holds and there is nothing to act on it with: Keycloak dropped SAML 1.1
  // years ago. So the mock is the only identity provider here, and
  // `sts_saml11.js` is what compensates — it writes the relying party ITSELF
  // rather than importing the debugger's, in the same spirit as `sts_dpop.js`
  // writing its own DPoP client, so a shared misunderstanding between the two
  // ends of the exchange cannot pass unnoticed.
  //
  // The three binding jobs and `sts_saml11.js` share a JOB_LOCK — see the note
  // beside it, which is the "read tests/CLAUDE.md before adding a test that
  // configures a shared service" case exactly.
  // ---------------------------------------------------------------------
  //
  // The SAML 1.1 metadata URL is the mock's PER-RELYING-PARTY descriptor, the
  // same device the SAML 2.0 job's `SAML_STS_METADATA_URL` is and computed the
  // same way. Nothing has to be provisioned: that service accepts any
  // identifier and mints the document on the ask.
  for (const SAML_BINDING of ["redirect", "post", "artifact"]) {
    const job = {
      name: `SAML 1.1 SSO — HTTP ${SAML_BINDING === 'post' ?
          'POST' : SAML_BINDING === 'artifact' ?
          'Artifact' : 'Redirect'} binding (mock STS)`,
      script: "saml11_sso.js",
      env: {
        SAML_BINDING,
        SAML11_METADATA_URL: env.SAML11_METADATA_URL,
        SAML11_METADATA_FILE: env.SAML11_METADATA_FILE,
        SAML_SP_ENTITY_ID: env.SAML_SP_ENTITY_ID,
        SAML_USER: env.SAML_STS_USER || env.SAML_USER || "saml",
        // The mock's management API: the relying party is put in the registry
        // before the flow starts. It matters more here than it does for SAML
        // 2.0, because SAML 1.1 has no request message for the relying party
        // to identify itself in — so what the entry holds is the only place
        // this profile's audience is written down.
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
      },
    };
    if (!env.SAML11_METADATA_URL && !env.SAML11_METADATA_FILE) {
      job.skip = "the mock STS is not reachable by the browser for SAML 1.1 " +
        "(SAML11_METADATA_URL and SAML11_METADATA_FILE both unset). The " +
        "launchers set it wherever the STS is reachable — the containerized " +
        "stack by compose DNS name, the host and live-site runs over " +
        "loopback. Keycloak cannot stand in: it has spoken no SAML 1.1 for " +
        "years.";
    } else if (SAML_BINDING === "artifact" && !samlBackendAvailable) {
      // The same gate the SAML 2.0 artifact job carries, and about the TARGET
      // rather than the identity provider: resolving an artifact is a SOAP
      // call the service provider has to make server-side, whichever version
      // minted it.
      job.skip = "HTTP Artifact needs the API backend (the SAML 1.1 SOAP " +
        "responder is a server-side call); unavailable on the static " +
        "deployment.";
    }
    jobs.push(job);
  }

  // What the SP / Request pane offers on SAML 1.1 and what it must stop
  // offering — the username hint, request signing, request encryption, Single
  // Logout and the SLO endpoints, each asserted DISABLED and greyed rather than
  // merely absent. No identity provider, so it is never skipped: a control
  // wrongly left live is invisible in the round-trip jobs above as long as the
  // flow works anyway, which it does.
  jobs.push({
    name: "SAML 1.1 SP/Request settings (what applies, what is switched off, " +
        "the Shibboleth request shape, the 1.1 SP metadata)",
    script: "saml11_options.js",
    env: {},
  });

  // The mock STS's own SAML 1.1 identity provider, over HTTP with no browser:
  // Browser/POST and Browser/Artifact end to end, the SOAP responder's four
  // request types (which makes that service an attribute authority), the
  // per-relying-party metadata, the NameIdentifier formats, and the four traps
  // this profile hides — the confirmation method, the signature reference
  // through the real AssertionID, an InResponseTo on a profile with no request,
  // and the one-shot artifact.
  //
  // Gated on the STS alone, like the tests it sits with. It restores every
  // setting it changes, through /admin-api/config/reset rather than by writing
  // the old value back, so it leaves no runtime override behind for the next
  // run against the same container — the mock's own suite reads that store and
  // fails on a leftover override.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "SAML 1.1 identity provider on the mock STS (Browser/POST, " +
          "Browser/Artifact, the SOAP responder, per-RP metadata)",
      script: "sts_saml11.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // SAML 2.0 ENCRYPTION on the mock STS, driven over HTTP with a service
  // provider the test writes itself — its own RSA key pair, its own XML
  // Encryption decryptor built on node's `crypto`, and a PKCS#1 v1.5 unwrap done
  // with BigInt because node refuses `RSA_PKCS1_PADDING` for private decryption.
  //
  // NOTHING IS BORROWED FROM THE MOCK, which is `sts_dpop.js`'s rule and matters
  // more here than anywhere else in this suite: if both ends of the encryption
  // came from one implementation, a shared misunderstanding about where the IV
  // lives or whether the GCM tag is appended would pass and interoperate with
  // nobody.
  //
  // It is the counterpart of `saml_encrypted_sso.js` and does not replace it.
  // That job proves the DEBUGGER can consume an encrypted assertion from
  // Keycloak, in a browser, with the SP key in the page. This one proves the
  // MOCK can produce one — and, mostly, that it REFUSES what it should: an
  // altered ciphertext, an EncryptedID encrypted to somebody else's key, and a
  // decrypted fragment that does not carry its own namespace.
  //
  // Gated on the STS alone, like the tests it sits with. It restores every
  // setting it changes through /admin-api/config/reset rather than by writing
  // the old value back, so it leaves no runtime override behind for the next
  // run against the same container — the mock's own suite reads that store and
  // fails on a leftover override.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "SAML 2.0 encryption on the mock STS (EncryptedAssertion, " +
          "EncryptedID both ways, four ciphers x two key transports)",
      script: "sts_saml_encryption.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // SAML 2.0 EncryptedAssertion decryption: SSO against a SAML client with
  // saml.encrypt=true (provisioned in common.sh), so Keycloak returns an
  // <saml:EncryptedAssertion>; the Response page decrypts it IN THE BROWSER
  // with the SP private key and renders the plaintext assertion.
  //
  // The decryption has never needed a backend — decryptAssertion() in
  // saml_response.js is node-forge in the page, the same XML-Enc engine the
  // WS-Trust and WS-Federation pages use, with no fetch and no Web Crypto. What
  // this job needs is somewhere for the IdP to POST the response: Keycloak's
  // encrypted client is provisioned saml.force.post.binding=true
  // (common/common.sh), so the response is POSTed whatever the AuthnRequest
  // asks for, and the Redirect-binding fallback the other SAML jobs use on a
  // static target is not available to it.
  //
  // That used to make this "unavailable on the static deployment". It no longer
  // is: infra/edge/saml_landing.js answers /samlacs at the CDN edge. So the
  // gate is whether a landing is actually deployed — remote-run-tests.sh probes
  // for one — not whether there is an api. Unset means "not probed" (the local
  // and containerized runs), where the api's ACS has always been there.
  //
  // It is also the case the profile cares about: an encrypted assertion is
  // ciphertext, which does not DEFLATE, so a redirect-bound one roughly doubles
  // in URL length — which is precisely why saml-profiles-2.0-os section 4.1.2
  // says the Redirect binding MUST NOT carry the Response.
  //
  // **THIS ONE IS KEYCLOAK-ONLY, and the reason is a documented non-feature
  // rather than an omission in the test.** The mock STS's Web Browser SSO
  // profile does not encrypt an assertion: there is no recipient certificate in
  // an AuthnRequest to encrypt to unless SP metadata is consumed, and that
  // service publishes metadata and does not consume it. (Its WS-Trust endpoint
  // does encrypt, at /sts?encrypt=1, because a WS-Security signature carries
  // the certificate.) So there is no `sts` half to add here — adding one would
  // be a job that could only ever fail or be skipped.
  {
    const encJob = {
      name: "SAML 2.0 EncryptedAssertion — decrypt on Response page",
      script: "saml_encrypted_sso.js",
      env: {
        SAML_METADATA_URL: env.SAML_METADATA_URL,
        SAML_METADATA_FILE: env.SAML_METADATA_FILE,
        SAML_ENC_SP_ENTITY_ID: env.SAML_ENC_SP_ENTITY_ID,
        SAML_USER: env.SAML_USER,
      },
    };
    if (env.SAML_LANDING_AVAILABLE === "false") {
      encJob.skip = "the target has no SAML ACS landing at " +
        (env.SAML_LANDING_URL || "<base>/samlacs") +
         " to receive the IdP's POST, and the encrypted " +
        "client forces the POST binding so the Redirect fallback cannot be " +
            "used. On a static " +
        "deployment, apply the infrastructure (./infra/terraform-local.sh " +
            "test apply) so the " +
        "Lambda@Edge landing exists, and build the site with samlEdgeLanding: true.";
    }
    jobs.push(encJob);
  }

  // SAML 2.0 Single Logout: log in via SSO (to establish the Keycloak session
  // and capture the NameID/SessionIndex), then send a signed LogoutRequest and
  // confirm the LogoutResponse renders with a Success status on the response
  // page.
  //
  // Once per identity provider, like the SSO jobs above. The interesting
  // difference between the two is where the LogoutResponse is SENT: a
  // LogoutRequest carries no return address, so Keycloak reads the SP metadata
  // it was configured with, and the mock — which publishes metadata and does
  // not consume it — uses the samlSingleLogoutService declared on the service
  // provider's directory entry, falling back to the assertion consumer service
  // URL it last used. The launchers declare it; the fallback is right for this
  // stack anyway, because the api's /samlacs and /samlslo are one handler.
  for (const idp of samlIdps) {
    const logoutJob = {
      name: "SAML 2.0 Single Logout (login → LogoutRequest → " +
          `LogoutResponse Success) (${idp.label})`,
      script: "saml_logout.js",
      env: Object.assign({}, idp.env),
    };
    if (idp.skip) {
      logoutJob.skip = idp.skip;
    }
    jobs.push(logoutJob);
  }

  // WS-Federation Passive Requestor Profile SSO, run twice: against the
  // dedicated Keycloak 8.0.1 + cloudtrust keycloak-wsfed side-car (the 26.x
  // Keycloak has no WS-Fed support) and against the mock STS, which grew this
  // profile in 2026-08. Every combination below is pushed once per IdP.
  //
  // Two IdPs rather than one because they fail differently, and each covers what
  // the other cannot:
  //
  //   * **Keycloak is somebody else's implementation.** An EOL server carrying a
  //     third-party extension, provisioned through its admin API, with a real
  //     session cookie and a real login form. It is the only thing here that can
  //     tell us the debugger interoperates with software this project did not
  //     write — which is the entire point of the side-car and the reason it is
  //     kept alive at 8.0.1.
  //   * **The mock STS READS what the debugger sends.** Keycloak's extension
  //     ignores wreq, accepts any wauth and never states a token type, so nine
  //     of these jobs prove only that a request was built and a round trip
  //     completed. The mock refuses a wauth it cannot perform, a token type it
  //     does not offer and a wreqptr outright, each with a reason — so a request
  //     that is well-formed but wrong fails there and passes at Keycloak. It is
  //     also the only WS-Fed IdP available where the side-car is not: it runs in
  //     every stack the suite starts, including the host and live-site runs.
  //
  // Each is gated on its own metadata URL, so an environment with one and not
  // the other runs half of these and skips the other half naming which.
  {
    // The landing gate is shared: it is about the TARGET (does anything at
    // <base>/wsfed answer the IdP's POST), not about which IdP sent it.
    let landingSkip = null;
    if (env.WSFED_LANDING_AVAILABLE === "false") {
      // The other end of the round trip. The Passive Requestor Profile has ONE
      // way to return the token — the IdP auto-POSTs the wresult to wreply —
      // and no redirect alternative to fall back to the way SAML has. So the
      // target needs something at /wsfed that answers a POST.
      //
      // This used to be keyed on SAML_BACKEND_AVAILABLE, i.e. "static
      // deployments cannot do this at all". That was wrong: they can, with a
      // Lambda@Edge on that path (infra/edge/wsfed_landing.js), which is what
      // the hosted sites now run. What actually decides it is whether the
      // landing is DEPLOYED — the site bundle and the Terraform ship
      // independently — so remote-run-tests.sh probes the target with a real
      // POST and sets this. Unset (the containerized and local runs) means "not
      // probed", and the job runs against the api backend's landing as it
      // always has.
      landingSkip = "the target has no WS-Federation landing at " +
        (env.WSFED_LANDING_URL || "<base>/wsfed") +
         " to receive the IdP's wresult POST " +
        "(the profile has no redirect binding). On a static deployment, " +
            "apply the infrastructure " +
        "(./infra/terraform-local.sh test apply) so the Lambda@Edge landing " +
            "exists, and build the " +
        "site with wsfedEdgeLanding: true.";
    }

    // The two IdPs. `env` per IdP is everything wsfed_sso.js needs to know
    // about it — the rest of the job list below is identical for both, which is
    // the property worth keeping: a case added for one is added for the other.
    const wsfedIdps = [
      {
        key: "keycloak",
        label: "Keycloak",
        // common.sh's configureKeycloakWsfed exports this only once the
        // side-car has provisioned AND served its descriptor, so an unset value
        // means the IdP is genuinely absent rather than merely unconfigured.
        skip: env.WSFED_METADATA_URL ? null :
          "WS-Federation side-car (Keycloak 8.0.1 + wsfed) not provisioned (WSFED_METADATA_URL unset).",
        env: {
          WSFED_IDP: "keycloak",
          WSFED_METADATA_URL: env.WSFED_METADATA_URL,
          WSFED_REALM: env.WSFED_REALM,
          WSFED_USER: env.WSFED_USER,
          // Where the MOCK is, which this half is not. It is passed to both
          // halves on purpose and selects itself out: the test registers the
          // relying party only when the identity provider it was given is on
          // that origin, so Keycloak's provisioned client is never also
          // created in the mock's registry. See tests/sts_applications.js.
          WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        },
      },
      {
        key: "sts",
        label: "mock STS",
        skip: env.WSFED_STS_METADATA_URL ? null :
          "the mock STS is not reachable by the browser for WS-Federation (WSFED_STS_METADATA_URL unset). " +
          "The launchers set it wherever the STS is reachable — the containerized stack by compose DNS " +
          "name, the host and live-site runs over loopback.",
        env: {
          WSFED_IDP: "sts",
          WSFED_METADATA_URL: env.WSFED_STS_METADATA_URL,
          // The mock REQUIRES no relying party registration, so the wtrealm is
          // any string and becomes the assertion's audience. It is given one
          // that says where it came from rather than reusing Keycloak's
          // provisioned client id, so an audience seen in a log names its own
          // test — and the job registers it before the first wsignin1.0, with
          // the wreply the page will actually use. See
          // tests/sts_applications.js.
          WSFED_REALM: env.WSFED_STS_REALM || "urn:wsfed:sts:rp",
          // It authenticates nobody: the username becomes the subject and the
          // only password refused is the literal "invalid".
          WSFED_USER: env.WSFED_STS_USER || "wsfed",
          // Its passive endpoint does not sit under its metadata path the way
          // Keycloak's does. deriveEndpoint() knows the AD FS shape, but this
          // is only a fallback for a failed parse either way, so it is passed
          // explicitly where it is known.
          WSFED_SIGNIN_ENDPOINT: env.WSFED_STS_ENDPOINT ||
            (env.WSFED_STS_METADATA_URL || "").replace(
              /\/FederationMetadata\/[^/]+\/FederationMetadata\.xml.*$/i,
              "/wsfed"),
          // And it READS the inline wreq, refusing a token type it does not
          // offer — so the jobs that send one ask for an assertion type it
          // advertises. See the note on WREQ_TOKEN_TYPE in wsfed_sso.js.
          WSFED_WREQ_TOKEN_TYPE: "urn:oasis:names:tc:SAML:2.0:assertion",
          // And where its management API is, so the relying party is in the
          // registry before the first wsignin1.0 rather than created by it.
          WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        },
      },
    ];

    // One push per IdP. The name carries the IdP because both appear in the
    // same report and a failure that does not say which one it was sends
    // somebody to the wrong service.
    const pushWsfed = (name, extraEnv) => {
      log.debug("Entering pushWsfed().");
      for (const idp of wsfedIdps) {
        const job = {
          name: name + " [" + idp.label + "]",
          script: "wsfed_sso.js",
          env: Object.assign({}, idp.env, extraEnv),
        };
        // The IdP's own absence is the more specific reason, so it wins over
        // the landing's when both apply.
        if (idp.skip) { job.skip = idp.skip; }
        else if (landingSkip) { job.skip = landingSkip; }
        jobs.push(job);
      }
      log.debug("Leaving pushWsfed().");
    };

    // Every valid combination of the sign-in request options the workflow
    // supports: the signing state (unsigned, or signed with each binding × each
    // algorithm) crossed with where the request is initiated from. The passive
    // request is not verified by the IdP, so a signature never blocks the round
    // trip — wsfed_sso.js asserts the signature was BUILT (client-side) and
    // then confirms the round trip still completes.
    const signStates = [{ key: "unsigned", env: { WSFED_SIGN: "off" } }];
    for (const binding of ["redirect", "enveloped"]) {
      for (const alg of ["rsa-sha256", "rsa-sha1", "rsa-sha384",
           "rsa-sha512"]) {
        signStates.push({
          key: binding + "+" + alg,
          env: { WSFED_SIGN: "on", WSFED_SIG_BINDING: binding,
                WSFED_SIG_ALG: alg },
        });
      }
    }
    for (const s of signStates) {
      for (const initiate of ["back", "front"]) {
        pushWsfed(
          `WS-Federation Sign-in (sign=${s.key}, initiate=${initiate})`,
          Object.assign({ WSFED_MODE: "signin", WSFED_INITIATE: initiate },
                        s.env)
        );
      }
    }

    // Optional passthrough request parameters (wctx/wct/wfresh/wauth/wp),
    // exercised together once. Keycloak largely ignores them, so there this
    // proves the debugger emits them without breaking the round trip; the mock
    // STS reads all five and REFUSES a wauth naming a method it cannot perform
    // or a wfresh that is not a number of minutes, so the same job additionally
    // proves the values are ones an IdP that checks will accept.
    pushWsfed(
      "WS-Federation Sign-in (optional params: wctx/wct/wfresh/wauth/wp)",
      { WSFED_MODE: "signin", WSFED_INITIATE: "back", WSFED_OPT_PARAMS: "true" }
    );
    // Unsigned inline wreq (RequestSecurityToken) once.
    pushWsfed(
      "WS-Federation Sign-in (inline wreq)",
      { WSFED_MODE: "signin", WSFED_INITIATE: "back",
       WSFED_INCLUDE_WREQ: "true" }
    );

    // Sign-out (wa=wsignout1.0) + session-ended check. Must share a browser
    // with a sign-in, so this one job does sign-in → sign-out (the original
    // flow); signing is off here to keep the leg focused on session
    // termination.
    pushWsfed(
      "WS-Federation Passive SSO + Sign-out (Call IdP → login → " +
          "wsfed_response → wsignout1.0)",
      { WSFED_MODE: "signout", WSFED_INITIATE: "back", WSFED_SIGN: "off" }
    );
  }

  // WS-Trust 1.4 against the STS (the mock STS service, or a real Apache CXF
  // STS if WSTRUST_STS_URL points at one). Exercises all four operations —
  // Issue, Renew, Validate, Cancel — plus a signed Issue (WS-Security
  // XML-DSIG). Each job builds a SOAP RequestSecurityToken, sends it through
  // the backend proxy (POST /wstrust), and asserts the RSTR / issued token /
  // status renders on the response page. Renew/Validate/Cancel first Issue a
  // token to act on.
  //
  // Skipped when no STS is reachable (WSTRUST_STS_URL unset) rather than
  // failing. Routing is exercised both ways: "back" sends through the API proxy
  // (POST /wstrust); "front" makes the browser call the STS directly. Issue
  // runs once per route; the other operations use backend routing.
  //
  // On a BACKEND-LESS target (the deployed static site: samlBackendAvailable
  // false) there is no /wstrust proxy — the page disables backend routing and
  // sends every request from the browser. So rewrite "back" to "front" there
  // (rather than letting the report claim backend routing it never used) and
  // skip the one job whose entire subject is backend routing. The live-site run
  // supplies a loopback STS the browser can reach; see remote-run-tests.sh.
  var wstrustStsUrl = env.WSTRUST_STS_URL || "";
  var wstrustSkip = "WS-Trust needs an STS (WSTRUST_STS_URL) — none reachable from this target.";
  var wstrustNoBackendSkip = "This target has no API proxy (POST /wstrust) — backend routing cannot be exercised; the frontend-routing jobs cover the exchange.";
  // Effective routing for a job that asks for the backend proxy.
  var wstrustRoute = function (route) {
    log.debug("Entering wstrustRoute().");
    log.debug("Leaving wstrustRoute().");
    return (route === "back" && !samlBackendAvailable) ? "front" : route;
  };
  var wstrustJobs = [
    { op: "issue", sign: "false", route: "back",
     label: "Issue (backend routing)", backendOnly: true },
    { op: "issue", sign: "false", route: "front",
     label: "Issue (frontend routing)" },
    { op: "issue", sign: "true", route: "back",
     label: "Issue (signed, WS-Security XML-DSIG)" },
    { op: "renew", sign: "false", route: "back", label: "Renew" },
    { op: "validate", sign: "false", route: "back", label: "Validate" },
    { op: "cancel", sign: "false", route: "back", label: "Cancel" },
  ];
  for (const wj of wstrustJobs) {
    const job = {
      name: "WS-Trust 1.4 — " + wj.label,
      script: "wstrust.js",
      env: {
        WSTRUST_STS_URL: wstrustStsUrl,
        WSTRUST_OP: wj.op,
        WSTRUST_SIGN: wj.sign,
        WSTRUST_ROUTE: wstrustRoute(wj.route),
      },
    };
    if (!wstrustStsUrl) {
      job.skip = wstrustSkip;
    } else if (wj.backendOnly && !samlBackendAvailable) {
      job.skip = wstrustNoBackendSkip;
    }
    jobs.push(job);
  }

  // Encrypted-token round-trip: sign the request, ask the STS to encrypt the
  // issued assertion (?encrypt=1) to the requestor cert, then DECRYPT it on the
  // response page and confirm a plaintext assertion (exercises decryptXml).
  var encJob = {
    name: "WS-Trust 1.4 — Issue (encrypted token, decrypt)",
    script: "wstrust.js",
    env: {
      WSTRUST_STS_URL: wstrustStsUrl,
      WSTRUST_OP: "issue",
      WSTRUST_SIGN: "true",
      WSTRUST_ROUTE: wstrustRoute("back"),
      WSTRUST_ENCRYPT: "true",
    },
  };
  if (!wstrustStsUrl) {
    encJob.skip = wstrustSkip;
  }
  jobs.push(encJob);

  // Cycle the WS-Trust protocol version (1.0–1.4) with an Issue each, so each
  // version's trust namespace and option-gating (Bearer key type is 1.3+,
  // ActAs is 1.4) is exercised end to end against the STS.
  for (const wv of ["1.0", "1.1", "1.2", "1.3", "1.4"]) {
    const job = {
      name: "WS-Trust " + wv + " — Issue",
      script: "wstrust.js",
      env: {
        WSTRUST_STS_URL: wstrustStsUrl,
        WSTRUST_OP: "issue",
        WSTRUST_SIGN: "false",
        WSTRUST_ROUTE: wstrustRoute("back"),
        WSTRUST_VERSION: wv,
      },
    };
    if (!wstrustStsUrl) {
      job.skip = wstrustSkip;
    }
    jobs.push(job);
  }

  // XML Signature & XML Encryption interop. A pure-Node test (no browser, no
  // IdP) that runs the WS-Trust workflow's in-browser crypto
  // (common/xmldsig.js) and validates its output against official
  // libraries: xml-crypto verifies the WS-Security signature; xml-encryption
  // decrypts the XML-Encryption output.
  jobs.push({
    name: "XML Signature & Encryption interop (xml-crypto / xml-encryption)",
    script: "xmlsec_interop.js",
    env: {},
  });

  // POST-QUANTUM XML SIGNATURE. A pure-Node test (no browser, no IdP) of the
  // sixteen SignatureMethod identifiers common/xmldsig.js took from
  // draft-eastlake-rfc9231bis-xmlsec-uris-09 — ML-DSA at three parameter sets,
  // SLH-DSA at twelve, and HSS/LMS — driven through the real engine with
  // client/src/xmldsig_pqc.js as the signer, which is the one bridge from a
  // URI to the module that performs it. The lattice itself is somebody else's
  // test (pqc_engines.js, hbs_signatures.js); what this asserts is the XML
  // layer: that the bytes signed are the canonicalized SignedInfo, that each
  // URI produces the signature length FIPS 204/205 specifies for the set it
  // names, that a tampered document is caught by the REFERENCE digest rather
  // than by the signature, and that HSS/LMS reports the one-time key it spent.
  jobs.push({
    name: "Post-quantum XML Signature (ML-DSA, SLH-DSA, HSS/LMS — the draft " +
          "identifiers, the signed octets, and the stateful one)",
    script: "xmldsig_pqc.js",
    env: {},
  });

  // FRODOKEM AND eFRODOKEM AGAINST THE PUBLISHED VECTORS. A pure-Node test of
  // client/src/frodokem.js, which is the only cryptographic primitive in this
  // project with NO LIBRARY BEHIND IT — @noble has no FrodoKEM, npm has none,
  // and the one credible open implementation is C. It was written from the
  // specification, so it is held to microsoft/PQCrypto-LWEKE's own KAT files
  // for all twelve parameter sets: seed NIST's AES-256-CTR-DRBG with the
  // published seed and require the published public key, secret key,
  // ciphertext and shared secret back. That is not a formality — it caught a
  // real defect on its first run, in four of the twelve, that a round-trip
  // test cannot see.
  jobs.push({
    name: "FrodoKEM and eFrodoKEM against the reference implementation's " +
          "Known Answer Tests (all twelve parameter sets)",
    script: "frodokem_vectors.js",
    env: {},
  });

  // WS-Trust message schema validation. A pure-Node test that builds the RST
  // for every scenario (each version × operation) with the real generator and
  // validates it against a schema derived from the official OASIS WS-Trust 1.3
  // XSD (libxmljs2/libxml2). Self-skips (exit 0) if libxmljs2 — an optional
  // native dependency — isn't installed on the platform.
  jobs.push({
    name: "WS-Trust message schema validation (RST vs OASIS-derived XSD)",
    script: "wstrust_schema_validate.js",
    env: {},
  });

  // ---------------------------------------------------------------------------
  // PKI: the certificate authority workflow (client/public/pki.html), its two
  // modules, and the TLS test the api makes for it.
  //
  // Three of the four are node-only and never skip. That split is deliberate
  // and it is what makes "every combination" affordable: the certificates
  // themselves are checked in node against OPENSSL — a second implementation,
  // which is the only kind of check that catches an encoding that is wrong and
  // self-consistent — while the browser test is left with only the page.
  // ---------------------------------------------------------------------------

  // Certificate authoring: every signature algorithm crossed with every subject
  // key algorithm (~240 certificates), every X.509v3 extension, a four-deep
  // root/intermediate/issuing/leaf chain, and the enforcement of the extensions
  // that are supposed to REFUSE something — name constraints, pathLenConstraint,
  // and an unknown critical extension.
  //
  // The assertions are made by `openssl verify` and `openssl x509 -text` rather
  // than by reading back what this codebase just wrote, because every defect
  // this test was written for produces bytes that parse perfectly and are
  // refused by something else: a Name built as one multi-valued RDN, an
  // otherName wrapped in a second [0] tag (`openssl verify` says
  // `ossl_x509v3_cache_extensions:reason(158)` and names nothing), a signature
  // whose declared algorithm is not the one used, and a 2050+ date encoded as a
  // UTCTime, which reads as 1950. Node only, never skipped.
  jobs.push({
    name: "PKI certificates (every algorithm combination, every X.509v3 " +
        "extension, a four-deep chain — against OpenSSL)",
    script: "pki_x509.js",
    env: {},
  });

  // Key generation and every keystore format — PEM, DER, JWK set and PKCS#12,
  // each with and without a password — read back by OpenSSL. This module was
  // the bottom third of jwt_tools.js and was exercised only through that page's
  // Download button, which can see a status line and not a file; extracting it
  // for the PKI page is what made the matrix testable. Node only, never
  // skipped.
  jobs.push({
    name: "PKI key material (7 algorithms x 4 keystore formats, encrypted " +
        "and not — against OpenSSL)",
    script: "pki_key_formats.js",
    env: {},
  });

  // The POST-QUANTUM half of the same page: ML-DSA, SLH-DSA and ML-KEM keys and
  // certificates (RFC 9881, 9909, 9935), the sixteen composite ML-DSA
  // algorithms of draft-ietf-lamps-pq-composite-sigs-19, the X.509 (2019)
  // hybrid extensions, and 126 links of chains that MIX classical and
  // post-quantum issuers.
  //
  // It is a second file rather than more rows in pki_x509.js because the oracle
  // is different: the `openssl` BINARY is whatever the base image ships — 3.5
  // today, 3.0 a release ago, 3.0 on an Ubuntu 22.04 development host — and on
  // 3.0 there are no post-quantum algorithms at all, so an ML-DSA certificate
  // comes back as `X509_PUBKEY_get0:decode error`, a statement about OpenSSL
  // rather than about the certificate. Node's OpenSSL moves with the node
  // version, which every image here PINS at 24.16 (OpenSSL 3.5.6), so the
  // assertions go through node's crypto module (tests/openssl35.js) and are
  // the same everywhere. The HYBRID cases go back to the binary deliberately,
  // whichever it is, because their whole claim is that a validator which does
  // not enforce those extensions accepts the certificate anyway. Node only,
  // never skipped.
  //
  // PQC_SLOW=1 additionally issues certificates with the six slow SLH-DSA
  // parameter sets, which costs about three minutes: SLH-DSA-SHAKE-256s takes
  // 18 seconds for one signature in JavaScript against 0.9 in OpenSSL's C.
  // Without it those six are covered in the direction that is free — OpenSSL
  // signs, this build verifies.
  jobs.push({
    name: "PKI post-quantum certificates (ML-DSA, SLH-DSA, ML-KEM, 16 " +
        "composites, hybrid extensions, mixed chains — against OpenSSL 3.5)",
    script: "pki_pqc_x509.js",
    env: {},
  });

  // The TLS / mutual-TLS probe behind POST /tls/connect. Same accounting as the
  // Kerberos relay — `tls.connect` is a raw socket, so the SSRF guard's axios
  // installation never sees it — plus one assertion that earns its keep more
  // than the rest: a COMPLETED HANDSHAKE IS NOT AN ACCEPTED CLIENT CERTIFICATE.
  // Under TLS 1.3 the client is finished before the server has said anything
  // about the certificate, and the refusal arrives afterwards as an alert or as
  // a bare hang-up, so an implementation that resolves on `secureConnect`
  // answers "client authentication not required" for every TLS 1.3 server on
  // earth. It drives the module directly, with its own throwaway listeners, so
  // it needs no running api. Node only, never skipped.
  //
  // Gated per target, the way the Kerberos and LDAP workflows are. This job is
  // node-only and self-contained — it brings up its own throwaway listeners and
  // needs no api, no site and no network — so nothing STOPS it running against
  // https://idptools.com, and that is precisely the problem the Kerberos sweep
  // below was written for: it exercises LOCAL code and reports nothing whatever
  // about the deployed site. On a target whose PKI page has its TLS pane greyed
  // out, a green "TLS probe" line is the most misleading thing in the report.
  const pkiTlsOff = env.PKI_TLS_AVAILABLE === "false";
  const pkiTlsSkip = pkiTlsOff
    ? "the TLS test is not on this deployment: it is the one pane of the PKI " +
      "page that needs the api (a browser cannot choose a client " +
      "certificate, cannot be given a truststore, and cannot read the " +
      "handshake it made), and a static site has no api — so pki.js greys " +
      "that pane and disables every control in it. The PKI page job still " +
      "runs and checks exactly that. This job needs no api and would pass " +
      "here, which is why it is skipped rather than left to: it measures " +
      "local code and says nothing about the deployed site. Set " +
      "PKI_TLS_AVAILABLE=true for a remote target that IS api-backed."
    : null;
  const tlsProbeJob = {
    name: "TLS probe (address policy on raw sockets, port allowlist, " +
        "truststores, mutual-auth measurement, deadlines)",
    script: "api_tls_probe.js",
    env: {},
  };
  if (pkiTlsSkip) tlsProbeJob.skip = pkiTlsSkip;
  jobs.push(tlsProbeJob);

  // The page itself: the root/intermediate/issuing/leaf hierarchy built
  // entirely through the form, the store surviving a reload, the private-key
  // opt-out in both states (read out of localStorage, because that failure is
  // silent in the reassuring direction), and the TLS test end to end through
  // the api. It also asserts the one thing this page's design forbids — a
  // browser-side option for the TLS test, which a browser could not honour.
  // Needs the client, and the api for its last section, which skips without
  // one.
  jobs.push({
    name: "PKI page (CA hierarchy through the form, the store, the " +
        "private-key opt-out, the api-only TLS test)",
    script: "pki_page.js",
    env: {},
  });

  // The same page against a server that ANSWERS BACK. The job above points the
  // TLS pane at the client's own plain-HTTP port on purpose — a handshake that
  // fails with a real alert proves the whole round trip and needs no TLS
  // service — but it therefore proves nothing about the certificate, since
  // nothing ever accepted one. This one issues a client certificate from a Root
  // and an Issuing CA in the browser, presents it to the mock STS's two HTTPS
  // listeners, and asserts on the SERVER's own account of the connection: which
  // chain it built (a leaf sent without its intermediates is invisible from the
  // client), which anchor it verified against, and that the mutual-auth verdict
  // is `required` rather than `required-and-rejected` — the two an operator
  // confuses, told apart here by trusting the CA between two otherwise
  // identical runs.
  //
  // STS_TLS_URL is the mock's PLAIN HTTP base, and it is a variable of its own
  // rather than WSTRUST_STS_URL for the reason WSFED_STS_METADATA_URL is: that
  // one may legitimately point at a real Apache CXF STS, which has no TLS
  // endpoint of this kind at all. The test skips without it, and skips again if
  // the service it finds is older than the endpoint.
  //
  // The PKI_TLS_AVAILABLE gate reaches this one too. On a static target
  // STS_TLS_URL is not set at all, so it is already absent — but the two
  // variables are independent (STS_TLS_URL says a TLS endpoint exists,
  // PKI_TLS_AVAILABLE says the target has an api to reach it through), and a
  // run that sets the first without the second would otherwise drive the whole
  // exchange through an api that is not there.
  if (env.STS_TLS_URL) {
    const mutualTlsJob = {
      name: "PKI mutual TLS (a certificate issued in the browser, presented " +
          "through the api, and read back from the server's point of view)",
      script: "pki_mutual_tls.js",
      env: { STS_TLS_URL: env.STS_TLS_URL },
    };
    if (pkiTlsSkip) mutualTlsJob.skip = pkiTlsSkip;
    jobs.push(mutualTlsJob);
  }

  // ---------------------------------------------------------------------------
  // Kerberos is either present on this target or it is not, and when it is not
  // NONE of its jobs belong in the run — not just the four page ones.
  //
  // The gate used to be called KERBEROS_PAGES_AVAILABLE and was applied only to
  // the pages, which was right as far as it went and left ten jobs behind: the
  // codec, the crypto vectors, the PAC layout, the decoder output, the codec
  // sync, the relay, the two mock-KDC exchanges and the two Windows ones. Those
  // are node-only, so nothing stopped them, and they duly ran against
  // https://test.idptools.com — a deployment that has no Kerberos at all.
  //
  // They should not have. They exercise LOCAL code and say nothing whatever
  // about the deployed site, so on that target they are noise at best. At worst
  // they are misleading, which is what happened on 2026-08-15 and 2026-08-16:
  // remote-run-tests.sh sets CONFIG_FILE=./env/test-idptools-com.js, and
  // sts/helpers.js resolves a relative CONFIG_FILE against sts/ rather than
  // tests/ — where no such file exists, the submodule shipping only local.js,
  // docker-tests.js and test.js. Both mock-KDC jobs died with "Cannot find
  // module './env/test-idptools-com.js'", naming a config file, on a run whose
  // target has nothing to do with the mock. Two red tests, twice, for a
  // protocol that is switched off there.
  //
  // Doing it as a sweep rather than at each push site is deliberate: a Kerberos
  // test added later inherits the gate without anyone remembering to add it,
  // which is exactly how the original ten came to be missed.
  if (kerberosOff) {
    const kerberosSkip =
      "Kerberos is not part of this target. The workflow needs the api's " +
      "port-88 relay, which a static deployment has not got, so " +
      "client/static_site.js leaves all six pages out of the build and both " +
      "landing cards are greyed out. The codec and mock-KDC jobs are skipped " +
      "here too: they exercise local code and report nothing about the " +
      "deployed site, so running them adds noise and, when the run's " +
      "CONFIG_FILE does not resolve inside the sts/ submodule, spurious " +
      "failures. Run them against the containerized stack " +
      "(./docker-run-tests.sh) or a local dev server. Set " +
      "KERBEROS_AVAILABLE=true for a remote target that IS api-backed.";
    let swept = 0;
    for (const job of jobs) {
      if (!/^(krb5_|kerberos_|api_krb5_)/.test(job.script)) { continue; }
      if (job.skip) { continue; }        // a more specific reason already won
      job.skip = kerberosSkip;
      swept += 1;
    }
    log.info("Kerberos is off for this target: skipped " + swept +
      " further job(s) beyond the pages.");
  }

  // Label every job unit or browser. Done as a sweep for the same reason the
  // Kerberos skip above is: a job pushed later inherits it without anybody
  // remembering, and there are roughly a hundred push sites.
  for (const job of jobs) {
    job.type = jobTypeOf(job.script);
  }
  log.info("Roster: " + jobs.filter((j) => j.type === "unit").length +
    " unit, " + jobs.filter((j) => j.type === "browser").length + " browser.");

  log.debug("Leaving buildJobs().");
  return jobs;
}

// A job's name is a sentence, not a label — the SPIFFE engines one is 250
// characters — and every filesystem here caps a single NAME component at 255
// bytes. Past that the run does not fail the test, it dies: the WriteStream
// emits ENAMETOOLONG as an unhandled 'error' event and takes the whole runner
// with it, naming a path rather than a job. So the slug is truncated; the
// NN- index prefix is what makes the file unique, and the full name is in the
// log's own header and in the report.
const SLUG_MAX = 80;

function slug(s) {
  log.debug("Entering slug().");
  var out = s.toLowerCase().replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (out.length > SLUG_MAX) {
    out = out.slice(0, SLUG_MAX).replace(/-+$/, "");
  }
  log.debug("Leaving slug().");
  return out;
}

function logPathFor(name, index) {
  log.debug("Entering logPathFor().");
  log.debug("Leaving logPathFor().");
  return path.join(LOGS_DIR, `${String(index + 1).padStart(2,
                   "0")}-${slug(name)}.log`);
}

function logHeader(name, script, startedAt) {
  log.debug("Entering logHeader().");
  log.debug("Leaving logHeader().");
  return (
    [
      `Test:     ${name}`,
      `Script:   ${script}`,
      `Base URL: ${BASE_URL}`,
      `Started:  ${startedAt}`,
    ].join("\n") +
    "\n\n===== OUTPUT (stdout + stderr, in the order produced) =====\n"
  );
}

// ---------------------------------------------------------------------------
// Reaping a job's PROCESS TREE, which is not the same thing as its process.
//
// A browser job is `node` -> `chromedriver` -> `chrome`, and Chrome is itself
// about FIFTEEN processes (browser, two crashpad handlers, two zygotes, a gpu
// process, the network and storage services, a renderer per frame). Only the
// first of those three is this runner's child. When a test dies without
// reaching `driver.quit()` -- the `process.exit(1)`-inside-a-`catch` that
// skipped its own `finally` was the usual way until 2026-08-26, and a Ctrl-C
// is the other -- selenium's own exit hook (`io/exec.js`) sends SIGTERM to
// CHROMEDRIVER and nothing at all to the browser it launched. Chromedriver
// dies, Chrome is orphaned, and it keeps its share of the machine's memory
// until somebody reboots. Measured that day: ONE failing job left 11 Chrome
// processes behind, and a run of this suite left 559, which is what took the
// laptop out.
//
// So every job is spawned `detached`, which gives it a process GROUP of its
// own whose id is the child's pid. chromedriver inherits that group from node
// and chrome inherits it from chromedriver, so a single `process.kill(-pgid)`
// reaches the whole tree however deep it got. That is what makes this a
// BACKSTOP rather than a second copy of the per-script fix: it does not care
// why the tree survived, or whether the script that made it had been written
// yet. It runs after every job, passing or failing -- a job that passed can
// still have left a browser behind.
//
// `detached` has one consequence that has to be paid for right here, and
// forgetting it would be worse than the leak: a child in its own process group
// NO LONGER RECEIVES the terminal's Ctrl-C. Without the signal handlers below,
// interrupting the runner would leave the entire pool running with nothing
// left alive to reap it.
// ---------------------------------------------------------------------------

// A job that has printed nothing and not exited is not necessarily hung, so
// this is deliberately far above the slowest real job rather than near it: the
// longest single job in the 2026-08-26 run was 389 seconds and the run before
// it had one at 415. Fifteen minutes bounds a hang without turning a slow
// machine into a failure. TEST_JOB_TIMEOUT_MS overrides it, and 0 disables the
// timeout while leaving the process-group reaping in place.
const JOB_TIMEOUT_MS = (function () {
  const asked = parseInt(process.env.TEST_JOB_TIMEOUT_MS || "", 10);
  if (Number.isFinite(asked) && asked >= 0) {
    return asked;
  }
  return 900000;
})();

// The process group of every job currently running: added at spawn, removed
// once the group has been reaped.
const liveJobGroups = new Set();

// Kill one job's whole process group. Every failure here is ordinary rather
// than exceptional, which is why nothing is thrown and nothing is returned.
function killJobGroup(pgid, signal) {
  log.debug("Entering killJobGroup().");
  if (!pgid) {
    log.debug("Leaving killJobGroup(). No group.");
    return;
  }
  try {
    process.kill(-pgid, signal);
  } catch (e) {
    // ESRCH is the ordinary case and means the group has already gone, which
    // is exactly what a clean exit looks like. EPERM would mean the group is
    // not ours, which cannot happen for one we created, so it is worth a line.
    if (e.code !== "ESRCH") {
      log.warn("killJobGroup(" + pgid + ", " + signal + "): " + e.message);
    }
  }
  log.debug("Leaving killJobGroup().");
}

// Every live job's tree, killed synchronously. Safe to call from an 'exit'
// handler, which cannot await anything -- process.kill() is a syscall that
// returns immediately, and that is precisely why the backstop is a signal
// rather than a driver.quit().
function reapAllJobGroups() {
  log.debug("Entering reapAllJobGroups().");
  liveJobGroups.forEach(function (pgid) {
    killJobGroup(pgid, "SIGKILL");
  });
  liveJobGroups.clear();
  log.debug("Leaving reapAllJobGroups().");
}

process.on("exit", reapAllJobGroups);

// Ctrl-C and friends. The runner exits with the conventional status for the
// signal rather than a tidy 0, so a run that was interrupted does not read as
// a run that finished.
["SIGINT", "SIGTERM", "SIGHUP"].forEach(function (sig) {
  process.on(sig, function () {
    log.warn("Received " + sig + "; killing " + liveJobGroups.size +
        " running job process group(s) before exiting.");
    reapAllJobGroups();
    process.exit(sig === "SIGINT" ? 130 : 143);
  });
});

// Run one test, streaming its stdout AND stderr live to the console while
// simultaneously writing them to a per-test log file (a tee). The log is
// opened and the header written before the child starts, and flushed as
// output arrives, so the full output survives even if the suite is killed
// or a test hangs. Returns a Promise resolving to the result.
function runJob(job, index, live) {
  log.debug("Entering runJob().");
  log.debug("Leaving runJob().");
  return new Promise((resolve) => {
    const startedAt = new Date().toISOString();
    const startMs = Date.now();
    fs.mkdirSync(LOGS_DIR, { recursive: true });
    const logPath = logPathFor(job.name, index);
    const logStream = fs.createWriteStream(logPath);
    // A WriteStream with no 'error' listener throws its error as an unhandled
    // 'error' event, which is not a failed job — it is the whole runner
    // exiting mid-pool, naming a path rather than a test. Losing one job's
    // log file is the smaller loss: the output is still in `output` and so
    // still reaches the report.
    logStream.on("error", (e) => {
      log.warn("Log file " + logPath + " is not writable (" + e.code +
        "); continuing without it.");
    });
    logStream.write(logHeader(job.name, job.script, startedAt));

    let output = "";
    // The job's process group, its watchdog, and the guard that keeps the
    // timeout path and the 'close' that follows it from finishing twice.
    let pgid = null;
    let timer = null;
    let finished = false;
    const tee = (chunk) => {
      log.debug("Entering tee().");
      const s = chunk.toString();
      output += s;
      logStream.write(s); // capture
      if (live) {
        process.stdout.write(s); // live echo
      }
      log.debug("Leaving tee().");
    };

    const finish = (code, codeLabel) => {
      log.debug("Entering finish().");
      // The timeout path kills the tree and finishes the job itself, so the
      // 'close' that follows must not finish it a second time.
      if (finished) {
        log.debug("Leaving finish(). Already finished.");
        return;
      }
      finished = true;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      // The backstop, and the whole reason the job was spawned detached:
      // whatever it left running -- a chromedriver, a Chrome, both -- goes
      // now. The PASSING path reaches this too, because a job that passed can
      // still have leaked a browser.
      killJobGroup(pgid, "SIGKILL");
      liveJobGroups.delete(pgid);
      const durationMs = Date.now() - startMs;
      const passed = code === 0;
      logStream.end(
        `\n===== RESULT: ${passed ? "PASS" : "FAIL"} ` +
          `(exit ${codeLabel}, ${(durationMs / 1000).toFixed(1)}s) =====\n`
      );
      // Buffered rather than echoed as it arrived (see CONCURRENCY), so write
      // the whole of it now, in ONE call, as one block. Anything less and four
      // browsers' lines arrive shuffled together.
      if (!live) {
        const secs = (durationMs / 1000).toFixed(1);
        process.stdout.write(
          `\n===== [${index + 1}] ${job.name} — ` +
          `${passed ? "PASS" : "FAIL"} (${secs}s) =====\n` +
          output +
          `===== end of ${job.name} =====\n`);
      }
      resolve({
        name: job.name,
        script: job.script,
        type: job.type || "browser",
        passed,
        code: codeLabel,
        durationMs,
        output,
        logFile: path.relative(TESTS_DIR, logPath),
      });
      log.debug("Leaving finish().");
    };

    // NODE_V8_COVERAGE makes the child write its own raw V8 coverage on exit;
    // see the coverage block at the top of this file. It is set for EVERY job,
    // not only the browserless ones, because a page test that also loads a
    // shared module in-process covers real branches in it. Off unless
    // COVERAGE=true, so an ordinary run is byte-for-byte what it was.
    const childEnv = { ...process.env, ...job.env };
    if (nodeCoverageOn) {
      childEnv.NODE_V8_COVERAGE = NODE_COVERAGE_TMP;
    }
    const child = spawn("node", [path.join(TESTS_DIR, job.script), "--url",
        BASE_URL], {
      env: childEnv,
      // A process group of this job's own, so its whole tree can be killed as
      // one. See the reaping note above this function.
      detached: true,
    });
    pgid = child.pid;
    liveJobGroups.add(pgid);
    if (JOB_TIMEOUT_MS > 0) {
      timer = setTimeout(() => {
        const secs = (JOB_TIMEOUT_MS / 1000).toFixed(0);
        tee("\n[runner] no exit after " + secs + "s; killing this job's " +
            "process tree. Raise or disable with TEST_JOB_TIMEOUT_MS.\n");
        killJobGroup(pgid, "SIGKILL");
        finish(1, "timeout after " + secs + "s");
      }, JOB_TIMEOUT_MS);
    }
    child.stdout.on("data", tee);
    child.stderr.on("data", tee);
    child.on("error", (err) => {
      // e.g. node binary missing — record it instead of crashing the runner
      tee(`\n[runner] failed to spawn: ${err.message}\n`);
      finish(1, `spawn error: ${err.message}`);
    });
    child.on("close", (code) => finish(code, code));
  });
}

// Record a skipped job (a capability the target can't exercise, e.g. Artifact
// on a backendless deployment). Written to a log + returned as a result that is
// neither pass nor fail, so it doesn't count against the suite.
function makeSkipResult(job, index) {
  log.debug("Entering makeSkipResult().");
  const startedAt = new Date().toISOString();
  fs.mkdirSync(LOGS_DIR, { recursive: true });
  const logPath = logPathFor(job.name, index);
  const reason = job.skip || "skipped";
  fs.writeFileSync(
    logPath,
    logHeader(job.name, job.script, startedAt) +
      "SKIPPED: " + reason + "\n" +
      "\n===== RESULT: SKIP =====\n"
  );
  log.debug("Leaving makeSkipResult().");
  return {
    name: job.name,
    script: job.script,
    type: job.type || "browser",
    passed: true, // not a failure
    skipped: true,
    reason,
    code: "skip",
    durationMs: 0,
    output: "SKIPPED: " + reason,
    logFile: path.relative(TESTS_DIR, logPath),
  };
}

// ---- scheduling ------------------------------------------------------------

// One finished job's line in the runner's own log. Written when the job
// FINISHES rather than when it starts, so with a pool the order of these lines
// is the order things completed; the report itself is written in job order.
function reportOne(result, index, total) {
  log.debug("Entering reportOne().");
  log.info(`----- [${index + 1}/${total}] ` +
      `${result.passed ? "PASS" : "FAIL"} ` +
      `(${(result.durationMs / 1000).toFixed(1)}s) → ${result.logFile} ` +
      `— ${result.name}`);
  log.debug("Leaving reportOne().");
}

// The first job that has not started and whose lock nothing is holding, or -1.
// Called once per free slot rather than once per job, so it is not a hot path.
function nextRunnableJob(jobs, started, held) {
  log.debug("Entering nextRunnableJob().");
  for (let i = 0; i < jobs.length; i++) {
    if (started[i]) {
      continue;
    }
    const lock = lockOf(jobs[i]);
    if (lock && held.has(lock)) {
      continue;
    }
    log.debug("Leaving nextRunnableJob(). " + i);
    return i;
  }
  log.debug("Leaving nextRunnableJob(). Nothing runnable.");
  return -1;
}

// The pool itself. It cannot deadlock: a lock is only ever held by a RUNNING
// job, so when nothing is running nothing is held and the next job is always
// runnable — which is also why `remaining` reaching 0 with nothing active is
// the only exit.
function runPool(jobs, results, started, total) {
  log.debug("Entering runPool().");
  return new Promise(function (resolve) {
    const held = new Set();
    let active = 0;
    let remaining = started.filter(function (done) {
      return !done;
    }).length;

    const pump = function () {
      log.debug("Entering pump().");
      while (active < CONCURRENCY) {
        const i = nextRunnableJob(jobs, started, held);
        if (i < 0) {
          break;
        }
        const job = jobs[i];
        const lock = lockOf(job);
        started[i] = true;
        if (lock) {
          held.add(lock);
        }
        active = active + 1;
        log.info(`===== [${i + 1}/${total}] ${job.name} — started` +
            `${lock ? " (lock: " + lock + ")" : ""} =====`);
        // runJob() resolves for every outcome a child can have, including a
        // spawn that failed — so a REJECTION here is the runner itself
        // breaking. Caught all the same: an unhandled one would leave this
        // slot occupied and the pool would hang with no line saying why.
        const settle = function (result) {
          results[i] = result;
          if (lock) {
            held.delete(lock);
          }
          active = active - 1;
          remaining = remaining - 1;
          reportOne(result, i, total);
          pump();
        };
        runJob(job, i, CONCURRENCY === 1).then(settle, function (err) {
          settle({
            name: job.name,
            script: job.script,
            type: job.type || "browser",
            passed: false,
            code: "runner error: " + (err && err.message),
            durationMs: 0,
            output: "the runner failed to run this job: " + (err && err.stack),
            logFile: "",
          });
        });
      }
      if (active === 0 && remaining === 0) {
        resolve();
      }
      log.debug("Leaving pump().");
    };

    pump();
  });
}

// Skips first (they cost nothing and hold nothing), then the EXCLUSIVE jobs
// alone, then everything else in the pool. The exclusive pass is first rather
// than in its place in the list because draining a pool to make room for a
// 0.3-second job means waiting out whatever longest job is in flight; a job in
// that class restores everything it changes, which is what makes its position
// free to choose. NOTHING CLAIMS EXCLUSIVE at present — the pass then finds no
// job and costs nothing — and the table says why the mechanism is kept. See
// JOB_LOCKS.
async function runAllJobs(jobs, results) {
  log.debug("Entering runAllJobs().");
  const total = jobs.length;
  const started = jobs.map(function () {
    return false;
  });

  for (const [i, job] of jobs.entries()) {
    if (!job.skip) {
      continue;
    }
    log.info(`===== [${i + 1}/${total}] ${job.name} — SKIPPED =====`);
    log.info(`----- SKIP: ${job.skip}`);
    results[i] = makeSkipResult(job, i);
    started[i] = true;
  }

  for (const [i, job] of jobs.entries()) {
    if (started[i] || lockOf(job) !== EXCLUSIVE) {
      continue;
    }
    log.info(`===== [${i + 1}/${total}] ${job.name} — alone =====`);
    started[i] = true;
    // Live output: nothing else is running, so there is nothing to interleave
    // with, and this pass is where a stack that came up wrong shows first.
    results[i] = await runJob(job, i, true);
    reportOne(results[i], i, total);
  }

  await runPool(jobs, results, started, total);
  log.debug("Leaving runAllJobs().");
}

// ---- report rendering ------------------------------------------------------

function esc(s) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderHtml(results, generatedAt, demo) {
  log.debug("Entering renderHtml().");
  const total = results.length;
  const skipped = results.filter((r) => r.skipped).length;
  const passed = results.filter((r) => r.passed && !r.skipped).length;
  const failed = total - passed - skipped;
  const totalMs = results.reduce((a, r) => a + r.durationMs, 0);
  const units = results.filter((r) => r.type === "unit").length;

  const rows = results
    .map((r, i) => {
      const cls = r.skipped ? "skip" : r.passed ? "pass" : "fail";
      const badge = r.skipped ? "SKIP" : r.passed ? "PASS" : "FAIL";
      const log = esc((r.output || "").trim());
      const logLink = r.logFile
        ? `<br><a href="logs/${esc(path.basename(r.logFile))}"><code>${esc(
            r.logFile)}</code></a>`
        : "";
      const type = r.type === "unit" ? "unit" : "browser";
      return `
      <tr class="${cls}">
        <td><span class="badge ${cls}">${badge}</span></td>
        <td><span class="type ${type}">${type}</span></td>
        <td>${esc(r.name)}<br><code>${esc(r.script)}</code></td>
        <td class="num">${(r.durationMs / 1000).toFixed(1)}s</td>
        <td class="num">${esc(r.code)}</td>
        <td><details><summary>output</summary><pre>${log ||
            "(no output)"}</pre></details>${logLink}</td>
      </tr>`;
    })
    .join("");

  log.debug("Leaving renderHtml().");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>OAuth2/OIDC Debugger — Selenium Test Report</title>
<style>
  body{font-family:system-ui,Segoe UI,Helvetica,Arial,sans-serif;margin:2rem;color:#1b1b1b}
  h1{margin:0 0 .25rem} .sub{color:#666;margin:0 0 1.5rem}
  .demo{background:#fff3cd;border:1px solid #ffe08a;padding:.6rem 1rem;border-radius:6px;margin-bottom:1rem}
  .cards{display:flex;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap}
  .card{border:1px solid #e2e2e2;border-radius:8px;padding:1rem 1.4rem;min-width:120px}
  .card .n{font-size:1.8rem;font-weight:700}
  .card.ok .n{color:#1a7f37}.card.bad .n{color:#c1121f}
  table{border-collapse:collapse;width:100%}
  th,td{border-bottom:1px solid #eee;padding:.55rem .6rem;text-align:left;vertical-align:top}
  th{background:#fafafa} .num{text-align:right;white-space:nowrap}
  tr.fail{background:#fff5f5}tr.skip{background:#fbfbf5}
  .badge{font-weight:700;font-size:.75rem;padding:.15rem .5rem;border-radius:4px;color:#fff}
  .badge.pass{background:#1a7f37}.badge.fail{background:#c1121f}.badge.skip{background:#8a6d00}
  .type{font-size:.7rem;padding:.1rem .45rem;border-radius:10px;border:1px solid #d0d0d0;color:#555;white-space:nowrap}
  .type.unit{background:#eef4ff;border-color:#c3d4f5;color:#274b8f}
  code{background:#f3f3f3;padding:.05rem .3rem;border-radius:3px}
  pre{background:#0d1117;color:#e6edf3;padding:.8rem;border-radius:6px;overflow:auto;max-height:360px;font-size:.8rem}
  summary{cursor:pointer;color:#0969da}
</style></head><body>
<h1>OAuth2/OIDC Debugger — Selenium Test Report</h1>
<p class="sub">Generated ${esc(generatedAt)} · base URL <code>${esc(
                               BASE_URL)}</code></p>
${demo ? '<div class="demo"><strong>SAMPLE REPORT</strong> — generated with <code>--demo</code>. No tests were run; the data below is illustrative only.</div>' : ""}
<div class="cards">
  <div class="card"><div class="n">${total}</div><div>total</div></div>
  <div class="card ok"><div class="n">${passed}</div><div>passed</div></div>
  <div class="card bad"><div class="n">${failed}</div><div>failed</div></div>
  ${skipped ? `<div class="card"><div class="n">${skipped}</div><div>skipped</div></div>` : ""}
  ${runWallMs ? `<div class="card"><div class="n">${(runWallMs / 1000)
      .toFixed(1)}s</div><div>wall clock</div></div>` : ""}
  <div class="card"><div class="n">${(totalMs / 1000)
      .toFixed(1)}s</div><div>job time</div></div>
  <div class="card"><div class="n">${units}</div><div>unit (no browser)</div></div>
</div>
<table>
  <thead><tr><th>Result</th><th>Type</th><th>Test</th><th>Time</th><th>Exit</th><th>Output</th></tr></thead>
  <tbody>${rows}</tbody>
</table>
</body></html>`;
}


// Selenium Manager, which ships inside selenium-webdriver — the same binary the
// library shells out to for a driver. It is used here for the BROWSER, which it
// will fetch on request.
function seleniumManagerPath() {
  log.debug("Entering seleniumManagerPath().");
  const dir = process.platform === "win32" ? "windows"
    : process.platform === "darwin" ? "macos" : "linux";
  const name = process.platform === "win32" ? "selenium-manager.exe"
    : "selenium-manager";
  const out = path.join(TESTS_DIR, "node_modules", "selenium-webdriver", "bin",
      dir, name);
  log.debug("Leaving seleniumManagerPath().");
  return out;
}

function browserVersionOf(bin) {
  log.debug("Entering browserVersionOf().");
  let out = null;
  try {
    out = execFileSync(bin, ["--version"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch (e) {
    log.debug("browserVersionOf(): " + bin + " did not answer: " + e.message);
  }
  log.debug("Leaving browserVersionOf(). " + out);
  return out;
}

// Fetch a Chrome for Testing (and the chromedriver that matches it) through
// Selenium Manager, into ~/.cache/selenium.
//
// This is what turns "skipped: your Chrome cannot side-load an extension" into
// a job that runs. The download is ~150MB the first time and instant every time
// after — the cache is keyed by version and shared with anything else on this
// host that uses Selenium Manager — so it is done here, once, while the roster
// is being built rather than in the middle of the job.
//
// --force-browser-download is required, not optional: without it the manager
// finds the branded Chrome already on PATH and reports THAT, which is the
// browser this whole function exists to get away from.
function fetchTestingBrowser() {
  log.debug("Entering fetchTestingBrowser().");
  const manager = seleniumManagerPath();
  if (!fs.existsSync(manager)) {
    log.debug("Leaving fetchTestingBrowser(). No Selenium Manager at " +
        manager);
    return null;
  }
  let parsed;
  try {
    log.info("No extension-capable browser here; asking Selenium Manager for " +
        "a Chrome for Testing (first run downloads it).");
    const out = execFileSync(manager,
        ["--browser", "chrome", "--force-browser-download",
         "--output", "JSON", "--avoid-stats"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
          timeout: 600000 });
    parsed = JSON.parse(out);
  } catch (e) {
    log.warn("fetchTestingBrowser(): " + e.message);
    log.debug("Leaving fetchTestingBrowser(). Could not fetch.");
    return null;
  }
  const result = parsed && parsed.result;
  if (!result || !result.browser_path || !fs.existsSync(result.browser_path)) {
    log.warn("fetchTestingBrowser(): Selenium Manager named no browser.");
    log.debug("Leaving fetchTestingBrowser(). Nothing usable.");
    return null;
  }
  const out = { bin: result.browser_path,
                driver: result.driver_path || null,
                version: browserVersionOf(result.browser_path),
                fetched: true };
  out.capable = /Chrome for Testing|Chromium/i.test(out.version || "");
  log.info("Using " + (out.version || out.bin) + " for the extension job.");
  log.debug("Leaving fetchTestingBrowser(). " + out.bin);
  return out.capable ? out : null;
}

// Can the browser this run will use side-load an unpacked extension?
//
// BRANDED Google Chrome cannot. It refuses the flags and says so only on stderr
// ("--disable-extensions-except is not allowed in Google Chrome, ignoring"),
// after which the extension is simply absent and every assertion in the
// extension job times out naming nothing. Chrome for Testing — which the tests
// image pins — and Chromium both allow it.
//
// It used to answer with the FIRST browser it found and let the job skip when
// that one was branded Chrome, which is what `./local-run-tests.sh` reported on
// every host whose `google-chrome` is the real thing — a permanent skip on the
// launcher most people run. Two things changed on 2026-08-18:
//
//   * every candidate is probed and a CAPABLE one wins, so a host carrying
//     both Chromium and branded Chrome uses the Chromium rather than reporting
//     on whichever name came first in the list;
//   * and when none of them is capable, one is FETCHED — Selenium Manager
//     downloads a Chrome for Testing and the chromedriver that matches it,
//     which is the same thing the containerized suite gets by pinning it in
//     the image.
//
// So the skip is now only for a host that has no capable browser AND cannot
// reach the network to get one, which is the one case where it really is an
// environment capability rather than something this runner can arrange.
function extensionCapableBrowser() {
  log.debug("Entering extensionCapableBrowser().");
  const candidates = [process.env.CHROME_BIN, "chrome", "chromium",
      "chromium-browser",
                      "google-chrome"].filter(Boolean);
  let firstFound = null;
  for (const bin of candidates) {
    const version = browserVersionOf(bin);
    // Not on PATH under this name; try the next.
    if (!version) {
      continue;
    }
    // Resolve to an absolute path, because the job is told to USE this exact
    // binary. Probing one browser and letting Selenium launch another is how a
    // host with both Chromium and branded Chrome would report capable and then
    // fail anyway.
    let resolved = bin;
    if (!path.isAbsolute(bin)) {
      try {
        resolved = execFileSync("which", [bin], { encoding: "utf8" }).trim() ||
            bin;
      } catch (e) {
        // `which` is absent or the name is a shell builtin; the PATH name is
        // the best we have, and Selenium resolves it the same way.
        resolved = bin;
      }
    }
    const found = { bin: resolved, driver: null, version: version,
                    capable: /Chrome for Testing|Chromium/i.test(version) };
    if (found.capable) {
      log.debug("Leaving extensionCapableBrowser(). " + version);
      return found;
    }
    if (!firstFound) firstFound = found;
  }
  const fetched = fetchTestingBrowser();
  if (fetched) {
    log.debug("Leaving extensionCapableBrowser(). Fetched " + fetched.version);
    return fetched;
  }
  log.debug("Leaving extensionCapableBrowser(). Nothing capable.");
  return firstFound ||
      { bin: null, driver: null, version: null, capable: false };
}

function renderJUnit(results, generatedAt) {
  log.debug("Entering renderJUnit().");
  const total = results.length;
  const failures = results.filter((r) => !r.passed && !r.skipped).length;
  const skips = results.filter((r) => r.skipped).length;
  const totalSec = (results.reduce((a, r) => a + r.durationMs,
      0) / 1000).toFixed(3);
  const cases = results
    .map((r) => {
      const time = (r.durationMs / 1000).toFixed(3);
      const sys = esc((r.output || "").trim());
      const body = r.skipped
        ? `<skipped message="${esc(r.reason || "skipped")}"/>`
        : r.passed
        ? ""
        : `<failure message="exit ${esc(r.code)}">Test exited with status ${esc(
                                        r.code)}</failure>`;
      // classname is what a CI dashboard groups by, so the two halves of the
      // suite are told apart there rather than only in report.html.
      const cls = r.type === "unit" ? "unit" : "selenium";
      return `    <testcase classname="${cls}" name="${esc(r.name)}" time="${time}">${body}<system-out>${sys}</system-out></testcase>`;
    })
    .join("\n");
  log.debug("Leaving renderJUnit().");
  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="oauth2-oidc-debugger" tests="${total}" failures="${failures}" skipped="${skips}" time="${totalSec}" timestamp="${esc(generatedAt)}">
${cases}
  </testsuite>
</testsuites>
`;
}

// ---- node coverage ---------------------------------------------------------

// Make (and empty) the directory the children will write raw V8 coverage into.
//
// Emptying it is not tidiness. NODE_V8_COVERAGE appends a file per process and
// c8 reads whatever it finds, so a leftover pile from the previous run would be
// merged into this one's numbers — a report that improves every time it is
// rendered and never says why.
function prepareNodeCoverage() {
  log.debug("Entering prepareNodeCoverage().");
  if (!nodeCoverageOn) {
    log.debug("Leaving prepareNodeCoverage(). Not collecting.");
    return;
  }
  try {
    fs.rmSync(NODE_COVERAGE_TMP, { recursive: true, force: true });
    fs.mkdirSync(NODE_COVERAGE_TMP, { recursive: true });
  } catch (e) {
    nodeCoverageOn = false;
    log.warn("Node coverage is off: " + NODE_COVERAGE_TMP + " is not " +
      "writable (" + e.message + "). Mount ./coverage into this container " +
      "(docker-compose-coverage.yml) or set NODE_COVERAGE_DIR.");
    log.debug("Leaving prepareNodeCoverage(). Disabled.");
    return;
  }
  log.info("Node coverage: children will write V8 data to " +
    NODE_COVERAGE_TMP + "; the report lands in " + NODE_COVERAGE_DIR + ".");
  log.debug("Leaving prepareNodeCoverage().");
}

// What c8 must NOT report on: the test scripts themselves.
//
// The tests image copies the shared modules FLAT beside the test scripts, so
// /usr/src/app holds both scim_engine.js (the test) and scim_client.js (the
// module it drives) — there is no directory to separate them by, only the name.
// The names are safe to exclude by: tests/jwk_pem_encoding.js already asserts
// that no shared module collides with a test script in that flat copy, which is
// what makes "exclude every job's script" mean "exclude the tests" and nothing
// else.
//
// The helpers are named too. They are modules rather than jobs, so no job's
// script names them and the sweep above would leave them in the report as
// though they were product code.
function coverageExcludes(jobs) {
  log.debug("Entering coverageExcludes().");
  const names = new Set(jobs.map((job) => job.script));
  ["run-report.js", "module_paths.js", "wait_for.js", "random_username.js",
    "common.sh"].forEach(function (name) {
    names.add(name);
  });
  // Every pattern is `**/`-prefixed, and that is not cosmetic: a bare
  // `scim_engine.js` matches NOTHING here. c8 reports on files above its own
  // cwd (the modules live in ../client/src and ../api on a host run), so it
  // resolves paths against a common ancestor rather than against cwd, and a
  // pattern with no directory part never lines up with the relative path it is
  // matched against. It fails silently — the report simply lists the test
  // scripts as though they were product code.
  //
  // The mock STS is somebody else's checkout (a submodule), and node-ldapjs is
  // vendored unmodified. A test that starts either one in-process would
  // otherwise drag its files into this repository's report.
  const out = Array.from(names).sort().map((name) => "**/" + name)
    .concat(["**/node_modules/**", "**/sts/**", "**/node-ldapjs/**"]);
  log.debug("Leaving coverageExcludes(). " + out.length + " pattern(s).");
  return out;
}

// Render the pile the children left behind. Runs HERE, in the tests container,
// for the same reason COVERAGE.md gives for rendering the frontend report
// inside the client image: the paths recorded in the raw data are the paths the
// modules were loaded from, and only this filesystem still has them.
function renderNodeCoverage(jobs) {
  log.debug("Entering renderNodeCoverage().");
  if (!nodeCoverageOn) {
    log.debug("Leaving renderNodeCoverage(). Not collecting.");
    return;
  }
  let files = [];
  try {
    files = fs.readdirSync(NODE_COVERAGE_TMP);
  } catch (e) {
    log.warn("renderNodeCoverage(): cannot read " + NODE_COVERAGE_TMP + ": " +
      e.message);
  }
  if (files.length === 0) {
    // Not an error worth failing on, but it is never expected: every job is a
    // node process and node writes this on exit. Say so loudly enough that a
    // silently empty report is not read as "nothing is covered".
    log.warn("Node coverage: no V8 data was written to " + NODE_COVERAGE_TMP +
      ". No report rendered.");
    log.debug("Leaving renderNodeCoverage(). Nothing collected.");
    return;
  }
  const c8 = path.join(TESTS_DIR, "node_modules", ".bin", "c8");
  if (!fs.existsSync(c8)) {
    log.warn("Node coverage: c8 is not installed at " + c8 + ". The raw V8 " +
      "data is still in " + NODE_COVERAGE_TMP + "; `npx c8 report " +
      "--temp-directory " + NODE_COVERAGE_TMP + "` renders it.");
    log.debug("Leaving renderNodeCoverage(). No c8.");
    return;
  }
  // --allowExternal is required, not decorative: c8 drops every file outside
  // its cwd by default, and on a HOST run the modules under test live in
  // ../client/src and ../api. Without it that run renders an empty report and
  // says nothing about why.
  const args = ["report", "--temp-directory", NODE_COVERAGE_TMP,
    "--reports-dir", NODE_COVERAGE_DIR, "--allowExternal",
    "--reporter=html", "--reporter=lcov", "--reporter=text-summary"];
  coverageExcludes(jobs).forEach(function (pattern) {
    args.push("--exclude", pattern);
  });
  log.info("Node coverage: rendering " + files.length + " V8 file(s) with c8.");
  try {
    const out = execFileSync(c8, args, { cwd: TESTS_DIR, encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"] });
    String(out || "").split(/\r?\n/).forEach(function (line) {
      if (line.trim() !== "") {
        log.info("c8: " + line);
      }
    });
  } catch (e) {
    log.warn("renderNodeCoverage(): c8 failed: " + e.message);
    log.debug("Leaving renderNodeCoverage(). c8 failed.");
    return;
  }
  log.info("Node coverage report written to " + NODE_COVERAGE_DIR +
    "/index.html (and lcov.info).");
  log.debug("Leaving renderNodeCoverage().");
}

function writeReports(results, demo) {
  log.debug("Entering writeReports().");
  const generatedAt = new Date().toISOString();
  fs.mkdirSync(RUN_DIR, { recursive: true });
  fs.writeFileSync(path.join(RUN_DIR, "report.html"), renderHtml(results,
                   generatedAt, demo));
  fs.writeFileSync(path.join(RUN_DIR, "report.xml"), renderJUnit(results,
                   generatedAt));
  updateLatestPointer();
  log.debug("Leaving writeReports().");
}

// Best-effort convenience pointer to the most recent run. Prefers a symlink;
// falls back to a small text file where symlinks aren't permitted (e.g.
// Windows).
function updateLatestPointer() {
  log.debug("Entering updateLatestPointer().");
  const link = path.join(REPORT_DIR, "latest");
  try {
    if (fs.existsSync(link) || fs.lstatSync(link, { throwIfNoEntry: false })) {
      fs.rmSync(link, { recursive: true, force: true });
    }
  } catch (_) {
    /* nothing to remove */
  }
  try {
    fs.symlinkSync(RUN_ID, link, "dir");
  } catch (_) {
    fs.writeFileSync(path.join(REPORT_DIR, "latest.txt"), RUN_ID + "\n");
  }
  log.debug("Leaving updateLatestPointer().");
}

function demoResults() {
  log.debug("Entering demoResults().");
  const startedAt = new Date().toISOString();
  fs.mkdirSync(LOGS_DIR, { recursive: true });
  log.debug("Leaving demoResults().");
  return buildJobs().map((j, i) => {
    const passed = i !== 2; // pretend one failed, for preview
    const output =
      (passed
        ? "Entering populateMetadata().\nFind oidc_discovery_endpoint.\n... (hundreds of lines in a real run) ...\nToken validated.\nTest completed successfully."
        : "Entering populateMetadata().\n... (hundreds of lines in a real " +
            "run) ...\nAssertionError: expected token to contain claim 'aud'") +
            "\n";
    const result = {
      name: j.name,
      script: j.script,
      type: j.type || "browser",
      passed,
      code: passed ? 0 : 1,
      durationMs: 3000 + i * 1500,
      output,
      logFile: path.relative(TESTS_DIR, logPathFor(j.name, i)),
    };
    // Write a demo log file mirroring what a real run produces.
    fs.writeFileSync(
      logPathFor(j.name, i),
      logHeader(j.name, j.script, startedAt) +
        output +
        `\n===== RESULT: ${passed ?
            "PASS" : "FAIL"} (exit ${result.code}, ${(result.durationMs / 1000)
            .toFixed(1)}s) =====\n`
    );
    return result;
  });
}

async function main() {
  log.debug("Entering main().");
  const demo = process.argv.includes("--demo");
  let results;

  if (demo) {
    results = demoResults();
    log.info("Writing SAMPLE report (--demo); no tests executed.");
  } else {
    const jobs = buildJobs();
    // Filled BY INDEX rather than pushed: with a pool the jobs finish out of
    // order, and the report is written in the order they were built.
    results = new Array(jobs.length);
    prepareNodeCoverage();
    log.info(`Running ${jobs.length} test(s) against ${BASE_URL}, ` +
        `${CONCURRENCY} at a time.`);
    const wallStart = Date.now();
    await runAllJobs(jobs, results);
    runWallMs = Date.now() - wallStart;
    const jobMs = results.reduce(function (sum, r) {
      return sum + ((r && r.durationMs) || 0);
    }, 0);
    log.info(`Wall clock ${(runWallMs / 1000).toFixed(1)}s, for ` +
        `${(jobMs / 1000).toFixed(1)}s of job time ` +
        `(${(jobMs / Math.max(runWallMs, 1)).toFixed(1)}x).`);
    renderNodeCoverage(jobs);
  }

  writeReports(results, demo);

  const failed = results.filter((r) => !r.passed && !r.skipped).length;
  const skipped = results.filter((r) => r.skipped).length;
  const passed = results.length - failed - skipped;
  const rel = path.relative(process.cwd(), RUN_DIR);
  log.info(`Report written to ${rel}/report.html (and report.xml, logs/)`);
  log.info(`Latest run also at ${path.relative(process.cwd(),
           path.join(REPORT_DIR, "latest"))}`);
  const units = results.filter((r) => r.type === "unit").length;
  log.info(`Summary: ${passed} passed, ${failed} failed, ${skipped} skipped, ${results.length} total`);
  log.info(`Of those, ${units} are unit jobs (no browser) and ` +
    `${results.length - units} drive one.`);

  // Don't fail the demo run; otherwise signal failures to the caller/CI.
  process.exit(demo ? 0 : failed > 0 ? 1 : 0);
  log.debug("Leaving main().");
}

main();
