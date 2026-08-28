// File: rfc9700_flows.js
//
// ---------------------------------------------------------------------------
// Every OAuth2 / OIDC grant this debugger supports, driven through
// oauth2_oidc_1.html and oauth2_oidc_2.html with **BOTH SIDES IN RFC 9700
// MODE** — the debugger's compliance checkbox on, and a mock STS enforcing the
// BCP.
//
// THE COMPLIANT SERVER IS A TRUST REALM, NOT A SECOND INSTANCE, since
// 2026-08-25. It used to be a container of its own (`sts-rfc9700`) because
// `oauth2.rfc9700` derives `global.https` over there and one process could not
// bind its main port two ways. That flag is now the one setting in that service
// marked `realmRuntime` — restart-only for the process, settable on a realm,
// because a realm binds no socket — so the SAME instance answers permissively
// at `/oauth2/authorize` and enforces the BCP at
// `/realm/rfc9700/oauth2/authorize`, with its own issuer, signing key, codes
// and tokens. common/common.sh's configureStsRfc9700Realm() creates it; the
// realm is in memory and gone on restart, which is why it is a launcher step.
//
// NOTHING IN THIS FILE KNOWS THAT. Every URL it uses is built from the base it
// is given, so RFC9700_STS_URL simply carries the prefix
// (https://localhost:8081/realm/rfc9700) and the metadata document, the
// requirement report and the management API call all land in the realm. That
// property is worth keeping: a test that had to compose realm prefixes itself
// would be a test that could compose one wrongly and still pass.
//
// That pairing is the point of the file. The existing OAuth2 / OIDC jobs run
// this same matrix with both sides permissive, and between them the two passes
// ask different questions:
//
//   permissive  — does the debugger still work against a server that
//                 implements none of this? (Most servers. It is why the
//                 checkbox exists.)
//   compliant   — when the server DOES enforce RFC 9700, does the client meet
//                 it? An authorization server in that mode refuses a redirect
//                 URI it has not been given, refuses PKCE it cannot verify,
//                 refuses a response type that would put an access token in
//                 the address bar, and issues over https only. A client that
//                 quietly sent the wrong thing in the permissive pass is
//                 indistinguishable from one that did not; here it fails.
//
// The negatives matter more than the positives and are a job of their own
// (RFC9700_FLOW=refused). A compliance mode that issues a token on the happy
// path looks finished and can be worth nothing: what it is FOR is refusing the
// Implicit Grant, refusing the password grant, refusing a code presented
// twice, and refusing a response whose state or nonce does not match. Those
// cannot be reached from the happy path by definition.
//
// The always-on half — the headers, the 303, the form_post landing, and the
// callback not being an open redirector — is checked over plain HTTP at the
// start of every job, before a browser is built. Those are not behind the
// checkbox (see rfc9700.js's note on why), and they are cheap enough to assert
// on every run rather than in one job somebody might skip.
//
// The STS is located from WSTRUST_STS_URL, as the other STS-backed jobs are.
// RFC9700_FLOW selects what to run.
// ---------------------------------------------------------------------------

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require("selenium-webdriver/lib/select");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const http = require("http");
const https = require("https");
const { URL } = require("url");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const registry = require("./sts_applications.js");
const { usernameFor } = require("./random_username.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "rfc9700_flows",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;

// ---------------------------------------------------------------------------
// THE REDIRECT URI IS NOT ALWAYS baseUrl + "/callback", AND THE REASON IS
// REQUIREMENT 1.3 RATHER THAN THE TEST.
//
// In mode the client refuses to send a redirect_uri that is neither https nor
// on the loopback interface — RFC 8252's exception, which is what lets the
// debugger's own `http://localhost:3000/callback` be used against a local
// stack. A HOST run is already there and this is unset.
//
// The CONTAINERIZED stack is not: it serves the debugger at
// `http://client:3000`, a plain-http name that is not loopback, so the mode
// correctly refused every authorization request and all three flow jobs failed
// at the sign-in screen that never appeared. That is the product being right,
// so what moves is the redirect URI: RFC9700_REDIRECT_URI names a loopback one
// (run-tests-in-container.sh sets it), and buildDriver() adds the Chrome
// host-resolver rule that makes the browser's `localhost:3000` reach the client
// container. Only the /callback hop is on that origin, and it is stateless —
// the landing 303s straight back to appconfig.uiUrl, which is where every page
// this test drives lives and where the transaction's state is kept.
// ---------------------------------------------------------------------------
var redirectUri = process.env.RFC9700_REDIRECT_URI || "";

const { populateMetadata } = require("../common/tests.js")({ By, until, Select,
       waitTime, log, assert });

// The identity typed at the mock's sign-in screen. The mock checks no
// password, so this is simply the name every token then describes — which is
// why it can be, and is, generated per run: the mock keeps a users page, an
// authentication log and a statistics pane keyed by the name presented, and a
// name every test shares makes all of that unattributable. The prefix names
// this file so a row in any of them can be traced back to it. Pin it with
// RFC9700_USER (or RANDOM_USERNAME_STAMP) to re-drive a failed run.
const USER = process.env.RFC9700_USER || usernameFor("rfc9700-flows");
// The client this run is. It must be the same string throughout, because
// requirement 13.1 compares the token's `sub` against it — and since
// 2026-08-27 it is also REGISTERED before the browser starts, which is what
// makes the redirect-URI check below mean anything. That sentence used to read
// "the mock registers no clients, so this is any string": true of what the mock
// requires, and exactly the reason this job was proving less than it looked
// like it was.
const CLIENT_ID = "rfc9700-debugger";

// ---------------------------------------------------------------------------
// What each job runs. `label` is the option text in the grant selector, which
// is what a user picks and therefore what this picks.
//
// Three of the debugger's eleven grants survive RFC 9700 mode and are driven
// end to end here. What is absent is as deliberate as what is present:
//
//   the three Implicit variants and two of the three Hybrids — refused by
//     requirement 1.11, and the `refused` job proves it rather than this one
//     quietly not listing them;
//   Resource Owner Password Credentials — refused by 5.1, same;
//   the Device Authorization Grant — the debugger permits it (RFC 9700 says
//     nothing against it) but the mock STS in RFC 9700 mode publishes no
//     device_authorization_endpoint, so there is nothing to drive it against.
//     Stated here rather than left as an absence somebody has to account for.
// ---------------------------------------------------------------------------
const FLOWS = {
  authorization_grant: {
    label: "OAuth2 Authorization Code Grant",
    responseType: "code",
    scope: "openid profile email offline_access",
    exchangesCode: true
  },
  oidc_authorization_code_flow: {
    label: "OIDC Authorization Code Flow(code)",
    responseType: "code",
    scope: "openid profile email offline_access",
    exchangesCode: true
  },
  oidc_hybrid_code_id_token: {
    label: "OIDC Hybrid(code id_token)",
    responseType: "code id_token",
    scope: "openid profile email offline_access",
    exchangesCode: true
  },
  client_credential: {
    label: "OAuth2 Client Credential",
    responseType: "",
    scope: "openid profile",
    exchangesCode: false
  }
};

// The grants RFC 9700 mode must refuse, and the requirement each one meets.
const REFUSED_GRANTS = {
  implicit_grant: "1.11",
  oidc_implicit_flow: "1.11",
  oidc_implicit_flow_id_token: "1.11",
  oidc_hybrid_code_token: "1.11",
  oidc_hybrid_code_id_token_token: "1.11",
  resource_owner: "5.1"
};


// ---------------------------------------------------------------------------
// Plain HTTP, for the checks that need no browser.
// ---------------------------------------------------------------------------

// One request, no redirect following, self-signed certificates accepted. The
// mock STS in RFC 9700 mode is HTTPS with a certificate it generated at
// startup, which is the whole reason for the last part.
function request(url, options) {
  log.debug("Entering request(). url=" + url);
  var opts = options || {};
  return new Promise(function (resolve, reject) {
    var parsed = new URL(url);
    var lib = parsed.protocol === "https:" ? https : http;
    var req = lib.request(url, {
      method: opts.method || "GET",
      headers: opts.headers || {},
      rejectUnauthorized: false
    }, function (res) {
      var body = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) { body += chunk; });
      res.on("end", function () {
        log.debug("Leaving request(). status=" + res.statusCode);
        resolve({ status: res.statusCode, headers: res.headers, body: body });
      });
    });
    req.on("error", reject);
    if (opts.body) {
      req.write(opts.body);
    }
    req.end();
  });
}

// ---------------------------------------------------------------------------
// THE CALLBACK IS ONE CONTRACT WITH TWO IMPLEMENTATIONS, AND ONLY ONE OF THEM
// CAN REDIRECT.
//
// `client/server.js` answers GET and POST /callback with a 303 to
// oauth2_oidc_2.html. A STATIC DEPLOYMENT has no Express at all — S3 serves
// bytes and CloudFront hands them on — so `client/build.js` writes a
// `/callback/index.html` shim that does the same forwarding from inside the
// browser with `location.replace()`. That is not a lesser version of the route
// for the purposes of this file: requirements 11.1 and 12.1 are about where
// the authorization response is sent NEXT and whether the request can choose
// that destination, and a shim answers both questions just as a 303 does.
//
// So this returns which of the two is in front of us, and it REFUSES anything
// that is neither. A test that fell back to the static branch whenever the 303
// was missing would report a broken Express landing as a static deployment and
// pass — which is the failure mode this suite has had before, and the reason
// the unrecognised case is an assertion rather than a default.
// ---------------------------------------------------------------------------
async function callbackKind(landing) {
  log.debug("Entering callbackKind(). status=" + landing.status);
  if (landing.status === 303) {
    log.info("The deployment answers /callback with a 303: this is the " +
      "Express client.");
    log.debug("Leaving callbackKind(). express");
    return "express";
  }
  const staticShim = landing.status === 200 &&
      /location\.replace/.test(landing.body) &&
      landing.body.indexOf("/oauth2_oidc_2.html") !== -1;
  assert.ok(staticShim,
    "GET /callback answered " + landing.status + " and the body is neither " +
    "a 303 to the token page nor the static shim client/build.js writes " +
    "(a location.replace() onto /oauth2_oidc_2.html). One of the two has to " +
    "be there: it is where every authorization response this debugger " +
    "receives arrives. Body began: " +
    landing.body.slice(0, 200).replace(/\s+/g, " "));
  log.info("The deployment answers /callback with the static shim: there is " +
    "no Express here.");
  log.debug("Leaving callbackKind(). static");
  return "static";
}

// Requirements 11.1 and 12.1 against the STATIC shim. What is asserted is the
// same claim the 303 branch makes — the response is forwarded to this
// deployment's own token page, and the request cannot choose where it goes —
// read off the only thing there is to read: the script the browser will run.
function checkStaticCallback(landing, hostile) {
  log.debug("Entering checkStaticCallback().");
  assert.ok(/window\.location\.replace\(/.test(landing.body),
    "Requirement 12.1: the static callback shim does not use " +
    "location.replace(), so the landing stays in the history and the Back " +
    "button walks a person into the authorization response's URL again.");
  assert.ok(/'\/oauth2_oidc_2\.html'/.test(landing.body),
    "Requirement 11.1: the static callback shim's destination is not the " +
    "LITERAL '/oauth2_oidc_2.html'. It is built from location.search and " +
    "location.hash, and a destination assembled out of either would be an " +
    "open redirector reachable at a registered redirect_uri.");
  // The same hostile parameters the Express branch sends. A static file cannot
  // vary with them — which is the point, and is worth asserting rather than
  // assuming, because a build step that templated this page per request would
  // be exactly the change that broke it.
  assert.strictEqual(hostile.body, landing.body,
    "Requirement 11.1: /callback answered differently when the request " +
    "carried redirect_uri / return_to / url pointing elsewhere. The static " +
    "shim must be one file that ignores them.");
  assert.strictEqual(hostile.body.indexOf("evil.example.com"), -1,
    "Requirement 11.1: an attacker's host from the query string reached the " +
    "body of the callback landing.");
  log.info("The static callback shim forwards to this deployment's own token " +
    "page and takes nothing from the request.");
  log.debug("Leaving checkStaticCallback().");
}

// The always-on posture, over the wire rather than over the source.
// tests/rfc9700_client.js asserts the same properties by reading
// client/server.js; this asserts that the running deployment actually sends
// them, which is a different claim — a reverse proxy, a CDN or a build that
// serves public/ some other way can drop every one of them.
//
// THE HEADERS ARE ASSERTED ON EVERY TARGET, static included. There is no
// middleware chain on a static site, so they come from a CloudFront response
// headers policy instead (infra/terraform/cloudfront.tf) — a different
// mechanism for the same three headers on the same pages, and this is what
// holds the two together.
//
// It RETURNS which of the two landings it found, because the browser half of
// this job needs the same answer: requirement 10.4 asks a client to request
// response_mode=form_post only where there is something to receive the POST,
// so what the authorization request must carry differs between the two
// deployments. Probing it once here and passing it down keeps the two halves
// from disagreeing — which is exactly what they did until 2026-08-27, when
// this function said 10.4 was unavailable on a static site and runFlow()
// asserted the request had asked for it anyway, failing all three flow jobs
// on ./remote-run-tests.sh for a property the client had right.
async function checkAlwaysOnPosture() {
  log.debug("Entering checkAlwaysOnPosture().");
  log.info("Entering checkAlwaysOnPosture().");

  const page = await request(baseUrl + "/oauth2_oidc_2.html");
  assert.strictEqual(page.status, 200,
    "The debugger's token page did not answer 200.");
  assert.strictEqual(page.headers["referrer-policy"], "no-referrer",
    "Requirement 10.2: the page that receives an authorization response is " +
    "served without Referrer-Policy: no-referrer, so the response's URL " +
    "travels to every link and resource on it.");
  assert.strictEqual(page.headers["x-frame-options"], "DENY",
    "Requirement 14.1: X-Frame-Options is not DENY.");
  assert.ok(/frame-ancestors 'none'/.test(
      page.headers["content-security-policy"] || ""),
    "Requirement 14.1: the Content-Security-Policy does not restrict " +
    "frame-ancestors. RFC 9700 section 4.16 asks for CSP Level 2 and that " +
    "is the clause it means.");

  // 12.1 and 11.1, on the GET landing — in whichever of its two forms this
  // deployment has. Both requests are made before the branch, because the
  // static shim is judged on the two bodies together.
  const got = await request(baseUrl + "/callback?code=abc&state=xyz");
  const openRedirect = await request(baseUrl +
    "/callback?code=abc&state=xyz&redirect_uri=https://evil.example.com/" +
    "&return_to=https://evil.example.com/&url=https://evil.example.com/");
  const kind = await callbackKind(got);
  if (kind === "static") {
    checkStaticCallback(got, openRedirect);
    // AND THE ONE THING A STATIC DEPLOYMENT STRUCTURALLY CANNOT HAVE. The
    // form_post landing below is a POST that answers 303 with the response in
    // a FRAGMENT, and neither S3 nor a CloudFront function in front of it can
    // receive a POST for a path that has no Lambda@Edge behind it. That is not
    // a posture this deployment gets wrong; it is a response mode it does not
    // offer. Said out loud rather than passed over, because the same sentence
    // is what somebody needs when they wonder why response_mode=form_post does
    // nothing on the hosted site — and the mechanism that WOULD fix it already
    // exists here, for the SAML and WS-Federation landings.
    log.warn("SKIPPED — requirement 10.4 (the form_post landing) — a static " +
      "deployment has no POST /callback at all: the three POST landings on " +
      "these sites are Lambda@Edge behaviors (/wsfed, /samlacs, /samlslo) " +
      "and there is none for /callback. response_mode=form_post is " +
      "unavailable here rather than mishandled.");
    log.info("Leaving checkAlwaysOnPosture(). The always-on posture holds " +
      "for a static deployment.");
    log.debug("Leaving checkAlwaysOnPosture(). Static.");
    return "static";
  }
  assert.strictEqual(got.status, 303,
    "Requirement 12.1: GET /callback answered " + got.status + " rather " +
    "than 303.");
  assert.ok(got.headers.location.indexOf("/oauth2_oidc_2.html") !== -1,
    "GET /callback did not forward to the token page: " +
    got.headers.location);

  // 11.1 for real: a request that TRIES to choose the destination, under
  // three of the parameter names that usually work.
  //
  // What is asserted is the ORIGIN AND PATH of the Location, not the absence
  // of the attacker's host from the whole header — because /callback copies
  // the authorization response's parameters through to the page, and an
  // attacker's string sitting in the QUERY of a URL whose destination is this
  // deployment's own page is not a redirect anywhere. Getting that distinction
  // wrong in the assertion is how a test comes to demand a fix that would
  // break every identity provider sending a vendor parameter.
  const landed = new URL(openRedirect.headers.location);
  assert.strictEqual(landed.origin + landed.pathname,
    new URL(baseUrl).origin + "/oauth2_oidc_2.html",
    "Requirement 11.1: /callback forwarded to a destination taken from the " +
    "request — " + openRedirect.headers.location + ". An open redirector on " +
    "a registered redirect_uri is how an authorization code is stolen from a " +
    "client that did everything else right.");

  // 10.4 and 12.1, on the form_post landing.
  const posted = await request(baseUrl + "/callback", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "code=the-code&state=the-state&iss=" +
          encodeURIComponent("https://op.example.com")
  });
  assert.strictEqual(posted.status, 303,
    "Requirement 12.1: POST /callback answered " + posted.status + ". A 307 " +
    "would replay the method and the body — which here IS the authorization " +
    "response — onto the next hop.");
  assert.ok(posted.headers.location.indexOf("#") !== -1,
    "Requirement 10.4: the form_post landing did not put the response in a " +
    "fragment: " + posted.headers.location);
  assert.ok(posted.headers.location.indexOf("?") === -1,
    "Requirement 10.4: the form_post landing put the response in a QUERY " +
    "string, which is the address bar and the history entry this response " +
    "mode exists to keep it out of: " + posted.headers.location);
  assert.ok(posted.headers.location.indexOf("the-code") !== -1,
    "The form_post landing dropped the code: " + posted.headers.location);
  assert.ok(posted.headers.location.indexOf("evil") === -1);

  log.info("Leaving checkAlwaysOnPosture(). The always-on posture holds.");
  log.debug("Leaving checkAlwaysOnPosture().");
  return "express";
}

// The other side of the pairing this file is named for. A run against an STS
// that is NOT in RFC 9700 mode would pass most of these assertions and prove
// nothing, so it is refused by name rather than allowed to look green.
async function requireCompliantSts(stsUrl) {
  log.debug("Entering requireCompliantSts().");
  const report = await request(stsUrl + "/oauth2/rfc9700");
  assert.strictEqual(report.status, 200,
    "The STS at " + stsUrl + " does not publish GET /oauth2/rfc9700, so it " +
    "predates its own RFC 9700 support. This job needs a build that has it.");
  const parsed = JSON.parse(report.body);
  assert.strictEqual(parsed.enabled, true,
    "The STS at " + stsUrl + " is NOT in RFC 9700 mode. That URL should carry " +
    "a trust realm prefix (.../realm/rfc9700) and the realm should have been " +
    "put into the mode by configureStsRfc9700Realm() in common/common.sh — " +
    "check the launcher's output for its WARNING. Running this job against a " +
    "permissive server would exercise the client's checks against a server " +
    "that never disagrees with them, which is the one arrangement that proves " +
    "nothing.");
  log.info("The STS is in RFC 9700 mode.");
  log.debug("Leaving requireCompliantSts().");
  return parsed;
}

// Which redirect URI this run sends, settled once the base URL is known — the
// -u option is parsed after this file's top-level runs, so this cannot be a
// constant. See the note on `redirectUri` above for why it is not always the
// base URL's own /callback.
function resolveRedirectUri() {
  log.debug("Entering resolveRedirectUri().");
  if (!redirectUri) {
    redirectUri = baseUrl + "/callback";
  }
  log.info("redirect_uri for this run: " + redirectUri);
  log.debug("Leaving resolveRedirectUri().");
  return redirectUri;
}

// The Chrome rule that makes a redirect URI on another name reachable, or null
// when there is nothing to map (every host run, and any deployment whose pages
// and callback share an origin).
//
// `MAP <host>:<port> <host>:<port>` is resolution only: the browser still sends
// the loopback ORIGIN it was given, which is what RFC 8252 — and therefore
// requirement 1.3 — is about, and what makes `localhost` a secure context.
function hostResolverRule() {
  log.debug("Entering hostResolverRule().");
  const from = new URL(redirectUri);
  const to = new URL(baseUrl);
  if (from.host === to.host) {
    log.debug("Leaving hostResolverRule(). Same origin, nothing to map.");
    return null;
  }
  const rule = "MAP " + from.host + " " + to.host;
  log.debug("Leaving hostResolverRule(). " + rule);
  return rule;
}

// ---------------------------------------------------------------------------
// THE REGISTRATION, WHICH IS TWO STEPS AND USED TO BE ONE.
//
// An RFC 9700 authorization server compares redirect_uri by exact string match
// against URIs the client was given, so the debugger's callback has to be one
// of them. This is not a workaround for the test: it is the registration step
// the specification requires, and doing it here is what makes the pairing
// honest.
//
// WHAT WAS WRONG WITH DOING ONLY THE SETTING. The mock chooses the list to
// judge against per client (sts/oauth-oidc/oauth2_bcp.js, registeredUrisFor):
// a client with an entry of its own is judged against THAT, and everything else
// falls back to the `oauth2.redirectUris` setting. This job registered nothing
// and therefore took the fallback — so what it demonstrated was a global list
// of URIs that no client in it had registered, which is the one arrangement
// where the check cannot catch a client sending somebody else's callback.
//
// So the application is created first, with this run's redirect URI on it, and
// the setting is written as well. Both, deliberately: the setting is what the
// `refused` job's negatives are judged against when they arrive with no
// client_id at all, and removing it would turn several refusals into refusals
// for a second reason — which passes, and stops testing what it names.
// ---------------------------------------------------------------------------
async function registerApplication(stsUrl) {
  log.debug("Entering registerApplication().");
  await registry.provision(registry.baseOf(stsUrl), {
    identifier: CLIENT_ID,
    name: "RFC 9700 debugger client",
    protocols: ["oauth2", "oidc"],
    fields: {
      oauthClientId: CLIENT_ID,
      // EXACTLY the URI this run will send, resolved by resolveRedirectUri()
      // a few lines before this is called. A registration naming the URI this
      // file would send on somebody else's stack is the failure mode the whole
      // check exists to catch, so it is read from the variable rather than
      // rebuilt from baseUrl.
      oauthRedirectUri: [redirectUri],
      oauthResponseType: Object.keys(FLOWS).map(function (key) {
        return FLOWS[key].responseType;
      }).filter(Boolean),
      // No `implicit` and no `password`: requirement 1.11 and requirement 5.1
      // are what this job exists to see REFUSED, and declaring them would be
      // an entry asserting that this client expects to be allowed them.
      oauthGrantType: ["authorization_code", "refresh_token",
                       "client_credentials"],
      oauthScope: ["openid", "profile", "email", "offline_access"],
      // PKCE with no secret: requirement 2.1.1 makes PKCE a MUST for a public
      // client, and this run has none to send. Saying so on the entry is what
      // lets the server judge it as the public client it is rather than as one
      // whose method was never stated.
      oauthTokenEndpointAuthMethod: "none",
      oauthConfidential: "FALSE"
    },
    why: "the client requirement 13.1 compares every token's sub against"
  });
  log.debug("Leaving registerApplication().");
}

async function registerRedirectUri(stsUrl) {
  log.debug("Entering registerRedirectUri().");
  const body = JSON.stringify({ key: "oauth2.redirectUris",
                                value: redirectUri });
  const res = await request(stsUrl + "/admin-api/config/set", {
    method: "POST",
    headers: { "Content-Type": "application/json",
               "Content-Length": Buffer.byteLength(body) },
    body: body
  });
  assert.strictEqual(res.status, 200,
    "Could not register " + redirectUri + " with the STS: " +
    res.status + " " + res.body.slice(0, 300));
  log.info("Registered " + redirectUri + " with the STS.");
  log.debug("Leaving registerRedirectUri().");
}


// ---------------------------------------------------------------------------
// The browser.
// ---------------------------------------------------------------------------
async function buildDriver() {
  log.debug("Entering buildDriver().");
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  // The mock STS is HTTPS on a certificate it generated at startup, so nothing
  // has an anchor for it — and since 2026-08-25 that is true of the WHOLE
  // suite rather than of this job alone, because the compliant server is a
  // trust realm on the one instance now and a realm cannot bind a scheme of
  // its own. So the certificate is handled where every browser job can reach
  // it: common/common.sh's trustStsCertificate() fetches it and exports an
  // SPKI pin, and this trusts that one key.
  //
  // It replaced --ignore-certificate-errors + setAcceptInsecureCerts(true),
  // which accepted ANY certificate. That was defensible while this was the
  // only job talking to a TLS mock; it is not now, and it never sat well in a
  // file whose subject is a client that refuses what it should refuse.
  browserFlags.addStsTrustFlags(options);
  // Where a loopback redirect URI actually resolves to. Nothing on a host run,
  // where the pages and the callback share an origin already.
  const rule = hostResolverRule();
  if (rule) {
    log.info("Chrome host resolution: " + rule);
    options.addArguments("--host-resolver-rules=" + rule);
  }
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  log.debug("Leaving buildDriver().");
  return await new Builder().forBrowser("chrome").setChromeOptions(options)
      .setLoggingPrefs(prefs).build();
}

// Tick the compliance checkbox, wherever on the workflow we happen to be.
// Returns nothing; the caller asserts what it wanted from it.
async function enableComplianceMode(driver) {
  log.debug("Entering enableComplianceMode().");
  log.info("Entering enableComplianceMode().");
  const box = By.id("rfc9700_mode");
  await driver.wait(until.elementLocated(box), waitTime);
  if (!(await driver.findElement(box).isSelected())) {
    // Clicked through the DOM rather than by Selenium's own click, because the
    // Configuration Parameters pane can be collapsed on any visit after the
    // first (initializeUIPostDebuggerInitialization() collapses it once
    // discovery has run) and an invisible control is "not interactable" — the
    // hazard tests/CLAUDE.md records against the grant selector, which is two
    // rows below this one.
    await driver.executeScript("arguments[0].click();",
                               await driver.findElement(box));
  }
  assert.strictEqual(await driver.executeScript(
    "return window.localStorage.getItem('rfc9700_mode');"), "true",
    "The RFC 9700 checkbox did not record the mode as on.");
  log.info("Leaving enableComplianceMode().");
  log.debug("Leaving enableComplianceMode().");
}

// Which grant options the selector has disabled, as an array of values.
async function disabledGrants(driver) {
  log.debug("Entering disabledGrants().");
  const values = await driver.executeScript(
    "return Array.from(document.querySelectorAll(" +
    "'#authorization_grant_type option')).filter(function (o) {" +
    "return o.disabled; }).map(function (o) { return o.value; });");
  log.debug("Leaving disabledGrants(). n=" + values.length);
  return values;
}

// Fill in the authorization request and return what the page built.
async function prepareRequest(driver, flow) {
  log.debug("Entering prepareRequest(). flow=" + flow.label);
  log.info("Entering prepareRequest(). flow=" + flow.label);
  const selector = By.id("authorization_grant_type");
  await driver.wait(until.elementLocated(selector), waitTime);
  if (!(await driver.findElement(selector).isDisplayed())) {
    await driver.findElement(By.id("config_expand_button")).click();
    await driver.wait(until.elementIsVisible(driver.findElement(selector)),
                      waitTime);
  }
  await new Select(await driver.findElement(selector))
      .selectByVisibleText(flow.label);

  const clientIdField = By.id("client_id");
  await driver.wait(until.elementLocated(clientIdField), waitTime);
  if (!(await driver.findElement(clientIdField).isDisplayed())) {
    await driver.findElement(By.id("authz_expand_button")).click();
  }
  await driver.wait(until.elementIsVisible(
    driver.findElement(clientIdField)), waitTime);

  for (const [id, value] of [["client_id", CLIENT_ID],
                             ["scope", flow.scope],
                             ["redirect_uri", redirectUri]]) {
    await driver.findElement(By.id(id)).clear();
    await driver.findElement(By.id(id)).sendKeys(value);
  }
  // Typing does not always redraw the preview (it is rebuilt on change and
  // keypress handlers that clear() + sendKeys() do not reliably fire), so ask.
  await driver.executeScript(
    "oauth2_oidc_1.recalculateAuthorizationRequestDescription();");
  const preview = await driver.findElement(
    By.id("display_authz_request_form_textarea1")).getAttribute("value");
  log.info("Authorization request preview:\n" + preview);
  log.debug("Leaving prepareRequest().");
  return preview;
}

// The mock's sign-in screen, which reuses Keycloak's field ids.
async function signIn(driver, user) {
  log.debug("Entering signIn().");
  log.info("Entering signIn(). user=" + user);
  const username = By.id("username");
  try {
    await driver.wait(until.elementLocated(username), waitTime * 3);
    await driver.wait(until.elementIsVisible(driver.findElement(username)),
                      waitTime);
  } catch (e) {
    // No sign-in screen means the authorization request was refused. In this
    // job that is the interesting failure, so say where the browser is rather
    // than reporting a timeout on a field.
    throw new Error("The STS did not show its sign-in screen, so it refused " +
      "the authorization request. The browser is at: " +
      (await driver.getCurrentUrl()));
  }
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  const password = await driver.findElements(By.id("password"));
  if (password.length) {
    await password[0].clear();
    await password[0].sendKeys(user);
  }
  await driver.findElement(By.id("kc-login")).click();
  log.info("Leaving signIn().");
  log.debug("Leaving signIn().");
}

// The text of one of the three RFC 9700 report panes.
async function reportText(driver, id) {
  log.debug("Entering reportText(). id=" + id);
  const panes = await driver.findElements(By.id(id));
  if (!panes.length) {
    log.debug("Leaving reportText(). No pane.");
    return "";
  }
  const text = await panes[0].getText();
  log.debug("Leaving reportText(). " + text.length + " characters.");
  return text;
}

// Assert that a report names a requirement, and that the row is not a failing
// one. The id is what is asserted rather than the wording: a report that fires
// under the wrong id sends a reader to the wrong section of the specification,
// and the wording is the part that is allowed to be improved.
function assertReportSays(text, id, what) {
  log.debug("Entering assertReportSays(). id=" + id);
  assert.ok(text.indexOf("(" + id + ")") !== -1,
    what + ": the report does not mention requirement " + id + ". It said:\n" +
    text);
  log.debug("Leaving assertReportSays().");
}

function assertNotRefused(text, what) {
  log.debug("Entering assertNotRefused().");
  assert.ok(text.indexOf("Refused.") === -1,
    what + ": RFC 9700 mode refused this step. The report said:\n" + text);
  log.debug("Leaving assertNotRefused().");
}


// ---------------------------------------------------------------------------
// The jobs.
// ---------------------------------------------------------------------------

// The happy path for one grant, both sides compliant. `landing` is what
// checkAlwaysOnPosture() found in front of /callback — "express" or "static" —
// and it decides one assertion below.
async function runFlow(driver, flowKey, stsUrl, landing) {
  log.debug("Entering runFlow(). flowKey=" + flowKey + " landing=" + landing);
  const flow = FLOWS[flowKey];
  assert.ok(flow, "Unknown RFC9700_FLOW: " + flowKey);

  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await enableComplianceMode(driver);
  await populateMetadata(driver,
                         stsUrl + "/.well-known/openid-configuration");

  // Requirement 8.1: every endpoint the metadata populated must be https. The
  // STS is on the loopback interface here, so this would also pass over plain
  // http — which is why the assertion is on the SCHEME the STS published
  // rather than on the check's verdict.
  const issuer = await driver.findElement(By.id("issuer")).getAttribute(
    "value");
  assert.ok(issuer.indexOf("https://") === 0,
    "Requirement 8.1: the STS in RFC 9700 mode published a plain-http " +
    "issuer (" + issuer + "). A trust realm cannot bind a scheme of its own, " +
    "so this is a property of the PROCESS: the mock has to have been started " +
    "with STS_HTTPS=true (it is set on the `sts` service in local-tests.yml, " +
    "docker-compose-run-tests.yml and keycloak-tests.yml). Without it the " +
    "realm enforces every check and still publishes http, which is a real " +
    "configuration of that service and is not the pairing this job claims.");

  if (!flow.exchangesCode) {
    // The Client Credentials grant never visits the authorization endpoint,
    // so there is no authorization request, no state, no nonce and no code —
    // and, importantly, RFC 9700 mode must not invent findings about their
    // absence. That is the whole of what this branch checks.
    log.info("Client Credentials: no authorization request to make.");
    await driver.get(baseUrl + "/oauth2_oidc_2.html");
    const response = await reportText(driver, "rfc9700_response_report");
    assert.strictEqual(response, "",
      "RFC 9700 mode drew an authorization-response report for a grant that " +
      "makes no authorization request. It said:\n" + response);
    log.debug("Leaving runFlow(). Client Credentials.");
    return;
  }

  const preview = await prepareRequest(driver, flow);

  // What the request must carry, before it is sent. Checked here rather than
  // afterwards because everything downstream still looks plausible when one of
  // these is missing — a server that does not enforce PKCE issues a perfectly
  // good token to a request that carried no challenge.
  assert.ok(/response_type=/.test(preview) &&
            preview.indexOf("response_type=" + flow.responseType) !== -1,
    "The request does not carry response_type=" + flow.responseType + ":\n" +
    preview);
  assert.ok(/code_challenge=\S+/.test(preview),
    "Requirement 1.6: the request carries no code_challenge:\n" + preview);
  assert.ok(/code_challenge_method=S256/.test(preview),
    "Requirement 1.7: the request does not use S256:\n" + preview);
  assert.ok(/state=\S+/.test(preview),
    "Requirement 2.1: the request carries no state:\n" + preview);
  assert.ok(/nonce=\S+/.test(preview),
    "Requirement 3.3: the request carries no nonce:\n" + preview);
  // Requirement 10.4, which is TWO conditions rather than one — and the second
  // is a property of the deployment this job is pointed at, not of the client.
  // The mock STS advertises form_post in RFC 9700 mode, so the first always
  // holds here; the second is whether there is anything to receive the POST.
  // Against a STATIC deployment there is not (no Express, and no Lambda@Edge
  // behavior for /callback — see checkAlwaysOnPosture()), so wantsFormPost()
  // correctly declines to ask for a response mode whose answer would arrive
  // nowhere. That case is asserted rather than skipped: a client that asked
  // for form_post there would send every authorization response into a POST
  // that S3 answers 405 to, and the run would show a page that never loaded
  // instead of the reason it did not.
  if (landing === "static") {
    assert.ok(!/response_mode=form_post/.test(preview),
      "Requirement 10.4: this deployment has no POST /callback, so asking " +
      "for response_mode=form_post would send the authorization response " +
      "somewhere nothing can read it. The request asked anyway:\n" + preview);
    log.info("Requirement 10.4: form_post correctly not requested — this " +
      "deployment has no backend to receive the POST.");
  } else {
    assert.ok(/response_mode=form_post/.test(preview),
      "Requirement 10.4: the STS advertises form_post and this build has a " +
      "/callback to receive it, so the request should have asked for it:\n" +
      preview);
  }

  const sentState = await driver.findElement(By.id("state")).getAttribute(
    "value");
  const sentNonce = await driver.findElement(
    By.id("nonce_field")).getAttribute("value");

  await driver.executeScript("oauth2_oidc_1.triggerAuthZEndpointCall();");
  await signIn(driver, USER);
  await driver.wait(until.urlContains("oauth2_oidc_2.html"), waitTime * 2);
  // The page reads the response and then removes it from the URL, so give the
  // ready() handler its chance before looking.
  await driver.wait(async function () {
    return !!(await reportText(driver, "rfc9700_response_report"));
  }, waitTime * 2, "The RFC 9700 authorization-response report never drew.");

  // Requirement 10.1: the response is out of the address bar. With form_post
  // it was never in a query string at all, and the fragment the landing used
  // to carry it across is gone too.
  const landedAt = await driver.getCurrentUrl();
  log.info("Landed at: " + landedAt);
  assert.ok(landedAt.indexOf("?") === -1 && landedAt.indexOf("#") === -1,
    "Requirement 10.1: the authorization response is still in the address " +
    "bar, and therefore in this history entry: " + landedAt);
  assert.ok(landedAt.indexOf(sentState) === -1);

  const responseReport = await reportText(driver, "rfc9700_response_report");
  log.info("Authorization response report:\n" + responseReport);
  assertNotRefused(responseReport, "the authorization response");
  assertReportSays(responseReport, "2.2", "state");
  assertReportSays(responseReport, "2.5", "the RFC 9207 iss parameter");
  assert.ok(/state matches/i.test(responseReport),
    "Requirement 2.2: the report does not say the state matched:\n" +
    responseReport);
  assert.ok(/iss matches/i.test(responseReport),
    "Requirement 2.5: the STS advertises the iss parameter and the report " +
    "does not say it matched:\n" + responseReport);

  // Requirement 3.1 needs the code, and the URL no longer has it — which is
  // itself the thing 10.1 just asserted. It is read off the field the page
  // filled, which is where the token request will take it from.
  const code = await driver.findElement(By.id("code")).getAttribute("value");
  assert.ok(code && code.length > 4,
    "The Token Request pane opened with no authorization code in it. The " +
    "code arrives in the landing's fragment with response_mode=form_post and " +
    "in its query string without it (" + landing + " landing here), and the " +
    "page reads both — so this is where that goes wrong.");

  // Exchange it.
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
    await driver.findElement(By.className("token_btn")));
  await driver.findElement(By.className("token_btn")).click();
  await driver.wait(async function () {
    return (await reportText(driver, "rfc9700_token_report"))
      .indexOf("Token Response") !== -1;
  }, waitTime * 3, "The RFC 9700 token-response report never drew.");

  const tokenReport = await reportText(driver, "rfc9700_token_report");
  log.info("Token response report:\n" + tokenReport);
  assertNotRefused(tokenReport, "the token response");
  assertReportSays(tokenReport, "3.2", "the ID Token nonce");
  assert.ok(/nonce matches/i.test(tokenReport),
    "Requirement 3.2: the report does not say the ID Token's nonce matched " +
    "the value sent (" + sentNonce + "):\n" + tokenReport);
  assertReportSays(tokenReport, "2.7", "the ID Token issuer");
  assertReportSays(tokenReport, "4.2", "the access token's audience");

  const accessToken = await driver.executeScript(
    "return window.localStorage.getItem('token_access_token');");
  assert.ok(accessToken && accessToken.length > 20,
    "No access token was issued. RFC 9700 mode discards a token set whose " +
    "nonce or issuer does not check out, so this is either that or the " +
    "exchange itself failing.");
  log.info("Access token issued and accepted by every applicable check.");

  // Requirement 3.1, live: the same code, a second time. This is the one that
  // cannot be reached from the happy path and is most of why this job exists —
  // a server that answers a replayed code has a defect, and a client that
  // presents one has already made it unfindable.
  // The pane has to be re-opened first: a successful exchange collapses the
  // Token Request fieldset, so the button is present and invisible and
  // Selenium reports "element not interactable" — which reads as a broken
  // page rather than as a pane that did what it was supposed to. Re-expanding
  // is also what a person would do to press it again.
  await driver.executeScript(
    "document.getElementById('token_fieldset').style.display = 'block';");
  await driver.wait(until.elementIsVisible(
    driver.findElement(By.className("token_btn"))), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
    await driver.findElement(By.className("token_btn")));
  await driver.findElement(By.className("token_btn")).click();
  await driver.wait(async function () {
    return (await reportText(driver, "rfc9700_token_report"))
      .indexOf("Refused.") !== -1;
  }, waitTime * 2,
    "Requirement 3.1: presenting the same authorization code a second time " +
    "was not refused. The report said:\n" +
    (await reportText(driver, "rfc9700_token_report")));
  const replayReport = await reportText(driver, "rfc9700_token_report");
  assertReportSays(replayReport, "3.1", "the replayed code");
  log.info("A replayed authorization code was refused, citing 3.1.");

  log.debug("Leaving runFlow().");
}

// The negatives: what RFC 9700 mode is actually for.
async function runRefusals(driver, stsUrl) {
  log.debug("Entering runRefusals().");
  log.info("Entering runRefusals().");

  await driver.get(baseUrl + "/oauth2_oidc_1.html");

  // Before the mode is on, NOTHING is disabled. This is the mode-off contract
  // seen from the browser, and it is the assertion that would catch the day a
  // check started firing unconditionally — at which point this debugger would
  // refuse to talk to most of the identity providers it exists for.
  await driver.executeScript(
    "window.localStorage.setItem('rfc9700_mode', 'false');");
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  const beforeMode = await disabledGrants(driver);
  assert.deepStrictEqual(beforeMode, [],
    "With the RFC 9700 checkbox CLEAR, the grant selector has options " +
    "disabled: " + beforeMode.join(", ") + ". Nothing in this mode may act " +
    "until it is switched on.");
  const beforeReport = await reportText(driver, "rfc9700_request_report");
  assert.strictEqual(beforeReport, "",
    "With the mode off, an RFC 9700 report was drawn anyway:\n" +
    beforeReport);
  log.info("The mode-off contract holds: nothing disabled, nothing drawn.");

  // Now on.
  await enableComplianceMode(driver);
  const disabled = await disabledGrants(driver);
  Object.keys(REFUSED_GRANTS).forEach(function (grant) {
    assert.ok(disabled.indexOf(grant) !== -1,
      "Requirement " + REFUSED_GRANTS[grant] + ": the grant '" + grant +
      "' is still selectable in RFC 9700 mode. Disabled: " +
      disabled.join(", "));
  });
  // And the ones that survive are still selectable. A mode that disabled
  // everything would satisfy the assertion above and be useless.
  ["authorization_grant", "oidc_authorization_code_flow",
   "oidc_hybrid_code_id_token", "client_credential",
   "device_authorization_grant"].forEach(function (grant) {
    assert.ok(disabled.indexOf(grant) === -1,
      "The grant '" + grant + "' was disabled in RFC 9700 mode. It should " +
      "not be: RFC 9700 refuses response types that return an access token " +
      "from the authorization endpoint, and this returns none.");
  });
  log.info("Six grants refused, five left standing.");

  // Each disabled option carries its own reason. Six controls sharing one
  // generic sentence would tell a reader nothing about which rule they met.
  for (const grant of Object.keys(REFUSED_GRANTS)) {
    const title = await driver.executeScript(
      "var o = document.querySelector('#authorization_grant_type " +
      "option[value=\"" + grant + "\"]'); return o ? o.title : null;");
    assert.ok(title && title.length > 40,
      "The disabled grant '" + grant + "' carries no reason a reader could " +
      "use. Its title is: " + title);
    assert.ok(/RFC 9700/.test(title),
      "The reason on '" + grant + "' does not cite RFC 9700: " + title);
  }
  log.info("Every refused grant states its own reason.");

  // The refusal must also hold at the ACT, not only at the control. A stored
  // configuration or a hand-edited form can reach the request with a grant the
  // selector would not have offered, and the selector is a control while the
  // request is the thing that leaves the browser.
  await populateMetadata(driver, stsUrl + "/.well-known/openid-configuration");
  //
  // The option has to be RE-ENABLED before it can be selected — assigning a
  // disabled option to a select's value leaves the value empty, which is why
  // the first version of this check passed for the wrong reason. Re-enabling
  // it is also the realistic bypass: a browser's developer tools do exactly
  // this, and so does a cached copy of the page from before the mode existed.
  // The point is that the request is refused anyway, because `disabled` is a
  // property of a control and the rule is a property of the request.
  const forced = await driver.executeScript(
    "var sel = document.getElementById('authorization_grant_type');" +
    "sel.querySelector('option[value=\"implicit_grant\"]').disabled = false;" +
    "sel.value = 'implicit_grant';" +
    "document.getElementById('response_type').value = 'token';" +
    "var v = oauth2_oidc_1.rfc9700GateAuthorizationRequest(false);" +
    "return JSON.stringify({ok: v.ok, selected: sel.value," +
    "ids: v.blocked.map(function (f) { return f.id; })});");
  const verdict = JSON.parse(forced);
  assert.strictEqual(verdict.selected, "implicit_grant",
    "The test could not actually select the Implicit Grant, so what follows " +
    "would pass for the wrong reason.");
  assert.strictEqual(verdict.ok, false,
    "Requirement 1.11: an Implicit Grant forced past the selector was not " +
    "refused at the request.");
  assert.ok(verdict.ids.indexOf("1.11") !== -1,
    "The forced Implicit Grant was refused under " + verdict.ids.join(", ") +
    " rather than 1.11.");
  log.info("A grant forced past the selector is still refused at the " +
           "request, citing 1.11.");

  // Requirement 7.1: with the mode on and no metadata retrieved, the request
  // is refused. Endpoints typed by hand are the misconfiguration section 7
  // exists to remove, and they are also how somebody points this at half of
  // one server and half of another.
  const noMetadata = await driver.executeScript(
    "window.localStorage.removeItem('discovery_info');" +
    "document.getElementById('authorization_grant_type').value = " +
    "'oidc_authorization_code_flow';" +
    "document.getElementById('response_type').value = 'code';" +
    "var v = oauth2_oidc_1.rfc9700GateAuthorizationRequest(false);" +
    "return JSON.stringify({ok: v.ok, ids: v.blocked.map(function (f) {" +
    "return f.id; })});");
  const noMetadataVerdict = JSON.parse(noMetadata);
  assert.strictEqual(noMetadataVerdict.ok, false,
    "Requirement 7.1: a request built from hand-typed endpoints was not " +
    "refused.");
  assert.ok(noMetadataVerdict.ids.indexOf("7.1") !== -1,
    "It was refused under " + noMetadataVerdict.ids.join(", ") +
    " rather than 7.1.");
  log.info("A request with no metadata behind it is refused, citing 7.1.");

  // And the whole thing is REVERSIBLE. A control left disabled after the mode
  // is switched off is indistinguishable from a broken page, and it is the
  // failure a test that only ever turns the mode ON can never see.
  await driver.executeScript(
    "document.getElementById('rfc9700_mode').checked = false;" +
    "oauth2_oidc_1.onRfc9700ModeChange();");
  const afterOff = await disabledGrants(driver);
  assert.deepStrictEqual(afterOff, [],
    "Turning RFC 9700 mode off left grants disabled: " + afterOff.join(", ") +
    ". Everything the mode does has to be reversible, or the switch is a " +
    "one-way door with a checkbox on it.");
  const pkceNo = await driver.findElement(By.id("usePKCE-no"));
  assert.strictEqual(await pkceNo.getAttribute("disabled"), null,
    "Turning RFC 9700 mode off left the 'no PKCE' option disabled.");
  log.info("Turning the mode off restored every control it had taken away.");

  log.debug("Leaving runRefusals().");
}


async function test() {
  log.debug("Entering test().");
  const stsUrl = (process.env.WSTRUST_STS_URL || "").replace(/\/$/, "");
  assert.ok(stsUrl,
    "WSTRUST_STS_URL is not set. This job needs the mock STS, started in " +
    "RFC 9700 mode (STS_OAUTH2_RFC9700=true).");
  const flowKey = process.env.RFC9700_FLOW || "oidc_authorization_code_flow";
  resolveRedirectUri();

  // Everything that needs no browser, first: it is cheap, and a failure here
  // explains every browser failure that would have followed it.
  const landing = await checkAlwaysOnPosture();
  await requireCompliantSts(stsUrl);
  await registerApplication(stsUrl);
  await registerRedirectUri(stsUrl);

  const driver = await buildDriver();
  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    if (flowKey === "refused") {
      await runRefusals(driver, stsUrl);
    } else {
      await runFlow(driver, flowKey, stsUrl, landing);
    }
    log.info("Test completed successfully. flow=" + flowKey);
  } catch (error) {
    log.error(error.stack || error.message);
    for (const entry of await driver.manage().logs()
                                   .get(logging.Type.BROWSER)) {
      if (entry.level.name === "SEVERE") {
        log.error("browser: " + entry.message.slice(0, 400));
      }
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
  .name("rfc9700_flows")
  .description("Every surviving grant, with the debugger AND the mock STS " +
               "both in RFC 9700 mode — plus the refusals, which are what " +
               "the mode is for.")
  .addOption(new Option("-u, --url <url>", "Set base URL."))
  .addOption(new Option("-b, --browser",
    "Display browser (only works within device)."))
  .action(function (options) {
    if (options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });
program.parse(process.argv);

test();
