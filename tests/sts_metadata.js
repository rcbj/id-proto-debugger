// File: sts_metadata.js
//
// GET /admin/sts-metadata — the mock STS's own index of what it offers.
//
// IT WAS `GET /sts-metadata` AND IT MOVED INTO THE CONSOLE on 2026-08-24, which
// costs this test two things and is worth knowing before either surprises you:
//
//   * **It is behind the console gate** (`admin.authRequired`, on by default).
//     A browser with no session is redirected to the sign-in screen and a
//     caller asking for `?format=json` is refused `401 login_required` — a
//     redirect to an HTML login screen is not an answer a program can read. So
//     this file signs in the way tests/admin_api.js does, and for the same
//     reason: the point of the checks below is the comparison, so the answer is
//     to walk through the door rather than to stop reading the page.
//   * **The page is drawn by the console's shell**, so the document now carries
//     a sidebar, a breadcrumb and a gate banner around the tables. That is
//     asserted rather than tolerated — theConsoleChromeIsThere() below —
//     because "it renders" and "it renders inside the console" are different
//     claims and only one of them was asked for.
//
// The page lists every endpoint the service registers, the HTTP methods each
// accepts, and every specification it implements. That list is read from the
// running Express router rather than from a table kept by hand, and this test
// is what makes that design worth anything: it fails if the descriptions and
// the router have drifted in EITHER direction.
//
// Why both directions matter, and why a weaker test would be worthless here:
//
//   * a route registered and undescribed means the page silently understates
//     what is callable. The page reports it, and this test fails on it. Adding
//     an endpoint to this service therefore costs one entry in sts_metadata.js,
//     which is the point — an index nobody is obliged to update is an index
//     that lies.
//   * a description whose path is NOT registered is the more dangerous half:
//     the page would advertise an endpoint that answers 404. That happens on a
//     rename, which is exactly when nobody thinks to check the index.
//
// It also asserts the things a reader would take on trust: that the methods
// shown are the methods that actually answer (checked by calling them), that
// every endpoint names specifications that exist, and that the endpoints the
// OTHER documents point at are all present here — so the index cannot omit the
// very endpoints the service's own metadata advertises.
//
// Needs the STS mock and nothing else — no browser.
const assert = require("assert");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_metadata",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/,
    "");

// The name this file signs into the console AS. A name and not a credential:
// this mock checks no password anywhere. It is distinctive so that a row in
// /admin/audit or an entry in the directory says which test made it.
const CONSOLE_USER = "sts-metadata-test";

// ---------------------------------------------------------------------------
// A browser sign-on session for the console, in the three steps a browser
// takes. Lifted from tests/admin_api.js, which needed it first and explains it
// at length; the short version is: ask for a page without ?format=json and
// without following the redirect, POST the `authn` id in that Location to
// /authn/login with any username, and send the cookie it sets.
//
// The role comes from `admin.openWhenEmpty`, on by default: while neither role
// group has a member, whoever signs in holds both. If some earlier job has
// granted a role to somebody else the roster is enforced and this user holds
// nothing — so the caller checks the read it makes rather than assuming, and
// the assertion says which of the two states it met.
//
// A gate that has been turned OFF is a legitimate state (the setting is
// switchable on purpose) and is reported rather than silently treated as a
// pass: no redirect means no session is needed and everything below works as it
// did before the page moved.
// ---------------------------------------------------------------------------
async function signInToTheConsole() {
  log.debug("Entering signInToTheConsole().");
  const gated = await fetch(issuerBase + "/admin/sts-metadata",
                            { redirect: "manual" });
  if (gated.status !== 302) {
    log.info("[console] admin.authRequired is off (GET /admin/sts-metadata " +
             "answered " + gated.status + " with no redirect), so the reads " +
             "below need no session.");
    log.debug("Leaving signInToTheConsole(). The gate is off.");
    return null;
  }
  const where = gated.headers.get("location") || "";
  const authn = (where.match(/[?&]authn=([^&]+)/) || [])[1];
  assert.ok(authn,
    "a console GET with no session should be sent to the sign-in screen " +
    "carrying the id of the request waiting there, and it went to \"" +
    where + "\". Without that id the screen has nothing to sign in FOR and " +
    "refuses the POST.");
  const signedIn = await fetch(issuerBase + "/authn/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "authn_id=" + encodeURIComponent(authn) +
          "&username=" + encodeURIComponent(CONSOLE_USER) +
          "&password=" + encodeURIComponent(CONSOLE_USER),
    redirect: "manual",
  });
  const setCookie = signedIn.headers.get("set-cookie") || "";
  const session = (setCookie.match(/(sts_mock_session=[^;]+)/) || [])[1];
  assert.ok(session,
    "signing in at /authn/login should set the session cookie; the reply was " +
    signedIn.status + " and its Set-Cookie is \"" + setCookie + "\". This " +
    "service checks no password, so a refusal here is about the request " +
    "rather than the credential.");
  log.info("[console] signed in as " + CONSOLE_USER + ". " +
           "admin.authRequired is on.");
  log.debug("Leaving signInToTheConsole(). Holding a session.");
  return session;
}

// One read of the page, carrying the session when there is one.
function withSession(session, options) {
  const opts = Object.assign({}, options || {});
  if (session) {
    opts.headers = Object.assign({}, opts.headers || {},
                                 { Cookie: session });
  }
  return opts;
}

// Paths that must never be described as spec endpoints, because they are this
// mock's own inventions for the benefit of tests and the debugger's panes. A
// reader who mistook one for a standard endpoint would go looking for it in a
// specification that does not mention it.
const NON_SPEC_PATHS = ["/oid4vci/last_request", "/oid4vci/notification/:id",
                        "/oid4vp/result/:state", "/admin/sts-metadata",
                            "/healthcheck"];

async function theDocumentIsServed(session) {
  log.debug("Entering theDocumentIsServed().");
  log.info("=== The document, in both forms ===");
  const json = await common.httpJson(issuerBase +
      "/admin/sts-metadata?format=json", withSession(session));
  assert.ok(json.ok,
            "GET /admin/sts-metadata?format=json should answer 200; got " +
            json.status + ". A 401 or a 403 here is the console's own gate " +
            "(admin.authRequired): the sign-in above got a session but the " +
            "roster is enforced and " + CONSOLE_USER + " holds no console " +
            "role, so grant one or turn the gate off.");
  const doc = json.body;
  assert.ok(doc && Array.isArray(doc.endpoints) && doc.endpoints.length > 20,
    "the document should list this service's endpoints; got " +
    (doc && doc.endpoints ? doc.endpoints.length : "none"));
  assert.ok(Array.isArray(doc.specifications) && doc.specifications.length > 10,
    "and the specifications it implements.");
  assert.strictEqual(doc.testDouble, true,
    "it must say it is a test double. A page describing this service as an " +
        "implementation of " +
    "twenty specifications, without saying it checks no passwords and " +
        "validates no access tokens, " +
    "would be the most misleading thing in the repository.");

  // Fetched directly rather than through httpJson(), which reports no headers:
  // the content type is the thing being asserted here, since a page served as
  // JSON or text/plain renders as source in a browser.
  const htmlResponse = await fetch(issuerBase + "/admin/sts-metadata",
                                   withSession(session));
  assert.ok(htmlResponse.ok, "the HTML form should answer 200; got " +
            htmlResponse.status);
  const contentType = htmlResponse.headers.get("content-type") || "";
  assert.ok(/text\/html/.test(contentType),
    "and it should be served as HTML, or a browser shows the source; got " +
        contentType);
  const page = await htmlResponse.text();
  assert.ok(/^<!DOCTYPE html>/.test(page.trim()),
            "and it should be a whole document.");
  assert.ok(/<table/.test(page) && /Specifications implemented/.test(page),
    "the page should carry the endpoint tables and the specification table.");
  // The service sets script-src 'none', so a page with a script would be broken
  // for every visitor rather than merely inelegant.
  assert.ok(!/<script/i.test(page),
    "the page must carry no <script>: this service's Content-Security-Policy " +
        "is script-src 'none'.");
  log.info("[document] OK — " + doc.endpoints.length + " endpoints, " +
           doc.protocols.length + " protocol families, " +
           doc.specifications.length + " specifications, in HTML and JSON.");
  log.debug("Leaving theDocumentIsServed().");
  return { doc: doc, page: page };
}

// ---------------------------------------------------------------------------
// IT IS A CONSOLE PAGE, WHICH IS A CLAIM ABOUT THE DOCUMENT AND NOT ABOUT THE
// URL IT IS AT.
//
// The page moved into /admin so that it would stop being a cul-de-sac: the
// whole point is the sidebar, which is how a reader gets from here to the rest
// of the console and back. Moving the route alone would satisfy every other
// check in this file and deliver none of that, which is exactly the kind of
// pass this suite is written to refuse — so the shell is asserted piece by
// piece: the console's own <title>, the sidebar with OTHER pages in it, this
// page marked as the one being read, and the breadcrumb.
//
// The download control is asserted here too, because it is the one part of the
// page that a person needs and no other check would notice the loss of: this
// service serves no script anywhere, so it has to be an <a download>, and an
// <a> that lost its `download` attribute renders the JSON in the tab instead —
// which looks like it worked.
// ---------------------------------------------------------------------------
function theConsoleChromeIsThere(page) {
  log.debug("Entering theConsoleChromeIsThere().");
  log.info("=== The console's shell around it ===");
  assert.ok(/<title>Service metadata — mock STS admin<\/title>/.test(page),
    "the page should carry the console's own title, which is what says it is " +
    "drawn by admin.js's page() rather than by a second shell of its own.");
  assert.ok(/<nav aria-label="Admin console sections">/.test(page),
    "and the console's sidebar. Without it this page is what it was before " +
    "the move: a document with no way back to anything.");
  const others = ["/admin/metrics", "/admin/tokens", "/admin/audit",
                  "/admin/config", "/admin/rbac"];
  others.forEach(function (path) {
    assert.ok(page.indexOf('href="' + path + '"') !== -1,
      "the sidebar should link " + path + ", or the navigation this page was " +
      "moved for is not there.");
  });
  assert.ok(/<li><span class="here">Service metadata<\/span><\/li>/.test(page),
    "and it should mark THIS page as the one being read — the sidebar item " +
    "for the active page is drawn as text rather than as a link.");
  assert.ok(/<p class="crumb"><a href="\/admin">Admin console<\/a>/.test(page),
    "the breadcrumb should start at the console, since that is the trail " +
    "every other console page draws.");
  assert.ok(
    /<a class="btn" href="\/admin\/sts-metadata\?format=json"[^>]*download=/
      .test(page),
    "the page should carry a download control for the whole document, and it " +
    "must be an <a download>: the Content-Security-Policy here is " +
    "script-src 'none', so anything that had to run to save the file would " +
    "be a button that does nothing.");
  log.info("[chrome] OK — the console's title, sidebar, active item, " +
           "breadcrumb and the download control.");
  log.debug("Leaving theConsoleChromeIsThere().");
}

// ---------------------------------------------------------------------------
// THE PROTOCOL LIST AT THE TOP, WHICH IS THE ONE PART OF THIS PAGE THAT IS NOT
// DERIVED — AND SO THE ONE PART THAT CAN LIE.
//
// A family reaches the endpoint tables only if it is HTTP, and Kerberos, LDAP,
// PKI and SPIFFE live mostly on raw sockets. So the list is hand-written, and
// the page reports three kinds of drift about it that this checks are empty: a
// card naming an endpoint group with no rows, a card citing a specification
// that does not exist, and — the direction nothing else catches — a group of
// endpoints no card claims, which is what a fifteenth protocol family added
// without a card looks like.
//
// The list itself moves on the MOCK's schedule rather than on this file's, the
// way the sts/ COPY closure in tests/Dockerfile does. **Federation** is the
// fourteenth and arrived with the submodule bump of 2026-08-25: both ends of a
// federation relationship, in five protocols, and it sits SECOND because that
// is where the mock's own PROTOCOLS table puts it. Adding a name here is the
// whole of the fix — the assertion is deepStrictEqual and so covers the order
// too, which is deliberate: the page draws the cards in this order and a list
// that only checked membership would let them be shuffled silently.
// ---------------------------------------------------------------------------
function theProtocolListIsHonest(doc, page) {
  log.debug("Entering theProtocolListIsHonest().");
  log.info("=== The protocol list ===");
  const expected = ["OAuth2 / OIDC", "Federation", "SAML 2.0", "SAML 1.1",
                    "WS-Federation", "WS-Trust", "Kerberos", "SPNEGO", "SPIFFE",
                    "SCIM", "LDAP", "PKI / X.509", "WebAuthn / CTAP",
                    "Verifiable Credentials (OID4VCI / OID4VP)"];
  assert.ok(Array.isArray(doc.protocols),
    "the document should carry the protocol list; it has none.");
  assert.deepStrictEqual(doc.protocols.map(function (p) { return p.name; }),
    expected,
    "the page should name every protocol family this service speaks, in " +
    "order. A family added to the service and not to that list is the drift " +
    "this list exists to make visible.");
  assert.deepStrictEqual(doc.unknownProtocolGroups, [],
    "these protocol cards name endpoint groups that have no rows on the " +
    "page, so the card links to a table that is not there: " +
    JSON.stringify(doc.unknownProtocolGroups));
  assert.deepStrictEqual(doc.unknownProtocolSpecIds, [],
    "these protocol cards cite specification ids that no entry in SPECS " +
    "defines, so the card shows a broken link: " +
    JSON.stringify(doc.unknownProtocolSpecIds));
  assert.deepStrictEqual(doc.unclaimedGroups, [],
    "these endpoint groups are on the page and no protocol card claims " +
    "them, which is what a new protocol family added to this service without " +
    "a card at the top of the page looks like: " +
    JSON.stringify(doc.unclaimedGroups));

  const ids = new Set(doc.specifications.map(function (s) { return s.id; }));
  let withEndpoints = 0;
  doc.protocols.forEach(function (p) {
    assert.ok(p.what && p.what.length > 40, p.name +
      " should say what this service does with it, in more than a phrase.");
    assert.ok(Array.isArray(p.specs) && p.specs.length, p.name +
      " should name the specifications it implements.");
    p.specs.forEach(function (id) {
      assert.ok(ids.has(id), p.name + " cites specification id " + id +
                ", which the page does not define.");
    });
    if (p.endpoints) withEndpoints++;
    // The two families with no route of their own must say where they are
    // instead, or the card reads as "this is not implemented".
    if (!p.groups.length) {
      assert.ok(p.sockets && p.sockets.length > 10, p.name +
        " has no endpoint group, so the card must say where the protocol " +
        "really is. Left blank it reads as a family this service does not " +
        "speak.");
    }
    assert.ok(page.indexOf(">" + p.name + "<") !== -1,
      p.name + " is in the document and not on the page.");
  });
  assert.ok(withEndpoints >= 10,
    "most families should have endpoints on the page; only " + withEndpoints +
    " did, which suggests the groups were renamed rather than that the " +
    "service shrank.");
  log.info("[protocols] OK — " + doc.protocols.length + " families, " +
           withEndpoints + " of them with endpoints here, no drift in " +
           "either direction.");
  log.debug("Leaving theProtocolListIsHonest().");
}

// The heart of it: no drift, in either direction.
function theIndexMatchesTheRouter(doc) {
  log.debug("Entering theIndexMatchesTheRouter().");
  log.info("=== The index against the router ===");
  assert.deepStrictEqual(doc.undocumentedPaths, [],
    "these routes are REGISTERED but described nowhere in " +
        "sts/sts_metadata.js, so the page " +
    "understates what this service offers. Add an ENDPOINTS entry for each: " +
    JSON.stringify(doc.undocumentedPaths));
  assert.deepStrictEqual(doc.stalePaths, [],
    "these paths are DESCRIBED but not registered, so the page advertises " +
        "endpoints that answer " +
    "404. Either the route was renamed or the description is stale: " +
        JSON.stringify(doc.stalePaths));
  assert.deepStrictEqual(doc.unknownSpecIds, [],
    "these endpoints reference specification ids that no entry in SPECS " +
        "defines, so the page shows " +
    "a broken link where the specification should be: " +
        JSON.stringify(doc.unknownSpecIds));
  doc.endpoints.forEach(function (e) {
    assert.strictEqual(e.documented, true, e.path +
                       " is listed as undocumented.");
    assert.ok(e.name && e.name !== "(undocumented)", e.path +
              " should have a name.");
    assert.ok(e.description && e.description.length > 20,
      e.path + " should say what it is, in more than a few words.");
    assert.ok(Array.isArray(e.methods) && e.methods.length,
      e.path + " should name at least one HTTP method.");
  });
  log.info("[drift] OK — every registered route is described and every " +
           "description is registered.");
  log.debug("Leaving theIndexMatchesTheRouter().");
}

function specificationsAreHonest(doc) {
  log.debug("Entering specificationsAreHonest().");
  log.info("=== The specification list ===");
  const ids = new Set();
  doc.specifications.forEach(function (s) {
    assert.ok(s.id && s.name && s.url && s.coverage,
      "every specification needs an id, a name, a URL and a coverage note: " +
          JSON.stringify(s));
    assert.ok(/^https:\/\//.test(s.url), s.id +
              " should link to the specification over https.");
    assert.ok(!ids.has(s.id), "duplicate specification id " + s.id);
    ids.add(s.id);
    // The coverage note is the honest part. "full" is allowed, but a bare word
    // is not: what is missing has to be said, or the list overstates.
    assert.ok(/^(full|partial|mock)\b/.test(s.coverage),
      s.id + ' should say how far it goes, starting "full", "partial" or ' +
          '"mock": "' +
      s.coverage.slice(0, 60) + '"');
    assert.ok(s.coverage.length > 30,
      s.id + "'s coverage note should say what is and is not implemented.");
  });

  // A specification nothing references is either an overstatement or a missing
  // link on an endpoint. Both are worth knowing about.
  const referenced = new Set();
  doc.endpoints.forEach(function (e) { (e.specs ||
                        []).forEach(function (id) { referenced.add(id); }); });
  const orphans =
      Array.from(ids).filter(function (id) { return !referenced.has(id); });
  assert.deepStrictEqual(orphans, [],
    "these specifications are listed but no endpoint claims to implement " +
        "them, which means either " +
    "the claim is idle or an endpoint is missing its link: " +
        JSON.stringify(orphans));

  // And the non-spec endpoints must not claim a specification.
  NON_SPEC_PATHS.forEach(function (path) {
    const entry =
        doc.endpoints.filter(function (e) { return e.path === path; })[0];
    if (!entry) return;
    assert.deepStrictEqual(entry.specs, [],
      path + " is this mock's own invention and must claim no specification, " +
          "or a reader will go " +
      "looking for it in one.");
  });
  log.info("[specs] OK — " + doc.specifications.length +
           " specifications, each with a coverage note, " +
           "each referenced by an endpoint.");
  log.debug("Leaving specificationsAreHonest().");
}

// The methods shown are the methods that answer. Asserted by CALLING them,
// because a table of methods read off the router is only as true as the
// router's own idea of what it registered.
// NO SESSION IS CARRIED HERE, and that is the one deliberate exception to what
// pathsAreFollowableLinks() does. This function calls EVERY method of every
// endpoint, POST included, and about a fifth of them are console forms: with a
// session in hand a bodyless POST /admin/tokens is a real console action
// against the shared mock rather than a probe, which is a test that changes the
// service every other job is reading. Unauthenticated, each is refused 401 —
// which is a handler answering, and a handler answering is the whole of what
// this check is asking.
async function theMethodsShownActuallyAnswer(doc) {
  log.debug("Entering theMethodsShownActuallyAnswer().");
  log.info("=== The methods, called ===");
  // Paths with a parameter or a wildcard need a value; paths that change state
  // or need a body are checked for "not 404/405" rather than for success.
  const substitutions = { ":client_id": "no-such-client", ":id": "no-such-id",
      ":state": "no-such-state",
                          "*": "probe" };
  let checked = 0;
  for (const e of doc.endpoints) {
    let path = e.path;
    if (path === "*") continue;              // the CORS preflight answers every path
    Object.keys(substitutions).forEach(function (token) {
      path = path.replace(token, substitutions[token]);
    });
    for (const method of e.methods) {
      const r = await common.httpJson(issuerBase + path, { method: method });
      // A 404 is ambiguous and the difference is the whole point of this check:
      // several of these endpoints answer 404 CORRECTLY for a resource that
      // does not exist (an unknown offer id, an unknown presentation state),
      // which proves the route is registered. Express's own 404 for a path with
      // no route is an HTML page reading "Cannot GET /path" — that one means
      // the index is advertising something that is not there. Treating them
      // alike would either fail on healthy endpoints or pass on missing ones.
      const routeMissing = r.status === 404 &&
        /^Cannot (GET|POST|PUT|DELETE)/.test(String(r.raw ||
                                             "").replace(/<[^>]*>/g, ""));
      assert.ok(!routeMissing,
        method + " " + path + " is listed on /admin/sts-metadata but no " +
        "route is registered for it — " +
        "the service answered Express's own 404. The index is advertising " +
            "something that is not " +
        "there.");
      assert.notStrictEqual(r.status, 405,
        method + " " + path +
            " is listed but the service refuses that method.");
      checked++;
    }
  }
  log.info("[methods] OK — " + checked +
           " method/path pairs reached a handler.");
  log.debug("Leaving theMethodsShownActuallyAnswer().");
}

// The index must not omit the endpoints this service's OTHER documents
// advertise. Those are discovered by clients, so an index that missed one would
// be missing exactly the endpoints that matter most.
async function theAdvertisedEndpointsAreAllListed(doc) {
  log.debug("Entering theAdvertisedEndpointsAreAllListed().");
  log.info("=== Against the service's own discovery documents ===");
  const listed = new Set(doc.endpoints.map(function (e) { return e.path; }));
  const as = (await common.httpJson(issuerBase +
      "/.well-known/oauth-authorization-server")).body || {};
  const vci = (await common.httpJson(issuerBase +
      "/.well-known/openid-credential-issuer")).body || {};

  const advertised = [as.authorization_endpoint, as.token_endpoint, as.jwks_uri,
                      as.registration_endpoint, as.revocation_endpoint,
                          as.introspection_endpoint,
                      as.service_documentation, as.op_policy_uri, as.op_tos_uri,
                      vci.credential_endpoint, vci.nonce_endpoint,
                          vci.notification_endpoint,
                      vci.deferred_credential_endpoint];
  let checked = 0;
  advertised.filter(Boolean).forEach(function (url) {
    const path = new URL(url).pathname;
    assert.ok(listed.has(path),
      "the service advertises " + url +
          " in its own metadata, but /admin/sts-metadata does not list " +
      path + ". The index must not omit an endpoint a client will discover.");
    checked++;
  });
  log.info("[discovery] OK — all " + checked +
           " endpoints named by the RFC 8414 and OID4VCI " +
           "metadata are listed.");
  log.debug("Leaving theAdvertisedEndpointsAreAllListed().");
}

// The path of each endpoint is a LINK to that path, where that is honest. This
// checks both halves of "where that is honest", because either half getting it
// wrong produces a page that lies about what you can click:
//
//   * every link must resolve. A link is a promise, and the specific way to
//     break it here is to link a path the router only answers for POST — the
//     reader lands on Express's "Cannot GET /oauth2/token", which reads as a
//     broken service.
//   * a path that cannot be followed must NOT be linked: no GET, or a route
//     pattern with a :parameter or a * in it, which is not the address of
//     anything.
async function pathsAreFollowableLinks(doc, page, session) {
  log.debug("Entering pathsAreFollowableLinks().");
  log.info("=== The path links ===");
  let checkedLinks = 0;
  let checkedPlain = 0;

  for (const e of doc.endpoints) {
    const followable = e.methods.indexOf("GET") !== -1 &&
                       e.path.indexOf(":") === -1 && e.path.indexOf("*") === -1;
    assert.strictEqual(e.linkable, followable,
      e.path + " (" + e.methods.join(",") + ") is reported linkable=" +
          e.linkable +
      " but a browser " + (followable ? "can" : "cannot") + " follow it.");

    // The page must agree with the document about which paths are links.
    const linked = new RegExp('href="' + e.path.replace(/[.*+?^${}()|[\]\\]/g,
        "\\$&") +
                              '"[^>]*><code>').test(page);
    if (!followable) {
      assert.strictEqual(linked, false,
        e.path + " is rendered as a link but cannot be followed — it would " +
            "404 or is a route pattern.");
      assert.ok(e.notLinkableBecause,
        e.path + " should say WHY it is not a link; that reason is the most " +
            "useful thing on the row.");
      checkedPlain++;
      continue;
    }
    assert.strictEqual(linked, true, e.path +
                       " should be rendered as a link on the page.");
    assert.ok(e.url && e.url.indexOf(e.path) !== -1,
      e.path + " should carry an absolute url in the JSON form; got " + e.url);

    // And it must actually answer. Anything but Express's own "Cannot GET"
    // means a handler was reached — 400 and 401 are fine, they are the endpoint
    // talking.
    // The session goes on every one of them. Half these links are console
    // pages now — this one included — and without it they answer a 302 to the
    // sign-in screen, which is not Express's "Cannot GET" and so would pass
    // this check while proving nothing about the page behind it.
    const r = await common.httpJson(e.url, withSession(session));
    const expressMiss = r.status === 404 && /^Cannot GET/.test(String(r.raw ||
        ""));
    assert.ok(!expressMiss,
      "the page links " + e.url + " but nothing answers a GET there: " +
      String(r.raw || "").slice(0, 80));
    checkedLinks++;
  }
  assert.ok(checkedLinks > 10,
            "most of this service should be followable; only " + checkedLinks +
            " was.");
  assert.ok(checkedPlain > 5,
    "the POST-only and parameterised paths should still be listed, " +
        "unlinked; only " +
    checkedPlain + " were.");
  log.info("[links] OK — " + checkedLinks + " links all resolve, " +
           checkedPlain +
           " unfollowable paths listed with a reason and no link.");
  log.debug("Leaving pathsAreFollowableLinks().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the /admin/sts-metadata checks against " + issuerBase);
  const session = await signInToTheConsole();
  const served = await theDocumentIsServed(session);
  const doc = served.doc;
  theConsoleChromeIsThere(served.page);
  theProtocolListIsHonest(doc, served.page);
  theIndexMatchesTheRouter(doc);
  specificationsAreHonest(doc);
  await theMethodsShownActuallyAnswer(doc);
  await pathsAreFollowableLinks(doc, served.page, session);
  await theAdvertisedEndpointsAreAllListed(doc);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_metadata")
  .description("Verify GET /admin/sts-metadata lists exactly the endpoints " +
      "the STS registers, and the specs it implements.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
