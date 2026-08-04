// File: sts_metadata.js
//
// GET /sts-metadata — the mock STS's own index of what it offers.
//
// The page lists every endpoint the service registers, the HTTP methods each
// accepts, and every specification it implements. That list is read from the
// running Express router rather than from a table kept by hand, and this test is
// what makes that design worth anything: it fails if the descriptions and the
// router have drifted in EITHER direction.
//
// Why both directions matter, and why a weaker test would be worthless here:
//
//   * a route registered and undescribed means the page silently understates what
//     is callable. The page reports it, and this test fails on it. Adding an
//     endpoint to this service therefore costs one entry in sts_metadata.js, which
//     is the point — an index nobody is obliged to update is an index that lies.
//   * a description whose path is NOT registered is the more dangerous half: the
//     page would advertise an endpoint that answers 404. That happens on a rename,
//     which is exactly when nobody thinks to check the index.
//
// It also asserts the things a reader would take on trust: that the methods shown
// are the methods that actually answer (checked by calling them), that every
// endpoint names specifications that exist, and that the endpoints the OTHER
// documents point at are all present here — so the index cannot omit the very
// endpoints the service's own metadata advertises.
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

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");

// Paths that must never be described as spec endpoints, because they are this
// mock's own inventions for the benefit of tests and the debugger's panes. A
// reader who mistook one for a standard endpoint would go looking for it in a
// specification that does not mention it.
const NON_SPEC_PATHS = ["/oid4vci/last_request", "/oid4vci/notification/:id",
                        "/oid4vp/result/:state", "/sts-metadata", "/healthcheck"];

async function theDocumentIsServed() {
  log.debug("Entering theDocumentIsServed().");
  log.info("=== The document, in both forms ===");
  const json = await common.httpJson(issuerBase + "/sts-metadata?format=json");
  assert.ok(json.ok, "GET /sts-metadata?format=json should answer 200; got " + json.status);
  const doc = json.body;
  assert.ok(doc && Array.isArray(doc.endpoints) && doc.endpoints.length > 20,
    "the document should list this service's endpoints; got " +
    (doc && doc.endpoints ? doc.endpoints.length : "none"));
  assert.ok(Array.isArray(doc.specifications) && doc.specifications.length > 10,
    "and the specifications it implements.");
  assert.strictEqual(doc.testDouble, true,
    "it must say it is a test double. A page describing this service as an implementation of " +
    "twenty specifications, without saying it checks no passwords and validates no access tokens, " +
    "would be the most misleading thing in the repository.");

  // Fetched directly rather than through httpJson(), which reports no headers:
  // the content type is the thing being asserted here, since a page served as
  // JSON or text/plain renders as source in a browser.
  const htmlResponse = await fetch(issuerBase + "/sts-metadata");
  assert.ok(htmlResponse.ok, "the HTML form should answer 200; got " + htmlResponse.status);
  const contentType = htmlResponse.headers.get("content-type") || "";
  assert.ok(/text\/html/.test(contentType),
    "and it should be served as HTML, or a browser shows the source; got " + contentType);
  const page = await htmlResponse.text();
  assert.ok(/^<!DOCTYPE html>/.test(page.trim()), "and it should be a whole document.");
  assert.ok(/<table/.test(page) && /Specifications implemented/.test(page),
    "the page should carry the endpoint tables and the specification table.");
  // The service sets script-src 'none', so a page with a script would be broken
  // for every visitor rather than merely inelegant.
  assert.ok(!/<script/i.test(page),
    "the page must carry no <script>: this service's Content-Security-Policy is script-src 'none'.");
  log.info("[document] OK — " + doc.endpoints.length + " endpoints, " +
           doc.specifications.length + " specifications, in HTML and JSON.");
  log.debug("Leaving theDocumentIsServed().");
  return doc;
}

// The heart of it: no drift, in either direction.
function theIndexMatchesTheRouter(doc) {
  log.debug("Entering theIndexMatchesTheRouter().");
  log.info("=== The index against the router ===");
  assert.deepStrictEqual(doc.undocumentedPaths, [],
    "these routes are REGISTERED but described nowhere in sts/sts_metadata.js, so the page " +
    "understates what this service offers. Add an ENDPOINTS entry for each: " +
    JSON.stringify(doc.undocumentedPaths));
  assert.deepStrictEqual(doc.stalePaths, [],
    "these paths are DESCRIBED but not registered, so the page advertises endpoints that answer " +
    "404. Either the route was renamed or the description is stale: " + JSON.stringify(doc.stalePaths));
  assert.deepStrictEqual(doc.unknownSpecIds, [],
    "these endpoints reference specification ids that no entry in SPECS defines, so the page shows " +
    "a broken link where the specification should be: " + JSON.stringify(doc.unknownSpecIds));
  doc.endpoints.forEach(function (e) {
    assert.strictEqual(e.documented, true, e.path + " is listed as undocumented.");
    assert.ok(e.name && e.name !== "(undocumented)", e.path + " should have a name.");
    assert.ok(e.description && e.description.length > 20,
      e.path + " should say what it is, in more than a few words.");
    assert.ok(Array.isArray(e.methods) && e.methods.length,
      e.path + " should name at least one HTTP method.");
  });
  log.info("[drift] OK — every registered route is described and every description is registered.");
  log.debug("Leaving theIndexMatchesTheRouter().");
}

function specificationsAreHonest(doc) {
  log.debug("Entering specificationsAreHonest().");
  log.info("=== The specification list ===");
  const ids = new Set();
  doc.specifications.forEach(function (s) {
    assert.ok(s.id && s.name && s.url && s.coverage,
      "every specification needs an id, a name, a URL and a coverage note: " + JSON.stringify(s));
    assert.ok(/^https:\/\//.test(s.url), s.id + " should link to the specification over https.");
    assert.ok(!ids.has(s.id), "duplicate specification id " + s.id);
    ids.add(s.id);
    // The coverage note is the honest part. "full" is allowed, but a bare word is
    // not: what is missing has to be said, or the list overstates.
    assert.ok(/^(full|partial|mock)\b/.test(s.coverage),
      s.id + ' should say how far it goes, starting "full", "partial" or "mock": "' +
      s.coverage.slice(0, 60) + '"');
    assert.ok(s.coverage.length > 30,
      s.id + "'s coverage note should say what is and is not implemented.");
  });

  // A specification nothing references is either an overstatement or a missing
  // link on an endpoint. Both are worth knowing about.
  const referenced = new Set();
  doc.endpoints.forEach(function (e) { (e.specs || []).forEach(function (id) { referenced.add(id); }); });
  const orphans = Array.from(ids).filter(function (id) { return !referenced.has(id); });
  assert.deepStrictEqual(orphans, [],
    "these specifications are listed but no endpoint claims to implement them, which means either " +
    "the claim is idle or an endpoint is missing its link: " + JSON.stringify(orphans));

  // And the non-spec endpoints must not claim a specification.
  NON_SPEC_PATHS.forEach(function (path) {
    const entry = doc.endpoints.filter(function (e) { return e.path === path; })[0];
    if (!entry) return;
    assert.deepStrictEqual(entry.specs, [],
      path + " is this mock's own invention and must claim no specification, or a reader will go " +
      "looking for it in one.");
  });
  log.info("[specs] OK — " + doc.specifications.length + " specifications, each with a coverage note, " +
           "each referenced by an endpoint.");
  log.debug("Leaving specificationsAreHonest().");
}

// The methods shown are the methods that answer. Asserted by CALLING them, because
// a table of methods read off the router is only as true as the router's own idea
// of what it registered.
async function theMethodsShownActuallyAnswer(doc) {
  log.debug("Entering theMethodsShownActuallyAnswer().");
  log.info("=== The methods, called ===");
  // Paths with a parameter or a wildcard need a value; paths that change state or
  // need a body are checked for "not 404/405" rather than for success.
  const substitutions = { ":client_id": "no-such-client", ":id": "no-such-id", ":state": "no-such-state",
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
      // several of these endpoints answer 404 CORRECTLY for a resource that does
      // not exist (an unknown offer id, an unknown presentation state), which
      // proves the route is registered. Express's own 404 for a path with no route
      // is an HTML page reading "Cannot GET /path" — that one means the index is
      // advertising something that is not there. Treating them alike would either
      // fail on healthy endpoints or pass on missing ones.
      const routeMissing = r.status === 404 &&
        /^Cannot (GET|POST|PUT|DELETE)/.test(String(r.raw || "").replace(/<[^>]*>/g, ""));
      assert.ok(!routeMissing,
        method + " " + path + " is listed on /sts-metadata but no route is registered for it — " +
        "the service answered Express's own 404. The index is advertising something that is not " +
        "there.");
      assert.notStrictEqual(r.status, 405,
        method + " " + path + " is listed but the service refuses that method.");
      checked++;
    }
  }
  log.info("[methods] OK — " + checked + " method/path pairs reached a handler.");
  log.debug("Leaving theMethodsShownActuallyAnswer().");
}

// The index must not omit the endpoints this service's OTHER documents advertise.
// Those are discovered by clients, so an index that missed one would be missing
// exactly the endpoints that matter most.
async function theAdvertisedEndpointsAreAllListed(doc) {
  log.debug("Entering theAdvertisedEndpointsAreAllListed().");
  log.info("=== Against the service's own discovery documents ===");
  const listed = new Set(doc.endpoints.map(function (e) { return e.path; }));
  const as = (await common.httpJson(issuerBase + "/.well-known/oauth-authorization-server")).body || {};
  const vci = (await common.httpJson(issuerBase + "/.well-known/openid-credential-issuer")).body || {};

  const advertised = [as.authorization_endpoint, as.token_endpoint, as.jwks_uri,
                      as.registration_endpoint, as.revocation_endpoint, as.introspection_endpoint,
                      as.service_documentation, as.op_policy_uri, as.op_tos_uri,
                      vci.credential_endpoint, vci.nonce_endpoint, vci.notification_endpoint,
                      vci.deferred_credential_endpoint];
  let checked = 0;
  advertised.filter(Boolean).forEach(function (url) {
    const path = new URL(url).pathname;
    assert.ok(listed.has(path),
      "the service advertises " + url + " in its own metadata, but /sts-metadata does not list " +
      path + ". The index must not omit an endpoint a client will discover.");
    checked++;
  });
  log.info("[discovery] OK — all " + checked + " endpoints named by the RFC 8414 and OID4VCI " +
           "metadata are listed.");
  log.debug("Leaving theAdvertisedEndpointsAreAllListed().");
}

// The path of each endpoint is a LINK to that path, where that is honest. This
// checks both halves of "where that is honest", because either half getting it
// wrong produces a page that lies about what you can click:
//
//   * every link must resolve. A link is a promise, and the specific way to break
//     it here is to link a path the router only answers for POST — the reader lands
//     on Express's "Cannot GET /oauth2/token", which reads as a broken service.
//   * a path that cannot be followed must NOT be linked: no GET, or a route pattern
//     with a :parameter or a * in it, which is not the address of anything.
async function pathsAreFollowableLinks(doc) {
  log.info("=== The path links ===");
  const page = await (await fetch(issuerBase + "/sts-metadata")).text();
  let checkedLinks = 0;
  let checkedPlain = 0;

  for (const e of doc.endpoints) {
    const followable = e.methods.indexOf("GET") !== -1 &&
                       e.path.indexOf(":") === -1 && e.path.indexOf("*") === -1;
    assert.strictEqual(e.linkable, followable,
      e.path + " (" + e.methods.join(",") + ") is reported linkable=" + e.linkable +
      " but a browser " + (followable ? "can" : "cannot") + " follow it.");

    // The page must agree with the document about which paths are links.
    const linked = new RegExp('href="' + e.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
                              '"[^>]*><code>').test(page);
    if (!followable) {
      assert.strictEqual(linked, false,
        e.path + " is rendered as a link but cannot be followed — it would 404 or is a route pattern.");
      assert.ok(e.notLinkableBecause,
        e.path + " should say WHY it is not a link; that reason is the most useful thing on the row.");
      checkedPlain++;
      continue;
    }
    assert.strictEqual(linked, true, e.path + " should be rendered as a link on the page.");
    assert.ok(e.url && e.url.indexOf(e.path) !== -1,
      e.path + " should carry an absolute url in the JSON form; got " + e.url);

    // And it must actually answer. Anything but Express's own "Cannot GET" means a
    // handler was reached — 400 and 401 are fine, they are the endpoint talking.
    const r = await common.httpJson(e.url);
    const expressMiss = r.status === 404 && /^Cannot GET/.test(String(r.raw || ""));
    assert.ok(!expressMiss,
      "the page links " + e.url + " but nothing answers a GET there: " +
      String(r.raw || "").slice(0, 80));
    checkedLinks++;
  }
  assert.ok(checkedLinks > 10, "most of this service should be followable; only " + checkedLinks + " was.");
  assert.ok(checkedPlain > 5,
    "the POST-only and parameterised paths should still be listed, unlinked; only " +
    checkedPlain + " were.");
  log.info("[links] OK — " + checkedLinks + " links all resolve, " + checkedPlain +
           " unfollowable paths listed with a reason and no link.");
}

async function test() {
  log.info("Running the /sts-metadata checks against " + issuerBase);
  const doc = await theDocumentIsServed();
  theIndexMatchesTheRouter(doc);
  specificationsAreHonest(doc);
  await theMethodsShownActuallyAnswer(doc);
  await pathsAreFollowableLinks(doc);
  await theAdvertisedEndpointsAreAllListed(doc);
  log.info("Test completed successfully.");
}

const program = new Command();
program
  .name("sts_metadata")
  .description("Verify GET /sts-metadata lists exactly the endpoints the STS registers, and the specs it implements.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
