// File: admin_api.js
//
// The mock STS's MANAGEMENT API at /admin-api — the /admin console's whole
// surface over JSON — and the OpenAPI document that describes it.
//
// The API is built so that most of it cannot go wrong on its own: every
// operation calls the same function the console's form posts to, and the
// document is generated from the table that registers the routes, so an
// operation cannot be undocumented and a documented one cannot be missing.
// This test exists for the three things that arrangement CANNOT check itself,
// and each of them is a way the API would rot silently:
//
//   * **A control added to the console with no operation here.** That is the
//     failure the whole feature is written against — an API that covers eight
//     of nine controls is worse than one that covers none, because the ninth
//     is discovered by somebody who has already written the code that assumed
//     it. Nothing in the mock can see a form appear on a page, so the parity
//     is asserted from OUTSIDE, and from the service's own answers rather than
//     from a list typed into this file: the console's page list comes back in
//     `pages`, and each action handler, asked to perform an action that does
//     not exist, replies with the names of the ones that do. Add an action to
//     the console's switch and that sentence grows; this test then fails until
//     the API has an operation for it.
//   * **A schema that describes a reply the service does not send.** A wrong
//     property name is invisible to a generator and fatal to whatever it
//     generated, so every documented property is checked against a LIVE reply.
//     It has already caught two: `expiresAt` for what is really `expiresAtMs`,
//     and a group drill-down documented with its members at the top level when
//     they are inside `group`.
//   * **That the revocation reached is the REAL one.** The API's whole claim to
//     usefulness is that it is not a second implementation, and the way to
//     prove it is not to read the code but to revoke a token here and watch
//     RFC 7662 introspection call it inactive.
//
// It also checks the one thing the explorer costs: /admin-api/docs is the only
// page in this service with a script on it, so it is the only one served under
// a relaxed Content-Security-Policy. That relaxation must stay scoped — the
// console next door must still be `script-src 'none'` — and it must stay
// minimal, which means `'self'` and never `'unsafe-inline'`.
//
// **This test restores what it changes.** The mock's admin state survives
// between jobs, so a test that leaves a custom claim behind changes what every
// later job's tokens contain. Everything mutated here is read first and put
// back at the end, including the tokens revoked by the bulk operations — which
// are restored one jti at a time, because `revoke-all` has no opposite.
//
// Needs the STS mock and nothing else — no browser, no Keycloak.
const assert = require("assert");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "admin_api",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
var api = base + "/admin-api";

// The console pages that are not this API's to mirror. /sts-metadata is on the
// console's nav because a reader wants it there; it is the whole service's
// index rather than one of the console's own pages, and it is already asserted
// by tests/sts_metadata.js.
const NOT_MIRRORED = ["/sts-metadata"];

// Properties a schema documents that a healthy reply may legitimately omit,
// each with the reason. Without this list the check below would have to be
// weakened to "no property is misspelt", which is most of its value gone.
const CONDITIONAL = {
  // Present, and false, only in a process with no LDAP directory loaded. A run
  // with one — which is every run of this suite — must not carry it.
  "GroupList.directory": true,
};

async function get(path) {
  log.debug("Entering get(). path=" + path);
  const r = await common.httpJson(api + path);
  assert.ok(r.ok, "GET " + api + path + " should answer 200; got " + r.status +
            " " + String(r.raw).slice(0, 200));
  log.debug("Leaving get().");
  return r.body;
}

async function post(path, body) {
  log.debug("Entering post(). path=" + path);
  const r = await common.httpJson(api + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  log.debug("Leaving post(). status=" + r.status);
  return r;
}

// ---------------------------------------------------------------------------
// The document itself.
// ---------------------------------------------------------------------------
async function theDocumentIsServedAndWellFormed() {
  log.debug("Entering theDocumentIsServedAndWellFormed().");
  log.info("=== The OpenAPI document ===");
  const doc = await get("/openapi.json");
  assert.strictEqual(doc.openapi, "3.1.0",
    "the document should declare OpenAPI 3.1.0. It uses JSON Schema " +
    "`examples` and union types, which 3.0 spells differently or not at all, " +
    "so a document that says 3.0 would fail in a generator's schemas rather " +
    "than at the top of the file; got " + doc.openapi);
  assert.ok(doc.info && doc.info.title && doc.info.version,
    "it should name and version itself.");
  assert.ok(/(nothing here is|not) protected/i.test(doc.info.description),
    "and its description must say the API is unprotected. Every other page " +
    "of this console says so where a reader will see it, and a machine-" +
    "readable document that omitted it would be the one artifact a person " +
    "could act on without being told.");
  assert.ok(Array.isArray(doc.servers) && doc.servers.length === 1 &&
            doc.servers[0].url === base,
    "servers[0].url should be this service as the request reached it (" +
    base + "), so a document fetched through a published port names an " +
    "address the caller can use; got " +
    JSON.stringify(doc.servers));
  assert.ok(Array.isArray(doc.security) && doc.security.length === 0,
    "security should be an EMPTY ARRAY rather than absent: that is how " +
    "OpenAPI states 'this needs no credential', which is true here and worth " +
    "stating rather than leaving to be inferred from a missing member.");
  assert.ok(!doc.components.securitySchemes,
    "and there should be no securityScheme at all, since nothing here " +
    "checks one.");

  const paths = Object.keys(doc.paths);
  assert.ok(paths.length > 25,
    "the console has four action resources and eight pages, so a document " +
    "with fewer than about thirty operations has lost some; got " +
    paths.length);
  paths.forEach(function (path) {
    assert.ok(path.indexOf(":") < 0,
      "a documented path must be a URL a caller can use. Express serves the " +
      "actions from one `:action` pattern each, and the document has to " +
      "list the concrete URLs behind it; " + path + " is a route pattern.");
    Object.keys(doc.paths[path]).forEach(function (method) {
      const operation = doc.paths[path][method];
      assert.ok(operation.operationId,
        method + " " + path + " needs an operationId; a generator names its " +
        "function after it.");
      assert.ok(operation.summary && operation.description,
        method + " " + path + " needs a summary and a description.");
      assert.ok(operation.responses && operation.responses["200"],
        method + " " + path + " should document its 200.");
      if (method === "post") {
        assert.ok(operation.responses["400"],
          "POST " + path + " should document its 400 — a refusal is the " +
          "reply half of these operations that a caller has to handle, and " +
          "it carries `errors` rather than a status alone.");
      }
    });
  });
  const ids = paths.reduce(function (out, path) {
    Object.keys(doc.paths[path]).forEach(function (method) {
      out.push(doc.paths[path][method].operationId);
    });
    return out;
  }, []);
  assert.strictEqual(new Set(ids).size, ids.length,
    "operationIds must be unique, or a generated client has two methods of " +
    "one name.");
  log.info("[document] OK — OpenAPI " + doc.openapi + ", " + paths.length +
           " paths, " + ids.length + " operations, no security scheme.");
  log.debug("Leaving theDocumentIsServedAndWellFormed().");
  return doc;
}

// The index has to agree with the document. It is a second listing of the same
// table, and a second listing is exactly the thing that goes stale.
async function theIndexAgreesWithTheDocument(doc) {
  log.debug("Entering theIndexAgreesWithTheDocument().");
  log.info("=== The index ===");
  const index = await get("");
  assert.strictEqual(index.protected, false,
    "the index must say so in a field as well as in prose.");
  const documented = [];
  Object.keys(doc.paths).forEach(function (path) {
    Object.keys(doc.paths[path]).forEach(function (method) {
      documented.push(method.toUpperCase() + " " + path);
    });
  });
  const listed = index.operations.map(function (o) {
    return o.method + " " + o.path;
  });
  assert.deepStrictEqual(listed.slice().sort(), documented.slice().sort(),
    "the index and the document should list the same operations; the index " +
    "has " + listed.length + " and the document " + documented.length);
  index.operations.forEach(function (operation) {
    assert.ok(operation.mirrors,
      operation.method + " " + operation.path + " should name the console " +
      "control it mirrors. That line is what makes the parity below " +
      "checkable at all.");
  });
  log.info("[index] OK — " + listed.length +
           " operations, each naming what it mirrors.");
  log.debug("Leaving theIndexAgreesWithTheDocument().");
  return index;
}

// ---------------------------------------------------------------------------
// PARITY. The reason this file exists.
// ---------------------------------------------------------------------------
function everyConsolePageIsMirrored(status, index) {
  log.debug("Entering everyConsolePageIsMirrored().");
  log.info("=== Parity: the console's pages ===");
  const mirrored = new Set(index.operations.map(function (o) {
    return o.mirrors.replace(/^(GET|POST)\s+/, "");
  }));
  assert.ok(Array.isArray(status.pages) && status.pages.length > 5,
    "the status reply should carry the console's own page list; got " +
    JSON.stringify(status.pages));
  const missing = status.pages.filter(function (page) {
    return NOT_MIRRORED.indexOf(page) < 0 && !mirrored.has(page);
  });
  assert.deepStrictEqual(missing, [],
    "every page of the /admin console must have an operation on /admin-api " +
    "that mirrors it. These have none: " + missing.join(", ") + ". That is " +
    "the rule this API is written under — a control added to the console " +
    "gets an operation in the same commit — and this is the check that " +
    "notices when it did not.");
  log.info("[parity/pages] OK — all " +
           (status.pages.length - NOT_MIRRORED.length) +
           " console pages are mirrored.");
  log.debug("Leaving everyConsolePageIsMirrored().");
}

// The action names, read off the service rather than written down here. Each
// action handler answers an unknown action with the list of the ones it knows,
// so this is the console's own switch statement, quoted back.
async function everyConsoleActionIsMirrored(index) {
  log.debug("Entering everyConsoleActionIsMirrored().");
  log.info("=== Parity: the console's actions ===");
  // The probe bodies matter. /claims validates its `set` BEFORE it looks at
  // the action, so a probe with an empty body comes back naming the four claim
  // SETS — a sentence of exactly the same shape, which this check would then
  // have read as four actions that do not exist. Each probe therefore carries
  // whatever that resource needs in order to reach its action switch.
  const resources = [
    { path: "/tokens", probe: {} },
    { path: "/claims", probe: { set: "id_token" } },
    { path: "/credential-claims", probe: {} },
    { path: "/verifier-request", probe: {} },
  ];
  const paths = new Set(index.operations.map(function (o) { return o.path; }));
  let checked = 0;
  for (const resource of resources) {
    const refused = await post(resource.path + "/no-such-action-exists",
                               resource.probe);
    assert.strictEqual(refused.status, 400,
      "POST " + resource.path + "/no-such-action-exists should be refused " +
      "with 400, not accepted and not routed away; got " + refused.status);
    const message = (refused.body.errors || []).join(" ");
    assert.ok(/unknown action/i.test(message),
      "and the refusal must be about the ACTION rather than about something " +
      "the probe body was missing — otherwise the list parsed below is a " +
      "list of something else. Got: " + message);
    // The sentence is 'Unknown action "x". The four are: add, remove, clear,
    // replace.' — so the names are what follows the colon. Parsed rather than
    // listed here on purpose; a list here would be a third copy of the same
    // facts and the first one to go stale.
    const tail = message.split(":").pop() || "";
    const actions = tail.replace(/\.$/, "").split(",").map(function (name) {
      return name.trim();
    }).filter(function (name) {
      return /^[a-z][a-z-]*$/.test(name);
    });
    assert.ok(actions.length >= 4,
      "the refusal for " + resource.path + " should name the actions that DO " +
      "exist — that sentence is what this parity check reads. Got: " +
      message);
    actions.forEach(function (action) {
      const wanted = "/admin-api" + resource.path + "/" + action;
      assert.ok(paths.has(wanted),
        "the console accepts the action '" + action + "' on " +
        resource.path + " and the management API has no operation for it. " +
        "Expected " + wanted + " to be one of its documented paths. Adding " +
        "an action to the console's switch means adding a row to " +
        "admin_api.js's table in the same commit.");
      checked += 1;
    });
  }
  log.info("[parity/actions] OK — all " + checked +
           " console actions across " + resources.length +
           " resources have an operation.");
  log.debug("Leaving everyConsoleActionIsMirrored().");
}

// ---------------------------------------------------------------------------
// The schemas describe the replies that are really sent.
// ---------------------------------------------------------------------------
async function theSchemasMatchTheReplies(doc) {
  log.debug("Entering theSchemasMatchTheReplies().");
  log.info("=== The schemas against live replies ===");
  const schemas = doc.components.schemas;
  const groups = await get("/groups");
  assert.ok(groups.groups && groups.groups.length,
    "this check needs the embedded directory, which every run of this suite " +
    "has: the mock seeds two groups at startup. None came back, so the " +
    "group half of these schemas would have been checked against nothing.");
  const dn = encodeURIComponent(groups.groups[0].dn);

  const cases = [
    { name: "ApiIndex", body: await get("") },
    { name: "Status", body: await get("/status") },
    { name: "Metrics", body: await get("/metrics") },
    { name: "UserList", body: await get("/users") },
    { name: "GroupList", body: groups },
    { name: "IssuedList", body: await get("/tokens") },
    { name: "ClaimSets", body: await get("/claims") },
    { name: "CredentialClaims", body: await get("/credential-claims") },
    { name: "VerifierRequest", body: await get("/verifier-request") },
    { name: "GroupDetail", body: await get("/groups?group=" + dn) },
  ];
  const detail = cases[cases.length - 1].body;
  cases.push({ name: "GroupDetail.group",
               schema: schemas.GroupDetail.properties.group,
               body: detail.group });

  // The schemas reached only through an `items`, which is where the two
  // property names this check has already caught both lived. A schema is not
  // checked by checking the list that carries it: IssuedList named `issued`
  // correctly for as long as IssuedRecord called `expiresAtMs` `expiresAt`.
  const issued = cases.filter(function (item) {
    return item.name === "IssuedList";
  })[0].body.issued;
  assert.ok(issued.length,
    "this check needs at least one issued artifact, and the revocation " +
    "check above has just minted three — an empty list here means " +
    "IssuedRecord would be checked against nothing at all, which is this " +
    "suite's classic way of passing while testing nothing.");
  cases.push({ name: "IssuedRecord", schema: schemas.IssuedRecord,
               body: issued[0] });

  const sets = cases.filter(function (item) {
    return item.name === "ClaimSets";
  })[0].body.sets;
  const populated = sets.filter(function (set) { return set.claims.length; });
  if (populated.length) {
    cases.push({ name: "ClaimEntry", schema: schemas.ClaimEntry,
                 body: populated[0].claims[0] });
  } else {
    // Not a skip that hides: the four sets are empty on a fresh service, which
    // is the normal state, and the claim-set check below adds one and reads it
    // back. Said out loud so a reader is not left wondering which schemas were
    // covered.
    log.info("[schemas] no custom claim is configured, so ClaimEntry is " +
             "covered by the claim-set check below rather than here.");
  }

  let checked = 0;
  cases.forEach(function (item) {
    const schema = item.schema || schemas[item.name];
    assert.ok(schema && schema.properties,
      item.name + " should be a documented schema with properties.");
    const absent = Object.keys(schema.properties).filter(function (name) {
      return !CONDITIONAL[item.name + "." + name] &&
             !(name in item.body);
    });
    assert.deepStrictEqual(absent, [],
      "the " + item.name + " schema documents " + absent.join(", ") +
      ", which the live reply does not carry. A property name that is wrong " +
      "is invisible to a reader and fatal to a generated client.");
    checked += Object.keys(schema.properties).length;
  });
  log.info("[schemas] OK — " + checked + " documented properties across " +
           cases.length + " schemas are all present in live replies.");
  log.debug("Leaving theSchemasMatchTheReplies().");
}

// ---------------------------------------------------------------------------
// The reads answer, are paged, and agree with the console.
// ---------------------------------------------------------------------------
async function theReadsAgreeWithTheConsole() {
  log.debug("Entering theReadsAgreeWithTheConsole().");
  log.info("=== The API and the console see one service ===");
  const apiTokens = await get("/tokens?per=5");
  assert.ok(apiTokens.held > 0,
    "the revocation check above has just minted three artifacts, so an " +
    "empty list here means this comparison would be 0 against 0 — which " +
    "passes and proves nothing.");
  const consoleTokens = await common.httpJson(
    base + "/admin/tokens?per=5&format=json");
  assert.ok(consoleTokens.ok, "the console's JSON view should answer 200.");
  assert.strictEqual(apiTokens.held, consoleTokens.body.held,
    "the API and the console must report the same number of held artifacts " +
    "— they are one list read through two doors. API " + apiTokens.held +
    ", console " + consoleTokens.body.held);
  assert.strictEqual(apiTokens.perPage, 5,
    "?per= should be honoured; got " + apiTokens.perPage);
  assert.ok(apiTokens.page >= 1 && apiTokens.pages >= 1,
    "and the reply should say which page of how many it is.");

  const clamped = await get("/tokens?page=99999");
  assert.strictEqual(clamped.page, clamped.pages,
    "a page past the end should be CLAMPED to the last page and say so, " +
    "rather than answering an empty page numbered 99999 — a caller walking " +
    "the list has no other way to know it has finished. Got page " +
    clamped.page + " of " + clamped.pages);

  const contradiction = await get("/tokens?family=kerberos&kind=id_token");
  assert.strictEqual(contradiction.matched, 0,
    "family and kind are ANDed, so a kind from another family should match " +
    "nothing; got " + contradiction.matched);

  const nobody = await get("/users?user=" + encodeURIComponent(
    "nobody-has-ever-signed-in-as-this"));
  assert.strictEqual(nobody.known, false,
    "an identity this service has never seen is an ANSWER and not a 404: " +
    "the call must return 200 with known:false, or a caller goes looking " +
    "for a routing problem.");
  log.info("[reads] OK — paging clamps, filters AND, and the API and the " +
           "console report the same " + apiTokens.held + " artifacts.");
  log.debug("Leaving theReadsAgreeWithTheConsole().");
}

// ---------------------------------------------------------------------------
// The revocation is the real one.
// ---------------------------------------------------------------------------
async function revokingHereReachesIntrospection() {
  log.debug("Entering revokingHereReachesIntrospection().");
  log.info("=== A revocation through the API reaches RFC 7662 ===");
  const minted = await common.httpJson(base + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=password&username=admin-api-test&password=x" +
          "&client_id=admin-api-test&scope=openid",
  });
  assert.ok(minted.ok && minted.body.access_token,
    "the password grant should mint a token to revoke; got " + minted.status);
  const token = minted.body.access_token;

  const before = await common.httpJson(base + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(token),
  });
  assert.strictEqual(before.body.active, true,
    "the freshly minted token must introspect as ACTIVE first, or the " +
    "assertion below would pass against a token that was never valid — " +
    "which is this suite's classic way of testing nothing at all.");

  // The whole token rather than its jti, because that is what somebody holding
  // a token actually has, and because it is the path that reads the jti out of
  // an unverified JWT.
  const revoked = await post("/tokens/revoke", { target: token });
  assert.strictEqual(revoked.status, 200,
    "the revocation should be applied; got " + revoked.status + " " +
    JSON.stringify(revoked.body));
  assert.strictEqual(revoked.body.ok, true, "and report ok.");

  const after = await common.httpJson(base + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(token),
  });
  assert.strictEqual(after.body.active, false,
    "a token revoked through /admin-api/tokens/revoke must introspect as " +
    "INACTIVE. If it does not, the API is writing to a second set of revoked " +
    "jtis — which would look correct from either side and never be seen from " +
    "both.");

  const userinfo = await common.httpJson(base + "/oauth2/userinfo", {
    headers: { Authorization: "Bearer " + token },
  });
  assert.strictEqual(userinfo.status, 401,
    "and UserInfo must refuse it; got " + userinfo.status);
  log.info("[revocation] OK — revoked through the API, dead at " +
           "/oauth2/introspect and /oauth2/userinfo.");
  log.debug("Leaving revokingHereReachesIntrospection().");
  return revoked.body.jti;
}

// ---------------------------------------------------------------------------
// The writes, each restored afterwards.
// ---------------------------------------------------------------------------
async function customClaimsCanBeChangedAndPutBack() {
  log.debug("Entering customClaimsCanBeChangedAndPutBack().");
  log.info("=== Custom claims ===");
  const before = await get("/claims");
  const idTokenSet = before.sets.filter(function (s) {
    return s.id === "id_token";
  })[0];
  assert.ok(idTokenSet, "there should be an id_token claim set.");
  const original = idTokenSet.claims;

  const added = await post("/claims/add", {
    set: "id_token", name: "admin_api_test", value: "${username}",
  });
  assert.strictEqual(added.status, 200,
    "adding a claim should be applied; got " + JSON.stringify(added.body));
  const withIt = await get("/claims");
  const names = withIt.sets.filter(function (s) {
    return s.id === "id_token";
  })[0].claims.map(function (c) { return c.name; });
  assert.ok(names.indexOf("admin_api_test") >= 0,
    "and the claim must actually be in the set afterwards, not merely " +
    "reported as added; the set holds " + names.join(", "));

  const reserved = await post("/claims/add", {
    set: "id_token", name: "exp", value: "9",
  });
  assert.strictEqual(reserved.status, 400,
    "a claim this service sets itself must be REFUSED with 400, not " +
    "accepted and not silently ignored. A settable exp would produce tokens " +
    "that fail to verify with nothing pointing back at the call.");
  assert.ok((reserved.body.errors || []).join(" ").indexOf("exp") >= 0,
    "and the refusal should name it.");

  const unknownSet = await post("/claims/add", {
    set: "not-a-set", name: "x", value: "y",
  });
  assert.strictEqual(unknownSet.status, 400,
    "an unknown claim set should be refused; got " + unknownSet.status);

  // Put it back exactly, through `replace` rather than `remove`, so that a set
  // this test found in an unexpected state is restored to that state.
  const restored = await post("/claims/replace", {
    set: "id_token", claims: original,
  });
  assert.strictEqual(restored.status, 200, "the set should be restorable.");
  const after = await get("/claims");
  assert.deepStrictEqual(
    after.sets.filter(function (s) { return s.id === "id_token"; })[0].claims,
    original,
    "and this test must leave the claim set exactly as it found it. The " +
    "mock's admin state survives between jobs, so a claim left behind here " +
    "changes what every later job's ID Tokens contain.");
  log.info("[claims] OK — added, refused a reserved name, refused an " +
           "unknown set, and restored " + original.length + " claim(s).");
  log.debug("Leaving customClaimsCanBeChangedAndPutBack().");
}

async function credentialClaimsCanBeChangedAndPutBack() {
  log.debug("Entering credentialClaimsCanBeChangedAndPutBack().");
  log.info("=== Credential claims ===");
  const before = await get("/credential-claims");
  const original = before.selected;
  assert.ok(original.length,
    "the issuer should start with a claim set selected; got none, which " +
    "would make the restore below a no-op and this whole check vacuous.");

  const narrowed = await post("/credential-claims/select", {
    attributes: ["givenName", "sn"],
  });
  assert.strictEqual(narrowed.status, 200,
    "narrowing the selection should be applied; got " +
    JSON.stringify(narrowed.body));
  assert.ok(narrowed.body.sweep,
    "and the reply must report what the DIRECTORY SWEEP did. Changing the " +
    "selection writes to the embedded directory, and a reply that did not " +
    "say so would hide the half of this operation that has an effect " +
    "outside the issuer.");
  const now = await get("/credential-claims");
  assert.deepStrictEqual(now.selected, ["givenName", "sn"],
    "the selection must actually have changed; it is " +
    now.selected.join(", "));
  assert.ok(now.preview && now.preview.claims,
    "and the preview should say what a credential would now carry.");

  const bogus = await post("/credential-claims/add", {
    attribute: "givenName",
  });
  assert.strictEqual(bogus.status, 400,
    "adding an attribute already selected should be refused rather than " +
    "treated as done; got " + bogus.status);

  const restored = await post("/credential-claims/select", {
    attributes: original,
  });
  assert.strictEqual(restored.status, 200, "the selection should restore.");
  const after = await get("/credential-claims");
  assert.deepStrictEqual(after.selected, original,
    "and this test must leave the credential claim set as it found it — it " +
    "decides what every later job's credentials carry AND what the issuer " +
    "metadata advertises.");
  log.info("[credential claims] OK — narrowed to 2, swept the directory, " +
           "refused a duplicate, restored " + original.length + ".");
  log.debug("Leaving credentialClaimsCanBeChangedAndPutBack().");
}

async function theVerifierRequestCanBeChangedAndPutBack() {
  log.debug("Entering theVerifierRequestCanBeChangedAndPutBack().");
  log.info("=== The verifier request ===");
  const before = await get("/verifier-request");
  const originalClaims = before.requested;
  const originalFormat = before.format;

  const asked = await post("/verifier-request/add", {
    claim: "no_credential_here_carries_this",
  });
  assert.strictEqual(asked.status, 200,
    "asking for a claim NOT in the catalogue must be ACCEPTED — it is the " +
    "only way to exercise what a wallet does with a request it cannot " +
    "satisfy, and refusing it would remove the negative this setting exists " +
    "for; got " + asked.status);
  const withIt = await get("/verifier-request");
  assert.ok(withIt.requested.indexOf("no_credential_here_carries_this") >= 0,
    "and it should be in the request.");
  assert.ok(JSON.stringify(withIt.dcqlQuery)
            .indexOf("no_credential_here_carries_this") >= 0,
    "and it must reach the dcql_query, which is what the wallet is actually " +
    "sent. A setting that changed a page and not the query would be the " +
    "worst possible outcome here.");

  const noFormat = await post("/verifier-request/format", { format: "nope" });
  assert.strictEqual(noFormat.status, 400,
    "an unknown credential format should be refused; got " + noFormat.status);

  const empty = await post("/verifier-request/select", { claims: [] });
  assert.strictEqual(empty.status, 200,
    "requesting NOTHING is a legitimate setting rather than an empty form: " +
    "DCQL reads an absent claims member as the whole credential.");
  const emptied = await get("/verifier-request");
  assert.strictEqual(emptied.requested.length, 0,
    "and nothing should be requested.");

  const restored = await post("/verifier-request/select",
                              { claims: originalClaims });
  assert.strictEqual(restored.status, 200, "the request should restore.");
  const formatBack = await post("/verifier-request/format",
                                { format: originalFormat });
  assert.strictEqual(formatBack.status, 200, "and so should the format.");
  const after = await get("/verifier-request");
  assert.deepStrictEqual(after.requested, originalClaims,
    "this test must leave the verifier request as it found it — it decides " +
    "what every later OID4VP job is asked for.");
  assert.strictEqual(after.format, originalFormat,
    "and in the format it found.");
  log.info("[verifier request] OK — asked for an unissued claim, refused a " +
           "bad format, emptied and restored " + originalClaims.length +
           " claim(s) in " + originalFormat + ".");
  log.debug("Leaving theVerifierRequestCanBeChangedAndPutBack().");
}

// The bulk revocations, and the restore that undoes them. `revoke-all` has no
// opposite, so what is put back is every jti that was NOT already revoked when
// this started — which is why the set is read first.
async function theBulkRevocationsWorkAndAreUndone() {
  log.debug("Entering theBulkRevocationsWorkAndAreUndone().");
  log.info("=== The bulk revocations ===");
  const before = await get("/tokens?state=revoked&per=300");
  const alreadyRevoked = new Set(before.issued.map(function (r) {
    return r.jti;
  }));
  const held = await get("/tokens?per=300");
  assert.ok(held.held > 0,
    "this check needs something to revoke, and the revocation test above " +
    "has just minted a token — so a run reaching here with an empty list " +
    "would be asserting against nothing.");

  const badKind = await post("/tokens/revoke-kind", { kind: "saml2" });
  assert.strictEqual(badKind.status, 400,
    "a kind that cannot be revoked must be refused rather than silently " +
    "revoking nothing: nothing consults this service about a SAML " +
    "assertion, so a success would be a lie about what happened.");

  const all = await post("/tokens/revoke-all", {});
  assert.strictEqual(all.status, 200, "revoke-all should be applied.");
  assert.ok(typeof all.body.revoked === "number",
    "and report how many it revoked; got " + JSON.stringify(all.body));
  const nowRevoked = await get("/tokens?state=revoked&per=300");
  assert.ok(nowRevoked.matched >= before.matched,
    "and the revoked list should not have shrunk.");

  let restored = 0;
  for (const record of nowRevoked.issued) {
    if (alreadyRevoked.has(record.jti) || !record.revocable) {
      continue;
    }
    const put = await post("/tokens/restore", { jti: record.jti });
    assert.strictEqual(put.status, 200,
      "restoring " + record.jti + " should be applied; got " + put.status);
    restored += 1;
  }
  const after = await get("/tokens?state=revoked&per=300");
  const leftBehind = after.issued.filter(function (record) {
    return !alreadyRevoked.has(record.jti);
  }).map(function (record) { return record.jti; });
  assert.deepStrictEqual(leftBehind, [],
    "this test must leave nothing revoked that it found valid: a later job " +
    "using a token minted before this one ran would fail with " +
    "invalid_grant and nothing to point at. Still revoked: " +
    leftBehind.join(", "));
  log.info("[bulk] OK — refused an unrevocable kind, revoked " +
           all.body.revoked + ", restored " + restored + ".");
  log.debug("Leaving theBulkRevocationsWorkAndAreUndone().");
}

// ---------------------------------------------------------------------------
// The explorer, and the one clause it costs.
// ---------------------------------------------------------------------------
async function theExplorerIsServedUnderAScopedPolicy() {
  log.debug("Entering theExplorerIsServedUnderAScopedPolicy().");
  log.info("=== The explorer and its Content-Security-Policy ===");
  const page = await fetch(api + "/docs");
  assert.ok(page.ok, "GET /admin-api/docs should answer 200; got " +
            page.status);
  assert.ok(/text\/html/.test(page.headers.get("content-type") || ""),
    "and be served as HTML, or a browser shows the source.");
  const policy = page.headers.get("content-security-policy") || "";
  assert.ok(/script-src 'self'/.test(policy),
    "the explorer needs script-src 'self'; its policy is: " + policy);
  assert.ok(!/unsafe-inline/.test(policy.replace(/style-src[^;]*/, "")),
    "and it must NOT relax anything else to 'unsafe-inline'. The script is " +
    "a separate resource precisely so that 'self' suffices — " +
    "'unsafe-inline' is the clause that would make this relaxation matter. " +
    "The policy is: " + policy);
  assert.ok(/connect-src 'self'/.test(policy),
    "and connect-src 'self', which is what lets the page call the API it " +
    "documents and nothing else.");
  assert.ok(/default-src 'none'/.test(policy),
    "everything else stays as the service sets it.");
  const html = await page.text();
  assert.ok(html.indexOf("<script") >= 0 &&
            html.indexOf("/admin-api/docs/explorer.js") >= 0,
    "the page should load its script from its own URL rather than inline.");
  assert.ok(/(nothing here is|not) protected/i.test(html),
    "and say it is unprotected in the HTML itself, so the warning is there " +
    "even when the document it renders cannot be fetched.");

  const script = await fetch(api + "/docs/explorer.js");
  assert.ok(script.ok, "the script should be served; got " + script.status);
  const source = await script.text();
  assert.ok(source.length > 2000,
    "and it should be the whole explorer; got " + source.length + " bytes.");
  // The lesson coverage_beacon.js taught in the client tree, applied here: a
  // file that reaches a browser as raw script has no module system, and a
  // require() at its top level throws before anything on the page runs.
  assert.ok(!/\brequire\s*\(/.test(source),
    "the explorer runs in a browser with no module system, so a require() " +
    "in it would throw at load and the page would never render.");
  assert.ok(!/\bprocess\.\w/.test(source),
    "and there is no `process` there either.");
  assert.ok(!/\.innerHTML\s*=/.test(source),
    "and it must build nodes rather than ASSIGN innerHTML — it renders " +
    "response bodies, which are not always this service's own. (The word " +
    "itself appears in a comment there saying exactly that, which is why " +
    "this looks for the assignment rather than the name.)");

  // The relaxation must be scoped. The console next door is the page that
  // would be most costly to have quietly loosened, since it renders values a
  // caller supplied.
  const consolePage = await fetch(base + "/admin");
  const consolePolicy =
    consolePage.headers.get("content-security-policy") || "";
  assert.ok(/script-src 'none'/.test(consolePolicy),
    "the /admin console must still be script-src 'none'. The explorer's " +
    "relaxation is scoped to its own two routes, and a middleware change " +
    "that widened it would show up here first. The console's policy is: " +
    consolePolicy);
  log.info("[explorer] OK — script-src 'self' on the two docs routes, " +
           "script-src 'none' next door, and no require/process/innerHTML " +
           "in " + source.length + " bytes of browser script.");
  log.debug("Leaving theExplorerIsServedUnderAScopedPolicy().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the management API checks against " + api);
  const doc = await theDocumentIsServedAndWellFormed();
  const index = await theIndexAgreesWithTheDocument(doc);
  const status = await get("/status");
  everyConsolePageIsMirrored(status, index);
  await everyConsoleActionIsMirrored(index);
  // First of the three that need artifacts to exist, because it is the one
  // that mints them: a schema checked against an empty list, and a comparison
  // of 0 against 0, both pass and prove nothing.
  await revokingHereReachesIntrospection();
  await theSchemasMatchTheReplies(doc);
  await theReadsAgreeWithTheConsole();
  await customClaimsCanBeChangedAndPutBack();
  await credentialClaimsCanBeChangedAndPutBack();
  await theVerifierRequestCanBeChangedAndPutBack();
  await theBulkRevocationsWorkAndAreUndone();
  await theExplorerIsServedUnderAScopedPolicy();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("admin_api")
  .description("Verify the mock STS management API at /admin-api: its " +
      "OpenAPI document, its parity with the /admin console, and that its " +
      "revocation is the same one /oauth2/revoke performs.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
