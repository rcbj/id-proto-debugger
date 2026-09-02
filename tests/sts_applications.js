// File: sts_applications.js
//
// ---------------------------------------------------------------------------
// PUT THE APPLICATION IN THE MOCK STS'S REGISTRY BEFORE THE PROTOCOL STARTS.
//
// One implementation, shared by every job in this suite that presents an
// identifier to the mock STS — a client_id at /oauth2/authorize, an entityID in
// an AuthnRequest, a wtrealm on a wsignin1.0, an AppliesTo in an
// RequestSecurityToken, an SPN at the KDC, a bind DN on 389, a workload id at
// the Workload API.
//
// WHY IT EXISTS
//
// That service accepts an identifier it has never heard of. Every one of these
// jobs was therefore written with no provisioning step at all, and the entry it
// leaves behind is created by the SIGHTING — which means the entry knows the
// identifier and nothing else: no redirect URI, no ACS, no reply URL, no
// declared protocol family, no name. That is the opposite of how a deployment
// works, and it hides the whole class of defect that pre-registration exists to
// catch, because there is nothing on the entry for a check to disagree with.
//
// It also went wrong in exactly the way an absent step does. RFC 9700 mode
// judges an authorization request against the client's OWN registered URIs when
// it has any and against the `oauth2.redirectUris` SETTING when it has none
// (sts/oauth-oidc/oauth2_bcp.js, registeredUrisFor) — so the compliant pass was
// being judged against a global list that no client in it had registered. It
// passed. It would have passed against a client whose registration named
// somebody else's callback too.
//
// So: every job that is about to speak a protocol to this service declares the
// application FIRST, with the configuration it is about to use. Three files had
// already done it by hand — tests/oauth2_delegation_chain.js,
// tests/wstrust_delegation_chain.js and the four federation jobs — and a fourth
// hand-written copy is what this module exists to stop. Where those files
// differed genuinely (a job that asserts on its own counters wants a FRESH
// entry; the rest must tolerate one another's) the difference is an option
// here rather than a fork.
//
// ---------------------------------------------------------------------------
// FIVE DECISIONS, EACH OF WHICH CHANGES WHAT A CALLER GETS.
//
// **CREATE OR RECONCILE, AND NEVER "CREATE AND HOPE".** `create` REFUSES an
// identifier that is already there, which is right — an identifier names one
// application whatever protocol brought it — and this suite meets that state in
// three ordinary ways: a second run against a container that has not restarted,
// a run where some earlier job already presented the identifier (a sighting
// creates the entry too), and two jobs of the SAME run provisioning
// concurrently, since run-report.js runs two to four at a time. A refusal whose
// reason is "it is already here" is therefore reconciled — every value this
// caller needs is ADDED to the entry that is there — and a refusal for any
// other reason fails the job HERE, naming the attribute, rather than three
// screens later as a protocol error that reads like a product bug.
//
// **THE ADD/SET MODE IS READ OFF THE SERVICE, NOT TYPED HERE.** Reconciling
// means writing one attribute at a time, and the management API has two calls
// for that: `add` for the attributes that accumulate and `set` for the ones
// holding a single value. A table of which is which, written here, would be a
// second definition of the mock's own EDITABLE table — and the mock's
// mgmt-api/admin_api.js records what that costs: six names moved from one
// sentence to the other when the per-protocol identifiers became multi-valued
// and neither sentence noticed. `GET /admin-api/applications/new` publishes the
// table as `editable`, each row with its `mode`, so this module asks.
//
// **IT READS THE ENTRY BACK.** The reply to a write is the service's account of
// what it did; the entry is what every protocol endpoint will actually read.
// Everything asserted here is asserted against `GET
// /admin-api/applications?application=…`, whose reply is FLAT — `found`,
// `fields`, `allowedProtocols` at the top level — rather than wrapping the
// entry in an `application` member the way the actions do.
//
// **NO STS MEANS SKIP; AN STS THAT REFUSES MEANS FAIL.** Half of these jobs are
// pushed once per identity provider — the Keycloak half and the mock half of
// the same script — and half again run against walt.id or against a static
// deployment with no mock at all. Called with no base, this returns null and
// the caller carries on: the Keycloak half must not be changed by any of this.
// Called WITH one, a refusal is fatal, because a provisioning step that skips
// itself quietly is a provisioning step that has stopped happening and nothing
// says so.
//
// **`fresh: true` IS OPT-IN AND IS ALMOST NEVER RIGHT.** It forgets the entry
// first, so the counters this run reads start at zero. Only a job that asserts
// on ITS OWN arithmetic wants it — tests/CLAUDE.md's "assert on your own
// litter" — and only for an identifier no other job shares, because forgetting
// one out from under a job running concurrently deletes that job's evidence.
//
// ---------------------------------------------------------------------------
// AND SINCE 2026-09-01, THE SECOND HALF: WHAT ONE APPLICATION MAY REACH ON
// ANOTHER.
//
// Everything above is about ONE entry. `delegate()` — down at the bottom of
// this file, behind a header of its own — is about a PAIR, and it is the step
// this suite was not taking at all: wherever a job asks for an access token
// whose audience is anything other than its own client_id, the target
// application exposes an API (a base URI and, by default, `read` and `write`)
// and the asking application is GRANTED those permissions, before the browser
// starts.
//
// The old spelling still works and is not going anywhere: a scope naming the
// TARGET'S BARE client_id becomes that token's audience, which is what
// `oauth2_delegation_chain.js` sends and what the deployments this suite
// copies actually do. Read it as the DEFAULT permissions — the whole API,
// unnamed. What is new beside it is a permission that has a name, so that
// `https://apigw1.example.com/read` and `https://apigw1.example.com/write` are
// two different asks and a register can tell them apart.
//
// It is pre-registration for a refusal that does not exist yet.
// `oauth2.delegatedPermissionsEnforced` is off in the mock, so today every one
// of these grants changes nothing about what is issued — which is precisely
// why they have to be made now rather than when the flag goes on: a suite that
// only ever ran against the permissive default cannot tell a service that
// consulted the register from one that has no register.
//
// **OAuth 2.0 and OIDC ONLY, deliberately.** Kerberos and WS-Trust delegate
// too — S4U2Proxy off `msDS-AllowedToDelegateTo`, `OnBehalfOf`/`ActAs` off
// nothing at all — and neither is wired to this register. Their turn is a
// later change and the model will not be this one, because a delegated
// permission is an OAuth scope and those two families have no scopes.
// ---------------------------------------------------------------------------

// The log level comes from the same configuration everything else here reads. A
// caller without one still has to be able to load this module, so an
// unresolvable CONFIG_FILE falls back to info rather than throwing — the same
// arrangement tests/wait_for.js has, and for the same reason.
var bunyan = require("bunyan");
var assert = require("assert");
var log = bunyan.createLogger({
  name: "sts_applications",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// LOCATING THE SERVICE.
//
// `WSTRUST_STS_URL` is what the launchers set and it names the WS-Trust
// endpoint (`https://host:8081/sts`), not the service — so the trailing `/sts`
// comes off. That replace is the idiom tests/federation_sso.js established and
// it is here so that eleven callers cannot spell it eleven ways.
//
// A REALM base is a legitimate answer and is left alone: the management API
// answers under a realm prefix exactly as it does at the root
// (`https://host:8081/realm/rfc9700/admin-api/...`), and an application created
// there belongs to that realm's registry and to no other. That is the whole
// reason a caller may pass a base rather than only naming an environment
// variable.
// ---------------------------------------------------------------------------
function baseOf(url) {
  log.debug("Entering baseOf(). url=" + url);
  var base = String(url || "").replace(/\/+$/, "").replace(/\/sts$/, "");
  log.debug("Leaving baseOf(). " + base);
  return base;
}

// The mock STS this process should provision against, from the environment, or
// "" when there is none. The order is the order of specificity: a job driving a
// REALM says so explicitly, and a job that was given only the WS-Trust endpoint
// gets the service that endpoint is on.
//
// STS_TLS_URL is last and is deliberately included: the PKI jobs are given only
// that one, and it is the same service.
function stsBaseFromEnv() {
  log.debug("Entering stsBaseFromEnv().");
  var candidates = [process.env.STS_ADMIN_URL, process.env.WSTRUST_STS_URL,
                    process.env.STS_URL, process.env.STS_TLS_URL];
  for (var i = 0; i < candidates.length; i++) {
    if (candidates[i]) {
      var base = baseOf(candidates[i]);
      log.debug("Leaving stsBaseFromEnv(). " + base);
      return base;
    }
  }
  log.debug("Leaving stsBaseFromEnv(). Nothing set.");
  return "";
}

// ---------------------------------------------------------------------------
// IS THIS URL ON THE MOCK STS, AND WHICH REALM OF IT?
//
// Half the jobs in this suite are pushed ONCE PER IDENTITY PROVIDER — the same
// script against Keycloak and against the mock — and the two halves are told
// apart only by the discovery document, metadata document or issuer they are
// given. So a job cannot provision on the strength of "an STS URL is set in the
// environment": on the containerized stack one always is, and the Keycloak half
// would then create an application in the mock's registry that nothing ever
// presents. That is not harmless — it is a registry full of applications that
// never connected, which is exactly the state the registry is supposed to make
// visible.
//
// The test is therefore about the URL the job is actually going to speak to.
// Same origin as the mock, and — when the mock base names a REALM — under that
// realm's prefix too, because /realm/rfc9700/oauth2/authorize and
// /oauth2/authorize are two authorization servers on one socket and an
// application created in the wrong one is invisible to the flow.
//
// Returns the base to provision against, or "" for "not the mock, do nothing".
// ---------------------------------------------------------------------------
function stsBaseFor(url, base) {
  log.debug("Entering stsBaseFor(). url=" + url);
  var mock = base === undefined ? stsBaseFromEnv() : baseOf(base);
  if (!mock || !url) {
    log.debug("Leaving stsBaseFor(). No mock STS configured, or no URL.");
    return "";
  }
  var target, service;
  try {
    target = new URL(String(url));
    service = new URL(mock);
  } catch (e) {
    // An unparseable URL is not this module's problem to report — the job that
    // is about to fetch it will say so far better than a provisioning helper
    // could. What matters here is that it is not treated as a match.
    log.debug("Leaving stsBaseFor(). Unparseable: " + e.message);
    return "";
  }
  if (target.origin !== service.origin) {
    log.debug("Leaving stsBaseFor(). Different origin (" + target.origin +
              " is not " + service.origin + ").");
    return "";
  }
  var prefix = service.pathname.replace(/\/+$/, "");
  if (prefix && target.pathname.indexOf(prefix + "/") !== 0 &&
      target.pathname !== prefix) {
    log.debug("Leaving stsBaseFor(). Same origin, different realm.");
    return "";
  }
  log.debug("Leaving stsBaseFor(). " + mock);
  return mock;
}

// ---------------------------------------------------------------------------
// The management API, which is deliberately NOT behind the console's gate — see
// the mock's mgmt-api/CLAUDE.md, where that is argued rather than assumed. It
// is what makes these calls work whatever `admin.authRequired` is doing, and it
// is why nothing here carries a credential.
// ---------------------------------------------------------------------------
async function adminGet(base, path) {
  log.debug("Entering adminGet(). " + path);
  var response;
  try {
    response = await fetch(base + "/admin-api" + path,
                           { headers: { Accept: "application/json" } });
  } catch (e) {
    // A refused connection arrives as an undici TypeError reading "fetch
    // failed", whose stack is all internals and which names neither the service
    // nor the URL. The caller needs both.
    log.debug("Leaving adminGet(). Unreachable.");
    throw new Error("could not reach the mock STS's management API at " +
                    base + "/admin-api" + path + ": " +
                    (e.cause ? e.cause.message : e.message) +
                    ". Is the service running, and is its URL right?");
  }
  var text = await response.text();
  var parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    // Not JSON — an HTML error page, or an empty body. The status and the raw
    // text say more than a parse error would.
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
  var response;
  try {
    response = await fetch(base + "/admin-api" + path, {
      method: "POST",
      headers: { "Content-Type": "application/json",
                 Accept: "application/json" },
      body: JSON.stringify(body || {})
    });
  } catch (e) {
    log.debug("Leaving adminPost(). Unreachable.");
    throw new Error("could not reach the mock STS's management API at " +
                    base + "/admin-api" + path + ": " +
                    (e.cause ? e.cause.message : e.message) +
                    ". Is the service running, and is its URL right?");
  }
  var text = await response.text();
  var parsed = null;
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

// ---------------------------------------------------------------------------
// THE EDITABLE TABLE, asked for once per process and remembered.
//
// It is per REALM in principle and identical in practice — the schema is the
// service's, not the realm's — but it is cached per base anyway, because a
// cache keyed on nothing is the kind of thing that is correct until somebody
// adds a realm with a schema of its own and then is silently wrong.
// ---------------------------------------------------------------------------
var editableByBase = {};

async function editableModes(base) {
  log.debug("Entering editableModes(). base=" + base);
  if (editableByBase[base]) {
    log.debug("Leaving editableModes(). Cached.");
    return editableByBase[base];
  }
  var doc = await adminGet(base, "/applications/new");
  var modes = {};
  (doc.editable || []).forEach(function (row) {
    // `multi` means the attribute accumulates and is written with `add`;
    // anything else holds one value and is written with `set`.
    modes[row.name] = row.mode === "multi" ? "add" : "set";
  });
  assert.ok(Object.keys(modes).length,
    "GET " + base + "/admin-api/applications/new published no `editable` " +
    "table, so this suite cannot tell an attribute that accumulates from one " +
    "that holds a single value. That member arrived with the applications " +
    "registry — a mock STS without it predates the registry entirely, and " +
    "the " +
    "fix is to bump the sts/ submodule rather than to guess the modes here.");
  editableByBase[base] = modes;
  log.debug("Leaving editableModes(). " + Object.keys(modes).length +
            " editable attribute(s).");
  return modes;
}

// Whether this service has an applications registry at all. A mock from before
// 2026-08-25 has none, and every call below would fail against it with a 404
// that names a path rather than a submodule.
async function registryAvailable(base) {
  log.debug("Entering registryAvailable(). base=" + base);
  try {
    var doc = await adminGet(base, "/applications/new");
    var yes = !!(doc && Array.isArray(doc.editable));
    log.debug("Leaving registryAvailable(). " + yes);
    return yes;
  } catch (e) {
    log.debug("Leaving registryAvailable(). " + e.message);
    return false;
  }
}

// ---------------------------------------------------------------------------
// ONE APPLICATION'S ENTRY, read through the management API's single-application
// view — the same question the console's own drill-down asks. The reply is FLAT
// and carries `fields`, which is the declared attributes only; `attributes`
// beside it is everything including the derived counters, and is not what a
// caller of this module wants.
// ---------------------------------------------------------------------------
async function entryOf(base, identifier) {
  log.debug("Entering entryOf(). identifier=" + identifier);
  var found = await adminGet(base, "/applications?application=" +
                             encodeURIComponent(identifier));
  log.debug("Leaving entryOf(). found=" + !!(found && found.found));
  return (found && found.found) ? found : null;
}

// Remove an application, if it is there. Only for a job that asserts on its own
// counters — see the note at the top of this file about who may ask for this.
async function forget(base, identifier) {
  log.debug("Entering forget(). identifier=" + identifier);
  var existing = await entryOf(base, identifier);
  if (!existing) {
    log.debug("Leaving forget(). Nothing to forget.");
    return false;
  }
  var result = await adminPost(base, "/applications/forget",
                               { application: identifier });
  assert.ok(result.ok,
    "removing the application \"" + identifier + "\" left behind by an " +
    "earlier run was refused by the mock STS: " +
    JSON.stringify(result.errors || result));
  log.info("[registry] forgot the earlier \"" + identifier + "\", so this " +
           "run's counters start at zero.");
  log.debug("Leaving forget(). Forgotten.");
  return true;
}

// A schema attribute's values as a list, whichever shape the entry hands them
// back in: `fields` holds a list for a multi-valued attribute and a bare string
// for a single-valued one, and a caller reading one of each must not have to
// care which it got.
function valuesOf(value) {
  log.debug("Entering valuesOf().");
  if (value === undefined || value === null || value === "") {
    log.debug("Leaving valuesOf(). Nothing.");
    return [];
  }
  var list = Array.isArray(value) ? value : [value];
  log.debug("Leaving valuesOf(). " + list.length + " value(s).");
  return list.map(String);
}

// ---------------------------------------------------------------------------
// THE CALL EVERY TEST MAKES.
//
//   const registry = require("./sts_applications.js");
//   await registry.provision(stsBase, {
//     identifier: CLIENT_ID,
//     name: "OIDC flows (mock STS)",
//     protocols: ["oauth2", "oidc"],
//     fields: {
//       oauthClientId: CLIENT_ID,
//       oauthRedirectUri: [baseUrl + "/callback"],
//       oauthGrantType: ["authorization_code", "refresh_token"],
//       oauthScope: ["openid", "profile", "email"]
//     },
//     why: "the client this job signs in as"
//   });
//
// `base` may be "" — the Keycloak half of a paired job passes exactly that, and
// gets null back and no side effect at all.
//
// What comes back is the entry as the registry now holds it, so a caller with
// something further to assert has it without a second round trip.
// ---------------------------------------------------------------------------
async function provision(base, spec) {
  log.debug("Entering provision(). identifier=" +
            (spec && spec.identifier));
  if (!base) {
    log.debug("Leaving provision(). No mock STS base; nothing to provision.");
    return null;
  }
  assert.ok(spec && spec.identifier,
    "provision() needs an identifier — the client_id, entityID, wtrealm, " +
    "AppliesTo, SPN, bind DN or workload id this test is about to present.");

  var identifier = String(spec.identifier);
  var protocols = (spec.protocols || []).map(String);
  var fields = spec.fields || {};

  if (!(await registryAvailable(base))) {
    // Loud, and NOT a failure: a suite pointed at a deployed service that
    // predates the registry still has to run. What it must not do is run
    // quietly, because "the provisioning silently stopped happening" is
    // indistinguishable from "the provisioning is working" in a green report.
    log.warn("[registry] the mock STS at " + base + " publishes no " +
             "applications registry, so \"" + identifier + "\" is NOT being " +
             "pre-registered and this job runs the way it did before " +
             "pre-registration existed. Bump the sts/ submodule to close " +
             "this.");
    log.debug("Leaving provision(). No registry.");
    return null;
  }

  if (spec.fresh) {
    await forget(base, identifier);
  }

  var created = await adminPost(base, "/applications/create", {
    identifier: identifier,
    name: spec.name || identifier,
    protocols: protocols,
    fields: fields
  });

  if (created.ok) {
    log.info("[registry] created \"" + identifier + "\" in " + base +
             (spec.why ? " — " + spec.why : "") + ".");
  } else {
    var errors = created.errors || [JSON.stringify(created)];
    var alreadyThere = errors.some(function (one) {
      return /already in this registry/i.test(String(one));
    });
    assert.ok(alreadyThere,
      "POST " + base + "/admin-api/applications/create refused \"" +
      identifier + "\" for a reason that is not \"it is already here\": " +
      JSON.stringify(errors) + ". If it names an attribute, this mock STS " +
      "does not have it and the sts/ submodule needs bumping; if it names a " +
      "protocol family, the vocabulary GET /admin-api/applications/new " +
      "publishes is the list to correct this call against.");
    log.info("[registry] \"" + identifier + "\" is already in " + base +
             ", so this run reconciles it rather than creating it.");
    await reconcile(base, identifier, protocols, fields);
  }

  var entry = await entryOf(base, identifier);
  assert.ok(entry,
    "the mock STS's registry at " + base + " has no application called \"" +
    identifier + "\" after this test created it, so the create answered ok " +
    "for something that did not happen.");
  assertMatches(entry, identifier, protocols, fields);
  log.info("[registry] \"" + identifier + "\": declared for " +
           ((entry.allowedProtocols || []).join(", ") || "(nothing)") +
           ", " + Object.keys(fields).length + " attribute(s) configured.");
  log.debug("Leaving provision().");
  return entry;
}

// Bring an entry that is already there up to what this caller needs, one
// attribute at a time. Every write here reports "nothing changed" for a value
// already present, so it is safe to repeat and safe to race — which is what a
// suite running two to four jobs at once needs it to be.
async function reconcile(base, identifier, protocols, fields) {
  log.debug("Entering reconcile(). identifier=" + identifier);
  var modes = await editableModes(base);

  for (var i = 0; i < protocols.length; i++) {
    var declared = await adminPost(base, "/applications/add", {
      application: identifier, attribute: "appAllowedProtocol",
      value: protocols[i]
    });
    assert.ok(declared.ok,
      "declaring " + protocols[i] + " on the existing \"" + identifier +
      "\" was refused: " + JSON.stringify(declared.errors || declared));
  }

  var names = Object.keys(fields);
  for (var n = 0; n < names.length; n++) {
    var name = names[n];
    var mode = modes[name];
    assert.ok(mode,
      "\"" + name + "\" is not an editable attribute of the mock STS's " +
      "application registry — its `editable` table names " +
      Object.keys(modes).length + " and not this one. A DERIVED attribute (a " +
      "counter, a sighting, appProtocol, appRedirectUriObserved) is refused " +
      "by name rather than written, because an entry created with one would " +
      "be asserting a past it does not have.");
    var values = valuesOf(fields[name]);
    if (mode === "set") {
      assert.strictEqual(values.length, 1,
        "\"" + name + "\" holds a single value and this test gave it " +
        values.length + ". The registry refuses that rather than truncating " +
        "to the first, which is the right answer: quietly keeping one of two " +
        "is exactly wrong for an attribute something compares by exact " +
        "string equality.");
      var wrote = await adminPost(base, "/applications/set", {
        application: identifier, attribute: name, value: values[0]
      });
      assert.ok(wrote.ok,
        "setting " + name + " on the existing \"" + identifier +
        "\" was refused: " + JSON.stringify(wrote.errors || wrote));
      continue;
    }
    for (var v = 0; v < values.length; v++) {
      var added = await adminPost(base, "/applications/add", {
        application: identifier, attribute: name, value: values[v]
      });
      assert.ok(added.ok,
        "adding " + name + "=" + values[v] + " to the existing \"" +
        identifier + "\" was refused: " +
        JSON.stringify(added.errors || added));
    }
  }
  log.debug("Leaving reconcile().");
}

// ---------------------------------------------------------------------------
// WHAT THE ENTRY MUST NOW SAY, asserted against the registry's own answer
// rather than against the write's.
//
// The assertion is CONTAINMENT and not equality, and that is deliberate in both
// directions. An entry reconciled from an earlier run legitimately holds more
// than this run asked for — another job's redirect URI, a family somebody else
// declared, a client_id observed by a sighting — and failing on that would make
// every second run of the suite red. What must be true is that everything this
// job is about to USE is on the entry, because that is the whole claim
// pre-registration makes.
// ---------------------------------------------------------------------------
function assertMatches(entry, identifier, protocols, fields) {
  log.debug("Entering assertMatches(). identifier=" + identifier);
  assert.strictEqual(entry.identifier, identifier,
    "the registry answered for \"" + entry.identifier + "\" when asked about " +
    "\"" + identifier + "\".");

  var declared = entry.allowedProtocols || [];
  protocols.forEach(function (protocol) {
    assert.ok(declared.indexOf(protocol) >= 0,
      "\"" + identifier + "\" should be declared for " + protocol +
      " and its entry declares [" + declared.join(", ") + "]. Declaring a " +
      "family grants nothing in this service — it is a record of INTENT, " +
      "kept " +
      "apart from appProtocol, which is what has actually happened — so it " +
      "is " +
      "asserted here or nowhere.");
  });

  var held = entry.fields || {};
  Object.keys(fields).forEach(function (name) {
    var want = valuesOf(fields[name]);
    var got = valuesOf(held[name]);
    want.forEach(function (one) {
      assert.ok(got.indexOf(one) >= 0,
        "\"" + identifier + "\" should carry " + name + "=" + one +
        " and its entry holds [" + got.join(", ") + "]. This is the " +
        "configuration the job is about to present, so an entry without it " +
        "is an entry describing a different application.");
    });
  });
  log.debug("Leaving assertMatches().");
}

// ---------------------------------------------------------------------------
// DELEGATED PERMISSIONS: WHAT ONE APPLICATION MAY REACH ON ANOTHER, GRANTED
// BEFORE ANYTHING ASKS FOR IT.
//
// Everything above puts ONE application in the registry. This half is about a
// PAIR of them, and it is the second thing a deployment configures and the
// first thing this suite was not configuring at all.
//
// WHAT IT IS, IN THE MOCK'S OWN MODEL (which is Microsoft Entra ID's, by name).
// A RESOURCE application exposes an API: a base URI
// (`oauthPermissionBaseUri`, Entra's Application ID URI) and a list of
// permission names (`oauthPermission`, Entra's `oauth2PermissionScopes`). A
// CLIENT application is granted some of them
// (`oauthDelegatedPermission`, Entra's `requiredResourceAccess`). A permission
// is identified by the two joined — `https://apigw1.example.com/` and `read`
// make `https://apigw1.example.com/read` — and a client asks for it by putting
// that whole string in an ordinary OAuth `scope`. The token that comes back is
// AUDIENCED to the base and carries the bare name on its `scope` claim, which
// is what lets a resource server check `aud` once and then read permission
// names.
//
// ---------------------------------------------------------------------------
// FIVE THINGS TO KNOW BEFORE CALLING ANY OF THIS.
//
// **READ AND WRITE, UNLESS SOMEBODY SAID OTHERWISE.** `DEFAULT_PERMISSIONS` is
// the answer to "which permissions?" everywhere in this suite that does not
// have a reason of its own. Two rather than one, because a single permission
// cannot show the difference between a grant that was CONSULTED and a grant
// that was assumed — a client holding `read` and asking for `write` is the
// case an enforcing service has to get right, and it does not exist on a
// resource that exposes one permission.
//
// **THE ORDERING IS NOT NEGOTIABLE AND IT IS THE SERVICE'S RULE, NOT THIS
// FILE'S.** A permission must be DEFINED on the resource before it can be
// GRANTED to a client: `applications.updateApplication()` refuses an
// `oauthDelegatedPermission` naming a permission no entry defines, and it says
// so by name. `delegate()` therefore does both halves in one call and in that
// order — which is why it exists at all, rather than callers making two.
//
// **DEFINING IS NOT IDEMPOTENT AND GRANTING IS.** Adding a value already on an
// entry answers `ok` with `changed: false` everywhere in this registry — that
// is what makes `provision()` safe to repeat and safe to race. `define-
// permission` is the ONE exception: a second permission of the same NAME is
// REFUSED rather than merged, because a permission has one description and two
// rows under one name would leave the second unreachable. So a re-run, a
// second job, or a stack that has not restarted meets that refusal every time
// and it means "it is already there" — it is reconciled here exactly the way
// `create` refusing a known identifier is, and every OTHER refusal still fails
// the job.
//
// **THE NORMALISED BASE IS REGISTERED AS AN AUDIENCE TOO, and that is the
// non-obvious line in `expose()`.** `oauthPermissionBaseUri` and
// `oauthAudience` are two different attributes read by two different lookups —
// `forPermission()` resolves a scope, `forAudience()` resolves the `aud` of an
// act when the delegation register files it — and the mock matches an audience
// EXACTLY. A permission base is normalised (a trailing separator is added
// where there is none) and an `oauthAudience` is not, so a resource registered
// as `https://apigw1.example.com` and exposing permissions under
// `https://apigw1.example.com/` would have every permission-scoped token filed
// against a URL that no application answers to — a box in the delegation map
// with a URL for a label, next to the box for the application it IS. Adding
// the normalised base to `oauthAudience` closes that, and it is additive: the
// spelling the resource already registered stays exactly where it was.
//
// **THE GRANT REFUSES NOTHING YET, AND PRE-REGISTERING IT IS THE POINT.**
// `oauth2.delegatedPermissionsEnforced` is OFF by default in the mock, so an
// ungranted permission is honoured, recorded as ungranted and drawn as such.
// A suite that only ever ran against the default therefore cannot tell a
// service that consulted the register from one that has no register — which is
// the same argument the header at the top of this file makes about
// registration itself, one attribute further on. The flag is coming; the
// grants are made now so that turning it on is a setting rather than a
// migration.
// ---------------------------------------------------------------------------

// The permissions a delegation gets when the caller names none. See the note
// above about why it is two.
var DEFAULT_PERMISSIONS = ["read", "write"];

// The mock's own normalisation, and it must stay the mock's: a permission
// identifier is a plain concatenation, so `https://example.com` + `read` would
// otherwise read as one word. `/`, `#` and `:` all already separate, which is
// what lets `api://<guid>:` — Entra's spelling — through unchanged.
function permissionBaseOf(value) {
  log.debug("Entering permissionBaseOf(). value=" + value);
  var text = String(value === undefined || value === null ? "" : value).trim();
  if (!text) {
    log.debug("Leaving permissionBaseOf(). Nothing.");
    return "";
  }
  var base = /[/#:]$/.test(text) ? text : text + "/";
  log.debug("Leaving permissionBaseOf(). " + base);
  return base;
}

// The whole identifier a client puts in a `scope`, and the whole identifier a
// grant names. One function, because the two must not be spelled twice.
function permissionIdOf(baseUri, name) {
  log.debug("Entering permissionIdOf(). name=" + name);
  var base = permissionBaseOf(baseUri);
  var leaf = String(name === undefined || name === null ? "" : name).trim();
  var id = (base && leaf) ? base + leaf : "";
  log.debug("Leaving permissionIdOf(). " + id);
  return id;
}

// The configured register, both directions, as the service holds it:
// `resources`, `permissions`, `grants`, `counts` and the graph the console
// draws. There is no per-application query on this endpoint, so it is read
// whole and filtered here.
async function permissionsRegister(base) {
  log.debug("Entering permissionsRegister(). base=" + base);
  var register = await adminGet(base, "/permissions");
  log.debug("Leaving permissionsRegister(). " +
            ((register.grants || []).length) + " grant(s).");
  return register;
}

// One of the five actions, with the sentence a caller needs when it is
// refused. `tolerate` is a regular expression for the ONE refusal that means
// "somebody already did this" — see the note above about `define-permission`
// being the exception to idempotence.
async function permissionsAction(base, action, body, what, tolerate) {
  log.debug("Entering permissionsAction(). action=" + action);
  var result = await adminPost(base, "/permissions/" + action, body);
  if (result.ok) {
    log.debug("Leaving permissionsAction(). ok.");
    return result;
  }
  var errors = result.errors || [JSON.stringify(result)];
  var already = tolerate && errors.some(function (one) {
    return tolerate.test(String(one));
  });
  assert.ok(already,
    "POST " + base + "/admin-api/permissions/" + action + " refused " + what +
    ": " + JSON.stringify(errors) + ". A refusal naming the ACTION rather " +
    "than the application means this mock STS predates delegated permissions " +
    "(added 2026-09-01) and the sts/ submodule needs bumping; a refusal " +
    "naming the ordering means the permission was granted before it was " +
    "defined, which delegate() exists to make impossible.");
  log.debug("Leaving permissionsAction(). Already done.");
  return result;
}

// ---------------------------------------------------------------------------
// THE RESOURCE HALF: this application exposes an API.
//
//   await registry.expose(stsBase, {
//     resource: "apigw1",
//     baseUri: "https://apigw1.example.com",
//     why: "the API the browser application's token is presented to"
//   });
//
// `permissions` defaults to read and write. What comes back is what a client
// will have to ask for — the normalised base and one `{ name, id }` per
// permission — so a caller composing a scope has it without spelling the
// concatenation again.
// ---------------------------------------------------------------------------
async function expose(base, spec) {
  log.debug("Entering expose(). resource=" + (spec && spec.resource));
  if (!base) {
    log.debug("Leaving expose(). No mock STS base; nothing to expose.");
    return null;
  }
  assert.ok(spec && spec.resource,
    "expose() needs a resource — the identifier of the application that " +
    "EXPOSES the API, not the one that will ask for it.");
  var resource = String(spec.resource);
  var baseUri = permissionBaseOf(spec.baseUri);
  assert.ok(baseUri,
    "expose() needs a baseUri for \"" + resource + "\". It becomes the `aud` " +
    "of every access token asking for one of its permissions, so it has to " +
    "be absolute — a relative one is an audience nothing can compare " +
    "against, and the service refuses it by name.");
  var names = (spec.permissions && spec.permissions.length)
      ? spec.permissions.map(String) : DEFAULT_PERMISSIONS.slice(0);
  var describe = spec.descriptions || {};

  if (!(await registryAvailable(base))) {
    log.warn("[permissions] the mock STS at " + base + " publishes no " +
             "applications registry, so \"" + resource + "\" is NOT being " +
             "given permissions and this job runs the way it did before " +
             "delegated permissions existed. Bump the sts/ submodule to " +
             "close this.");
    log.debug("Leaving expose(). No registry.");
    return null;
  }

  await permissionsAction(base, "set-permission-base",
    { resource: resource, baseUri: baseUri },
    "the base URI " + baseUri + " on \"" + resource + "\"", null);

  var exposed = [];
  for (var i = 0; i < names.length; i++) {
    await permissionsAction(base, "define-permission",
      { resource: resource, name: names[i],
        description: describe[names[i]] || defaultDescription(names[i],
                                                              resource) },
      "the permission \"" + names[i] + "\" on \"" + resource + "\"",
      /already defines a permission called/i);
    exposed.push({ name: names[i], id: permissionIdOf(baseUri, names[i]) });
  }

  // THE AUDIENCE, so that a token addressed to this API resolves back to this
  // APPLICATION rather than to a URL. See the fourth note in the header above
  // — this is the line that is not obvious, and it is additive.
  var registered = await adminPost(base, "/applications/add", {
    application: resource, attribute: "oauthAudience", value: baseUri
  });
  assert.ok(registered.ok,
    "registering the audience " + baseUri + " on \"" + resource + "\" was " +
    "refused: " + JSON.stringify(registered.errors || registered) + ". " +
    "Without it a token audienced to this API is filed in the delegation " +
    "register against the URI instead of against the application, and the " +
    "map draws a box for a URL beside the box for the application it is.");

  log.info("[permissions] \"" + resource + "\" exposes " +
           exposed.map(function (one) { return one.id; }).join(", ") +
           (spec.why ? " — " + spec.why : "") + ".");
  log.debug("Leaving expose(). " + exposed.length + " permission(s).");
  return { resource: resource, baseUri: baseUri, permissions: exposed };
}

// The prose a permission carries when the caller wrote none. It is read by a
// person looking at /admin/delegation, so it says which application and which
// verb rather than repeating the identifier that is already in the column
// beside it.
function defaultDescription(name, resource) {
  log.debug("Entering defaultDescription(). name=" + name);
  var what = name === "read" ? "Read" : (name === "write" ? "Change" : name);
  var description = what + " what \"" + resource + "\" holds, on behalf of " +
      "the signed-in user";
  log.debug("Leaving defaultDescription().");
  return description;
}

// ---------------------------------------------------------------------------
// THE CLIENT HALF: this application holds those permissions.
//
// It lands on the CLIENT's entry, because the client is the party that will
// name the permission in a `scope` — so the entry that answers "may this
// request be honoured" is the entry the request identifies.
// ---------------------------------------------------------------------------
async function grantPermissions(base, spec) {
  log.debug("Entering grantPermissions(). client=" + (spec && spec.client));
  if (!base) {
    log.debug("Leaving grantPermissions(). No mock STS base.");
    return null;
  }
  assert.ok(spec && spec.client,
    "grantPermissions() needs a client — the application whose client_id " +
    "will be on the token request, not the one exposing the API.");
  var client = String(spec.client);
  var ids = (spec.permissionIds || []).map(String);
  if (!ids.length) {
    var baseUri = permissionBaseOf(spec.baseUri);
    var names = (spec.permissions && spec.permissions.length)
        ? spec.permissions.map(String) : DEFAULT_PERMISSIONS.slice(0);
    ids = names.map(function (one) {
      return permissionIdOf(baseUri, one);
    });
  }
  assert.ok(ids.length && ids.every(Boolean),
    "grantPermissions() was given nothing to grant \"" + client + "\". Pass " +
    "permissionIds, or a baseUri the names hang off.");

  for (var i = 0; i < ids.length; i++) {
    await permissionsAction(base, "grant-permission",
      { client: client, permission: ids[i] },
      "the grant of \"" + ids[i] + "\" to \"" + client + "\"", null);
  }
  log.info("[permissions] \"" + client + "\" is granted " + ids.join(", ") +
           ".");
  log.debug("Leaving grantPermissions(). " + ids.length + " grant(s).");
  return ids;
}

// ---------------------------------------------------------------------------
// BOTH HALVES, IN THE ONE ORDER THAT WORKS, AND READ BACK.
//
//   await registry.delegate(stsBase, {
//     client: "webapp1",
//     resource: "apigw1",
//     baseUri: "https://apigw1.example.com",
//     why: "the browser application presents its token to the gateway"
//   });
//
// `baseUri` may be omitted, and then it is READ OFF THE RESOURCE'S OWN ENTRY —
// the first `oauthAudience` it registered, which is what a token aimed at it
// is already addressed to. A resource that has registered none is a failure
// with the sentence that says so, rather than a base invented from its name:
// an invented one would produce permissions nothing in the run ever asks for
// and a register that looks configured.
// ---------------------------------------------------------------------------
async function delegate(base, spec) {
  log.debug("Entering delegate(). client=" + (spec && spec.client) +
            ", resource=" + (spec && spec.resource));
  if (!base) {
    log.debug("Leaving delegate(). No mock STS base; nothing to delegate.");
    return null;
  }
  assert.ok(spec && spec.client && spec.resource,
    "delegate() needs a client and a resource — who is asking, and whose API " +
    "they are asking for. They are deliberately two names rather than one " +
    "pair, because a body naming the wrong one still succeeds and writes the " +
    "grant onto the API instead of onto its caller.");
  var client = String(spec.client);
  var resource = String(spec.resource);
  assert.notStrictEqual(client, resource,
    "\"" + client + "\" cannot be granted its own permission: the token " +
    "would be addressed to itself, which is what an ID Token already is. The " +
    "service refuses it, and a suite that asked for it is describing a " +
    "delegation that has no second party.");

  var baseUri = permissionBaseOf(spec.baseUri || await audienceOf(base,
                                                                  resource));
  assert.ok(baseUri,
    "delegate() has no base URI for \"" + resource + "\" and its entry " +
    "registers no `oauthAudience` to take one from. Pass `baseUri` — it " +
    "becomes the `aud` of every token asking for one of its permissions, so " +
    "it is the deployment's own statement about where that API answers and " +
    "not something this module may invent from an identifier.");
  var names = (spec.permissions && spec.permissions.length)
      ? spec.permissions.map(String) : DEFAULT_PERMISSIONS.slice(0);

  var exposed = await expose(base, {
    resource: resource, baseUri: baseUri, permissions: names,
    descriptions: spec.descriptions, why: spec.why
  });
  if (!exposed) {
    log.debug("Leaving delegate(). Nothing exposed, so nothing granted.");
    return null;
  }
  var ids = await grantPermissions(base, {
    client: client, permissionIds: exposed.permissions.map(function (one) {
      return one.id;
    })
  });

  await assertDelegated(base, client, resource, ids);
  log.info("[permissions] \"" + client + "\" may reach \"" + resource +
           "\" as " + ids.join(", ") +
           (spec.why ? " — " + spec.why : "") + ".");
  log.debug("Leaving delegate().");
  return { client: client, resource: resource, baseUri: exposed.baseUri,
           permissionIds: ids };
}

// The first audience a resource has registered, for a caller that named none.
// Read off the entry rather than off the permission register, because a
// resource that exposes nothing yet is not in that register at all — which is
// exactly the state the first call to delegate() meets.
async function audienceOf(base, resource) {
  log.debug("Entering audienceOf(). resource=" + resource);
  var entry = await entryOf(base, resource);
  var registered = valuesOf(entry && entry.fields &&
                            entry.fields.oauthAudience);
  log.debug("Leaving audienceOf(). " + registered.length + " audience(s).");
  return registered.length ? registered[0] : "";
}

// ---------------------------------------------------------------------------
// WHAT THE REGISTER MUST NOW SAY, asserted against the service's own answer
// rather than against the writes'.
//
// CONTAINMENT again, and for the reason the header at the top of this file
// gives: a resource reconciled from an earlier run legitimately exposes more
// than this job asked for, and another client legitimately holds the same
// permissions. What must be true is that every permission this job is about to
// rely on is DEFINED by the resource it named and HELD by the client that will
// ask — and that no grant of it is `dangling`, which is the state a grant
// reaches when its permission was removed from under it and the one state that
// looks configured on the client's own entry and resolves to nothing.
// ---------------------------------------------------------------------------
async function assertDelegated(base, client, resource, ids) {
  log.debug("Entering assertDelegated(). client=" + client);
  var register = await permissionsRegister(base);
  var defined = (register.permissions || []).filter(function (one) {
    return one.resource === resource;
  });
  var held = (register.grants || []).filter(function (one) {
    return one.client === client;
  });
  ids.forEach(function (id) {
    assert.ok(defined.some(function (one) { return one.id === id; }),
      "\"" + resource + "\" should expose the permission " + id + " and the " +
      "register says it exposes [" +
      defined.map(function (one) { return one.id || "(no identifier)"; })
        .join(", ") + "]. A permission with no identifier is one whose base " +
      "URI was removed from under it, and no client can ask for it.");
    var grant = held.filter(function (one) {
      return one.permissionId === id;
    })[0];
    assert.ok(grant,
      "\"" + client + "\" should hold " + id + " and the register says it " +
      "holds [" + held.map(function (one) { return one.permissionId; })
        .join(", ") + "]. This is the grant the run is about to rely on, so " +
      "an entry without it is an entry describing a different client.");
    assert.ok(!grant.dangling,
      "\"" + client + "\" holds " + id + " and the register calls it " +
      "DANGLING, which means no application defines it — the resource's " +
      "permission or its base URI went away after the grant was made. The " +
      "grant is on the entry and resolves to nothing, which is the one shape " +
      "of this configuration that reads as correct and is not.");
  });
  log.debug("Leaving assertDelegated(). " + ids.length + " checked.");
}

// Several delegations, in order and for `provisionAll()`'s reason. The order
// matters more here than it does there: two of them may name the same resource,
// and `expose()` writing the base URI twice is a no-op only because the writes
// do not overlap.
async function delegateAll(base, specs) {
  log.debug("Entering delegateAll(). " + (specs || []).length + " spec(s).");
  var made = [];
  for (var i = 0; i < (specs || []).length; i++) {
    made.push(await delegate(base, specs[i]));
  }
  log.debug("Leaving delegateAll().");
  return made;
}

// Several applications, in order. Sequential rather than concurrent on purpose:
// they are three or four sub-second calls each, and a Promise.all here would
// interleave writes to one registry for no gain that anybody would notice.
async function provisionAll(base, specs) {
  log.debug("Entering provisionAll(). " + (specs || []).length + " spec(s).");
  var entries = [];
  for (var i = 0; i < (specs || []).length; i++) {
    entries.push(await provision(base, specs[i]));
  }
  log.debug("Leaving provisionAll().");
  return entries;
}

module.exports = {
  baseOf: baseOf,
  stsBaseFromEnv: stsBaseFromEnv,
  stsBaseFor: stsBaseFor,
  registryAvailable: registryAvailable,
  provision: provision,
  provisionAll: provisionAll,
  entryOf: entryOf,
  forget: forget,
  valuesOf: valuesOf,
  // The delegated permission half. `delegate()` is the one every caller
  // wants; the other four are here for a job that needs one side of it alone
  // — a resource nobody has been granted anything on yet, or a grant of a
  // permission some other job defined.
  DEFAULT_PERMISSIONS: DEFAULT_PERMISSIONS,
  permissionBaseOf: permissionBaseOf,
  permissionIdOf: permissionIdOf,
  permissionsRegister: permissionsRegister,
  expose: expose,
  grantPermissions: grantPermissions,
  delegate: delegate,
  delegateAll: delegateAll
};
