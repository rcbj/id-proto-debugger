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
  valuesOf: valuesOf
};
