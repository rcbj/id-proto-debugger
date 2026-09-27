// File: federation_admin.js
//
// ===========================================================================
// THE MOCK STS'S MANAGEMENT API, for the tests that configure a federation.
//
// Four functions and nothing else: a GET, a POST, a POST that must have
// worked, and a POST that is allowed not to have. Every federation test here
// begins by provisioning realms, applications and relationships through
// `/admin-api`, and until 2026-08-26 each of them carried its own private copy
// of these four — `federation_sso.js` and `federation_chain_sso.js`, character
// for character apart from one error message naming the base URL and one not.
// `federation_matrix_sso.js` would have been the third copy. It is not.
//
// Beside those four are the questions every federation job asks of the
// result: who a person IS in a realm (`subjectOf()`), and what the service
// provider files them under (`federatedNameOf()`, `localNameAt()`, and
// `pinSubjectPolicy()`, which decides it — see the note above it for why the
// jobs pin the policy they do), and how a realm is let dial its partner's
// back channel (`trustPartnerTls()`).
//
// ---------------------------------------------------------------------------
// WHY `/admin-api` AND NOT THE `/admin` CONSOLE.
//
// Since 2026-08-24 the mock ships `admin.authRequired` ON, so every console
// page and every console form needs a browser session and a role, and a caller
// posting JSON is answered 401 rather than redirected. `/admin-api` is
// the surface that exists for a program, and since 2026-09-09 it wants a
// credential of its own — an OAuth 2.0 access token rather than the console's
// session. Nothing in this file mints or presents one: run-report.js preloads
// tools/attach-admin-token.js into every job, which puts the run's token on
// these calls and on nothing else. See tests/CLAUDE.md.
//
// The one difference from driving the console's forms is that the ACTION IS IN
// THE PATH here rather than in the body: `/applications/create`,
// `/federation/set`, `/realms/create`.
//
// ---------------------------------------------------------------------------
// WHY A FAILURE IS NOT AN EXCEPTION FROM `adminPost()`.
//
// The mock answers a refusal with 400 and an `errors` array rather than
// throwing, and that array is the service's own account of what it disliked —
// "fedSsoUrl is not an absolute URL", "unknown protocol", "no such
// relationship". `must()` puts it in the assertion message, which is worth
// rather more than "the call failed". A caller that wants to inspect the
// refusal itself calls `adminPost()` and reads `.ok`.
//
// ---------------------------------------------------------------------------
// IT TAKES THE LOGGER. Every test here creates its own bunyan logger named
// after its file, and a shared module with a logger of its own would put half
// of a run's configuration trail under a name that matches no job in the
// report. So the caller passes its own in once, at require time.
// ===========================================================================

const assert = require("assert");

// The module's own logger, used only if a caller never configures one. It is
// created lazily for the reason `wait_for.js`'s is: requiring this file must
// not depend on CONFIG_FILE being set, because `tests/jwk_pem_encoding.js`
// walks the closure of every test module without one.
let log = null;

function logger() {
  if (log) {
    return log;
  }
  const bunyan = require("bunyan");
  let level = "info";
  try {
    level = require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
  } catch (e) {
    // No CONFIG_FILE, or one that will not load. This module does nothing that
    // needs it, and a test that has one configures the logger below anyway, so
    // falling back to "info" is the whole of the recovery.
    level = "info";
  }
  log = bunyan.createLogger({ name: "federation_admin", level: level });
  return log;
}

// The caller's logger, so a run's configuration trail is filed under the job's
// own name.
function configure(options) {
  logger().debug("Entering configure().");
  if (options && options.log) {
    log = options.log;
  }
  logger().debug("Leaving configure().");
}

async function adminGet(base, path) {
  logger().debug("Entering adminGet(). " + path);
  const response = await fetch(base + "/admin-api" + path,
                               { headers: { Accept: "application/json" } });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    logger().debug("Leaving adminGet(). Not JSON.");
    throw new Error("GET " + base + "/admin-api" + path + " answered " +
                    response.status + " with something that is not JSON: " +
                    text.slice(0, 300));
  }
  logger().debug("Leaving adminGet(). " + response.status);
  return parsed;
}

async function adminPost(base, path, body) {
  logger().debug("Entering adminPost(). " + path);
  const response = await fetch(base + "/admin-api" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    logger().debug("Leaving adminPost(). Not JSON.");
    throw new Error("POST " + base + "/admin-api" + path + " answered " +
                    response.status + " with something that is not JSON: " +
                    text.slice(0, 300));
  }
  logger().debug("Leaving adminPost(). ok=" + parsed.ok);
  return parsed;
}

// A management API call that must have worked. See the header: the message a
// failure produces is the mock's own account of what it disliked.
async function must(base, path, body, what) {
  logger().debug("Entering must(). " + what);
  const result = await adminPost(base, path, body);
  assert.ok(result.ok, what + " was refused by the mock STS: " +
            JSON.stringify(result.errors || result));
  logger().debug("Leaving must().");
  return result;
}

// A call that is ALLOWED to fail because it is a tidy-up: removing something an
// earlier run may or may not have left behind. It is a separate function rather
// than a flag on must(), because a swallowed failure and an asserted one must
// not be one line apart with a boolean between them — the whole point of the
// asserted kind is that a setup step which quietly did nothing is worse than
// none.
async function tidy(base, path, body, what) {
  logger().debug("Entering tidy(). " + what);
  const result = await adminPost(base, path, body);
  if (!result.ok) {
    logger().debug("tidy(): " + what + " was not needed: " +
                   JSON.stringify(result.errors || result));
  }
  logger().debug("Leaving tidy().");
  return result;
}

// ---------------------------------------------------------------------------
// WHO A PERSON IS IN A REALM, NOW THAT IT IS NOT THEIR NAME (2026-09-14).
//
// Since iya-sts 64580f4 a person's `sub` is `urn:uuid:<entryUUID>` in every
// protocol — the directory entry's RFC 4530 identifier — where it used to be
// built from the name. Two things follow for a federation test, and both are
// the mock's documented rules rather than guesses:
//
//   * `subjectOf(base, name)` is the subject a realm holds for somebody. It is
//     not derivable from the name any more, so the realm's management API is
//     asked; `/admin-api/users?user=` answers it on the person's drill-down.
//   * `federatedNameOf(idpBase, name)` is what the NEAR realm files a person
//     under when the far realm names them by that subject. A partner's
//     `urn:uuid:` is a value in the PARTNER's namespace, so the near realm
//     never looks it up in its own directory: it becomes the local name
//     `sub-<uuid>` (iya-sts `federation/federation_map.js`'s `usernameFor()`).
//     That applies only where the far realm hands over its `sub` — an OAuth
//     2.0 or OpenID Connect hop. A SAML or WS-Federation hop names the person
//     by a NameID, which is still the username, so the name crosses as it is.
// ---------------------------------------------------------------------------
async function subjectOf(base, name) {
  logger().debug("Entering subjectOf(). " + name);
  const person = await adminGet(base,
    "/users?user=" + encodeURIComponent(name));
  const subject = String((person && person.subject) || "");
  assert.ok(/^urn:uuid:[0-9a-f-]{36}$/.test(subject),
    base + " holds no urn:uuid subject for \"" + name + "\". Since iya-sts " +
    "64580f4 no signed-in session exists without a directory entry, so a " +
    "person who has signed in there must have one. It answered: " +
    JSON.stringify(person).slice(0, 300));
  logger().debug("Leaving subjectOf(). " + subject);
  return subject;
}

// `spBase` and `relationship` are optional, and with them the answer is the
// name the near realm files the person under THROUGH that relationship — which
// since iya-sts #109 is not always the mapped name. See localNameAt().
async function federatedNameOf(idpBase, name, spBase, relationship) {
  logger().debug("Entering federatedNameOf(). " + name);
  const subject = await subjectOf(idpBase, name);
  const mapped = "sub-" + subject.slice("urn:uuid:".length).toLowerCase();
  if (!spBase || !relationship) {
    logger().debug("Leaving federatedNameOf(). " + mapped);
    return mapped;
  }
  const local = await localNameAt(spBase, relationship, mapped);
  logger().debug("Leaving federatedNameOf(). " + local);
  return local;
}

// ---------------------------------------------------------------------------
// WHICH LOCAL PERSON A PARTNER'S SUBJECT BECOMES (iya-sts #109, 2026-09-22).
//
// Until #109 a service-provider-side relationship matched the name it mapped
// out of an assertion onto a local person, and created one of that name when
// there was none. Since then a partner signs in only the person its subject
// is LINKED to, and the relationship's `fedSubjectPolicy` decides what an
// unlinked subject becomes:
//
//   link-at-first-sign-in  the default (and what an empty value means). A
//                          subject naming an existing person is sent to the
//                          SP's own sign-in screen first, to link; one naming
//                          nobody gets a NEW entry `<relationship>~<name>`.
//   jit-namespaced         always a new entry `<relationship>~<name>`.
//   pre-linked             nobody is signed in who was not linked first,
//                          through POST /admin-api/users/federation-link.
//   any-existing           the old name match, and a created entry keeps the
//                          plain name. DEVELOPMENT ONLY: product refuses to
//                          set it (STS-FED-0095).
//
// WHAT THE FEDERATION JOBS HERE PIN, AND WHY IT IS `any-existing`. Each of
// them signs in a person the service provider has never seen and asserts two
// things about the result: that the SP CREATED the entry at the first
// federated sign-in, and that the application's tokens name NEITHER the
// partner realm NOR the relationship — "the one property the whole feature
// exists to have", in federation_sso.js's words. Under the default policy
// the created entry is `<relationship>~<name>`, and the relationship ids here
// ARE partner realm names (`federation-realm-2`, `choice-saml2`, the chain's
// `federation-realm-4`), so the SP's own username would carry the partner
// into every ID Token and the second assertion could not hold. `pre-linked`
// keeps the names but provisions the person BEFORE the sign-in, which is the
// first assertion gone, and it needs the partner's `urn:uuid:` subject before
// anybody has signed in there. `any-existing` keeps both assertions exactly
// as they were; what it costs is that these jobs need a DEVELOPMENT realm,
// which they already did — product never creates a federated person
// (STS-FED-0090), and the partner realms here check no password. The subject
// policies themselves are the mock's own job to test
// (`sts_federation_subject_policy.js` in iya-sts), and an sts from before #109
// has no such attribute, so it is set only where the relationship's own
// `editable` list names it.
// ---------------------------------------------------------------------------
const SUBJECT_POLICY_FOR_TESTS = "any-existing";

// Where `fedSubjectPolicy` is known, per relationship, once read: null for an
// sts that predates it, otherwise the policy in force (empty meaning the
// default). Keyed on the realm base AND the id, for editableModes()'s reason
// in sts_applications.js.
const policyByRelationship = {};

async function subjectPolicyOf(spBase, relationship) {
  logger().debug("Entering subjectPolicyOf(). " + relationship);
  const key = spBase + " " + relationship;
  if (Object.prototype.hasOwnProperty.call(policyByRelationship, key)) {
    logger().debug("Leaving subjectPolicyOf(). Cached.");
    return policyByRelationship[key];
  }
  const view = await adminGet(spBase,
    "/federation?relationship=" + encodeURIComponent(relationship));
  assert.ok(view && view.found,
    "The relationship \"" + relationship + "\" is not registered at " +
    spBase + ", so which person its partner signs in cannot be read off it.");
  const knows = (view.editable || []).some(function (row) {
    return row && row.name === "fedSubjectPolicy";
  });
  const policy = knows
    ? String((view.fields || {}).fedSubjectPolicy || "").trim()
    : null;
  policyByRelationship[key] = policy;
  logger().debug("Leaving subjectPolicyOf(). " +
                 (policy === null ? "Before #109." : policy || "(default)"));
  return policy;
}

// Put SUBJECT_POLICY_FOR_TESTS on a service-provider-side relationship, where
// the sts knows the attribute. Answers true when it was set and false for an
// sts from before #109, which behaves that way with no attribute at all.
async function pinSubjectPolicy(spBase, relationship) {
  logger().debug("Entering pinSubjectPolicy(). " + relationship);
  const key = spBase + " " + relationship;
  delete policyByRelationship[key];
  if ((await subjectPolicyOf(spBase, relationship)) === null) {
    logger().info("[federation] " + spBase + " predates fedSubjectPolicy " +
                  "(iya-sts #109), so \"" + relationship + "\" matches the " +
                  "mapped name onto a local person without being told to.");
    logger().debug("Leaving pinSubjectPolicy(). Before #109.");
    return false;
  }
  const result = await adminPost(spBase, "/federation/set",
    { id: relationship, field: "fedSubjectPolicy",
      value: SUBJECT_POLICY_FOR_TESTS });
  assert.ok(result.ok,
    "Setting fedSubjectPolicy=" + SUBJECT_POLICY_FOR_TESTS + " on \"" +
    relationship + "\" at " + spBase + " was refused: " +
    JSON.stringify(result.errors || result) + ". That value is " +
    "development-only (STS-FED-0095), and this job needs it for the reason " +
    "federation_admin.js gives: it asserts a person CREATED at the first " +
    "federated sign-in, which a product-mode realm never does. Run it " +
    "against a development realm.");
  delete policyByRelationship[key];
  const now = await subjectPolicyOf(spBase, relationship);
  assert.strictEqual(now, SUBJECT_POLICY_FOR_TESTS,
    "\"" + relationship + "\" was set to fedSubjectPolicy=" +
    SUBJECT_POLICY_FOR_TESTS + " and its entry says \"" + now + "\".");
  logger().info("[federation] \"" + relationship + "\" matches the mapped " +
                "name onto a local person (fedSubjectPolicy=" + now + ").");
  logger().debug("Leaving pinSubjectPolicy(). Set.");
  return true;
}

// The name the service provider at `spBase` files a person under when the
// partner behind `relationship` names them `name` (the MAPPED name: the
// NameID, or `sub-<uuid>` for an OAuth 2.0 or OpenID Connect hop — see
// federatedNameOf()) and nobody linked that subject beforehand, so the
// entry was created by the sign-in. Read off the relationship's own policy,
// so it is right whichever one a job chose.
async function localNameAt(spBase, relationship, name) {
  logger().debug("Entering localNameAt(). " + relationship + " " + name);
  const policy = await subjectPolicyOf(spBase, relationship);
  if (policy === null || policy === "any-existing") {
    logger().debug("Leaving localNameAt(). The name as mapped.");
    return name;
  }
  if (policy === "pre-linked") {
    // Nobody is created under pre-linked: the person is whoever an
    // administrator linked, which the job that linked them knows and this
    // cannot work out. The mapped name is the only answer there is.
    logger().debug("Leaving localNameAt(). Pre-linked; the name as mapped.");
    return name;
  }
  // link-at-first-sign-in (or empty) and jit-namespaced: a created entry is
  // namespaced to the relationship, `federation_links.ts`'s namespacedName().
  const local = relationship + "~" + name;
  logger().debug("Leaving localNameAt(). " + local);
  return local;
}

// ---------------------------------------------------------------------------
// LETTING A REALM DIAL ITS PARTNER'S BACK CHANNEL (iya-sts #171, 2026-09-23).
//
// An OAuth 2.0 or OpenID Connect relationship redeems its code at the
// partner's token endpoint through `federation_http`, which refuses plain
// http and a certificate nothing trusts. Until #171 one realm setting,
// `federation.outboundAllowInsecure`, waived both; it is gone, and writing it
// is now refused by name. Three settings replace it, and this picks the
// strictest one that works:
//
//   * `federation.outboundCaFile`, VERIFICATION ON. Every stack here hands
//     the mock the stack's own leaf (`tls.certificateFile`, which is
//     `stack-tls-cert.pem` — leaf, issuing CA and root), and the partner is
//     the same process answering on the same certificate. So the file the
//     mock already serves from is a CA file naming the root its own partner
//     chains to, and the mock can read it because it reads it to listen.
//   * `federation.outboundSkipTlsVerification`, development only, when the
//     mock was given no certificate and makes its own at every start — a
//     bare `docker run`, or ./remote-run-tests.sh against somebody else's
//     mock. There is no file to name then, and nothing better to do.
//   * `federation.outboundAllowHttp` as well, when the realm is served over
//     plain http, because that is a separate refusal now.
//
// An sts from before #171 knows none of the three, and there the old setting
// is still the answer — one branch, so it is kept.
//
// Written WHILE THE REALM IS AMBIENT, and that is asserted: a setting
// without one lands process-wide, where it would change the certificate
// check for every other job on this mock. Answers the keys it wrote, so a
// caller that puts them back knows what to reset.
// ---------------------------------------------------------------------------
async function trustPartnerTls(spBase, realm, why) {
  logger().debug("Entering trustPartnerTls(). " + realm);
  const before = await adminGet(spBase, "/config");
  const settings = {};
  // `groups[].settings[]`, each row carrying its key and the value in force
  // in the realm that answered.
  (before.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (row) {
      if (row && row.key) {
        settings[row.key] = row;
      }
    });
  });
  const writes = [];
  if (!settings["federation.outboundCaFile"]) {
    writes.push({ key: "federation.outboundAllowInsecure", value: "true" });
  } else {
    const certificateFile = settings["tls.certificateFile"]
      ? String(settings["tls.certificateFile"].value || "").trim()
      : "";
    if (certificateFile) {
      writes.push({ key: "federation.outboundCaFile",
                    value: certificateFile });
    } else {
      writes.push({ key: "federation.outboundSkipTlsVerification",
                    value: "true" });
    }
    if (/^http:/i.test(spBase)) {
      writes.push({ key: "federation.outboundAllowHttp", value: "true" });
    }
  }
  for (const write of writes) {
    await must(spBase, "/config/set", write,
               "setting " + write.key + "=" + write.value + " in " + realm +
               " (" + why + ")");
  }
  const after = await adminGet(spBase, "/config");
  assert.strictEqual(String(after.realm), realm,
    "Reading " + realm + "'s configuration answered for the \"" +
    after.realm + "\" realm, so the writes above did not land where this " +
    "test thinks they did either.");
  const own = after.realmSettings || [];
  writes.forEach(function (write) {
    assert.ok(own.indexOf(write.key) >= 0,
      realm + " does not list " + write.key + " among its OWN settings " +
      "(it lists: " + own.join(", ") + "), so the write went process-wide " +
      "— which is not this test's to do, and would change the certificate " +
      "check for every other job on this mock.");
  });
  logger().info("[federation] " + realm + " may dial its partner's back " +
                "channel: " + writes.map(function (write) {
                  return write.key + "=" + write.value;
                }).join(", ") + ".");
  logger().debug("Leaving trustPartnerTls().");
  return writes.map(function (write) {
    return write.key;
  });
}

module.exports = {
  configure: configure,
  trustPartnerTls: trustPartnerTls,
  adminGet: adminGet,
  adminPost: adminPost,
  must: must,
  tidy: tidy,
  subjectOf: subjectOf,
  federatedNameOf: federatedNameOf,
  subjectPolicyOf: subjectPolicyOf,
  pinSubjectPolicy: pinSubjectPolicy,
  localNameAt: localNameAt,
  SUBJECT_POLICY_FOR_TESTS: SUBJECT_POLICY_FOR_TESTS
};
