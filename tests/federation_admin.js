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

async function federatedNameOf(idpBase, name) {
  logger().debug("Entering federatedNameOf(). " + name);
  const subject = await subjectOf(idpBase, name);
  const local = "sub-" + subject.slice("urn:uuid:".length).toLowerCase();
  logger().debug("Leaving federatedNameOf(). " + local);
  return local;
}

module.exports = {
  configure: configure,
  adminGet: adminGet,
  adminPost: adminPost,
  must: must,
  tidy: tidy,
  subjectOf: subjectOf,
  federatedNameOf: federatedNameOf
};
