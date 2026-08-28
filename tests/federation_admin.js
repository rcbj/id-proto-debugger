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
// deliberately not gated and is the surface that exists for a program.
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

module.exports = {
  configure: configure,
  adminGet: adminGet,
  adminPost: adminPost,
  must: must,
  tidy: tidy
};
