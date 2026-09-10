// File: tools/admin-api-token.js
//
// MINT THE ACCESS TOKEN THIS SUITE DRIVES THE MOCK STS'S `/admin-api` WITH.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS.
//
// The mock's management API required no credential at all until the 2026-09-09
// submodule bump. It now takes an OAuth 2.0 access token audienced to itself,
// carrying `admin:read` to read and `admin:write` to write — one middleware on
// the base path, so all 232 of its operations are gated by construction.
// About fifteen jobs in this suite configure the mock through that API, so
// without a token a bump would report fifteen broken tests instead of one
// missing credential.
//
// THIS IS THE ONE PLACE A RUN OBTAINS ONE. `run-report.js` calls it once,
// before any job starts, and hands the result to every job it spawns together
// with `tools/attach-admin-token.js`, which presents it. The `--*-only` modes
// in `local-run-tests.sh` get the same token from `mintAdminApiToken()` in
// `common/common.sh`, which runs this file as a program.
//
// IT IS A TOOL AND NOT A TEST, which is why it is under `tools/`: three source
// -inspection jobs (`browser_tests_headless.js`, `driver_quit_reachable.js`,
// `download_dir_pinned.js`) read every `.js` BESIDE them and would otherwise
// hold this file to rules written for a Selenium test.
//
// ---------------------------------------------------------------------------
// THE BOOTSTRAP HOLE, AND WHY A LAUNCHER HAS TO PIN A SECRET.
//
// The token comes from the seeded `sts-management-api` client with
// `client_credentials`. That client's secret is minted at every start of the
// mock and is readable only THROUGH the API it unlocks — so a service that has
// started is a service nobody can get a token for. `adminApi.clientSecret`
// (env `ADMIN_API_CLIENT_SECRET` on that container) pins it, and the launchers
// here generate one per run and hand the same value to the mock and to
// whoever mints. `STS_ADMIN_API_CLIENT_SECRET` is how it reaches this file.
//
// The fallback below reads the secret out of the API instead, and it works
// only while `adminApi.authRequired` is off. That is not dead code: it is what
// makes `./remote-run-tests.sh` against a mock somebody else configured work
// with nothing set here.
// ---------------------------------------------------------------------------
'use strict';

const bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "admin-api-token",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to
      // info loses only the configured verbosity.
      return "info";
    }
  })(),
});

// The client the mock seeds for this purpose, and the two scopes its access
// policy asks for. `common/roles.js` over there turns them into the built-in
// ADMIN_READ and ADMIN_WRITE roles.
const CLIENT_ID = "sts-management-api";
const SCOPES = "admin:read admin:write";

// What `aud` has to name. The mock's `adminApi.audience` is empty on every
// stack here, which means "this service's own /admin-api under the host the
// request arrived on" — exactly what asking for `resource=<base>/admin-api`
// at the token endpoint (RFC 8707) produces.
function audienceFor(base) {
  log.debug("Entering audienceFor().");
  const wanted = String(base).replace(/\/+$/, "") + "/admin-api";
  log.debug("Leaving audienceFor(). " + wanted);
  return wanted;
}

// Is the API gated on this service? Asked by CALLING it rather than by reading
// a configuration this side does not own — `adminApi.authRequired` is settable
// while the mock is running and per trust realm, so the only honest answer is
// the one the service gives. 401 means a token is needed; anything else means
// this run needs none and must not fail trying to obtain one.
async function isGated(base) {
  log.debug("Entering isGated().");
  let response = null;
  try {
    response = await fetch(audienceFor(base) + "/config",
                           { headers: { Accept: "application/json" } });
  } catch (e) {
    log.debug("Leaving isGated(). Unreachable: " + e.message);
    throw new Error("could not reach " + audienceFor(base) + ": " + e.message);
  }
  const gated = response.status === 401;
  log.debug("Leaving isGated(). " + response.status + " -> " + gated);
  return gated;
}

// The seeded client's secret. The environment first, because that is what a
// launcher pins; the open API second, for a service that is not gated.
async function secretFor(base) {
  log.debug("Entering secretFor().");
  if (process.env.STS_ADMIN_API_CLIENT_SECRET) {
    log.debug("Leaving secretFor(). From the environment.");
    return process.env.STS_ADMIN_API_CLIENT_SECRET;
  }
  const response = await fetch(audienceFor(base) + "/applications?identifier=" +
                               encodeURIComponent(CLIENT_ID),
                               { headers: { Accept: "application/json" } });
  if (response.status !== 200) {
    log.debug("Leaving secretFor(). The API answered " + response.status + ".");
    return "";
  }
  const text = await response.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Leaving secretFor(). Not JSON.");
    return "";
  }
  const rows = body.applications ||
        (body.application ? [body.application] : []);
  const row = rows.filter(function (one) {
    return one && one.identifier === CLIENT_ID;
  })[0];
  const secret = (row && row.registration &&
                  row.registration.client_secret) || "";
  log.debug("Leaving secretFor(). " + (secret ? "Read it." : "Not there."));
  return secret;
}

// `options` exists for a job that wants a token this run's jobs would not
// otherwise be given — one scope only, or an audience naming somebody else, to
// assert the gate's refusals. It is a parameter rather than a second token
// endpoint call written out in that job for the reason this file exists: the
// client id, the grant, the authentication scheme and the shape of the form
// are one fact, and a test that restated them would go on passing against a
// service that had changed any of them.
async function mint(base, secret, options) {
  log.debug("Entering mint().");
  const wanted = options || {};
  const audience = wanted.audience || audienceFor(base);
  const scope = wanted.scope === undefined ? SCOPES : wanted.scope;
  const form = "grant_type=client_credentials" +
        "&scope=" + encodeURIComponent(scope) +
        "&resource=" + encodeURIComponent(audience);
  const response = await fetch(String(base).replace(/\/+$/, "") +
                               "/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      Authorization: "Basic " +
        Buffer.from(CLIENT_ID + ":" + secret).toString("base64")
    },
    body: form
  });
  const text = await response.text();
  if (response.status !== 200) {
    log.debug("Leaving mint(). The token endpoint answered " +
              response.status + ".");
    throw new Error("the token endpoint answered " + response.status + " " +
                    text.slice(0, 300));
  }
  const body = JSON.parse(text);
  if (!body.access_token) {
    log.debug("Leaving mint(). 200 with no access_token.");
    throw new Error("the token endpoint answered 200 with no access_token: " +
                    text.slice(0, 300));
  }
  log.debug("Leaving mint(). Minted.");
  return body.access_token;
}

async function tokenFor(base, options) {
  log.debug("Entering tokenFor().");
  const secret = await secretFor(base);
  if (!secret) {
    log.debug("Leaving tokenFor(). No secret.");
    throw new Error("could not read the " + CLIENT_ID + " client secret " +
                    "from " + base + ". Set STS_ADMIN_API_CLIENT_SECRET " +
                    "(the launchers pin ADMIN_API_CLIENT_SECRET on the mock " +
                    "and pass the same value here), or start that service " +
                    "with adminApi.authRequired=false.");
  }
  const token = await mint(base, secret, options);
  log.debug("Leaving tokenFor().");
  return token;
}

module.exports = {
  tokenFor: tokenFor,
  audienceFor: audienceFor,
  isGated: isGated,
  mint: mint,
};

// AS A PROGRAM it writes the token on stdout and NOTHING AT ALL when the
// service leaves /admin-api open, so a shell caller can export what it gets
// and let an empty answer mean "no credential is needed here". Everything it
// has to say to a person goes to stderr, which is what keeps that contract
// usable from `$(...)`.
if (require.main === module) {
  const base = process.argv[2] || process.env.STS_URL ||
        "https://localhost:8081";
  isGated(base).then(function (gated) {
    if (!gated) {
      process.stderr.write("admin-api-token: " + base + "/admin-api is " +
                           "open; no token is needed.\n");
      return "";
    }
    return tokenFor(base);
  }).then(function (token) {
    if (token) {
      process.stdout.write(token + "\n");
    }
  }).catch(function (e) {
    process.stderr.write("admin-api-token: " + e.message + "\n");
    process.exit(1);
  });
}
