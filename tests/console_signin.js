// File: console_signin.js
//
// ---------------------------------------------------------------------------
// SIGNING IN TO THE MOCK STS'S /admin CONSOLE, IN ONE PLACE.
//
// THIS IS A HELPER AND NOT A JOB. It has no assertions about this debugger at
// all, nothing in run-report.js schedules it, and `browser_flags.js`,
// `expectation.js` and `paths.js` are here on the same terms.
//
// WHY IT EXISTS. Two jobs here read pages off that console — the delegation
// MAPS, which are the only way to see the pictures those two scenarios draw,
// because the mock's delegation register is in memory and dies with the
// container — and until 2026-09-10 each carried its own copy of the walk that
// reaches them. The walk was three fetches then: a gated GET answered 302 to
// `/authn/login?authn=…`, a POST of a username, and a cookie came back.
//
// On 2026-09-06 the mock made `/admin` a RELYING PARTY of its own
// authorization server, so the walk is FIVE hops and TWO cookies, and both
// copies broke in the same way at the same moment — quietly, because a gate
// that now answers 303 rather than 302 reads to the old probe as a gate that
// is switched OFF. Each job then went on to fetch a console page with no
// session, was handed the sign-in screen with a 200 on it, and failed several
// steps later saying the map was not an SVG document and that no identifier on
// the tokens page linked to a lineage — two messages that name a drawing and a
// register, and neither of which names a session.
//
// That is the argument for one copy rather than two, and it is the same one
// `common/xmldsig.js` and `client/src/jws.js` make about a canonicalizer and a
// signature: the copies agree on the day they are written, and the first time
// the thing they describe gains a hop the one nobody edited stops being a test
// of anything.
//
// ---------------------------------------------------------------------------
// WHAT THE WALK IS, AND WHY EACH HOP IS NAMED.
//
//   GET  /admin/<anything>   -> 302/303 /oauth2/authorize?client_id=…
//   GET  /oauth2/authorize   -> 302 /authn/login?authn=…
//   POST /authn/login        -> 303 back to /oauth2/authorize
//   GET  /oauth2/authorize   -> 302 /admin/callback?code=…&state=…
//   GET  /admin/callback     -> 303 wherever the reader was going, plus the
//                               console's own session cookie
//
// A `redirect: "follow"` fetch would do the whole of that silently and would
// then tell a caller only that signing in worked, so a broken hop would
// present as a 401 five steps further on. Each hop is taken by hand for that
// reason. The mock's own `tests/vendored/console_signin.js` makes the same
// walk with assertions on every hop; this side reports rather than asserts,
// because the console is somebody else's surface and a job here that failed on
// it would be reporting a defect in the mock as a defect in this debugger.
//
// IT KEEPS EVERY COOKIE, BY NAME. There are two by the end — the sign-on
// session (`sts_session`, the identity provider's) and the console's own
// (`sts_admin`, established from the ID Token) — and the console reads the
// SECOND. A jar that kept only the last `Set-Cookie` seen would work by luck
// and break the day the order changed. Both lost their `mock_` in iya-sts
// 27b81c5 (2026-09-12), and a walk still looking for the old names reports
// "set no sign-on session cookie" after a perfectly good 303.
//
// A GATE THAT IS OFF IS A LEGITIMATE STATE — `admin.authRequired` is
// switchable — and is reported rather than treated as a pass: no redirect
// means no session is needed and the reads a caller then makes work exactly as
// they did before any of this existed. That is why this answers `null` rather
// than throwing, and why every caller's read path already copes with a null
// session.
// ---------------------------------------------------------------------------
const bunyan = require("bunyan");
const log = bunyan.createLogger({
  name: "console_signin",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// How many redirects the tail of the walk may take before it is a loop rather
// than a flow. Four is the two hops above plus slack; a redirect loop then
// fails as a loop instead of hanging.
const MAX_HOPS = 4;

// ---------------------------------------------------------------------------
// A CONSOLE ROLE, FOR A CALLER THAT ASKS FOR ONE (iya-sts #103, 2026-09-22).
//
// Until #103 whoever signed in held both console roles while the roster was
// empty (`admin.openWhenEmpty`), so a job here signed in as a name of its own
// and read what it needed. Product mode never opens that window now, and a
// development roster stops being open to anyone the moment somebody else is
// granted a role — so a signed-in person with no role is refused 403 on every
// page, and the two delegation-chain jobs lost their maps without failing.
//
// So a caller may pass `{ grant: "read" }` (or "write", which is both), and
// the account is given that role through `POST /admin-api/rbac/grant` before
// it signs in — BUT ONLY WHERE `GET /admin-api/rbac` says the console is NOT
// open to anyone. That condition is the whole design, and it points both ways:
//
//   * where the window is open (a development stack whose roster is empty, or
//     whose seeded bootstrap administrator has not signed in yet), a grant is
//     not needed — and it would CLOSE the window for every other job in the
//     pool that signs in the old way, because the first grant closes it;
//   * where it is shut (product always; development once anybody holds a
//     role), a grant is the only way in.
//
// `iya-sts`'s own `sts_xacml_editor.js` makes the same test for the same
// reason. The pinned sts/ gitlink already publishes `openToAnyone` and the
// grant operation, so this is not gated on a version.
//
// A PASSWORD GOES WITH THE ROLE. Development checks no password, which is why
// the walk types the username twice; product verifies it against the entry.
// So an account about to be given a role is created through
// `POST /admin-api/users/create` with a password of its own (or given one, if
// it exists), random per process — a console account on a deployment that
// outlives the run must not hold a password anybody could derive — and that
// is what the walk types. Every step REPORTS rather than asserts, for the
// reason the header gives: a refusal here is logged, and the caller's reads
// then say what the console answered.
// ---------------------------------------------------------------------------
const consolePasswords = {};

function consolePasswordFor(user) {
  log.debug("Entering consolePasswordFor().");
  const name = String(user);
  if (!consolePasswords[name]) {
    consolePasswords[name] = "Console-signin-" +
        require("crypto").randomBytes(12).toString("base64url") + "-Aa1!";
  }
  log.debug("Leaving consolePasswordFor().");
  return consolePasswords[name];
}

// One management API call, answered as `{ status, body }` whatever came back:
// a refused connection is status 0 and a body that is not JSON is `{ raw }`.
// The run's access token is attached by tools/attach-admin-token.js.
async function adminApi(root, method, path, payload) {
  log.debug("Entering adminApi(). " + method + " " + path);
  let response;
  try {
    response = await fetch(root + "/admin-api" + path, {
      method: method,
      headers: Object.assign({ Accept: "application/json" },
          payload ? { "Content-Type": "application/json" } : {}),
      body: payload ? JSON.stringify(payload) : undefined
    });
  } catch (e) {
    log.debug("Leaving adminApi(). Unreachable: " + (e && e.message));
    return { status: 0, body: { raw: String((e && e.message) || e) } };
  }
  const raw = await response.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in adminApi(): " + ((e && e.message) || e));
    // An HTML error page or an empty body; the raw text is the message.
    body = { raw: raw.slice(0, 300) };
  }
  log.debug("Leaving adminApi(). " + response.status);
  return { status: response.status, body: body };
}

// Give `user` the console role `grant` asks for, where the console is shut
// to anybody without one. Answers the password the walk must type, or null
// to type the username as it always did (no grant was asked for or needed).
async function grantConsoleRole(root, user, grant, say, warn) {
  log.debug("Entering grantConsoleRole(). user=" + user + " grant=" + grant);
  if (grant !== "read" && grant !== "write") {
    log.debug("Leaving grantConsoleRole(). No role asked for.");
    return null;
  }
  const roster = await adminApi(root, "GET", "/rbac");
  if (roster.status !== 200) {
    warn("[console] GET /admin-api/rbac answered " + roster.status + " " +
         JSON.stringify(roster.body).slice(0, 200) + ", so whether " + user +
         " needs a console role cannot be read. Signing in without one; the " +
         "console reads say what that was worth.");
    log.debug("Leaving grantConsoleRole(). No roster.");
    return null;
  }
  if (roster.body.openToAnyone) {
    say("[console] the console is open to anybody who signs in (its roster's " +
        "bootstrap window), so " + user + " is given no role — a grant " +
        "would close that window for every other job in the pool.");
    log.debug("Leaving grantConsoleRole(). Open to anyone.");
    return null;
  }
  const password = consolePasswordFor(user);
  const created = await adminApi(root, "POST", "/users/create", {
    username: user, invent: false, credential: "password", password: password,
    attributes: { cn: "Console " + user, givenName: "Console",
                  sn: String(user), displayName: "Console " + user,
                  mail: String(user) + "@console-signin.test" }
  });
  if (!(created.status === 200 && created.body && created.body.ok)) {
    const set = await adminApi(root, "POST", "/users/set-password",
                               { user: user, password: password });
    if (!(set.status === 200 && set.body && set.body.ok)) {
      warn("[console] " + user + " could be neither created (" +
           created.status + " " + JSON.stringify(created.body).slice(0, 200) +
           ") nor given a password (" + set.status + " " +
           JSON.stringify(set.body).slice(0, 200) + "). A product-mode " +
           "sign-in verifies the password, so it will be refused.");
    }
  }
  const roles = grant === "write" ? ["read", "write"] : ["read"];
  for (const role of roles) {
    const granted = await adminApi(root, "POST", "/rbac/grant",
                                   { username: user, role: role });
    if (granted.status !== 200) {
      warn("[console] granting " + user + " the console's " + role + " role " +
           "answered " + granted.status + " " +
           JSON.stringify(granted.body).slice(0, 200) + ". The console reads " +
           "will be refused 403.");
    }
  }
  say("[console] the console is open only to a role holder (openToAnyone is " +
      "false), so " + user + " was given " + roles.join(" and ") + " and a " +
      "password of its own before signing in.");
  log.debug("Leaving grantConsoleRole(). Granted.");
  return password;
}

// ---------------------------------------------------------------------------
// THE COOKIE JAR. Two cookies, kept by name, presented together.
// ---------------------------------------------------------------------------
function makeJar() {
  log.debug("Entering makeJar().");
  const held = {};
  const jar = {
    keep: function (response) {
      log.debug("Entering keep().");
      const set = response.headers.getSetCookie
          ? response.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const name = pair.split("=")[0];
        const value = pair.slice(name.length + 1);
        // An empty value is a cookie being CLEARED — what a sign-out sends —
        // so it removes the entry rather than storing a name with nothing
        // after it, which the console would then be presented with.
        if (value === "") {
          delete held[name];
        } else {
          held[name] = value;
        }
      });
      log.debug("Leaving keep(). " + Object.keys(held).length + " held.");
    },
    header: function () {
      log.debug("Entering header().");
      const line = Object.keys(held).map(function (name) {
        return name + "=" + held[name];
      }).join("; ");
      log.debug("Leaving header().");
      return line;
    },
    names: function () {
      log.debug("Entering names().");
      const names = Object.keys(held);
      log.debug("Leaving names().");
      return names;
    },
    get: function (name) {
      log.debug("Entering get(). " + name);
      const value = held[name] || "";
      log.debug("Leaving get().");
      return value;
    }
  };
  log.debug("Leaving makeJar().");
  return jar;
}

// ---------------------------------------------------------------------------
// THE WALK.
//
// `base` is the mock's base URL with no trailing slash; `user` is the name to
// type, which is also the password (a development service checks none) unless
// a role was granted below, which gives the account a password of its own.
// `callerLog` is the JOB's logger, so the two lines a reader cares about
// appear in the job's own output rather than in this module's — and it is a
// parameter rather than the module's `log` on purpose: a parameter named `log`
// would SHADOW the module logger, which is the `edge_landing_contract.js` trap
// CLAUDE.md records.
//
// Answers the Cookie header to send on console reads, or null when the gate is
// off or when the walk did not complete.
//
// `options.grant` — "read" or "write" — gives the account that console role
// first, where the console is shut to anybody without one. See
// grantConsoleRole() above for when it is, and why it is not granted when the
// console is open.
// ---------------------------------------------------------------------------
async function signInToTheConsole(base, user, callerLog, options) {
  log.debug("Entering signInToTheConsole(). user=" + user);
  const opts = options || {};
  const say = (callerLog && callerLog.info) ? callerLog.info.bind(callerLog)
      : log.info.bind(log);
  const warn = (callerLog && callerLog.warn) ? callerLog.warn.bind(callerLog)
      : log.warn.bind(log);
  const cookies = makeJar();
  const root = String(base || "").replace(/\/+$/, "");

  function absolute(where) {
    log.debug("Entering absolute().");
    const url = /^https?:\/\//i.test(String(where || ""))
        ? String(where) : root + String(where || "");
    log.debug("Leaving absolute().");
    return url;
  }

  async function hop(where, options) {
    log.debug("Entering hop(). " + where);
    const settings = Object.assign({ redirect: "manual" }, options || {});
    settings.headers = Object.assign({ cookie: cookies.header() },
        settings.headers || {});
    const response = await fetch(absolute(where), settings);
    cookies.keep(response);
    log.debug("Leaving hop(). " + response.status);
    return response;
  }

  // Hop one. A 302 OR A 303: the console answered 302 until 2026-09-06 and
  // answers 303 now, and reading only one of them as "gated" is precisely the
  // failure this module was written for.
  const gated = await hop("/admin/tokens");
  if (gated.status !== 302 && gated.status !== 303) {
    say("[console] admin.authRequired is off (GET /admin/tokens answered " +
        gated.status + " with no redirect), so the console reads need no " +
        "session.");
    log.debug("Leaving signInToTheConsole(). The gate is off.");
    return null;
  }

  const toAuthorize = gated.headers.get("location") || "";
  if (!/\/oauth2\/authorize\?/.test(toAuthorize)) {
    warn("[console] a gated console GET should start an AUTHORIZATION " +
         "REQUEST and went to \"" + toAuthorize + "\". The console signs in " +
         "as the seeded client sts-admin-console; if that entry has been " +
         "deleted the gate answers 503 with the reason rather than " +
         "redirecting. The console reads are skipped.");
    log.debug("Leaving signInToTheConsole(). Not an authorization request.");
    return null;
  }

  // Hop two: the authorization endpoint, which has no sign-on session yet and
  // sends the browser to the screen carrying the id of the request waiting
  // there. Without that id the screen has nothing to sign in FOR.
  const toScreen = await hop(toAuthorize);
  const where = toScreen.headers.get("location") || "";
  const authn = (where.match(/[?&]authn=([^&]+)/) || [])[1];
  if (!authn) {
    warn("[console] the authorization endpoint sent this session to \"" +
         where + "\", which carries no authn id, so there is nothing to sign " +
         "in FOR. The console reads are skipped.");
    log.debug("Leaving signInToTheConsole(). No authn id.");
    return null;
  }

  // Hop three: the screen itself, for its CSRF token. It is read rather than
  // assumed because the mock added one with the same commit that made the
  // console a relying party, and a POST without it is refused as a forgery —
  // a 403 that says nothing about a session.
  const screen = await hop(where);
  const html = await screen.text();
  const csrf = (html.match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";

  // The role, where one is asked for and the console needs one — and with it
  // the password the account now holds. Without one the username is typed as
  // the password, which a development service does not check.
  const password = await grantConsoleRole(root, user, opts.grant, say, warn);

  let signedIn = await hop("/authn/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "authn_id=" + encodeURIComponent(authn) +
        "&username=" + encodeURIComponent(user) +
        "&password=" + encodeURIComponent(password || user) +
        "&action=login" +
        (csrf ? "&csrf_token=" + encodeURIComponent(csrf) : "")
  });
  // AN ADMINISTRATOR IS OFFERED A SECOND FACTOR (iya-sts #246): an account
  // holding a console role and no second factor is shown a set-up step with
  // an Ignore button rather than being signed in, under the authentication
  // policy's default `offer`. Ignore finishes the sign-in on the password,
  // which is all a job reading the console wants. An sts without the step
  // answers the POST with the redirect below and never reaches this.
  if (signedIn.status === 200) {
    const offered = await signedIn.text();
    const setupId = /id="mfa-setup-ignore"/.test(offered)
        ? (offered.match(/name="mfa_id" value="([^"]+)"/) || [])[1] || ""
        : "";
    if (setupId) {
      signedIn = await hop("/authn/mfa-setup", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "mfa_id=" + encodeURIComponent(setupId) + "&action=ignore"
      });
      say("[console] " + user + " was offered a second factor to set up and " +
          "ignored it.");
    }
  }
  if (!cookies.get("sts_session")) {
    warn("[console] signing in at /authn/login answered " + signedIn.status +
         " and set no sign-on session cookie. This service checks no " +
         "password, so a refusal there is about the request rather than the " +
         "credential. The console reads are skipped.");
    log.debug("Leaving signInToTheConsole(). No sign-on cookie.");
    return null;
  }

  // Hops four and five: back through the authorization endpoint, which now
  // has a session, and then the callback, which redeems the code and
  // establishes the console's own cookie.
  let at = await hop(signedIn.headers.get("location") || "");
  let i;
  for (i = 0; i < MAX_HOPS && (at.status === 302 || at.status === 303); i++) {
    at = await hop(at.headers.get("location") || "");
  }

  if (!cookies.get("sts_admin")) {
    warn("[console] the authorization code flow finished holding [" +
         cookies.names().join(", ") + "] and not the CONSOLE's own session " +
         "cookie. That cookie is what the console reads: since 2026-09-06 " +
         "the sign-on session alone does not open it, which is the point of " +
         "the console being a relying party rather than a reader of the " +
         "identity provider's store. The console reads are skipped.");
    log.debug("Leaving signInToTheConsole(). No console cookie.");
    return null;
  }

  say("[console] signed in as " + user + " through the authorization code " +
      "flow; holding " + cookies.names().length + " cookie(s).");
  log.debug("Leaving signInToTheConsole(). Holding a session.");
  return cookies.header();
}

module.exports = {
  signInToTheConsole: signInToTheConsole,
  makeJar: makeJar,
  consolePasswordFor: consolePasswordFor
};
