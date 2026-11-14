// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

"use strict";
//
// File: console_signin.js
//
// ===========================================================================
// SIGNING IN AS THE STATIC ADMIN CONSOLE, OVER HTTP, AND ASKING WHAT ITS
// PAGES ASK (#446, 2026-10-05).
//
// **THIS IS A HELPER AND NOT A JOB.** It has no assertions of its own beyond
// the ones that say the flow did not happen. BROUGHT BACK FROM iya-sts (2026-10-22, rcbj's decision): written in
// that repository's tests/vendored/ while this suite still drove the old
// form-based screens, and copied here under this repository's licence once
// the sts/ submodule was bumped past them..
//
// ---------------------------------------------------------------------------
// WHAT CHANGED AT THE CUTOVER, AND SO WHAT THIS DOES.
//
// The console was a relying party that kept a session cookie, and a job read
// a page with that cookie and `?format=json`. Since #446 the console is a
// static page: every `/admin/*` path answers the same document, and the page
// signs in IN THE BROWSER as the public client `sts-admin-console` — the
// code flow with PKCE S256, `resource` the realm's `/admin-api`, a token
// that is always DPoP-bound — and draws each page from its `/admin-api`
// operation's answer. So a job signs in the same way and asks the same
// operations:
//
//   GET  /oauth2/authorize?…code_challenge…     -> 302 /authn/login?authn=…
//   the sign-in screen, over /authn-api (#571)  -> back to authorize
//   GET  /oauth2/authorize                      -> 302 /admin/callback?code=…
//   POST /oauth2/token (DPoP)                   -> a DPoP-bound access token
//
// The callback itself is not fetched: it is the console's own page, and what
// it does with the code — the token request — is done here.
//
// **THE CLIENT IT ANSWERS** reaches a console path through the operation
// that MIRRORS it, read off the index `GET /admin-api` answers (every
// operation names the console control it mirrors — rule 7), the way the
// console's runtime does (`admin-ui/web_forms.ts`):
//
//   * `page(path, query)` — the operation a page is drawn from, asked with
//     the page's query: what `?format=json` used to answer.
//   * `draw(path, query)` — that answer drawn by the console's own
//     renderers (`admin-ui/console.bundle.js`), for a job that reads a page.
//   * `act(path, fields)` — the POST operation the form at `path` with this
//     `action` is, sent its fields as JSON.
//   * `api(method, path, body)` — any `/admin-api` path, as the console.
//   * `raw(method, path, bytes, contentType)` — bytes as the body, as the
//     console sends a file to an operation that takes one.
//   * `refresh()` — the refresh grant with the same DPoP key, as the
//     console renews; `token` and `refreshToken` are the current pair.
//   * `get(url)` — a console URL as the jobs wrote one before the cutover,
//     answered `{ status, body, text }`: `body` what `?format=json` was,
//     `text` the page drawn.
//
// Each request carries a fresh DPoP proof with `ath`, and a `use_dpop_nonce`
// refusal is retried once with the server's nonce (RFC 9449 section 8).
//
// **IT KEEPS EVERY COOKIE, BY NAME**, for the sign-on session the walk sets
// (`sts_session`); `client.cookie` is that header, for a job that also needs
// the person's browser session.
// ===========================================================================

const assert = require("assert");
// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'console_signin',
  level: process.env.LOG_LEVEL || 'info' });

// The jar, and the two things a caller does with it.
function jar() {
  log.debug("Entering jar().");
  const held = {};
  log.debug("Leaving jar().");
  return {
    keep: function (response) {
      log.debug("Entering keep().");
      const set = response.headers.getSetCookie
        ? response.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const name = pair.split("=")[0];
        const value = pair.slice(name.length + 1);
        // An empty value is a cookie being CLEARED — what a sign-out sends —
        // and it has to remove the entry rather than store an empty one, or
        // the jar goes on presenting a name with nothing after it.
        if (value === "") {
          delete held[name];
        } else {
          held[name] = value;
        }
      });
      log.debug("Leaving keep().");
    },
    header: function () {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(held).map(function (k) {
        return k + "=" + held[k];
      }).join("; ");
    },
    names: function () {
      log.debug("Entering names().");
      log.debug("Leaving names().");
      return Object.keys(held);
    },
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return held[name] || "";
    }
  };
}

// ---------------------------------------------------------------------------
// THE PERSON WHO SIGNS IN IS CREATED FIRST, WITH A PASSWORD AND THE ATTRIBUTES
// A REAL ACCOUNT CARRIES (2026-09-12).
//
// This walk used to type a name nobody had created and a password equal to it,
// and it worked because development mode checks no password and creates a
// person — with an INVENTED persona on the entry — for any name that signs in.
// Product mode does neither: it verifies the password against the person's own
// entry and invents no `sn`, `mail` or `displayName`. So the account is made
// through `POST /admin-api/users/create` with `invent: false`, its own
// attributes and a password of at least twelve characters, and that is the
// password typed. A name already taken (a second job, or a second run against a
// kept stack) gets the same password SET rather than a second entry, because
// one entry per person is the directory's rule and the sign-in below has to
// present a password that entry holds.
//
// The management API is reached with whatever credential the run's preload
// attaches (`tests/tools/attach-admin-token.js`); nothing here mints one.
// ---------------------------------------------------------------------------
// THE PASSWORD IS RANDOM PER PROCESS, AND STABLE WITHIN IT (2026-09-18).
// It was derived from the name — `Console-signin-<user>-Passw0rd!` — which is
// harmless on a stack torn down after the run and a published credential on
// a deployment that outlives it: testidp, where a signed-in console account may
// hold a console role (see `grant` below). Stable within the process because a
// job signs the same account in twice (admin_api.js asks for it again), and a
// new random one per process means an account a previous run left behind has
// a password nobody holds.
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

async function ensureConsoleAccount(base, user, say) {
  log.debug("Entering ensureConsoleAccount().");
  const password = consolePasswordFor(user);
  const domain = "console-signin.test";
  async function apiPost(path, payload) {
    log.debug("Entering apiPost().");
    const r = await fetch(base + "/admin-api" + path, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const raw = await r.text();
    let body = {};
    try {
      body = JSON.parse(raw);
    } catch (e) {
      log.debug("Caught in apiPost(): " + ((e && e.message) || e));
      // Not JSON — an HTML error page. Kept as the raw text for the message.
      body = { raw: raw };
    }
    log.debug("Leaving apiPost().");
    return { status: r.status, body: body };
  }
  const created = await apiPost("/users/create", {
    username: user, invent: false,
    attributes: { cn: "Console " + user, givenName: "Console", sn: String(user),
                  displayName: "Console " + user,
                  mail: String(user) + "@" + domain },
    credential: "password", password: password
  });
  if (created.status === 200 && created.body && created.body.ok) {
    say("[console] created " + user + " with a password and its attributes " +
        "before signing in.");
    log.debug("Leaving ensureConsoleAccount().");
    return password;
  }
  if (created.body && created.body.existing) {
    const set = await apiPost("/users/set-password",
                              { user: user, password: password });
    if (!(set.status === 200 && set.body && set.body.ok)) {
      // NOT A FAILURE HERE, though the sign-in below will be one: the
      // password is new to this process, so a refusal is a policy this helper
      // does not satisfy, and the sign-in names it. The same process asking
      // twice is the one ordinary refusal — the history holds the same value.
      say("[console] " + user + " already exists and setting its password " +
          "again answered " + set.status + " " +
          JSON.stringify(set.body).slice(0, 200) + ".");
    }
    log.debug("Leaving ensureConsoleAccount().");
    return password;
  }
  assert.fail("creating the console account " + user + " through POST " +
    "/admin-api/users/create answered " + created.status + " " +
    JSON.stringify(created.body).slice(0, 300));
  log.debug("Leaving ensureConsoleAccount().");
}

// --- DPoP and PKCE, with node's crypto -------------------------------------

function b64u(buffer) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buffer).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A P-256 key per sign-in, as the console makes one per page load, and the
// RFC 9449 proof it signs: `typ` dpop+jwt, the public key in the header,
// `htu` without query or fragment, `ath` beside an access token, `nonce`
// once a server has given one. node signs ECDSA as r || s with
// `dsaEncoding: "ieee-p1363"`, which is JOSE's ES256 form.
function dpopKey() {
  log.debug("Entering dpopKey().");
  const crypto = require("crypto");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const state = { nonce: "" };
  log.debug("Leaving dpopKey().");
  return {
    publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    keepNonce: function (response) {
      const nonce = response.headers.get("dpop-nonce");
      if (nonce) {
        state.nonce = nonce;
      }
    },
    proof: function (method, url, accessToken) {
      const header = { typ: "dpop+jwt", alg: "ES256", jwk: this.publicJwk };
      const claims = { jti: b64u(crypto.randomBytes(16)),
                       htm: String(method).toUpperCase(),
                       htu: String(url).replace(/[?#].*$/, ""),
                       iat: Math.floor(Date.now() / 1000) };
      if (accessToken) {
        claims.ath = b64u(crypto.createHash("sha256").update(accessToken)
          .digest());
      }
      if (state.nonce) {
        claims.nonce = state.nonce;
      }
      const input = b64u(JSON.stringify(header)) + "." +
                    b64u(JSON.stringify(claims));
      const signature = crypto.sign("sha256", Buffer.from(input),
        { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
      return input + "." + b64u(signature);
    }
  };
}

// --- which operation a console path is --------------------------------------

// The console paths a `mirrors` declaration names after one method.
function mirroredPaths(mirrors, method) {
  log.debug("Entering mirroredPaths().");
  const out = [];
  const re = new RegExp(method + " (\\/admin[^\\s,;)]*)", "g");
  let m = re.exec(String(mirrors || ""));
  while (m) {
    out.push(m[1].replace(/[.:]+$/, ""));
    m = re.exec(String(mirrors || ""));
  }
  log.debug("Leaving mirroredPaths().");
  return out;
}

// Of several operations that mirror one control, the one in the page's own
// area wins — `/admin/users`'s list is `/admin-api/users`, not the many that
// name it — which is `web_forms.ts`'s rule.
function preferOwn(rows, path) {
  log.debug("Entering preferOwn().");
  const own = "/admin-api" + path.slice("/admin".length);
  const mine = rows.filter(function (row) {
    return row.path === own || row.path.indexOf(own + "/") === 0;
  });
  log.debug("Leaving preferOwn().");
  return (mine.length ? mine : rows)[0] || null;
}

// THE CONSOLE'S RENDERERS, as a browser loads them: `admin-ui/
// console.bundle.js`, the image build's esbuild output of `web_pages.ts`,
// run in a context with no require, process or Buffer — what a browser has —
// as `tests/console_web_bundle.js` runs it. Its page table says which
// operation a page is drawn from and with what query, and `render()` draws
// it. Loaded once, the first time a job asks.
let bundle = null;
function consoleBundle() {
  log.debug("Entering consoleBundle().");
  if (!bundle) {
    const fs = require("fs");
    const path = require("path");
    const vm = require("vm");
    const file = path.join(__dirname, "..", "..", "admin-ui",
                           "console.bundle.js");
    const code = fs.readFileSync(file, "utf8");
    bundle = vm.runInContext(code + "\n;StsConsole;", vm.createContext({}),
                             { filename: "console.bundle.js" });
  }
  log.debug("Leaving consoleBundle().");
  return bundle;
}

// `base` is the service's base URL (with a realm's prefix for a realm);
// `user` is the name to sign in as. `log` is optional and says what was done.
//
// `options.grant` — "read" or "write" — GIVES the account that console role
// first (2026-09-18). A development stack with an empty roster admits anybody;
// a deployment with an administrator admits only a holder, and a job that
// reads console pages answers 403 for want of a role rather than for anything
// it tests. Opt-in, because sts_realm_administrators.js grants and confines
// roles itself. "write" grants both. The role goes to an account whose
// password only this process holds.
//
// Answers the client described at the top of this file.
async function signInToTheConsole(base, user, log2, options) {
  log.debug("Entering signInToTheConsole().");
  const say = (log2 && log2.info) ? log2.info.bind(log2) : function () {};
  const opts = options || {};
  const cookies = jar();
  const crypto = require("crypto");
  const key = dpopKey();

  function fromLocation(location) {
    return new URL(String(location || ""), base).toString();
  }

  async function fetchKeeping(url, init) {
    const sent = Object.assign({ redirect: "manual" }, init || {});
    sent.headers = Object.assign({ cookie: cookies.header() },
                                 sent.headers || {});
    const r = await fetch(url, sent);
    cookies.keep(r);
    return r;
  }

  const password = await ensureConsoleAccount(base, user, say);
  if (opts.grant === "read" || opts.grant === "write") {
    const roles = opts.grant === "write" ? ["read", "write"] : ["read"];
    for (const role of roles) {
      const r = await fetch(base + "/admin-api/rbac/grant", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, role: role })
      });
      assert.ok(r.status === 200, "granting Admin " + role + " to " + user +
        " through POST /admin-api/rbac/grant answered " + r.status + " " +
        (await r.text()).slice(0, 200));
    }
    say("[console] " + user + " holds Admin " + roles.join(" and ") + ".");
  }

  // THE SHELL FIRST, as a browser opens the console: serving it registers
  // this realm's `/admin/callback` on the seeded console client
  // (`oidcRp.ensureConsoleCallback()`), which the authorization request
  // below must name.
  // `?realm=default` past the realm chooser a bare `/admin` draws on the
  // default realm once realms exist; under a realm's prefix it is ignored.
  const shell = await fetchKeeping(base + "/admin?realm=default");
  assert.ok(shell.status === 200,
    "GET " + base + "/admin should answer the console's shell; it answered " +
    shell.status);

  // THE AUTHORIZATION REQUEST, as the console's page sends it.
  const verifier = b64u(crypto.randomBytes(32));
  const state = b64u(crypto.randomBytes(16));
  const redirectUri = base + "/admin/callback";
  const resource = base + "/admin-api";
  const authorize = base + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: "sts-admin-console",
    redirect_uri: redirectUri,
    scope: "openid admin:read admin:write admin:console",
    state: state, code_challenge: b64u(crypto.createHash("sha256")
      .update(verifier).digest()),
    code_challenge_method: "S256", resource: resource,
    // OpenID Connect's nonce, derived from the verifier as the runtime
    // derives it (`SpaClient.nonceFor()`); FAPI 1.0 requires one.
    nonce: crypto.createHash("sha256").update("nonce:" + verifier)
      .digest("base64url") }).toString();
  const toScreen = await fetchKeeping(authorize);
  const where = toScreen.headers.get("location") || "";
  const authn = (where.match(/[?&]authn=([^&]+)/) || [])[1];
  assert.ok(authn,
    "the console's authorization request should send a browser with no " +
    "sign-on session to the sign-in screen carrying the id of the request " +
    "waiting there; it answered " + toScreen.status + " to \"" + where +
    "\". The console signs in as the seeded public client " +
    "sts-admin-console, with PKCE.");

  // THE SIGN-IN SCREEN, OVER `/authn-api` (#571), through the one helper:
  // the shell, the view and the act, with this walk's cookies — and an
  // administrator's OFFERED second factor (#246) ignored there, as rcbj
  // asked ("update tests to just click ignore for the time being").
  const signedIn = await authnSignin.signIn(base, fromLocation(where),
    { action: "login", username: user, password: password },
    { cookie: cookies.header() });
  cookies.keep(signedIn);
  if (signedIn.ignored) {
    say("[console] " + user + " was offered a second factor and ignored it.");
  }
  assert.ok(signedIn.next === "redirect" && cookies.get("sts_session"),
    "signing in at /authn/login should set the sign-on session cookie and " +
    "answer where to go; it answered " + signedIn.status + " " +
    signedIn.next + " " + JSON.stringify(signedIn.errors));

  // Back through the authorization endpoint — which now has a session —
  // until it answers the callback with a code. Bounded, so a loop fails as
  // a loop; the callback is the console's page and is not fetched.
  let at = null;
  let location = signedIn.location;
  for (let i = 0; i < 5 && !/\/admin\/callback\?/.test(location) &&
       (!at || at.status === 302 || at.status === 303); i++) {
    at = await fetchKeeping(fromLocation(location));
    location = at.headers.get("location") || "";
  }
  const back = new URL(fromLocation(location));
  const code = back.searchParams.get("code");
  assert.ok(/\/admin\/callback$/.test(back.pathname) && code &&
            back.searchParams.get("state") === state,
    "the authorization endpoint should answer the console's callback with " +
    "a code and the state it was sent; it answered " +
    (at ? at.status : signedIn.status) + " to \"" +
    location + "\"");

  // THE TOKEN REQUEST, DPoP-bound, retried once with a nonce.
  const tokenUrl = base + "/oauth2/token";
  let tokenAnswer = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const r = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded",
                 dpop: key.proof("POST", tokenUrl, "") },
      body: new URLSearchParams({
        grant_type: "authorization_code", code: code,
        redirect_uri: redirectUri, client_id: "sts-admin-console",
        code_verifier: verifier, resource: resource }).toString()
    });
    key.keepNonce(r);
    tokenAnswer = { status: r.status, json: await r.json().catch(function () {
      return {};
    }) };
    if (!(r.status === 400 && tokenAnswer.json.error === "use_dpop_nonce")) {
      break;
    }
  }
  assert.ok(tokenAnswer.status === 200 && tokenAnswer.json.access_token &&
            /^dpop$/i.test(String(tokenAnswer.json.token_type || "")),
    "the console's code should redeem for a DPoP-bound access token; the " +
    "token endpoint answered " + tokenAnswer.status + " " +
    JSON.stringify(tokenAnswer.json).slice(0, 300));
  let token = tokenAnswer.json.access_token;
  let refreshToken = tokenAnswer.json.refresh_token || "";

  // THE REFRESH GRANT WITH THE SAME KEY, as the console renews: the refresh
  // token rotated, the new access token taking the old one's place.
  async function refresh() {
    log.debug("Entering refresh().");
    let answer = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const r = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded",
                   dpop: key.proof("POST", tokenUrl, "") },
        body: new URLSearchParams({
          grant_type: "refresh_token", refresh_token: refreshToken,
          client_id: "sts-admin-console", resource: resource }).toString()
      });
      key.keepNonce(r);
      answer = { status: r.status,
                 json: await r.json().catch(function () {
                   return {};
                 }) };
      if (!(r.status === 400 && answer.json.error === "use_dpop_nonce")) {
        break;
      }
    }
    if (answer.status === 200 && answer.json.access_token) {
      token = answer.json.access_token;
      refreshToken = answer.json.refresh_token || refreshToken;
    }
    log.debug("Leaving refresh().");
    return answer;
  }

  // ONE REQUEST TO THE API AS THE CONSOLE, retried once with a nonce.
  async function api(method, path, body) {
    log.debug("Entering api().");
    const url = /^https?:/.test(path) ? path : base + path;
    let answer = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const headers = { authorization: "DPoP " + token,
                        dpop: key.proof(method, url, token),
                        accept: "application/json" };
      const init = { method: method, headers: headers };
      if (body !== undefined) {
        headers["content-type"] = "application/json";
        init.body = JSON.stringify(body);
      }
      const r = await fetch(url, init);
      key.keepNonce(r);
      const text = await r.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch (e) {
        log.debug("Caught in api(): " + ((e && e.message) || e));
        // Not JSON: a document, a file; answered as its text.
        json = null;
      }
      answer = { status: r.status, json: json, text: text,
                 headers: r.headers };
      const challenge = String(r.headers.get("www-authenticate") || "");
      // AN EXPIRED TOKEN IS RENEWED AND THE REQUEST SENT AGAIN, as the
      // console does: a long job outlives the access token's lifetime.
      if (r.status === 401 && /invalid_token/.test(challenge) &&
          refreshToken && attempt === 0) {
        const renewed = await refresh();
        if (renewed.status === 200) {
          continue;
        }
      }
      if (!(r.status === 401 && /use_dpop_nonce/.test(challenge))) {
        break;
      }
    }
    log.debug("Leaving api().");
    return answer;
  }

  // BYTES AS THE BODY, as the console sends a file to an operation that
  // takes one (the risk dataset upload): the same proof, a content type of
  // the caller's.
  async function raw(method, path, bytes, contentType) {
    log.debug("Entering raw().");
    const url = /^https?:/.test(path) ? path : base + path;
    let answer = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const r = await fetch(url, { method: method, body: bytes,
        headers: { authorization: "DPoP " + token,
                   dpop: key.proof(method, url, token),
                   accept: "application/json",
                   "content-type": contentType } });
      key.keepNonce(r);
      const text = await r.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch (e) {
        log.debug("Caught in raw(): " + ((e && e.message) || e));
        // Not JSON: answered as its text.
        json = null;
      }
      answer = { status: r.status, json: json, text: text,
                 headers: r.headers };
      const challenge = String(r.headers.get("www-authenticate") || "");
      if (!(r.status === 401 && /use_dpop_nonce/.test(challenge))) {
        break;
      }
    }
    log.debug("Leaving raw().");
    return answer;
  }

  let index = null;
  async function operations() {
    log.debug("Entering operations().");
    if (!index) {
      const answer = await api("GET", "/admin-api");
      assert.ok(answer.status === 200 && answer.json &&
                Array.isArray(answer.json.operations),
        "GET /admin-api should answer the index of operations; it answered " +
        answer.status);
      index = answer.json.operations;
    }
    log.debug("Leaving operations().");
    return index;
  }

  say("[console] signed in as " + user + " as the static console: PKCE, a " +
      "DPoP-bound token for " + resource + ".");
  log.debug("Leaving signInToTheConsole().");
  return {
    user: user,
    get token() {
      return token;
    },
    get refreshToken() {
      return refreshToken;
    },
    cookie: cookies.header(),
    api: api,
    raw: raw,
    refresh: refresh,
    // The operation a console page is drawn from, asked with its query as
    // the console asks it (the page table's names and fixed members); a
    // path the table does not hold is found by what mirrors it.
    page: async function (path, query) {
      const asked = Object.assign({}, query || {});
      delete asked.format;
      const table = consoleBundle();
      const known = table.pageFor(path);
      let operation = known ? known.operation : "";
      let q = known ? table.operationQuery(path, asked) : asked;
      if (!operation) {
        const rows = (await operations()).filter(function (row) {
          return row.method === "GET" &&
                 mirroredPaths(row.mirrors, "GET").indexOf(path) >= 0;
        });
        const row = preferOwn(rows, path);
        assert.ok(row, "no /admin-api operation mirrors GET " + path);
        operation = row.path;
        q = asked;
      }
      const qs = new URLSearchParams(q).toString();
      const answer = await api("GET", operation + (qs ? "?" + qs : ""));
      // A COMBINED PAGE IS SEVERAL ANSWERS (2026-10-11): the SAML, Kerberos,
      // XACML, VC, OAuth and SSF pages draw their tabs from the `compose`
      // members their page row names, fetched beside the main operation and
      // merged in under each member's name — what the runtime's draw does.
      // Without them the renderer throws "missing a tab view".
      // Each member is asked as the runtime asks it (`composeRequests()`,
      // 2026-10-12): under the names its own operation reads, which on
      // Protocols → Cert issuance are not the page's.
      if (known && known.compose && answer.status === 200 && answer.json) {
        const members = table.composeRequests(known, asked);
        const answers = await Promise.all(members.map(function (one) {
          const search = new URLSearchParams(one.params).toString();
          return api("GET", one.operation + (search ? "?" + search : ""));
        }));
        const json = Object.assign({}, answer.json);
        answers.forEach(function (one, index) {
          assert.ok(one.status === 200 && one.json,
                    members[index].operation + " answered " +
                    one.status + " composing " + path);
          json[members[index].member] = one.json;
        });
        return Object.assign({}, answer, { json: json });
      }
      return answer;
    },
    // THE READER'S LANGUAGE FOR A BUNDLE A JOB LOADED ITSELF (#539): the
    // shell's `locale` member, asked once, built into that bundle's
    // translator and made its default, as the runtime's applyLocale() does.
    // A job that draws with its own bundle calls this once before drawing.
    localize: async function (table) {
      if (this.localeData === undefined) {
        const shell = await api("GET", "/admin-api/console");
        this.localeData = shell.json && shell.json.locale
          ? shell.json.locale : null;
      }
      if (!this.localeData || !table || !table.messages) {
        return null;
      }
      const translator =
        table.messages.WebTranslator.fromData(this.localeData);
      table.messages.WebTranslator.setDefault(function () {
        return translator;
      });
      return translator;
    },
    // The page drawn, as the console draws it for this token's reader:
    // `{ status, json, html }`, `html` empty when the operation refused.
    draw: async function (path, query) {
      const answer = await this.page(path, query);
      const table = consoleBundle();
      // DRAWN FOR WHAT THIS TOKEN MAY DO, as the console draws for its
      // reader: `GET /admin-api/me`'s `write`, asked once.
      if (this.mayWrite === undefined) {
        const me = await api("GET", "/admin-api/me");
        this.mayWrite = !!(me.json && me.json.write);
      }
      // AND IN THE READER'S LANGUAGE, as the console's runtime draws it
      // (#539): a translator built by the bundle from the shell's `locale`
      // member, asked once. Without it every message renders as its key.
      if (this.translator === undefined) {
        const shell = await api("GET", "/admin-api/console");
        this.translator = table.messages && shell.json && shell.json.locale
          ? table.messages.WebTranslator.fromData(shell.json.locale) : null;
      }
      // AND IT IS THE DEFAULT, as the runtime's applyLocale() makes it: a
      // helper the renderers call with no translator (the pager, a pane)
      // falls back to it, and without this drew keys here and English in a
      // browser. Set on every draw, because two clients share one bundle.
      if (this.translator && table.messages) {
        const translator = this.translator;
        table.messages.WebTranslator.setDefault(function () {
          return translator;
        });
      }
      const asked = Object.assign({}, query || {});
      delete asked.format;
      const html = answer.status === 200 && answer.json
        ? table.render(path, answer.json,
                       table.kit.context(asked, this.mayWrite,
                                         this.translator || undefined)) ||
          "" : "";
      return { status: answer.status, json: answer.json, html: html };
    },
    // A CONSOLE URL AS THE JOBS WROTE ONE — `/admin/scheduler?per=200`,
    // `?format=json` or not, with or without `base` — answered as a page
    // read was: `body` the operation's answer (what `?format=json` was),
    // `text` the page drawn from it.
    get: async function (url) {
      const u = new URL(String(url), base + "/");
      const prefix = new URL(base + "/").pathname.replace(/\/$/, "");
      const path = u.pathname.indexOf(prefix + "/admin") === 0
        ? u.pathname.slice(prefix.length) : u.pathname;
      const query = {};
      u.searchParams.forEach(function (value, name) {
        query[name] = value;
      });
      const drawn = await this.draw(path, query);
      return { status: drawn.status, body: drawn.json || {}, json: drawn.json,
               text: drawn.html };
    },
    // The POST operation the form at `path` with this `action` is.
    act: async function (path, fields) {
      const body = Object.assign({}, fields || {});
      const action = String(body.action || "");
      delete body.action;
      const rows = (await operations()).filter(function (row) {
        return row.method === "POST" &&
               mirroredPaths(row.mirrors, "POST").indexOf(path) >= 0;
      });
      const named = action ? rows.filter(function (row) {
        return row.path.split("/").pop() === action;
      }) : rows;
      const row = named.length > 1 ? preferOwn(named, path)
        : (named[0] || null);
      assert.ok(row, "no /admin-api operation is the console form POST " +
        path + (action ? " action=" + action : ""));
      return api("POST", row.path, body);
    }
  };
}

module.exports = { signInToTheConsole: signInToTheConsole, jar: jar,
                   ensureConsoleAccount: ensureConsoleAccount,
                   consolePasswordFor: consolePasswordFor };
