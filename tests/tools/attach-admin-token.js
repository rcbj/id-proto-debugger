// File: tools/attach-admin-token.js
//
// PRESENT THE MANAGEMENT API'S ACCESS TOKEN, IN ONE PLACE.
//
// ---------------------------------------------------------------------------
// The mock STS's `/admin-api` requires an OAuth 2.0 access token since the
// 2026-09-09 submodule bump. About fifteen jobs here configure the mock
// through it and NOT ONE OF THEM SHARES AN HTTP HELPER — `federation_sso.js`,
// `federation_chain_sso.js`, `federation_matrix_sso.js`, `federation_admin.js`
// and the rest each carry their own `adminGet`/`adminPost` pair — so making
// them all authenticate is either fifteen edits that say the same thing, or
// one place that says it once. This is that place: `run-report.js` preloads it
// into every job it spawns with `--require`, and `common/common.sh` puts it in
// `NODE_OPTIONS` for the `--*-only` modes, which run a test script directly.
//
// WHY A PRELOAD RATHER THAN A SHARED CLIENT. A shared client is the right
// answer for a suite being written today; adopting one across fifteen files
// that each have their own conventions is a large change with no test behind
// it, and every one of those files would be touched for a reason that has
// nothing to do with what it asserts. This leaves the jobs about what they
// test, and there is exactly one thing to read to know how they authenticate.
//
// IT IS DELIBERATELY NARROW. It attaches the token to `/admin-api` and nothing
// else, and it NEVER replaces an Authorization header a job set itself —
// several jobs authenticate as somebody on purpose (the SCIM schemes, a token
// the job has just minted), and a shim that overwrote those would silently
// rewrite the thing under test. A job that wants to drive `/admin-api`
// unauthenticated — to assert the refusal — sends `Authorization: none`, which
// this leaves alone and the service reads as a malformed credential.
//
// NO STS_ADMIN_API_TOKEN MEANS NO SHIM AT ALL. That is the case where the mock
// is not gated (`adminApi.authRequired` off) or where no mock is in the run,
// and the jobs then behave exactly as they did before this file existed.
//
// It is loaded by `--require`, so it runs at the top of every job's process:
// there is no function here to enter or leave and the logging convention has
// nothing to attach to. The two interceptors below are on the HOT PATH of
// every HTTP call a job makes and deliberately log nothing — a debug line per
// request in a suite of two hundred jobs is the whole log.
// ---------------------------------------------------------------------------
'use strict';

const TOKEN = process.env.STS_ADMIN_API_TOKEN || "";

if (TOKEN) {
  const http = require("http");
  const https = require("https");

  // `/admin-api` in any trust realm: the mock leaves the `/realm/<id>` prefix
  // on the URL a client sends, and the federation jobs configure realms
  // through exactly that shape, so both have to match.
  const WANTED = /^(?:\/realm\/[^/]+)?\/admin-api(?:\/|$|\?)/;

  const wants = function (pathname) {
    return WANTED.test(String(pathname || ""));
  };

  const hasAuth = function (headers) {
    if (!headers) {
      return false;
    }
    if (typeof headers.get === "function") {
      return !!headers.get("authorization");
    }
    return Object.keys(headers).some(function (one) {
      return one.toLowerCase() === "authorization";
    });
  };

  // ---- global fetch, which is what every one of those jobs uses -----------
  if (typeof globalThis.fetch === "function") {
    const realFetch = globalThis.fetch;
    globalThis.fetch = function (input, init) {
      const url = typeof input === "string" ? input
            : (input && input.url) || String(input);
      let where = "";
      try {
        const parsed = new URL(url);
        where = parsed.pathname + (parsed.search || "");
      } catch (e) {
        where = String(url);
      }
      if (!wants(where)) {
        return realFetch.apply(this, arguments);
      }
      const options = Object.assign({}, init || {});
      const headers = Object.assign({}, (options.headers || {}));
      if (!hasAuth(init && init.headers) && !hasAuth(headers) &&
          !(typeof input === "object" && input && hasAuth(input.headers))) {
        headers.authorization = "Bearer " + TOKEN;
      }
      options.headers = headers;
      return realFetch.call(this, input, options);
    };
  }

  // ---- http/https.request, for a job that builds its own ------------------
  // Nothing here drives `/admin-api` that way today. It is covered anyway
  // because the failure it would produce is a 401 on a perfectly good
  // credential, three files from anything that mentions a token.
  [http, https].forEach(function (mod) {
    const real = mod.request;
    mod.request = function (first, second) {
      let options = null;
      if (typeof first === "string" || first instanceof URL) {
        options = (second && typeof second === "object") ? second : null;
      } else if (first && typeof first === "object") {
        options = first;
      }
      let where = "";
      if (typeof first === "string") {
        try {
          where = new URL(first).pathname;
        } catch (e) {
          where = first;
        }
      } else if (first instanceof URL) {
        where = first.pathname;
      } else if (options) {
        where = options.path || "";
      }
      if (options && wants(where) && !hasAuth(options.headers)) {
        options.headers = Object.assign({}, options.headers || {},
                                        { authorization: "Bearer " + TOKEN });
      }
      return real.apply(this, arguments);
    };
  });
}
