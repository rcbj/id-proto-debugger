// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

"use strict";
//
// File: authn_signin.js
//
// ===========================================================================
// SIGNING IN AT THE SIGN-IN SCREEN, OVER `/authn-api`, AS ITS PAGE DOES
// (#571, 2026-10-12).
//
// **THIS IS A HELPER AND NOT A JOB.** Every job that signs somebody in at
// `/authn/login` without a browser signs in through it, so the screen's
// protocol is written down once, the way `console_signin.js` writes the
// console's. BROUGHT BACK FROM iya-sts (2026-10-22, rcbj's decision): written in
// that repository's tests/vendored/ while this suite still drove the old
// form-based screens, and copied here under this repository's licence once
// the sts/ submodule was bumped past them..
//
// ---------------------------------------------------------------------------
// WHAT CHANGED AT #571, AND SO WHAT THIS DOES.
//
// The screen was a form: `GET /authn/login?authn=<id>` drew it with a hidden
// `authn_id` and `csrf_token`, and `POST /authn/login` answered a 303 back
// to the caller, or a page — the screen again, a second factor's, the
// forced password change's. Since #571 the screen is a static surface:
//
//   GET  /authn/login?authn=<id>               the shell; it mints the
//                                              sts_session arrival cookie
//                                              where the browser has none
//   GET  /authn-api/pending/<id>               { view, csrf }
//   POST /authn-api/pending/<id>/<operation>   JSON, Origin, X-CSRF-Token
//        -> { ok, next: 'redirect' | 'mfa' | 'password-change' |
//             'home-cell', location, step, id, form }
//        -> { ok: false, next: 'refused', errors }
//
// So this does what the page does: the shell (for its cookie), the view
// (for the token), and the act, with the cookies kept between them.
//
// ---------------------------------------------------------------------------
// WHAT IT ANSWERS: `submit()` takes the FORM's fields as the jobs wrote them
// before — `action` (`login`, `cancel`, `anonymous`, `email-code`,
// `email-link`, `passkey`), `username`, `password`, `use_webauthn`,
// `webauthn_only`, `remember_browser`, `device_fp`, `passkey_credential` —
// and answers:
//
//   { status, json, next, location, step, id, errors, view, csrf,
//     cookie, setCookies, headers }
//
// `location` ABSOLUTE (on the base's origin) for `redirect`, `mfa` and
// `password-change`; `cookie` the request's cookie header with every
// cookie both requests set folded in; `headers` a `get()`/`getSetCookie()`
// pair over the same, so a job's own jar `keep()`s the answer as it kept a
// fetch response. A job follows `location` with a GET, as a browser follows
// the 303 the form was answered with.
//
// ---------------------------------------------------------------------------
// AND THE STEPS AFTER THE SCREEN (#572, #573): the second-factor pages and
// the emailed factor's are pages of the same surface, each drawn from
//
//   GET  /authn-api/mfa/<id>?page=<page>        { view, csrf }
//   POST /authn-api/mfa/<id>/<operation>        JSON, Origin, X-CSRF-Token
//
// `step()` opens one at the address an answer named (the shell, then the
// view), `stepAct()` sends one of its acts, and `passkeyStep()` runs a
// passkey ceremony with the job's own authenticator. `ignoreOffer()`
// presses the offered set-up step's Ignore over the API.
//
// AND THE OAUTH CONSENT SCREEN (#576), a page of the same surface since
// then: `consentPage()`, `answerConsent()` and `consentWithJar()`, below.
// ===========================================================================

const log = require("bunyan").createLogger({ name: "authn_signin",
  level: process.env.LOG_LEVEL || "info" });

/**
 * The pending sign-in's id in a screen address, or the id itself.
 *
 * @param {string} where - `/authn/login?authn=…`, an absolute URL, or an id
 * @returns {string} the id
 */
function pendingIdOf(where) {
  log.debug("Entering pendingIdOf().");
  const text = String(where || "");
  const m = text.match(/[?&](?:authn|change)=([^&#]+)/);
  log.debug("Leaving pendingIdOf().");
  return m ? decodeURIComponent(m[1]) : text;
}

/**
 * A cookie header with set-cookie lines folded in; an emptied value
 * removes the cookie, as a browser does.
 *
 * @param {string} header - the cookie header so far
 * @param {string[]} setCookies - `Set-Cookie` lines
 * @returns {string} the cookie header
 */
function foldCookies(header, setCookies) {
  log.debug("Entering foldCookies().");
  const held = {};
  const order = [];
  String(header || "").split(/;\s*/).forEach(function (pair) {
    const at = pair.indexOf("=");
    if (at > 0) {
      const name = pair.slice(0, at).trim();
      if (!(name in held)) {
        order.push(name);
      }
      held[name] = pair.slice(at + 1);
    }
  });
  (setCookies || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const name = pair.slice(0, at).trim();
    const value = pair.slice(at + 1);
    if (value === "") {
      delete held[name];
      return;
    }
    if (!(name in held)) {
      order.push(name);
    }
    held[name] = value;
  });
  log.debug("Leaving foldCookies().");
  return order.filter(function (name) {
    return name in held;
  }).map(function (name) {
    return name + "=" + held[name];
  }).join("; ");
}

/**
 * The set-cookie lines of a fetch response.
 *
 * @param {object} res - the response
 * @returns {string[]} the lines
 */
function setCookiesOf(res) {
  log.debug("Entering setCookiesOf().");
  log.debug("Leaving setCookiesOf().");
  return res.headers.getSetCookie ? res.headers.getSetCookie() : [];
}

/**
 * The service's base without a trailing slash, and its origin.
 *
 * @param {string} base - the base URL, a realm's prefix included
 * @returns {{base: string, origin: string}} both
 */
function baseOf(base) {
  log.debug("Entering baseOf().");
  const b = String(base || "").replace(/\/+$/, "");
  log.debug("Leaving baseOf().");
  return { base: b, origin: new URL(b).origin };
}

/**
 * Opens the screen as the page does: the shell (for the arrival cookie a
 * browser without one is given) and the view (for the CSRF token).
 *
 * @param {string} base - the service's base, a realm's prefix included
 * @param {string} where - the screen's address or the pending id
 * @param {object} [options] - `cookie`, the request's cookie header;
 *   `headers`, sent on every request; `page`, `select-idp` or
 *   `password-change` for those pages' views
 * @returns {Promise<object>} `{ status, json, view, csrf, cookie,
 *   setCookies, shellStatus }`
 */
async function screen(base, where, options) {
  log.debug("Entering screen().");
  const opts = options || {};
  const b = baseOf(base);
  const id = pendingIdOf(where);
  const page = opts.page || "login";
  const shellPath = page === "password-change"
    ? "/authn/password-change?change=" : (page === "select-idp"
      ? "/authn/select-idp?authn=" : "/authn/login?authn=");
  let cookie = String(opts.cookie || "");
  const setCookies = [];
  const extra = opts.headers || {};
  const shell = await fetch(b.base + shellPath + encodeURIComponent(id),
    { redirect: "manual", headers: Object.assign({}, extra,
                                                 cookie ? { cookie: cookie }
                                                        : {}) });
  setCookiesOf(shell).forEach(function (one) {
    setCookies.push(one);
  });
  cookie = foldCookies(cookie, setCookies);
  await shell.text();
  const viewPath = page === "password-change"
    ? "/authn-api/password-change/" + encodeURIComponent(id)
    : "/authn-api/pending/" + encodeURIComponent(id) +
      (page === "select-idp" ? "/partners" : "");
  const res = await fetch(b.base + viewPath, {
    headers: Object.assign({ accept: "application/json" }, extra,
                           cookie ? { cookie: cookie } : {}) });
  setCookiesOf(res).forEach(function (one) {
    setCookies.push(one);
  });
  cookie = foldCookies(cookie, setCookiesOf(res));
  const json = await res.json().catch(function (e) {
    log.debug("Caught in screen(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the status.
    return null;
  });
  log.debug("Leaving screen(). " + res.status);
  return { status: res.status, shellStatus: shell.status, json: json,
           view: json && json.view, csrf: (json && json.csrf) || "",
           cookie: cookie, setCookies: setCookies, id: id };
}

/**
 * Sends one act to the sign-in API, bound as the page binds it.
 *
 * @param {string} base - the service's base
 * @param {string} path - the operation's path under the base, its id
 *   filled (`/authn-api/pending/<id>/password`)
 * @param {object} body - the act's JSON
 * @param {object} options - `cookie`, `csrf`, `headers`; `origin` and
 *   `contentType` to send something else (a refusal test)
 * @returns {Promise<object>} the answer, as `submit()` describes it
 */
async function act(base, path, body, options) {
  // The id is a bearer capability: not logged.
  log.debug("Entering act(). " +
            String(path).replace(/\/(pending|password-change|mfa|consent)\/[^/]+/,
                                 "/$1/(id)"));
  const opts = options || {};
  const b = baseOf(base);
  const headers = Object.assign({}, opts.headers || {},
    { accept: "application/json",
      "content-type": opts.contentType || "application/json" });
  if (opts.origin !== null) {
    headers.origin = opts.origin || b.origin;
  }
  if (opts.csrf) {
    headers["x-csrf-token"] = opts.csrf;
  }
  if (opts.cookie) {
    headers.cookie = opts.cookie;
  }
  const res = await fetch(b.base + path, { method: "POST",
    redirect: "manual", headers: headers,
    body: typeof body === "string" ? body : JSON.stringify(body || {}) });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in act(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the status and the text.
    json = null;
  }
  const answer = answerOf(b, res, json, text, opts.cookie,
                          opts.setCookies || []);
  log.debug("Leaving act(). " + res.status + " " + answer.next);
  return answer;
}

/**
 * The answer a job reads, from an act's response.
 *
 * @param {object} b - `baseOf()`'s answer
 * @param {object} res - the fetch response
 * @param {object|null} json - its JSON
 * @param {string} text - its text
 * @param {string} cookie - the cookie header the act was sent with
 * @param {string[]} earlier - set-cookie lines of the requests before it
 * @returns {object} the answer
 */
function answerOf(b, res, json, text, cookie, earlier) {
  log.debug("Entering answerOf().");
  const own = setCookiesOf(res);
  const all = (earlier || []).concat(own);
  const j = json || {};
  const location = j.location
    ? new URL(String(j.location), b.origin).toString() : "";
  log.debug("Leaving answerOf().");
  return {
    status: res.status, json: json, text: text,
    ok: !!j.ok, next: String(j.next || (json ? "" : "not-json")),
    location: location, step: j.step || "", id: j.id || "",
    form: j.form || null, errors: j.errors || [],
    cookie: foldCookies(cookie, own), setCookies: all,
    headers: {
      get: function (name) {
        const n = String(name).toLowerCase();
        if (n === "location") {
          return location || null;
        }
        if (n === "set-cookie") {
          return all.length ? all.join(", ") : null;
        }
        return res.headers.get(name);
      },
      getSetCookie: function () {
        return all.slice();
      }
    }
  };
}

// The operation each of the form's buttons is, and the body it takes.
const OPERATIONS = {
  login: "password", cancel: "cancel", anonymous: "anonymous",
  "email-code": "email", "email-link": "email", passkey: "passkey"
};

/**
 * The JSON body of an act, from the form's fields as a job wrote them.
 *
 * @param {string} action - the button
 * @param {object} fields - the form's fields
 * @returns {object} the body
 */
function bodyFor(action, fields) {
  log.debug("Entering bodyFor(). " + action);
  const f = fields || {};
  const flag = function (v) {
    return ["1", "true", "on", "yes", true].indexOf(v) >= 0 ? "1"
                                                            : undefined;
  };
  let out = {};
  if (action === "login") {
    out = { username: f.username, password: f.password,
            use_webauthn: flag(f.use_webauthn),
            webauthn_only: flag(f.webauthn_only),
            remember_browser: flag(f.remember_browser),
            device_fp: f.device_fp || undefined };
  } else if (action === "anonymous") {
    out = { remember_browser: flag(f.remember_browser),
            device_fp: f.device_fp || undefined };
  } else if (action === "email-code" || action === "email-link") {
    out = { username: f.username,
            kind: action === "email-link" ? "link" : "code",
            remember_browser: flag(f.remember_browser),
            device_fp: f.device_fp || undefined };
  } else if (action === "passkey") {
    out = { credential: f.passkey_credential || f.credential,
            remember_browser: flag(f.remember_browser),
            device_fp: f.device_fp || undefined };
  }
  Object.keys(out).forEach(function (k) {
    if (out[k] === undefined) {
      delete out[k];
    }
  });
  log.debug("Leaving bodyFor().");
  return out;
}

/**
 * Submits the sign-in screen as its page does: opens it (shell and view),
 * then sends the act the form's `action` is.
 *
 * @param {string} base - the service's base, a realm's prefix included
 * @param {string} where - the screen's address, or the pending id
 * @param {object} fields - the form's fields, `action` among them
 *   (`login` where left out)
 * @param {object} [options] - `cookie`; `headers`, sent on every request
 *   (a User-Agent); `screen`, a `screen()` answer already in hand
 * @returns {Promise<object>} the answer, with the view it was sent from
 */
async function submit(base, where, fields, options) {
  log.debug("Entering submit().");
  const opts = options || {};
  const action = String((fields && fields.action) || "login");
  const opened = opts.screen || await screen(base, where,
                                             { cookie: opts.cookie,
                                               headers: opts.headers });
  if (!opened.view) {
    log.debug("Leaving submit(). No view: " + opened.status);
    return Object.assign({ status: opened.status, json: opened.json,
      ok: false, next: "no-view", location: "", errors:
        (opened.json && opened.json.errors) || [], view: null, csrf: "",
      cookie: opened.cookie, setCookies: opened.setCookies,
      headers: {
        get: function () {
          return null;
        },
        getSetCookie: function () {
          return opened.setCookies;
        }
      }
    });
  }
  const op = OPERATIONS[action];
  if (!op) {
    throw new Error("authn_signin: the sign-in screen has no button " +
                    action);
  }
  const answer = await act(base, "/authn-api/pending/" +
    encodeURIComponent(opened.id) + "/" + op, bodyFor(action, fields),
    { cookie: opened.cookie, csrf: opened.csrf,
      setCookies: opened.setCookies, headers: opts.headers });
  answer.view = opened.view;
  answer.csrf = opened.csrf;
  log.debug("Leaving submit(). " + answer.next);
  return answer;
}

/**
 * Arms a passkey ceremony with no username on a pending sign-in.
 *
 * @param {string} base - the service's base
 * @param {object} opened - a `screen()` answer
 * @returns {Promise<object>} `{ status, json }`: `challenge`, `rpId`,
 *   `options`
 */
async function passkeyOptions(base, opened) {
  log.debug("Entering passkeyOptions().");
  const answer = await act(base, "/authn-api/pending/" +
    encodeURIComponent(opened.id) + "/passkey/options", {},
    { cookie: opened.cookie, csrf: opened.csrf });
  log.debug("Leaving passkeyOptions().");
  return answer;
}

/**
 * Changes the password a sign-in is waiting on, as the forced change's
 * page does.
 *
 * @param {string} base - the service's base
 * @param {string} where - the page's address or the step's id
 * @param {object} fields - `new_password`, `confirm_password`
 * @param {object} [options] - `cookie`
 * @returns {Promise<object>} the answer
 */
async function changePassword(base, where, fields, options) {
  log.debug("Entering changePassword().");
  const opts = options || {};
  const opened = await screen(base, where, { cookie: opts.cookie,
                                             page: "password-change" });
  const answer = await act(base, "/authn-api/password-change/" +
    encodeURIComponent(opened.id), {
      new_password: fields.new_password,
      confirm_password: fields.confirm_password },
    { cookie: opened.cookie, csrf: opened.csrf,
      setCookies: opened.setCookies });
  answer.view = opened.view;
  log.debug("Leaving changePassword(). " + answer.next);
  return answer;
}

/**
 * Signs in and, where an administrator is OFFERED a second factor (#246's
 * `requireSecondFactorForAdministrators: offer`), presses that step's
 * Ignore button, as every job that only wants the person signed in on a
 * password has done since rcbj's "just click ignore". The step's page is
 * still server-drawn (#572), so it is fetched and posted as a form.
 *
 * @param {string} base - the service's base
 * @param {string} where - the screen's address or the pending id
 * @param {object} fields - the form's fields
 * @param {object} [options] - `cookie`
 * @returns {Promise<object>} the sign-in's answer, or — after an ignored
 *   offer — `{ status, next: 'redirect', location, cookie, setCookies,
 *   headers, ignored: true }` from the set-up step's 303
 */
async function signIn(base, where, fields, options) {
  log.debug("Entering signIn().");
  const opts = options || {};
  const answer = await submit(base, where, fields, opts);
  const out = await ignoreOffer(base, answer);
  log.debug("Leaving signIn(). " + out.next);
  return out;
}

// THE STEPS AFTER THE SCREEN (#572, #573): each page's path, and the name
// `GET /authn-api/mfa/{id}?page=` gives it.
const STEP_PAGES = {
  "/authn/totp": "totp", "/authn/webauthn": "webauthn",
  "/authn/backup-code": "backup-code", "/authn/password-factor": "password",
  "/authn/mfa-setup": "setup", "/authn/email-code": "email-code",
  "/authn/email-link": "email-link",
  "/authn/email-link/open": "email-link-open"
};

/**
 * Opens a step's page as the sign-in surface does (#572, #573): the shell
 * (for the arrival cookie) and `GET /authn-api/mfa/{id}?page=`.
 *
 * @param {string} where - the step's address, absolute (an answer's
 *   `location`, or a mailed link)
 * @param {object} [options] - `cookie`; `headers`; `page`, another page of
 *   the same step
 * @returns {Promise<object>} `{ status, json, view, csrf, cookie,
 *   setCookies, id, page, t, base }`
 */
async function step(where, options) {
  log.debug("Entering step().");
  const opts = options || {};
  const url = new URL(String(where));
  const path = Object.keys(STEP_PAGES).sort(function (x, y) {
    return y.length - x.length;
  }).filter(function (one) {
    return url.pathname.endsWith(one);
  })[0] || "";
  const base = url.origin + url.pathname.slice(0, url.pathname.length -
                                                path.length);
  const id = url.searchParams.get("mfa") || "";
  const key = url.searchParams.get("key") || "";
  const page = opts.page || STEP_PAGES[path] || "totp";
  let cookie = String(opts.cookie || "");
  const setCookies = [];
  const extra = opts.headers || {};
  const shell = await fetch(url.toString(), { redirect: "manual",
    headers: Object.assign({}, extra, cookie ? { cookie: cookie } : {}) });
  setCookiesOf(shell).forEach(function (one) {
    setCookies.push(one);
  });
  cookie = foldCookies(cookie, setCookies);
  await shell.text();
  const res = await fetch(base + "/authn-api/mfa/" + encodeURIComponent(id) +
    "?page=" + page + (key ? "&key=" + encodeURIComponent(key) : ""), {
      headers: Object.assign({ accept: "application/json" }, extra,
                             cookie ? { cookie: cookie } : {}) });
  setCookiesOf(res).forEach(function (one) {
    setCookies.push(one);
  });
  cookie = foldCookies(cookie, setCookiesOf(res));
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in step(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the status.
    json = null;
  }
  log.debug("Leaving step(). " + res.status);
  return { status: res.status, shellStatus: shell.status, json: json,
           text: text, view: json && json.view,
           csrf: (json && json.csrf) || "", cookie: cookie,
           setCookies: setCookies, id: id, page: page, key: key,
           t: url.searchParams.get("t") || "", base: base };
}

/**
 * Sends one of a step's acts, bound as its page binds it.
 *
 * @param {object} opened - a `step()` answer
 * @param {string} op - `totp`, `backup-code`, `password`,
 *   `webauthn/options`, `webauthn`, `setup/totp`, `setup/confirm`,
 *   `setup/webauthn`, `skip`, `email/send`, `email/code`,
 *   `email-link/open`
 * @param {object} body - the act's JSON
 * @param {object} [options] - `headers`; `cookie` (the step's where left
 *   out); `origin`, `contentType`, `csrf` to send something else
 * @returns {Promise<object>} the answer, as `act()`'s
 */
async function stepAct(opened, op, body, options) {
  log.debug("Entering stepAct(). " + op);
  const opts = options || {};
  const answer = await act(opened.base, "/authn-api/mfa/" +
    encodeURIComponent(opened.id) + "/" + op, body || {},
    { cookie: opts.cookie || opened.cookie,
      csrf: opts.csrf === undefined ? opened.csrf : opts.csrf,
      origin: opts.origin, contentType: opts.contentType,
      setCookies: opened.setCookies, headers: opts.headers });
  log.debug("Leaving stepAct(). " + answer.status + " " + answer.next);
  return answer;
}

/**
 * A step's passkey ceremony with the job's own authenticator: arms it
 * (`webauthn/options`), hands the options to `make` — which answers the
 * credential's JSON form, or a promise of it — and sends the result.
 *
 * @param {object} opened - the passkey page, a `step()` answer
 * @param {Function} make - `(ceremony) => credential`: `ceremony` is
 *   `{ mode, challenge, rpId, user, allow, exclude, options }`
 * @param {object} [options] - `key`, a chosen passkey (#534); `headers`
 * @returns {Promise<object>} the answer, `armed` beside it
 */
async function passkeyStep(opened, make, options) {
  log.debug("Entering passkeyStep().");
  const opts = options || {};
  const armed = await stepAct(opened, "webauthn/options",
                              opts.key ? { key: opts.key } : {}, opts);
  if (!armed.json || !armed.json.ok) {
    log.debug("Leaving passkeyStep(). Not armed.");
    armed.armed = armed;
    return armed;
  }
  const credential = await make(armed.json);
  const answer = await stepAct(opened, "webauthn",
    { credential: typeof credential === "string" ? credential
                                                 : JSON.stringify(credential) },
    Object.assign({}, opts, { cookie: armed.cookie }));
  answer.armed = armed;
  log.debug("Leaving passkeyStep(). " + answer.next);
  return answer;
}

/**
 * Where an answer is an administrator's OFFERED second factor (#246's
 * `requireSecondFactorForAdministrators: offer`), presses its Ignore button
 * over the API (#572) — any other answer as it is, and a REQUIRED set-up
 * step's answer with the step's view beside it (`opened`). For a walk that
 * reaches the offer after another step (the forced password change).
 *
 * @param {string} base - the service's base (unused since #572: the
 *   answer's address names it)
 * @param {object} answer - an act's answer
 * @returns {Promise<object>} the Ignore's answer, `ignored: true`
 */
async function ignoreOffer(base, answer) {
  log.debug("Entering ignoreOffer().");
  void base;
  if (!(answer.next === "mfa" && answer.step === "enrol")) {
    log.debug("Leaving ignoreOffer(). " + answer.next);
    return answer;
  }
  const opened = await step(answer.location, { cookie: answer.cookie });
  if (!(opened.view && opened.view.setup && opened.view.setup.optional)) {
    log.debug("Leaving ignoreOffer(). A required set-up step.");
    answer.opened = opened;
    answer.text = opened.text;
    return answer;
  }
  const ignored = await stepAct(opened, "skip", {});
  ignored.setCookies = (answer.setCookies || []).concat(
    ignored.setCookies || []);
  ignored.ignored = true;
  ignored.view = answer.view;
  ignored.csrf = answer.csrf;
  log.debug("Leaving ignoreOffer(). The offer was ignored.");
  return ignored;
}

/**
 * An answer read the way a job read the form's response: an answer naming
 * where to go (`redirect`, `mfa`, `password-change`) as the 303 the form was
 * answered with — the browser follows both with a GET — and anything else
 * at its own status, its body the JSON's text. For a job whose flow reads
 * `status` and `headers.get("location")` and goes on; what it asserts
 * about the SCREEN it asserts on the answer itself.
 *
 * @param {object} answer - `submit()`'s, `signIn()`'s or `act()`'s answer
 * @returns {object} `{ status, headers, text(), json(), answer }`
 */
function responseLike(answer) {
  log.debug("Entering responseLike(). " + answer.next);
  const goes = !!answer.location && ["redirect", "mfa", "password-change"]
    .indexOf(answer.next) >= 0;
  const body = typeof answer.text === "string" ? answer.text
                                               : JSON.stringify(answer.json);
  log.debug("Leaving responseLike().");
  return {
    status: goes ? 303 : answer.status,
    headers: answer.headers,
    answer: answer,
    text: async function () {
      return body;
    },
    json: async function () {
      return JSON.parse(body);
    }
  };
}

/**
 * Signs in for a job whose browser keeps its cookies in a PLAIN OBJECT,
 * name to value (most jobs' own `browser()`): the jar's cookies are sent,
 * every cookie the walk sets is written back into it (an emptied one
 * removed), and the answer comes back in the shape such a browser's `go()`
 * answered — `{ status, location, text }` — read as the form's 303 where
 * the act names where to go (`responseLike()`'s reading), with the API's
 * `answer` beside it for what a job asserts about the screen.
 *
 * @param {string} base - the service's base, a realm's prefix included
 * @param {string} where - the screen's address or the pending id
 * @param {object} fields - the form's fields, `action` among them
 * @param {object} jar - the cookie jar, name to value; written in place
 * @param {object} [options] - `ignoreOffer`: ignore an administrator's
 *   offered second factor (`signIn()`); `headers`
 * @returns {Promise<object>} `{ status, location, text, answer }`
 */
async function signInWithJar(base, where, fields, jar, options) {
  log.debug("Entering signInWithJar().");
  const opts = options || {};
  const cookie = Object.keys(jar).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ");
  const run = opts.ignoreOffer ? signIn : submit;
  const answer = await run(base, where, fields,
                           { cookie: cookie, headers: opts.headers });
  (answer.setCookies || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const value = pair.slice(at + 1);
    if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(line))) {
      delete jar[pair.slice(0, at)];
    } else {
      jar[pair.slice(0, at)] = value;
    }
  });
  const like = responseLike(answer);
  log.debug("Leaving signInWithJar(). " + answer.next);
  return { status: like.status, location: answer.location || "",
           text: typeof answer.text === "string" ? answer.text
                                                 : JSON.stringify(answer.json),
           answer: answer };
}

/**
 * An answer read as the form's POST was answered, for a job with a
 * browser of its own: `redirect` as the 303 it was, `{ status: 303,
 * location }`; a next step on a page of its own (`mfa`,
 * `password-change`) as that page — fetched with the job's own `go(method,
 * url)`, as a browser fetches it after the 303 — which is the page the form's
 * POST used to answer with; anything else at its status, its body the
 * JSON's text. The job keeps the answer's cookies first
 * (`answer.headers.getSetCookie()`).
 *
 * @param {object} answer - `submit()`'s, `signIn()`'s or `act()`'s answer
 * @param {Function} go - the job's `go(method, url)`, answering
 *   `{ status, location, text }`
 * @returns {Promise<object>} `{ status, location, text, answer }`
 */
async function asFormAnswer(answer, go) {
  log.debug("Entering asFormAnswer(). " + answer.next);
  if (answer.next === "redirect" && answer.location) {
    log.debug("Leaving asFormAnswer(). A redirect.");
    return { status: 303, location: answer.location, text: "",
             answer: answer };
  }
  if ((answer.next === "mfa" || answer.next === "password-change") &&
      answer.location) {
    // A STEP'S PAGE IS A PAGE OF THE SIGN-IN SURFACE (#572, #573): its
    // shell is fetched with the job's `go()` (its cookies kept), and what
    // the page shows is its view, beside it as `step`.
    const page = await go("GET", answer.location);
    if (answer.next === "mfa") {
      const opened = await step(answer.location, { cookie: answer.cookie });
      log.debug("Leaving asFormAnswer(). The step's view.");
      return Object.assign({}, page, { answer: answer, step: opened,
                                       text: opened.text });
    }
    log.debug("Leaving asFormAnswer(). The step's page.");
    return Object.assign({}, page, { answer: answer });
  }
  log.debug("Leaving asFormAnswer(). " + answer.status);
  return { status: answer.status, location: "",
           text: typeof answer.text === "string" ? answer.text
                                                 : JSON.stringify(answer.json),
           answer: answer };
}

// ===========================================================================
// AND THE SIGN-OUT (#577): `/logout` is a static page whose view and act
// are on this API and bound the same way —
//
//   GET  /logout[?username=]              the shell (an arrival cookie for a
//                                         browser holding none)
//   GET  /authn-api/logout[?username=]    { view, csrf }
//   POST /authn-api/logout                JSON, Origin, X-CSRF-Token
//        -> { ok, next: 'signed-out', view }    nothing to fan out
//        -> { ok, next: 'signed-out', form }    the signed-out document,
//           which the page posts as a navigation: POST /logout/signed-out
//
// `signOut()` walks it as the page does and answers the last response —
// the signed-out document's HTML where the act answered its form, the
// act's JSON otherwise — with every cookie the walk set folded in.
// ===========================================================================
/**
 * Signs out at `/logout` as its page does.
 *
 * @param {string} base - the service's base, a realm's prefix included
 * @param {object} fields - the old form's: `scope`, `select` (one or
 *   several), `username`
 * @param {object} [options] - `cookie`, the request's cookie header;
 *   `headers`, sent on every request
 * @returns {Promise<object>} `{ status, text, json, view, csrf, act,
 *   document, cookie, setCookies, headers }` — `document` true where the
 *   answer is the signed-out document
 */
async function signOut(base, fields, options) {
  log.debug("Entering signOut().");
  const opts = options || {};
  const f = fields || {};
  const b = baseOf(base);
  const extra = opts.headers || {};
  const q = f.username ? "?username=" + encodeURIComponent(f.username) : "";
  let cookie = String(opts.cookie || "");
  const setCookies = [];
  const keep = function (res) {
    log.debug("Entering keep().");
    setCookiesOf(res).forEach(function (one) {
      setCookies.push(one);
    });
    cookie = foldCookies(cookie, setCookiesOf(res));
    log.debug("Leaving keep().");
  };
  const shell = await fetch(b.base + "/logout" + q, { redirect: "manual",
    headers: Object.assign({}, extra, cookie ? { cookie: cookie } : {}) });
  keep(shell);
  await shell.text();
  const seen = await fetch(b.base + "/authn-api/logout" + q, {
    headers: Object.assign({ accept: "application/json" }, extra,
                           cookie ? { cookie: cookie } : {}) });
  keep(seen);
  const seenText = await seen.text();
  let json = null;
  try {
    json = JSON.parse(seenText);
  } catch (e) {
    log.debug("Caught in signOut(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the status and the text.
    json = null;
  }
  const headersOf = function (res) {
    log.debug("Entering headersOf().");
    log.debug("Leaving headersOf().");
    return {
      get: function (name) {
        return String(name).toLowerCase() === "set-cookie"
          ? (setCookies.length ? setCookies.join(", ") : null)
          : res.headers.get(name);
      },
      getSetCookie: function () {
        return setCookies.slice();
      }
    };
  };
  if (seen.status !== 200 || !json) {
    log.debug("Leaving signOut(). The view: " + seen.status);
    return { status: seen.status, text: seenText, json: json,
             view: json && json.view, csrf: "", act: null, document: false,
             cookie: cookie, setCookies: setCookies,
             headers: headersOf(seen) };
  }
  const body = {};
  if (f.scope) {
    body.scope = f.scope;
  }
  if (f.select !== undefined) {
    body.select = [].concat(f.select);
  }
  if (f.username) {
    body.username = f.username;
  }
  const answer = await act(base, "/authn-api/logout", body,
    { cookie: cookie, csrf: json.csrf, headers: extra });
  answer.setCookies.forEach(function (one) {
    setCookies.push(one);
  });
  cookie = answer.cookie;
  const j = answer.json || {};
  if (j.ok && j.form) {
    const doc = await fetch(b.origin + String(j.form.action), {
      method: String(j.form.method || "POST"), redirect: "manual",
      headers: Object.assign({}, extra, {
        "content-type": "application/x-www-form-urlencoded",
        origin: b.origin }, cookie ? { cookie: cookie } : {}),
      body: new URLSearchParams(j.form.fields || {}).toString() });
    keep(doc);
    const text = await doc.text();
    log.debug("Leaving signOut(). The signed-out document: " + doc.status);
    return { status: doc.status, text: text, json: null, view: json.view,
             csrf: json.csrf, act: answer, document: true, cookie: cookie,
             setCookies: setCookies, headers: headersOf(doc) };
  }
  log.debug("Leaving signOut(). The act: " + answer.status);
  return { status: answer.status, text: answer.text, json: answer.json,
           view: json.view, csrf: json.csrf, act: answer, document: false,
           cookie: cookie, setCookies: setCookies,
           headers: answer.headers };
}

// ---------------------------------------------------------------------------
// THE OAUTH CONSENT SCREEN (#576): a page of the same surface.
//
//   GET  /oauth2/consent?consent=<id>       the shell (400 where the three
//                                           checks refuse, as before)
//   GET  /authn-api/consent/<id>            { view, csrf }
//   POST /authn-api/consent/<id>            JSON, Origin, X-CSRF-Token:
//        { action: 'allow' | 'deny', lim_t0r<n>_<member>: … }
//        -> { ok, next: 'redirect', location }   back to the request
//        -> { ok: false, next: 'refused', errors }
//
// `consentPage()` opens it as its page does and `answerConsent()` answers
// it; `consentFor()` does both with a cookie header, and `consentWithJar()`
// does both for a job whose browser keeps its
// cookies in a plain object, answered in that browser's shape — a 303 to
// the authorization request, as the form was answered.
// ---------------------------------------------------------------------------

/**
 * Whether an address is the consent screen's.
 *
 * @param {string} where - an address, absolute or a path
 * @returns {boolean} whether it is
 */
function isConsent(where) {
  log.debug("Entering isConsent().");
  log.debug("Leaving isConsent().");
  return /\/oauth2\/consent\?(?:[^#]*&)?consent=/.test(String(where || ""));
}

/**
 * Opens the consent screen as its page does: the shell, then the view.
 *
 * @param {string} where - the screen's address, absolute (the
 *   authorization endpoint's Location, resolved)
 * @param {object} [options] - `cookie`; `headers`, sent on every request
 * @returns {Promise<object>} `{ status, shellStatus, shellText, json, text,
 *   view, csrf, cookie, setCookies, id, base }`
 */
async function consentPage(where, options) {
  log.debug("Entering consentPage().");
  const opts = options || {};
  const url = new URL(String(where));
  const base = url.origin + url.pathname.replace(/\/oauth2\/consent$/, "");
  const id = url.searchParams.get("consent") || "";
  let cookie = String(opts.cookie || "");
  const setCookies = [];
  const extra = opts.headers || {};
  const shell = await fetch(url.toString(), { redirect: "manual",
    headers: Object.assign({}, extra, cookie ? { cookie: cookie } : {}) });
  setCookiesOf(shell).forEach(function (one) {
    setCookies.push(one);
  });
  cookie = foldCookies(cookie, setCookies);
  const shellText = await shell.text();
  const res = await fetch(base + "/authn-api/consent/" +
    encodeURIComponent(id), { headers: Object.assign(
      { accept: "application/json" }, extra,
      cookie ? { cookie: cookie } : {}) });
  setCookiesOf(res).forEach(function (one) {
    setCookies.push(one);
  });
  cookie = foldCookies(cookie, setCookiesOf(res));
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in consentPage(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the status.
    json = null;
  }
  log.debug("Leaving consentPage(). " + shell.status + " " + res.status);
  return { status: res.status, shellStatus: shell.status,
           shellText: shellText, json: json, text: text,
           view: json && json.view, csrf: (json && json.csrf) || "",
           cookie: cookie, setCookies: setCookies, id: id, base: base };
}

/**
 * Answers the consent screen as its page does: Allow (the default) or
 * Deny, with any limit lowered.
 *
 * @param {object} opened - a `consentPage()` answer
 * @param {string} [decision] - `allow` or `deny`
 * @param {object} [options] - `limits`, the controls' values by name
 *   (`lim_t0r0_amount`); `headers`; `origin`, `contentType`, `csrf` to
 *   send something else
 * @returns {Promise<object>} the answer, as `act()`'s, `opened` beside it
 */
async function answerConsent(opened, decision, options) {
  log.debug("Entering answerConsent(). " + (decision || "allow"));
  const opts = options || {};
  const answer = await act(opened.base, "/authn-api/consent/" +
    encodeURIComponent(opened.id), Object.assign({}, opts.limits || {},
      { action: decision === "deny" ? "deny" : "allow" }),
    { cookie: opened.cookie,
      csrf: opts.csrf === undefined ? opened.csrf : opts.csrf,
      origin: opts.origin, contentType: opts.contentType,
      setCookies: opened.setCookies, headers: opts.headers });
  answer.opened = opened;
  answer.view = opened.view;
  log.debug("Leaving answerConsent(). " + answer.status + " " + answer.next);
  return answer;
}

/**
 * Opens and answers the consent screen in one, with a cookie header: the
 * answer is `answerConsent()`'s — `headers` a `get()`/`getSetCookie()`
 * pair a job's own jar `take()`s, `responseLike()` reading it as the 303
 * the form was answered with — or, where the page drew no view (an expired
 * consent, another person's session), `next: 'no-view'` at the status the
 * page answered.
 *
 * @param {string} where - the screen's address, absolute
 * @param {string} cookie - the cookie header the browser sends there
 * @param {object} [options] - `decision`; `limits`; `headers`
 * @returns {Promise<object>} the answer
 */
async function consentFor(where, cookie, options) {
  log.debug("Entering consentFor().");
  const opts = options || {};
  const opened = await consentPage(where, { cookie: cookie,
                                            headers: opts.headers });
  if (!opened.view) {
    log.debug("Leaving consentFor(). No view: " + opened.status);
    const shown = opened.shellStatus === 200;
    return { status: shown ? opened.status : opened.shellStatus,
      json: opened.json, text: shown ? opened.text : opened.shellText,
      ok: false, next: "no-view", location: "", errors:
        (opened.json && opened.json.errors) || [], view: null,
      cookie: opened.cookie, setCookies: opened.setCookies, opened: opened,
      headers: {
        get: function () {
          return null;
        },
        getSetCookie: function () {
          return opened.setCookies.slice();
        }
      } };
  }
  const answer = await answerConsent(opened, opts.decision, opts);
  log.debug("Leaving consentFor(). " + answer.next);
  return answer;
}

/**
 * Opens and answers the consent screen in one, for a job with a browser
 * of its own: its jar's cookies are sent (a plain object, name to value,
 * written back in place) and the answer comes back as the form's was — a
 * 303 to the authorization request (`{ status, location, text }`), or the
 * refusal at its own status — with the API's `answer` and the page's view
 * beside it.
 *
 * @param {string} where - the screen's address, absolute
 * @param {string} [decision] - `allow` or `deny`
 * @param {object} jar - the cookie jar, name to value; written in place
 * @param {object} [options] - `limits`; `headers`
 * @returns {Promise<object>} `{ status, location, text, answer, opened }`
 */
async function consentWithJar(where, decision, jar, options) {
  log.debug("Entering consentWithJar().");
  const opts = options || {};
  const cookie = Object.keys(jar).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ");
  const opened = await consentPage(where, { cookie: cookie,
                                            headers: opts.headers });
  if (!opened.view) {
    log.debug("Leaving consentWithJar(). No view: " + opened.status);
    return { status: opened.shellStatus === 200 ? opened.status
                                                : opened.shellStatus,
             location: "", text: opened.shellStatus === 200 ? opened.text
                                                            : opened.shellText,
             answer: null, opened: opened };
  }
  const answer = await answerConsent(opened, decision, opts);
  (answer.setCookies || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const value = pair.slice(at + 1);
    if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(line))) {
      delete jar[pair.slice(0, at)];
    } else {
      jar[pair.slice(0, at)] = value;
    }
  });
  const goes = answer.next === "redirect" && !!answer.location;
  log.debug("Leaving consentWithJar(). " + answer.next);
  return { status: goes ? 303 : answer.status,
           location: goes ? answer.location : "",
           text: typeof answer.text === "string" ? answer.text
                                                 : JSON.stringify(answer.json),
           answer: answer, opened: opened };
}

module.exports = {
  signOut: signOut,
  isConsent: isConsent,
  consentPage: consentPage,
  answerConsent: answerConsent,
  consentFor: consentFor,
  consentWithJar: consentWithJar,
  pendingIdOf: pendingIdOf,
  foldCookies: foldCookies,
  screen: screen,
  act: act,
  submit: submit,
  signIn: signIn,
  ignoreOffer: ignoreOffer,
  responseLike: responseLike,
  asFormAnswer: asFormAnswer,
  signInWithJar: signInWithJar,
  passkeyOptions: passkeyOptions,
  changePassword: changePassword,
  STEP_PAGES: STEP_PAGES,
  step: step,
  stepAct: stepAct,
  passkeyStep: passkeyStep,
  bodyFor: bodyFor
};
