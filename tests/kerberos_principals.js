// File: kerberos_principals.js
// ---------------------------------------------------------------------------
// WHAT THE KERBEROS JOBS ASKED `GET /krb5/principals` FOR, ASKED OF WHERE IT
// LIVES NOW.
//
// iya-sts published its KDC's principal table, its realm, its KDC port and its
// account policy on an open demonstration page, `/krb5/principals`. #595
// deleted that page: the table and the account policy are
// `GET /admin-api/kerberos/principals` (paged, under the management API's
// token, which tools/attach-admin-token.js puts on every job's /admin-api
// calls), and the KDC port and the two shared development passwords are
// SETTINGS (`krb5.kdcPort`, `krb5.userPassword`, `krb5.autoServicePassword`),
// read from `GET /admin-api/config`.
//
// Five jobs read that document and each reads a handful of its members, so
// this rebuilds the members they read — `realm`, `kdcPort`, `principals`,
// `accountPolicy` (with the two passwords back in it), `realmsServed` and
// `serviceAccount` — rather than each job learning two endpoints and a paging
// loop. It answers in the shape of a fetch Response (`ok`, `status`,
// `json()`), so a job's call site changes one line and its checks none.
//
// A SHARED MODULE AND NOT A JOB, so tests/Dockerfile carries a COPY line for
// it like random_username.js's.
// ---------------------------------------------------------------------------

"use strict";

var bunyan = require("bunyan");
var level = "info";
try {
  level = require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
} catch (e) {
  level = "info";
}
var log = bunyan.createLogger({ name: "kerberos_principals", level: level });

// The most rows one page may carry (iya-sts's MAX_ROWS ceiling clamps a
// larger ask anyway); the loop below reads every page.
var PER = 500;

async function getJson(url) {
  log.debug("Entering getJson(). " + url);
  var response = await fetch(url, { headers: { Accept: "application/json" } });
  var body = null;
  try {
    body = await response.json();
  } catch (e) {
    log.debug("Caught in getJson(): " + e.message);
    body = null;
  }
  log.debug("Leaving getJson(). " + response.status);
  return { status: response.status, ok: response.ok, body: body };
}

// One setting's value off GET /admin-api/config, whose rows are under
// groups[].settings.
//
// A MASKED SETTING IS ABSENT, NOT ITS MASK. Since iya-sts v1.0.0 the secret
// settings — krb5.servicePassword, krb5.userPassword,
// krb5.autoServicePassword, krb5.krbtgtPassword — answer
// `"value":"********","masked":true`. Taken at face value that is a password
// of eight asterisks, and a ticket "opened" with it simply never opens, which
// is how kerberos_spnego_page.js failed on the bump. So a masked row reads as
// undefined, and principalsDocument() below supplies the value another way.
function settingOf(config, key) {
  log.debug("Entering settingOf(). " + key);
  var found;
  ((config && config.groups) || []).forEach(function (group) {
    (group.settings || []).forEach(function (row) {
      if (row.key === key && found === undefined && !row.masked) {
        found = row.value !== undefined ? row.value : row.text;
      }
    });
  });
  log.debug("Leaving settingOf().");
  return found;
}

// The three Kerberos passwords these jobs need, which iya-sts no longer
// publishes (masked, above). Each comes from the job's environment when the
// launcher or a person set one — which is what a run against a deployment with
// its own secrets has to do — and otherwise from iya-sts's SHIPPED DEFAULTS
// (its env/defaults.js), which is what every stack this repository starts
// runs with: none of them overrides these.
var SHIPPED_KRB5_PASSWORDS = {
  "krb5.servicePassword": { env: "KRB5_SERVICE_PASSWORD",
                            dflt: "service-account-password" },
  "krb5.userPassword": { env: "KRB5_USER_PASSWORD", dflt: "password!" },
  "krb5.autoServicePassword": { env: "KRB5_AUTO_SERVICE_PASSWORD",
                                dflt: "auto-service-password" }
};

function passwordSetting(config, key) {
  log.debug("Entering passwordSetting(). " + key);
  var published = settingOf(config, key);
  if (published !== undefined) {
    log.debug("Leaving passwordSetting(). Published.");
    return published;
  }
  var known = SHIPPED_KRB5_PASSWORDS[key];
  var fromEnv = known && process.env[known.env];
  if (fromEnv) {
    log.debug("Leaving passwordSetting(). From " + known.env + ".");
    return fromEnv;
  }
  log.info(key + " is masked by iya-sts, so this job uses its shipped " +
           "default; set " + (known ? known.env : "it") + " if the service " +
           "was started with another.");
  log.debug("Leaving passwordSetting(). Shipped default.");
  return known ? known.dflt : undefined;
}

// The document, as a fetch-shaped answer.
async function principalsDocument(stsUrl) {
  log.debug("Entering principalsDocument().");
  var base = String(stsUrl).replace(/\/+$/, "") + "/admin-api";
  var first = await getJson(base + "/kerberos/principals?per=" + PER);
  if (!first.ok || !first.body) {
    log.debug("Leaving principalsDocument(). " + first.status);
    return { ok: false, status: first.status,
      json: async function () {
        return first.body;
      } };
  }
  var view = first.body;
  var rows = (view.database || []).slice();
  var pages = Number((view.databasePaging || {}).pages || 1);
  for (var page = 2; page <= pages; page++) {
    var more = await getJson(base + "/kerberos/principals?per=" + PER +
                             "&databasePage=" + page);
    rows = rows.concat((more.body && more.body.database) || []);
  }
  var config = (await getJson(base + "/config")).body || {};
  var policy = Object.assign({}, view.accountPolicy || {});
  policy.userPassword = passwordSetting(config, "krb5.userPassword");
  policy.autoServicePassword = passwordSetting(config,
      "krb5.autoServicePassword");
  var doc = {
    realm: view.realm,
    kdcPort: Number(settingOf(config, "krb5.kdcPort") || 88),
    principals: rows,
    accountPolicy: policy,
    realmsServed: view.realmsServed || [],
    serviceAccount: view.acceptor || null,
    // The sign-in door's acceptor account (`/authn/spnego`), keyed from these
    // settings unless an operator stored a random key over it.
    serviceAccountSettings: {
      principal: settingOf(config, "krb5.servicePrincipal"),
      password: passwordSetting(config, "krb5.servicePassword"),
      salt: settingOf(config, "krb5.serviceSalt")
    },
    kerberos: view.kerberos || null
  };
  log.debug("Leaving principalsDocument(). " + rows.length + " principals.");
  return { ok: true, status: 200,
    json: async function () {
      return doc;
    } };
}

// WHAT iya-sts's SPNEGO SIGN-IN DOOR SAYS, read off the page it answers.
// Since iya-sts #575 (2026-10-12) `/authn/spnego`'s bodies are the sign-in
// surface's shell, drawn in the browser from the state the response carries
// in `data-sts-state` on `<html>` — `{ view: { door, kind, username,
// principal, session, subject, flags, amr, acr, ... } }`, `kind`
// `signed-in` / `challenge` / `off`. The text "Signed in as ..." is drawn by
// the runtime and is not in the bytes. So a client that runs no script — a
// job reading the body — reads the state. Accepts the HTML, or text
// containing it. Answers the `view`, or null when there is none.
function spnegoDoorView(html) {
  log.debug("Entering spnegoDoorView().");
  const found = /data-sts-state="([^"]*)"/.exec(String(html || ""));
  if (!found) {
    log.debug("Leaving spnegoDoorView(). No state.");
    return null;
  }
  const text = found[1].replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  let state = null;
  try {
    state = JSON.parse(text);
  } catch (e) {
    log.debug("Leaving spnegoDoorView(). Not JSON: " + e.message);
    return null;
  }
  log.debug("Leaving spnegoDoorView().");
  return (state && state.view) || null;
}

module.exports = { principalsDocument: principalsDocument,
                   spnegoDoorView: spnegoDoorView };
