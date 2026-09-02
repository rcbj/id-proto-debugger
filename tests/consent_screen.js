// File: consent_screen.js
//
// ---------------------------------------------------------------------------
// PASS THE MOCK STS'S CONSENT SCREEN. One implementation, shared by every job
// in this suite that signs a person in to that service and then expects an
// OAuth 2.0 or OpenID Connect authorization response.
//
// WHY THIS EXISTS
//
// Since 2026-09-01 the mock's authorization endpoint asks before it issues. The
// FIRST time a given username signs in to a given `client_id` for a given
// scope, `/oauth2/consent` is drawn and nothing is issued until somebody
// presses Allow — `oauth2.consentRequired`, which is ON by default and is the
// one policy in that service that is. Every flow in this suite therefore has
// one more hop in it than it had the day before, and the hop is in the middle
// of a redirect chain that most of these jobs walk by hand.
//
// It is a MODULE rather than fifteen copies of the same four lines for the
// reason `sts_applications.js` is: fifteen copies is fifteen chances to write
// the wait wrong, and a job that got it wrong would fail with "no code in the
// redirect" — a sentence that names the token endpoint for a problem that is a
// button nobody pressed.
//
// ---------------------------------------------------------------------------
// TWO SURFACES, BECAUSE THIS SUITE DRIVES THAT SERVICE TWO WAYS.
//
//   * `settleAuthorization()` — for the jobs that follow redirects THEMSELVES
//     with `redirect: "manual"`. It walks the hops that stay on the mock's own
//     origin (the authorization endpoint, the consent screen) and hands back
//     the first one that leaves — which is the client's `redirect_uri`, the
//     thing those jobs were reading before this screen existed.
//
//   * `passInBrowser()` — for the Selenium jobs. It looks for the Allow button,
//     presses it if it is there, and returns quietly if it is not.
//
// **NEITHER OF THEM ASSERTS THAT THE SCREEN APPEARED**, and that is deliberate
// rather than lax. A scope under `oauthGlobalConsent`, a username that has
// consented before in the same run, and `oauth2.consentRequired` turned off are
// all states in which the screen correctly does not appear — and a helper that
// insisted on it would make every job here also a test of the consent feature,
// failing in fifteen places for one reason. What tests the screen itself is
// `sts/tests/vendored/sts_consent.js`, which asserts it appears, asserts what
// is on it, and asserts what happens when it is refused.
//
// **THEY DEFAULT TO ALLOW.** A job that wants the refusal asks for it
// explicitly, because Deny ends the flow with `access_denied` and every caller
// here is in the middle of something it expects to finish.
// ---------------------------------------------------------------------------

"use strict";

const bunyan = require("bunyan");

const log = bunyan.createLogger({ name: "consent_screen",
                                  level: process.env.LOG_LEVEL || "info" });

// The path the mock registers the screen at. Matched on the PATH and not on the
// whole URL, because a job may be driving a trust realm — `/realm/acme/oauth2/consent`
// is the same screen — and because the location may be relative or absolute
// depending on which hop produced it.
const CONSENT_PATH = /\/oauth2\/consent(\?|$)/;

// And the authorization endpoint, which is where the screen sends the browser
// back to. `settleAuthorization()` has to follow that hop as well: the answer to
// Allow is a 303 to the authorization request, and the authorization RESPONSE
// is one hop further on.
const AUTHORIZE_PATH = /\/oauth2\/authorize(\?|$)/;

function isConsentScreen(url) {
  return CONSENT_PATH.test(String(url || ""));
}

function isAuthorizeEndpoint(url) {
  return AUTHORIZE_PATH.test(String(url || ""));
}

// A Location that may be relative, made absolute against the service it came
// from. The mock answers relative Locations for its own pages and absolute ones
// for a client's redirect_uri, which is exactly the distinction these jobs care
// about — so this is careful not to turn the second into the first.
function absolute(base, location) {
  const target = String(location || "");
  if (/^https?:\/\//i.test(target)) {
    return target;
  }
  return String(base || "").replace(/\/+$/, "") + target;
}

// Is this URL still on the service we are driving? Only same-origin hops are
// followed, so a client redirect_uri that happens to contain the word `consent`
// is never mistaken for the screen.
function sameOrigin(base, location) {
  let here, there;
  try {
    here = new URL(String(base));
    there = new URL(absolute(base, location));
  } catch (e) {
    // An unparseable URL is not this module's problem to report — the job that
    // is about to fetch it will say so far better. What matters is that it is
    // not treated as a match.
    log.debug("Leaving sameOrigin(). Unparseable: " + e.message);
    return false;
  }
  return here.origin === there.origin;
}

// The `consent_id` on the screen, or "". Read out of the markup rather than off
// the query string, because the FORM is what the answer is posted with and a
// test that posted the query parameter would be asserting its own reading of
// the page rather than the page.
function consentIdOf(html) {
  return (String(html || "").match(/name="consent_id" value="([^"]+)"/) || [])[1] || "";
}

// ---------------------------------------------------------------------------
// THE HTTP SURFACE.
//
// `opts.base`      the mock's origin, e.g. https://localhost:8081
// `opts.location`  the Location the last hop answered with
// `opts.cookie`    the session cookie, which the screen will not answer without
// `opts.decision`  "allow" (default) or "deny"
// `opts.headers`   anything else the job sends on every request
//
// Returns `{ location, cookie, screens, page }` — the first Location that
// leaves this service, the cookie (unchanged; the screen sets none), how many
// consent screens were answered, and the last screen's markup for a caller that
// wants to look at it.
//
// IT LOOPS RATHER THAN HANDLING ONE SCREEN, and the loop is bounded. One
// authorization request draws at most one screen today, but the shape that
// makes that true — every scope outstanding is asked about at once — is the
// service's and not this file's, and a helper that silently stopped after the
// first would fail as "no code in the redirect" if that ever changed. Six hops
// is far past anything correct and is a bound rather than a limit.
// ---------------------------------------------------------------------------
async function settleAuthorization(opts) {
  log.debug("Entering settleAuthorization().");
  const options = opts || {};
  const base = String(options.base || "");
  const cookie = String(options.cookie || "");
  const decision = options.decision === "deny" ? "deny" : "allow";
  const headers = Object.assign({}, options.headers || {});
  if (cookie) {
    headers.cookie = cookie;
  }
  let location = String(options.location || "");
  let screens = 0;
  let page = "";

  for (let hop = 0; hop < 6; hop++) {
    if (!location || !sameOrigin(base, location)) {
      break;
    }
    if (isConsentScreen(location)) {
      const shown = await fetch(absolute(base, location),
                               { redirect: "manual", headers: headers });
      page = await shown.text();
      const id = consentIdOf(page);
      if (!id) {
        // The screen refused to draw — an expired record, or a session that
        // belongs to somebody else. Handing the caller the status is more use
        // than throwing here: the job knows what it was expecting.
        log.debug("Leaving settleAuthorization(). The consent screen carried no " +
                  "consent_id; status " + shown.status + ".");
        return { location: location, cookie: cookie, screens: screens,
                 page: page, status: shown.status, blocked: true };
      }
      const answered = await fetch(absolute(base, "/oauth2/consent"), {
        method: "POST", redirect: "manual",
        headers: Object.assign({ "Content-Type": "application/x-www-form-urlencoded" },
                               headers),
        body: new URLSearchParams({ consent_id: id, action: decision }).toString()
      });
      screens++;
      location = answered.headers.get("location") || "";
      continue;
    }
    if (isAuthorizeEndpoint(location) && screens > 0) {
      // Back at the authorization request, which is where Allow sends the
      // browser. Only followed AFTER a screen has been answered: an authorize
      // URL that arrives without one is the caller's own next step and
      // following it here would take a hop the job meant to take itself.
      const back = await fetch(absolute(base, location),
                               { redirect: "manual", headers: headers });
      location = back.headers.get("location") || "";
      if (!location) {
        log.debug("Leaving settleAuthorization(). The authorization endpoint " +
                  "answered " + back.status + " rather than redirecting.");
        return { location: "", cookie: cookie, screens: screens, page: page,
                 status: back.status, blocked: true };
      }
      continue;
    }
    break;
  }
  log.debug("Leaving settleAuthorization(). " + screens + " screen(s) answered.");
  return { location: location, cookie: cookie, screens: screens, page: page,
           blocked: false };
}

// THE PATHS THAT MEAN "STILL SOMEWHERE ON THE IDENTITY SERVICE".
//
// `passInBrowser()` is called after every sign-in in this suite, and on most of
// those calls there is no screen to press — so what decides its cost is how
// fast it can tell "not yet" from "never". A URL outside this set is the
// application's own page, which means the flow finished without being asked and
// the answer is known immediately; a URL inside it is a hop still in flight and
// is worth waiting on.
//
// It is deliberately GENEROUS. A federated sign-in goes out through
// /federation, comes back through an ACS and only then meets the consent
// screen, and a set that named only /oauth2 would give up in the middle of that
// and report no screen where there was one — which is a failure two steps
// later, in the job, with nothing pointing here.
const STILL_AT_THE_IDENTITY_SERVICE =
  /\/(oauth2|authn|federation|wsfed|saml2|saml11|spnego|realm)\b/;

// ---------------------------------------------------------------------------
// THE BROWSER SURFACE.
//
// `driver` and `By` are PASSED IN rather than required here, so that a job with
// no browser in it can require this module without dragging selenium-webdriver
// into a process that has no use for it.
//
// It waits a SHORT time and then gives up quietly. That is the whole design: on
// most calls the screen is not there — the scope is globally consented, or this
// person has answered before — and a long wait per call would add minutes to a
// suite in order to confirm a page's absence. Two seconds is far longer than a
// same-origin redirect on a loopback bridge and far shorter than anything a
// person would notice.
// ---------------------------------------------------------------------------
async function passInBrowser(driver, By, opts) {
  log.debug("Entering passInBrowser().");
  const options = opts || {};
  const decision = options.decision === "deny" ? "deny" : "allow";
  const id = decision === "deny" ? "consent-deny" : "consent-allow";
  const deadline = Date.now() + (options.timeoutMs || 4000);
  for (;;) {
    let url = "";
    try {
      url = await driver.getCurrentUrl();
    } catch (e) {
      // A navigation in flight makes this throw rather than answer. Retried
      // below like any other unhelpful answer; the deadline ends this loop, not
      // the first stumble.
      log.debug("passInBrowser(): " + e.message);
    }
    if (url && !STILL_AT_THE_IDENTITY_SERVICE.test(url)) {
      // THE BROWSER HAS ALREADY LANDED SOMEWHERE ELSE, which is what a flow
      // that was never asked looks like — a scope already agreed to, one under
      // a global consent, or `oauth2.consentRequired` off. Returning here
      // rather than waiting out the deadline is what keeps the cost of calling
      // this after every sign-in negligible.
      log.debug("Leaving passInBrowser(). Already past the identity service.");
      return false;
    }
    let found = [];
    try {
      found = await driver.findElements(By.id(id));
    } catch (e) {
      log.debug("passInBrowser(): " + e.message);
      found = [];
    }
    if (found.length) {
      await found[0].click();
      log.debug("Leaving passInBrowser(). Pressed " + id + ".");
      return true;
    }
    if (Date.now() >= deadline) {
      log.debug("Leaving passInBrowser(). No consent screen appeared within " +
                "the window, which is the ordinary case for a scope already " +
                "agreed to or globally consented.");
      return false;
    }
    await driver.sleep(100);
  }
}

module.exports = {
  isConsentScreen: isConsentScreen,
  isAuthorizeEndpoint: isAuthorizeEndpoint,
  consentIdOf: consentIdOf,
  settleAuthorization: settleAuthorization,
  passInBrowser: passInBrowser
};
