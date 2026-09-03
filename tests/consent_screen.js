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
//   * `passAllInBrowser()` — the same thing until there are no more screens.
//     A FEDERATED sign-in meets two of them (the far realm's and the near
//     realm's) and a caller that cannot know which it is should use this one.
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

// AND THE PATHS THAT ARE A HOP RATHER THAN A DESTINATION.
//
// A narrower set, used only to decide whether the short window below may be
// extended. Every one of these is somewhere a browser passes THROUGH in the
// middle of an authorization leg and never a page a finished flow rests on:
// the authorization endpoint, the consent screen itself, and the two ends of a
// federated hop — /federation/login on the way out and /federation/acs on the
// way back, where the near realm redeems what the far realm issued before it
// draws its own screen.
//
// /federation/acs IS THE ONE THAT WAS MISSING, and its absence is what took
// the OIDC/OIDC/password point of the grid on 2026-09-03T08-01-08. A federated
// sign-in draws TWO consent screens — the far realm asks whether the near realm
// may act for this person, then the near realm asks whether the application may
// — and between them the browser waits at /federation/acs while the near realm
// redeems the code over a back channel. Past the four-second window that URL
// was not recognised as mid-leg, so passInBrowser() returned false,
// passAllInBrowser() stopped, and the near realm's screen was left standing.
// It fails 100 seconds later in collectOauthArtifacts() as "the flow never came
// back to the debugger", with that unanswered screen's own words quoted in it.
const MID_AUTHORIZATION_LEG =
  /\/(oauth2\/(authorize|consent)|federation\/(acs|login))\b/;

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
  // The cap on the extension below. Generous against the four-second window it
  // extends, because what it is waiting out is a whole authorization leg, and
  // bounded because a caller that is wrong about a screen coming must still
  // return rather than hang.
  const hardDeadline = Date.now() + (options.maxMs || 30000);
  // THE MOVEMENT SIGNAL. `lastUrl` is what the browser said last time round
  // this loop and `movedDeadline` is how long a change buys — one more window,
  // renewed by the next change. A chain that is still redirecting therefore
  // keeps its extension, and a page the flow has come to rest on loses it a
  // window after it arrived.
  let lastUrl = null;
  let movedDeadline = 0;
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
    if (url && url !== lastUrl) {
      // The chain moved. Noted before anything below reads it, so that the
      // extension at the bottom sees this pass's hop rather than the last.
      lastUrl = url;
      movedDeadline = Date.now() + (options.timeoutMs || 4000);
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
      try {
        await found[0].click();
        log.debug("Leaving passInBrowser(). Pressed " + id + ".");
        return true;
      } catch (e) {
        // FOUND AND THEN GONE, which is a hop in flight rather than a fault.
        // `findElements()` and the click are two round trips, and the redirect
        // chain this screen sits in the middle of can land between them — so
        // the reference is stale by the time it is pressed
        // (`StaleElementReferenceError`), and where the far realm's screen is
        // being replaced by the near realm's, the button that arrives is a
        // different one anyway. Retried on the next pass of this loop rather
        // than reported: the deadline below still ends it, and a screen that
        // is really there is found again in a tenth of a second.
        log.debug("passInBrowser(): " + e.message);
      }
    }
    if (Date.now() >= deadline) {
      // THE WINDOW IS EXTENDED WHILE THE FLOW IS DEMONSTRABLY STILL RUNNING,
      // and without that this gives up on a screen that is on its way.
      //
      // Returning false here means "no screen is coming", and the four-second
      // window is sized for that ordinary case — a scope already agreed to
      // draws nothing and the caller should not pay for asking. But a FEDERATED
      // sign-in draws two screens with a whole authorization leg between them:
      // press the far realm's Allow, and the browser goes back through the near
      // realm's authorize endpoint, completes the federated leg and only then
      // draws the near realm's screen. On a pool of four browsers, straight
      // after a WebAuthn ceremony, that chain takes longer than four seconds —
      // so passAllInBrowser() saw `false`, stopped, and left the second screen
      // standing. What that failure says, four functions later, is "the flow
      // never came back to the debugger", with the unanswered screen's own
      // words quoted in it. It took the OAuth2/OIDC/WebAuthn point of the grid
      // on 2026-09-03T07-28-00.
      //
      // The distinction that makes this safe is that the browser itself says
      // which case it is, and it says it TWO WAYS — neither of which covers the
      // chain alone.
      //
      // THE URL: one of MID_AUTHORIZATION_LEG's paths is a hop and never a
      // destination, so sitting on one is the flow demonstrably mid-leg.
      //
      // MOVEMENT: a URL that has changed since the last look is a redirect
      // chain still walking, wherever it happens to be at this instant. That
      // covers a hop this file has not thought of — and it expires, so a page
      // the flow has come to REST on stops extending anything one window after
      // it arrived, which is what keeps the ordinary "no screen is coming"
      // answer as cheap as it was.
      //
      // Both are capped by the hard deadline, so a service that is genuinely
      // stuck still ends this loop rather than hanging the job.
      const stillWorking = MID_AUTHORIZATION_LEG.test(url) ||
          Date.now() < movedDeadline;
      if (stillWorking && Date.now() < hardDeadline) {
        log.debug("passInBrowser(): past the window but still at " + url +
                  "; the flow is mid-leg, so waiting on.");
        await driver.sleep(100);
        continue;
      }
      log.debug("Leaving passInBrowser(). No consent screen appeared within " +
                "the window, which is the ordinary case for a scope already " +
                "agreed to or globally consented.");
      return false;
    }
    await driver.sleep(100);
  }
}

// ---------------------------------------------------------------------------
// EVERY SCREEN ON THE WAY OUT, rather than the first one.
//
// One authorization request draws at most one screen, and a FEDERATED sign-in
// is two authorization requests: the far realm asks whether the near realm may
// act for this person, and then the near realm asks whether the application
// may. Both are answered by a browser walking one redirect chain, so a caller
// that pressed Allow once and moved on is left sitting on the second screen —
// which is how this failed before, reported four functions later as "the flow
// never came back to the application".
//
// A caller that cannot know how many screens are coming should use this one.
// It costs nothing extra in the ordinary case: pressing the last Allow puts the
// browser on the application's own origin, which `passInBrowser()` recognises
// and returns from at once.
//
// Returns how many screens were answered. The bound is a bound and not a
// limit — four is far past anything correct, and stopping there is better than
// a loop that a service answering its own consent screen with another one
// could spin in for ever.
// ---------------------------------------------------------------------------
async function passAllInBrowser(driver, By, opts) {
  log.debug("Entering passAllInBrowser().");
  const options = opts || {};
  const bound = options.bound || 4;
  let screens = 0;
  while (screens < bound) {
    const pressed = await passInBrowser(driver, By, options);
    if (!pressed) {
      log.debug("Leaving passAllInBrowser(). " + screens + " screen(s) " +
                "answered.");
      return screens;
    }
    screens++;
  }
  log.debug("Leaving passAllInBrowser(). Stopped at the bound of " + bound +
            " screen(s).");
  return screens;
}

module.exports = {
  isConsentScreen: isConsentScreen,
  isAuthorizeEndpoint: isAuthorizeEndpoint,
  consentIdOf: consentIdOf,
  settleAuthorization: settleAuthorization,
  passInBrowser: passInBrowser,
  passAllInBrowser: passAllInBrowser
};
