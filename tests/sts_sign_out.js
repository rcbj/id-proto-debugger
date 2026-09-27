// File: sts_sign_out.js
//
// ---------------------------------------------------------------------------
// SIGN THE BROWSER OUT OF THE MOCK STS, for the Selenium jobs that need the
// next authorization request to meet a login form rather than a live session.
//
// WHY THIS EXISTS
//
// Those jobs used to `driver.get(STS + "/oauth2/logout")` and carry on. Since
// the mock implemented OpenID Connect RP-Initiated Logout 1.0 whole (iya-sts
// #124, with #115), a GET that carries no id_token_hint for THIS session is
// not obeyed on the spot: section 2 says the OP SHOULD ask the End-User
// whether to sign out, and the mock does — it draws a "Sign out?" page whose
// form POSTs back with `confirm=yes` and a `confirm_for` value only that page
// carries. Nobody pressed it, the session lived on, and the next
// authorization request went straight past the login form. What the jobs
// then reported was a timeout waiting for `#username` — a sentence about the
// sign-in page for a problem that is a button on the sign-out one.
//
// It presses the button when the page asks and returns quietly when it does
// not (no session, or a mock from before #124), exactly as consent_screen.js
// does for the consent screen, and for the same reason: whether the question
// is asked is the mock's business and is asserted by the mock's own tests.
// ---------------------------------------------------------------------------

"use strict";

const bunyan = require("bunyan");

const log = bunyan.createLogger({ name: "sts_sign_out",
                                  level: process.env.LOG_LEVEL || "info" });

// The confirmation button, by what it submits rather than by its label.
const CONFIRM = "form button[name='confirm'][value='yes']";

// `sts` is the mock's base URL (its origin, or a trust realm's base); `By`
// and `until` are the caller's selenium-webdriver exports, passed in so this
// module needs no selenium of its own. Resolves true when a confirmation was
// pressed and false when none was asked for.
async function signOutInBrowser(driver, sts, By, until, timeoutMs) {
  log.debug("Entering signOutInBrowser().");
  const wait = timeoutMs || 8000;
  await driver.get(String(sts).replace(/\/+$/, "") + "/oauth2/logout");
  const buttons = await driver.findElements(By.css(CONFIRM));
  if (!buttons.length) {
    log.debug("Leaving signOutInBrowser(). Not asked.");
    return false;
  }
  await buttons[0].click();
  // The answer is a page saying it is done (or a front-channel page on the
  // way there); what matters is that the question is gone.
  await driver.wait(until.stalenessOf(buttons[0]), wait,
    "pressed Sign out on the mock's RP-Initiated Logout confirmation, and " +
    "the page never moved on");
  log.debug("Leaving signOutInBrowser(). Confirmed.");
  return true;
}

module.exports = { signOutInBrowser };
