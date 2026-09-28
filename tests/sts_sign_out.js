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
  // THE CLICK IS RETRIED ON A STALE REFERENCE. The page this lands on can be
  // replaced between finding the button and pressing it, and the press then
  // fails with "Node with given id does not belong to the document" — which
  // is what took webauthn_oidc_mfa's password-only section out twice on
  // 2026-09-28. On a stale reference the button is looked for again: present,
  // it is pressed; gone, the page has already moved on, and there is no
  // question left to answer.
  const deadline = Date.now() + wait;
  let pressed = null;
  for (;;) {
    const buttons = await driver.findElements(By.css(CONFIRM));
    if (!buttons.length) {
      log.debug("Leaving signOutInBrowser(). " +
          (pressed ? "Confirmed." : "Not asked."));
      return !!pressed;
    }
    try {
      await buttons[0].click();
      pressed = buttons[0];
      break;
    } catch (e) {
      const stale = e.name === "StaleElementReferenceError" ||
          /does not belong to the document|stale element/i.test(
              e.message || "");
      if (!stale || Date.now() > deadline) {
        log.debug("Leaving signOutInBrowser(). " + e.message);
        throw e;
      }
      log.info("the sign-out page was replaced under the click; looking " +
          "for the button again");
    }
  }
  // The answer is a page saying it is done (or a front-channel page on the
  // way there); what matters is that the question is gone.
  await driver.wait(until.stalenessOf(pressed), wait,
    "pressed Sign out on the mock's RP-Initiated Logout confirmation, and " +
    "the page never moved on");
  log.debug("Leaving signOutInBrowser(). Confirmed.");
  return true;
}

module.exports = { signOutInBrowser };
