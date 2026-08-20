// File: page_load.js
//
// ---------------------------------------------------------------------------
// Load a page and make sure the BROWSER got the page, not Chrome's
// network-error page. One implementation, shared by the browser tests that
// navigate to a target over the public internet.
//
// WHY THIS EXISTS
//
// `driver.get()` does not tell you the navigation worked. Chromedriver reports
// some failures by THROWING (`unknown error: net::ERR_CONNECTION_REFUSED`,
// `net::ERR_NAME_NOT_RESOLVED` — a connection that was never established) and
// others not at all: when the connection IS established and then dropped —
// ERR_EMPTY_RESPONSE, ERR_CONNECTION_RESET, ERR_HTTP2_PROTOCOL_ERROR, the
// shapes a CDN edge produces once in a few hundred requests — `get()` resolves
// normally, `getCurrentUrl()` returns the URL that was ASKED FOR, and the
// document in the tab is Chromium's error page. Nothing the caller can see
// says the load failed.
//
// So the test proceeds, waits for a field that will never exist, and fails a
// full wait-budget later with `Waiting for element to be located ... Wait timed
// out after 10080ms` — a message that names one of OUR ids for a problem that
// is entirely somebody else's socket, on a page that was never ours. That has
// cost two remote runs: `WS-Trust 1.2 — Issue` on 2026-08-15T09-04-15
// (test.idptools.com) and `WS-Trust 1.4 — Validate` on 2026-08-20T07-56-55
// (idptools.com). In both the neighbouring cases loaded the SAME page seconds
// either side and passed, which is what a dropped connection looks like and is
// not what a broken page looks like.
//
// TWO THINGS THIS GETS RIGHT
//
// 1. It retries ONLY the network-error page. If the document really is ours and
//    the field is still missing, that is a product failure and it is raised on
//    the first attempt, at the original timeout — a retry there would treble
//    the time every genuine breakage takes to report and prove nothing.
//
// 2. It says the error CODE. The old diagnostic in wstrust.js logged the first
//    6000 characters of the page source, and the first 6000 characters of
//    Chromium's error page are Chromium's stylesheet: two failed runs are on
//    record whose logs contain several KB of `--google-gray-700` and not one
//    word about what went wrong. The code (`ERR_EMPTY_RESPONSE`) is in the DOM
//    the whole time, in `.error-code`, about 12 KB further down.
//
// HOW THE ERROR PAGE IS RECOGNISED, and why not by the URL
//
// `document.getElementById("main-frame-error")` and `document.body.className
// === "neterror"` — the container and the class Chromium's neterror.html has
// carried for years — plus `.error-code` for the code itself. The URL is NOT a
// usable signal: `driver.getCurrentUrl()` reports the requested URL even while
// the tab holds the error page (verified against Chrome 151 and matching the
// two failed runs above, where the logged "Current URL" was the page that had
// not loaded). Only `location.href` inside the document says
// `chrome-error://chromewebdata/`, and it is simpler to ask the DOM what it is.
//
// USAGE
//
//   const { loadPage, describeLoad } = require("./page_load");
//   await loadPage(driver, baseUrl + "/wstrust_tools.html", "wst_sts_url",
//                  { timeout: waitTime });
//
// It returns { attempts, url } — how many navigations it took. Callers ignore
// it; page_load_retry.js asserts on it, because "did it retry?" cannot be
// answered from the outside: Chrome re-sends a GET of its own accord when a
// connection is dropped before any response byte arrives, so the target seeing
// two requests says nothing about whether THIS function tried twice.
//
// `readyId` is an element that is in the page's own HTML from the moment it
// parses — the same id the caller would have waited for itself. It is what
// distinguishes "our page" from "a page"; see wait_for.js for why a field being
// PRESENT still says nothing about it being FILLED.
// ---------------------------------------------------------------------------

const { By, until } = require("selenium-webdriver");

// The log level comes from the same configuration everything else here reads.
// A caller without one still has to be able to load this module, so an
// unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "page_load",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// Three attempts, because the failure this exists for is a single dropped
// connection: the retry either works immediately or the target is down, and a
// target that is down should be reported rather than waited on. Each is
// overridable per call; there is deliberately no setter for the defaults,
// since one test changing them for the rest of a process is the kind of
// action at a distance this suite has been bitten by elsewhere.
var defaultAttempts = 3;
var defaultTimeout = 20000;
var defaultRetryDelay = 1000;

// What is actually in the tab. Returns { errorPage, code, title, href } and
// never throws: it is called from catch blocks, where a second failure would
// replace the diagnosis with its own.
//
// The function handed to executeScript runs in the BROWSER, where there is no
// bunyan — it is exempt from the Entering/Leaving convention, as everything
// serialised into the page is. See CLAUDE.md.
async function describeLoad(driver) {
  log.debug("Entering describeLoad().");
  try {
    var state = await driver.executeScript(
      "var mf = document.getElementById('main-frame-error');" +
      "var ec = document.querySelector('.error-code');" +
      "var cls = document.body ? (document.body.className || '') : '';" +
      "return { errorPage: !!mf || cls === 'neterror'," +
      " code: ec ? ec.textContent.trim() : null," +
      " title: document.title, href: location.href };");
    log.debug("Leaving describeLoad().");
    return state || { errorPage: false, code: null, title: null, href: null };
  } catch (e) {
    log.debug("Leaving describeLoad(). Could not read the document: " +
              e.message);
    return { errorPage: false, code: null, title: null, href: null };
  }
}

// A one-line summary for a log or an error message, so the code is what the
// reader sees rather than Chromium's stylesheet.
function describeToString(state, url) {
  log.debug("Entering describeToString().");
  if (!state.errorPage) {
    log.debug("Leaving describeToString().");
    return "the document at " + url + " is not Chrome's error page (title: " +
        (state.title || "(none)") + ")";
  }
  log.debug("Leaving describeToString().");
  return "Chrome's network-error page for " + url + ": " +
      (state.code || "(no error code in the page)");
}

// Navigate to `url` and return { attempts, url } once an element with id
// `readyId` is there.
//
// Retries only a navigation that landed on Chrome's network-error page. Any
// other failure — including the page being ours and the element missing — is
// raised on the first attempt, with what the tab actually held appended to the
// message.
async function loadPage(driver, url, readyId, opts) {
  log.debug("Entering loadPage().");
  opts = opts || {};
  var attempts = opts.attempts || defaultAttempts;
  var timeout = opts.timeout || defaultTimeout;
  var retryDelay = typeof opts.retryDelay === "number" ? opts.retryDelay :
      defaultRetryDelay;
  var lastState = null;

  for (var attempt = 1; attempt <= attempts; attempt++) {
    var failure = null;
    var state = null;
    try {
      await driver.get(url);
    } catch (e) {
      // The throwing half of the split described at the top of this file:
      // a connection that was never established.
      failure = e;
    }
    if (!failure) {
      // Ask the tab what it holds BEFORE spending the element budget on it.
      // get() resolves on the error page too, and #readyId can never appear
      // there — so waiting is a whole timeout per attempt spent on a document
      // already known to be the wrong one, which on a remote run's 10s budget
      // is half a minute of nothing before the retry that fixes it.
      state = await describeLoad(driver);
      if (state.errorPage) {
        failure = new Error("The navigation landed on Chrome's error page.");
      } else {
        try {
          await driver.wait(until.elementLocated(By.id(readyId)), timeout);
          log.debug("Leaving loadPage().");
          return { attempts: attempt, url: url };
        } catch (e) {
          // The page was ours when it arrived and the element never came.
          // Re-read the document rather than trusting the reading above: a
          // navigation can still have happened during the wait.
          failure = e;
          state = null;
        }
      }
    }

    lastState = state || await describeLoad(driver);
    if (!lastState.errorPage) {
      // Our page (or at least not Chromium's), and #readyId is not in it.
      // That is a real failure and retrying it only delays the report.
      failure.message = failure.message + " — " +
          describeToString(lastState, url);
      log.debug("Leaving loadPage(). The page loaded; #" + readyId +
                " is not in it.");
      throw failure;
    }

    log.warn("Attempt " + attempt + " of " + attempts + " to load " + url +
             " landed on " + describeToString(lastState, url) + ".");
    if (attempt < attempts) {
      // A fixed pause, deliberately: there is no page-side condition to poll
      // for — the thing being waited on is somebody else's socket.
      await driver.sleep(retryDelay);
    }
  }

  var error = new Error("Could not load " + url + " in " + attempts +
      " attempts: " + describeToString(lastState || { errorPage: true }, url) +
      ". The neighbouring cases load the same page, so this is the target or " +
      "the network rather than the page.");
  log.debug("Leaving loadPage(). Every attempt hit the network-error page.");
  throw error;
}

module.exports = {
  describeLoad: describeLoad,
  describeToString: describeToString,
  loadPage: loadPage
};
