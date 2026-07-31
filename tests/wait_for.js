// File: wait_for.js
//
// ---------------------------------------------------------------------------
// Wait for CONTENT, not for the element. One implementation, shared by the
// browser tests that poll a page's fields.
//
// WHY THIS EXISTS
//
// Every field these tests read is a static <input>/<textarea>/<span> that is in
// the HTML from the moment the page parses. So `until.elementLocated` succeeds
// almost immediately and tells you nothing about whether the page has filled the
// field in yet. Following it with a fixed `driver.sleep(N)` turns every such read
// into a bet that the page finished within N milliseconds — and those bets lose
// periodically, on a loaded machine, in a way that looks like a product bug.
//
// It cost two failed runs of the SD-JWT VC issuance suite (2026-07-31T05-15-44
// and 07-16-13), both `SyntaxError: Unexpected end of JSON input` at the same
// line. The field was `#jwt_payload` on token_detail.html, which is filled only
// at the end of a promise chain that fetches /claimdescription over HTTP,
// DOMParses the IANA claim registry, and then loops over EVERY claim in that
// registry re-decoding the token and rebuilding the tables on each pass. Its fill
// time is therefore load-dependent, and under a full suite run it exceeds the
// half-second the test was betting on.
//
// ONE DETAIL THAT MAKES THIS NASTIER THAN IT LOOKS, and that these helpers are
// built around: an un-filled <textarea> written across two lines of HTML —
//
//     <textarea id="jwt_payload" readonly>
//     </textarea>
//
// has a .value of "\n            ". That is WHITESPACE, not "". So it is TRUTHY:
// every `if (!value) …` guard waves it through, and `JSON.parse` of it throws
// "Unexpected end of JSON input" — the exact error those runs failed with, which
// names JSON for a problem that was timing. Truthiness is not a usable test for
// "has the page filled this in"; parsing it, or trimming it, is.
//
// The helpers here poll until the content is actually there. They are FASTER in
// the normal case (no fixed wait to sit through) and they do not fail in the slow
// case. Use them instead of sleep-then-read.
//
// TWO THINGS THEY GET RIGHT THAT ARE EASY TO GET WRONG
//
// 1. The error message. `driver.wait(fn, timeout, message)` takes a plain STRING,
//    evaluated at call time — so interpolating the polled value into it reports
//    the value from before the first poll, i.e. always "". That is exactly what
//    the older copy of waitForStatus did, and it is why failed runs logged the
//    useless "(last status: )". Here the last value is attached in a catch, after
//    the wait has failed, preserving the original error's type and stack.
//
// 2. Still failing. A wait that can never fail is worse than a sleep. These all
//    time out at the configured budget and say what the field last held, so a
//    genuinely broken page is still a red test with a readable reason.
//
// USAGE
//
//   const { configure, waitForFilled, waitForJson, waitForStatus } = require("./wait_for");
//   configure({ timeout: fetchWait });          // once, near the top of the test
//   var raw = await waitForFilled(driver, "vc_credential_raw", "step 3 should show the credential");
//
// configure() sets a module-level default because one test file runs per process;
// any call may still override it with a trailing timeout argument.
// ---------------------------------------------------------------------------

// Generous enough for a page that fetches over the network before rendering.
// Overridden per test by configure({ timeout }).
var defaultTimeout = 20000;

function configure(options) {
  if (options && typeof options.timeout === "number" && options.timeout > 0) {
    defaultTimeout = options.timeout;
  }
  return defaultTimeout;
}

// Long values (a 10 KB credential, a JWKS) would bury the log; an absent field
// must not read the same as an empty one; and a WHITESPACE-only value must not be
// printed raw, or the message comes out as "(last value:             )" — which
// looks exactly like the always-empty bug this module exists to fix, and is the
// normal state of an unfilled two-line <textarea>. So it gets a name too.
function forMessage(v) {
  if (v === null || v === undefined) return "(absent)";
  var s = typeof v === "object" ? JSON.stringify(v) : String(v);
  if (s === "") return "(empty)";
  if (s.trim() === "") return "(blank: " + s.length + " chars of whitespace)";
  return s.length > 120 ? s.slice(0, 120) + "…" : s;
}

function text(driver, id) {
  return driver.executeScript(
    "var e = document.getElementById(arguments[0]); return e ? e.textContent.trim() : null;", id);
}

function value(driver, id) {
  return driver.executeScript(
    "var e = document.getElementById(arguments[0]); return e ? e.value : null;", id);
}

// The general form: poll a getter until a predicate holds. Everything else here
// is a shorthand for this.
async function waitFor(driver, getter, predicate, message, timeout) {
  var last;
  try {
    await driver.wait(async function () {
      last = await getter();
      return predicate(last);
    }, timeout || defaultTimeout);
  } catch (e) {
    // See note (1) above: the message must be built HERE, not passed to wait().
    e.message = message + " (last: " + forMessage(last) + ") — " + e.message;
    throw e;
  }
  return last;
}

// textContent of an element (status lines, notes, banners).
async function waitForStatus(driver, id, predicate, message, timeout) {
  var last = "";
  try {
    await driver.wait(async function () {
      last = (await text(driver, id)) || "";
      return predicate(last);
    }, timeout || defaultTimeout);
  } catch (e) {
    e.message = message + " (last status: " + forMessage(last) + ") — " + e.message;
    throw e;
  }
  return last;
}

// .value of an input/textarea.
async function waitForValue(driver, id, predicate, message, timeout) {
  var last = null;
  try {
    await driver.wait(async function () {
      last = await value(driver, id);
      return predicate(last === null || last === undefined ? "" : last);
    }, timeout || defaultTimeout);
  } catch (e) {
    e.message = message + " (last value: " + forMessage(last) + ") — " + e.message;
    throw e;
  }
  return last;
}

// The common case: any non-empty value.
function waitForFilled(driver, id, message, timeout) {
  return waitForValue(driver, id, function (v) { return v.trim() !== ""; }, message, timeout);
}

// Waits until the field holds parseable JSON and returns the PARSED object.
// The point is that "not filled in yet" and "filled with something that is not
// JSON" both become a timeout naming the field and its content, instead of a
// SyntaxError from JSON.parse with no context — which is the failure this module
// was written for.
async function waitForJson(driver, id, message, timeout) {
  var parsed = null;
  var last = null;
  try {
    await driver.wait(async function () {
      last = await value(driver, id);
      // Not `if (!last)`: an unfilled two-line <textarea> holds whitespace, which
      // is truthy. See the note above — this is the whole bug.
      if (!last || last.trim() === "") return false;
      try {
        parsed = JSON.parse(last);
        return true;
      } catch (e) {
        // Half-written, or not JSON at all — keep waiting rather than throw here.
        return false;
      }
    }, timeout || defaultTimeout);
  } catch (e) {
    e.message = message + " (last value: " + forMessage(last) + ") — " + e.message;
    throw e;
  }
  return parsed;
}

module.exports = {
  configure: configure,
  forMessage: forMessage,
  text: text,
  value: value,
  waitFor: waitFor,
  waitForStatus: waitForStatus,
  waitForValue: waitForValue,
  waitForFilled: waitForFilled,
  waitForJson: waitForJson
};
