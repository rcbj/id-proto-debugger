// File: webdriver_deadline.js
//
// ---------------------------------------------------------------------------
// EVERY WEBDRIVER COMMAND GETS AN ANSWER OR A DEADLINE, and one that gets
// neither can no longer hold a job until the runner's watchdog kills it.
//
// WHAT IT LOOKED LIKE
//
// On 2026-09-28 the coverage job of the push run on 6b32f4e spent 2700
// seconds — the whole of TEST_JOB_TIMEOUT_MS on that launcher — on one line
// of wsfed_sso.js:
//
//   await driver.wait(until.urlContains("wsfed_response.html"), loginWait,
//     "the IdP's POST never reached a landing ...");
//
// straight after the sign-in click at the mock STS. The job's log ends at
// "Wait for the WS-Federation response page." and the next line is the
// runner's "no exit after 2700s; killing this job's process tree". loginWait
// is seconds, and the wait never reported it.
//
// WHY THE WAIT'S OWN TIMEOUT DID NOT FIRE
//
// selenium-webdriver's driver.wait() with a FUNCTION condition (every
// until.* is one) compares the elapsed time against its timeout only AFTER an
// evaluation of the condition resolves (lib/webdriver.js, pollCondition). An
// evaluation is a WebDriver command — getCurrentUrl() here — and the HTTP
// client under it has no request timeout at all. So a command that chromedriver
// never answers is a wait that never times out, and a test with every wait
// bounded can still hang for ever.
//
// Chromedriver's page-load timeout does not cover it either. That bounds a
// NAVIGATION (a get(), or a click that starts one) and it was five minutes by
// default here, yet this job sat for forty-five: whatever chromedriver was
// blocked on, it was not a timer of its own. renderer_wedge.js describes the
// fault that is the likely cause — a renderer that stops answering under
// concurrency and is never recovered — and when that fault surfaces through
// the page-load timer the runner retries it. When it surfaces as silence it
// surfaced as nothing, until now.
//
// WHAT THIS DOES
//
// WebDriver.prototype.execute — the one method every command of every driver
// goes through, quit() included — is wrapped so the command races a deadline.
// The deadline is NOT one fixed number, because a command may legitimately
// take as long as the timeouts the session was given: an executeAsyncScript
// runs up to the script timeout (saml_tools.js sets 120 s for its power-set
// sweep), a get() up to the page-load timeout. So it is the LARGEST of the
// script, page-load and implicit timeouts in force, plus GRACE_MS for
// chromedriver to report its own timeout first. Chromedriver's own error is
// always the better message, and GRACE_MS is what lets it arrive.
//
// The timeouts in force are tracked per driver, from PAGE_LOAD_TIMEOUT_MS
// (which browser_flags.js sends as the session's `timeouts` capability) and
// from every setTimeouts() the test makes, which is a SET_TIMEOUT command and
// passes through here like any other.
//
// WHAT A MISSED DEADLINE LOOKS LIKE
//
//   WebDriverCommandDeadline: WebDriver command getCurrentUrl got no answer
//   from chromedriver in 180000 ms ...
//
// It is deliberately NOT a selenium TimeoutError. Several helpers here catch
// TimeoutError as "not there yet" and go round again, and a command that is
// never going to be answered must end the test rather than start another
// three-minute wait. It is also NOT retried by the runner: renderer_wedge.js
// retries one message by name, on purpose, and this is a different one.
//
// The abandoned request is left in flight rather than destroyed: destroying
// the socket makes selenium's HTTP client RETRY the command (it retries a
// reset connection), and re-sending a click is not a safe thing to do on a
// session nobody can see into. The test fails, its finally calls quit() —
// which has the same deadline — and the runner kills the job's process group,
// chromedriver included, when the job exits.
//
// Loaded by browser_flags.js, which every browser test in this suite requires
// (tests/download_dir_pinned.js fails the run when one builds a driver without
// going through it), so the patch is in place before any driver exists.
// ---------------------------------------------------------------------------
const { WebDriver } = require("selenium-webdriver/lib/webdriver");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "webdriver_deadline",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The page-load timeout browser_flags.js gives every session. Chromedriver's
// default is 300 s; a page in this suite loads in seconds even under the
// instrumented coverage bundles, and a renderer that has stopped answering is
// recognised (renderer_wedge.js) by the message this timer produces — so the
// shorter it is, the sooner that job is retried in a fresh browser.
const PAGE_LOAD_TIMEOUT_MS = 120000;

// W3C WebDriver's defaults for the two the suite does not always set.
const DEFAULT_SCRIPT_TIMEOUT_MS = 30000;
const DEFAULT_IMPLICIT_TIMEOUT_MS = 0;

// How much longer than its own timeout chromedriver is given to report it.
const GRACE_MS = 60000;

class WebDriverCommandDeadline extends Error {
  constructor(message) {
    super(message);
    this.name = "WebDriverCommandDeadline";
  }
}

// The timeouts this driver is running under, created on first use.
//
// HOT PATH: this and deadlineFor() run for EVERY WebDriver command a job
// sends, which is thousands per browser job, so neither logs. noteTimeouts()
// runs only for a setTimeouts() and keeps its pair.
function timeoutsOf(driver) {
  if (!driver.__deadlineTimeouts) {
    driver.__deadlineTimeouts = {
      script: DEFAULT_SCRIPT_TIMEOUT_MS,
      pageLoad: PAGE_LOAD_TIMEOUT_MS,
      implicit: DEFAULT_IMPLICIT_TIMEOUT_MS
    };
  }
  return driver.__deadlineTimeouts;
}

// Folds a SET_TIMEOUT command's parameters into what this driver is under.
// W3C names them script/pageLoad/implicit; the legacy form is type + ms.
function noteTimeouts(driver, parameters) {
  log.debug("Entering noteTimeouts().");
  var now = timeoutsOf(driver);
  var p = parameters || {};
  ["script", "pageLoad", "implicit"].forEach(function (one) {
    if (typeof p[one] === "number") {
      now[one] = p[one];
    }
  });
  if (typeof p.type === "string" && typeof p.ms === "number") {
    var legacy = { "page load": "pageLoad" }[p.type] || p.type;
    if (legacy in now) {
      now[legacy] = p.ms;
    }
  }
  log.debug("Leaving noteTimeouts(). script=" + now.script + " pageLoad=" +
            now.pageLoad + " implicit=" + now.implicit + ".");
}

// How long a command on this driver may take before it is abandoned.
// Hot path; see timeoutsOf().
function deadlineFor(driver) {
  var now = timeoutsOf(driver);
  return Math.max(now.script, now.pageLoad, now.implicit) + GRACE_MS;
}

// Installed once per process, however many modules require this one.
function install() {
  log.debug("Entering install().");
  if (WebDriver.prototype.execute.__withDeadline) {
    log.debug("Leaving install(). Already installed.");
    return;
  }
  const original = WebDriver.prototype.execute;
  // Every command of every driver passes through here, so it logs nothing of
  // its own: a debug pair per command is the whole log of a browser job. The
  // one line it does write is the missed deadline, which is the point of it.
  const withDeadline = function (command) {
    const name = command.getName();
    if (name === "setTimeout") {
      noteTimeouts(this, command.getParameters());
    }
    const ms = deadlineFor(this);
    let timer = null;
    const deadline = new Promise(function (resolve, reject) {
      timer = setTimeout(function () {
        const message = "WebDriver command " + name + " got no answer " +
            "from chromedriver in " + ms + " ms — longer than any timeout " +
            "the session is under, so it is not coming. The browser has " +
            "most likely stopped answering; see tests/webdriver_deadline.js " +
            "and tests/renderer_wedge.js.";
        log.error(message);
        reject(new WebDriverCommandDeadline(message));
      }, ms);
    });
    const result = original.call(this, command);
    return Promise.race([result, deadline]).finally(function () {
      clearTimeout(timer);
    });
  };
  withDeadline.__withDeadline = true;
  WebDriver.prototype.execute = withDeadline;
  log.debug("Leaving install().");
}

install();

module.exports = {
  PAGE_LOAD_TIMEOUT_MS: PAGE_LOAD_TIMEOUT_MS,
  GRACE_MS: GRACE_MS,
  WebDriverCommandDeadline: WebDriverCommandDeadline,
  deadlineFor: deadlineFor,
  noteTimeouts: noteTimeouts
};
