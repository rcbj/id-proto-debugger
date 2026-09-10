// File: expectation.js
//
// ---------------------------------------------------------------------------
// A TEST THAT DOES NOT RUN IS NOT A PASSING TEST.
//
// Every job here can end three ways, and until 2026-09-02 only two of them
// were visible. A job that failed exited non-zero and went red; a job the
// LAUNCHER decided not to run got `job.skip` in run-report.js, was recorded by
// makeSkipResult() and appeared as `<skipped>` in report.xml. The third way was
// a test declining to run ITSELF — a capability probe against the mock STS, a
// service that answered 404, an environment variable nobody set — which logged
// a line saying SKIPPED and then `return`ed out of `test()`. Returning from
// `test()` exits the process 0, and exit 0 is how this runner is told a test
// passed. So a job that did nothing at all was counted, reported and tallied as
// a job that did everything it was written to do.
//
// THAT IS NOT A THEORETICAL HOLE. On 2026-09-01 the mock STS moved five
// directory pages behind its admin console (`/ldap/applications` became
// `/admin/ldap/applications`, mirrored for programs at
// `/admin-api/ldap/applications`) and the sts/ submodule here was bumped to it.
// Six capability probes in this directory still fetched the old paths. Every
// one of them got a 404, read it as "this checkout's mock is too old", and
// turned itself off. FIFTY-FOUR JOBS — the whole federation family, all
// forty-nine grid points among them, plus both LDAP jobs — stopped running.
// The run that followed reported `tests="292" failures="0" skipped="2"`, the
// two being the Windows-KDC jobs that skip on every machine without a domain
// controller. Nineteen percent of the suite had been switched off by a URL
// change and the report was green.
//
// So the rule this module exists to enforce:
//
//   * A prerequisite that is genuinely ABSENT — no WSTRUST_STS_URL, no
//     KRB5_DC_HOST, a deployment with no api behind it — is a SKIP, and a skip
//     is now a first-class result rather than a pass with a note in the log.
//     `declineToRun()` below.
//   * A prerequisite that is PRESENT and does not have what the test needs is
//     a FAILURE. `require()` below. The service answered, so it is there; the
//     test was expected to run against it and could not, and the reason is a
//     defect in one of the two — a moved endpoint, an un-bumped submodule, a
//     feature that regressed — rather than a fact about this machine.
//
// The second half is the one that matters, and it is the one that reads as
// harsh until you have watched the alternative. "The mock does not publish
// appFederationRelationship" is not a property of the environment the way "this
// laptop has no Windows domain controller" is. It is a sentence that can only
// be true when something is wrong, and a suite that answers it with silence
// answers every future endpoint move the same way.
//
// ---------------------------------------------------------------------------
// WHY THIS SETS process.exitCode RATHER THAN CALLING process.exit()
//
// `tests/driver_quit_reachable.js` forbids `process.exit()` anywhere a
// WebDriver session can be open, and it is right to: exit() is synchronous
// termination, so it skips the `finally` that quits the driver and leaves a
// whole headless Chrome (~15 OS processes) resident. A run of this suite once
// left 559 of them behind and cost a reboot.
//
// Assigning `process.exitCode` has none of that: it records the code node will
// exit WITH once the event loop drains normally, so the caller's `return`,
// every `finally` above it and the driver quit all still happen. The callers
// here run before a driver exists anyway — a gate is the first thing in
// `test()` — but a helper that would be a landmine the day one moved is not
// worth having.
// ---------------------------------------------------------------------------
const bunyan = require("bunyan");
const log = bunyan.createLogger({
  name: "expectation",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The exit code a job uses to say "I declined to run, and here is why". It is
// not 0 (which means the test ran and passed) and not 1 (which means it ran and
// failed), so runJob() in run-report.js can tell all three apart without
// parsing anything. 42 is arbitrary and only has to be none of the codes node
// itself produces: 1 for an uncaught throw, 3/4/5 for internal errors, 128+n
// for a signal.
const SELF_SKIP_EXIT = 42;

// The line runJob() greps the job's output for to recover the reason. It is
// written to stdout as PLAIN TEXT rather than through bunyan, because every log
// line in this suite is a JSON record and the runner would otherwise have to
// parse a log format to find out whether a test ran.
const SELF_SKIP_MARKER = "===== SELF-SKIP: ";

// ---------------------------------------------------------------------------
// THE PREREQUISITE IS ABSENT. Record a skip and let the caller return.
//
// The caller still has to `return` — this cannot do it for them, and a
// `declineToRun()` whose caller carries on would report a skip for a job that
// then ran and failed. Every call site is therefore
//
//   declineToRun(log, "why");
//   log.debug("Leaving test(). Skipped.");
//   return;
//
// `callerLog` rather than `log`: this module has a module-level `log` of its
// own two paragraphs up, and a parameter of the same name would shadow it —
// which is the `edge_landing_contract.js` trap CLAUDE.md records, where a log
// line added to a helper was a ReferenceError that took out every
// WS-Federation case before a browser had been opened.
// ---------------------------------------------------------------------------
function declineToRun(callerLog, why) {
  log.debug("Entering declineToRun().");
  const reason = String(why || "no reason given").replace(/\s+/g, " ").trim();
  // Plain stdout, on a line of its own, for the runner. See SELF_SKIP_MARKER.
  process.stdout.write("\n" + SELF_SKIP_MARKER + reason + "\n");
  if (callerLog && typeof callerLog.warn === "function") {
    callerLog.warn("SKIPPED: " + reason);
  }
  process.exitCode = SELF_SKIP_EXIT;
  log.debug("Leaving declineToRun(). exitCode=" + SELF_SKIP_EXIT);
}

// ---------------------------------------------------------------------------
// THE PREREQUISITE IS PRESENT AND CANNOT DO WHAT THIS TEST NEEDS. Fail.
//
// `what` names the thing that is there — "the mock STS at https://…" — and
// `why` says what it could not do. Both are in the message, because the two
// halves answer different questions: which service, and which capability. A
// message with only the second sends somebody to the wrong process.
//
// It throws rather than asserting so the stack names this module, which is the
// one line of the trace that says what KIND of failure this is: not a wrong
// value, not a missing element, but a service that is not the service this test
// was written against.
// ---------------------------------------------------------------------------
function require_(condition, what, why) {
  log.debug("Entering require_().");
  if (condition) {
    log.debug("Leaving require_(). Satisfied.");
    return;
  }
  log.debug("Leaving require_(). Throwing.");
  throw new Error(
    "UNMET EXPECTATION — this test was expected to run and could not. " +
    what + " " + why + "\n\n" +
    "This is a FAILURE rather than a skip on purpose. The service is " +
    "reachable, so it is there; what is missing is a capability it is " +
    "supposed to have. That is a moved endpoint, an un-bumped sts/ gitlink, " +
    "or a regression — never a fact about this machine. A suite that skipped " +
    "here would go green with the test switched off, which is exactly how " +
    "fifty-four jobs stopped running unnoticed on 2026-09-01. See " +
    "tests/expectation.js.");
}

// ---------------------------------------------------------------------------
// THE SAME RULE FOR THE `preconditions()` SHAPE, which a dozen files here
// share: an object carrying `ok` and, when it is false, a `why` naming which
// of several checks failed.
//
// Those functions ask whether the services this job was scheduled against are
// up and are the versions it was written for — the api answering
// GET /krb5/limits, the mock's LDAP listener actually bound, a page that is
// on this deployment. Every one of those is a thing the launcher already
// decided was here: run-report.js gates each family on its own variable
// (LDAP_AVAILABLE, SPIFFE_AVAILABLE, the Kerberos sweep) and hands the job a
// declared skip when the target has not got it. So by the time
// `preconditions()` runs, this job was EXPECTED TO RUN, and a precondition
// that fails is the stack being wrong rather than the target being different.
//
// `needs` says what the job needed, in the words the reader can act on —
// "the client, the api and the mock STS with its KDC on port 88". It is the
// half `why` does not carry: `why` is which check failed, `needs` is what to
// go and start.
// ---------------------------------------------------------------------------
function mustBeReady(ready, needs) {
  log.debug("Entering mustBeReady().");
  if (ready && ready.ok) {
    log.debug("Leaving mustBeReady(). Ready.");
    return;
  }
  const why = (ready && ready.why) || "a precondition failed and said nothing";
  log.debug("Leaving mustBeReady(). Throwing.");
  require_(false, "The services this job was scheduled against are not " +
           "ready:", why + ".\n\nThis test needs " + needs);
}

module.exports = {
  SELF_SKIP_EXIT: SELF_SKIP_EXIT,
  SELF_SKIP_MARKER: SELF_SKIP_MARKER,
  declineToRun: declineToRun,
  mustBeAbleTo: require_,
  mustBeReady: mustBeReady
};
