// File: renderer_wedge.js
//
// ---------------------------------------------------------------------------
// ONE CHROME FAULT, RECOGNISED IN ONE PLACE: the renderer that stops answering
// and never starts again.
//
// WHAT IT LOOKS LIKE
//
// A `driver.get()` — any navigation, on any page, in any job — never returns,
// and chromedriver eventually gives up with its page-load timeout, which is
// FIVE MINUTES by default and which nothing here sets:
//
//   TimeoutError: timeout: Timed out receiving message from renderer: 299.995
//     (Session info: chrome=121.0.6167.85)
//       ...
//       at async misconfigureTheWallet (/usr/src/app/sd_jwt_vc_waltid.js:227)
//
// The message names a page-load timeout, so it reads as a slow server or a
// heavy bundle. It is neither, and that was checked rather than assumed. When
// it happens:
//
//   * the CLIENT is fine — the other jobs in the pool are loading the same
//     pages, from the same container, in two or three seconds throughout;
//   * the BROWSER is fine — its DevTools endpoint answers, a NEW tab in the
//     same browser evaluates JavaScript, navigates to that same URL and reads
//     that origin's localStorage back;
//   * the RENDERER is idle rather than busy — the process sleeps in a futex,
//     the container's CPU is 90% idle, and there is no dialog open;
//   * and the tab is gone for good — `Runtime.evaluate` and `Page.enable`
//     time out against it, and a `Page.stopLoading` or a `Page.navigate` to
//     `about:blank` is accepted by the BROWSER and changes nothing, because
//     the renderer never acts on it: evaluating in that tab still times out
//     afterwards. Nothing from inside that session brings it back.
//
// It is provoked by CONCURRENCY, not by any page: four browser jobs at once in
// the tests container reproduced it in about a third of the sessions measured
// on 2026-09-02, on the coverage stack and on the plain one alike, and the
// same job run alone on the same stack passed every time it was tried. That is
// why it reaches the report as a different test each time —
// `sd_jwt_vc_waltid.js` on 2026-09-02T10-41-25 and 2026-09-03T00-50-15,
// `sd_jwt_vc_issuance.js` on 2026-09-02T06-40-39 — and why the failing line is
// wherever that job happened to be navigating.
//
// WHY A RETRY, AND WHY ONLY THIS
//
// The tab cannot be recovered, so the only thing that can clear it is a new
// browser, and the only place in this suite that starts one is a new run of
// the job. `run-report.js` therefore runs a job a SECOND time when its output
// carries this message and nothing else has passed — the same shape as
// `page_load.js`, which retries Chromium's network-error page and nothing
// else: one known transient browser fault, recognised by name, retried once,
// and said out loud in the log and in the report so a run that met it cannot
// be mistaken for a run that did not.
//
// It is deliberately NOT widened. "Timed out receiving message from renderer"
// is the only message here that a bounded page load can produce with the
// server and the browser both demonstrably healthy. An assertion that failed,
// a wait that expired, a page that did not load, a service that was down —
// those are the failures this suite exists to report, and a runner that ran
// them twice would take twice as long to tell the truth about them.
//
// THE UNDERLYING FAULT WAS THE PINNED BROWSER, AND THE PIN HAS MOVED. The
// tests image carried Chrome 121.0.6167.85 (January 2024) when this was
// written; it is 152.0.7977.75 since 2026-09-03, and the four-at-once harness
// that wedged about a third of its sessions on 121 ran TWELVE consecutive
// sessions clean on 152.
//
// THIS STAYS ANYWAY, and the reason is not caution. It costs a healthy run
// nothing — the retry is reached only by a job that has already failed with
// this one message — and what it buys is that a recurrence is a line in the
// log rather than a red job nobody can reproduce. A browser is a dependency
// this suite does not control: the pin will move again, a runner will be
// slower, a pool will be wider, and somebody will pin BACKWARDS to bisect a
// regression and take the old behaviour back with them. The diagnosis above
// is what makes this file worth keeping either way; it cost a day to
// establish and none of it is visible from the failure message.
// ---------------------------------------------------------------------------

// The log level comes from the same configuration everything else here reads.
// A caller without one still has to be able to load this module, so an
// unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "renderer_wedge",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// Chromedriver's own wording, and the whole of what is matched. The number
// after it is the timeout that expired, so it is not part of the signature.
var SIGNATURE = "Timed out receiving message from renderer";

// Does this job's captured output carry the wedge?
//
// The output rather than the exit code, because the exit code of a job whose
// navigation timed out is the exit code of any other failure — 1 — and the
// message is the only thing that tells them apart.
function isRendererWedge(output) {
  log.debug("Entering isRendererWedge().");
  var found = String(output || "").indexOf(SIGNATURE) !== -1;
  log.debug("Leaving isRendererWedge(). " + found + ".");
  return found;
}

// What the log and the report say about a job that was run again. Kept here
// beside the predicate so the two cannot drift: a retry that is not explained
// is indistinguishable from a suite that quietly runs everything twice.
function wedgeNote(jobName) {
  log.debug("Entering wedgeNote().");
  var note = "[runner] " + jobName + " failed with Chrome's \"" + SIGNATURE +
      "\": the tab stopped answering and cannot be recovered from inside " +
      "the session. Running the job once more in a fresh browser. See " +
      "tests/renderer_wedge.js. Only this one message is retried.";
  log.debug("Leaving wedgeNote().");
  return note;
}

module.exports = {
  isRendererWedge: isRendererWedge,
  wedgeNote: wedgeNote,
  SIGNATURE: SIGNATURE
};
