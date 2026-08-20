// File: page_load_retry.js
//
// What tests/page_load.js promises, checked against a browser and a socket
// rather than assumed.
//
// The helper exists because a page load can fail in a way nothing the caller
// can see reports: when the connection IS established and then dropped,
// `driver.get()` resolves normally, `getCurrentUrl()` returns the URL that was
// asked for, and the tab holds Chromium's network-error page. The test then
// waits out its whole budget for a field that was never there and fails naming
// one of OUR ids — which is what happened to `WS-Trust 1.2 — Issue` on
// 2026-08-15 (test.idptools.com) and to `WS-Trust 1.4 — Validate` on
// 2026-08-20 (idptools.com), in both cases while the neighbouring jobs loaded
// the same page seconds either side and passed.
//
// Three properties are worth a test of their own, because each of them is
// silent when it breaks:
//
//   A. A dropped connection is RETRIED and the load succeeds. If the retry
//      stopped working the suite would go back to a flake nobody can
//      reproduce. Note what this has to be careful about: Chrome retries a
//      dropped GET itself, so the check is on the number of navigations
//      loadPage() reports, against a target that outlasts those.
//   B. A target that keeps dropping is reported with its ERROR CODE, not with
//      Chromium's stylesheet — the first 6000 characters of that error page
//      are CSS, which is what both failed runs above logged instead of a
//      reason.
//   C. A page that IS ours with the field missing fails on the FIRST attempt.
//      This is the property most likely to rot: making the retry
//      unconditional would still pass A and B while trebling the time every
//      genuine breakage takes to report — and a retried product failure reads
//      as a slow test rather than as a wrong one.
//
// The targets are sockets this test opens on loopback and closes again, so it
// needs no api, no client, no STS and no network: it is never skipped, and it
// runs the same in a checkout and in the tests image. The one thing it does
// need is a browser, like every other browser test here — headless, per
// tests/browser_tests_headless.js.
const { Builder } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const net = require("net");
const assert = require("assert");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { loadPage } = require("./page_load.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "page_load_retry",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// Headless by default, cleared with `--headless false` by a human who wants to
// watch a run. An opt-IN is what a CI runner and the tests container cannot
// survive, and tests/browser_tests_headless.js refuses one.
var headless = true;

const program = new Command();
program.addOption(new Option("-l, --headless <headless>",
                             "run the browser headless")
                  .default("true"));
// Accepted and ignored: run-report.js passes --url to every job, and commander
// exits(1) on an option it has not been told about — which is a job that fails
// before its first line runs, naming the option rather than the test. This
// one's targets are sockets it opens on loopback, so there is no base url for
// it to honour.
program.addOption(new Option("-u, --url <url>",
                             "base url (unused: this test serves its own " +
                             "targets on loopback)"));
program.parse(process.argv);
if (program.opts().headless === "false") {
  headless = false;
}

// The page the fake target serves when it serves one. `wst_sts_url` is the id
// wstrust.js waits for, so this exercises the helper exactly as its caller
// does.
const READY_ID = "wst_sts_url";
const PAGE = "<html><body><input id='" + READY_ID + "'></body></html>";
const NO_FIELD = "<html><body><p>a page, but not ours</p></body></html>";

// Short by the standards of this suite, deliberately: check C spends a whole
// timeout proving it does NOT retry, so a generous budget here is paid three
// times over for nothing.
const TIMEOUT = 5000;
const RETRY_DELAY = 200;

// A target that DROPS the connection for the first `dropCount` requests and
// answers with `body` after that. Dropping an established connection is the
// half of the failure that `driver.get()` does not report — see the top of
// page_load.js — and destroying the socket mid-request is how Chrome is made
// to produce ERR_EMPTY_RESPONSE on demand.
//
// It speaks HTTP by hand rather than through `http.createServer` because
// `sock.destroy()` on a raw socket is the whole point and node's HTTP server
// works hard to avoid doing that.
function makeTarget(dropCount, body) {
  log.debug("Entering makeTarget().");
  var seen = 0;
  var srv = net.createServer(function (sock) {
    var counted = false;
    // A destroyed socket raises ECONNRESET on the writing side. There is
    // nothing to do about it and an unhandled 'error' here would take the test
    // process down instead of the request.
    sock.on("error", function () {});
    sock.on("data", function (buf) {
      if (counted) {
        return;
      }
      counted = true;
      // Match the REQUEST LINE only. The favicon request Chrome makes after
      // every navigation carries the page's URL in its `Referer` header, so a
      // check against the whole buffer counts one navigation as two — which is
      // exactly how check C first reported a retry that had not happened.
      var line = String(buf).split("\r\n")[0];
      if (line.indexOf("page_load_retry.html") < 0) {
        sock.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n" +
                 "Connection: close\r\n\r\n");
        return;
      }
      seen++;
      if (seen <= dropCount) {
        sock.destroy();
        return;
      }
      sock.end("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
               "Content-Length: " + body.length + "\r\n" +
               "Connection: close\r\n\r\n" + body);
    });
  });
  srv.requestsForThePage = function () {
    return seen;
  };
  log.debug("Leaving makeTarget().");
  return srv;
}

// Run `fn(url, target)` against a target listening on an EPHEMERAL port, and
// close it afterwards however that goes. A fixed port would collide with
// whatever else the machine running the suite has open, and the failure would
// be an EADDRINUSE in a test about page loads.
async function withTarget(dropCount, body, fn) {
  log.debug("Entering withTarget().");
  var srv = makeTarget(dropCount, body);
  await new Promise(function (resolve) {
    srv.listen(0, "127.0.0.1", resolve);
  });
  var url = "http://127.0.0.1:" + srv.address().port + "/page_load_retry.html";
  try {
    return await fn(url, srv);
  } finally {
    srv.close();
    log.debug("Leaving withTarget().");
  }
}

// A. Dropped connections, then the page. The load must succeed, and it must be
// THIS helper that made it succeed.
//
// That second half is the whole difficulty, and it is why the target's request
// count cannot be the assertion. Chrome re-sends a GET of its own accord when
// the connection is dropped before any response byte arrives, two or three
// times per navigation — so a single dropped connection is recovered by the
// browser before the helper ever sees an error page, and a check written
// against "the target saw two requests" passes with the retry deleted. Hence
// DROPS_BEFORE_THE_PAGE, which is more than one navigation-worth of Chrome's
// own attempts, and hence loadPage() reporting the number of navigations it
// made: `attempts > 1` is the helper retrying, and nothing else is.
const DROPS_BEFORE_THE_PAGE = 3;

async function recoversFromADroppedConnection(driver) {
  log.debug("Entering recoversFromADroppedConnection().");
  log.info("A: dropped connections followed by the page.");
  await withTarget(DROPS_BEFORE_THE_PAGE, PAGE, async function (url, srv) {
    var result = await loadPage(driver, url, READY_ID,
                                { timeout: TIMEOUT,
                                  retryDelay: RETRY_DELAY });
    assert.ok(result && result.attempts > 1,
        "loadPage() must have navigated more than once — a target that drops " +
        DROPS_BEFORE_THE_PAGE + " connections outlasts Chrome's own retries, " +
        "so a load that took one attempt means this helper did not retry at " +
        "all. Got: " + JSON.stringify(result));
    log.info("A: recovered on attempt " + result.attempts + " of " +
             "loadPage()'s own, after " + srv.requestsForThePage() +
             " request(s) at the target.");
  });
  log.debug("Leaving recoversFromADroppedConnection().");
}

// B. Every connection dropped. The load must fail after the configured number
// of attempts, and the message must carry the ERROR CODE — the reason the
// helper reads `.error-code` out of the DOM at all.
async function reportsTheErrorCodeWhenEveryAttemptFails(driver) {
  log.debug("Entering reportsTheErrorCodeWhenEveryAttemptFails().");
  log.info("B: a target that drops every connection.");
  await withTarget(Number.MAX_SAFE_INTEGER, PAGE, async function (url, srv) {
    var raised = null;
    try {
      await loadPage(driver, url, READY_ID, { timeout: TIMEOUT,
                                              retryDelay: RETRY_DELAY });
    } catch (e) {
      raised = e;
    }
    assert.ok(raised, "loadPage() returned for a target that never served " +
              "the page.");
    assert.ok(/ERR_[A-Z_]+/.test(raised.message),
        "The failure must name Chrome's error code, which is the whole " +
        "reason the error page is read rather than dumped. Got: " +
        raised.message);
    assert.ok(/3 attempts/.test(raised.message),
        "The failure must say how many attempts were made. Got: " +
        raised.message);
    // A floor, not an equality: each attempt is one navigation, and Chrome
    // makes more than one request per navigation when it is dropped (see
    // check A).
    assert.ok(srv.requestsForThePage() >= 3,
        "The target should have been asked at least once per attempt; it " +
        "saw " + srv.requestsForThePage() + ".");
    log.info("B: failed after 3 attempts naming the code: " + raised.message);
  });
  log.debug("Leaving reportsTheErrorCodeWhenEveryAttemptFails().");
}

// C. The page loads and the field is not in it. That is a PRODUCT failure and
// it must be raised on the first attempt: one request, one timeout, and a
// message saying the document was not Chrome's error page.
async function doesNotRetryAPageThatLoaded(driver) {
  log.debug("Entering doesNotRetryAPageThatLoaded().");
  log.info("C: a page that loads without the field in it.");
  await withTarget(0, NO_FIELD, async function (url, srv) {
    var startedAt = Date.now();
    var raised = null;
    try {
      await loadPage(driver, url, READY_ID, { timeout: TIMEOUT,
                                              retryDelay: RETRY_DELAY });
    } catch (e) {
      raised = e;
    }
    var elapsed = Date.now() - startedAt;
    assert.ok(raised, "loadPage() returned for a page with no #" + READY_ID +
              " in it.");
    assert.strictEqual(srv.requestsForThePage(), 1,
        "A page that loaded must not be retried — retrying trebles the time " +
        "every genuine breakage takes to report. The target saw " +
        srv.requestsForThePage() + " request(s).");
    assert.ok(elapsed < TIMEOUT * 2,
        "One attempt should cost about one timeout (" + TIMEOUT + "ms); this " +
        "took " + elapsed + "ms, which is more than one attempt's worth.");
    assert.ok(/not Chrome's error page/.test(raised.message),
        "The failure must say the document was ours, so the reader is not " +
        "sent looking at the network. Got: " + raised.message);
    log.info("C: failed on the first attempt in " + elapsed + "ms: " +
             raised.message.replace(/\n/g, " | "));
  });
  log.debug("Leaving doesNotRetryAPageThatLoaded().");
}

// D. Nothing listening at all — the OTHER half of the split page_load.js
// describes, where chromedriver reports the failure by THROWING out of
// `driver.get()`. The helper must handle that path too, and it must still end
// with a message naming the code rather than with chromedriver's raw error.
async function handlesAConnectionThatIsNeverEstablished(driver) {
  log.debug("Entering handlesAConnectionThatIsNeverEstablished().");
  log.info("D: a port with nothing listening on it.");
  // Take a port and give it straight back, so the address is one nothing is
  // bound to. Asking the OS is better than picking a number: a hard-coded port
  // is one somebody else's service is eventually on, and this check would then
  // pass or fail on what that service answered.
  var probe = net.createServer();
  await new Promise(function (resolve) {
    probe.listen(0, "127.0.0.1", resolve);
  });
  var port = probe.address().port;
  await new Promise(function (resolve) {
    probe.close(resolve);
  });
  var url = "http://127.0.0.1:" + port + "/page_load_retry.html";
  var raised = null;
  try {
    await loadPage(driver, url, READY_ID, { timeout: TIMEOUT,
                                            retryDelay: RETRY_DELAY });
  } catch (e) {
    raised = e;
  }
  assert.ok(raised, "loadPage() returned for a port nothing is listening on.");
  assert.ok(/ERR_[A-Z_]+/.test(raised.message),
      "A refused connection must be reported with its code as well. Got: " +
      raised.message);
  log.info("D: reported the refusal: " + raised.message.split("\n")[0]);
  log.debug("Leaving handlesAConnectionThatIsNeverEstablished().");
}

async function test() {
  log.debug("Entering test().");
  var options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless=new", "--no-sandbox",
                         "--disable-dev-shm-usage", "--window-size=1400,1400");
  }
  browserFlags.addBrowserAccessFlags(options, "http://127.0.0.1");
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await recoversFromADroppedConnection(driver);
    await reportsTheErrorCodeWhenEveryAttemptFails(driver);
    await doesNotRetryAPageThatLoaded(driver);
    await handlesAConnectionThatIsNeverEstablished(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    log.debug("Leaving test(). Failed.");
    await driver.quit();
    process.exit(1);
  }
  await driver.quit();
  log.debug("Leaving test().");
}

test();
