// File: browser_tests_headless.js
//
// Every browser test in this suite must start Chrome HEADLESS by default.
//
// This is not a style preference. A test that builds a driver without a
// headless argument opens a real window, and it does that in three places that
// each fail differently:
//
//   * on a developer's desktop it steals focus for the length of the run —
//     dozens of windows appearing and vanishing while the machine is being used
//     for something else, which is how this was noticed;
//   * on a CI runner there is usually no display at all, so the run dies at
//     `session not created` / `unable to discover open window`, naming the page
//     the test was about to visit rather than the missing flag;
//   * on the containerized suite it is a Chrome inside a container with no X
//     server, the same failure again.
//
// The mistake is easy and silent: a browser test is normally written by copying
// a neighbour, and `browserFlags.addBrowserAccessFlags(options, baseUrl)` looks
// like it configures the browser completely — it does not, it deals with the
// secure-context and private-network hazards only and says nothing about
// headless mode. `kerberos_delegation_page.js` was written that way and popped
// a window on every run.
//
// So this reads the suite's own sources: any file that builds a Selenium driver
// must pass a --headless argument, and if it keeps the customary `headless`
// variable so a human can watch a run, that variable must DEFAULT to true. An
// opt-out is fine; an opt-in is what this refuses.
//
// No browser, no services and no client/src: it reads this directory, which is
// present in a checkout and in the tests image alike, so it never skips.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "browser_tests_headless",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const TEST_DIR = __dirname;

// How many driver-building tests this suite is known to have. A source scan
// that finds nothing passes vacuously, and a scan that suddenly finds four
// files where it used to find forty has stopped matching rather than found a
// tidier suite. Both are the failure mode this suite calls "a test that quietly
// does nothing", so the count is asserted too. It is a floor, not an equality:
// adding a browser test must not fail this.
const MIN_BROWSER_TESTS = 25;

// A line that is only a comment is not code — this very file quotes
// `--headless` in prose a dozen times, and so do several of the tests it reads.
function isComment(text) {
  log.debug("Entering isComment().");
  log.debug("Leaving isComment().");
  return /^\s*(\/\/|\*|\/\*)/.test(text);
}

// Bracket depth of a fragment with string literals removed first, so a quoted
// bracket cannot skew it. Only brackets that continue an EXPRESSION count: an
// open `{` starts a block, and reading on through a block would join this
// statement to whatever follows it. Same approximation as
// xml_parse_inert.js's, and for the same reason.
function bracketDepth(text) {
  log.debug("Entering bracketDepth().");
  const bare = text.replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, "");
  let depth = 0;
  for (const ch of bare) {
    if (ch === "(" || ch === "[") depth += 1;
    if (ch === ")" || ch === "]") depth -= 1;
  }
  log.debug("Leaving bracketDepth().");
  return depth;
}

// The file as STATEMENTS rather than lines. Every check below is about a call,
// and an 80-column limit means a call is routinely three lines:
//
//   options.addArguments("--headless=new", "--no-sandbox",
//       "--disable-dev-shm-usage", "--window-size=1400,1400");
//
// A check anchored to a single line reads that as an addArguments with no
// headless flag and reports a test that is perfectly fine — which is the
// documented way this class of check breaks (see tests/CLAUDE.md).
function statements(text) {
  log.debug("Entering statements().");
  const raw = text.split("\n").map(function (line, index) {
    return { number: index + 1, text: line };
  }).filter(function (line) {
    return !isComment(line.text);
  });
  const CONTINUES = /[,+&|=.([?:]\s*$/;
  log.debug("Leaving statements().");
  return raw.map(function (line, i) {
    let text = line.text;
    let k = i;
    while (k + 1 < raw.length && k - i < 8 &&
           (bracketDepth(text) > 0 || CONTINUES.test(text))) {
      k += 1;
      text += " " + raw[k].text.trim();
    }
    return { number: line.number, text: text };
  });
}

function testFiles() {
  log.debug("Entering testFiles().");
  const files = fs.readdirSync(TEST_DIR).filter(function (name) {
    return /\.js$/.test(name) && name !== path.basename(__filename);
  }).sort().map(function (name) {
    return path.join(TEST_DIR, name);
  });
  log.debug("Leaving testFiles().");
  return files;
}

// A file that starts a browser. Both halves are required: `new Builder()` is
// Selenium's, and `forBrowser` is what turns it into a real session — a module
// that merely mentions Builder in a comment has neither.
function buildsADriver(text) {
  log.debug("Entering buildsADriver().");
  const builds = /new\s+Builder\s*\(\s*\)/.test(text) &&
      /\.forBrowser\s*\(/.test(text);
  log.debug("Leaving buildsADriver().");
  return builds;
}

// --- 1. every browser test passes a headless argument -----------------------

function everyBrowserTestIsHeadless(files) {
  log.debug("Entering everyBrowserTestIsHeadless().");
  log.info("[headless] Every test that builds a driver must pass " +
      "--headless.");
  const browserTests = [];
  const offences = [];
  let legacyMode = 0;
  files.forEach(function (file) {
    const text = fs.readFileSync(file, "utf8");
    if (!buildsADriver(text)) {
      return;
    }
    const name = path.basename(file);
    browserTests.push(name);
    // The flag has to reach chrome through addArguments — a bare mention of
    // the word anywhere in the file (a comment, a CLI option description,
    // `log.info("headless = false")`) proves nothing.
    const flags = statements(text).filter(function (line) {
      return /addArguments\s*\(/.test(line.text) &&
          /--headless/.test(line.text);
    });
    if (flags.length === 0) {
      offences.push(name + "  builds a driver but never passes --headless " +
          "to addArguments()");
      return;
    }
    if (!flags.some(function (line) {
      return /--headless=new/.test(line.text);
    })) {
      // Not a failure: sixteen of the older tests here use bare --headless and
      // are headless, which is what this check is about. It IS worth counting,
      // because in the image's pinned Chrome 121 the bare spelling selects the
      // old implementation, where
      // --unsafely-treat-insecure-origin-as-secure has no effect and
      // crypto.subtle stays undefined on http://client:3000. See
      // tests/CLAUDE.md.
      legacyMode += 1;
      log.debug("[headless] " + name + " uses bare --headless (old mode " +
          "in Chrome 121).");
    }
  });
  assert.ok(browserTests.length >= MIN_BROWSER_TESTS,
    "found only " + browserTests.length + " tests that build a Selenium " +
        "driver, expected at least " + MIN_BROWSER_TESTS + ". This check " +
        "reads sources, so far too few matches means the detection stopped " +
        "working, not that the suite shrank.");
  assert.deepStrictEqual(offences, [],
    "these tests start Chrome with a VISIBLE window. On a desktop that " +
        "steals focus for the whole run;\non a CI runner or in a container " +
        "there is no display at all and the session simply fails to " +
        "start,\nnaming the page the test was about to visit:\n  " +
    offences.join("\n  "));
  log.info("[headless] OK — all " + browserTests.length +
      " driver-building tests pass --headless (" + legacyMode +
      " with the bare spelling, which is the old mode in Chrome 121).");
  log.debug("Leaving everyBrowserTestIsHeadless().");
  return browserTests;
}

// --- 2. headless is the DEFAULT, not an opt-in ------------------------------

function headlessIsTheDefault(files) {
  log.debug("Entering headlessIsTheDefault().");
  log.info("[default] A test's `headless` variable must start out true.");
  const offences = [];
  let checked = 0;
  files.forEach(function (file) {
    const text = fs.readFileSync(file, "utf8");
    if (!buildsADriver(text)) {
      return;
    }
    const name = path.basename(file);
    // The convention across this suite is a module-scope `var headless =
    // true;` that a --no-headless / -h false flag can clear for a human
    // watching a run. That is fine. What is not fine is the same variable
    // initialized false — the flag then only appears when somebody asks for
    // it, and every unattended run opens a window.
    const declarations = statements(text).filter(function (line) {
      return /^\s*(var|let|const)\s+headless\s*=/.test(line.text);
    });
    if (declarations.length === 0) {
      return;
    }
    checked += 1;
    declarations.forEach(function (line) {
      if (/^\s*(var|let|const)\s+headless\s*=\s*true\s*;/.test(line.text)) {
        return;
      }
      offences.push(name + ":" + line.number + "  " +
          line.text.trim().slice(0, 90));
    });
  });
  assert.deepStrictEqual(offences, [],
    "these tests make headless mode an OPT-IN. It has to be the default, " +
        "with the flag clearing it:\n  " +
    offences.join("\n  "));
  log.info("[default] OK — " + checked +
      " tests keep a headless switch and all of them default to true.");
  log.debug("Leaving headlessIsTheDefault().");
}

// --- 3. the two flags that let Chrome START in a container ------------------
//
// --no-sandbox and --disable-dev-shm-usage are in the same class as --headless
// and are missed the same way, so they are checked in the same place. The
// containerized suite runs Chrome with no user namespaces for its sandbox to
// use and with docker's default 64MB /dev/shm, which a renderer outgrows;
// without these two the browser exits during startup and chromedriver reports
//
//   session not created: Chrome failed to start: exited normally.
//   (session not created: DevToolsActivePort file doesn't exist)
//
// before the first driver.get(). That message names no flag, no page and no
// file, and a HOST run passes — so the only place this is visible is the
// containerized suite, which is the one that matters.
//
// pki_page.js and pki_mutual_tls.js were written without them and were the only
// two of fifty driver-building tests here in that state. Both were copied from
// a neighbour, like kerberos_delegation_page.js above; what they copied was the
// headless line and the browserFlags call, which between them look complete.
function everyBrowserTestCanStartInAContainer(files) {
  log.debug("Entering everyBrowserTestCanStartInAContainer().");
  log.info("[container] Every test that builds a driver must pass " +
      "--no-sandbox and --disable-dev-shm-usage.");
  const REQUIRED = ["--no-sandbox", "--disable-dev-shm-usage"];
  const offences = [];
  let checked = 0;
  files.forEach(function (file) {
    const text = fs.readFileSync(file, "utf8");
    if (!buildsADriver(text)) {
      return;
    }
    const name = path.basename(file);
    checked += 1;
    // As in section 1: the flag has to reach chrome through addArguments, so a
    // mention in a comment or a log line does not count. statements() has
    // already joined a wrapped call back into one string.
    const args = statements(text).filter(function (line) {
      return /addArguments\s*\(/.test(line.text);
    });
    const missing = REQUIRED.filter(function (flag) {
      return !args.some(function (line) {
        return line.text.indexOf(flag) !== -1;
      });
    });
    if (missing.length > 0) {
      offences.push(name + "  never passes " + missing.join(" or ") +
          " to addArguments()");
    }
  });
  assert.ok(checked >= MIN_BROWSER_TESTS,
    "found only " + checked + " tests that build a Selenium driver, " +
        "expected at least " + MIN_BROWSER_TESTS + ". As in section 1, far " +
        "too few matches means the detection stopped working.");
  assert.deepStrictEqual(offences, [],
    "these tests cannot start Chrome in the tests image. The failure they " +
        "produce is\n  session not created: Chrome failed to start: " +
        "exited normally (DevToolsActivePort file doesn't exist)\nwhich " +
        "names neither the flag nor this rule, and it does NOT reproduce " +
        "on a host run:\n  " +
    offences.join("\n  "));
  log.info("[container] OK — all " + checked +
      " driver-building tests pass both flags.");
  log.debug("Leaving everyBrowserTestCanStartInAContainer().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Every browser test starts Chrome headless.");
  const files = testFiles();
  const browserTests = everyBrowserTestIsHeadless(files);
  headlessIsTheDefault(files);
  everyBrowserTestCanStartInAContainer(files);
  log.debug("the driver-building tests are: " + browserTests.join(", "));
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("browser_tests_headless")
  .description("Verify that every Selenium test in this suite starts Chrome " +
      "headless by default.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
