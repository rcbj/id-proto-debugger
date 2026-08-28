// File: driver_quit_reachable.js
//
// No test in this suite may call process.exit() while a WebDriver session is
// open.
//
// This is not a style preference either, and it is the most expensive rule in
// this directory to break. `process.exit()` is SYNCHRONOUS TERMINATION: the
// `finally` of an `async` function needs a microtask turn that never comes, so
//
//   } catch (e) {
//     log.error(e.message);
//     process.exit(1);          // <-- terminates here
//   } finally {
//     await driver.quit();      // <-- never runs
//   }
//
// quits nothing. Thirty-nine files in this directory were written that way,
// and none of them looked wrong: the `finally` is right there.
//
// What that costs is not one process. A browser job is `node` ->
// `chromedriver` -> `chrome`, and one headless Chrome is about FIFTEEN OS
// processes (browser, two crashpad handlers, two zygotes, a gpu process, the
// network and storage services, a renderer per frame); only the first of the
// three is anybody's child. Selenium's own exit hook
// (selenium-webdriver/io/exec.js) sends SIGTERM to CHROMEDRIVER and nothing at
// all to the browser it launched, so chromedriver dies and Chrome is orphaned
// and stays resident. Measured on 2026-08-26: ONE failing job left 11 Chrome
// processes behind, and a run of this suite left 559 of them, which exhausted
// the machine's memory and cost a reboot.
//
// `run-report.js` now spawns every job `detached` and kills the whole process
// GROUP when the job ends, which is a backstop for a suite run. It is not a
// reason to skip this check, for two reasons: it does not help anybody running
// `node tests/foo.js` by hand, which is how a browser test is developed; and a
// backstop that is never exercised is a backstop nobody notices has broken.
//
// THREE shapes leak, and the second and third are the ones that get missed:
//
//   1. process.exit() in the CATCH of a try whose finally quits — the shape
//      above.
//   2. process.exit() in the TRY BODY. It skips the finally exactly as
//      thoroughly. Five files validated PKCE_ENABLED this way.
//   3. process.exit() in a HELPER called from that try. It skips the CALLER's
//      finally, and nothing at the call site suggests it could.
//      `tokenDetailPage()` in oidc_authorization_code.js did this.
//
// The fix in every case is the same shape: record the failure, let the
// `finally` quit the driver, and exit AFTER the try statement has finished —
// or, inside the try body or a helper, `throw` and let the catch do it.
//
// This parses rather than greps. A regex over these files cannot tell the
// catch of a quitting try from the `test().catch(...)` at the bottom of the
// file — every one of these files has the second, and it is correct there —
// and CLAUDE.md already records two source-inspection tests in this suite that
// silently stopped matching when a line was wrapped. acorn is a dependency of
// this package for exactly this.
//
// No browser, no services and no client/src: it reads this directory, which is
// present in a checkout and in the tests image alike, so it never skips.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const acorn = require("acorn");
const walk = require("acorn-walk");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "driver_quit_reachable",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const TEST_DIR = __dirname;

// How many driver-building tests this suite is known to have. A source scan
// that finds nothing passes vacuously, and one that suddenly finds four files
// where it used to find sixty has stopped matching rather than found a tidier
// suite — the failure this suite calls "a test that quietly does nothing". A
// floor, not an equality: adding a browser test must not fail this.
const MIN_BROWSER_TESTS = 50;

// Likewise for the guarded try statements themselves. Every driver-building
// test has at least one try/finally that quits, so finding far fewer of those
// than of the files means the finalizer detection has stopped working and this
// whole check has quietly become a no-op.
const MIN_GUARDED_TRIES = 50;

// Every .js file in this directory, sorted so the offence list is stable.
function testFiles() {
  log.debug("Entering testFiles().");
  const files = fs.readdirSync(TEST_DIR)
    .filter(function (name) {
      return name.endsWith(".js");
    })
    .sort()
    .map(function (name) {
      return path.join(TEST_DIR, name);
    });
  log.debug("Leaving testFiles(). " + files.length + " files.");
  return files;
}

// A `process.exit(...)` call node, or null. Written against the AST rather
// than the text so that `process . exit ( 1 )` and a wrapped argument list are
// the same call, which is the whole reason this file parses.
function isProcessExit(node) {
  log.debug("Entering isProcessExit().");
  if (node.type !== "CallExpression") {
    log.debug("Leaving isProcessExit(). Not a call.");
    return false;
  }
  const callee = node.callee;
  const hit = callee.type === "MemberExpression" &&
    !callee.computed &&
    callee.object.type === "Identifier" &&
    callee.object.name === "process" &&
    callee.property.type === "Identifier" &&
    callee.property.name === "exit";
  log.debug("Leaving isProcessExit(). " + hit);
  return hit;
}

// The [start, end) ranges of every try statement whose FINALIZER quits a
// driver. Those are the regions a process.exit() must not run inside, and the
// regions whose callees must not exit either.
function quittingTryRanges(ast, source) {
  log.debug("Entering quittingTryRanges().");
  const ranges = [];
  walk.full(ast, function (node) {
    if (node.type !== "TryStatement" || !node.finalizer) {
      return;
    }
    const finalizer = source.slice(node.finalizer.start, node.finalizer.end);
    if (finalizer.indexOf(".quit()") < 0) {
      return;
    }
    ranges.push({ start: node.start, end: node.end,
                  line: node.loc.start.line });
  });
  log.debug("Leaving quittingTryRanges(). " + ranges.length + " found.");
  return ranges;
}

// The name of every function CALLED anywhere inside one of those ranges. A
// helper that exits skips its caller's finally, and the call site gives no
// hint of it — this is shape 3 above.
function calleeNamesInside(ranges, source) {
  log.debug("Entering calleeNamesInside().");
  const names = new Set();
  ranges.forEach(function (range) {
    const segment = source.slice(range.start, range.end);
    const calls = segment.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g);
    for (const match of calls) {
      names.add(match[1]);
    }
  });
  log.debug("Leaving calleeNamesInside(). " + names.size + " names.");
  return names;
}

// The innermost named FunctionDeclaration containing a node, or null. Only
// declarations: an exit inside an anonymous callback is not reachable from a
// call site by name, and the trailing `test().catch(function (e) {...})` in
// every one of these files is exactly that — and is correct, because by then
// the driver has already been quit.
function enclosingDeclaration(ast, node) {
  log.debug("Entering enclosingDeclaration().");
  let best = null;
  walk.full(ast, function (candidate) {
    if (candidate.type !== "FunctionDeclaration" || !candidate.id) {
      return;
    }
    if (candidate.start <= node.start && candidate.end >= node.end) {
      if (!best || candidate.start > best.start) {
        best = candidate;
      }
    }
  });
  log.debug("Leaving enclosingDeclaration(). " +
      (best ? best.id.name : "none"));
  return best;
}

// Does this file actually OPEN a session? Parsed rather than grepped: this
// file and browser_tests_headless.js both quote `new Builder` in prose a
// dozen times, and an indexOf() for it reports them as browser tests that
// never quit — which is exactly the false positive this check must not have.
function buildsADriver(ast) {
  log.debug("Entering buildsADriver().");
  let found = false;
  walk.full(ast, function (node) {
    if (node.type === "NewExpression" &&
        node.callee.type === "Identifier" &&
        node.callee.name === "Builder") {
      found = true;
    }
  });
  log.debug("Leaving buildsADriver(). " + found);
  return found;
}

// Is this node preceded, among the statements of its own block, by a call to
// .quit()? That is how a test with no try/finally can still be correct:
// `page_load_retry.js` quits explicitly on both paths, immediately before
// each exit, and refusing that shape would be this check inventing a rule
// rather than enforcing the one that matters.
function quitPrecedesInBlock(ast, node) {
  log.debug("Entering quitPrecedesInBlock().");
  let block = null;
  walk.full(ast, function (candidate) {
    if (candidate.type !== "BlockStatement") {
      return;
    }
    if (candidate.start <= node.start && candidate.end >= node.end) {
      if (!block || candidate.start > block.start) {
        block = candidate;
      }
    }
  });
  if (!block) {
    log.debug("Leaving quitPrecedesInBlock(). No block.");
    return false;
  }
  const source = block.__source;
  for (const statement of block.body) {
    if (statement.start > node.start) {
      break;
    }
    if (statement.start <= node.start && statement.end >= node.end) {
      // The statement the exit is IN. A quit on this same statement would
      // have to be an argument to it, which is not the shape being allowed.
      continue;
    }
    if (source.slice(statement.start, statement.end).indexOf(".quit()") >= 0) {
      log.debug("Leaving quitPrecedesInBlock(). Quit found before it.");
      return true;
    }
  }
  log.debug("Leaving quitPrecedesInBlock(). No quit before it.");
  return false;
}

// --- the check --------------------------------------------------------------

function noExitCanSkipADriverQuit(files) {
  log.debug("Entering noExitCanSkipADriverQuit().");
  log.info("[quit] No process.exit() may run while a driver is open.");
  const offences = [];
  let browserTests = 0;
  let guardedTries = 0;

  files.forEach(function (file) {
    const name = path.basename(file);
    const source = fs.readFileSync(file, "utf8");
    // Only files that actually open a session. `new Builder()` is how every
    // one of them does it, and this file and browser_tests_headless.js quote
    // the phrase in prose — which is why the test is on the CALL, parsed.
    let ast;
    try {
      // Both allowances are what CommonJS actually is, not laxity: node
      // wraps every module in a function (so a top-level `return` is legal,
      // and webauthn_cross_impl.js uses one) and strips a `#!` line before
      // compiling (run-report.js has one). Without them those two files are
      // reported as offences for not parsing.
      ast = acorn.parse(source, { ecmaVersion: 2022, sourceType: "script",
                                  locations: true, allowHashBang: true,
                                  allowReturnOutsideFunction: true });
    } catch (e) {
      // A file in this directory that does not parse is a failure of this
      // check rather than a file to skip: it would silently stop being read.
      offences.push(name + "  does not parse (" + e.message + ")");
      return;
    }
    if (!buildsADriver(ast)) {
      return;
    }
    browserTests += 1;
    // quitPrecedesInBlock() needs the file's text to read a statement back.
    walk.full(ast, function (node) {
      if (node.type === "BlockStatement") {
        node.__source = source;
      }
    });

    const ranges = quittingTryRanges(ast, source);
    guardedTries += ranges.length;
    const helpers = calleeNamesInside(ranges, source);

    walk.full(ast, function (node) {
      if (!isProcessExit(node)) {
        return;
      }
      const line = node.loc.start.line;
      const inside = ranges.some(function (range) {
        return node.start > range.start && node.end < range.end;
      });
      if (inside) {
        offences.push(name + ":" + line + "  process.exit() inside a try " +
            "whose finally quits the driver (shapes 1 and 2)");
        return;
      }
      const declaration = enclosingDeclaration(ast, node);
      if (!declaration) {
        return;
      }
      const fname = declaration.id.name;
      // `test()` itself is where the exit BELONGS, after its own try has
      // finished — that is the fixed shape, not an offence.
      if (fname !== "test" && helpers.has(fname)) {
        offences.push(name + ":" + line + "  process.exit() in " + fname +
            "(), which is called from inside that try (shape 3)");
        return;
      }
      // A file with no quitting finally at all is not wrong by that fact
      // alone — it may quit explicitly on every path instead. What it may
      // not do is exit from the driver-holding function with no quit before
      // it anywhere in the same block.
      if (!ranges.length && fname === "test" &&
          !quitPrecedesInBlock(ast, node)) {
        offences.push(name + ":" + line + "  process.exit() in test(), " +
            "which builds a driver, with no driver.quit() before it and no " +
            "finally that quits");
      }
    });
  });

  assert.ok(browserTests >= MIN_BROWSER_TESTS,
    "found only " + browserTests + " tests that build a Selenium driver, " +
        "expected at least " + MIN_BROWSER_TESTS + ". This check reads " +
        "sources, so far too few matches means the detection stopped " +
        "working, not that the suite shrank.");
  assert.ok(guardedTries >= MIN_GUARDED_TRIES,
    "found only " + guardedTries + " try statements whose finally quits a " +
        "driver, across " + browserTests + " driver-building tests. Every " +
        "one of them has at least one, so this means the finalizer " +
        "detection stopped matching and this check had become a no-op.");
  assert.deepStrictEqual(offences, [],
    "process.exit() is synchronous termination: it SKIPS the finally that " +
        "quits the driver,\nleaving a full headless Chrome (~15 OS " +
        "processes) resident for the life of the machine.\nOne failing job " +
        "left 11 behind on 2026-08-26 and a whole run left 559, which cost " +
        "a reboot.\nRecord the failure, let the finally quit, and exit " +
        "after the try — or throw:\n  " +
    offences.join("\n  "));
  log.info("[quit] OK — " + browserTests + " driver-building tests, " +
      guardedTries + " try/finally blocks that quit, no reachable " +
      "process.exit() among them.");
  log.debug("Leaving noExitCanSkipADriverQuit().");
  return browserTests;
}

// The runner's own half of the rule. `detached` and the group kill are what
// catch a leak this file cannot see — a test that hangs, or one written after
// this check was last read — and they are two lines that a refactor of
// runJob() would drop without any test noticing. So they are asserted here,
// where the reason for them is written down.
function theRunnerReapsProcessGroups() {
  log.debug("Entering theRunnerReapsProcessGroups().");
  log.info("[runner] run-report.js must spawn detached and kill the group.");
  const runner = path.join(TEST_DIR, "run-report.js");
  const source = fs.readFileSync(runner, "utf8");
  // Read as statements rather than lines: CLAUDE.md records two checks in
  // this suite that stopped seeing a call the moment it was wrapped.
  const flat = source.replace(/\s+/g, " ");
  assert.ok(/detached:\s*true/.test(flat),
    "run-report.js no longer spawns jobs detached, so a job's chromedriver " +
        "and chrome are in the runner's own process group and cannot be " +
        "killed as a unit. Without it the group kill below reaps nothing.");
  assert.ok(/process\.kill\(\s*-\s*pgid/.test(flat),
    "run-report.js no longer kills the job's process GROUP (the leading " +
        "minus on the pid is what makes it a group). Killing the child " +
        "alone leaves the browser it started running.");
  assert.ok(/JOB_TIMEOUT_MS/.test(flat),
    "run-report.js no longer has a per-job timeout, so a job that hangs " +
        "holds its browser open for the whole run.");
  assert.ok(/process\.on\(\s*sig/.test(flat) || /SIGINT/.test(flat),
    "run-report.js no longer handles SIGINT. A detached child does NOT " +
        "receive the terminal's Ctrl-C, so without this, interrupting the " +
        "runner leaves the entire pool running with nothing left to reap it.");
  log.info("[runner] OK — detached spawn, group kill, timeout and signal " +
      "handling are all present.");
  log.debug("Leaving theRunnerReapsProcessGroups().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. No process.exit() while a driver is open.");
  const files = testFiles();
  const browserTests = noExitCanSkipADriverQuit(files);
  theRunnerReapsProcessGroups();
  log.debug("checked " + browserTests + " driver-building tests.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("driver_quit_reachable")
  .description("Verify that no test can call process.exit() while a " +
      "WebDriver session is open, and that run-report.js still reaps each " +
      "job's process group.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
