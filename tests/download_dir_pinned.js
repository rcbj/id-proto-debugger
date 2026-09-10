// File: download_dir_pinned.js
//
// No browser test may leave a file in the developer's home directory.
//
// ---------------------------------------------------------------------------
// Why this needs a test, and why it needed one twice.
//
// Several pages here have a Download button — the keystore matrix on the
// Digital Signature, JWT Tools and Encryption / Decryption pages, the key pair
// on the PKI page — and a test that drives one writes a real file. Where it
// writes it is the browser's default download directory, and on a host run
// (./local-run-tests.sh, ./remote-run-tests.sh) the browser is the developer's
// own Chrome, whose default is ~/Downloads.
//
// NOTHING FAILS WHEN THAT HAPPENS. The assertion is on the page's own status
// line — "Downloaded rsa-keys.pem" — which reads the same wherever the file
// went, so the run is green and the only evidence is somebody else's home
// directory filling up with key material. On 2026-09-03 this one held 71
// copies each of `ml-kem-keys (N).pem` and `ecies-keys.jwk (N).json`, one pair
// per run since 2026-08-27, beside the keystore matrices from before the first
// fix.
//
// THE FIRST FIX WAS PER TEST, WHICH IS WHY IT CAME BACK. jwt_tools.js and
// digital_signature.js each grew a throwaway temp directory, four Chrome user
// preferences and a CDP call of their own. encryption_tools.js then arrived
// with a key-download section built on the same client/src/key_material.js and
// none of those four lines, because there was nothing to tell whoever wrote it
// that they existed. A rule that lives in the tests that remembered it
// protects only those tests.
//
// The rule now lives in browser_flags.js section (6) and is reached from
// addBrowserAccessFlags() and addStsTrustFlags(), the two functions every
// browser test in this suite already calls. This test is what keeps that true:
// it fails when one of those two stops applying it, when a test builds a Chrome
// driver without going through either, and when a second caller of
// setUserPreferences() appears — that setter REPLACES the preference map
// rather than merging into it, so a second caller silently drops the download
// directory and puts the files straight back in ~/Downloads.
//
// No browser and no services: node only, so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const chrome = require("selenium-webdriver/chrome");
const bunyan = require("bunyan");
const { Command, Option } = require("commander");

var log = bunyan.createLogger({
  name: "download_dir_pinned",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to info
      // loses only the configured verbosity.
      return "info";
    }
  })()
});

const browserFlags = require("./browser_flags.js");

// A test drives a browser if it asks selenium for one. Both quotings appear.
const BUILDS_A_DRIVER = /forBrowser\(\s*['"]chrome['"]\s*\)/;

// The two functions section (6) is reached from. A driver-building test must
// name at least one of them; how it imports them (destructured or through the
// module object) is not this test's business.
const A_DOOR = /\b(?:addBrowserAccessFlags|addStsTrustFlags)\s*\(/;

// A click whose target names a download, in any of the three shapes this suite
// writes one: clickButton(driver, pane, 'Download Keys'),
// click(driver, onclickBtn("downloadSigningKeys")) and
// click(driver, onclickBtn(cfg.download)). Deliberately loose — a false
// positive costs one extra line in a test, and a false negative is the defect
// this whole file is about.
const CLICKS_A_DOWNLOAD = /\bclick\w*\s*\([^;]{0,300}?[Dd]ownload/;

// Reads every .js beside this file once. `name -> source`.
function testSources() {
  log.debug("Entering testSources().");
  const sources = {};
  fs.readdirSync(__dirname)
    .filter(function (one) {
      return /\.js$/.test(one);
    })
    .forEach(function (one) {
      sources[one] = fs.readFileSync(path.join(__dirname, one), "utf8");
    });
  log.debug("Leaving testSources(). " + Object.keys(sources).length +
            " file(s).");
  return sources;
}

// (1) The rule is where it is claimed to be, and both doors apply it.
function bothDoorsApplyTheRule(sources) {
  log.debug("Entering bothDoorsApplyTheRule().");
  ["addDownloadDirFlags", "pinDownloadDir", "downloadDir"]
    .forEach(function (one) {
      assert.strictEqual(typeof browserFlags[one], "function",
        "browser_flags.js no longer exports " + one + "(). Section (6) of " +
        "that file is what keeps a keystore download out of the " +
        "developer's home directory, and every browser test reaches it " +
        "through those exports.");
    });
  const source = sources["browser_flags.js"];
  assert.ok(source,
    "browser_flags.js was not found beside this test, so nothing was " +
    "checked. This test must fail rather than pass vacuously.");
  ["addBrowserAccessFlags", "addStsTrustFlags"].forEach(function (fn) {
    const body = functionBody(source, fn);
    assert.ok(body,
      "browser_flags.js has no function " + fn + "() any more. It is one of " +
      "the two doors every browser test in this suite goes through, which " +
      "is why the download directory is applied from it.");
    assert.ok(/addDownloadDirFlags\s*\(/.test(body),
      fn + "() in browser_flags.js no longer calls addDownloadDirFlags(). " +
      "That call is the only thing standing between a Download button in a " +
      "test and the developer's ~/Downloads, and removing it breaks NO " +
      "assertion anywhere: the status line every download test reads says " +
      "\"Downloaded ...\" whatever directory the file went to.");
  });
  log.info("[doors] OK — addBrowserAccessFlags() and addStsTrustFlags() both " +
           "apply the download directory.");
  log.debug("Leaving bothDoorsApplyTheRule().");
}

// The text of one top-level function, from its `function name(` to the line
// that closes it at column 0. Enough for "does this call that", and it does
// not need a parser.
function functionBody(source, name) {
  log.debug("Entering functionBody(). name=" + name);
  const at = source.indexOf("\nfunction " + name + "(");
  if (at === -1) {
    log.debug("Leaving functionBody(). Not found.");
    return null;
  }
  const rest = source.slice(at + 1);
  const end = rest.indexOf("\n}\n");
  const body = end === -1 ? rest : rest.slice(0, end);
  log.debug("Leaving functionBody(). " + body.length + " characters.");
  return body;
}

// (2) Every test that builds a Chrome driver goes through one of the doors.
function everyBrowserTestGoesThroughADoor(sources) {
  log.debug("Entering everyBrowserTestGoesThroughADoor().");
  const drivers = Object.keys(sources).filter(function (one) {
    return BUILDS_A_DRIVER.test(sources[one]);
  });
  assert.ok(drivers.length > 50,
    "only " + drivers.length + " file(s) beside this test look like they " +
    "build a Chrome driver, and this suite has upwards of seventy. The " +
    "detection is wrong rather than the suite, and a detection that finds " +
    "nothing passes this test while checking nothing.");
  const stragglers = drivers.filter(function (one) {
    return !A_DOOR.test(sources[one]);
  });
  assert.deepStrictEqual(stragglers, [],
    "these tests build a Chrome driver without calling " +
    "addBrowserAccessFlags() or addStsTrustFlags():\n  " +
    stragglers.join("\n  ") + "\nThose two are where browser_flags.js " +
    "section (6) points the browser's downloads at a throwaway directory, " +
    "so a test outside them writes any file it downloads into the " +
    "developer's ~/Downloads — silently, since the page's status line reads " +
    "the same either way. Add the call rather than a private copy of the " +
    "four preferences: that is exactly how this regressed once already.");
  log.info("[doors] OK — all " + drivers.length + " driver-building tests " +
           "pass through one.");
  log.debug("Leaving everyBrowserTestGoesThroughADoor().");
}

// (3) One caller of setUserPreferences(), because it replaces rather than
//     merges.
function oneCallerOfSetUserPreferences(sources) {
  log.debug("Entering oneCallerOfSetUserPreferences().");
  const callers = Object.keys(sources).filter(function (one) {
    return one !== "download_dir_pinned.js" &&
        /\.setUserPreferences\s*\(/.test(sources[one]);
  });
  assert.deepStrictEqual(callers, ["browser_flags.js"],
    "setUserPreferences() is called from " + callers.join(", ") + ". " +
    "selenium-webdriver's chromium.Options assigns the map it is given " +
    "(`this.options_.prefs = prefs`) rather than merging into it, so a " +
    "second caller REPLACES the download directory section (6) set and puts " +
    "that test's downloads back in ~/Downloads with nothing failing. Pass " +
    "the preference to browserFlags.addDownloadDirFlags(options, extra) " +
    "instead.");
  log.info("[prefs] OK — browser_flags.js is the only caller of " +
           "setUserPreferences().");
  log.debug("Leaving oneCallerOfSetUserPreferences().");
}

// (4) A test that clicks a Download button also pins the running browser.
function everyDownloadingTestPinsTheBrowser(sources) {
  log.debug("Entering everyDownloadingTestPinsTheBrowser().");
  const downloaders = Object.keys(sources).filter(function (one) {
    return BUILDS_A_DRIVER.test(sources[one]) &&
        CLICKS_A_DOWNLOAD.test(sources[one]);
  });
  assert.ok(downloaders.length >= 3,
    "only " + downloaders.length + " test(s) look like they click a " +
    "Download button, and digital_signature.js, jwt_tools.js and " +
    "encryption_tools.js all do. The detection is wrong rather than the " +
    "suite.");
  const unpinned = downloaders.filter(function (one) {
    return !/pinDownloadDir\s*\(/.test(sources[one]);
  });
  assert.deepStrictEqual(unpinned, [],
    "these tests click a Download button without calling " +
    "browserFlags.pinDownloadDir(driver) after building the driver:\n  " +
    unpinned.join("\n  ") + "\nThe user preference the doors apply is " +
    "already enough on the Chrome and chromedriver this suite pins; this is " +
    "the same instruction to the browser that is running, for the day one " +
    "of them reads the profile differently. It is one line after the " +
    "Builder.");
  log.info("[cdp] OK — all " + downloaders.length + " downloading tests pin " +
           "the running browser too: " + downloaders.join(", ") + ".");
  log.debug("Leaving everyDownloadingTestPinsTheBrowser().");
}

// (5) What the doors actually put on a real chrome.Options — the check that
//     survives a rename of anything above.
function theOptionsCarryATemporaryDirectory() {
  log.debug("Entering theOptionsCarryATemporaryDirectory().");
  const home = os.homedir();
  [
    ["addBrowserAccessFlags", function (options) {
      return browserFlags.addBrowserAccessFlags(options,
          "http://client:3000");
    }],
    ["addStsTrustFlags", function (options) {
      return browserFlags.addStsTrustFlags(options);
    }],
    ["addDownloadDirFlags", function (options) {
      return browserFlags.addDownloadDirFlags(options);
    }]
  ].forEach(function (pair) {
    const name = pair[0];
    const options = new chrome.Options();
    pair[1](options);
    // chrome.Options extends Capabilities, and the chromedriver-specific
    // half is one capability under a vendor key. That is the public way to
    // read back what setUserPreferences() wrote.
    const prefs = (options.get("goog:chromeOptions") || {}).prefs || {};
    const dir = prefs["download.default_directory"];
    assert.ok(dir,
      name + "() left no download.default_directory on the options it was " +
      "given, so a browser started with them downloads into whatever the " +
      "profile's default is — ~/Downloads on any host run.");
    assert.strictEqual(prefs["download.prompt_for_download"], false,
      name + "() left download.prompt_for_download unset or true. A prompt " +
      "in a headless browser is a download that never completes and a " +
      "status line that never changes.");
    assert.ok(dir.indexOf(path.join(os.tmpdir(), "")) === 0,
      name + "() pointed downloads at " + dir + ", which is not under " +
      os.tmpdir() + ".");
    assert.ok(dir.indexOf(home) !== 0,
      name + "() pointed downloads at " + dir + ", which is inside the " +
      "home directory this whole file exists to keep files out of.");
    assert.ok(fs.existsSync(dir),
      name + "() named a download directory that does not exist (" + dir +
      "). Chrome falls back to its default when it cannot write there, " +
      "which is the failure this test is about, arriving silently.");
  });
  // One directory per process: two doors on one options object must not be
  // two directories, and a test that calls both would otherwise get whichever
  // ran last.
  assert.strictEqual(browserFlags.downloadDir(), browserFlags.downloadDir(),
    "browserFlags.downloadDir() returned two different directories on two " +
    "calls. It is memoised on purpose: the doors are called more than once " +
    "per test, and the exit handler that removes it removes one path.");
  log.info("[options] OK — both doors leave a throwaway directory under " +
           os.tmpdir() + " on the options: " + browserFlags.downloadDir());
  log.debug("Leaving theOptionsCarryATemporaryDirectory().");
}

// (6) A driver that refuses the CDP command is not a failed test.
async function aRefusedCdpCommandIsNotAFailure() {
  log.debug("Entering aRefusedCdpCommandIsNotAFailure().");
  const refusing = {
    sendDevToolsCommand: function () {
      return Promise.reject(new Error("unknown command: " +
          "Browser.setDownloadBehavior"));
    }
  };
  await browserFlags.pinDownloadDir(refusing);
  log.info("[cdp] OK — a driver that refuses Browser.setDownloadBehavior is " +
           "reported and does not throw; the preference still applies.");
  log.debug("Leaving aRefusedCdpCommandIsNotAFailure().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  const sources = testSources();
  bothDoorsApplyTheRule(sources);
  everyBrowserTestGoesThroughADoor(sources);
  oneCallerOfSetUserPreferences(sources);
  everyDownloadingTestPinsTheBrowser(sources);
  theOptionsCarryATemporaryDirectory();
  await aRefusedCdpCommandIsNotAFailure();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("download_dir_pinned")
  .description("Verify that no browser test can write a downloaded file " +
               "into the developer's home directory.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
