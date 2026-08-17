// File: kerberos_page_density.js
//
// The Kerberos workflow's SIX pages, measured: does the control each page
// exists for sit on the first screen?
//
// ---------------------------------------------------------------------------
// Why this is one test over six pages rather than an assertion in each page's
// own file.
//
// theConfigurationAndBothControlsFitOnOneScreen() in kerberos_as_page.js has
// protected the AS page since 2026-08-15, and the other five had nothing —
// which is exactly how they came to carry, between them, a 500px key pane, a
// configuration pane laid out one field per line, and three paragraphs of
// orientation above a paste box. Worse, the AS page's own guard could not see
// the defect they shared: bootstrap's `legend { line-height: 40px }` was back
// on every pane of every page, because the fix for it was written against
// `.krb-pane > legend` and the panes had since moved to the shared `.dbg-pane`
// chrome. Nothing matched the old selector, the rule was still in the sheet, and
// each page quietly paid ~19px per pane again.
//
// So this file measures ALL SIX, and asserts the two CSS facts underneath as
// well as the outcome — because a height assertion that fails tells you a page
// got taller, and these two tell you why:
//
//  * the pane legends are ~1.4 line-heights tall and not 40px, and
//  * `.krb-field` keeps the 4px bottom margin it asks for rather than losing it
//    to bootstrap's `input[type="text"]`, which outranks a bare class.
//
// It needs the SITE and nothing else — no KDC, no api. Every page's markup and
// stylesheet are static, and the buttons measured are in the served HTML rather
// than rendered by the bundle, so an unreachable KDC changes none of it. That is
// deliberate: this is the check that still runs on a day when the stack is half
// up, which is when a layout regression is most likely to be waved through.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "kerberos_page_density",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";

// 640px at 1366x768, the house standard — see the note in tests/navigation.js
// on CARD_HEIGHT_BUDGET and the same constant in kerberos_as_page.js. Headless
// Chrome has no toolbar, so its viewport is more generous than a real browser's;
// both limits are asserted below, and whichever is smaller is the one that
// bites.
const BUDGET = 640;

// Each page, and the control it exists for: the thing a reader must be able to
// reach without scrolling past the explanation to find it. Where a page has two
// equal first moves (the AS page's two AS-REQs, SPNEGO's two round trips) both
// are named, because fitting one of them is not fitting the page.
const PAGES = [
  { page: "kerberos.html",
    controls: ["krb_noreauth_button", "krb_preauth_button"] },
  { page: "kerberos_tgs.html", controls: ["krb_tgs_button"] },
  { page: "kerberos_ap.html", controls: ["krb_present_button"] },
  // Four exchanges on one page: only the first can be promised a place on the
  // first screen, and the point of the other three being below it is that they
  // are a sequence. Asserting all four would be asserting something false.
  { page: "kerberos_delegation.html", controls: ["krb_s4u2self_button"] },
  { page: "kerberos_decoder.html", controls: ["krb_decode_button"] },
  { page: "spnego.html",
    controls: ["krb_probe_button", "krb_authenticate_button"] },
];

// Everything read out of one page, in one round trip. Written as a string and
// evaluated in the browser: there is no bunyan in there and a log line would be
// a ReferenceError reported as a page fault — see the repo-root CLAUDE.md. This
// function and everything it declares are therefore exempt from the
// Entering/Leaving convention.
const PROBE =
  "var ids = arguments[0];" +
  "var bottom = function (id) {" +
  "  var e = document.getElementById(id);" +
  "  return e ? Math.round(e.getBoundingClientRect().bottom) : null; };" +
  "var legend = document.querySelector('.dbg-pane > .dbg-legend');" +
  "var field = document.querySelector('.krb-field');" +
  "var controls = {};" +
  "ids.forEach(function (id) { controls[id] = bottom(id); });" +
  "return {" +
  "  viewport: window.innerHeight," +
  "  controls: controls," +
  "  panes: document.querySelectorAll('.dbg-pane').length," +
  "  hScroll: document.documentElement.scrollWidth > window.innerWidth + 1," +
  "  legendHeight: legend ? Math.round(legend.getBoundingClientRect().height)" +
  "      : null," +
  "  legendLineHeight: legend ? getComputedStyle(legend).lineHeight : null," +
  "  fieldMarginBottom: field ? getComputedStyle(field).marginBottom : null," +
  "  folded: document.querySelectorAll('details.krb-more').length," +
  "  openFolds: document.querySelectorAll('details.krb-more[open]').length" +
  "};";

// ---------------------------------------------------------------------------
// One page: its control is reachable, and it does not scroll sideways to get
// there.
// ---------------------------------------------------------------------------
async function thePageFitsOnOneScreen(driver, spec) {
  log.debug("Entering thePageFitsOnOneScreen(). " + spec.page);
  await driver.get(baseUrl + "/" + spec.page);
  await driver.wait(until.elementLocated(By.id(spec.controls[0])), 20000);
  const m = await driver.executeScript(PROBE, spec.controls);
  const limit = Math.min(BUDGET, m.viewport);

  spec.controls.forEach(function (id) {
    const bottom = m.controls[id];
    assert.ok(bottom !== null,
      spec.page + " has no #" + id + " on it. That control is what the page " +
          "is for; if it was renamed, rename it here too rather than " +
          "dropping the row.");
    assert.ok(bottom <= limit,
      spec.page + ": #" + id + " ends at " + bottom + "px, past the " + limit +
          "px first screen (budget " + BUDGET + ", viewport " + m.viewport +
          "). Something above it grew. Measure before trimming: walk the " +
          "container's children printing height/top, the way the 2026-08-17 " +
          "pass did — two of the four biggest costs it found were CSS rules " +
          "that had stopped matching, not content.");
  });

  assert.ok(!m.hScroll,
    spec.page + " scrolls horizontally at 1366x768. A value this workflow " +
        "does not control (a base64url ticket, an SPN) has escaped its pane " +
        "— see the .krb-value note in css/kerberos.css.");
  log.info(spec.page + ": " + spec.controls.map(function (id) {
    return id + " ends at " + m.controls[id] + "px";
  }).join(", ") + " (limit " + limit + ", " + m.panes + " panes, " +
      m.folded + " folded sections)");
  log.debug("Leaving thePageFitsOnOneScreen().");
  return m;
}

// ---------------------------------------------------------------------------
// The two rules the heights rest on. Asserted separately because each has
// already been broken once WITHOUT any page looking wrong — a legend is a
// legend at either line-height, and 10px of margin under a field reads as
// spacing somebody chose.
// ---------------------------------------------------------------------------
function thePaneChromeIsNotBootstrapsDefault(m, page) {
  log.debug("Entering thePaneChromeIsNotBootstrapsDefault(). " + page);
  assert.ok(m.legendHeight !== null,
    page + " has no .dbg-pane > .dbg-legend on it, so the pane chrome this " +
        "checks cannot be measured. The panes moved to that structure on " +
        "2026-08-16; if they moved again, move this with them.");
  assert.ok(m.legendHeight <= 30,
    page + "'s first pane legend is " + m.legendHeight + "px tall, computed " +
        "line-height " + m.legendLineHeight + ". Bootstrap sets " +
        "`legend { line-height: 40px }` for its own 21px legends, so a 15px " +
        "word sits in a 40px box and every pane on the page pays ~19px. " +
        "css/kerberos.css overrides it on .dbg-legend — check that selector " +
        "still matches what the panes actually use. It stopped matching once " +
        "already, and the fix was still in the file.");

  assert.strictEqual(m.fieldMarginBottom, "4px",
    page + "'s .krb-field has a bottom margin of " + m.fieldMarginBottom +
        " rather than the 4px it asks for. Bootstrap's " +
        "`input[type=\"text\"] { margin-bottom: 10px }` is (0,1,1) and beats " +
        "a bare `.krb-field` at (0,1,0), which is why css/kerberos.css also " +
        "writes it as `input.krb-field`. Six pixels times ten fields a page " +
        "is not a rounding error.");
  log.debug("Leaving thePaneChromeIsNotBootstrapsDefault().");
}

// ---------------------------------------------------------------------------
// The prose is FOLDED, not deleted. This is the half of the pass that could be
// "fixed" by cutting the explanations, which would make every page fit and
// destroy the reason the workflow is worth using.
// ---------------------------------------------------------------------------
function theProseWasFoldedAndNotCut(driver, m, page) {
  log.debug("Entering theProseWasFoldedAndNotCut(). " + page);
  assert.ok(m.folded >= 2,
    page + " carries " + m.folded + " <details class=\"krb-more\"> " +
        "section(s). The long explanations on these pages are folded rather " +
        "than cut — if they have gone, they were deleted, and the page now " +
        "fits by saying less. Put them back inside a fold.");
  assert.strictEqual(m.openFolds, 0,
    page + " has " + m.openFolds + " fold(s) open on arrival. A fold that " +
        "starts open costs exactly what the prose cost before it was folded.");
  log.debug("Leaving theProseWasFoldedAndNotCut().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The six Kerberos pages at " + baseUrl + ".");

  const options = new chrome.Options();
  // --headless=new, never bare --headless: see tests/CLAUDE.md.
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1366,768",
      // Without this the scrollbar eats width and a page that fits at 1366
      // measures as scrolling sideways.
      "--hide-scrollbars");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    // The window has to be the size the budget is quoted at, and setting it
    // through the driver rather than only through the flag is what makes that
    // true in every chromedriver version this suite has met.
    await driver.manage().window().setRect({ width: 1366, height: 768 });
    for (const spec of PAGES) {
      const m = await thePageFitsOnOneScreen(driver, spec);
      thePaneChromeIsNotBootstrapsDefault(m, spec.page);
      theProseWasFoldedAndNotCut(driver, m, spec.page);
    }
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("kerberos_page_density")
  .description("Verify that each of the six Kerberos pages puts the control " +
      "it exists for on the first screen at 1366x768, and that the two CSS " +
      "rules that height rests on still match.")
  .addOption(new Option("-u, --url <url>",
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
