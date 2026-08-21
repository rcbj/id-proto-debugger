// File: oauth2_config_pane_layout.js
//
// The Configuration Parameters pane on oauth2_oidc_1.html and
// oauth2_oidc_2.html: do its fields stay inside the pane they are drawn in?
//
// ---------------------------------------------------------------------------
// Why this is a test rather than a look at the page.
//
// Bootstrap sizes every text input, select and textarea to a FIXED
// `width: 206px` (`input, textarea, .uneditable-input`), which outranks the
// `size="60"` several of these fields carry and takes no notice of the box it
// is in. The pane on page 2 is one of THREE flex columns — ~419px at 1366
// against ~854px on page 1 — so the label column plus that fixed width put
// every field's right edge on, and the four boolean `select`s 25px PAST, the
// pane's border; at an 820px viewport the pane is 196px and the selects hung
// 136px outside it. Nothing about that is visible on page 1 at a wide window,
// which is exactly why it survived: the same markup, the same stylesheet, and
// a defect only the narrower of the two panes shows.
//
// css/debugger.css fixes it by sizing the fields to their column
// (`.dbg-config-table`), and this file asserts BOTH halves — the outcome (no
// control crosses the pane's content edge) and the rule underneath it (a
// field's width tracks its cell rather than sitting at bootstrap's 206px).
// The second is what makes a failure legible: a width assertion that fails
// says the class stopped matching, where the geometry alone would only say
// that something, somewhere, got wider.
//
// It measures at several viewport widths because bootstrap-responsive.css
// steps the container between them (1170 / 940 / 724) and the panes step with
// it — one width would have missed this exact bug at 1366. The range stops at
// 768: below roughly 700 the three-column flex row itself stops being
// tenable (the pane is narrower than one long label), which is a layout
// question about the row rather than about these fields.
//
// It needs the SITE and nothing else — no api, no IdP, no mock STS. Every
// field it measures is in the served HTML rather than rendered by the bundle,
// so it is still a real check on a day the rest of the stack is down, and it
// runs unchanged against a deployed static site (both pages are carried
// there).
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "oauth2_config_pane_layout",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";

// Both pages carry the pane under the same id, with the same table, and it is
// collapsed on arrival on page 2 — the probe opens it either way.
const PAGES = ["oauth2_oidc_1.html", "oauth2_oidc_2.html"];

// The container steps at 1200 and 980 (bootstrap-responsive.css), so these
// straddle both. 1366 is the house viewport; 1000 and 900 are the widths at
// which page 2's pane is narrow enough that the old fixed field width hung a
// select 83px and 108px outside it.
const WIDTHS = [1366, 1280, 1100, 1000, 900, 820, 768];

// A field a page has and the other has not is not an error here — page 2 does
// not offer the device, introspection, revocation or registration endpoints —
// so each is measured where it exists. These four are the ones that carried
// the defect: a plain input, an input with a `size` attribute the stylesheet
// overrode anyway, and the two flavours of select.
const FIELDS = ["authorization_endpoint", "scopes_supported",
    "authorization_grant_type", "claims_parameter_supported"];

// Everything read out of one page, in one round trip. Written as a string and
// evaluated in the browser: there is no bunyan in there and a log line would
// be a ReferenceError reported as a page fault — see the repo-root CLAUDE.md.
// This function and everything it declares are therefore exempt from the
// Entering/Leaving convention.
//
// `over` is measured against the pane's CONTENT edge (border and padding
// removed), which is the line the user reads as "the pane". Tooltip bubbles
// are skipped: they are absolutely positioned hover popups and are meant to
// leave the pane.
const PROBE =
  "var ids = arguments[0];" +
  "var fs = document.getElementById('config_fieldset');" +
  "if (!fs) return { missing: true };" +
  "fs.style.display = 'block';" +
  "var pane = fs.closest('.dbg-pane');" +
  "var cs = getComputedStyle(pane);" +
  "var pr = pane.getBoundingClientRect();" +
  "var edge = pr.right - parseFloat(cs.paddingRight) -" +
  "    parseFloat(cs.borderRightWidth);" +
  "var over = [];" +
  "var all = fs.querySelectorAll('*');" +
  "for (var i = 0; i < all.length; i++) {" +
  "  var e = all[i];" +
  "  if (e.classList && e.classList.contains('tooltiptext')) continue;" +
  "  var r = e.getBoundingClientRect();" +
  "  if (r.width === 0 && r.height === 0) continue;" +
  "  if (r.right > edge + 0.5) {" +
  "    over.push({ tag: e.tagName, id: e.id || '', name: e.name || ''," +
  "                over: Math.round(r.right - edge)," +
  "                width: Math.round(r.width) });" +
  "  }" +
  "}" +
  "over.sort(function (a, b) { return b.over - a.over; });" +
  "var fields = {};" +
  "ids.forEach(function (id) {" +
  "  var e = document.getElementById(id);" +
  "  if (!e) { fields[id] = null; return; }" +
  "  var td = e.closest('td');" +
  "  var tcs = getComputedStyle(td);" +
  "  fields[id] = {" +
  "    width: Math.round(e.getBoundingClientRect().width)," +
  "    cellWidth: Math.round(td.getBoundingClientRect().width -" +
  "        parseFloat(tcs.paddingLeft) - parseFloat(tcs.paddingRight))," +
  "    tag: e.tagName" +
  "  };" +
  "});" +
  "var radio = fs.querySelector('input[type=\"radio\"]');" +
  "var box = fs.querySelector('input[type=\"checkbox\"]');" +
  "return {" +
  "  paneWidth: Math.round(pr.width)," +
  "  edgeGap: Math.round(pr.right - edge)," +
  "  tableIsStyled: !!fs.querySelector('table.dbg-config-table')," +
  "  over: over.slice(0, 10)," +
  "  overCount: over.length," +
  "  fields: fields," +
  "  radioWidth: radio ? Math.round(radio.getBoundingClientRect().width)" +
  "      : null," +
  "  checkboxWidth: box ? Math.round(box.getBoundingClientRect().width)" +
  "      : null" +
  "};";

// ---------------------------------------------------------------------------
// One page at one width: nothing in the pane crosses the pane's content edge.
// ---------------------------------------------------------------------------
function noControlEscapesThePane(m, page, width) {
  log.debug("Entering noControlEscapesThePane(). " + page + " @ " + width);
  const where = page + " at a " + width + "px viewport (pane " + m.paneWidth +
      "px)";
  assert.strictEqual(m.overCount, 0,
    where + ": " + m.overCount + " element(s) in the Configuration " +
        "Parameters pane stick out past its content edge, worst first: " +
        m.over.map(function (o) {
          return (o.id || o.name || o.tag.toLowerCase()) + " +" + o.over +
              "px (" + o.width + "px wide)";
        }).join(", ") + ". Bootstrap's fixed " +
        "`input, textarea { width: 206px }` is the usual cause — a field " +
        "that does not size to its column will " +
        "hang out of whichever pane is narrowest, and the narrowest here is " +
        "page 2's, which is one of three flex columns. See " +
        ".dbg-config-table in client/public/css/debugger.css.");
  log.debug("Leaving noControlEscapesThePane().");
}

// ---------------------------------------------------------------------------
// The rule underneath: each field fills its own table cell rather than sitting
// at bootstrap's fixed width. Asserted separately because it can break without
// anything looking wrong on page 1 — an 854px pane hides a 220px field
// perfectly well, and the next narrow pane is where it shows up.
// ---------------------------------------------------------------------------
function eachFieldSizesToItsColumn(m, page, width) {
  log.debug("Entering eachFieldSizesToItsColumn(). " + page + " @ " + width);
  assert.ok(m.tableIsStyled,
    page + ": the Configuration Parameters form has no " +
        "table.dbg-config-table on it. That class is what css/debugger.css " +
        "hangs the fluid field widths on; without it every field is back at " +
        "bootstrap's 206px regardless of the pane.");

  Object.keys(m.fields).forEach(function (id) {
    const f = m.fields[id];
    // Page 2 does not carry every field page 1 does. A field that is absent
    // is not measured; a field that is present is measured on both.
    if (!f) {
      log.debug("Skipping " + id + " — not on " + page + ".");
      return;
    }
    assert.ok(Math.abs(f.width - f.cellWidth) <= 2,
      page + " at " + width + "px: " + f.tag.toLowerCase() + " #" + id +
          " is " + f.width + "px wide in a " + f.cellWidth + "px cell. It " +
          "should fill the cell — a field pinned to some other width is a " +
          "field that will leave the pane as soon as the pane is narrower " +
          "than that width. 220px means bootstrap's `width: 206px` plus " +
          "padding is winning and the .dbg-config-table rule has stopped " +
          "matching.");
  });
  log.debug("Leaving eachFieldSizesToItsColumn().");
}

// ---------------------------------------------------------------------------
// The controls whose width is their appearance rather than their content stay
// intrinsic. This is the failure mode of the fix itself: a selector broadened
// to `input` would stretch a radio button across the pane, which is not a
// thing anybody would report as a bug but is not what a radio is.
// ---------------------------------------------------------------------------
function theBoxesAndRadiosStayIntrinsic(m, page, width) {
  log.debug("Entering theBoxesAndRadiosStayIntrinsic(). " + page);
  [["radio", m.radioWidth], ["checkbox", m.checkboxWidth]].forEach(
    function (pair) {
      if (pair[1] === null) {
        log.debug("No " + pair[0] + " in the pane on " + page + ".");
        return;
      }
      assert.ok(pair[1] <= 40,
        page + " at " + width + "px: an " + pair[0] + " in the pane is " +
            pair[1] + "px wide. The fluid-width rule is meant to reach text " +
            "inputs, selects and textareas only — a stretched " + pair[0] +
            " means it caught `input` outright.");
    });
  log.debug("Leaving theBoxesAndRadiosStayIntrinsic().");
}

// ---------------------------------------------------------------------------
// One page, every width.
// ---------------------------------------------------------------------------
async function thePaneHoldsItsFields(driver, page) {
  log.debug("Entering thePaneHoldsItsFields(). " + page);
  for (const width of WIDTHS) {
    await driver.manage().window().setRect({ width: width, height: 900 });
    await driver.get(baseUrl + "/" + page);
    // Wait on the field itself rather than on the fieldset: the pane is
    // collapsed on arrival on page 2, and a collapsed pane still contains
    // everything. See tests/CLAUDE.md on waiting for content.
    await driver.wait(until.elementLocated(By.id("authorization_endpoint")),
        20000);
    const m = await driver.executeScript(PROBE, FIELDS);
    assert.ok(!m.missing,
      page + " has no #config_fieldset on it. That is the Configuration " +
          "Parameters pane; if it was renamed, rename it here too rather " +
          "than dropping the page.");
    noControlEscapesThePane(m, page, width);
    eachFieldSizesToItsColumn(m, page, width);
    theBoxesAndRadiosStayIntrinsic(m, page, width);
    log.info(page + " @ " + width + ": pane " + m.paneWidth + "px, fields " +
        Object.keys(m.fields).filter(function (id) {
          return m.fields[id];
        }).map(function (id) {
          return id + "=" + m.fields[id].width + "px";
        }).join(", ") + ", nothing outside the pane.");
  }
  log.debug("Leaving thePaneHoldsItsFields().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The Configuration Parameters pane on both " +
      "OAuth2/OIDC pages at " + baseUrl + ".");

  const options = new chrome.Options();
  // --headless=new, never bare --headless: see tests/CLAUDE.md.
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1366,900",
      // Without this the scrollbar eats width, and a pane measured at 1366 is
      // really a pane at 1351.
      "--hide-scrollbars");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    for (const page of PAGES) {
      await thePaneHoldsItsFields(driver, page);
    }
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("oauth2_config_pane_layout")
  .description("Verify that every field in the Configuration Parameters " +
      "pane on oauth2_oidc_1.html and oauth2_oidc_2.html stays inside its " +
      "pane at every viewport width the container steps through, and that " +
      "the fields size to their column rather than to bootstrap's fixed " +
      "206px.")
  .addOption(new Option("-u, --url <url>",
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
