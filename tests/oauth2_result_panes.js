// File: oauth2_result_panes.js
//
// ---------------------------------------------------------------------------
// THE FIVE RESULT PANES ON oauth2_oidc_2.html: COLLAPSED, NEVER INVISIBLE.
//
// Five of that page's panes do not exist until something has been called. The
// Authorization Endpoint's tokens, the token endpoint's, the refresh call's,
// the set selected out of Token History and the history itself are each BUILT
// AS A STRING by `oauth2_oidc_2.js` and dropped into an empty container with
// `.html()`. Until then the container holds nothing — and an empty flex child
// is not a gap, it is a COLUMN with nothing in it, so the page rendered rows
// of three panes with two blanks in them.
//
// **`collapsePane()` was already being called on all five and could not help.**
// It shows the container and hides the first fieldset INSIDE it, and a
// container with no pane inside has no fieldset and no legend — so it
// collapses to nothing at all. That is the difference between COLLAPSED and
// INVISIBLE, and it is why this was fixed more than once without holding.
//
// **THE FIX IS IN TWO HALVES AND BOTH ARE LOAD-BEARING**, which is the other
// reason this file exists. Each container carries a collapsed PLACEHOLDER pane
// in `oauth2_oidc_2.html`, so there is something to collapse; and
// `capturePlaceholderPanes()` / `clearResultPane()` in the bundle put that
// markup back where the code used to `.html("")` a pane away. Measured on
// 2026-09-01 with the markup half alone, three of the eleven grant types were
// still broken on arrival:
//
//     resource_owner              the Authorization Endpoint AND token panes
//     client_credential           the token pane
//     device_authorization_grant  the Authorization Endpoint pane
//
// — because `resetUI()` runs from `document.ready` on every load and empties
// them per grant. A test that checked only the default grant would have passed
// over all three.
//
// **SO IT WALKS EVERY GRANT THE MENU OFFERS**, setting it in `localStorage`
// and RELOADING rather than firing a `change`: changing that select navigates
// to `oauth2_oidc_1.html`, so a test that drives the menu directly measures the
// wrong page — which it does silently, since the ids it looks for are simply
// absent there. The grant a reader arrives with is the one in storage anyway,
// which is the state being tested.
//
// **WHAT IS ASSERTED IS THE PANE AND NOT THE PIXELS.** A collapsed pane has a
// visible legend and a height in the tens; an invisible one has neither. The
// check is "there is a legend, and the container is as tall as a title bar"
// rather than an exact height, because the height is a font metric and the
// containerized run's fonts are not a host's.
//
// It needs the SITE and nothing else — no api, no IdP, no mock STS. The
// placeholders are in the served HTML and the bundle needs no network to lay
// them out, so this is a real check on a day the rest of the stack is down,
// and it runs unchanged against a deployed static site.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "oauth2_result_panes",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";

const WAIT = 20000;

// The five containers a pane is rendered INTO, with the title each one's
// placeholder carries. The title is asserted as well as the geometry: a
// container that is the right height with the wrong pane in it is a pane that
// has been rendered over by something else, and the height alone cannot see
// that.
const RESULT_PANES = [
  { id: "authorization_endpoint_result", title: "Authorization Endpoint" },
  { id: "token_endpoint_result", title: "Token Endpoint Results" },
  { id: "refresh_endpoint_result", title: "Refresh Token Call" },
  { id: "currently-viewing-panel", title: "Currently Viewing" },
  { id: "token-history-panel", title: "Token History" }
];

// A collapsed pane is a title bar. Anything at or below this is a container
// that rendered nothing — the empty ones measured 0px, and 20px for the two
// that held an `&nbsp;`.
const MIN_COLLAPSED_HEIGHT = 30;

// Read off the page rather than listed here, so a grant added to the menu is
// covered by construction. `resetUI()` branches on these values, and three of
// its branches are what this file exists for.
const GRANTS_PROBE =
  "return [].map.call(" +
  "    document.getElementById('authorization_grant_type').options," +
  "    function (o) { return o.value; });";

const PANES_PROBE =
  "var out = {};" +
  "arguments[0].forEach(function (id) {" +
  "  var e = document.getElementById(id);" +
  "  if (!e) { out[id] = null; return; }" +
  "  var legend = e.querySelector('legend');" +
  "  out[id] = {" +
  "    height: Math.round(e.getBoundingClientRect().height)," +
  "    legend: legend ? legend.textContent.replace(/\\s+/g, ' ').trim() : ''," +
  "    panes: e.querySelectorAll('.dbg-pane').length," +
  "    fieldsets: e.querySelectorAll('fieldset').length" +
  "  };" +
  "});" +
  "return out;";

function everyPaneIsCollapsedRatherThanGone(seen, grant) {
  log.debug("Entering everyPaneIsCollapsedRatherThanGone(). " + grant);
  RESULT_PANES.forEach(function (pane) {
    const m = seen[pane.id];
    assert.ok(m !== null && m !== undefined,
      "#" + pane.id + " is not on oauth2_oidc_2.html at all. That container " +
      "is where the " + pane.title + " pane is rendered; if it was renamed, " +
      "rename it here rather than dropping it.");
    assert.ok(m.panes >= 1,
      "With the grant type '" + grant + "', #" + pane.id + " holds no " +
      ".dbg-pane. An empty container is a flex COLUMN with nothing in it, " +
      "not a gap — which is the row of blanks this page used to show. It " +
      "needs a collapsed placeholder pane in oauth2_oidc_2.html, and " +
      "clearResultPane() rather than .html('') wherever the bundle empties " +
      "it.");
    assert.ok(m.legend !== "",
      "With the grant type '" + grant + "', #" + pane.id + " has no visible " +
      "legend. collapsePane() hides the fieldset and KEEPS the title, which " +
      "is what makes a collapsed pane recoverable — no title means there was " +
      "no pane there to collapse.");
    assert.ok(m.legend.indexOf(pane.title) >= 0,
      "With the grant type '" + grant + "', #" + pane.id + " is titled " +
      JSON.stringify(m.legend) + " rather than something containing " +
      JSON.stringify(pane.title) + ". Something has rendered over that " +
      "container, which the height alone cannot see.");
    assert.ok(m.height >= MIN_COLLAPSED_HEIGHT,
      "With the grant type '" + grant + "', #" + pane.id + " is " + m.height +
      "px tall. A collapsed pane is a title bar; anything this short " +
      "rendered nothing. The empty containers measured 0px, and 20px where " +
      "they held an &nbsp;.");
  });
  log.debug("Leaving everyPaneIsCollapsedRatherThanGone().");
}

async function everyGrantArrivesWithItsPanes(driver) {
  log.debug("Entering everyGrantArrivesWithItsPanes().");
  await driver.get(baseUrl + "/oauth2_oidc_2.html");
  await driver.wait(until.elementLocated(By.id("authorization_grant_type")),
      WAIT, "oauth2_oidc_2.html did not load");
  const grants = await driver.executeScript(GRANTS_PROBE);
  assert.ok(grants.length >= 8,
    "The grant menu offers " + grants.length + " options and this page has " +
    "eleven. Reading them off the page is what keeps this test covering a " +
    "grant added later, so a short list means the menu, not this file.");

  for (const grant of grants) {
    // SET IT IN STORAGE AND RELOAD, never fire a change on the select:
    // changing it navigates to oauth2_oidc_1.html, and every id below is
    // absent there, so the assertions would be measuring the wrong page
    // without saying so. The grant a reader arrives with is the stored one.
    await driver.executeScript(
      "localStorage.setItem('authorization_grant_type', arguments[0]);",
      grant);
    await driver.navigate().refresh();
    await driver.wait(until.elementLocated(By.id("token_endpoint_result")),
        WAIT, "oauth2_oidc_2.html did not come back after the reload");
    // Wait for the bundle: resetUI() runs from document.ready and is the
    // thing being tested, so measuring before it has run would pass on the
    // markup alone — which is exactly the half-fix this file exists to catch.
    await driver.wait(async function () {
      return await driver.executeScript(
        "return typeof window.oauth2_oidc_2 === 'object';");
    }, WAIT, "the oauth2_oidc_2 bundle never defined its global");
    const seen = await driver.executeScript(PANES_PROBE,
        RESULT_PANES.map(function (p) { return p.id; }));
    everyPaneIsCollapsedRatherThanGone(seen, grant);
    log.info("[" + grant + "] all five result panes collapsed, titled and " +
        "on the page (" + RESULT_PANES.map(function (p) {
          return seen[p.id].height + "px";
        }).join(", ") + ").");
  }
  log.debug("Leaving everyGrantArrivesWithItsPanes().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The five result panes on " + baseUrl +
      "/oauth2_oidc_2.html, across every grant type the menu offers.");

  const options = new chrome.Options();
  // --headless=new, never bare --headless: see tests/CLAUDE.md.
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1600,2400",
      // A scrollbar eats width, and a pane measured at 1600 is really 1585.
      "--hide-scrollbars");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    await everyGrantArrivesWithItsPanes(driver);
    log.info("Test completed successfully.");
  } finally {
    // driver.quit() in a FINALLY and never after a process.exit(): the exit
    // skips the finally, and one headless Chrome is about fifteen OS
    // processes of which only the first is this runner's child. See
    // tests/CLAUDE.md.
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("oauth2_result_panes")
  .description("Verify that the five result panes on oauth2_oidc_2.html — " +
      "which do not exist until something has been called — arrive " +
      "COLLAPSED rather than invisible, for every grant type the menu " +
      "offers, since three of them take a reset branch that used to empty " +
      "the container outright.")
  .addOption(new Option("-u, --url <url>",
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
