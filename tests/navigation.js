const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require('commander');
const assert = require("assert");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'navigation',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// Landing page: the protocol-choice cards.
//
// THREE protocols live on the OAuth2 / OIDC pages — the flows themselves, Dynamic
// Client Registration and Token Exchange — so href alone no longer identifies a
// card: two of them point at /debugger.html. Those two are located by their title
// instead, which is what a person reads and what the test is really about.
var cardByTitle = function (title) {
  return By.xpath("//a[contains(@class,'landing-card')]" +
                  "[.//span[contains(@class,'landing-card-title')][normalize-space()=\"" + title + "\"]]");
};
var OAUTH2_CARD = cardByTitle("OAuth2 / OIDC Protocol");
var TOKEN_EXCHANGE_CARD = cardByTitle("OAuth2 Token Exchange");
var SAML_CARD = By.css('a.landing-card[href="/saml_request.html"]');
var WSTRUST_CARD = By.css('a.landing-card[href="/wstrust_tools.html"]');
var SDJWTVC_CARD = By.css('a.landing-card[href="/vc-issuance-0.html"]');
var SDJWTVP_CARD = By.css('a.landing-card[href="/vc-presentation-0.html"]');
var WSFED_CARD = By.css('a.landing-card[href="/wsfed_request.html"]');
// Dynamic Client Registration lives on debugger.html, so its card is told apart
// from the OAuth2 card by the fragment naming the DCR pane. The OAuth2 locator
// above is an EXACT href match, so it still resolves to one element.
var DCR_CARD = By.css('a.landing-card[href="/debugger.html#dcr_fieldset"]');
var CHOICES = By.css('.landing-choices');
// The header "Home" nav link (returns to the landing page).
var HOME_LINK = By.css('.header_debugger a[href="/index.html"]');

async function waitVisible(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(locator)), waitTime);
  return driver.findElement(locator);
}

// M.N.O, shown in the footer of every page. The build number must be identical
// everywhere — it identifies the build being served, not the moment of the
// request — so the first one seen becomes the expectation for the rest.
var VERSION_RE = /^v\d+\.\d+\.\d+$/;
var seenVersion = null;
async function checkFooterVersion(driver, where) {
  log.debug("Entering checkFooterVersion().");
  var el = await waitVisible(driver, By.css('.footer-version'));
  var text = (await el.getText()).trim();
  assert.ok(VERSION_RE.test(text),
    "[" + where + "] the footer should show a M.N.O version, found: '" + text + "'");
  var title = await el.getAttribute('title');
  assert.ok(/Build \S+ — built /.test(title || ''),
    "[" + where + "] the version tooltip should carry the build provenance, found: '" + title + "'");
  if (seenVersion === null) { seenVersion = text; log.info("Footer version: " + text); }
  else {
    assert.strictEqual(text, seenVersion,
      "[" + where + "] every page must report the same build: " + text + " vs " + seenVersion);
  }
  log.debug("Leaving checkFooterVersion().");
}

// ---------------------------------------------------------------------------
// Did the page's styling actually arrive?
//
// Two ways it can fail to, and both have happened in a merge, and neither shows
// up in any other assertion — a page whose CSS never loaded still has every
// element and id a functional test looks for:
//
//   1. a <link> that 404s, or resolves to a stylesheet with no rules in it;
//   2. a page that links the WRONG sheet — the WS-Federation pages linked
//      `saml_tools.css`, the small page-specific sheet, where every `saml-*`
//      class they use is defined in the shared `saml_common.css`. The link
//      resolved, so nothing 404'd; the page simply rendered unstyled.
//
// The second is caught by a naming convention rather than a list: a class with a
// `saml-` / `wst-` / `wsfed-` / `vc-` prefix is a styling class by definition, so
// if a page uses one that none of its stylesheets defines, that page is missing a
// stylesheet. Classes without those prefixes are left alone — the older debugger
// pages use plenty of them as pure JavaScript selectors.
// ---------------------------------------------------------------------------
var STYLED_PREFIXES = /^(saml|wst|wsfed|vc|vp)-/;

async function checkStylesheetsLoaded(driver, where) {
  log.debug("Entering checkStylesheetsLoaded(). where=" + where);
  var m = await driver.executeScript(
    "var links = Array.prototype.slice.call(document.querySelectorAll('link[rel=stylesheet]'))" +
    "  .map(function (l) { return l.getAttribute('href'); });" +
    "var empty = [];" +
    "var defined = {};" +
    "Array.prototype.slice.call(document.styleSheets).forEach(function (sheet) {" +
    "  var rules = null;" +
    "  try { rules = sheet.cssRules; } catch (e) { rules = null; }" +
    "  if (!rules || !rules.length) { if (sheet.href) empty.push(sheet.href); return; }" +
    "  Array.prototype.slice.call(rules).forEach(function collect(rule) {" +
    "    if (rule.selectorText) {" +
    "      (rule.selectorText.match(/\\.[A-Za-z0-9_-]+/g) || []).forEach(function (sel) {" +
    "        defined[sel.slice(1)] = true; });" +
    "    } else if (rule.cssRules) {" +
    "      Array.prototype.slice.call(rule.cssRules).forEach(collect);" +
    "    }" +
    "  });" +
    "});" +
    "var used = {};" +
    "Array.prototype.slice.call(document.querySelectorAll('[class]')).forEach(function (e) {" +
    "  Array.prototype.slice.call(e.classList).forEach(function (c) { used[c] = true; }); });" +
    "return { links: links, empty: empty, sheets: document.styleSheets.length," +
    "         used: Object.keys(used), defined: Object.keys(defined) };");

  assert.ok(m.sheets > 0, "[" + where + "] the page loaded no stylesheets at all.");
  assert.deepStrictEqual(m.empty, [],
    "[" + where + "] these stylesheets loaded with no rules in them (a 404 serving an error page, or an " +
    "empty file): " + m.empty.join(", "));

  var definedSet = {};
  m.defined.forEach(function (c) { definedSet[c] = true; });
  var unstyled = m.used.filter(function (c) { return STYLED_PREFIXES.test(c) && !definedSet[c]; });
  assert.deepStrictEqual(unstyled, [],
    "[" + where + "] these styling classes are used but defined in none of the page's stylesheets: " +
    unstyled.join(", ") + ". The page is probably linking the wrong sheet — it links: " + m.links.join(", "));
  log.info("[styles] " + where + " — " + m.sheets + " stylesheet(s), all with rules, and every " +
           "prefixed class it uses is defined.");
  log.debug("Leaving checkStylesheetsLoaded().");
}

async function click(driver, locator) {
  var elArtifact = await waitVisible(driver, locator);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", elArtifact);
  await elArtifact.click();
}

// ---------------------------------------------------------------------------
// Every protocol card visible without scrolling, on a 1366x768 screen — the
// smallest one anybody is likely to use, and the size at which this last went
// wrong, twice: six cards in the two-wide grid the page had when there were four
// of them made three rows, and a seventh in the three-wide grid that replaced it
// would have done the same. A choice you have to scroll to find is one you do not
// know you have, so it is checked geometrically rather than by eye.
//
// Also checked here, because both were real and neither is visible in a
// screenshot: a card nested INSIDE another (an unclosed <a> in the markup, which
// the browser silently recovers from) and a card whose icon has no accent colour
// of its own (landing.css carries one rule per card, so a new protocol needs one
// or it inherits the text colour).
// ---------------------------------------------------------------------------
var DEFAULT_TEXT_COLOUR = "rgb(51, 51, 51)";
// How much of a 768px-tall screen the cards may occupy. The viewport check below
// is not enough on its own: headless Chrome has no tab strip, toolbar or bookmark
// bar, so window.innerHeight there is the whole 768 while a real browser leaves
// roughly 620-640. Measured 2026-07-30 at 571px with seven cards in a 4 + 3 grid,
// so this budget is the slack that remains — an eighth protocol has to fit inside
// it, which most likely means another column or shorter descriptions.
var CARD_HEIGHT_BUDGET = 640;

async function landingFitsOnOneScreen(driver) {
  log.debug("Entering landingFitsOnOneScreen().");
  log.info("Entering landingFitsOnOneScreen().");
  var was = await driver.manage().window().getRect();
  await driver.manage().window().setRect({ width: 1366, height: 768 });
  await driver.get(baseUrl);
  await waitVisible(driver, CHOICES);
  await driver.sleep(300);

  var m = await driver.executeScript(
    "var cards = Array.prototype.slice.call(document.querySelectorAll('a.landing-card'));" +
    "var rows = [];" +
    "cards.forEach(function (c) {" +
    "  var top = Math.round(c.getBoundingClientRect().top);" +
    "  var row = rows.filter(function (r) { return Math.abs(r.top - top) < 12; })[0];" +
    "  if (!row) { row = { top: top, count: 0 }; rows.push(row); }" +
    "  row.count++;" +
    "});" +
    "rows.sort(function (a, b) { return a.top - b.top; });" +
    "return {" +
    "  count: cards.length," +
    "  rows: rows.map(function (r) { return r.count; })," +
    "  viewportHeight: window.innerHeight," +
    "  lowestCardBottom: Math.max.apply(null, cards.map(function (c) {" +
    "    return Math.round(c.getBoundingClientRect().bottom); }))," +
    "  horizontalScroll: document.documentElement.scrollWidth > window.innerWidth + 1," +
    "  nested: document.querySelectorAll('a.landing-card a.landing-card').length," +
    "  titles: cards.map(function (c) {" +
    "    var t = c.querySelector('.landing-card-title'); return t ? t.textContent.trim() : ''; })," +
    "  iconColours: cards.map(function (c) {" +
    "    var i = c.querySelector('.landing-icon'); return i ? getComputedStyle(i).color : ''; })" +
    "};");

  try {
    assert.ok(m.count >= 8, "the landing page should offer every protocol; found " + m.count + " card(s).");
    assert.strictEqual(m.nested, 0,
      "no protocol card may be nested inside another — that means an unclosed <a> in index.html. Found " +
      m.nested + ".");
    assert.ok(m.lowestCardBottom <= m.viewportHeight,
      "every protocol card must be visible without scrolling at 1366x768: the lowest card ends at " +
      m.lowestCardBottom + "px, the viewport is " + m.viewportHeight + "px. Rows: [" + m.rows.join(", ") +
      "]. Adding a protocol means making the cards fit, not letting them run off the screen.");
    assert.ok(!m.horizontalScroll, "and the page must not scroll sideways.");
    assert.ok(m.lowestCardBottom <= CARD_HEIGHT_BUDGET,
      "the cards must also fit the " + CARD_HEIGHT_BUDGET + "px a REAL browser leaves on a 768px screen " +
      "once its tab strip and toolbar are accounted for (headless has neither, so the viewport check above " +
      "passes too easily). The lowest card ends at " + m.lowestCardBottom + "px.");
    // More than one row, and none of them a lone leftover: the grid should be
    // filled left to right, which is what "arranged in rows" means here.
    assert.ok(m.rows.length >= 2, "the cards should be laid out in rows, not one long column.");
    assert.ok(m.rows[0] >= 4,
      "the first row should hold at least four cards at this width; got " + m.rows[0] + ".");
    m.iconColours.forEach(function (colour, i) {
      assert.notStrictEqual(colour, DEFAULT_TEXT_COLOUR,
        "the '" + m.titles[i] + "' card's icon has no accent colour of its own — landing.css needs a " +
        ":nth-child(" + (i + 1) + ") rule. Got " + colour + ".");
    });
    log.info("[landing] OK — " + m.count + " cards in rows of [" + m.rows.join(", ") + "], all visible " +
             "(lowest ends " + m.lowestCardBottom + "px of " + m.viewportHeight + "px), each with its own " +
             "accent colour.");
  } finally {
    await driver.manage().window().setRect(was);
  }
  log.info("Leaving landingFitsOnOneScreen().");
  log.debug("Leaving landingFitsOnOneScreen().");
}

async function navigationActivities(driver) {
  log.debug("Entering navigationActivities().");
  // 1. Hit the base URL -> the landing page (site root serves index.html).
  log.info("Load the base URL (landing page).");
  await driver.get(baseUrl);
  await waitVisible(driver, CHOICES);
  log.info("Landing page loaded (protocol choices present).");
  await checkFooterVersion(driver, "landing page");
  await landingFitsOnOneScreen(driver);
  await checkStylesheetsLoaded(driver, "landing page");

  // 2. Choose the OAuth2 / OIDC debugger -> debugger.html.
  log.info("Click the OAuth2 / OIDC debugger card.");
  await click(driver, OAUTH2_CARD);
  await driver.wait(until.urlContains("debugger.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("authorization_grant_type")), waitTime);
  log.info("Landed on debugger.html.");
  await checkFooterVersion(driver, "debugger.html");
  await checkStylesheetsLoaded(driver, "debugger.html");

  // 3. Click Home -> back to the landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);
  log.info("Back on the landing page.");

  // 4. Choose the SAML debugger -> saml_request.html.
  log.info("Click the SAML debugger card.");
  await click(driver, SAML_CARD);
  await driver.wait(until.urlContains("saml_request.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("saml_metadata_url")), waitTime);
  log.info("Landed on saml_request.html.");
  await checkFooterVersion(driver, "saml_request.html");
  await checkStylesheetsLoaded(driver, "saml_request.html");

  // 5. Return to Home -> landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);
  log.info("Back on the landing page.");

  // 6. Choose the WS-Trust debugger -> wstrust_tools.html.
  log.info("Click the WS-Trust debugger card.");
  await click(driver, WSTRUST_CARD);
  await driver.wait(until.urlContains("wstrust_tools.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("wst_sts_url")), waitTime);
  log.info("Landed on wstrust_tools.html.");
  await checkFooterVersion(driver, "wstrust_tools.html");
  await checkStylesheetsLoaded(driver, "wstrust_tools.html");

  // 7. Return to Home -> landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);
  log.info("Back on the landing page.");

  // 8. Choose the SD-JWT VC issuance workflow -> the use-case chooser.
  log.info("Click the VC Issuance card.");
  await click(driver, SDJWTVC_CARD);
  await driver.wait(until.urlContains("vc-issuance-0.html"), waitTime);
  await driver.wait(until.elementLocated(By.css("button.vc-usecase")), waitTime);
  log.info("Landed on vc-issuance-0.html (choose a use case).");
  await checkFooterVersion(driver, "vc-issuance-0.html");
  await checkStylesheetsLoaded(driver, "vc-issuance-0.html");

  // 9. Return to Home -> landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);

  // 10. Choose the SD-JWT VC presentation workflow -> its flow chooser.
  log.info("Click the VC Presentation card.");
  await click(driver, SDJWTVP_CARD);
  await driver.wait(until.urlContains("vc-presentation-0.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("vp_usecases")), waitTime);
  log.info("Landed on vc-presentation-0.html (choose a flow).");
  await checkFooterVersion(driver, "vc-presentation-0.html");
  await checkStylesheetsLoaded(driver, "vc-presentation-0.html");

  // 11. Return to Home -> landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);

  // 12. Choose OIDC Dynamic Client Registration -> debugger.html, at the DCR pane.
  // Same page as the OAuth2 card, reached by a different card and a fragment, so
  // what is checked is that the pane it names is really there.
  log.info("Click the OIDC Dynamic Client Registration card.");
  await click(driver, DCR_CARD);
  await driver.wait(until.urlContains("debugger.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("dcr_fieldset")), waitTime);
  var dcrUrl = await driver.getCurrentUrl();
  assert.ok(dcrUrl.indexOf("#dcr_fieldset") >= 0,
    "the card should open debugger.html at the Dynamic Client Registration pane. Got: " + dcrUrl);
  await driver.wait(until.elementLocated(By.id("dcr_registration_endpoint")), waitTime);
  log.info("Landed on debugger.html at the Dynamic Client Registration pane.");
  await checkFooterVersion(driver, "debugger.html#dcr_fieldset");

  // 13. Return to Home -> landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);

  // 14. Choose OAuth2 Token Exchange -> debugger.html. Its pane is on
  // debugger2.html (an exchange needs a token to exchange), so what this checks is
  // that the card is there, is distinct from the OAuth2 card, and lands on the
  // page where a subject token is obtained.
  log.info("Click the OAuth2 Token Exchange card.");
  await click(driver, TOKEN_EXCHANGE_CARD);
  await driver.wait(until.urlContains("debugger.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("authorization_grant_type")), waitTime);
  log.info("Landed on debugger.html from the Token Exchange card.");
  await checkFooterVersion(driver, "debugger.html (Token Exchange card)");

  // 15. Return to Home -> landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);

  // 16. Choose the WS-Federation debugger -> wsfed_request.html. Its own suite
  // needs the WS-Federation Keycloak side-car and is skipped without it, so this
  // is the only place the page is loaded on every run — which is how it came to
  // be served unstyled for a while without anything failing.
  log.info("Click the WS-Federation debugger card.");
  await click(driver, WSFED_CARD);
  await driver.wait(until.urlContains("wsfed_request.html"), waitTime);
  await driver.wait(until.elementLocated(By.id("wsfed_metadata_url")), waitTime);
  log.info("Landed on wsfed_request.html.");
  await checkFooterVersion(driver, "wsfed_request.html");
  await checkStylesheetsLoaded(driver, "wsfed_request.html");

  // 17. Return to Home -> landing page.
  log.info("Click Home -> landing page.");
  await click(driver, HOME_LINK);
  await waitVisible(driver, CHOICES);
  await checkFooterVersion(driver, "landing page (return)");
  log.info("Back on the landing page. Navigation test succeeded.");
  log.debug("Leaving navigationActivities().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages under coverage.
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");

  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  try {
    await navigationActivities(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('navigation')
  .description("Run basic navigation test.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });

program.parse(process.argv).opts();

test();
