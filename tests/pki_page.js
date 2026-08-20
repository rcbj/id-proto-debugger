// File: pki_page.js
//
// The PKI page (client/public/pki.html): building a CA hierarchy through the
// UI, the store that keeps it, the private-key opt-out, and the TLS test.
//
// ---------------------------------------------------------------------------
// WHAT THIS TEST IS FOR, GIVEN THAT tests/pki_x509.js EXISTS
//
// The certificates themselves are checked against OpenSSL in node by
// tests/pki_x509.js, and the keystore formats by tests/pki_key_formats.js.
// Neither of those touches a browser, so neither can catch the failures that
// live between the form and the module:
//
//   * a field the form reads under one id and the page writes under another —
//     a whole extension silently absent from every certificate issued, with
//     nothing on screen to say so;
//   * a store that does not survive a reload, which makes a "certificate
//     authority" a thing that exists until you press F5;
//   * the private-key opt-out failing in the reassuring direction: the box
//     unticks, the note appears, and the key goes on being written. That is
//     invisible without reading storage, which is why keypair_storage_optout.js
//     exists for the other four protocols and why this section is here;
//   * the TLS pane growing a browser-side option, which is the one thing
//     the design of this page forbids;
//   * and the page's LAYOUT, which is the newest of these and the only one
//     that is not about correctness. This page carries more fields than any
//     other in the tree, and on 2026-08-18 its three configuration panes
//     became one and its extension list became two columns. Both savings undo
//     themselves silently — a fourth pane looks like tidiness, and a card that
//     stops fitting collapses the columns with no symptom but more scrolling —
//     so section 2 measures them.
//
// So this drives the workflow the page exists for — root, intermediate,
// issuing CA, then a leaf — entirely through the form, and then reads storage.
//
// It needs the client and (for the last section) the api. No identity provider,
// no STS, no KDC.
// ---------------------------------------------------------------------------
const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const assert = require("assert");
const browserFlags = require("./browser_flags.js");
// The subject-DN defaults and the profile subjectAltName are the
// module's, not the page's — this is the one place in this file that
// compares against them rather than against a list copied into it, and
// it is worth the require: a default changed in x509.js and not reaching
// the form is exactly the shape of failure this whole file exists for.
//
// Resolved through module_paths.js rather than by a bare
// require("../client/src/x509.js"), because the tests IMAGE copies the
// borrowed client modules FLAT beside the test scripts — so the checkout
// path exists only in a checkout, and the literal require died in the
// container at load with MODULE_NOT_FOUND before a browser had started,
// while every host run stayed green. The three node-only PKI jobs already
// resolve it this way; this browser one is the odd file out.
const path = require("path");
const paths = require("./module_paths.js");
const x509 = paths.requireSharedModule(
  [path.join(__dirname, "..", "client", "src", "x509.js"),
   path.join(__dirname, "x509.js")],
  "client/src/x509.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "pki_page",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
// Headless by DEFAULT, and initialized true rather than false: a test that
// pops a window on every unattended run is a stolen desktop locally and a dead
// run in CI, which has no display. tests/browser_tests_headless.js asserts
// this over this directory's own sources.
var headless = true;
var waitTime = appconfig.waitTime;
var PAGE = "/pki.html";

// The generation and issuing this page does is real cryptography in the
// browser, and an RSA-4096 key pair on a loaded CI runner is not instant. These
// waits are for CONTENT (a field filling, a row appearing) rather than for an
// element, per tests/wait_for.js, so they are fast when the page is fast.
var CRYPTO_WAIT = Math.max(waitTime, 20000);

async function waitVisible(driver, locator) {
  log.debug("Entering waitVisible().");
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(locator)),
                    waitTime);
  log.debug("Leaving waitVisible().");
  return driver.findElement(locator);
}

// ---------------------------------------------------------------------------
// Open the page the way a person does: from the landing page's PKI card, not
// by typing the URL. The card (client/public/index.html, added 2026-08-18) is
// this workflow's own front door — every other route to the page is somebody
// else's Tools pane — and a test that navigates straight to PAGE goes on
// passing after the card stops pointing anywhere, since nothing else in this
// file reads index.html. tests/navigation.js checks the card too, but only
// once and only on the containerized stack's own base URL; this runs wherever
// this test runs, the deployed static sites included.
//
// EVERY load here goes through it, the reloads included. localStorage is per
// ORIGIN rather than per page, so a trip via the landing page preserves
// exactly what a direct re-get would and the store assertions still mean what
// they say — while a reload that never leaves the page would be a weaker check
// than the one it replaces.
//
// Clicked rather than followed by href: a card that is present, correct and
// covered by something drawn over it is a card nobody can use, and only a real
// click says so. It is scrolled into view first because the grid's last row
// sits below the fold at the default window size.
// ---------------------------------------------------------------------------
var LANDING_CHOICES = By.css(".landing-choices");
var PKI_CARD = By.css('a.landing-card[href="' + PAGE + '"]');

async function openThePageFromTheLandingCard(driver) {
  log.debug("Entering openThePageFromTheLandingCard().");
  await driver.get(baseUrl);
  await waitVisible(driver, LANDING_CHOICES);
  const card = await waitVisible(driver, PKI_CARD);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", card);
  await card.click();
  await driver.wait(until.urlContains("pki.html"), waitTime,
    "the landing page's PKI card did not open " + PAGE);
  log.debug("Leaving openThePageFromTheLandingCard().");
}

// Set a field the way a person does — assign and dispatch — rather than
// assigning .value alone, which fires no event and so never reaches the page's
// change listener. Everything this page persists goes through that listener.
//
// NOTE: the function body below runs IN THE BROWSER. There is no bunyan there,
// so it carries no log lines — see tests/CLAUDE.md.
async function setField(driver, id, value) {
  log.debug("Entering setField(). id=" + id);
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (!e) { return false; }" +
    "e.value = arguments[1];" +
    "e.dispatchEvent(new Event('input', { bubbles: true }));" +
    "e.dispatchEvent(new Event('change', { bubbles: true }));" +
    "return true;", id, value);
  log.debug("Leaving setField().");
}

async function setCheckbox(driver, id, want) {
  log.debug("Entering setCheckbox(). id=" + id);
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (!e) { return false; }" +
    "if (e.checked !== arguments[1]) {" +
    "  e.checked = arguments[1];" +
    "  e.dispatchEvent(new Event('change', { bubbles: true }));" +
    "}" +
    "return e.checked;", id, want);
  log.debug("Leaving setCheckbox().");
}

async function selectOption(driver, id, value) {
  log.debug("Entering selectOption(). id=" + id + " value=" + value);
  const applied = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (!e) { return 'no such element'; }" +
    "e.value = arguments[1];" +
    "if (e.value !== arguments[1]) { return 'no such option'; }" +
    "e.dispatchEvent(new Event('change', { bubbles: true }));" +
    "return 'ok';", id, value);
  assert.strictEqual(applied, "ok",
    "could not select " + value + " in " + id + ": " + applied);
  log.debug("Leaving selectOption().");
}

async function valueOf(driver, id) {
  log.debug("Entering valueOf(). id=" + id);
  const value = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return e ? e.value : null;", id);
  log.debug("Leaving valueOf().");
  return value;
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). id=" + id);
  const text = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return e ? (e.textContent || '') : null;", id);
  log.debug("Leaving textOf().");
  return text;
}

async function click(driver, id) {
  log.debug("Entering click(). id=" + id);
  const element = await waitVisible(driver, By.id(id));
  await element.click();
  log.debug("Leaving click().");
}

async function storeEntries(driver) {
  log.debug("Entering storeEntries().");
  const raw = await driver.executeScript(
    "return window.localStorage.getItem('pkitools_objects');");
  const entries = raw ? JSON.parse(raw) : [];
  log.debug("Leaving storeEntries(). " + entries.length + " entries.");
  return entries;
}

// Wait for the status line to say something other than what it said before —
// a results box that persists between two identical actions is satisfied by
// the previous run's text, which is a test that quietly does nothing.
async function waitForStatusChange(driver, id, previous, what) {
  log.debug("Entering waitForStatusChange(). what=" + what);
  let last = previous;
  try {
    await driver.wait(async function () {
      last = await textOf(driver, id);
      return last && last.trim() && last !== previous;
    }, CRYPTO_WAIT);
  } catch (e) {
    throw new Error("timed out waiting for " + what + " (the " + id +
      " line still reads " + JSON.stringify(last) + ")");
  }
  log.debug("Leaving waitForStatusChange(). " + last);
  return last;
}

// The one button generates the key pair and THEN issues, so the status line
// passes through "Generating a … key pair…" and "Generated a …" before it says
// anything about a certificate. A wait for "the line changed" returns the
// first of those, and the assertion after it then fails naming a subject that
// was never going to be in a message about a key pair.
async function waitForIssueOutcome(driver, what) {
  log.debug("Entering waitForIssueOutcome(). what=" + what);
  let last = "";
  try {
    await driver.wait(async function () {
      last = await textOf(driver, "pki_status");
      return /Issued "|Could not issue|failed/.test(last || "");
    }, CRYPTO_WAIT);
  } catch (e) {
    throw new Error("timed out waiting for " + what + " (the pki_status " +
      "line still reads " + JSON.stringify(last) + ")");
  }
  log.debug("Leaving waitForIssueOutcome(). " + last);
  return last;
}

// ---------------------------------------------------------------------------
// 1. The page loads, offers what the modules define, and offers no TLS option
//    the browser could not honour.
// ---------------------------------------------------------------------------
async function thePageOffersWhatTheModulesDefine(driver) {
  log.debug("Entering thePageOffersWhatTheModulesDefine().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_key_alg"));
  await driver.executeScript("window.localStorage.clear();");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_key_alg"));

  // The dropdowns are filled from key_material.js and x509.js rather than from
  // markup, so a new algorithm or profile is one table edit. That only holds
  // if they are actually filled.
  const keyAlgs = await driver.executeScript(
    "var e = document.getElementById('pki_key_alg');" +
    "return Array.prototype.map.call(e.options, function (o) {" +
    "  return o.value; });");
  assert.ok(keyAlgs.length >= 7,
    "the key algorithm dropdown has " + keyAlgs.length + " entries; the " +
    "page fills it from key_material.js, so an empty one means the module " +
    "did not load");
  ["rsa-2048", "rsa-4096", "ec-p256", "ec-p521", "ed25519"].forEach(
    function (wanted) {
      assert.ok(keyAlgs.indexOf(wanted) >= 0,
        "the key algorithm dropdown is missing " + wanted);
    });

  const profiles = await driver.executeScript(
    "var e = document.getElementById('pki_profile');" +
    "return Array.prototype.map.call(e.options, function (o) {" +
    "  return o.value; });");
  ["root-ca", "intermediate-ca", "issuing-ca", "tls-server", "tls-client",
   "code-signing", "ocsp-responder", "kdc"].forEach(function (wanted) {
    assert.ok(profiles.indexOf(wanted) >= 0,
      "the profile dropdown is missing " + wanted);
  });

  // Every X.509v3 extension the module can build must have a control. An
  // extension with no control is one nobody can set, and nothing else notices.
  const missing = await driver.executeScript(
    "var wanted = arguments[0];" +
    "return wanted.filter(function (id) {" +
    "  return !document.getElementById(id); });",
    ["pki_ext_bc", "pki_ext_ku", "pki_ext_eku", "pki_ext_skid",
     "pki_ext_akid", "pki_ext_san", "pki_ext_ian", "pki_ext_cdp",
     "pki_ext_freshest", "pki_ext_aia", "pki_ext_sia", "pki_ext_policies",
     "pki_ext_policy_mappings", "pki_ext_policy_constraints",
     "pki_ext_name_constraints", "pki_ext_inhibit_any", "pki_ext_pkup",
     "pki_ext_tls_feature", "pki_ext_ocsp_nocheck", "pki_ext_ns_cert_type",
     "pki_ext_ns_comment", "pki_custom_extensions"]);
  assert.deepStrictEqual(missing, [],
    "the extension editor has no control for: " + missing.join(", "));

  // Every keyUsage bit and every extendedKeyUsage the module knows, likewise.
  const missingFlags = await driver.executeScript(
    "var wanted = arguments[0];" +
    "return wanted.filter(function (id) {" +
    "  return !document.getElementById(id); });",
    ["pki_ku_digitalSignature", "pki_ku_nonRepudiation",
     "pki_ku_keyEncipherment", "pki_ku_dataEncipherment",
     "pki_ku_keyAgreement", "pki_ku_keyCertSign", "pki_ku_cRLSign",
     "pki_ku_encipherOnly", "pki_ku_decipherOnly",
     "pki_eku_serverAuth", "pki_eku_clientAuth", "pki_eku_codeSigning",
     "pki_eku_emailProtection", "pki_eku_timeStamping",
     "pki_eku_ocspSigning", "pki_eku_msSmartcardLogon",
     "pki_eku_kdcAuthentication", "pki_eku_anyExtendedKeyUsage"]);
  assert.deepStrictEqual(missingFlags, [],
    "the extension editor has no checkbox for: " + missingFlags.join(", "));

  // THE DESIGN ASSERTION. Every other page here offers "call from the browser
  // or through the api"; this one must not, because a browser cannot choose a
  // client certificate, cannot be given a truststore, and cannot read the
  // handshake. A radio pair appearing in this pane would be a button that
  // answers a different question badly.
  const tlsPaneHtml = await driver.executeScript(
    "var e = document.getElementById('pane_tls');" +
    "return e ? e.innerHTML : '';");
  assert.ok(tlsPaneHtml.length > 0, "the TLS pane is missing from the page");
  assert.ok(!/type="radio"/i.test(tlsPaneHtml) &&
      !/type='radio'/i.test(tlsPaneHtml),
    "the TLS pane has grown a radio button. There must be no browser/api " +
    "choice here: a browser cannot present a chosen client certificate, " +
    "cannot be given a truststore, and cannot read the negotiated version, " +
    "cipher or chain — so an in-browser option would answer a different " +
    "question and every answer would be about the browser.");
  assert.ok(/API layer/i.test(tlsPaneHtml),
    "the TLS pane must say that the api makes this connection, so the " +
    "absence of a browser option reads as a decision rather than an " +
    "oversight");
  log.debug("Leaving thePageOffersWhatTheModulesDefine().");
}

// ---------------------------------------------------------------------------
// 2. The configuration is ONE pane, and the layout that made it one still
//    works.
//
// "Key Pair", "Issue a Certificate" and "X.509v3 Extensions" were three panes
// describing one act — every field in all three is an input to the single
// "Generate Key Pair & Issue Certificate" button at the top of the one pane
// that replaced them.
// Each pane cost a title bar, two borders and the gap between them before a
// field was drawn, and made the reader collapse three things to reach the
// store rather than one.
//
// Every part of that merge fails SILENTLY, which is why it is asserted rather
// than left to the eye:
//
//   * a fourth pane, added for the next block of fields, costs all of it back
//     and looks like tidiness in the diff;
//   * the headings the lost legends became are `div`s with no control to
//     point at, so nothing but this notices when one goes — and without them
//     the key algorithm dropdown and the profile dropdown are two unlabelled
//     selects side by side;
//   * the pane itself is THREE columns (key pair | certificate | subject DN)
//     and a grid row is as tall as its tallest item, so a block moved from one
//     column to another turns into dead space at the foot of the short one
//     rather than into a shorter page — and the third column wraps to a row of
//     its own, silently and for the worse, if `.pki-cols`' 390px minimum is
//     raised. Both are measured;
//   * the extension list is three columns by way of `columns: 380px 3`, which
//     is a MAXIMUM: one card that stops fitting costs a whole column, which is
//     ~400px of page and the only symptom is that you scroll further. So the
//     column count is measured rather than assumed;
//   * and the prose folded into `<details>` is folded rather than CUT. A
//     `<summary>` whose paragraph was deleted in some later tidy-up still
//     opens, still closes, and says nothing.
//
// The last assertion is the one that keeps the folds honest in the other
// direction: nothing a person has to OPERATE may be inside a fold. A checkbox
// behind a summary is a setting nobody can find, and unlike missing prose it
// costs a certificate rather than an explanation.
// ---------------------------------------------------------------------------
var LAYOUT_WIDTH = 1366;
var LAYOUT_HEIGHT = 768;

// How tall the whole page may be at that size, with every pane expanded.
//
// MEASURED at 1366x768 in headless Chrome, four times on the same page:
// **4941px** for the seven-pane version with a single-column extension list;
// **3323px** on 2026-08-18 when the first three panes became one and that list
// became two columns; **~2600px** later the same day when the configuration
// pane went to THREE columns (the subject DN is one of its own), the extension
// list to three, and the TLS pane to two; and **2196px** on 2026-08-18 when
// every standing note and warning became the tooltip of the control it
// describes. This budget is that last measurement plus ~20%, which is slack
// for the fonts: the containerized run has fonts-liberation and a host run has
// the host's Arial, and their metrics are not the same. It is deliberately not
// tight. What it is here to catch is the change that gives a whole saving back
// at once — un-merging the configuration pane, either list falling a column,
// or a paragraph of prose unfolded back onto the page — each of which is worth
// many hundreds of pixels rather than the tens that a font accounts for.
var PAGE_HEIGHT_BUDGET = 2700;

// The panes this page has after the merge, in order. Named rather than
// counted, so a pane that is renamed and a pane that is added fail
// differently.
var EXPECTED_PANES = ["pane_config", "pane_store", "pane_details", "pane_tls",
                      "pane_history"];

async function theConfigurationIsOnePane(driver) {
  log.debug("Entering theConfigurationIsOnePane().");
  const was = await driver.manage().window().getRect();
  await driver.manage().window().setRect({ width: LAYOUT_WIDTH,
                                           height: LAYOUT_HEIGHT });
  try {
    await openThePageFromTheLandingCard(driver);
    await waitVisible(driver, By.id("pane_config"));

    // NOTE: every function body inside these executeScript strings runs IN THE
    // BROWSER, where there is no bunyan — see tests/CLAUDE.md. They carry no
    // log lines for that reason.
    const panes = await driver.executeScript(
      "return Array.prototype.map.call(" +
      "  document.querySelectorAll('fieldset.saml-pane')," +
      "  function (p) { return p.id; });");
    assert.deepStrictEqual(panes, EXPECTED_PANES,
      "the page's panes are " + panes.join(", ") + ". Key Pair, Issue a " +
      "Certificate and X.509v3 Extensions are ONE pane (pane_config): they " +
      "are one act, and each extra pane costs a title bar, two borders and " +
      "the gap between them before a single field is drawn.");

    // Everything the merged pane is supposed to hold is INSIDE it, rather
    // than merely present on the page — a field left behind in a stray
    // container still answers getElementById.
    const outside = await driver.executeScript(
      "var pane = document.getElementById('pane_config');" +
      "return arguments[0].filter(function (id) {" +
      "  var e = document.getElementById(id);" +
      "  return !e || !pane.contains(e); });",
      ["pki_key_alg", "pki_reuse_key", "pki_private_key", "pki_ks_format",
       "pki_save_keys", "pki_profile", "pki_issuer", "pki_sig_alg",
       "pki_dn_cn", "pki_dn_extra", "pki_ext_bc", "pki_ext_san",
       "pki_custom_extensions", "pki_issue"]);
    assert.deepStrictEqual(outside, [],
      "these belong in the one configuration pane and are not in it: " +
      outside.join(", "));

    // The two legends that were lost are headings now. A pane legend can only
    // say one thing, so what they said had to go somewhere.
    const groups = await driver.executeScript(
      "return Array.prototype.map.call(" +
      "  document.querySelectorAll('#pane_config .pki-group')," +
      "  function (g) { return (g.textContent || '').trim(); });");
    ["Key Pair", "Issue a Certificate", "Subject Distinguished Name",
     "X.509v3 Extensions"].forEach(
      function (wanted) {
        assert.ok(groups.indexOf(wanted) >= 0,
          "the '" + wanted + "' heading is gone. It was a pane legend and is " +
          "now a .pki-group over the block it named; without it that block " +
          "is a run of unlabelled fields. Headings found: " +
          groups.join(" | "));
      });

    // The configuration pane's own three columns — key pair, certificate,
    // subject DN — and the two ways that layout fails without a symptom. A
    // grid ROW is as tall as its tallest item, so a column carrying twice what
    // its neighbour carries is not a layout, it is dead space with a border:
    // with the DN inside the certificate column this pane was 392px beside
    // 675px, and 283px of nothing at the foot of the key pair. And the third
    // column silently wraps to a second ROW if `.pki-cols`' 390px minimum is
    // raised — three columns need 3*390 + 2*22 = 1214px and there are 1275 —
    // at which point the same markup is TALLER than what it replaced. So the
    // tops are checked as well as the heights.
    const cols = await driver.executeScript(
      "return Array.prototype.map.call(" +
      "  document.querySelectorAll('#pane_config .pki-col')," +
      "  function (c) {" +
      "    var r = c.getBoundingClientRect();" +
      "    return { top: Math.round(r.top + window.scrollY)," +
      "             height: Math.round(r.height) }; });");
    assert.strictEqual(cols.length, 3,
      "the configuration pane has " + cols.length + " .pki-col columns; it " +
      "is meant to have three — the key pair, the certificate fields and the " +
      "subject DN");
    const tops = cols.map(function (c) { return c.top; });
    assert.strictEqual(Math.max.apply(null, tops) -
                       Math.min.apply(null, tops), 0,
      "the configuration columns are on " + tops.length + " different rows " +
      "(tops " + tops.join(", ") + ") at " + LAYOUT_WIDTH + "px, so one of " +
      "them wrapped. `.pki-cols` is repeat(auto-fit, minmax(390px, 1fr)): a " +
      "minimum raised past 410px puts the third column on a row of its own " +
      "and makes the pane taller than the two-column version it replaced.");
    const heights = cols.map(function (c) { return c.height; });
    assert.ok(Math.min.apply(null, heights) >=
              Math.max.apply(null, heights) * 0.6,
      "the configuration columns are " + heights.join(", ") + "px tall. A " +
      "grid row is as tall as its tallest item, so the difference is dead " +
      "space — move a block between the columns rather than leaving it.");

    // The two rows the middle column's height turns on, and the ONE property
    // that says they are still rows. Both were two lines each — the algorithm
    // select on its own above the button, the format and password above the
    // Download button and its checkboxes — and those four lines are what left
    // the key-pair column ~70px below the two beside it.
    //
    // What is asserted is the BOTTOM edge, not the height. Above 1330px both
    // rows are `flex-wrap: nowrap` (css/pki.css) and `.saml-row` aligns its
    // items along their bottoms, so one flex line is one distinct bottom
    // however much a checkbox LABEL wraps inside it — which is what happens
    // between 1330 and 1530, and is a line of text rather than a row of
    // layout. A control that has moved onto a line of its own is a second
    // bottom and nothing else on the page would show it: the row still holds
    // every field, the page still works, and it is simply taller.
    const bands = await driver.executeScript(
      "return arguments[0].map(function (sel) {" +
      "  var row = document.querySelector(sel);" +
      "  if (!row) { return { sel: sel, missing: true }; }" +
      "  var bottoms = {};" +
      "  Array.prototype.forEach.call(row.children, function (c) {" +
      "    bottoms[Math.round(c.getBoundingClientRect().bottom)] = true;" +
      "  });" +
      "  return { sel: sel, lines: Object.keys(bottoms).length," +
      "           kids: row.children.length," +
      "           height: Math.round(row.getBoundingClientRect().height) };" +
      "});",
      ["#pane_config .pki-actions", "#pane_config .pki-export-row"]);
    bands.forEach(function (row) {
      assert.ok(!row.missing,
        "the row " + row.sel + " is gone. The key-pair column's height is " +
        "these two rows: the algorithm select, the JWK toggle, the issue " +
        "button and its reuse checkbox on one, and the keystore format, the " +
        "password, both checkboxes and Download on the other.");
      assert.strictEqual(row.lines, 1,
        row.sel + " is on " + row.lines + " lines at " + LAYOUT_WIDTH +
        "px (" + row.kids + " controls, " + row.height + "px tall). It is " +
        "meant to be one: `flex-wrap: nowrap` above 1330px makes a width it " +
        "cannot meet wrap a checkbox label instead of moving a control to a " +
        "line of its own. A control that is too wide to shrink — a longer " +
        "button caption, a `.pki-narrow` width raised past what it holds — " +
        "puts the line back and the column below its neighbours again.");
    });

    // The extension list's third column. `columns: 380px 3` is a maximum, so
    // this is measured from where the cards actually landed.
    const ext = await driver.executeScript(
      "var list = document.querySelector('.pki-ext-list');" +
      "if (!list) { return null; }" +
      "var cards = Array.prototype.slice.call(" +
      "  list.querySelectorAll('.pki-ext'));" +
      "var lefts = {};" +
      "var sum = 0;" +
      "cards.forEach(function (c) {" +
      "  var r = c.getBoundingClientRect();" +
      "  lefts[Math.round(r.left)] = true;" +
      "  sum += r.height;" +
      "});" +
      "return { cards: cards.length," +
      "         columns: Object.keys(lefts).length," +
      "         listHeight: list.getBoundingClientRect().height," +
      "         cardHeightSum: sum };");
    assert.ok(ext && ext.cards >= 20,
      "the extension list is missing or nearly empty: " + JSON.stringify(ext));
    assert.ok(ext.columns >= 3,
      "the " + ext.cards + " extension cards laid out in " + ext.columns +
      " column(s) at " + LAYOUT_WIDTH + "px. They are meant to flow in " +
      "three: `columns: 380px 3` in css/pki.css is a MAXIMUM, so one card " +
      "that stopped fitting 380px — a `.pki-flags` grid whose minimum grew " +
      "past 172px is the likely one — costs a whole column, about 400px of " +
      "page, whose only symptom is that you scroll further.");
    assert.ok(ext.listHeight < ext.cardHeightSum * 0.75,
      "the extension list is " + Math.round(ext.listHeight) + "px tall for " +
      Math.round(ext.cardHeightSum) + "px of cards, so the cards are " +
      "stacking rather than flowing into columns.");

    // No control hangs out of the column it is in — which is the overflow
    // the page CANNOT show you. `.pki-col` carries `min-width: 0` and its
    // items are `flex: 1 1 0`, so a control with a FIXED width does not
    // shrink with its column: it keeps that width and draws over whatever is
    // in the next one. There is no scrollbar (the grid itself still fits),
    // nothing is clipped, and the page height does not move — the only
    // symptom is two controls sharing a few pixels, which reads as a font
    // difference until it is measured.
    //
    // It is a shared-sheet omission that puts one there, so the check is over
    // every control rather than over the one that had it: saml_common.css
    // sizes `input[type="text"]`, `input[type="password"]`, `select` and
    // `textarea` at `width: 100%` and does not name `input[type="number"]`,
    // which left bootstrap.css's 220px on *Validity (years)* — 49px inside
    // the Key Pair column at this width, over the *Keystore Format* label
    // and select — and on the TLS pane's *Port*. Both are fixed in
    // css/pki.css. Any control type that sheet does not name arrives the
    // same way.
    const spill = await driver.executeScript(
      "var out = [];" +
      "Array.prototype.forEach.call(" +
      "  document.querySelectorAll('.pki-col'), function (col) {" +
      "  var cr = col.getBoundingClientRect();" +
      "  Array.prototype.forEach.call(" +
      "    col.querySelectorAll('input, select, textarea, label')," +
      "    function (e) {" +
      "    var r = e.getBoundingClientRect();" +
      "    if (r.width > 0 && r.right > cr.right + 1) {" +
      "      out.push((e.id || e.htmlFor || e.tagName) + ' (' +" +
      "        (e.type || e.tagName.toLowerCase()) + ') by ' +" +
      "        Math.round(r.right - cr.right) + 'px');" +
      "    }" +
      "  });" +
      "});" +
      "return out;");
    assert.deepStrictEqual(spill, [],
      "these controls are drawn outside the column they belong to at " +
      LAYOUT_WIDTH + "px: " + spill.join(", ") + ". A fixed width on a " +
      "control in a `flex: 1 1 0` field does not shrink with its column — " +
      "it overlaps the column beside it, with no scrollbar and no clipping " +
      "to say so. Give it `width: 100%` and `box-sizing: border-box` the " +
      "way css/saml_common.css does for every other control.");

    // Nothing scrolls sideways. The columns are grid and multi-column items
    // holding 64-character base64 lines, and a missing `min-width: 0` on
    // .pki-col reads as a broken page rather than as two words of CSS.
    const sideways = await driver.executeScript(
      "return document.documentElement.scrollWidth > window.innerWidth + 1;");
    assert.strictEqual(sideways, false,
      "the page scrolls horizontally at " + LAYOUT_WIDTH + "px");

    // And the whole point of all of it: the page is a third shorter than the
    // seven-pane version was. Checked last, so that when it fails the three
    // assertions above have already said which piece of the layout gave way.
    const pageHeight = await driver.executeScript(
      "return document.documentElement.scrollHeight;");
    assert.ok(pageHeight <= PAGE_HEIGHT_BUDGET,
      "the page is " + pageHeight + "px tall at " + LAYOUT_WIDTH + "x" +
      LAYOUT_HEIGHT + ", over the " + PAGE_HEIGHT_BUDGET + "px budget. It " +
      "measured ~2600px with the configuration pane in three columns, the " +
      "extension list in three and the TLS pane in two, down from 4941px " +
      "for the seven-pane version; the budget carries ~20% of slack for " +
      "font metrics, so this is not a few pixels of drift. Look for a pane " +
      "that came back, either list that fell a column, or prose that was " +
      "unfolded.");

    // The folds kept their prose, and hold nothing anybody has to operate.
    const folds = await driver.executeScript(
      "return Array.prototype.map.call(" +
      "  document.querySelectorAll('details.pki-more'), function (d) {" +
      "  var s = d.querySelector('summary');" +
      "  var body = (d.textContent || '').length -" +
      "             ((s && s.textContent) || '').length;" +
      "  return { summary: s ? (s.textContent || '').trim() : ''," +
      "           bodyLength: body," +
      "           open: d.open," +
      "           controls: d.querySelectorAll(" +
      "             'input, select, textarea, button').length };" +
      "});");
    assert.ok(folds.length >= 5,
      "the page has " + folds.length + " folded notes; the prose that was " +
      "taking the first screen is meant to be folded rather than cut");
    folds.forEach(function (f) {
      assert.ok(f.summary.length > 0,
        "a <details class=\"pki-more\"> has no summary, so nothing on " +
        "screen says what opening it gives you");
      assert.ok(f.bodyLength > 80,
        "the fold titled '" + f.summary + "' holds " + f.bodyLength +
        " characters. The prose is why this page is worth using and is " +
        "folded rather than cut; a summary whose paragraph was deleted in " +
        "some later tidy-up still opens and still says nothing.");
      assert.strictEqual(f.open, false,
        "the fold titled '" + f.summary + "' is open by default, which " +
        "gives back the space folding it saved");
      assert.strictEqual(f.controls, 0,
        "the fold titled '" + f.summary + "' contains " + f.controls +
        " form control(s). A fold is for prose: a checkbox behind a summary " +
        "is a setting nobody finds, and that costs a certificate rather " +
        "than an explanation.");
    });

    // And a fold opens. It is a <details> with no script behind it, so this
    // is cheap — and a summary that does not open is indistinguishable from
    // one whose paragraph is missing until you try.
    const opened = await driver.executeScript(
      "var d = document.querySelector('details.pki-more');" +
      "d.open = true;" +
      "var r = d.querySelector('p').getBoundingClientRect();" +
      "var visible = r.height > 0;" +
      "d.open = false;" +
      "return visible;");
    assert.strictEqual(opened, true,
      "opening a folded note showed nothing");
  } finally {
    await driver.manage().window().setRect(was);
  }
  log.debug("Leaving theConfigurationIsOnePane().");
}

// ---------------------------------------------------------------------------
// 2b. The serial number: filled in, editable, and a NEW one after every issue.
//
// The field used to be optional and empty, with x509.js picking a serial at
// issue time; now the page puts a random 128-bit one there on load and a fresh
// one there after every successful issue. Two of the three things asserted
// here fail silently:
//
//   * a serial that is shown but not the one signed makes the field a
//     decoration — the store row and the certificate would disagree with what
//     the operator read before pressing the button;
//   * a serial that does NOT rotate gives the next certificate from the same
//     CA the same (issuer, serial) pair, which is the one pair a CRL entry, an
//     OCSP request and every cache keyed on it cannot tell apart. The store
//     shows two rows differing everywhere else, so nothing on the page says
//     so.
//
// The reload in the middle is the third: newSerial() calls saveState() itself,
// because setVal() fires no event and the page's delegated change listener is
// what persists every `.stored` field.
// ---------------------------------------------------------------------------
const SERIAL_RE = /^[0-9a-f]{32}$/i;

async function theSerialIsFilledInEditableAndRotates(driver) {
  log.debug("Entering theSerialIsFilledInEditableAndRotates().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_serial"));
  await driver.executeScript("window.localStorage.clear();");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_serial"));

  const first = await valueOf(driver, "pki_serial");
  assert.ok(SERIAL_RE.test(first || ""),
    "the Serial Number field does not hold a random 128-bit hex value on " +
    "load, it holds " + JSON.stringify(first));
  assert.ok(parseInt(first.slice(0, 2), 16) < 0x80,
    "the generated serial has its top bit set, so DER encodes it with a " +
    "leading zero byte and parsers report a 17-byte serial: " + first);

  // It is saved like every other .stored field. setVal() fires no event, so
  // this is the assertion that fails if newSerial() ever stops calling
  // saveState() — and it fails on the NEXT page load, not on this one.
  await driver.navigate().refresh();
  await waitVisible(driver, By.id("pki_serial"));
  assert.strictEqual(await valueOf(driver, "pki_serial"), first,
    "the serial shown before a reload is not the one shown after it, so the " +
    "value the operator was reading was never persisted");

  // What is shown is what gets signed.
  const status = await issueThrough(driver, { profile: "root-ca",
    keyAlg: "ec-p256", sigAlg: "sha256-ecdsa", cn: "Page Serial Root" });
  assert.ok(status.indexOf(first.slice(0, 16)) >= 0,
    "the certificate was not issued with the serial the field was showing (" +
    first + "): " + status);
  let entries = await storeEntries(driver);
  assert.strictEqual(entries.length, 1,
    "expected one object in the store, found " + entries.length);
  assert.strictEqual(String(entries[0].serialHex).toLowerCase(),
    first.toLowerCase(),
    "the stored certificate's serial is not the one the form showed");

  // And a new one is waiting for the next certificate.
  const second = await valueOf(driver, "pki_serial");
  assert.ok(SERIAL_RE.test(second || ""),
    "the Serial Number field was not refilled after issuing, it holds " +
    JSON.stringify(second));
  assert.notStrictEqual(second.toLowerCase(), first.toLowerCase(),
    "the serial did not change after issuing, so the next certificate from " +
    "this CA would carry the same (issuer, serial) pair as the last one");

  // It is an ordinary field: a serial typed by hand is the one signed.
  const typed = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
  await issueThrough(driver, { profile: "root-ca", keyAlg: "ec-p256",
    sigAlg: "sha256-ecdsa", cn: "Page Serial Root Two",
    apply: async function (d) {
      await setField(d, "pki_serial", typed);
    } });
  entries = await storeEntries(driver);
  const typedEntry = entries.filter(function (e) {
    return e.subject.indexOf("Page Serial Root Two") >= 0;
  })[0];
  assert.ok(typedEntry,
    "the second certificate is not in the store: " +
    entries.map(function (e) { return e.subject; }).join(" | "));
  assert.strictEqual(String(typedEntry.serialHex).toLowerCase(), typed,
    "a serial typed into the field was not the one signed — the field is a " +
    "decoration rather than an input");
  const third = await valueOf(driver, "pki_serial");
  assert.ok(SERIAL_RE.test(third || "") && third.toLowerCase() !== typed,
    "a typed serial was left in the field after issuing, so pressing the " +
    "button twice signs it twice: " + JSON.stringify(third));
  log.debug("Leaving theSerialIsFilledInEditableAndRotates().");
}

// ---------------------------------------------------------------------------
// 2c. The rest of the subject DN, and the subjectAltName that follows the CN.
//
// The CN has followed the profile since the profiles existed; O/OU/L/ST/C are
// new on 2026-08-18 and behave DIFFERENTLY on purpose — they do not vary by
// profile, so they are filled once into whatever is empty and never replaced.
// The two rules are asserted together because the failure is the same one in
// both directions: a default that overwrites something typed loses work, and a
// default that never arrives leaves a DN with nothing in it but a CN.
//
// The subjectAltName is the one that matters most and shows least. For a TLS
// server the name a client checks is the SAN — every current browser ignores
// the Common Name — so a server certificate issued here with the CN filled in
// and the SAN empty is a certificate no client will accept, and nothing on the
// page or in the store says so. The two serverAuth profiles therefore tick the
// box and fill in `dns:` + their own CN, and picking a Root CA afterwards has
// to take it away again: `dns:server` on a root is a name that certificate has
// no business asserting.
// ---------------------------------------------------------------------------
async function theSubjectDefaultsAndTheSanFollowTheProfile(driver) {
  log.debug("Entering theSubjectDefaultsAndTheSanFollowTheProfile().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_dn_o"));
  await driver.executeScript("window.localStorage.clear();");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_dn_o"));

  // What the module defines is what the form holds.
  const DN_FIELDS = [["O", "pki_dn_o"], ["OU", "pki_dn_ou"],
                     ["L", "pki_dn_l"], ["ST", "pki_dn_st"],
                     ["C", "pki_dn_c"]];
  for (const [name, id] of DN_FIELDS) {
    const wanted = x509.DEFAULT_DN[name];
    assert.ok(wanted,
      "x509.js defines no DEFAULT_DN." + name + ", so this test is checking " +
      "the page against nothing");
    assert.strictEqual(await valueOf(driver, id), wanted,
      "the " + name + " field holds " +
      JSON.stringify(await valueOf(driver, id)) + " on a first load; " +
      "x509.js's DEFAULT_DN says " + JSON.stringify(wanted));
  }

  // Fill-only. A value in the field is somebody's, including one this page
  // put there yesterday, and the path that loses it is the RELOAD.
  await setField(driver, "pki_dn_o", "My Own Company Ltd");
  await selectOption(driver, "pki_profile", "tls-client");
  assert.strictEqual(await valueOf(driver, "pki_dn_o"), "My Own Company Ltd",
    "changing the profile overwrote an O that was typed by hand");
  await driver.navigate().refresh();
  await waitVisible(driver, By.id("pki_dn_o"));
  assert.strictEqual(await valueOf(driver, "pki_dn_o"), "My Own Company Ltd",
    "a reload overwrote an O that was typed by hand — the defaults are " +
    "applied after restoreState(), so this is the path that loses it");

  // The subjectAltName follows the profile, both ways.
  await selectOption(driver, "pki_profile", "tls-server");
  const wantedSan = x509.defaultSubjectAltName("tls-server");
  assert.ok(wantedSan,
    "x509.js gives the tls-server profile no default subjectAltName");
  assert.strictEqual(await valueOf(driver, "pki_san"), wantedSan,
    "choosing the TLS Server profile did not fill in the subjectAltName. " +
    "The CN is not what a TLS client checks, so a server certificate " +
    "without one is refused by every current browser — and neither the page " +
    "nor the store says why.");
  assert.strictEqual(await valueOf(driver, "pki_dn_cn"),
    x509.defaultSubjectCN("tls-server"),
    "the TLS Server profile's CN is not the module's");
  assert.strictEqual(wantedSan, "dns:" + x509.defaultSubjectCN("tls-server"),
    "the profile's default subjectAltName does not name its own CN, so the " +
    "certificate asserts one name and is called another");
  const sanOn = await driver.executeScript(
    "return document.getElementById('pki_ext_san').checked;");
  assert.strictEqual(sanOn, true,
    "the subjectAltName VALUE was filled in but the extension is not ticked, " +
    "so none of it reaches the certificate");

  await selectOption(driver, "pki_profile", "root-ca");
  assert.strictEqual(await valueOf(driver, "pki_san"), "",
    "a Root CA kept the TLS Server profile's subjectAltName. A root " +
    "asserting dns:" + x509.defaultSubjectCN("tls-server") + " is a name it " +
    "has no business carrying, and it is two columns away from where the " +
    "profile was chosen.");
  const stillOn = await driver.executeScript(
    "return document.getElementById('pki_ext_san').checked;");
  assert.strictEqual(stillOn, false,
    "the subjectAltName extension is still ticked with nothing in it");

  // The SAN follows the CN, which is the case this exists for: picking TLS
  // Server and then typing the name you actually want is the ordinary way to
  // use this page, and a SAN left saying dns:server while the CN says
  // something else is the same unusable certificate as no SAN at all.
  await selectOption(driver, "pki_profile", "tls-server");
  await setField(driver, "pki_dn_cn", "www.my-own-name.test");
  assert.strictEqual(await valueOf(driver, "pki_san"),
    "dns:www.my-own-name.test",
    "typing a CN under the TLS Server profile left the subjectAltName " +
    "naming " + JSON.stringify(await valueOf(driver, "pki_san")) + ". The " +
    "certificate would then assert one name and be called another, which is " +
    "the certificate this default is here to stop.");

  // And a name somebody typed is never touched.
  await setField(driver, "pki_san", "dns:something.else.test");
  await setField(driver, "pki_dn_cn", "www.changed-again.test");
  assert.strictEqual(await valueOf(driver, "pki_san"),
    "dns:something.else.test",
    "changing the CN overwrote a subjectAltName that was typed by hand");
  await selectOption(driver, "pki_profile", "tls-server-client");
  assert.strictEqual(await valueOf(driver, "pki_san"),
    "dns:something.else.test",
    "changing the profile overwrote a subjectAltName that was typed by hand");

  await driver.executeScript("window.localStorage.clear();");
  log.debug("Leaving theSubjectDefaultsAndTheSanFollowTheProfile().");
}

// ---------------------------------------------------------------------------
// 2d. Every control on the page has a tooltip.
//
// This page carries more fields than any other in the tree and, since
// 2026-08-18, its standing notes are gone: the prose that was a paragraph
// under a field is the `title` of that field. That is what took the page from
// ~2600px to ~2200px, and it is only an improvement while the tooltip is
// actually there — a field with neither a note nor a title is not compact, it
// is undocumented, and nothing on screen distinguishes the two.
//
// A control counts as documented if it has a title of its own, or its
// `label[for=…]` has one, or it sits inside a `<label>` that has one — the
// three shapes this page uses. Hidden inputs are skipped: `pki_selected` is
// state, not a field.
// ---------------------------------------------------------------------------
async function everyFieldHasATooltip(driver) {
  log.debug("Entering everyFieldHasATooltip().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_dn_cn"));

  const found = await driver.executeScript(
    "function tip(e) {" +
    "  if ((e.title || '').trim()) { return true; }" +
    "  if (e.id) {" +
    "    var l = document.querySelector('label[for=\"' + e.id + '\"]');" +
    "    if (l && (l.title || '').trim()) { return true; }" +
    "  }" +
    "  var p = e.parentElement;" +
    "  while (p) {" +
    "    if (p.tagName === 'LABEL' && (p.title || '').trim()) {" +
    "      return true;" +
    "    }" +
    "    p = p.parentElement;" +
    "  }" +
    "  return false;" +
    "}" +
    "var out = { total: 0, missing: [] };" +
    "Array.prototype.forEach.call(" +
    "  document.querySelectorAll('input, select, textarea'), function (e) {" +
    "  if (e.type === 'hidden') { return; }" +
    "  out.total++;" +
    "  if (!tip(e)) { out.missing.push((e.id || e.name || '(unnamed)') +" +
    "    ' [' + e.type + ']'); }" +
    "});" +
    "return out;");
  assert.ok(found.total >= 120,
    "only " + found.total + " controls were found on the page, so this " +
    "check is looking at the wrong document");
  assert.deepStrictEqual(found.missing, [],
    "these controls have no tooltip — not on themselves, not on their " +
    "label[for], not on a label around them: " + found.missing.join(", ") +
    ". The notes that used to explain them were moved into titles to shorten " +
    "the page, so a field without one now has no explanation anywhere.");
  log.debug("Leaving everyFieldHasATooltip(). " + found.total + " controls.");
}

// ---------------------------------------------------------------------------
// 2e. Not Before / Not After are date-and-time pickers, and an ISO 8601 string
//     stored by the older build still arrives.
//
// These four fields were text inputs holding ISO 8601 until 2026-08-18. A
// `datetime-local` input takes "YYYY-MM-DDTHH:MM" in LOCAL time and rejects
// anything else by silently setting itself to EMPTY — so the reload that
// upgrades somebody's page would have dropped the validity dates they had
// stored, with nothing anywhere to say why. restoreState() converts instead,
// which is what the second half of this asserts.
// ---------------------------------------------------------------------------
async function theValidityFieldsArePickers(driver) {
  log.debug("Entering theValidityFieldsArePickers().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_not_before"));

  const types = await driver.executeScript(
    "return arguments[0].map(function (id) {" +
    "  var e = document.getElementById(id);" +
    "  return id + '=' + (e ? e.type : '(missing)'); });",
    ["pki_not_before", "pki_not_after", "pki_pkup_not_before",
     "pki_pkup_not_after"]);
  types.forEach(function (pair) {
    assert.ok(/=datetime-local$/.test(pair),
      "a validity field is not a date-and-time picker: " +
      types.join(", ") + ". All four are pickers so that a date is chosen " +
      "rather than typed in a format that has to be explained.");
  });

  // A value the OLD build stored, arriving at the new one.
  await driver.executeScript(
    "window.localStorage.setItem('pkitools_pki_not_before'," +
    " '2031-03-04T05:06:07Z');" +
    "window.localStorage.setItem('pkitools_pki_not_after'," +
    " '2032-03-04T05:06:07Z');");
  await driver.navigate().refresh();
  await waitVisible(driver, By.id("pki_not_before"));
  const before = await valueOf(driver, "pki_not_before");
  const after = await valueOf(driver, "pki_not_after");
  assert.ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(before),
    "an ISO 8601 value stored by the older build came back as " +
    JSON.stringify(before) + ". A datetime-local input refuses anything but " +
    "YYYY-MM-DDTHH:MM by emptying itself, so without the conversion in " +
    "restoreState() the upgrade silently discards the dates.");
  assert.ok(/^2031-03-0[34]T/.test(before),
    "the converted Not Before is " + before + ", which is not the instant " +
    "that was stored (2031-03-04T05:06:07Z, in this machine's own zone)");
  assert.ok(/^2032-03-0[34]T/.test(after),
    "the converted Not After is " + after);

  // And a picked value is the one that gets signed.
  await driver.executeScript("window.localStorage.clear();");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_not_before"));
  await setField(driver, "pki_not_before", "2035-06-07T08:09");
  await setField(driver, "pki_not_after", "2036-06-07T08:09");
  await issueThrough(driver, { profile: "root-ca", keyAlg: "ec-p256",
    sigAlg: "sha256-ecdsa", cn: "Page Picker Root" });
  const entries = await storeEntries(driver);
  const issued = entries.filter(function (e) {
    return e.subject.indexOf("Page Picker Root") >= 0;
  })[0];
  assert.ok(issued, "the certificate issued with picked dates is not in the " +
    "store: " + entries.map(function (e) { return e.subject; }).join(" | "));
  assert.ok(/^2035-06-0[678]/.test(String(issued.notBefore)),
    "the certificate's notBefore is " + issued.notBefore + ", not the " +
    "2035-06-07 that was picked — the picker's value is local time and has " +
    "to reach the encoder as the instant it names");
  assert.ok(/^2036-06-0[678]/.test(String(issued.notAfter)),
    "the certificate's notAfter is " + issued.notAfter + ", not the " +
    "2036-06-07 that was picked");

  await driver.executeScript("window.localStorage.clear();");
  log.debug("Leaving theValidityFieldsArePickers().");
}

// ---------------------------------------------------------------------------
// 2f. "View certificate details" opens a page that can read what this one
//     issues — ALL of it, not the RSA quarter of it.
//
// That button hands the PEM to saml_cert.html through localStorage and opens
// it in a second tab. Until 2026-08-18 that page parsed with node-forge, whose
// certificateFromPem() reads the SubjectPublicKeyInfo eagerly and knows one
// algorithm, so every EC and every Ed25519 certificate — which is every
// certificate this page issues except the RSA ones — arrived at
//
//     Parse error: Cannot read public key. OID is not RSA.
//
// a message about a public key, on a page that had not got as far as the
// subject. It parses with x509.js now, which is the module the certificate was
// issued with.
//
// Neither module's own tests could see this: pki_x509.js never opens a
// browser, and this file never left the PKI page. So the assertion is made
// where the defect was — through the button, in the tab it opens, once per key
// algorithm.
// ---------------------------------------------------------------------------
async function theDetailsPageReadsEveryKeyAlgorithm(driver) {
  log.debug("Entering theDetailsPageReadsEveryKeyAlgorithm().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_key_alg"));
  await driver.executeScript("window.localStorage.clear();");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_key_alg"));

  // One per key algorithm family, because the family is what the old parser
  // could not read. The signature algorithm follows the key: a root is
  // self-signed, so it can only be signed with what its own key produces.
  //
  // EC FIRST, and deliberately: RSA is the one algorithm a parser that knows
  // only RSA gets right, so running it first makes the failure report
  // whatever the RSA case happens to trip over next instead of the message
  // the reader needs, which is on the second case.
  const CASES = [
    { keyAlg: "ec-p256", sigAlg: "sha256-ecdsa", cn: "Page View P256",
      key: /^ECDSA P-256$/ },
    { keyAlg: "ed25519", sigAlg: "ed25519", cn: "Page View Ed25519",
      key: /^Ed25519$/ },
    { keyAlg: "ec-p521", sigAlg: "sha512-ecdsa", cn: "Page View P521",
      key: /^ECDSA P-521$/ },
    { keyAlg: "rsa-2048", sigAlg: "sha256-rsa", cn: "Page View RSA",
      key: /^RSA 2048-bit$/ }
  ];

  const main = await driver.getWindowHandle();
  for (const item of CASES) {
    await issueThrough(driver, { profile: "root-ca", keyAlg: item.keyAlg,
      sigAlg: item.sigAlg, cn: item.cn });

    // Issuing shows the certificate but does not SELECT it, and the button
    // reads the selection — so this is the click a person makes.
    const picked = await driver.executeScript(
      "var want = arguments[0];" +
      "var rows = document.querySelectorAll('#pki_store_table tbody tr');" +
      "for (var i = 0; i < rows.length; i++) {" +
      "  if ((rows[i].textContent || '').indexOf(want) >= 0) {" +
      "    var radio = rows[i].querySelector('input[type=\"radio\"]');" +
      "    if (radio) { radio.click(); return true; }" +
      "  }" +
      "}" +
      "return false;", item.cn);
    assert.strictEqual(picked, true,
      "no row for " + item.cn + " in the store to select");

    const before = await driver.getAllWindowHandles();
    await click(driver, "pki_view_cert");
    await driver.wait(async function () {
      return (await driver.getAllWindowHandles()).length > before.length;
    }, CRYPTO_WAIT, "View certificate details opened no tab for " + item.cn);
    const opened = (await driver.getAllWindowHandles()).filter(function (h) {
      return before.indexOf(h) < 0;
    })[0];
    await driver.switchTo().window(opened);
    try {
      await waitVisible(driver, By.id("saml_cert_input"));
      // The page parses on load, so this waits for CONTENT rather than for
      // the element — per tests/wait_for.js.
      let status = "";
      await driver.wait(async function () {
        status = await valueOf(driver, "saml_cert_status");
        return !!(status && status.trim());
      }, CRYPTO_WAIT, "the details page never said whether it parsed " +
        item.cn);
      assert.ok(/^Parsed/.test(status),
        "the certificate details page could not read a " + item.keyAlg +
        " certificate: " + JSON.stringify(status) + ". It is handed the PEM " +
        "this page issued, so a parser that knows one public-key algorithm " +
        "fails here on every certificate but the RSA ones — and says so in a " +
        "message about a key, before it has shown the subject.");

      const rows = await driver.executeScript(
        "var t = document.getElementById('saml_cert_table');" +
        "if (!t) { return null; }" +
        "var out = {};" +
        "Array.prototype.forEach.call(t.querySelectorAll('tr')," +
        "  function (r) { out[r.cells[0].textContent] =" +
        "    r.cells[1].textContent; });" +
        "return out;");
      assert.ok(rows, "the details page printed no table for " + item.cn);
      assert.ok(rows.Subject && rows.Subject.indexOf(item.cn) >= 0,
        "the details page is showing " + JSON.stringify(rows.Subject) +
        " rather than the certificate that was selected (" + item.cn + ")");
      assert.ok(item.key.test(rows["Public Key"] || ""),
        "the details page describes the public key of a " + item.keyAlg +
        " certificate as " + JSON.stringify(rows["Public Key"]) + ". The " +
        "algorithm is in the SubjectPublicKeyInfo, so this is readable " +
        "without importing the key.");
      assert.ok((rows["SHA-256 Fingerprint"] || "").indexOf(":") > 0,
        "the details page shows no SHA-256 fingerprint for " + item.cn +
        ": " + JSON.stringify(rows["SHA-256 Fingerprint"]));
      assert.ok(Object.keys(rows).filter(function (k) {
        return k.indexOf("Extension") === 0;
      }).length >= 3,
        "a root CA has basicConstraints, keyUsage and two key identifiers; " +
        "the details page listed " + Object.keys(rows).filter(function (k) {
          return k.indexOf("Extension") === 0;
        }).length + " extension(s)");

      // And the way back. saml_cert.html is reached from ten pages and reads
      // ?from= to label its return link; a caller missing from that map
      // leaves the reader on a page with no way back to where they were.
      const back = await driver.executeScript(
        "var a = document.getElementById('return_link');" +
        "return a ? { href: a.getAttribute('href')," +
        "             text: (a.textContent || '').trim() } : null;");
      assert.ok(back && back.href === "/pki.html",
        "the details page's return link points at " +
        JSON.stringify(back && back.href) + " rather than back at the PKI " +
        "page it was opened from");
      assert.ok(/Certificate Authority/.test(back.text),
        "the return link reads " + JSON.stringify(back && back.text));
    } finally {
      await driver.close();
      await driver.switchTo().window(main);
    }
  }

  await driver.executeScript("window.localStorage.clear();");
  log.debug("Leaving theDetailsPageReadsEveryKeyAlgorithm().");
}

// ---------------------------------------------------------------------------
// 3. The workflow: a root, an intermediate, an issuing CA and a leaf, built
//    entirely through the form.
// ---------------------------------------------------------------------------
// The key pair is no longer generated by a button of its own: ONE button
// generates it and issues the certificate, because a pair that is never
// certified is kept nowhere and a certificate cannot be issued without one.
// So this asserts what the pair looked like AFTER the issue, which is the only
// moment it exists.
async function keyPairWasGenerated(driver, algId) {
  log.debug("Entering keyPairWasGenerated(). alg=" + algId);
  const priv = await valueOf(driver, "pki_private_key");
  assert.ok(priv && priv.indexOf("-----BEGIN") === 0,
    algId + ": the private key field did not fill");
  const publicPem = await valueOf(driver, "pki_public_key");
  assert.ok(publicPem.indexOf("-----BEGIN PUBLIC KEY-----") === 0,
    algId + ": the public key field does not hold a SubjectPublicKeyInfo PEM");
  log.debug("Leaving keyPairWasGenerated().");
}

async function issueThrough(driver, spec) {
  log.debug("Entering issueThrough(). subject=" + spec.cn);
  await selectOption(driver, "pki_key_alg", spec.keyAlg);
  await selectOption(driver, "pki_profile", spec.profile);
  if (spec.issuerSubject) {
    // The issuer dropdown holds store ids, so it is chosen by the label the
    // page renders rather than by an id no human ever sees.
    const chosen = await driver.executeScript(
      "var e = document.getElementById('pki_issuer');" +
      "var want = arguments[0];" +
      "for (var i = 0; i < e.options.length; i++) {" +
      "  if (e.options[i].textContent.indexOf(want) >= 0) {" +
      "    e.value = e.options[i].value;" +
      "    e.dispatchEvent(new Event('change', { bubbles: true }));" +
      "    return e.options[i].textContent;" +
      "  }" +
      "}" +
      "return null;", spec.issuerSubject);
    assert.ok(chosen,
      "the issuer dropdown does not offer '" + spec.issuerSubject +
      "'. Only CAs whose private key is still in this browser are listed, " +
      "so this is either a missing CA or a purged key.");
  }
  await selectOption(driver, "pki_sig_alg", spec.sigAlg);
  await setField(driver, "pki_dn_cn", spec.cn);
  await setField(driver, "pki_dn_o", "idptools test");
  await setField(driver, "pki_dn_c", "US");
  if (spec.san) {
    await setCheckbox(driver, "pki_ext_san", true);
    await setField(driver, "pki_san", spec.san);
  }
  if (spec.apply) await spec.apply(driver);

  await click(driver, "pki_issue");
  const status = await waitForIssueOutcome(driver,
      "the certificate for " + spec.cn + " to be issued");
  assert.ok(status.indexOf("Issued") >= 0,
    "issuing " + spec.cn + " failed: " + status);
  assert.ok(status.indexOf(spec.cn) >= 0,
    "the status line names a different subject than the one issued: " +
    status);
  await keyPairWasGenerated(driver, spec.keyAlg);
  log.debug("Leaving issueThrough().");
  return status;
}

async function theHierarchyIsBuiltThroughTheForm(driver) {
  log.debug("Entering theHierarchyIsBuiltThroughTheForm().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_key_alg"));
  await driver.executeScript("window.localStorage.clear();");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_key_alg"));

  // A different key algorithm and signature algorithm at each level: a
  // hierarchy where every link is the same shape is one where a mix-up cannot
  // show.
  await issueThrough(driver, { profile: "root-ca", keyAlg: "rsa-2048",
    sigAlg: "sha256-rsa", cn: "Page Root CA" });
  await issueThrough(driver, { profile: "intermediate-ca",
    keyAlg: "ec-p384", sigAlg: "sha384-rsapss", cn: "Page Intermediate CA",
    issuerSubject: "Page Root CA" });
  await issueThrough(driver, { profile: "issuing-ca", keyAlg: "ec-p256",
    sigAlg: "sha384-ecdsa", cn: "Page Issuing CA",
    issuerSubject: "Page Intermediate CA" });
  await issueThrough(driver, { profile: "tls-client", keyAlg: "ec-p256",
    sigAlg: "sha256-ecdsa", cn: "Page Client",
    issuerSubject: "Page Issuing CA",
    san: "email:client@example.test\nupn:client@EXAMPLE.TEST" });

  const entries = await storeEntries(driver);
  assert.strictEqual(entries.length, 4,
    "expected four objects in the store, found " + entries.length);
  const subjects = entries.map(function (e) { return e.subject; });
  ["Page Root CA", "Page Intermediate CA", "Page Issuing CA", "Page Client"]
    .forEach(function (cn) {
      assert.ok(subjects.filter(function (s) {
        return s.indexOf(cn) >= 0;
      }).length === 1, "the store has no entry for " + cn + ": " +
        subjects.join(" | "));
    });
  const leaf = entries.filter(function (e) {
    return e.subject.indexOf("Page Client") >= 0;
  })[0];
  assert.strictEqual(leaf.kind, "leaf",
    "a TLS client certificate is not a certificate authority");
  assert.ok(leaf.issuerId,
    "the leaf does not record which CA issued it, so its chain cannot be " +
    "assembled");
  assert.ok(leaf.privateKeyPem && leaf.certificatePem,
    "the leaf is missing its key or its certificate");
  assert.ok(entries.filter(function (e) { return e.kind === "ca"; })
      .length === 3, "expected three CAs");

  // The chain pane has to render, and every link has to verify — this is the
  // page's own reading of what it just built.
  await waitVisible(driver, By.id("pki_chain_table"));
  const chainText = await driver.executeScript(
    "var t = document.getElementById('pki_chain_table');" +
    "return t ? t.textContent : '';");
  assert.ok(chainText.indexOf("INVALID") < 0,
    "the chain pane reports an invalid signature:\n" + chainText);
  assert.ok(chainText.indexOf("NO") < 0,
    "the chain pane reports a name mismatch:\n" + chainText);
  assert.ok(chainText.indexOf("Page Root CA") >= 0,
    "the chain shown for the leaf does not reach the root:\n" + chainText);
  const links = await driver.executeScript(
    "var t = document.getElementById('pki_chain_table');" +
    "return t ? t.querySelectorAll('tbody tr').length : 0;");
  assert.strictEqual(links, 4,
    "expected four links in the chain, got " + links);

  // The extensions asked for are in the certificate, read back by the page's
  // own detail table — which is where a form field wired to the wrong id
  // shows.
  const detailText = await driver.executeScript(
    "var t = document.getElementById('pki_details_table');" +
    "return t ? t.textContent : '';");
  assert.ok(detailText.indexOf("client@example.test") >= 0,
    "the subjectAltName typed into the form is not in the issued " +
    "certificate:\n" + detailText);
  assert.ok(detailText.indexOf("clientAuth") >= 0,
    "the tls-client profile did not put clientAuth in the extendedKeyUsage:" +
    "\n" + detailText);
  assert.ok(/othername|UPN/i.test(detailText),
    "the UPN otherName is missing from the issued certificate:\n" +
    detailText);
  log.debug("Leaving theHierarchyIsBuiltThroughTheForm().");
}

// ---------------------------------------------------------------------------
// 4. The store survives a reload. A "certificate authority" that does not is
//    a generator.
// ---------------------------------------------------------------------------
async function theStoreSurvivesAReload(driver) {
  log.debug("Entering theStoreSurvivesAReload().");
  const before = await storeEntries(driver);
  assert.ok(before.length >= 4, "the previous section left nothing to reload");
  await driver.navigate().refresh();
  await waitVisible(driver, By.id("pki_key_alg"));
  const after = await storeEntries(driver);
  assert.strictEqual(after.length, before.length,
    "the store lost entries across a reload");
  const rows = await driver.executeScript(
    "var t = document.querySelector('#pki_store_table table tbody');" +
    "return t ? t.querySelectorAll('tr').length : 0;");
  assert.strictEqual(rows, before.length,
    "the store table shows " + rows + " rows for " + before.length +
    " stored objects");
  const count = await textOf(driver, "pki_store_count");
  assert.ok(count.indexOf(String(before.length)) >= 0,
    "the store count says " + count);

  // And the issuer dropdown has to be repopulated from it, or nothing further
  // can be signed after a reload.
  const issuers = await driver.executeScript(
    "var e = document.getElementById('pki_issuer');" +
    "return Array.prototype.map.call(e.options, function (o) {" +
    "  return o.textContent; });");
  assert.ok(issuers.filter(function (label) {
    return label.indexOf("Page Root CA") >= 0;
  }).length === 1, "the root CA is not offered as an issuer after a reload: " +
    issuers.join(" | "));
  log.debug("Leaving theStoreSurvivesAReload().");
}

// ---------------------------------------------------------------------------
// 5. The private-key opt-out, in both states — the same four things
//    keypair_storage_optout.js checks for the other protocols, adapted to a
//    store that holds many objects rather than one pair.
//
// The distinction that matters here and nowhere else: clearing the box strips
// the PRIVATE half and keeps the certificates. They are public documents, and
// throwing them away would lose the trust anchors and the chain along with the
// key.
// ---------------------------------------------------------------------------
async function thePrivateKeyOptOutIsReal(driver) {
  log.debug("Entering thePrivateKeyOptOutIsReal().");
  let entries = await storeEntries(driver);
  assert.ok(entries.length >= 4, "nothing in the store to opt out of");
  assert.ok(entries.every(function (e) { return !!e.privateKeyPem; }),
    "private keys should be saved by DEFAULT — the workflow depends on it, " +
    "and a CA whose key is gone cannot sign next week, which is the whole " +
    "point of a root");

  const box = await waitVisible(driver, By.id("pki_save_keys"));
  assert.strictEqual(await box.isSelected(), true,
    "the save-keys box must start checked");

  // 1. Clearing it PURGES what was already written.
  await setCheckbox(driver, "pki_save_keys", false);
  entries = await storeEntries(driver);
  assert.strictEqual(entries.length, 4,
    "clearing the box deleted objects; it must strip the private half only");
  assert.ok(entries.every(function (e) { return !e.privateKeyPem; }),
    "a private key survived the opt-out. Skipping future writes is not " +
    "enough — an opt-out that leaves yesterday's CA key in storage is not " +
    "an opt-out.");
  // 2. And the public half is KEPT, which is the distinction this page makes.
  assert.ok(entries.every(function (e) {
    return !!e.certificatePem && !!e.publicKeyPem;
  }), "the certificates were thrown away with the private keys. They are " +
    "public documents: keeping them is what leaves the trust anchors and " +
    "the chain usable.");

  const note = await textOf(driver, "pki_keys_storage_note");
  assert.ok(note && note.length > 0,
    "clearing the box must say what it costs, at the moment it is cleared");
  assert.ok(/sign|client certificate/i.test(note),
    "the note must say what stops working: " + note);

  // 3. The purge SURVIVES later saves. saveState() runs on nearly every
  //    interaction, so a guard that only fired in the change handler would put
  //    the key straight back on the next keystroke.
  await setField(driver, "pki_dn_cn", "Something Else Entirely");
  await setField(driver, "pki_tls_host", "example.test");
  entries = await storeEntries(driver);
  assert.ok(entries.every(function (e) { return !e.privateKeyPem; }),
    "a private key came back after an unrelated field was edited — the " +
    "purge must live in the write path, not in the change handler");

  // 4. A CA with no private key is not offered as an issuer, because it cannot
  //    sign. Offering it produces a Web Crypto error two clicks later naming
  //    neither the CA nor the missing key.
  const issuerCount = await driver.executeScript(
    "var e = document.getElementById('pki_issuer');" +
    "return Array.prototype.filter.call(e.options, function (o) {" +
    "  return o.value; }).length;");
  assert.strictEqual(issuerCount, 0,
    "certificate authorities whose private key was purged are still offered " +
    "as issuers");

  // The preference itself survives a reload, and the purge is not undone by
  // one.
  await driver.navigate().refresh();
  await waitVisible(driver, By.id("pki_save_keys"));
  const stillOff = await driver.findElement(By.id("pki_save_keys"));
  assert.strictEqual(await stillOff.isSelected(), false,
    "the preference did not survive a reload");
  entries = await storeEntries(driver);
  assert.ok(entries.every(function (e) { return !e.privateKeyPem; }),
    "a reload put the private keys back");
  assert.ok(entries.every(function (e) { return !!e.certificatePem; }),
    "a reload lost the certificates");

  // Turning it back ON must not resurrect anything — the keys are gone, and
  // saying otherwise would be worse than the loss.
  await setCheckbox(driver, "pki_save_keys", true);
  entries = await storeEntries(driver);
  assert.ok(entries.every(function (e) { return !e.privateKeyPem; }),
    "turning saving back on appeared to restore private keys that were " +
    "purged — they cannot come back, and pretending they have is worse than " +
    "the loss");
  log.debug("Leaving thePrivateKeyOptOutIsReal().");
}

// ---------------------------------------------------------------------------
// 5b. The subject CN follows the profile, and stops the moment somebody types
//     one of their own.
//
// An empty subject is a legal DN, so nothing about issuing fails without this
// — what it costs is four rows in the store that read the same and a chain
// view nobody can follow. The default is in x509.js beside the extension
// defaults, so this asserts through the page what the node tests assert
// through the module.
//
// Two of the three cases fail silently and neither is visible from the page:
//
//   * a default that does NOT move with the profile issues an intermediate
//     called "RootCA" — it chains correctly, it validates, and it
//     reads as a bug in the chain view rather than in the form;
//   * a default that overwrites a name somebody typed loses their work, and
//     the moment it happens is a page RELOAD, where onProfileChange() runs
//     again after restoreState() has just put their CN back in the field.
// ---------------------------------------------------------------------------
async function theSubjectCnFollowsTheProfile(driver) {
  log.debug("Entering theSubjectCnFollowsTheProfile().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_profile"));
  await driver.executeScript("window.localStorage.clear();");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_profile"));

  // Every profile fills the field, and no two kinds of certificate that a
  // reader has to tell apart in the store fill it with the same thing.
  const profiles = await driver.executeScript(
    "var e = document.getElementById('pki_profile');" +
    "return Array.prototype.map.call(e.options, function (o) {" +
    "  return o.value; });");
  const seen = {};
  for (const profileId of profiles) {
    await selectOption(driver, "pki_profile", profileId);
    const cn = await valueOf(driver, "pki_dn_cn");
    assert.ok(cn && cn.trim().length > 0,
      "the " + profileId + " profile left the CN empty. An empty subject is " +
      "a legal DN and a store full of rows nobody can tell apart.");
    seen[profileId] = cn;
  }
  ["root-ca", "intermediate-ca", "issuing-ca"].forEach(function (a) {
    ["root-ca", "intermediate-ca", "issuing-ca"].forEach(function (b) {
      if (a === b) return;
      assert.notStrictEqual(seen[a], seen[b],
        "the " + a + " and " + b + " profiles both default the CN to '" +
        seen[a] + "'. These three are issued one after another into the same " +
        "store and the chain view is read by subject.");
    });
  });
  assert.ok(/root/i.test(seen["root-ca"]),
    "the root CA profile defaults the CN to '" + seen["root-ca"] + "', " +
    "which does not say what it is");

  // A name somebody typed is never touched — not by a profile change, and not
  // by the reload that runs onProfileChange() over a restored field.
  await setField(driver, "pki_dn_cn", "my-own-name.test");
  await selectOption(driver, "pki_profile", "tls-server");
  assert.strictEqual(await valueOf(driver, "pki_dn_cn"), "my-own-name.test",
    "changing the profile overwrote a CN that was typed by hand");
  await driver.navigate().refresh();
  await waitVisible(driver, By.id("pki_dn_cn"));
  assert.strictEqual(await valueOf(driver, "pki_dn_cn"), "my-own-name.test",
    "a reload overwrote a CN that was typed by hand — onProfileChange() runs " +
    "after restoreState(), so this is the path that loses it");

  // And an emptied field is filled again, so clearing it is not a trap.
  await setField(driver, "pki_dn_cn", "");
  await selectOption(driver, "pki_profile", "issuing-ca");
  assert.strictEqual(await valueOf(driver, "pki_dn_cn"), seen["issuing-ca"],
    "an emptied CN was not refilled by the next profile change");

  await driver.executeScript("window.localStorage.clear();");
  log.debug("Leaving theSubjectCnFollowsTheProfile().");
}

// ---------------------------------------------------------------------------
// 6. The list fields' syntax, which is what the extension editor is made of.
//    Driven through the page's own exported parsers: the syntax is documented
//    on the page beside each field, and a parser that quietly accepts
//    something else is a certificate carrying something the operator did not
//    write.
// ---------------------------------------------------------------------------
async function theListFieldSyntaxIsWhatThePageDocuments(driver) {
  log.debug("Entering theListFieldSyntaxIsWhatThePageDocuments().");
  // NOTE: everything inside these executeScript strings runs IN THE BROWSER.
  const altNames = await driver.executeScript(
    "return JSON.stringify(pki.parseAltNames(" +
    "'dns:a.example\\nip:10.0.0.1\\nemail:x@y.z\\nuri:https://q/\\n" +
    "upn:u@R\\nkrb5:host/h@R\\nrid:1.2.3\\ndirname:CN=x\\n" +
    "othername:1.2.3.4:BQA='));");
  const parsed = JSON.parse(altNames);
  assert.strictEqual(parsed.length, 9,
    "expected nine alternative names, got " + parsed.length);
  assert.deepStrictEqual(parsed.map(function (n) { return n.kind; }),
    ["dns", "ip", "email", "uri", "upn", "krb5", "registeredID", "dirName",
     "otherName"],
    "the alternative-name syntax parsed to the wrong types: " + altNames);
  assert.strictEqual(parsed[8].oid, "1.2.3.4",
    "an othername's OID was lost");

  const constraints = await driver.executeScript(
    "return JSON.stringify(pki.parseNameConstraints(" +
    "'permit dns:good.example\\nexclude ip:10.0.0.0/8'));");
  const nc = JSON.parse(constraints);
  assert.strictEqual(nc.permitted.length, 1, "one permitted subtree");
  assert.strictEqual(nc.excluded.length, 1, "one excluded subtree");
  assert.strictEqual(nc.excluded[0].value, "10.0.0.0/8",
    "the excluded IP prefix was mangled: " + constraints);

  const policies = await driver.executeScript(
    "return JSON.stringify(pki.parsePolicies(" +
    "'1.2.3|cps=https://c/|notice=hello there'));");
  const pol = JSON.parse(policies)[0];
  assert.strictEqual(pol.oid, "1.2.3", "the policy OID was lost");
  assert.strictEqual(pol.cps, "https://c/", "the CPS URI was lost");
  assert.strictEqual(pol.notice, "hello there",
    "the user notice was lost (and a notice with a space in it is the " +
    "normal case)");

  const aia = await driver.executeScript(
    "return JSON.stringify(pki.parseAiaEntries(" +
    "'ocsp:http://o/\\ncaissuers:http://c/'));");
  assert.deepStrictEqual(JSON.parse(aia),
    [{ method: "ocsp", url: "http://o/" },
     { method: "caIssuers", url: "http://c/" }],
    "the access-description syntax parsed to " + aia);

  const custom = await driver.executeScript(
    "return JSON.stringify(pki.parseCustomExtensions('1.2.3|critical|BQA='));");
  assert.deepStrictEqual(JSON.parse(custom),
    [{ oid: "1.2.3", critical: true, value: "BQA=" }],
    "the custom-extension syntax parsed to " + custom);

  // A malformed line has to be refused BY NAME rather than silently dropped:
  // a certificate quietly missing the name somebody typed is the failure this
  // whole page exists to avoid.
  const refusal = await driver.executeScript(
    "try { pki.parseAltNames('example.com'); return null; }" +
    "catch (e) { return e.message; }");
  assert.ok(refusal && /has no type/.test(refusal),
    "an alternative name with no type must be refused by name, got: " +
    refusal);
  log.debug("Leaving theListFieldSyntaxIsWhatThePageDocuments().");
}

// ---------------------------------------------------------------------------
// 7. The TLS test, end to end through the api.
//
// It is pointed at the CLIENT's own plain-HTTP port, which is a deliberate
// choice: a handshake that FAILS with a real alert proves the whole round trip
// — page to api, api to socket, report back to page — and needs no TLS service
// of its own. A handshake that succeeds against a service this suite happens
// to have would prove less and skip more often.
// ---------------------------------------------------------------------------
// The TLS pane on a build that declares it has no api — the static
// deployments, where client/static_site.js greys the landing cards of the three
// workflows that are not there at all and this one is deliberately NOT among
// them: the certificate authority, every X.509v3 extension and the whole
// keystore matrix are Web Crypto and pkijs in the browser and work there
// exactly as they do here. One pane cannot, so one pane is switched off.
//
// Both halves are asserted because they fail independently and only one of
// them can be seen: the class is what greys the pane, `disabled` is what stops
// it being used. A pane that only looks dead still submits when somebody
// presses Return in a text field, and runTlsTest()'s own refusal is then the
// first thing that says anything — one status line at the bottom of a pane
// full of live-looking controls.
async function theTlsPaneIsSwitchedOffWithoutAnApi(driver) {
  log.debug("Entering theTlsPaneIsSwitchedOffWithoutAnApi().");
  // NOTE: the function body inside this executeScript string runs IN THE
  // BROWSER, where there is no bunyan — so it carries no logging, per the
  // repo-root CLAUDE.md. What it returns is logged out here.
  const state = await driver.executeScript(
    "var pane = document.getElementById('pane_tls');" +
    "var body = document.getElementById('pane_tls_body');" +
    "var notice = document.getElementById('pki_tls_unavailable');" +
    "if (!pane || !body) return null;" +
    "var controls = body.querySelectorAll(" +
    "    'input, select, textarea, button');" +
    "var live = [];" +
    "for (var i = 0; i < controls.length; i++) {" +
    "  if (!controls[i].disabled) {" +
    "    live.push(controls[i].id || controls[i].name ||" +
    "        controls[i].tagName); } }" +
    "return { greyed: (' ' + pane.className + ' ')" +
    "    .indexOf(' pki-pane-disabled ') >= 0," +
    "  controls: controls.length," +
    "  live: live," +
    "  noticeShown: !!notice &&" +
    "      window.getComputedStyle(notice).display !== 'none' };");
  assert.ok(state, "the TLS pane is missing from the page");
  log.info("The TLS pane on this backend-less build: greyed=" + state.greyed +
    ", controls=" + state.controls + ", still enabled=" + state.live.length +
    ", notice shown=" + state.noticeShown + ".");
  assert.ok(state.greyed,
    "this build has no api — the backend notice is on the page — but " +
    "#pane_tls does not carry pki-pane-disabled, so the TLS pane is not " +
    "greyed out. See disableTlsPane() in client/src/pki.js.");
  // Without this the check below passes on a pane whose controls the markup
  // no longer holds, which is the shape of a test that quietly does nothing.
  assert.ok(state.controls > 0,
    "the TLS pane has no controls at all, so the enabled-control check " +
    "measures nothing. Either the pane was emptied or the ids moved.");
  assert.deepStrictEqual(state.live, [],
    "this build has no api, but " + state.live.length + " control(s) in the " +
    "TLS pane are still enabled: " + state.live.join(", ") + ". Greying is " +
    "not switching off — a live control still submits on a Return keypress.");
  assert.ok(state.noticeShown,
    "the TLS pane is greyed but #pki_tls_unavailable is not on the page, so " +
    "nothing on it says why it is off.");
  log.debug("Leaving theTlsPaneIsSwitchedOffWithoutAnApi().");
}

async function theTlsTestGoesThroughTheApi(driver) {
  log.debug("Entering theTlsTestGoesThroughTheApi().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_tls_host"));

  // Is there an api behind this build? Read the RENDERED banner rather than
  // its inline style. pki.js's show() sets an inline display AND toggles the
  // saml-hidden class, and for a long time it set only the inline one while
  // `.saml-notice.saml-hidden { display: none }` kept the banner off the page.
  // A check written against the inline style cannot see that: it agrees with
  // the caller rather than with the user, which is exactly how the banner came
  // to be invisible on every static deployment with this test green.
  const backendNoticeShown = await driver.executeScript(
    "var e = document.getElementById('pki_backend_notice');" +
    "if (!e) return false;" +
    "return window.getComputedStyle(e).display !== 'none';");
  if (backendNoticeShown) {
    // Not a bare skip. On a deployment with no api this pane must be OFF, and
    // that is a property of exactly this build — so the section that cannot
    // run here is replaced by the assertion that belongs here instead, rather
    // than by a log line saying nothing was checked.
    await theTlsPaneIsSwitchedOffWithoutAnApi(driver);
    log.info("The TLS section proper is not run here: this build has no api " +
      "behind it (backendAvailable is false). The pane was checked to be " +
      "switched off instead.");
    log.debug("Leaving theTlsTestGoesThroughTheApi(). No api on this build.");
    return;
  }

  // The api's limits have to arrive, or the page cannot say what it will and
  // will not do before a call fails.
  await driver.wait(async function () {
    const text = await textOf(driver, "pki_tls_limits");
    return text && text.trim().length > 0;
  }, CRYPTO_WAIT, "the page never read GET /tls/limits");
  const limits = await textOf(driver, "pki_tls_limits");
  assert.ok(/connect budget|will connect to/.test(limits),
    "the limits line does not say what the api will do: " + limits);

  const target = new URL(baseUrl);
  await setField(driver, "pki_tls_host", target.hostname);
  await setField(driver, "pki_tls_port",
      target.port || (target.protocol === "https:" ? "443" : "80"));
  await setField(driver, "pki_tls_servername", target.hostname);
  await setCheckbox(driver, "pki_tls_probe_mutual", false);

  await click(driver, "pki_tls_run");
  // Wait for a SETTLED status rather than for any change. The pane writes
  // "Connecting to host:port…" the moment the button is pressed, so a
  // wait-for-anything-different is satisfied by the page's own progress
  // message and asserts on a call that has not happened yet.
  let status = "";
  await driver.wait(async function () {
    status = (await textOf(driver, "pki_tls_status")) || "";
    return status.trim().length > 0 && !/^Connecting/.test(status.trim());
  }, CRYPTO_WAIT, "the TLS test never came back from the api (the status " +
    "line is still the page's own progress message)");
  assert.ok(!/could not be run/i.test(status),
    "the call to the api failed rather than the handshake: " + status);

  await waitVisible(driver, By.id("pki_tls_table"));
  const reportText = await driver.executeScript(
    "var t = document.getElementById('pki_tls_table');" +
    "return t ? t.textContent : '';");
  assert.ok(reportText.indexOf("Connected") >= 0,
    "the report has no Connected row:\n" + reportText);
  if (target.protocol === "http:") {
    // A plain-HTTP port cannot complete a TLS handshake, and the report has to
    // say so with the far end's own error rather than a blank pane.
    assert.ok(/Handshake error/.test(reportText),
      "a TLS handshake against a plain-HTTP port must be reported as a " +
      "handshake error, with the alert — that alert is the most " +
      "informative thing this endpoint produces:\n" + reportText);
    assert.ok(/did not complete/i.test(status),
      "the status line should say the handshake did not complete: " + status);
  }

  // The operations history records it — three of this page's four operations
  // never leave the browser and the fourth is this one.
  const historyText = await driver.executeScript(
    "var e = document.getElementById('pki_operation_history');" +
    "return e ? e.textContent : '';");
  assert.ok(historyText.indexOf("TLS test connection") >= 0,
    "the TLS test is not in the operations history:\n" + historyText);
  log.debug("Leaving theTlsTestGoesThroughTheApi().");
}

// ---------------------------------------------------------------------------
// 8. The browser console must be clean. A page that throws on load looks
//    exactly like a page that is working until something on it is used.
// ---------------------------------------------------------------------------
async function theBrowserConsoleIsClean(driver) {
  log.debug("Entering theBrowserConsoleIsClean().");
  const entries = await driver.manage().logs().get(logging.Type.BROWSER);
  const severe = entries.filter(function (entry) {
    if (entry.level.name !== "SEVERE") return false;
    // A failed fetch to an api that is not there is this page saying so, not
    // a defect in it; the assertions above cover whether it said so.
    if (/favicon/.test(entry.message)) return false;
    return true;
  });
  assert.deepStrictEqual(severe.map(function (e) { return e.message; }), [],
    "the browser console carries severe errors, which on this page means a " +
    "bundle that did not load or a handler that threw");
  log.debug("Leaving theBrowserConsoleIsClean().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying " + baseUrl + PAGE);

  const options = new chrome.Options();
  // --headless=new, NOT plain --headless. The tests image pins Chrome 121,
  // where plain --headless selects the OLD headless implementation — and in
  // that one --unsafely-treat-insecure-origin-as-secure has no effect, so on
  // the containerized suite's http://client:3000 origin window.crypto.subtle
  // stays undefined however carefully browser_flags.js was called. Every key
  // pair on this page needs it, and the symptom is a timeout waiting for a
  // field that never fills, naming neither crypto nor headless mode.
  if (headless) {
    options.addArguments("--headless=new");
  }
  // --no-sandbox and --disable-dev-shm-usage are what make Chrome start AT ALL
  // in the tests image, and this file and pki_page.js were the only two of the
  // fifty browser tests here without them. The failure is not a missing flag
  // and does not mention one: Chrome exits during startup and chromedriver
  // reports "session not created: Chrome failed to start: exited normally
  // (DevToolsActivePort file doesn't exist)", before the first driver.get().
  // The container has no user namespaces for the sandbox to use, and its
  // /dev/shm is the docker default 64MB, which the renderer outgrows. Neither
  // shows up on a host run, where both tests passed while the containerized
  // suite could not open a window.
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage");
  // The secure-context and private-network hazards. This page is ALL Web
  // Crypto, so it is exactly the kind that fails without these.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  // And the third hazard, which is this page's alone: Chrome enabled Ed25519
  // in Web Crypto by default only in Chrome 137, and the tests image pins 121.
  // Without it the ed25519 case below fails as an 'importKey' error on a
  // certificate — see the function's own comment in browser_flags.js — so a
  // key algorithm this page offers is one the browser running the test cannot
  // produce. No other browser test here needs this: digital_signature.js signs
  // Ed25519 through @noble rather than through crypto.subtle.
  browserFlags.addWebCryptoEd25519Flags(options);

  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  // The in-page work here (an RSA key pair, four certificates) is bounded by
  // the WebDriver SCRIPT timeout, which is set separately from every
  // driver.wait in this suite and defaults to 30s. A CI runner is about twice
  // as slow as a dev host on identical code, so it is set explicitly rather
  // than inherited.
  await driver.manage().setTimeouts({ script: 60000 });

  try {
    await thePageOffersWhatTheModulesDefine(driver);
    await theConfigurationIsOnePane(driver);
    await theSubjectCnFollowsTheProfile(driver);
    await theSerialIsFilledInEditableAndRotates(driver);
    await theSubjectDefaultsAndTheSanFollowTheProfile(driver);
    await everyFieldHasATooltip(driver);
    await theValidityFieldsArePickers(driver);
    await theListFieldSyntaxIsWhatThePageDocuments(driver);
    await theDetailsPageReadsEveryKeyAlgorithm(driver);
    await theHierarchyIsBuiltThroughTheForm(driver);
    await theStoreSurvivesAReload(driver);
    await thePrivateKeyOptOutIsReal(driver);
    await theTlsTestGoesThroughTheApi(driver);
    await theBrowserConsoleIsClean(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    try {
      const url = await driver.getCurrentUrl();
      log.error("Current URL: " + url);
      const entries = await driver.manage().logs().get(logging.Type.BROWSER);
      entries.slice(-15).forEach(function (entry) {
        log.error("browser: " + entry.level.name + " " + entry.message);
      });
    } catch (e) {
      log.error("could not collect the browser log: " + e.message);
    }
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("pki_page")
  .description("Verify the PKI page: the CA hierarchy through the form, the " +
      "store, the private-key opt-out, and the api-only TLS test.")
  .addOption(new Option("-u, --url <url>",
      "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser",
      "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
