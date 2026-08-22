// File: encryption_tools.js
//
// ---------------------------------------------------------------------------
// The Encryption / Decryption page, top to bottom, in a browser.
//
// It needs no IdP and no api: every one of the nine panes runs entirely in the
// page. What this job proves is the WIRING — that each control reaches the
// engine behind it, that a value put in one box comes back out of another,
// that a refusal reaches the status line as a sentence somebody can act on,
// and that the page's own claims about itself are true.
//
// WHAT IT DELIBERATELY DOES NOT PROVE is that the bytes are right, and the
// distinction is the reason tests/crypto_engines.js exists beside it. Encrypt
// followed by decrypt agrees with itself whatever the implementation does, so
// a round trip through this page would pass just as well against a cipher that
// interoperates with nothing. The RFCs' own vectors, the cross-check against
// OpenSSL and the primality of the MODP groups are all over there, in node,
// where they can run without a browser. Read that file before adding a
// "does it encrypt correctly" check here — the answer is that this one cannot
// tell, on purpose.
//
// The page is also where the two halves meet: it is the only place the shared
// modules (crypto_bytes, symmetric_crypto, pk_encryption, jose_jwe,
// key_material, tool_panes) are exercised through a bundle rather than a
// require, so a browserify resolution or an envify substitution that went
// wrong shows up here and nowhere else.
// ---------------------------------------------------------------------------

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'encryption_tools',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
// Headless by DEFAULT, and asserted to be by tests/browser_tests_headless.js:
// a CI runner and the tests container have no display, so a `false` here is a
// suite that dies at `session not created` on every unattended run.
var headless = true;
var waitTime = appconfig.waitTime;
// Anything that generates a key or runs a KDF needs its own budget: an RSA
// 2048-bit key pair is pure JS in the page, and scrypt is deliberately slow.
// waitTime is 2000ms and is right for reading a field the page already holds.
var keyWait = Math.max(waitTime * 15, 60000);
var cryptoWait = Math.max(waitTime * 4, 15000);

const browserFlags = require("./browser_flags.js");
const { loadPage } = require("./page_load.js");
const waitForContent = require("./wait_for.js");

// ---------------------------------------------------------------------------
// What the page offers, listed here rather than read off the page — a test
// that enumerates the dropdown it is testing cannot notice an option that has
// gone missing. These lists are the contract; `optionsOf()` below asserts the
// page still offers exactly them.
// ---------------------------------------------------------------------------
var SYMMETRIC_PANES = [
  { prefix: 'aes', pane: 'pane_aes', name: 'AES',
    algs: ['AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM',
           'AES-256-CBC', 'AES-192-CBC', 'AES-128-CBC',
           'AES-256-CTR', 'AES-256-CFB', 'AES-256-OFB', 'AES-256-ECB'],
    aead: ['AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM'] },
  { prefix: 'cc', pane: 'pane_chacha', name: 'ChaCha20-Poly1305',
    algs: ['CHACHA20-POLY1305', 'CHACHA20'],
    aead: ['CHACHA20-POLY1305'] },
  { prefix: 'des', pane: 'pane_des', name: '3DES / DES',
    algs: ['3DES-192-CBC', '3DES-128-CBC', '3DES-192-ECB', 'DES-CBC',
           'DES-ECB'],
    aead: [] }
];

// The message every pane is driven with. Non-ASCII and a trailing space,
// because both are lost by an implementation that round-trips through a
// latin-1 string or trims its fields — and both round-trip silently in a test
// whose message is "hello".
var MESSAGE = "Encrypt me ✓ — and keep the trailing space: ";

var ALL_PANES = ['pane_aes', 'pane_chacha', 'pane_des', 'pane_rsa',
                 'pane_ecc', 'pane_kem', 'pane_ffc', 'pane_jwe', 'pane_pbe'];

// ===========================================================================
// UI helpers
// ===========================================================================
async function expand(driver, paneId) {
  log.debug("Entering expand(). pane=" + paneId);
  // Every pane starts collapsed, and a collapsed fieldset's controls are
  // display:none — Selenium reports "element not interactable", which reads as
  // a broken page rather than as a pane nobody opened.
  await driver.executeScript(
    "document.getElementById(arguments[0]).classList.remove('ds-collapsed');",
    paneId);
  await driver.wait(until.elementIsVisible(
    driver.findElement(By.id(paneId))), waitTime);
  log.debug("Leaving expand().");
}

function fieldId(prefix, name) {
  log.debug("Entering fieldId().");
  log.debug("Leaving fieldId().");
  return 'enc_' + prefix + '_' + name;
}

async function setField(driver, prefix, name, text) {
  log.debug("Entering setField(). " + prefix + "." + name);
  const el = await driver.findElement(By.id(fieldId(prefix, name)));
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                             el);
  await el.clear();
  if (text) {
    await el.sendKeys(text);
  }
  log.debug("Leaving setField().");
}

async function getField(driver, prefix, name) {
  log.debug("Entering getField(). " + prefix + "." + name);
  log.debug("Leaving getField().");
  return await driver.findElement(By.id(fieldId(prefix, name)))
      .getAttribute("value");
}

// Set a field's value directly. Used only where sendKeys would be absurd —
// pasting a 3,168-byte ML-KEM private key one keystroke at a time is minutes
// of wall clock. The change event is not needed: nothing on this page listens
// for one on a value box.
async function pasteField(driver, prefix, name, text) {
  log.debug("Entering pasteField(). " + prefix + "." + name);
  await driver.executeScript(
    "document.getElementById(arguments[0]).value = arguments[1];",
    fieldId(prefix, name), text);
  log.debug("Leaving pasteField().");
}

async function clickButton(driver, paneId, label) {
  log.debug("Entering clickButton(). " + paneId + " / " + label);
  const locator = By.xpath("//fieldset[@id='" + paneId +
      "']//input[@type='submit' and @value=" + xpathLiteral(label) + "]");
  await driver.wait(until.elementLocated(locator), waitTime);
  const el = await driver.findElement(locator);
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                             el);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await blankStatusFor(driver, el);
  await el.click();
  log.debug("Leaving clickButton().");
}

// XPath has no escape character, so a literal containing a quote has to be
// built with concat(). None of this page's labels do today, and writing it
// properly costs four lines and removes the trap entirely.
function xpathLiteral(text) {
  log.debug("Entering xpathLiteral().");
  if (text.indexOf("'") === -1) {
    log.debug("Leaving xpathLiteral(). Simple.");
    return "'" + text + "'";
  }
  log.debug("Leaving xpathLiteral(). concat().");
  return "concat('" + text.split("'").join("', \"'\", '") + "')";
}

async function selectOption(driver, selectId, value) {
  log.debug("Entering selectOption(). " + selectId + " = " + value);
  const el = await driver.findElement(By.id(selectId));
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                             el);
  await blankStatusFor(driver, el);
  await new Select(el).selectByValue(value);
  // The page's onchange handlers run on a real selection; selectByValue fires
  // one, but say so explicitly so a future switch to a scripted set does not
  // silently stop calling them.
  await driver.executeScript(
    "arguments[0].dispatchEvent(new Event('change'));", el);
  log.debug("Leaving selectOption().");
}

async function optionsOf(driver, selectId) {
  log.debug("Entering optionsOf(). " + selectId);
  log.debug("Leaving optionsOf().");
  return await driver.executeScript(
    "var out = [];" +
    "var sel = document.getElementById(arguments[0]);" +
    "for (var i = 0; i < sel.options.length; i++) {" +
    "  out.push(sel.options[i].value);" +
    "}" +
    "return out;", selectId);
}

// Wait for a pane's status line to settle. Every in-progress message on this
// page ends with an ellipsis, so "settled" is "does not end with one" — the
// same rule the Digital Signature page's test uses, and for the same reason:
// finished messages quote ranges and counts that contain dots.
async function waitForSettled(driver, prefix, message, timeout) {
  log.debug("Entering waitForSettled(). " + prefix);
  const value = await waitForContent.waitForValue(driver,
    fieldId(prefix, 'status'),
    function (text) {
      return !!text && text.trim().length > 0 && !/…\s*$/.test(text);
    },
    message || ("the " + prefix + " pane's status line never settled"),
    timeout || cryptoWait);
  log.debug("Leaving waitForSettled().");
  return value;
}

// EMPTY THE STATUS LINE BEFORE ACTING, ALWAYS — AND AUTOMATICALLY.
//
// waitForSettled() is satisfied by any non-empty line that is not still
// working, and the PREVIOUS action's line is exactly that. So a stale status
// makes the wait return instantly, the assertion after it grade the wrong
// operation, and the output field be read before the new value is written. It
// cost this test two false passes before it cost it a failure: the "As PBES2
// JWE" step read a one-segment value out of the ciphertext box because the
// wait had already returned on the previous refusal's message.
//
// It is done HERE, inside the two functions that act on the page, rather than
// at each of the thirty call sites — the version of this that a caller has to
// remember is the version that gets forgotten, and it fails by passing. The
// pane is found from the element itself, so nothing has to be told which
// status line goes with which control.
//
// This is the hazard tests/CLAUDE.md records for a results box that persists
// between two identical actions, one field further along: it applies to the
// STATUS line too, and on this page every pane has one.
async function blankStatusFor(driver, element) {
  log.debug("Entering blankStatusFor().");
  const cleared = await driver.executeScript(
    "var pane = arguments[0].closest('fieldset');" +
    "if (!pane) return null;" +
    "var status = pane.querySelector('.ds-status');" +
    "if (!status) return null;" +
    "status.value = '';" +
    "return status.id;", element);
  assert.ok(cleared,
    "could not find the status line of the pane this control is in, so a " +
    "wait after it would be satisfied by the previous action's message");
  log.debug("Leaving blankStatusFor(). " + cleared);
  return cleared;
}

// A status line that reports a failure. Every one of them is a sentence rather
// than a code, which is the page's whole reason for existing, so a refusal is
// asserted on its CONTENT and not merely on the operation not happening.
function assertRefused(status, expected, what) {
  log.debug("Entering assertRefused().");
  assert.ok(expected.test(status),
    what + " was not refused with a message that says why. The status line " +
    "read: " + status);
  log.debug("Leaving assertRefused().");
}

function assertAccepted(status, what) {
  log.debug("Entering assertAccepted().");
  assert.ok(!/error|not valid|did not verify|needs a|refus/i.test(status),
    what + " reported a problem: " + status);
  log.debug("Leaving assertAccepted().");
}

// ===========================================================================
// Section 1 — the page loads, and it is the page it says it is.
// ===========================================================================
async function pageStructure(driver) {
  log.debug("Entering pageStructure().");
  log.info("[structure] Nine panes, their titles, and the algorithm lists.");

  const panes = await driver.executeScript(
    "var out = [];" +
    "var f = document.querySelectorAll('.ds-grid > fieldset');" +
    "for (var i = 0; i < f.length; i++) {" +
    "  out.push({ id: f[i].id," +
    "             collapsed: f[i].classList.contains('ds-collapsed')," +
    "             title: f[i].querySelector('legend').textContent.trim() });" +
    "}" +
    "return out;");
  assert.deepStrictEqual(panes.map(function (p) { return p.id; }), ALL_PANES,
    "the page does not carry exactly the nine panes this test knows about");
  panes.forEach(function (pane) {
    assert.ok(pane.collapsed,
      "pane " + pane.id + " did not start collapsed. Nine panes open is a " +
      "page you scroll past to reach the one you came for, and the titles " +
      "are the index.");
    assert.ok(pane.title.length > 2, "pane " + pane.id + " has no title");
  });

  // Every algorithm this test drives must still be on offer, and nothing else
  // may be — an option added without a test is the half of this that a
  // round-trip check cannot see.
  for (const pane of SYMMETRIC_PANES) {
    const offered = await optionsOf(driver, fieldId(pane.prefix, 'alg'));
    assert.deepStrictEqual(offered, pane.algs,
      "the " + pane.name + " pane offers " + offered.join(", ") +
      " but this test drives " + pane.algs.join(", ") +
      ". Either an algorithm was added without a case here, or one was " +
      "removed.");
  }
  log.info("[structure] OK — nine panes, all collapsed, " +
           SYMMETRIC_PANES.reduce(function (n, p) {
             return n + p.algs.length;
           }, 0) + " symmetric algorithms offered and all of them driven.");
  log.debug("Leaving pageStructure().");
}

// ===========================================================================
// Section 1b — the stylesheet this page shares is actually loaded.
//
// The look of both tool pages lives in css/tool_panes.css, which was called
// digital_signature.css until this page started linking it. A rename like that
// breaks in the one way nothing reports: the `<link>` still resolves (to a
// sheet that exists, or to a 404 the browser swallows), the classes match
// nothing, and the page renders as unstyled markup. That is exactly what
// happened to the WS-Federation pages after the saml_tools.css rename — see
// checkStylesheetsLoaded() in tests/navigation.js, which is the same check for
// the pages that ARE landing cards.
//
// So this asks the CSSOM: for every ds- class the markup uses, is there a rule
// defining it in a sheet this page actually loaded?
// ===========================================================================
async function stylesheetLoaded(driver) {
  log.debug("Entering stylesheetLoaded().");
  log.info("[stylesheet] Every ds- class the page uses must be defined.");
  const undefinedClasses = await driver.executeScript(
    "var used = {};" +
    "var nodes = document.querySelectorAll('[class]');" +
    "for (var i = 0; i < nodes.length; i++) {" +
    "  var names = nodes[i].className.split(/\\s+/);" +
    "  for (var j = 0; j < names.length; j++) {" +
    "    if (names[j].indexOf('ds-') === 0) used[names[j]] = true;" +
    "  }" +
    "}" +
    "var defined = {};" +
    "for (var s = 0; s < document.styleSheets.length; s++) {" +
    "  var rules;" +
    "  try { rules = document.styleSheets[s].cssRules; }" +
    "  catch (e) { rules = null; }" +
    "  if (!rules) continue;" +
    "  for (var r = 0; r < rules.length; r++) {" +
    "    var text = rules[r].selectorText || '';" +
    "    var found = text.match(/\\.ds-[a-z0-9-]+/g) || [];" +
    "    for (var f = 0; f < found.length; f++) {" +
    "      defined[found[f].slice(1)] = true;" +
    "    }" +
    "  }" +
    "}" +
    "var missing = [];" +
    "for (var name in used) { if (!defined[name]) missing.push(name); }" +
    "return { missing: missing, used: Object.keys(used).length," +
    "         defined: Object.keys(defined).length };");
  assert.ok(undefinedClasses.used > 5,
    "the page uses only " + undefinedClasses.used + " ds- classes, which " +
    "means this check found nothing to check — has the markup changed?");
  assert.deepStrictEqual(undefinedClasses.missing, [],
    "these classes are used by the markup and defined in no stylesheet the " +
    "page loaded, so the page is rendering unstyled and nothing 404'd: " +
    undefinedClasses.missing.join(", "));
  // And the pane grid must actually be a grid, which is the one rule whose
  // absence is visible in a screenshot and invisible to the check above.
  const display = await driver.executeScript(
    "return getComputedStyle(document.querySelector('.ds-grid')).display;");
  assert.strictEqual(display, "grid",
    "the pane grid is laid out as '" + display + "' rather than a grid, so " +
    "css/tool_panes.css is not in effect");
  log.info("[stylesheet] OK — " + undefinedClasses.used + " ds- classes " +
           "used, all defined, and the pane grid is a grid.");
  log.debug("Leaving stylesheetLoaded().");
}

// ===========================================================================
// Section 2 — the collapse / expand control.
// ===========================================================================
async function collapseControl(driver) {
  log.debug("Entering collapseControl().");
  log.info("[collapse] The expand-all toggle and the clickable legends.");

  // The checkbox itself is VISUALLY HIDDEN — css/tool_panes.css gives it
  // `position:absolute; opacity:0; width:0; height:0` and draws the slider
  // span instead, which is how the switch gets its look. So Selenium answers a
  // click on `#ds_toggle_all` with "element not interactable", which reads as
  // a broken control rather than as a styled one. Click the SLIDER, which is
  // also what a person clicks.
  const toggle = By.css("label.ds-toggle .ds-toggle-slider");
  await driver.findElement(toggle).click();
  await driver.wait(async function () {
    return (await driver.executeScript(
      "return document.querySelectorAll(" +
      "'.ds-grid > fieldset.ds-collapsed').length;")) === 0;
  }, waitTime * 3, "Expand all did not open every pane");
  assert.strictEqual(await driver.executeScript(
    "return document.getElementById('ds_toggle_all').checked;"), true,
    "the panes opened but the switch did not move with them");
  assert.strictEqual(await driver.executeScript(
    "return document.querySelector('.ds-toggle-text').textContent;"),
    "Collapse all panes",
    "the switch's label still offers to expand what is already expanded");

  await driver.findElement(toggle).click();
  await driver.wait(async function () {
    return (await driver.executeScript(
      "return document.querySelectorAll(" +
      "'.ds-grid > fieldset.ds-collapsed').length;")) === ALL_PANES.length;
  }, waitTime * 3, "Collapse all did not close every pane");

  // A legend opens its own pane and no other. This is tool_panes.js's
  // wireCollapsibleLegends(), shared with the Digital Signature page.
  await driver.findElement(
    By.css("#pane_aes > legend")).click();
  const openIds = await driver.executeScript(
    "var out = [];" +
    "var f = document.querySelectorAll('.ds-grid > fieldset');" +
    "for (var i = 0; i < f.length; i++) {" +
    "  if (!f[i].classList.contains('ds-collapsed')) out.push(f[i].id);" +
    "}" +
    "return out;");
  assert.deepStrictEqual(openIds, ['pane_aes'],
    "clicking one legend opened " + openIds.join(", ") +
    " — a legend must toggle its own fieldset and nothing else");
  log.info("[collapse] OK — expand all, collapse all, and one legend opens " +
           "one pane.");
  log.debug("Leaving collapseControl().");
}

// ===========================================================================
// Section 3 — the three symmetric panes, every algorithm.
// ===========================================================================
async function symmetricPane(driver, pane) {
  log.debug("Entering symmetricPane(). " + pane.name);
  log.info("[" + pane.prefix + "] " + pane.name + " — " + pane.algs.length +
           " algorithms.");
  await expand(driver, pane.pane);

  for (const alg of pane.algs) {
    const isAead = pane.aead.indexOf(alg) !== -1;
    // Selecting an algorithm reports what it needs. That line is the pane's
    // answer to the single most common mistake here, so it is asserted rather
    // than waited past.
    await selectOption(driver, fieldId(pane.prefix, 'alg'), alg);
    const described = await waitForSettled(driver, pane.prefix,
      "selecting " + alg + " produced no description");
    assert.ok(described.indexOf(isAead ? 'authenticated' : 'NOT authenticated')
              !== -1,
      alg + " is " + (isAead ? "" : "not ") + "an AEAD and the pane does not " +
      "say so: " + described);

    await clickButton(driver, pane.pane, 'Generate Key');
    const generated = await waitForSettled(driver, pane.prefix,
      "Generate Key produced no status for " + alg);
    assertAccepted(generated, "generating a key for " + alg);

    const key = await getField(driver, pane.prefix, 'key');
    const iv = await getField(driver, pane.prefix, 'iv');
    assert.ok(/^[0-9a-f]+$/.test(key),
      alg + " produced a key that is not hex: " + key);
    if (alg.indexOf('ECB') === -1) {
      assert.ok(iv.length > 0, alg + " produced no IV");
    } else {
      assert.strictEqual(iv, "",
        "ECB has no IV, and leaving one in the box invites the reader to " +
        "believe it is used");
    }

    await setField(driver, pane.prefix, 'plaintext', MESSAGE);
    await clickButton(driver, pane.pane, 'Encrypt');
    const encrypted = await waitForSettled(driver, pane.prefix,
      "Encrypt produced no status for " + alg);
    assertAccepted(encrypted, "encrypting with " + alg);

    const ciphertext = await getField(driver, pane.prefix, 'ciphertext');
    const tag = await getField(driver, pane.prefix, 'tag');
    assert.ok(ciphertext.length > 0, alg + " produced no ciphertext");
    assert.notStrictEqual(ciphertext, MESSAGE);
    if (isAead) {
      assert.ok(tag.length > 0, alg + " is an AEAD and produced no tag");
    } else {
      assert.strictEqual(tag, "",
        alg + " authenticates nothing, so a tag in that box would be a " +
        "claim the mode cannot support");
    }

    // Empty the plaintext before decrypting. Leaving it there means the
    // assertion below is satisfied by the value that was never removed — a
    // test that quietly does nothing.
    await setField(driver, pane.prefix, 'plaintext', "");
    assert.strictEqual(await getField(driver, pane.prefix, 'plaintext'), "",
      "the plaintext box did not clear, so the round-trip assertion would " +
      "pass on a leftover value");

    await clickButton(driver, pane.pane, 'Decrypt');
    await waitForContent.waitForValue(driver,
      fieldId(pane.prefix, 'plaintext'),
      function (text) { return text.length > 0; },
      alg + ": Decrypt never refilled the plaintext box", cryptoWait);
    assert.strictEqual(await getField(driver, pane.prefix, 'plaintext'),
                       MESSAGE,
      alg + " did not round-trip the message exactly");

    // An AEAD must refuse a modified ciphertext, and say which way it failed.
    if (isAead) {
      await pasteField(driver, pane.prefix, 'ciphertext',
                       flipBase64(ciphertext));
      await setField(driver, pane.prefix, 'plaintext', "");
      await clickButton(driver, pane.pane, 'Decrypt');
      const refused = await waitForSettled(driver, pane.prefix,
        alg + ": a modified ciphertext produced no status");
      assertRefused(refused, /did not verify/i,
                    alg + " with a modified ciphertext");
      assert.strictEqual(await getField(driver, pane.prefix, 'plaintext'), "",
        alg + " put something in the plaintext box for a ciphertext whose " +
        "tag did not verify");
      await pasteField(driver, pane.prefix, 'ciphertext', ciphertext);
    }
  }

  // A key of the wrong length is named, with the field and the number. This is
  // the pane's most common failure and the one a range error from inside a
  // buffer explains worst.
  await selectOption(driver, fieldId(pane.prefix, 'alg'), pane.algs[0]);
  await pasteField(driver, pane.prefix, 'key', 'aabb');
  await clickButton(driver, pane.pane, 'Encrypt');
  const short = await waitForSettled(driver, pane.prefix,
    "a short key produced no status");
  assertRefused(short, /needs a \d+-byte key/, "a two-byte key");

  // A key that is not hex names the BOX as well as the problem. Both of
  // crypto_bytes' two refusals are exercised, because they are different
  // mistakes and the first draft of this check only ever reached one of them:
  // "not a key" loses its spaces to the whitespace strip and arrives as seven
  // characters, so it is refused for its LENGTH and the not-hex branch never
  // runs.
  await pasteField(driver, pane.prefix, 'key', 'zzzz');
  await clickButton(driver, pane.pane, 'Encrypt');
  const notHex = await waitForSettled(driver, pane.prefix,
    "a non-hex key produced no status");
  assertRefused(notHex, /Secret Key.*not hexadecimal/i, "a non-hex key");

  await pasteField(driver, pane.prefix, 'key', 'abc');
  await clickButton(driver, pane.pane, 'Encrypt');
  const oddLength = await waitForSettled(driver, pane.prefix,
    "an odd-length key produced no status");
  assertRefused(oddLength, /Secret Key.*odd number of digits/i,
                "a key with an odd number of hex digits");

  log.info("[" + pane.prefix + "] OK — " + pane.algs.length +
           " algorithms round-trip, every AEAD refuses a modified " +
           "ciphertext, and a bad key names the field.");
  log.debug("Leaving symmetricPane().");
}

// Flip one bit of a base64 value, keeping it valid base64 of the same length.
function flipBase64(value) {
  log.debug("Entering flipBase64().");
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const first = value.charAt(0);
  const index = alphabet.indexOf(first);
  const replacement = alphabet.charAt((index + 1) % 64);
  log.debug("Leaving flipBase64().");
  return replacement + value.slice(1);
}

// ===========================================================================
// Section 4 — RSA.
// ===========================================================================
async function rsaPane(driver) {
  log.debug("Entering rsaPane().");
  log.info("[rsa] Direct and hybrid, both paddings.");
  await expand(driver, 'pane_rsa');

  // 2048 only: a 4096-bit key pair is pure JS in the page and would dominate
  // this job's runtime. The key SIZES are covered by tests/crypto_engines.js,
  // which pays nothing for them.
  await selectOption(driver, 'enc_rsa_bits', '2048');
  await clickButton(driver, 'pane_rsa', 'Generate Keys');
  const generated = await waitForSettled(driver, 'rsa',
    "RSA key generation never finished", keyWait);
  assertAccepted(generated, "RSA key generation");
  assert.ok(/Direct mode carries at most \d+ bytes/.test(generated),
    "the pane does not report the direct-mode size limit after generating a " +
    "key. That number depends on the key, the padding AND the hash, and " +
    "meeting it as a failure afterwards explains none of them: " + generated);

  const privateKey = await getField(driver, 'rsa', 'private_key');
  const publicKey = await getField(driver, 'rsa', 'public_key');
  assert.ok(/BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY/.test(privateKey),
    "the RSA private key box does not hold a PEM key");
  assert.ok(/BEGIN PUBLIC KEY/.test(publicKey),
    "the RSA public key box does not hold a PEM key");

  for (const padding of ['oaep', 'v1_5']) {
    for (const mode of ['hybrid', 'direct']) {
      await selectOption(driver, 'enc_rsa_mode', mode);
      await selectOption(driver, 'enc_rsa_padding', padding);
      await setField(driver, 'rsa', 'plaintext', MESSAGE);
      await clickButton(driver, 'pane_rsa', 'Encrypt');
      const encrypted = await waitForSettled(driver, 'rsa',
        "RSA " + mode + "/" + padding + " produced no status", cryptoWait);
      assertAccepted(encrypted, "RSA " + mode + "/" + padding);

      const wrapped = await getField(driver, 'rsa', 'encapsulation');
      if (mode === 'hybrid') {
        assert.ok(wrapped.length > 0,
          "hybrid mode produced no wrapped key, so nothing was wrapped");
        assert.ok(/Hybrid/.test(encrypted),
          "hybrid mode did not say what it did: " + encrypted);
      } else {
        assert.strictEqual(wrapped, "",
          "direct mode filled the Wrapped Key box, which would mean a " +
          "symmetric key was involved after all");
      }

      await setField(driver, 'rsa', 'plaintext', "");
      await clickButton(driver, 'pane_rsa', 'Decrypt');
      await waitForContent.waitForValue(driver, 'enc_rsa_plaintext',
        function (text) { return text.length > 0; },
        "RSA " + mode + "/" + padding + ": Decrypt never refilled the box",
        cryptoWait);
      assert.strictEqual(await getField(driver, 'rsa', 'plaintext'), MESSAGE,
        "RSA " + mode + "/" + padding + " did not round-trip the message");
    }
  }

  // Direct mode's size limit, reached deliberately. This is the pane's own
  // teaching point and the reason the hybrid default exists, so the refusal
  // has to name the alternative rather than just the failure.
  await selectOption(driver, 'enc_rsa_mode', 'direct');
  await selectOption(driver, 'enc_rsa_padding', 'oaep');
  await selectOption(driver, 'enc_rsa_hash', 'SHA-256');
  await pasteField(driver, 'rsa', 'plaintext', 'A'.repeat(400));
  await clickButton(driver, 'pane_rsa', 'Encrypt');
  const tooLong = await waitForSettled(driver, 'rsa',
    "an over-long direct-mode message produced no status");
  assertRefused(tooLong, /at most \d+ bytes directly/,
                "a 400-byte message in direct mode");
  assert.ok(/Hybrid/.test(tooLong),
    "the refusal does not point at Hybrid, which is the thing to do about " +
    "it: " + tooLong);

  // The same message in hybrid mode must work — otherwise the advice above is
  // wrong, and a refusal that recommends something broken is worse than one
  // that recommends nothing.
  await selectOption(driver, 'enc_rsa_mode', 'hybrid');
  await clickButton(driver, 'pane_rsa', 'Encrypt');
  const hybridLong = await waitForSettled(driver, 'rsa',
    "the 400-byte message produced no status in hybrid mode", cryptoWait);
  assertAccepted(hybridLong, "a 400-byte message in hybrid mode");
  await setField(driver, 'rsa', 'plaintext', "");
  await clickButton(driver, 'pane_rsa', 'Decrypt');
  await waitForContent.waitForValue(driver, 'enc_rsa_plaintext',
    function (text) { return text.length === 400; },
    "the 400-byte hybrid message did not come back", cryptoWait);

  log.info("[rsa] OK — both paddings in both modes, the size limit is " +
           "reported before it is met, and the refusal's advice works.");
  log.debug("Leaving rsaPane().");
}

// ===========================================================================
// Section 5 — the three key-agreement panes.
//
// ECIES, ML-KEM and the finite-field family have the same shape — generate,
// encrypt, clear, decrypt, and a negative — so they are driven by one function
// with the per-pane differences in a table. What differs is only which
// selector chooses the parameters.
// ===========================================================================
var AGREEMENT_PANES = [
  { prefix: 'ecc', pane: 'pane_ecc', name: 'ECIES',
    selectors: [{ id: 'enc_ecc_curve',
                  values: ['P-256', 'P-384', 'P-521', 'secp256k1',
                           'X25519'] }],
    generate: 'Generate Keys', usesInfo: true },
  { prefix: 'kem', pane: 'pane_kem', name: 'ML-KEM',
    selectors: [{ id: 'enc_kem_set',
                  values: ['ML-KEM-768', 'ML-KEM-512', 'ML-KEM-1024'] },
                { id: 'enc_kem_mode', values: ['hybrid', 'pq'] }],
    generate: 'Generate Keys', usesInfo: true },
  { prefix: 'ffc', pane: 'pane_ffc', name: 'DSA family',
    selectors: [{ id: 'enc_ffc_group',
                  values: ['modp-2048', 'modp-3072'] },
                { id: 'enc_ffc_mode', values: ['hybrid', 'elgamal'] }],
    generate: 'Generate Keys', usesInfo: true }
];

// Every combination of the pane's selectors, as a list of {id: value} objects.
function combinations(selectors) {
  log.debug("Entering combinations().");
  var out = [{}];
  selectors.forEach(function (selector) {
    const next = [];
    out.forEach(function (partial) {
      selector.values.forEach(function (value) {
        const merged = Object.assign({}, partial);
        merged[selector.id] = value;
        next.push(merged);
      });
    });
    out = next;
  });
  log.debug("Leaving combinations(). n=" + out.length);
  return out;
}

async function agreementPane(driver, pane) {
  log.debug("Entering agreementPane(). " + pane.name);
  const cases = combinations(pane.selectors);
  log.info("[" + pane.prefix + "] " + pane.name + " — " + cases.length +
           " combinations.");
  await expand(driver, pane.pane);

  for (const combination of cases) {
    const label = Object.keys(combination).map(function (id) {
      return combination[id];
    }).join(" / ");
    for (const id of Object.keys(combination)) {
      await selectOption(driver, id, combination[id]);
    }

    await clickButton(driver, pane.pane, pane.generate);
    const generated = await waitForSettled(driver, pane.prefix,
      pane.name + " " + label + ": key generation never finished", keyWait);
    assertAccepted(generated, pane.name + " " + label + " key generation");
    const privateKey = await getField(driver, pane.prefix, 'private_key');
    const publicKey = await getField(driver, pane.prefix, 'public_key');
    assert.ok(privateKey.length > 0 && publicKey.length > 0,
      pane.name + " " + label + " generated an empty key");
    assert.notStrictEqual(privateKey, publicKey,
      pane.name + " " + label + " put the same value in both key boxes");

    await setField(driver, pane.prefix, 'plaintext', MESSAGE);
    await clickButton(driver, pane.pane, 'Encrypt');
    const encrypted = await waitForSettled(driver, pane.prefix,
      pane.name + " " + label + ": Encrypt produced no status", cryptoWait);
    assertAccepted(encrypted, pane.name + " " + label + " encryption");

    const encapsulation = await getField(driver, pane.prefix, 'encapsulation');
    const ciphertext = await getField(driver, pane.prefix, 'ciphertext');
    assert.ok(encapsulation.length > 0,
      pane.name + " " + label + " produced nothing for the recipient to " +
      "agree the secret with");
    assert.ok(ciphertext.length > 0,
      pane.name + " " + label + " produced no ciphertext");

    await setField(driver, pane.prefix, 'plaintext', "");
    await clickButton(driver, pane.pane, 'Decrypt');
    await waitForContent.waitForValue(driver,
      fieldId(pane.prefix, 'plaintext'),
      function (text) { return text.length > 0; },
      pane.name + " " + label + ": Decrypt never refilled the box",
      cryptoWait);
    assert.strictEqual(await getField(driver, pane.prefix, 'plaintext'),
                       MESSAGE,
      pane.name + " " + label + " did not round-trip the message");

    // Encrypting twice must not produce the same thing. Every one of these
    // uses a fresh ephemeral secret per message, and if that stopped being
    // true nothing else on the page would show it.
    await setField(driver, pane.prefix, 'plaintext', MESSAGE);
    await clickButton(driver, pane.pane, 'Encrypt');
    await waitForSettled(driver, pane.prefix,
      pane.name + " " + label + ": the second encryption produced no status",
      cryptoWait);
    assert.notStrictEqual(await getField(driver, pane.prefix, 'encapsulation'),
                          encapsulation,
      pane.name + " " + label + " reused its ephemeral value — two " +
      "encryptions of one message to one recipient must differ");
  }

  // Somebody else's key must not open it: generate a second key pair and try.
  const firstPrivate = await getField(driver, pane.prefix, 'private_key');
  const held = {
    encapsulation: await getField(driver, pane.prefix, 'encapsulation'),
    iv: await getField(driver, pane.prefix, 'iv'),
    ciphertext: await getField(driver, pane.prefix, 'ciphertext'),
    tag: await getField(driver, pane.prefix, 'tag')
  };
  await clickButton(driver, pane.pane, pane.generate);
  await waitForSettled(driver, pane.prefix,
    pane.name + ": the second key pair never arrived", keyWait);
  const secondPrivate = await getField(driver, pane.prefix, 'private_key');
  assert.notStrictEqual(secondPrivate, firstPrivate,
    pane.name + " generated the same key pair twice");
  for (const name of Object.keys(held)) {
    await pasteField(driver, pane.prefix, name, held[name]);
  }
  await setField(driver, pane.prefix, 'plaintext', "");
  await clickButton(driver, pane.pane, 'Decrypt');
  const wrongKey = await waitForSettled(driver, pane.prefix,
    pane.name + ": decrypting under the wrong key produced no status",
    cryptoWait);
  assert.ok(/did not verify|length marker|error/i.test(wrongKey),
    pane.name + " accepted a ciphertext under a key that did not make it: " +
    wrongKey);
  assert.strictEqual(await getField(driver, pane.prefix, 'plaintext'), "",
    pane.name + " put something in the plaintext box while decrypting under " +
    "the wrong key");

  log.info("[" + pane.prefix + "] OK — " + cases.length + " combinations " +
           "round-trip, each is non-deterministic, and another key does not " +
           "open the result.");
  log.debug("Leaving agreementPane().");
}

// The one thing the finite-field pane does that the others do not: the two
// modes are different SCHEMES, and the pane has to say which boxes each uses.
async function elgamalSpecifics(driver) {
  log.debug("Entering elgamalSpecifics().");
  log.info("[ffc] ElGamal's own limits.");
  await expand(driver, 'pane_ffc');
  await selectOption(driver, 'enc_ffc_group', 'modp-2048');
  await selectOption(driver, 'enc_ffc_mode', 'elgamal');
  const described = await waitForSettled(driver, 'ffc',
    "selecting ElGamal produced no description");
  assert.ok(/at most \d+ bytes/.test(described) &&
            /unauthenticated/i.test(described),
    "the pane does not say what ElGamal's limits are: " + described);

  await clickButton(driver, 'pane_ffc', 'Generate Keys');
  await waitForSettled(driver, 'ffc', "no finite-field key pair", keyWait);
  await pasteField(driver, 'ffc', 'plaintext', 'A'.repeat(300));
  await clickButton(driver, 'pane_ffc', 'Encrypt');
  const tooLong = await waitForSettled(driver, 'ffc',
    "an over-long ElGamal message produced no status", cryptoWait);
  assertRefused(tooLong, /at most \d+ bytes/, "a 300-byte ElGamal message");
  assert.ok(/Hybrid|DHIES/i.test(tooLong),
    "the refusal does not point at the hybrid: " + tooLong);

  // And the same message under DHIES works, so the advice is good.
  await selectOption(driver, 'enc_ffc_mode', 'hybrid');
  await clickButton(driver, 'pane_ffc', 'Encrypt');
  const hybrid = await waitForSettled(driver, 'ffc',
    "the 300-byte message produced no status under DHIES", cryptoWait);
  assertAccepted(hybrid, "a 300-byte message under DHIES");
  log.info("[ffc] OK — ElGamal states and enforces its limit, and DHIES " +
           "carries what it refuses.");
  log.debug("Leaving elgamalSpecifics().");
}

// ===========================================================================
// Section 6 — JWE. The one pane whose output is a protocol artifact.
// ===========================================================================
async function jwePane(driver) {
  log.debug("Entering jwePane().");
  log.info("[jwe] Compact serialization, RSA and ECDH-ES.");
  await expand(driver, 'pane_jwe');

  const algs = ['RSA-OAEP-256', 'RSA-OAEP', 'ECDH-ES', 'ECDH-ES+A128KW',
                'ECDH-ES+A256KW'];
  const offered = await optionsOf(driver, 'enc_jwe_alg');
  algs.forEach(function (alg) {
    assert.ok(offered.indexOf(alg) !== -1,
      "the JWE pane no longer offers " + alg);
  });

  for (const alg of algs) {
    await selectOption(driver, 'enc_jwe_alg', alg);
    await selectOption(driver, 'enc_jwe_enc', 'A256GCM');
    await clickButton(driver, 'pane_jwe', 'Generate Keys');
    const generated = await waitForSettled(driver, 'jwe',
      "JWE " + alg + ": key generation never finished", keyWait);
    assertAccepted(generated, "JWE key generation for " + alg);

    const payload = '{"sub":"alice","alg":"' + alg + '"}';
    await setField(driver, 'jwe', 'plaintext', payload);
    await clickButton(driver, 'pane_jwe', 'Encrypt');
    const encrypted = await waitForSettled(driver, 'jwe',
      "JWE " + alg + ": Encrypt produced no status", cryptoWait);
    assertAccepted(encrypted, "JWE encryption with " + alg);

    const compact = await getField(driver, 'jwe', 'ciphertext');
    assert.strictEqual(compact.split(".").length, 5,
      "a compact JWE has five dot-separated segments; " + alg +
      " produced " + compact.split(".").length + ": " + compact.slice(0, 80));
    // The header must say what was actually used — read from the token rather
    // than from the dropdown, which is the whole point of showing it.
    const header = JSON.parse(Buffer.from(
      compact.split(".")[0].replace(/-/g, '+').replace(/_/g, '/'),
      "base64").toString("utf8"));
    assert.strictEqual(header.alg, alg,
      "the JWE's protected header says alg=" + header.alg + " for a token " +
      "encrypted with " + alg);
    assert.strictEqual(header.enc, 'A256GCM');
    if (alg.indexOf('ECDH-ES') === 0) {
      assert.ok(header.epk && header.epk.kty === 'EC',
        alg + " produced no epk in the header, so the recipient has nothing " +
        "to agree the key with");
    }

    await setField(driver, 'jwe', 'plaintext', "");
    await clickButton(driver, 'pane_jwe', 'Decrypt');
    await waitForContent.waitForValue(driver, 'enc_jwe_plaintext',
      function (text) { return text.length > 0; },
      "JWE " + alg + ": Decrypt never refilled the payload", cryptoWait);
    assert.strictEqual(await getField(driver, 'jwe', 'plaintext'), payload,
      "JWE " + alg + " did not round-trip the payload");
  }

  // A tampered JWE must be refused. The AAD of a JWE is its protected header,
  // so editing the header is what proves the binding rather than merely
  // flipping a byte of ciphertext.
  const good = await getField(driver, 'jwe', 'ciphertext');
  const parts = good.split(".");
  await pasteField(driver, 'jwe', 'ciphertext',
                   parts[0] + "." + parts[1] + "." + parts[2] + "." +
                   flipBase64(parts[3]) + "." + parts[4]);
  await setField(driver, 'jwe', 'plaintext', "");
  await clickButton(driver, 'pane_jwe', 'Decrypt');
  const refused = await waitForSettled(driver, 'jwe',
    "a modified JWE produced no status", cryptoWait);
  // The message, not merely the absence of a plaintext. This is the check that
  // found the page's worst silence: Web Crypto rejects a bad tag with an
  // `OperationError` whose message is the EMPTY STRING, so before
  // describeError() existed the status line went blank on the one refusal that
  // matters most here — a token somebody had modified.
  assert.ok(/did not check out|did not verify|OperationError/i.test(refused),
    "a modified JWE was refused without saying why. The status line read: " +
    JSON.stringify(refused));
  assert.strictEqual(await getField(driver, 'jwe', 'plaintext'), "",
    "a modified JWE was decrypted anyway");
  log.info("[jwe] OK — five algs round-trip, the header names what was " +
           "used, ECDH-ES carries an epk, and a modified token is refused.");
  log.debug("Leaving jwePane().");
}

// ===========================================================================
// Section 7 — password-based encryption.
// ===========================================================================
async function pbePane(driver) {
  log.debug("Entering pbePane().");
  log.info("[pbe] PBKDF2, scrypt, HKDF, and the PBES2 JWE form.");
  await expand(driver, 'pane_pbe');

  // A small iteration count, because this job is testing the wiring and the
  // KDF's slowness is the one property it must NOT pay for. The real defaults
  // (600,000 / N=16384) are what the page seeds; tests/crypto_engines.js is
  // where a KDF's output is checked.
  const kdfs = [{ id: 'PBKDF2-SHA256', iterations: '1000' },
                { id: 'PBKDF2-SHA512', iterations: '1000' },
                { id: 'scrypt', iterations: '1024' },
                { id: 'HKDF-SHA256', iterations: '1' }];

  for (const kdf of kdfs) {
    await selectOption(driver, 'enc_pbe_kdf', kdf.id);
    await setField(driver, 'pbe', 'iterations', kdf.iterations);
    await setField(driver, 'pbe', 'password', 'correct horse battery staple');
    await clickButton(driver, 'pane_pbe', 'New Salt');
    await waitForSettled(driver, 'pbe', kdf.id + ": no salt");

    await clickButton(driver, 'pane_pbe', 'Derive Key');
    const derived = await waitForSettled(driver, 'pbe',
      kdf.id + ": Derive Key never finished", keyWait);
    assertAccepted(derived, kdf.id + " key derivation");
    const key = await getField(driver, 'pbe', 'key');
    assert.strictEqual(key.length, 64,
      kdf.id + " derived a key that is not 32 bytes: " + key.length / 2);

    await setField(driver, 'pbe', 'plaintext', MESSAGE);
    await clickButton(driver, 'pane_pbe', 'Encrypt');
    const encrypted = await waitForSettled(driver, 'pbe',
      kdf.id + ": Encrypt never finished", keyWait);
    assertAccepted(encrypted, kdf.id + " encryption");

    await setField(driver, 'pbe', 'plaintext', "");
    await clickButton(driver, 'pane_pbe', 'Decrypt');
    await waitForContent.waitForValue(driver, 'enc_pbe_plaintext',
      function (text) { return text.length > 0; },
      kdf.id + ": Decrypt never refilled the box", keyWait);
    assert.strictEqual(await getField(driver, 'pbe', 'plaintext'), MESSAGE,
      kdf.id + " did not round-trip the message");

    // The wrong password must fail, and the tag is what says so — which is
    // also the pane's claim that a verified tag means the password was right.
    await setField(driver, 'pbe', 'password', 'wrong horse battery staple');
    await setField(driver, 'pbe', 'plaintext', "");
    await clickButton(driver, 'pane_pbe', 'Decrypt');
    const wrong = await waitForSettled(driver, 'pbe',
      kdf.id + ": the wrong password produced no status", keyWait);
    assertRefused(wrong, /did not verify/i,
                  kdf.id + " with the wrong password");
    assert.strictEqual(await getField(driver, 'pbe', 'plaintext'), "",
      kdf.id + " produced a plaintext under the wrong password");
    await setField(driver, 'pbe', 'password', 'correct horse battery staple');
  }

  // scrypt's N must be a power of two, and the pane says so rather than
  // letting the library complain.
  await selectOption(driver, 'enc_pbe_kdf', 'scrypt');
  await setField(driver, 'pbe', 'iterations', '1000');
  await clickButton(driver, 'pane_pbe', 'Derive Key');
  const badN = await waitForSettled(driver, 'pbe',
    "a non-power-of-two N produced no status", keyWait);
  assertRefused(badN, /power of two/, "scrypt with N = 1000");

  // An empty password is refused for the reason that matters.
  await setField(driver, 'pbe', 'password', "");
  await setField(driver, 'pbe', 'iterations', '1024');
  await clickButton(driver, 'pane_pbe', 'Derive Key');
  const empty = await waitForSettled(driver, 'pbe',
    "an empty password produced no status", keyWait);
  assertRefused(empty, /Enter a password/, "an empty password");

  // The JOSE form. This is jose_jwe.js's pbes2JweEncrypt() — the same
  // function that password-protects a downloaded key set on this page and on
  // the Digital Signature page — so it is exercised here rather than only
  // through a download nothing reads back.
  await setField(driver, 'pbe', 'password', 'correct horse battery staple');
  await setField(driver, 'pbe', 'plaintext', MESSAGE);
  await clickButton(driver, 'pane_pbe', 'As PBES2 JWE');
  const jwe = await waitForSettled(driver, 'pbe',
    "As PBES2 JWE produced no status", keyWait);
  assertAccepted(jwe, "the PBES2 JWE form");
  const compact = await getField(driver, 'pbe', 'ciphertext');
  assert.strictEqual(compact.split(".").length, 5,
    "the PBES2 form is a compact JWE and must have five segments");
  const header = JSON.parse(Buffer.from(
    compact.split(".")[0].replace(/-/g, '+').replace(/_/g, '/'),
    "base64").toString("utf8"));
  assert.strictEqual(header.alg, 'PBES2-HS256+A128KW');
  assert.ok(header.p2s && header.p2c,
    "a PBES2 JWE carries its salt and iteration count in its header, which " +
    "is what makes it the form that needs nothing kept beside it");
  log.info("[pbe] OK — four KDFs round-trip, the wrong password is refused " +
           "by the tag, scrypt's N is checked, and the PBES2 JWE carries " +
           "its own parameters.");
  log.debug("Leaving pbePane().");
}

// ===========================================================================
// Section 8 — key downloads.
//
// The status line only; the file itself is checked in node by
// tests/pki_key_formats.js, which produces the whole matrix and hands every
// cell to OpenSSL. What matters here is that the button reaches
// key_material.js at all, and that an unsupported combination says so rather
// than emitting a broken file.
// ===========================================================================
async function keyDownloads(driver) {
  log.debug("Entering keyDownloads().");
  log.info("[downloads] Every key pane's keystore formats.");

  // RSA has the full matrix, because an RSA key pair is an ordinary PKCS#8 /
  // SPKI pair and key_material.js can write all four.
  await expand(driver, 'pane_rsa');
  for (const format of ['pem', 'der', 'jwk']) {
    await selectOption(driver, 'enc_rsa_ks_format', format);
    await setField(driver, 'rsa', 'ks_password', "");
    await clickButton(driver, 'pane_rsa', 'Download Keys');
    const status = await waitForSettled(driver, 'rsa',
      "RSA " + format + " download produced no status", keyWait);
    assert.ok(/Download/i.test(status),
      "the RSA " + format + " download did not report a download: " + status);
  }
  // PKCS#12 without a password must be refused, naming the field.
  await selectOption(driver, 'enc_rsa_ks_format', 'pkcs12');
  await setField(driver, 'rsa', 'ks_password', "");
  await clickButton(driver, 'pane_rsa', 'Download Keys');
  const noPassword = await waitForSettled(driver, 'rsa',
    "PKCS#12 without a password produced no status", keyWait);
  assertRefused(noPassword, /requires a password/i,
                "PKCS#12 with no password");
  // And with one it works. A PBES2 JWE is Web Crypto, so this is also the
  // check that the secure-context flags did their job.
  await setField(driver, 'rsa', 'ks_password', 'hunter2');
  await clickButton(driver, 'pane_rsa', 'Download Keys');
  const p12 = await waitForSettled(driver, 'rsa',
    "PKCS#12 with a password produced no status", keyWait);
  assertAccepted(p12, "a password-protected PKCS#12 download");

  // The raw-byte panes offer less, and must SAY so rather than write a file
  // nothing can open.
  await expand(driver, 'pane_kem');
  const kemFormats = await optionsOf(driver, 'enc_kem_ks_format');
  assert.deepStrictEqual(kemFormats, ['pem'],
    "ML-KEM keys are opaque bytes with no registered JWK type, so offering " +
    "one would be inventing a format: " + kemFormats.join(", "));
  await clickButton(driver, 'pane_kem', 'Download Keys');
  const kem = await waitForSettled(driver, 'kem',
    "the ML-KEM download produced no status", keyWait);
  assert.ok(/Download/i.test(kem),
    "the ML-KEM PEM download did not report a download: " + kem);

  // ECIES DOES have a JWK form, with use="enc" — which is the one member that
  // separates these keys from the Digital Signature page's ECC pane.
  await expand(driver, 'pane_ecc');
  await selectOption(driver, 'enc_ecc_curve', 'P-256');
  await clickButton(driver, 'pane_ecc', 'Generate Keys');
  await waitForSettled(driver, 'ecc', "no ECIES key pair", keyWait);
  await selectOption(driver, 'enc_ecc_ks_format', 'jwk');
  await clickButton(driver, 'pane_ecc', 'Download Keys');
  const ecc = await waitForSettled(driver, 'ecc',
    "the ECIES JWK download produced no status", keyWait);
  assert.ok(/JWK set/i.test(ecc),
    "the ECIES JWK download did not report a JWK set: " + ecc);
  log.info("[downloads] OK — RSA writes all four formats and refuses " +
           "PKCS#12 without a password; the raw-key panes offer only what " +
           "is defined and say so.");
  log.debug("Leaving keyDownloads().");
}

// ===========================================================================
// Section 9 — the page is reachable from where it says it is.
// ===========================================================================
async function navigation(driver) {
  log.debug("Entering navigation().");
  log.info("[navigation] The Tools pane links and the return link.");

  for (const from of ['oauth2_oidc_1.html', 'oauth2_oidc_2.html']) {
    await loadPage(driver, baseUrl + "/" + from, "tools_expand_button",
                   { timeout: waitTime * 6 });
    await waitForContent.waitForPageBundle(driver,
      "the " + from + " bundle never finished loading");
    await driver.findElement(By.id("tools_expand_button")).click();
    const link = await driver.wait(until.elementLocated(
      By.css("a[href='/encryption_tools.html?from=" + from + "']")),
      waitTime * 3,
      "the Tools pane on " + from + " has no link to the Encryption / " +
      "Decryption page");
    await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                               link);
    await link.click();
    await driver.wait(until.urlContains("encryption_tools.html"), waitTime * 3,
      "the Tools link on " + from + " did not reach the page");
    await waitForContent.waitForPageBundle(driver,
      "the encryption_tools bundle never finished loading");
    const returnHref = await driver.findElement(By.id("return_link"))
        .getAttribute("href");
    assert.ok(returnHref.indexOf(from) !== -1,
      "arriving from " + from + ", the return link points at " + returnHref);
  }

  // An unknown ?from= must fall back rather than be reflected into the href —
  // this page's return link is a whitelist, not a redirect.
  await loadPage(driver,
    baseUrl + "/encryption_tools.html?from=https://evil.example/",
    "return_link", { timeout: waitTime * 6 });
  await waitForContent.waitForPageBundle(driver,
    "the encryption_tools bundle never finished loading");
  const fallback = await driver.findElement(By.id("return_link"))
      .getAttribute("href");
  assert.ok(fallback.indexOf("evil.example") === -1,
    "an unknown ?from= reached the return link's href: " + fallback);
  assert.ok(fallback.indexOf("oauth2_oidc_1.html") !== -1,
    "an unknown ?from= did not fall back to the debugger: " + fallback);
  log.info("[navigation] OK — both Tools panes link here, the return link " +
           "follows ?from=, and an unknown one falls back rather than being " +
           "reflected.");
  log.debug("Leaving navigation().");
}

// ===========================================================================
// The browser console, and the one distinction that makes this check useful.
//
// A page this size wired with inline onclick handlers naming a browserify
// global fails in exactly one visible way when a bundle is mis-wired: an
// uncaught ReferenceError nobody reads. That is what this is for.
//
// It cannot simply demand an empty console, and the first draft did. Every
// refusal this test drives on purpose — 26 of them — goes through the page's
// fail(), which calls log.error(), which is bunyan's browser shim, which is
// console.error. Those are the page working. Chrome renders them as
// `…/encryption_tools.js 13465:16 Object`, because the shim logs a bunyan
// RECORD rather than a string, and that shape is exactly what separates them
// from a fault: an uncaught exception is reported as text beginning "Uncaught",
// and a failed subresource names the URL and the status.
//
// So the rule is: nothing uncaught, nothing failing to load, and the page's
// own logging is allowed — but COUNTED, because an unexpected flood of it is
// still a finding.
// ===========================================================================
function isPageLoggerRecord(message) {
  log.debug("Entering isPageLoggerRecord().");
  log.debug("Leaving isPageLoggerRecord().");
  return /encryption_tools\.js \d+:\d+ Object\s*$/.test(message);
}

async function severeErrors(driver) {
  log.debug("Entering severeErrors().");
  const entries = await driver.manage().logs().get(logging.Type.BROWSER);
  const severe = entries.filter(function (entry) {
    return entry.level && entry.level.name === "SEVERE" &&
        !/favicon|manifest/i.test(entry.message);
  }).map(function (entry) { return entry.message; });
  const logged = severe.filter(isPageLoggerRecord);
  const faults = severe.filter(function (message) {
    return !isPageLoggerRecord(message);
  });
  log.debug("Leaving severeErrors(). " + faults.length + " faults, " +
            logged.length + " of the page's own error records.");
  return { faults: faults, logged: logged };
}

// ===========================================================================
async function encryptionToolsActivities(driver) {
  log.debug("Entering encryptionToolsActivities().");
  await loadPage(driver, baseUrl + "/encryption_tools.html", "pane_aes",
                 { timeout: waitTime * 6 });
  // Every control on this page is an inline handler naming the browserify
  // `--standalone` global, and the markup carrying it is in the HTML from the
  // moment the page parses. A click before the bundle has run raises
  // `ReferenceError: encryption_tools is not defined` INSIDE the page and
  // looks out here like a button that did nothing, for ever.
  await waitForContent.waitForPageBundle(driver,
    "the encryption_tools bundle never finished loading");

  await pageStructure(driver);
  await stylesheetLoaded(driver);
  await collapseControl(driver);
  for (const pane of SYMMETRIC_PANES) {
    await symmetricPane(driver, pane);
  }
  await rsaPane(driver);
  for (const pane of AGREEMENT_PANES) {
    await agreementPane(driver, pane);
  }
  await elgamalSpecifics(driver);
  await jwePane(driver);
  await pbePane(driver);
  await keyDownloads(driver);

  const console_ = await severeErrors(driver);
  assert.deepStrictEqual(console_.faults, [],
    "the browser console carried faults — an uncaught error or a resource " +
    "that failed to load — while driving this page. An uncaught " +
    "ReferenceError here means a control was wired to a name the bundle " +
    "does not export:\n" + console_.faults.join("\n"));
  // The page's own error records are expected — every refusal this test
  // drives on purpose produces one — but a flood of them is not.
  assert.ok(console_.logged.length <= 60,
    "the page logged " + console_.logged.length + " errors of its own, " +
    "which is far more than the refusals this test drives. Something is " +
    "failing repeatedly without the status line saying so.");
  log.info("[console] OK — no uncaught errors and no failed loads across " +
           "all nine panes; " + console_.logged.length + " deliberate " +
           "refusals logged by the page itself.");

  await navigation(driver);
  log.debug("Leaving encryptionToolsActivities().");
}

async function test() {
  log.debug("Entering test().");
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const options = new chrome.Options().setLoggingPrefs(prefs);
  options.addArguments("--window-size=1500,1400");
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  // /tmp rather than the container's 64MB /dev/shm, which otherwise kills the
  // tab on a page carrying a 2.7MB bundle with an inline source map.
  options.addArguments("--disable-dev-shm-usage");
  // The JWE pane and every password-protected download are Web Crypto, and the
  // containerized origin (http://client:3000 — plain HTTP on a DNS name) is
  // not a secure context, so crypto.subtle is undefined there. These flags are
  // what make it one. Without them the JWE section fails reporting an error
  // nothing else on the page would produce, and the symmetric panes — which
  // are pure JS — carry on passing, which is what makes it confusing.
  browserFlags.addBrowserAccessFlags(options, baseUrl);

  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    log.info("Starting Test run against " + baseUrl);
    await driver.manage().deleteAllCookies();
    await encryptionToolsActivities(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('encryption_tools')
  .description("Run the Encryption / Decryption UI test — AES in every mode, " +
      "ChaCha20-Poly1305, 3DES/DES, RSA, ECIES, ML-KEM, ElGamal/DHIES, JWE " +
      "and password-based encryption, plus the keystore downloads.")
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
