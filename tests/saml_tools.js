// File: saml_tools.js
//
// SAML Assertion Tool UI test. A fully client-side page needing no IdP:
//
//   Pane 1 (Compose)  — the version-specific assertion structure (SAML 2.0 vs
//                       1.1 vs 1.0), the auto-populated ID and instants, the
//                       default Issuer (this debugger's URL), the optional
//                       element toggles, custom attributes (value type + URI
//                       prefix + name + value), and the compliance report.
//   Pane 2 (Sign)     — RSA key generation, the enveloped XML Signature, its
//                       version-specific placement and Reference URI, in-page
//                       verification, and a tamper negative control.
//   Pane 3 (Encrypt)  — recipient key generation, XML Encryption of the signed
//                       assertion, the <saml:EncryptedAssertion> wrapper, and
//                       the decrypt round-trip.
//
// Pane 1 is exercised EXHAUSTIVELY, for each of the three assertion versions:
// every option of every <select>, every text field, every attribute value type,
// and the complete power set of the optional-element checkboxes (2^9 states per
// version). Each state is checked three ways — the Generated Assertion box is
// well-formed XML, every element is present exactly when the settings say it
// should be, and the compliance report shows failures only for the states that
// genuinely are not compliant (an assertion with no statements and no Subject).
//
// The signing and encryption round-trips run ONCE, with freshly generated key
// pairs in both pane 2 and pane 3: the crypto itself is covered far more
// thoroughly, and against independent libraries, by xmlsec_interop.js — which
// also verifies the per-version signature placement and Reference URI for all
// three versions. This test covers the page wiring.
//
// It also checks the Tools pane added to the SAML Test Tools page links here,
// and that the whole run produces no browser console errors.

const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const logging = require("selenium-webdriver/lib/logging");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'saml_tools',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
// Signing / encryption are fast, but can exceed the default element wait on a
// busy CI host. node-forge RSA key generation is pure JS and much slower.
var cryptoWait = Math.max(waitTime, 20000);
var rsaWait = Math.max(waitTime, 90000);

var ATTR_PREFIX = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/";
var ATTR_NAME = "emailaddress";
var ATTR_VALUE = "testuser@example.com";

// ===========================================================================
// UI helpers
// ===========================================================================
async function click(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", el);
  await el.click();
}
async function setInput(driver, id, text) {
  var el = driver.findElement(By.id(id));
  await el.clear();
  await el.sendKeys(text);
}
async function getValue(driver, id) {
  return await driver.findElement(By.id(id)).getAttribute("value");
}
async function waitForValue(driver, id, pred, msg, timeout) {
  await driver.wait(async function () {
    try {
      return pred((await driver.findElement(By.id(id)).getAttribute("value")) || "");
    } catch (e) {
      // The element is not there yet — keep waiting.
      return false;
    }
  }, timeout || cryptoWait, msg);
  return await getValue(driver, id);
}
async function selectValue(driver, id, value) {
  await new Select(driver.findElement(By.id(id))).selectByValue(value);
}
// The inline handlers read "return saml_tools.<fn>(...)". Matching on the
// call prefix (name + open paren) is quote-agnostic, so it survives the HTML
// minification the hosted build applies to inline attributes.
function onclickBtn(fn) {
  return By.xpath("//input[contains(@onclick, \"saml_tools." + fn + "(\")]");
}
function isHidden(driver, id) {
  return driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return !e || e.classList.contains('saml-hidden');", id);
}
// Whether a single <option> is hidden because the selected version does not
// define it.
function isOptionHidden(driver, selectId, value) {
  return driver.executeScript(
    "var s = document.getElementById(arguments[0]);" +
    "for (var i = 0; i < s.options.length; i++) {" +
    "  if (s.options[i].value === arguments[1]) return !!s.options[i].hidden;" +
    "}" +
    "return null;", selectId, value);
}

// ===========================================================================
// Pane 1 — Compose
// ===========================================================================
async function testDefaults(driver) {
  log.info("=== Pane #1 Compose — defaults ===");
  var xml = await waitForValue(driver, 'sa_assertion',
    function (v) { return v.indexOf('saml:Assertion') !== -1; },
    "the assertion was not built on load.");

  var issuer = await getValue(driver, 'sa_issuer');
  assert.strictEqual(issuer, baseUrl.replace(/\/+$/, '') + '/issuer',
    "The Issuer should default to this debugger's URL with an /issuer path.");
  assert.ok(xml.indexOf('<saml:Issuer>' + issuer + '</saml:Issuer>') !== -1,
    "The default Issuer (the debugger URL) is not in the assertion. Issuer=" + issuer);
  assert.ok(xml.indexOf('Version="2.0"') !== -1, "The page does not default to SAML 2.0.");

  // Every instant is auto-populated with a UTC xs:dateTime.
  assert.ok(/IssueInstant="\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"/.test(xml),
    "IssueInstant was not auto-populated: " + xml.slice(0, 300));
  assert.ok(/NotBefore="[^"]+" NotOnOrAfter="[^"]+"/.test(xml),
    "The Conditions validity window was not auto-populated.");
  assert.ok(/AuthnInstant="\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"/.test(xml),
    "AuthnInstant was not auto-populated.");
  assert.ok((await getValue(driver, 'sa_id')).indexOf('_') === 0,
    "The assertion ID is not an NCName (it must start with '_').");

  assert.ok(xml.indexOf('<saml:NameID') !== -1, "No <saml:NameID> in the assertion.");
  assert.ok(xml.indexOf('<saml:AuthnStatement') !== -1, "No <saml:AuthnStatement> in the assertion.");
  assert.ok(xml.indexOf('AttributeStatement') === -1,
    "An <AttributeStatement> was emitted before any attribute was added.");
  log.info("[defaults] OK — SAML 2.0 assertion, Issuer=" + issuer + ", instants populated.");
}

async function testOptionalElements(driver) {
  log.info("=== Pane #1 Compose — optional elements ===");
  // Each toggle must add and remove its element. Checkbox id -> marker in the XML.
  var toggles = [
    ['sa_opt_authz', 'AuthzDecisionStatement'],
    ['sa_opt_proxy', 'ProxyRestriction'],
    ['sa_opt_onetimeuse', 'OneTimeUse'],
    ['sa_opt_advice', 'Advice'],
    ['sa_opt_locality', 'SubjectLocality'],
  ];
  for (var i = 0; i < toggles.length; i++) {
    var id = toggles[i][0], marker = toggles[i][1];
    await click(driver, By.id(id));
    await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf(marker) !== -1; },
      "<" + marker + "> did not appear after enabling " + id + ".");
    await click(driver, By.id(id));
    await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf(marker) === -1; },
      "<" + marker + "> did not disappear after disabling " + id + ".");
    log.info("[optional] OK — " + marker + " toggles on and off.");
  }

  // Turning the Conditions off drops the whole block (and its children with it).
  await click(driver, By.id('sa_opt_conditions'));
  await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('<saml:Conditions') === -1; },
    "<Conditions> did not disappear when disabled.");
  await click(driver, By.id('sa_opt_conditions'));
  await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('<saml:Conditions') !== -1; },
    "<Conditions> did not come back when re-enabled.");
  log.info("[optional] OK — Conditions toggles on and off.");
}

async function testCustomAttribute(driver) {
  log.info("=== Pane #1 Compose — custom attributes ===");
  // The section is gated by a checkbox that is unchecked by default.
  assert.ok(await isHidden(driver, 'sa_attr_group'),
    "The Add Custom SAML Attribute fields should be hidden until the checkbox is ticked.");
  await click(driver, By.id('sa_opt_attrs'));
  assert.ok(!(await isHidden(driver, 'sa_attr_group')),
    "Ticking the attribute checkbox should reveal the Add Custom SAML Attribute fields.");

  await selectValue(driver, 'sa_attr_type', 'string');
  await setInput(driver, 'sa_attr_prefix', ATTR_PREFIX);
  await setInput(driver, 'sa_attr_name', ATTR_NAME);
  await setInput(driver, 'sa_attr_value', ATTR_VALUE);
  await click(driver, onclickBtn('addAttribute'));

  var xml = await waitForValue(driver, 'sa_assertion',
    function (v) { return v.indexOf('AttributeStatement') !== -1; },
    "the <AttributeStatement> did not appear after adding an attribute.");
  assert.ok(xml.indexOf('Name="' + ATTR_PREFIX + ATTR_NAME + '"') !== -1,
    "The attribute Name is not the URI prefix + name: " + xml);
  assert.ok(xml.indexOf('NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"') !== -1,
    "A URI prefix did not switch NameFormat to attrname-format:uri.");
  assert.ok(xml.indexOf('xsi:type="xs:string"') !== -1,
    "The value type was not emitted as xsi:type.");
  assert.ok(xml.indexOf('xmlns:xs="http://www.w3.org/2001/XMLSchema"') !== -1 &&
    xml.indexOf('xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"') !== -1,
    "The xs/xsi namespaces used by xsi:type are not declared on the assertion.");
  assert.ok(xml.indexOf('>' + ATTR_VALUE + '</saml:AttributeValue>') !== -1,
    "The attribute value is not in the assertion.");

  var rows = await driver.findElements(By.css('#sa_attr_rows tr'));
  assert.strictEqual(rows.length, 1, "The attribute table should list exactly one attribute.");

  // A second attribute with a non-string type, then removal of it.
  await selectValue(driver, 'sa_attr_type', 'integer');
  await setInput(driver, 'sa_attr_prefix', '');
  await setInput(driver, 'sa_attr_name', 'employeeNumber');
  await setInput(driver, 'sa_attr_value', '4711');
  await click(driver, onclickBtn('addAttribute'));
  xml = await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('employeeNumber') !== -1; },
    "the second attribute was not added.");
  assert.ok(xml.indexOf('xsi:type="xs:integer"') !== -1, "The integer value type was not emitted.");
  assert.ok(xml.indexOf('NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"') !== -1,
    "An attribute with no URI prefix should use the unspecified name format.");

  var removes = await driver.findElements(By.css('#sa_attr_rows button'));
  assert.strictEqual(removes.length, 2, "Expected a Remove button per attribute row.");
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", removes[1]);
  await removes[1].click();
  await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('employeeNumber') === -1; },
    "removing an attribute did not update the assertion.");
  log.info("[attributes] OK — add (typed, prefixed), list, and remove.");
}

// Every checkbox collapses the fields it governs, so nothing that cannot apply
// is left on screen.
async function testDependentFieldCollapse(driver) {
  log.info("=== Pane #1 Compose — dependent-field collapse ===");
  var deps = [
    ['sa_opt_conditions', 'sa_conditions_group'],
    ['sa_opt_conditions', 'sa_row_conditions_times'],
    ['sa_opt_audience', 'sa_row_audience'],
    ['sa_opt_advice', 'sa_row_advice_ref'],
    ['sa_opt_authn', 'sa_authn_group'],
    ['sa_opt_locality', 'sa_row_locality_fields'],
    ['sa_opt_authz', 'sa_authz_group'],
    ['sa_opt_subject', 'sa_subject_group'],
    ['sa_opt_subjconf', 'sa_subjconf_group'],
    ['sa_opt_proxy', 'sa_row_proxy_count'],
  ];
  for (var i = 0; i < deps.length; i++) {
    var box = deps[i][0], group = deps[i][1];
    var wasOn = await driver.findElement(By.id(box)).isSelected();
    if (!wasOn) await click(driver, By.id(box));         // turn it on
    assert.ok(!(await isHidden(driver, group)),
      "[" + box + "] " + group + " should be visible while the box is checked.");
    await click(driver, By.id(box));                     // turn it off
    assert.ok(await isHidden(driver, group),
      "[" + box + "] " + group + " should be hidden while the box is unchecked.");
    if (wasOn) await click(driver, By.id(box));          // restore
  }
  log.info("[dependencies] OK — " + deps.length + " checkbox/field-group pairs collapse and expand.");
}

// Every field carries a tooltip, as on the other tool pages.
async function testTooltips(driver) {
  log.info("=== Tooltips ===");
  var missing = await driver.executeScript(
    "var bad = [];" +
    "var els = document.querySelectorAll('.saml-pane input, .saml-pane select, .saml-pane textarea, .saml-pane label');" +
    "for (var i = 0; i < els.length; i++) {" +
    "  var e = els[i];" +
    "  if (e.type === 'button' || e.type === 'submit') { if (!e.title) bad.push(e.value || e.id); continue; }" +
    "  if (!e.title) bad.push(e.id || e.htmlFor || e.textContent.trim().slice(0, 30));" +
    "}" +
    "return bad;");
  assert.strictEqual(missing.length, 0,
    "These controls have no tooltip: " + JSON.stringify(missing));
  log.info("[tooltips] OK — every field, label, and button carries a title.");
}

// The Generated Assertion box sits at the top of pane 1 and has a Pretty Print
// button that re-indents it without changing the XML.
async function testPrettyPrint(driver) {
  log.info("=== Pane #1 Compose — layout + pretty print ===");
  var firstField = await driver.executeScript(
    "var b = document.getElementById('pane_compose_body');" +
    "var f = b.querySelector('textarea, input, select');" +
    "return f ? f.id : '';");
  assert.strictEqual(firstField, 'sa_assertion',
    "The Generated Assertion field should be the first field in pane 1. Found: " + firstField);

  // Flatten the assertion, then pretty print it back into indented form.
  await driver.executeScript(
    "var e = document.getElementById('sa_assertion');" +
    "e.value = e.value.replace(/>\\s+</g, '><');");
  var flat = await getValue(driver, 'sa_assertion');
  assert.ok(flat.indexOf('\n') === -1, "The assertion was not flattened for the test.");
  await click(driver, onclickBtn('prettyPrintAssertion'));
  var pretty = await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('\n') !== -1; },
    "Pretty Print did not re-indent the assertion.");
  assert.ok(pretty.indexOf('\n  <saml:Issuer>') !== -1,
    "Pretty Print did not indent the assertion's children:\n" + pretty.slice(0, 300));
  // Same document, just re-indented.
  assert.strictEqual(pretty.replace(/>\s+</g, '><'), flat,
    "Pretty Print changed the XML, not just its whitespace.");
  log.info("[pretty print] OK — re-indents the generated assertion.");
}

async function checkCompliance(driver, label) {
  await complianceIsClean(driver, "[" + label + "]");
  log.info("[" + label + "] OK — compliance check reports no failures.");
}

// ===========================================================================
// Pane 2 — Sign, and Pane 3 — Encrypt
// ===========================================================================
async function signAndVerify(driver, label, expect) {
  await driver.executeScript("document.getElementById('sa_signed_assertion').value = '';");
  await click(driver, onclickBtn('signAssertion'));
  var signed = await waitForValue(driver, 'sa_signed_assertion',
    function (v) { return v.indexOf('SignatureValue') !== -1; },
    "[" + label + "] the assertion was not signed.");
  assert.ok(signed.indexOf('<ds:Signature') !== -1, "[" + label + "] no <ds:Signature> was produced.");

  // Reference URI + <ds:Signature> placement are version-specific.
  assert.ok(signed.indexOf('<ds:Reference URI="' + expect.refUri + '">') !== -1,
    "[" + label + '] expected Reference URI="' + expect.refUri + '" in:\n' + signed.slice(0, 800));
  if (expect.signatureLast) {
    assert.ok(/<\/ds:Signature><\/saml:Assertion>\s*$/.test(signed.trim()),
      "[" + label + "] the <ds:Signature> must be the assertion's last child:\n" + signed.slice(-200));
  } else {
    var afterIssuer = signed.indexOf('</saml:Issuer>');
    var sigAt = signed.indexOf('<ds:Signature');
    assert.ok(sigAt > afterIssuer && signed.slice(afterIssuer + '</saml:Issuer>'.length, sigAt).trim() === '',
      "[" + label + "] the <ds:Signature> must directly follow <saml:Issuer>:\n" + signed.slice(0, 600));
  }

  await driver.executeScript("document.getElementById('sa_verify_output').value = '';");
  await click(driver, onclickBtn('verifySignature'));
  var out = await waitForValue(driver, 'sa_verify_output',
    function (v) { return v.length > 0; }, "[" + label + "] verification produced no output.");
  assert.ok(out.indexOf('VALID') === 0, "[" + label + "] the signature did not verify:\n" + out);
  log.info("[" + label + "] OK — signed and verified (" + expect.placement + ").");

  // Negative control: tampering with a signed value must fail verification.
  await driver.executeScript(
    "var e = document.getElementById('sa_verify_input');" +
    "e.value = e.value.replace(arguments[0], 'attacker@example.com');" +
    "document.getElementById('sa_verify_output').value = '';", ATTR_VALUE);
  await click(driver, onclickBtn('verifySignature'));
  var bad = await waitForValue(driver, 'sa_verify_output',
    function (v) { return v.length > 0; }, "[" + label + "] tamper verification produced no output.");
  assert.ok(bad.indexOf('INVALID') === 0,
    "[" + label + "] a tampered assertion was accepted:\n" + bad);
  log.info("[" + label + "] OK — tampered assertion rejected.");

  // Put the untampered signature back. The page deliberately stops auto-filling
  // this box once its contents differ from the signature it produced (it will
  // not overwrite what the user typed), so leaving the tampered copy here would
  // make every later verification check the wrong document.
  await driver.executeScript(
    "document.getElementById('sa_verify_input').value = arguments[0];" +
    "document.getElementById('sa_verify_output').value = '';", signed);
  return signed;
}

async function encryptAndDecrypt(driver, label, signed, expectWrapper) {
  await driver.executeScript(
    "document.getElementById('sa_encrypted').value = '';" +
    "document.getElementById('sa_dec_input').value = '';");
  await click(driver, onclickBtn('encryptAssertion'));
  var enc = await waitForValue(driver, 'sa_encrypted',
    function (v) { return v.length > 0; }, "[" + label + "] the assertion was not encrypted.");
  if (expectWrapper) {
    assert.ok(enc.indexOf('<saml:EncryptedAssertion') === 0,
      "[" + label + "] SAML 2.0 output should be wrapped in <saml:EncryptedAssertion>: " + enc.slice(0, 120));
  } else {
    assert.ok(enc.indexOf('<xenc:EncryptedData') === 0,
      "[" + label + "] SAML 1.x has no EncryptedAssertion element; expected a bare EncryptedData: " + enc.slice(0, 120));
  }
  assert.ok(enc.indexOf('<xenc:EncryptedKey') !== -1,
    "[" + label + "] the wrapped session key (<xenc:EncryptedKey>) is missing.");
  assert.ok(enc.indexOf(ATTR_VALUE) === -1,
    "[" + label + "] the plaintext leaked into the encrypted output.");

  await driver.executeScript("document.getElementById('sa_dec_output').value = '';");
  await click(driver, onclickBtn('decryptAssertion'));
  var dec = await waitForValue(driver, 'sa_dec_output',
    function (v) { return v.length > 0; }, "[" + label + "] the assertion was not decrypted.");
  assert.strictEqual(dec, signed,
    "[" + label + "] the decrypted assertion does not match the signed one:\n" + dec.slice(0, 300));
  log.info("[" + label + "] OK — encrypt/decrypt round-trip (sign-then-encrypt).");
}

// Signing and encryption stay engaged: pane 1 shows the signed assertion, and
// any later edit — in any pane — rebuilds it, re-signs it, and re-encrypts it
// with no button pressed.
async function testAutoUpdate(driver) {
  log.info("=== Live updates — re-sign and re-encrypt on change ===");
  var signed = await getValue(driver, 'sa_signed_assertion');
  assert.strictEqual(await getValue(driver, 'sa_assertion'), signed,
    "Clicking Sign Assertion should put the signed assertion in the Generated Assertion box.");
  var beforeEnc = await getValue(driver, 'sa_encrypted');
  assert.ok(beforeEnc.length > 0, "expected a ciphertext from the previous step.");

  // Edit a pane 1 field — no buttons.
  var sess = driver.findElement(By.id('sa_session_index'));
  await sess.clear();
  await sess.sendKeys('_autoupdate1');
  var resigned = await waitForValue(driver, 'sa_signed_assertion',
    function (v) { return v.indexOf('_autoupdate1') !== -1; },
    "the signature was not recomputed after an edit.");
  assert.notStrictEqual(resigned, signed, "the signature did not change with the assertion.");
  assert.strictEqual(await getValue(driver, 'sa_assertion'), resigned,
    "the Generated Assertion box did not follow the recomputed signature.");

  // The recomputed signature must be valid over the new content.
  await driver.executeScript("document.getElementById('sa_verify_output').value = '';");
  await click(driver, onclickBtn('verifySignature'));
  var out = await waitForValue(driver, 'sa_verify_output', function (v) { return v.length > 0; },
    "verification of the recomputed signature produced no output.");
  assert.ok(out.indexOf('VALID') === 0, "the recomputed signature does not verify:\n" + out);

  // ... and the ciphertext must carry it.
  var reenc = await waitForValue(driver, 'sa_encrypted',
    function (v) { return v.length > 0 && v !== beforeEnc; },
    "the ciphertext was not recomputed after an edit.");
  assert.ok(reenc.length > 0);
  await driver.executeScript("document.getElementById('sa_dec_output').value = '';");
  await click(driver, onclickBtn('decryptAssertion'));
  var dec = await waitForValue(driver, 'sa_dec_output', function (v) { return v.length > 0; },
    "the recomputed ciphertext did not decrypt.");
  assert.strictEqual(dec, resigned,
    "the recomputed ciphertext does not carry the recomputed signed assertion.");

  // A pane 2 setting change re-signs as well.
  await selectValue(driver, 'sa_sig_alg', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512');
  await waitForValue(driver, 'sa_signed_assertion', function (v) { return v.indexOf('rsa-sha512') !== -1; },
    "changing the signature algorithm did not re-sign the assertion.");
  await selectValue(driver, 'sa_sig_alg', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
  await waitForValue(driver, 'sa_signed_assertion', function (v) { return v.indexOf('rsa-sha256') !== -1; },
    "restoring the signature algorithm did not re-sign the assertion.");
  log.info("[live updates] OK — edits re-sign and re-encrypt; pane 1 tracks the signed form.");
}

// Reset returns every pane to its declared defaults.
async function testReset(driver) {
  log.info("=== Reset ===");
  assert.strictEqual((await driver.findElements(By.xpath('//input[@value="Rebuild"]'))).length, 0,
    "The Rebuild button should be gone — the assertion updates automatically.");

  // Mutate state in all three panes first.
  await setInput(driver, 'sa_issuer', 'https://reset.example.com/issuer');
  await selectValue(driver, 'sa_sig_alg', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
  await selectValue(driver, 'sa_enc_data_alg', 'http://www.w3.org/2001/04/xmlenc#aes128-cbc');
  await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('reset.example.com') !== -1; },
    "the edited issuer did not reach the assertion.");

  await click(driver, onclickBtn('resetToDefaults'));
  await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('reset.example.com') === -1; },
    "Reset did not rebuild the assertion.");

  var expected = [
    ['sa_version', '2.0'],
    ['sa_issuer', baseUrl.replace(/\/+$/, '') + '/issuer'],
    ['sa_validity_minutes', '5'],
    ['sa_sig_alg', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'],
    ['sa_enc_data_alg', 'http://www.w3.org/2009/xmlenc11#aes256-gcm'],
    ['sa_authz_action', 'Read'],
    // Generated key material and every output are cleared.
    ['sa_private_key', ''], ['sa_public_key', ''], ['sa_enc_cert', ''], ['sa_enc_private_key', ''],
    ['sa_signed_assertion', ''], ['sa_encrypted', ''], ['sa_verify_output', ''], ['sa_dec_output', ''],
    ['sa_compliance_output', ''],
  ];
  for (var i = 0; i < expected.length; i++) {
    assert.strictEqual(await getValue(driver, expected[i][0]), expected[i][1],
      "Reset did not restore " + expected[i][0] + " to its default.");
  }
  assert.strictEqual(await driver.findElement(By.id('sa_opt_attrs')).isSelected(), false,
    "Reset should leave the custom-attribute checkbox unchecked.");
  assert.strictEqual(await driver.findElement(By.id('sa_opt_conditions')).isSelected(), true,
    "Reset should restore the Conditions checkbox to its default (checked).");
  var rows = await driver.findElements(By.css('#sa_attr_rows td.sa-empty'));
  assert.strictEqual(rows.length, 1, "Reset should drop every custom attribute.");

  var xml = await getValue(driver, 'sa_assertion');
  assert.ok(xml.indexOf('Version="2.0"') !== -1, "Reset should rebuild a SAML 2.0 assertion.");
  assert.ok(xml.indexOf('<ds:Signature') === -1, "Reset should leave the assertion unsigned.");
  assert.ok(xml.indexOf('AttributeStatement') === -1, "Reset should drop the AttributeStatement.");
  log.info("[reset] OK — all three panes restored to their defaults.");
}

// ===========================================================================
// Exhaustive pane 1 coverage, per assertion version
// ===========================================================================

// Put the optional-element checkboxes in a known state (all the ones the sweep
// and the field walks depend on turned ON, so every field is live and visible).
async function setCheckboxes(driver, state) {
  await driver.executeScript(
    "var s = arguments[0], last = null;" +
    "for (var id in s) { var e = document.getElementById(id); if (!e) continue;" +
    "  if (e.checked !== s[id]) { e.checked = s[id]; last = e; } }" +
    "(last || document.getElementById('sa_opt_conditions'))" +
    "  .dispatchEvent(new Event('change', { bubbles: true }));", state);
}
var ALL_ON = {
  sa_opt_subject: true, sa_opt_subjconf: true, sa_opt_conditions: true, sa_opt_audience: true,
  sa_opt_onetimeuse: true, sa_opt_proxy: true, sa_opt_advice: true, sa_opt_authn: true,
  sa_opt_locality: true, sa_opt_authz: true, sa_opt_attrs: true,
};

// The values of a <select>, skipping options hidden because the selected
// version does not define them.
async function visibleOptions(driver, id) {
  return driver.executeScript(
    "var s = document.getElementById(arguments[0]); var out = [];" +
    "for (var i = 0; i < s.options.length; i++) { if (!s.options[i].hidden) out.push(s.options[i].value); }" +
    "return out;", id);
}

async function complianceIsClean(driver, context) {
  await driver.executeScript("document.getElementById('sa_compliance_output').value = '';");
  await click(driver, onclickBtn('checkCompliance'));
  var out = await waitForValue(driver, 'sa_compliance_output', function (v) { return v.length > 0; },
    context + ": the compliance check produced no output.");
  assert.ok(out.indexOf('no failures') !== -1, context + ": assertion is not compliant:\n" + out);
}

// Every option of every <select> in pane 1, checking the assertion picks it up
// and stays compliant.
async function testAllSelectOptions(driver, v) {
  var v2 = v === '2.0';
  var cmPrefix = v2 ? 'urn:oasis:names:tc:SAML:2.0:cm:' : 'urn:oasis:names:tc:SAML:1.0:cm:';
  var cases = [
    { id: 'sa_nameid_format', expect: function (xml, o) { return xml.indexOf('Format="' + o + '"') !== -1; } },
    { id: 'sa_confirm_method', expect: function (xml, o) { return xml.indexOf(cmPrefix + o) !== -1; } },
    { id: 'sa_authz_decision', expect: function (xml, o) { return xml.indexOf('Decision="' + o + '"') !== -1; } },
    v2
      ? { id: 'sa_authn_context', expect: function (xml, o) { return xml.indexOf('<saml:AuthnContextClassRef>' + o + '<') !== -1; } }
      : { id: 'sa_authn_method', expect: function (xml, o) { return xml.indexOf('AuthenticationMethod="' + o + '"') !== -1; } },
  ];
  var total = 0;
  for (var c = 0; c < cases.length; c++) {
    var opts = await visibleOptions(driver, cases[c].id);
    assert.ok(opts.length > 0, "[" + v + "] " + cases[c].id + " offers no selectable option.");
    for (var i = 0; i < opts.length; i++) {
      var o = opts[i];
      await selectValue(driver, cases[c].id, o);
      var expect = cases[c].expect;
      await waitForValue(driver, 'sa_assertion', function (xml) { return expect(xml, o); },
        "[" + v + "] " + cases[c].id + "=" + o + " did not reach the assertion.");
      await complianceIsClean(driver, "[" + v + "] " + cases[c].id + "=" + o);
      total++;
    }
  }
  log.info("[" + v + "] OK — " + total + " select option(s) exercised, each reflected and compliant.");
}

// Every free-text field in pane 1: set a distinctive value and confirm it lands
// in the assertion in the right place for this version.
async function testAllTextFields(driver, v) {
  var v2 = v === '2.0';
  var fields = [
    { id: 'sa_issuer', value: 'https://sweep-' + v + '.example.com/issuer',
      expect: function (x, s) { return v2 ? x.indexOf('<saml:Issuer>' + s + '</saml:Issuer>') !== -1 : x.indexOf('Issuer="' + s + '"') !== -1; } },
    { id: 'sa_nameid_value', value: 'sweep-user@example.com',
      expect: function (x, s) { return x.indexOf('>' + s + '</saml:Name') !== -1; } },
    { id: 'sa_nameid_qualifier', value: 'urn:sweep:name-qualifier',
      expect: function (x, s) { return x.indexOf('NameQualifier="' + s + '"') !== -1; } },
    { id: 'sa_audience', value: 'https://sweep.example.com/sp',
      expect: function (x, s) { return x.indexOf('<saml:Audience>' + s + '</saml:Audience>') !== -1; } },
    { id: 'sa_advice_ref', value: '_sweepadvice1',
      expect: function (x, s) { return x.indexOf('>' + s + '<') !== -1; } },
    { id: 'sa_locality_address', value: '198.51.100.7',
      expect: function (x, s) { return x.indexOf((v2 ? 'Address="' : 'IPAddress="') + s + '"') !== -1; } },
    { id: 'sa_locality_dns', value: 'sweep.example.com',
      expect: function (x, s) { return x.indexOf((v2 ? 'DNSName="' : 'DNSAddress="') + s + '"') !== -1; } },
    { id: 'sa_authz_resource', value: 'https://sweep.example.com/protected',
      expect: function (x, s) { return x.indexOf('Resource="' + s + '"') !== -1; } },
    { id: 'sa_authz_action', value: 'Execute',
      expect: function (x, s) { return x.indexOf('>' + s + '</saml:Action>') !== -1; } },
    { id: 'sa_authz_action_ns', value: 'urn:oasis:names:tc:SAML:1.0:action:rwedc-negation',
      expect: function (x, s) { return x.indexOf('Namespace="' + s + '"') !== -1; } },
    { id: 'sa_id', value: '_sweepassertionid' + v.replace('.', ''),
      expect: function (x, s) { return x.indexOf((v2 ? 'ID="' : 'AssertionID="') + s + '"') !== -1; } },
    { id: 'sa_issue_instant', value: '2026-03-04T05:06:07Z',
      expect: function (x, s) { return x.indexOf('IssueInstant="' + s + '"') !== -1; } },
    { id: 'sa_not_before', value: '2026-03-04T05:00:00Z',
      expect: function (x, s) { return x.indexOf('NotBefore="' + s + '"') !== -1; } },
    { id: 'sa_not_on_or_after', value: '2026-03-04T06:00:00Z',
      expect: function (x, s) { return x.indexOf('NotOnOrAfter="' + s + '"') !== -1; } },
    { id: 'sa_authn_instant', value: '2026-03-04T05:06:07Z',
      expect: function (x, s) { return x.indexOf((v2 ? 'AuthnInstant="' : 'AuthenticationInstant="') + s + '"') !== -1; } },
  ];
  // SAML 2.0-only fields.
  if (v2) {
    fields = fields.concat([
      { id: 'sa_nameid_spqualifier', value: 'urn:sweep:sp-qualifier',
        expect: function (x, s) { return x.indexOf('SPNameQualifier="' + s + '"') !== -1; } },
      { id: 'sa_confirm_recipient', value: 'https://sweep.example.com/acs',
        expect: function (x, s) { return x.indexOf('Recipient="' + s + '"') !== -1; } },
      { id: 'sa_confirm_inresponseto', value: '_sweeprequest1',
        expect: function (x, s) { return x.indexOf('InResponseTo="' + s + '"') !== -1; } },
      { id: 'sa_confirm_address', value: '203.0.113.9',
        expect: function (x, s) { return x.indexOf('Address="' + s + '"') !== -1; } },
      { id: 'sa_confirm_notonorafter', value: '2026-03-04T05:16:07Z',
        expect: function (x, s) { return x.indexOf('NotOnOrAfter="' + s + '"') !== -1; } },
      { id: 'sa_session_index', value: '_sweepsession1',
        expect: function (x, s) { return x.indexOf('SessionIndex="' + s + '"') !== -1; } },
      { id: 'sa_session_notonorafter', value: '2026-03-04T09:06:07Z',
        expect: function (x, s) { return x.indexOf('SessionNotOnOrAfter="' + s + '"') !== -1; } },
      { id: 'sa_proxy_count', value: '3',
        expect: function (x, s) { return x.indexOf('Count="' + s + '"') !== -1; } },
    ]);
  }

  for (var i = 0; i < fields.length; i++) {
    var f = fields[i];
    await setInput(driver, f.id, f.value);
    var expect = f.expect, value = f.value;
    await waitForValue(driver, 'sa_assertion', function (xml) { return expect(xml, value); },
      "[" + v + "] " + f.id + '="' + f.value + '" did not reach the assertion.');
  }
  await complianceIsClean(driver, "[" + v + "] after every text field");

  // The timestamp controls: a new validity window must move NotOnOrAfter.
  var before = await getValue(driver, 'sa_not_on_or_after');
  await setInput(driver, 'sa_validity_minutes', '90');
  await setInput(driver, 'sa_skew_seconds', '120');
  await click(driver, onclickBtn('refreshTimestamps'));
  var after = await waitForValue(driver, 'sa_not_on_or_after', function (x) { return x !== before && x.length > 0; },
    "[" + v + "] Refresh Times did not recompute the validity window.");
  assert.ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(after),
    "[" + v + "] Refresh Times produced a malformed instant: " + after);
  // ... and New ID must mint a fresh NCName that reaches the assertion.
  var oldId = await getValue(driver, 'sa_id');
  await click(driver, onclickBtn('refreshId'));
  var newId = await waitForValue(driver, 'sa_id', function (x) { return x !== oldId; },
    "[" + v + "] New ID did not change the assertion identifier.");
  assert.ok(newId.indexOf('_') === 0, "[" + v + "] a generated ID must be an NCName: " + newId);
  await waitForValue(driver, 'sa_assertion', function (x) { return x.indexOf(newId) !== -1; },
    "[" + v + "] the new assertion ID did not reach the assertion.");
  await complianceIsClean(driver, "[" + v + "] after the timestamp/ID controls");
  log.info("[" + v + "] OK — " + fields.length + " text field(s) plus the timestamp and ID controls.");
}

// Every attribute value type, and both the prefixed and unprefixed name forms.
async function testAllAttributeTypes(driver, v) {
  var v2 = v === '2.0';
  await click(driver, onclickBtn('clearAttributes'));
  var types = await visibleOptions(driver, 'sa_attr_type');
  for (var i = 0; i < types.length; i++) {
    var t = types[i];
    var name = 'sweep' + t;
    var value = t === 'integer' ? '4711'
      : t === 'boolean' ? 'true'
      : t === 'dateTime' ? '2026-03-04T05:06:07Z'
      : t === 'anyURI' ? 'https://sweep.example.com/attr'
      : t === 'base64Binary' ? 'c3dlZXA='
      : 'sweep-' + t;
    // Alternate prefixed / unprefixed so both name forms are covered.
    var prefix = (i % 2 === 0) ? ATTR_PREFIX : '';
    await selectValue(driver, 'sa_attr_type', t);
    await setInput(driver, 'sa_attr_prefix', prefix);
    await setInput(driver, 'sa_attr_name', name);
    await setInput(driver, 'sa_attr_value', value);
    await click(driver, onclickBtn('addAttribute'));

    var xml = await waitForValue(driver, 'sa_assertion', function (x) { return x.indexOf(name) !== -1; },
      "[" + v + "] attribute " + name + " was not added.");
    if (v2) {
      assert.ok(xml.indexOf('Name="' + prefix + name + '"') !== -1,
        "[" + v + "] attribute Name should be the URI prefix + name for " + t + ".");
      assert.ok(xml.indexOf('NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:' +
        (prefix ? 'uri' : 'unspecified') + '"') !== -1,
        "[" + v + "] wrong NameFormat for " + (prefix ? 'a prefixed' : 'an unprefixed') + " attribute.");
    } else {
      assert.ok(xml.indexOf('AttributeName="' + name + '"') !== -1,
        "[" + v + "] SAML 1.x should use AttributeName for " + t + ".");
      assert.ok(xml.indexOf('AttributeNamespace="' + (prefix || 'urn:oasis:names:tc:SAML:1.0:assertion') + '"') !== -1,
        "[" + v + "] SAML 1.x should use AttributeNamespace for " + t + ".");
    }
    if (t === 'unspecified') {
      assert.ok(xml.indexOf('>' + value + '</saml:AttributeValue>') !== -1,
        "[" + v + "] the unspecified type should emit a bare AttributeValue.");
    } else {
      assert.ok(xml.indexOf('xsi:type="xs:' + t + '">' + value + '</saml:AttributeValue>') !== -1,
        "[" + v + "] xsi:type=xs:" + t + " was not emitted with its value.");
    }
    await complianceIsClean(driver, "[" + v + "] attribute type " + t);
  }
  var rows = await driver.findElements(By.css('#sa_attr_rows tr'));
  assert.strictEqual(rows.length, types.length,
    "[" + v + "] the attribute table should list every added attribute.");

  // Back to a single attribute for the power-set sweep.
  await click(driver, onclickBtn('clearAttributes'));
  await selectValue(driver, 'sa_attr_type', 'string');
  await setInput(driver, 'sa_attr_prefix', ATTR_PREFIX);
  await setInput(driver, 'sa_attr_name', ATTR_NAME);
  await setInput(driver, 'sa_attr_value', ATTR_VALUE);
  await click(driver, onclickBtn('addAttribute'));
  log.info("[" + v + "] OK — " + types.length + " attribute value type(s), prefixed and unprefixed.");
}

// The complete power set of the optional-element checkboxes. Driven in-page (a
// round-trip per state would take minutes): for each of the 2^9 combinations it
// rebuilds, then checks the XML parses, that each element is present exactly
// when the settings imply it, and that the compliance verdict matches whether
// the combination is genuinely valid.
var POWER_SET_SCRIPT = [
  "var version = arguments[0], markers = arguments[1];",
  "var keys = ['subject','subjconf','conditions','audience','onetimeuse','proxy','advice','authn','locality','authz'];",
  "var ids = {subject:'sa_opt_subject', subjconf:'sa_opt_subjconf', conditions:'sa_opt_conditions',",
  "           audience:'sa_opt_audience', onetimeuse:'sa_opt_onetimeuse', proxy:'sa_opt_proxy',",
  "           advice:'sa_opt_advice', authn:'sa_opt_authn', locality:'sa_opt_locality', authz:'sa_opt_authz'};",
  "var v2 = version === '2.0';",
  "var problems = [], states = 0;",
  "var attrsBox = document.getElementById('sa_opt_attrs');",
  "var parser = new DOMParser();",
  "for (var mask = 0; mask < (1 << keys.length); mask++) {",
  "  var on = {};",
  "  for (var i = 0; i < keys.length; i++) {",
  "    on[keys[i]] = !!(mask & (1 << i));",
  "    document.getElementById(ids[keys[i]]).checked = on[keys[i]];",
  "  }",
  "  on.attrs = attrsBox.checked;",
  "  document.getElementById(ids.conditions).dispatchEvent(new Event('change', { bubbles: true }));",
  "  states++;",
  "  var xml = document.getElementById('sa_assertion').value;",
  "  var label = version + ' [' + keys.filter(function (k) { return on[k]; }).join(',') + ']';",
  "",
  "  var doc = parser.parseFromString(xml, 'application/xml');",
  "  if (doc.getElementsByTagName('parsererror').length) { problems.push(label + ': not well-formed XML'); continue; }",
  "",
  "  var stmts = (on.authn ? 1 : 0) + (on.attrs ? 1 : 0) + (on.authz ? 1 : 0);",
  "  var subjectShown = v2 ? on.subject : stmts > 0;",
  "  var expected = {",
  "    subject: subjectShown,",
  "    subjconf: subjectShown && on.subjconf,",
  "    conditions: on.conditions,",
  "    audience: on.conditions && on.audience,",
  "    onetimeuse: on.conditions && on.onetimeuse && version !== '1.0',",
  "    proxy: on.conditions && on.proxy && v2,",
  "    advice: on.advice,",
  "    authn: on.authn,",
  "    locality: on.authn && on.locality,",
  "    attrs: on.attrs,",
  "    authz: on.authz",
  "  };",
  "  for (var k in expected) {",
  "    if (!markers[k]) continue;",
  "    var present = xml.indexOf(markers[k]) !== -1;",
  "    if (present !== expected[k]) {",
  "      problems.push(label + ': ' + markers[k] + ' is ' + (present ? 'present' : 'absent') +",
  "                    ' but should be ' + (expected[k] ? 'present' : 'absent'));",
  "    }",
  "  }",
  "",
  "  saml_tools.checkCompliance();",
  "  var report = document.getElementById('sa_compliance_output').value;",
  "  var clean = report.indexOf('no failures') !== -1;",
  "  var shouldBeClean = v2 ? (stmts > 0 || on.subject) : (stmts > 0);",
  "  if (clean !== shouldBeClean) {",
  "    problems.push(label + ': compliance says ' + (clean ? 'clean' : 'failing') +",
  "                  ' but the combination is ' + (shouldBeClean ? 'valid' : 'invalid') + '\\n' + report);",
  "  }",
  "  if (problems.length > 12) { problems.push('... stopping after 12 problems'); break; }",
  "}",
  "return { states: states, problems: problems };",
].join("\n");

async function testOptionalElementPowerSet(driver, v) {
  var v2 = v === '2.0';
  var markers = {
    subject: '<saml:Subject>',
    subjconf: '<saml:SubjectConfirmation',
    conditions: '<saml:Conditions',
    audience: v2 ? '<saml:AudienceRestriction>' : '<saml:AudienceRestrictionCondition>',
    onetimeuse: v2 ? '<saml:OneTimeUse/>' : '<saml:DoNotCacheCondition/>',
    proxy: '<saml:ProxyRestriction',
    advice: '<saml:Advice>',
    authn: v2 ? '<saml:AuthnStatement' : '<saml:AuthenticationStatement',
    locality: '<saml:SubjectLocality',
    attrs: '<saml:AttributeStatement>',
    authz: v2 ? '<saml:AuthzDecisionStatement' : '<saml:AuthorizationDecisionStatement',
  };
  var result = await driver.executeScript(POWER_SET_SCRIPT, v, markers);
  assert.strictEqual(result.problems.length, 0,
    "[" + v + "] optional-element combinations misbehaved:\n  " + result.problems.join("\n  "));
  assert.strictEqual(result.states, 1024, "[" + v + "] expected 1024 combinations, ran " + result.states);
  log.info("[" + v + "] OK — " + result.states + " optional-element combinations: structure and compliance both correct.");
  await setCheckboxes(driver, ALL_ON);
}

// ===========================================================================
// Version-specific structure
// ===========================================================================
async function testSaml1x(driver, minor) {
  var label = "SAML 1." + minor;
  log.info("=== " + label + " structure ===");
  await selectValue(driver, 'sa_version', '1.' + minor);
  var xml = await waitForValue(driver, 'sa_assertion',
    function (v) { return v.indexOf('MinorVersion="' + minor + '"') !== -1; },
    "[" + label + "] the assertion did not switch version.");

  assert.ok(xml.indexOf('xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"') !== -1,
    "[" + label + "] SAML 1.x must use the 1.0 assertion namespace.");
  assert.ok(xml.indexOf('MajorVersion="1"') !== -1, "[" + label + "] MajorVersion is missing.");
  assert.ok(xml.indexOf('AssertionID="_') !== -1, "[" + label + "] SAML 1.x identifies the assertion by AssertionID.");
  assert.ok(xml.indexOf('<saml:Issuer>') === -1 && /\sIssuer="[^"]+"/.test(xml),
    "[" + label + "] SAML 1.x carries the Issuer as an attribute, not an element.");
  assert.ok(xml.indexOf('<saml:NameIdentifier') !== -1,
    "[" + label + "] SAML 1.x uses <NameIdentifier>, not <NameID>.");
  assert.ok(xml.indexOf('<saml:AudienceRestrictionCondition>') !== -1,
    "[" + label + "] SAML 1.x uses <AudienceRestrictionCondition>.");
  assert.ok(xml.indexOf('<saml:AuthenticationStatement') !== -1,
    "[" + label + "] SAML 1.x uses <AuthenticationStatement>.");
  assert.ok(xml.indexOf('<saml:Subject>') > xml.indexOf('<saml:AuthenticationStatement'),
    "[" + label + "] in SAML 1.x the Subject belongs to each statement.");
  assert.ok(xml.indexOf('AttributeName="' + ATTR_NAME + '"') !== -1 &&
    xml.indexOf('AttributeNamespace="' + ATTR_PREFIX + '"') !== -1,
    "[" + label + "] the URI prefix should become AttributeNamespace in SAML 1.x:\n" + xml);

  // SubjectConfirmation is an element with a <ConfirmationMethod> child in 1.x,
  // and the URI carries the 1.0 version segment whichever method is selected
  // (the select itself is walked option by option in testAllSelectOptions).
  assert.ok(/<saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1\.0:cm:[a-z-]+<\/saml:ConfirmationMethod>/.test(xml),
    "[" + label + "] the 1.x confirmation method URI is wrong:\n" + xml);

  // DoNotCacheCondition arrived in 1.1; it must never appear in a 1.0 assertion.
  var otuHidden = await isHidden(driver, 'sa_row_onetimeuse');
  if (minor === '0') {
    assert.ok(otuHidden, "[" + label + "] the OneTimeUse/DoNotCacheCondition row must be hidden for SAML 1.0.");
  } else {
    assert.ok(!otuHidden, "[" + label + "] DoNotCacheCondition should be offered for SAML 1.1.");
    // Normalize first — earlier steps may have left the box either way.
    if (await driver.findElement(By.id('sa_opt_onetimeuse')).isSelected()) {
      await click(driver, By.id('sa_opt_onetimeuse'));
    }
    await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('DoNotCacheCondition') === -1; },
      "[" + label + "] <DoNotCacheCondition> should be absent while the box is unchecked.");
    await click(driver, By.id('sa_opt_onetimeuse'));
    await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('<saml:DoNotCacheCondition/>') !== -1; },
      "[" + label + "] <DoNotCacheCondition> did not appear.");
    await click(driver, By.id('sa_opt_onetimeuse'));
    await waitForValue(driver, 'sa_assertion', function (v) { return v.indexOf('DoNotCacheCondition') === -1; },
      "[" + label + "] <DoNotCacheCondition> did not disappear.");
  }

  // SAML 2.0-only controls are hidden.
  assert.ok(await isHidden(driver, 'sa_row_proxy'),
    "[" + label + "] the ProxyRestriction row must be hidden (SAML 2.0 only).");
  assert.ok(await isHidden(driver, 'sa_row_session'),
    "[" + label + "] the SessionIndex row must be hidden (SAML 2.0 only).");
  assert.ok(await isHidden(driver, 'sa_row_authn_context'),
    "[" + label + "] AuthnContextClassRef must be hidden (SAML 2.0 only).");
  assert.ok(!(await isHidden(driver, 'sa_row_authn_method')),
    "[" + label + "] AuthenticationMethod must be shown for SAML 1.x.");
  assert.ok(await isHidden(driver, 'sa_row_spqualifier'),
    "[" + label + "] SPNameQualifier must be hidden (SAML 2.0 only).");
  assert.ok(await isHidden(driver, 'sa_row_confirm_data'),
    "[" + label + "] the SubjectConfirmationData fields must be hidden (SAML 2.0 only).");
  assert.ok(await isHidden(driver, 'sa_row_enc_wrap'),
    "[" + label + "] the EncryptedAssertion wrapper option must be hidden in pane 3 (SAML 2.0 only).");
  // Down to individual <select> options.
  assert.strictEqual(await isOptionHidden(driver, 'sa_confirm_method', 'artifact'), false,
    "[" + label + "] the artifact confirmation method should be offered for SAML 1.x.");
  assert.strictEqual(
    await isOptionHidden(driver, 'sa_nameid_format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'), true,
    "[" + label + "] the SAML 2.0-only NameID formats must be hidden.");

  await checkCompliance(driver, label);
}

// The signing and encryption round-trips, run once with key pairs generated
// fresh in pane 2 (signing) and pane 3 (recipient) — two distinct certificates.
async function testCryptoOnce(driver) {
  log.info("=== Panes #2 and #3 — key generation, sign/validate, encrypt/decrypt ===");

  await click(driver, onclickBtn('generateKeys'));
  await waitForValue(driver, 'sa_private_key', function (v) { return v.indexOf('BEGIN') !== -1; },
    "the signing private key was not generated.", rsaWait);
  var signCert = await waitForValue(driver, 'sa_public_key',
    function (v) { return v.indexOf('BEGIN CERTIFICATE') !== -1; },
    "the signing certificate was not generated.", rsaWait);

  await click(driver, onclickBtn('generateEncryptionKeys'));
  await waitForValue(driver, 'sa_enc_private_key', function (v) { return v.indexOf('BEGIN') !== -1; },
    "the recipient private key was not generated.", rsaWait);
  var encCert = await waitForValue(driver, 'sa_enc_cert',
    function (v) { return v.indexOf('BEGIN CERTIFICATE') !== -1 && v !== signCert; },
    "the recipient certificate was not generated.", rsaWait);
  assert.notStrictEqual(encCert, signCert,
    "pane 3 should generate its own recipient certificate, not reuse the signing one.");
  log.info("[keys] OK — separate key pairs generated in pane 2 and pane 3.");

  var signed = await signAndVerify(driver, "SAML 2.0", {
    refUri: '#' + (await getValue(driver, 'sa_id')),
    signatureLast: false,
    placement: 'Signature directly after Issuer',
  });
  await encryptAndDecrypt(driver, "SAML 2.0", signed, true);
  return signed;
}

// Nothing on the page may raise a browser console error over the whole run.
async function testNoConsoleErrors(driver) {
  log.info("=== Browser console ===");
  var entries;
  try {
    entries = await driver.manage().logs().get(logging.Type.BROWSER);
  } catch (e) {
    log.info("[console] SKIP — the browser log is unavailable here: " + e.message);
    return;
  }
  var severe = (entries || []).filter(function (e) {
    return e.level && e.level.name === 'SEVERE';
  }).map(function (e) { return e.message; });
  assert.strictEqual(severe.length, 0, "the page logged console errors:\n  " + severe.join("\n  "));
  log.info("[console] OK — no console errors across " + (entries || []).length + " log entr(y|ies).");
}

async function testToolsPane(driver) {
  log.info("=== SAML Test Tools — Tools pane ===");
  await driver.get(baseUrl + "/saml_request.html");
  await driver.wait(until.elementLocated(By.id('pane_tools')), waitTime);
  var link = driver.findElement(By.css('#pane_tools_body a[href^="/saml_tools.html"]'));
  var text = await link.getText();
  assert.ok(text.indexOf('SAML Assertion Tool') !== -1,
    "The Tools pane does not link to the SAML Assertion Tool. Found: " + text);

  // The pane collapses/expands like the others, and the page-level switch
  // (samlSetAllPanes) covers it too.
  var body = driver.findElement(By.id('pane_tools_body'));
  await click(driver, By.xpath("//legend[contains(@onclick, \"pane_tools_body\")]"));
  await driver.wait(until.elementIsNotVisible(body), waitTime,
    "the Tools pane did not collapse when its title was clicked.");
  await click(driver, By.xpath("//legend[contains(@onclick, \"pane_tools_body\")]"));
  await driver.wait(until.elementIsVisible(body), waitTime,
    "the Tools pane did not expand when its title was clicked again.");
  // The switch input itself is visually hidden (opacity:0); its label's slider
  // is the clickable surface.
  await click(driver, By.css('.saml-toggle-slider'));
  await driver.wait(until.elementIsNotVisible(body), waitTime,
    "the collapse-all switch did not collapse the Tools pane.");
  // The switch input itself is visually hidden (opacity:0); its label's slider
  // is the clickable surface.
  await click(driver, By.css('.saml-toggle-slider'));
  await driver.wait(until.elementIsVisible(body), waitTime,
    "the expand-all switch did not expand the Tools pane.");
  log.info("[tools pane] OK — collapses and expands with the other panes.");
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", link);
  await link.click();
  await driver.wait(until.urlContains('saml_tools.html'), waitTime);
  var ret = await driver.findElement(By.id('return_link')).getAttribute('href');
  assert.ok(ret.indexOf('/saml_request.html') !== -1,
    "The assertion page should return to the SAML Test Tools page. Found: " + ret);
  log.info("[tools pane] OK — links to the SAML Assertion Tool and back.");
}

// The same Tools pane is carried on the SAML Response page (whose panes are not
// collapsible, so only the links are checked here).
async function testResponseToolsPane(driver) {
  log.info("=== SAML Response — Tools pane ===");
  await driver.get(baseUrl + "/saml_response.html");
  await driver.wait(until.elementLocated(By.id('pane_tools')), waitTime);
  var link = driver.findElement(By.css('#pane_tools_body a[href^="/saml_tools.html"]'));
  var text = await link.getText();
  assert.ok(text.indexOf('SAML Assertion Tool') !== -1,
    "The SAML Response Tools pane does not link to the SAML Assertion Tool. Found: " + text);
  var cert = await driver.findElements(By.css('#pane_tools_body a[href^="/saml_cert.html"]'));
  assert.strictEqual(cert.length, 1, "The SAML Response Tools pane should link to the certificate details page.");
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", link);
  await link.click();
  await driver.wait(until.urlContains('saml_tools.html'), waitTime);
  log.info("[tools pane] OK — the SAML Response page carries the same pane.");
}

// ===========================================================================
async function samlAssertionActivities(driver) {
  await driver.get(baseUrl + "/saml_tools.html");
  // The page persists everything to localStorage; start from a clean slate so a
  // previous run's attributes or toggles cannot skew the assertions below.
  await driver.executeScript("window.localStorage.clear();");
  await driver.get(baseUrl + "/saml_tools.html");
  await driver.wait(until.elementLocated(By.id('sa_assertion')), waitTime);

  await testDefaults(driver);
  await testTooltips(driver);
  await testOptionalElements(driver);
  await testDependentFieldCollapse(driver);
  await testCustomAttribute(driver);
  await testPrettyPrint(driver);
  await checkCompliance(driver, "SAML 2.0");

  // SAML 2.0: the 1.x-only artifact confirmation method is hidden.
  assert.strictEqual(await isOptionHidden(driver, 'sa_confirm_method', 'artifact'), true,
    "The artifact confirmation method is SAML 1.x only and should be hidden for 2.0.");
  assert.strictEqual(
    await isOptionHidden(driver, 'sa_nameid_format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'), false,
    "The SAML 2.0 NameID formats should be offered for 2.0.");

  // ---- Exhaustive pane 1 coverage, per version ---------------------------
  // Signing/encryption are still off here, so every state below is a plain
  // rebuild of the assertion: fast, and the Generated Assertion box holds the
  // composed assertion itself.
  var versions = [['2.0', null], ['1.1', '1'], ['1.0', '0']];
  for (var i = 0; i < versions.length; i++) {
    var v = versions[i][0], minor = versions[i][1];
    log.info("=== Exhaustive pane #1 sweep — SAML " + v + " ===");
    if (minor !== null) await testSaml1x(driver, minor);
    else await selectValue(driver, 'sa_version', '2.0');
    await setCheckboxes(driver, ALL_ON);
    await testAllSelectOptions(driver, v);
    await testAllTextFields(driver, v);
    await testAllAttributeTypes(driver, v);
    await testOptionalElementPowerSet(driver, v);
  }

  // ---- Crypto: once, on a SAML 2.0 assertion -----------------------------
  await selectValue(driver, 'sa_version', '2.0');
  await waitForValue(driver, 'sa_assertion', function (x) { return x.indexOf('Version="2.0"') !== -1; },
    "could not switch back to SAML 2.0 for the crypto round-trip.");
  await checkCompliance(driver, "SAML 2.0 (before signing)");
  await testCryptoOnce(driver);
  await testAutoUpdate(driver);

  await testReset(driver);
  await testNoConsoleErrors(driver);

  await testToolsPane(driver);
  await testResponseToolsPane(driver);
}

async function test() {
  const options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages under coverage.
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  var secureOrigin = baseUrl.replace(/\/+$/, "");
  options.addArguments("--unsafely-treat-insecure-origin-as-secure=" + secureOrigin);
  options.addArguments("--user-data-dir=/tmp/saml-assertion-chrome-" + Date.now());
  // Collect browser-side errors so the run can assert the page logged none.
  try {
    const prefs = new logging.Preferences();
    prefs.setLevel(logging.Type.BROWSER, logging.Level.SEVERE);
    options.setLoggingPrefs(prefs);
  } catch (e) {
    log.info("browser logging preferences unavailable: " + e.message);
  }
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    log.info("Starting Test run.");
    await driver.manage().deleteAllCookies();
    await samlAssertionActivities(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program
  .name('saml_tools')
  .description("Run SAML Assertion Tool UI test (compose 1.0/1.1/2.0, sign, encrypt).")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });
program.parse(process.argv).opts();

test();
