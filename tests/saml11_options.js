// File: saml11_options.js
//
// ===========================================================================
// WHAT THE SAML REQUEST PAGE OFFERS WHEN PROTOCOL VERSION IS **SAML 1.1**, AND
// WHAT IT MUST STOP OFFERING.
//
// No identity provider is involved and none is needed: everything here is a
// property of the page in front of the settings, which is exactly what
// `saml11_sso.js` cannot isolate — that test drives a real round trip, so a
// control wrongly left live is invisible there as long as the flow works
// anyway.
//
// ---------------------------------------------------------------------------
// SAML 1.1 HAS NO REQUEST MESSAGE, AND FIVE SETTINGS FOLLOW FROM THAT.
//
// The browser profiles (saml-profile-1.1 sections 4.1 and 4.2) are
// IDENTITY-PROVIDER-INITIATED. There is no `<samlp:AuthnRequest>`; what a real
// SAML 1.1 service provider sends is Shibboleth's request profile — the query
// parameters `TARGET`, `shire`, `providerId` and `time`. So:
//
//   the username hint      belongs in <saml:Subject> on an AuthnRequest
//   sign the request       there is nothing to sign
//   encrypt the request    there is nothing to encrypt
//   Single Logout          SAML 1.1 has none — absent from the protocol
//   the SLO endpoints      nothing publishes them
//
// **EACH IS ASSERTED TWICE, and the second half is the one that matters.** The
// class is what a reader sees; `disabled` is what a Return keypress in a text
// field obeys. A block that only LOOKS dead still submits, and the refusal
// inside callIdp() is then the first thing that says anything — by which point
// the browser has been handed to an identity provider. `tests/pki_page.js`
// asserts the same two properties separately about `#pane_tls` and for the same
// reason.
//
// **AND THE SP KEY PAIR IS ASSERTED STILL LIVE**, which is the one that looks
// inconsistent and is deliberate: it signs the SOAP <samlp:Request> that
// resolves an artifact, and it is the KeyDescriptor in the SP metadata this
// page builds. A sweep that greyed "everything to do with signing" would take
// away two things that work, and only a check that says so will stop it.
//
// ---------------------------------------------------------------------------
// THE OTHER HALF: WHAT IT MUST START OFFERING.
//
//   * The request preview holds Shibboleth's parameters and NOT an
//     <AuthnRequest> — per binding, since the `profile` parameter is what
//     chooses between the two browser profiles and nothing in SAML 1.1 lets a
//     relying party ask.
//   * `Call IdP` refuses BY NAME rather than navigating, when there is no
//     inter-site transfer service address and when there is no `shire`.
//   * `Logout` refuses BY NAME, naming the protocol rather than an
//     implementation gap.
//   * The SP metadata the page builds describes a SAML **1.1** service
//     provider: `protocolSupportEnumeration` names the 1.1 protocol, the
//     assertion consumer endpoints are bound with the two PROFILE URIs (a 1.1
//     descriptor's Binding attribute carries a profile identifier, which is
//     what Shibboleth's own metadata does), there is no SingleLogoutService and
//     no `AuthnRequestsSigned`. A document that advertised the SAML 2.0
//     bindings here describes endpoints no SAML 1.1 identity provider will use,
//     and nothing about it looks wrong.
//   * Switching BACK to 2.0 restores every control. A one-way transition is the
//     easy defect here and it survives any test that only ever selects 1.1.
// ===========================================================================

const { Builder, By, until } = require("selenium-webdriver");
const browserFlags = require("./browser_flags.js");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'saml11_options',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// The SAML 1.1 vocabulary this test asserts against. Every URI carries `1.0`
// except the protocol one, and that is not a typo in either direction: the
// schemas were never renamed between 1.0 and 1.1 (the version travels in
// MajorVersion/MinorVersion), while protocolSupportEnumeration names the
// PROTOCOL and is spelled 1.1.
const PROFILE_POST = 'urn:oasis:names:tc:SAML:1.0:profiles:browser-post';
const PROFILE_ARTIFACT = 'urn:oasis:names:tc:SAML:1.0:profiles:artifact-01';
const PROTOCOL_11 = 'urn:oasis:names:tc:SAML:1.1:protocol';
const PROTOCOL_20 = 'urn:oasis:names:tc:SAML:2.0:protocol';

// The controls that must go dead on SAML 1.1, and the container greyed with
// each. A container of '' means the control is greyed on its own.
const OFF_ON_11 = [
  ['saml_username_hint', 'saml_hint_field',
   'the username hint goes in <saml:Subject> on an AuthnRequest, and SAML ' +
   '1.1 has no request document'],
  ['saml_sign_request', 'saml_sign_field',
   'there is nothing to sign: Shibboleth\'s request profile is unsigned ' +
   'query parameters'],
  ['saml_encrypt_request', 'saml_encrypt_field',
   'there is nothing to encrypt either, and SAML 2.0\'s own option here is ' +
   'already marked non-standard'],
  ['saml_slo_post', 'saml_slo_section',
   'SAML 1.1 publishes no logout endpoint because it has no logout message'],
  ['saml_slo_redirect', 'saml_slo_section', 'the same'],
  ['saml_slo_artifact', 'saml_slo_section', 'the same'],
  ['saml_logout_btn', '',
   'SAML 1.1 has no Single Logout at all — absent from the protocol, not ' +
   'unimplemented here']
];

async function click(driver, locator) {
  log.debug("Entering click().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var target = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(target), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", target);
  await target.click();
  log.debug("Leaving click().");
}
async function setInput(driver, id, text) {
  log.debug("Entering setInput().");
  var target = driver.findElement(By.id(id));
  await target.clear();
  if (text) await target.sendKeys(text);
  log.debug("Leaving setInput().");
}
async function selectValue(driver, id, value) {
  log.debug("Entering selectValue().");
  await new Select(driver.findElement(By.id(id))).selectByValue(value);
  log.debug("Leaving selectValue().");
}
async function valueOf(driver, id) {
  log.debug("Entering valueOf().");
  var v = await driver.findElement(By.id(id)).getAttribute("value");
  log.debug("Leaving valueOf().");
  return v || "";
}
async function textOf(driver, id) {
  log.debug("Entering textOf().");
  var v = await driver.executeScript(
    "var e = document.getElementById(arguments[0]); " +
    "return e ? (e.textContent || '') : '';", id);
  log.debug("Leaving textOf().");
  return v || "";
}
async function isDisabled(driver, id) {
  log.debug("Entering isDisabled().");
  var v = await driver.executeScript(
    "var e = document.getElementById(arguments[0]); " +
    "return e ? !!e.disabled : null;", id);
  log.debug("Leaving isDisabled().");
  return v;
}
async function hasClass(driver, id, className) {
  log.debug("Entering hasClass().");
  var v = await driver.executeScript(
    "var e = document.getElementById(arguments[0]); " +
    "return e ? e.classList.contains(arguments[1]) : null;", id, className);
  log.debug("Leaving hasClass().");
  return v;
}
// The colour a reader actually sees, rather than the class that is supposed to
// produce it. A class whose stylesheet never loaded is the failure this catches
// and the class check cannot — `css/saml_common.css` is shared with the
// WS-Trust and WS-Federation pages and has been linked wrongly before.
async function isGreyed(driver, id) {
  log.debug("Entering isGreyed().");
  var v = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (!e) return null;" +
    "return window.getComputedStyle(e).color;", id);
  log.debug("Leaving isGreyed(). color=" + v);
  return v;
}

function btn(fn) {
  log.debug("Entering btn().");
  log.debug("Leaving btn().");
  return By.xpath("//input[contains(@onclick, \"saml_request." + fn + "(\")]");
}

// Wait for the page bundle's global to exist. An inline onclick fired before
// browserify's --standalone global is defined is a SILENT no-op, which reads
// here as a button that did nothing.
async function waitForBundle(driver) {
  log.debug("Entering waitForBundle().");
  await driver.wait(async function () {
    return driver.executeScript(
      "return typeof window.saml_request === 'object' && " +
      "typeof window.saml_request.callIdp === 'function';");
  }, waitTime, "the saml_request bundle never defined its global.");
  log.debug("Leaving waitForBundle().");
}

// Selecting a version through the real <select> AND its change handler, then
// waiting for the page to have acted on it. Setting `.value` alone fires
// nothing, which would make every assertion below read the previous version's
// state and pass for the wrong reason.
async function chooseVersion(driver, version) {
  log.debug("Entering chooseVersion(). version=" + version);
  await selectValue(driver, 'saml_version', version);
  await driver.wait(async function () {
    var v = await valueOf(driver, 'saml_version');
    if (v !== version) return false;
    // onVersionChange() runs applyVersionAvailability(), whose last visible
    // effect is the hint field's state — so waiting on that is waiting on the
    // whole of it.
    var off = await isDisabled(driver, 'saml_username_hint');
    return version === '2.0' ? off === false : off === true;
  }, waitTime, "the page never applied Protocol Version " + version + ".");
  log.debug("Leaving chooseVersion().");
}

async function assertControlsOffForSaml11(driver) {
  log.debug("Entering assertControlsOffForSaml11().");
  for (var i = 0; i < OFF_ON_11.length; i++) {
    var id = OFF_ON_11[i][0];
    var container = OFF_ON_11[i][1];
    var why = OFF_ON_11[i][2];
    var off = await isDisabled(driver, id);
    assert.strictEqual(off, true, "#" + id + " must be DISABLED on SAML 1.1 " +
      "— " + why + ". A control that is merely greyed still submits on a " +
      "Return keypress. disabled=" + off);
    var greyTarget = container || id;
    var grey = await hasClass(driver, greyTarget, 'saml-unavailable');
    assert.strictEqual(grey, true, "#" + greyTarget + " must carry the " +
      "saml-unavailable class on SAML 1.1, so a reader can SEE what stopped " +
      "applying — " + why + ".");
    var colour = await isGreyed(driver, greyTarget);
    assert(colour && colour !== '',
      "#" + greyTarget + " has no computed colour at all, which means the " +
      "stylesheet carrying saml-unavailable did not load.");
  }
  // The SP key pair stays live. See the header.
  var keyOff = await isDisabled(driver, 'saml_sp_private_key');
  assert.strictEqual(keyOff, false,
    "the SP key pair must stay usable on SAML 1.1: it signs the SOAP " +
    "<samlp:Request> that resolves an artifact, and it is the KeyDescriptor " +
    "in the SP metadata this page builds.");
  var keyGreyed = await hasClass(driver, 'saml_signing_section',
                                 'saml-unavailable');
  assert.strictEqual(keyGreyed, false,
    "the SP Signing Key Pair section must not be greyed on SAML 1.1 — it is " +
    "still used.");
  // And the section is still on the page, even though the checkbox above it is
  // clear: onSignChange() would otherwise hide it, and a key pair you cannot
  // see is a key pair you cannot paste in.
  var visible = await driver.executeScript(
    "var e = document.getElementById('saml_signing_section');" +
    "return e ? window.getComputedStyle(e).display !== 'none' : null;");
  assert.strictEqual(visible, true,
    "the SP Signing Key Pair section must stay VISIBLE on SAML 1.1: the " +
    "checkbox above it is off because there is no request to sign, and the " +
    "pane is still needed for the artifact back-channel.");
  // The encryption sub-section, in contrast, must be closed: there is nothing
  // to encrypt, and leaving it open over a checkbox that cannot be ticked is
  // the state that reads as a broken page.
  var encOpen = await driver.executeScript(
    "var e = document.getElementById('saml_encryption_section');" +
    "return e ? window.getComputedStyle(e).display !== 'none' : null;");
  assert.strictEqual(encOpen, false,
    "the AuthnRequest Encryption section must be closed on SAML 1.1.");
  log.debug("Leaving assertControlsOffForSaml11().");
}

async function assertControlsOnForSaml20(driver) {
  log.debug("Entering assertControlsOnForSaml20().");
  for (var i = 0; i < OFF_ON_11.length; i++) {
    var id = OFF_ON_11[i][0];
    var container = OFF_ON_11[i][1];
    var off = await isDisabled(driver, id);
    assert.strictEqual(off, false, "#" + id + " must come back when SAML 2.0 " +
      "is selected again. A one-way transition passes every test that only " +
      "ever selects 1.1.");
    var grey = await hasClass(driver, container || id, 'saml-unavailable');
    assert.strictEqual(grey, false, "#" + (container || id) +
      " must lose the " +
      "saml-unavailable class when SAML 2.0 is selected again.");
  }
  log.debug("Leaving assertControlsOnForSaml20().");
}

// The version notice. It is the one line in the greyed area that has to stay
// readable, so it is checked for CONTENT — a reader who has just lost five
// controls is owed the reason.
async function assertVersionNoticeExplains(driver) {
  log.debug("Entering assertVersionNoticeExplains().");
  var shown = await driver.executeScript(
    "var e = document.getElementById('saml_version_warning');" +
    "return e ? window.getComputedStyle(e).display !== 'none' : null;");
  assert.strictEqual(shown, true,
    "the Protocol Version notice must be shown on SAML 1.1.");
  var text = await textOf(driver, 'saml_version_warning');
  log.info("Version notice: " + text);
  assert(text.indexOf('AuthnRequest') >= 0 && text.indexOf('shibboleth') >= 0,
    "the notice must say what SAML 1.1 sends INSTEAD of an AuthnRequest — " +
    "Shibboleth's request profile — rather than only that something is " +
    "unavailable. It says: " + text);
  assert(text.indexOf('Single Logout') >= 0,
    "the notice must say that SAML 1.1 has no Single Logout, since that is " +
    "the control whose absence is least self-explanatory. It says: " + text);
  log.debug("Leaving assertVersionNoticeExplains().");
}

// The request preview, per binding. This is the whole of what "SAML 1.1 has no
// request message" looks like from outside the page.
//
// The parameters are read back out of the preview rather than matched as
// substrings, and that is not fastidiousness: a URL percent-encodes its values,
// so `indexOf(acsUrl)` is false for a preview that carries exactly the right
// `shire`. A check written that way passes only while every value happens to be
// free of reserved characters, which no real ACS URL is.
function previewParams(text) {
  log.debug("Entering previewParams().");
  var out = {};
  var body = text;
  var q = text.indexOf('?');
  if (text.indexOf('POST ') === 0) {
    // The form shape: a blank line, then `name=value` per line, UNENCODED —
    // they are shown as they will be put in the form fields.
    var lines = text.split('\n');
    var started = false;
    for (var i = 0; i < lines.length; i++) {
      if (!started) {
        if (lines[i] === '') started = true;
        continue;
      }
      var eq = lines[i].indexOf('=');
      if (eq > 0) out[lines[i].substring(0, eq)] = lines[i].substring(eq + 1);
    }
    log.debug("Leaving previewParams(). A form.");
    return out;
  }
  if (q >= 0) body = text.substring(q + 1);
  var pairs = body.split('&');
  for (var j = 0; j < pairs.length; j++) {
    var e = pairs[j].indexOf('=');
    if (e > 0) {
      out[decodeURIComponent(pairs[j].substring(0, e))] =
          decodeURIComponent(pairs[j].substring(e + 1));
    }
  }
  log.debug("Leaving previewParams(). A query string.");
  return out;
}

async function assertRequestPreview(driver, binding, its, acs, sp) {
  log.debug("Entering assertRequestPreview(). binding=" + binding);
  await selectValue(driver, 'saml_binding', binding);
  var wantProfile = binding === 'artifact' ? 'artifact' : 'post';
  await driver.wait(async function () {
    var v = await valueOf(driver, 'saml_authn_request');
    return previewParams(v).profile === wantProfile;
  }, waitTime, "the request preview was not rebuilt for binding=" + binding +
     ". It should ask for the " + wantProfile + " browser profile: nothing " +
     "in SAML 1.1 lets a relying party choose between them, so the page has " +
     "to send the non-standard profile parameter or the identity provider's " +
     "own default decides.");
  var text = await valueOf(driver, 'saml_authn_request');
  var params = previewParams(text);
  log.info("Preview (" + binding + "):\n" + text);

  assert(text.indexOf('<samlp:AuthnRequest') < 0,
    "SAML 1.1 has no <samlp:AuthnRequest> and the page built one:\n" + text);
  assert.strictEqual(params.shire, acs,
    "shire must be the ACS URL — it is the only way a SAML 1.1 relying party " +
    "can say where the assertion goes. want=" + acs + " got=" + params.shire);
  assert.strictEqual(params.providerId, sp,
    "providerId must be the SP entityID — the only way a SAML 1.1 relying " +
    "party names itself, and what becomes the assertion's audience " +
    "restriction. want=" + sp + " got=" + params.providerId);
  assert(/^[0-9]+$/.test(params.time || ''),
    "Shibboleth's time parameter must be present and numeric (seconds since " +
    "the epoch); it is: " + params.time);
  assert(params.TARGET,
    "TARGET must be present — it is SAML 1.1's relay state, the only value " +
    "the browser profiles round-trip, and the artifact flow has nowhere else " +
    "to carry the API's context handle:\n" + text);

  if (binding === 'post') {
    assert(text.indexOf('POST ' + its) === 0,
      "with the POST binding the parameters travel in a form body, so the " +
      "preview shows the endpoint and the fields rather than a URL:\n" + text);
    assert(text.indexOf('application/x-www-form-urlencoded') >= 0,
      "the POST preview should name the content type the form will use:\n" +
          text);
  } else {
    assert(text.indexOf(its + '?') === 0,
      "with the " + binding + " binding the request is a URL at the " +
      "inter-site transfer service:\n" + text);
  }
  log.debug("Leaving assertRequestPreview().");
}

// Call IdP must refuse, by name, rather than navigating — and the Operations
// History row must say why. A refusal that only wrote a status line would leave
// the log claiming nothing was ever attempted.
async function assertCallRefusedWithoutShire(driver) {
  log.debug("Entering assertCallRefusedWithoutShire().");
  var before = await driver.getCurrentUrl();
  await setInput(driver, 'saml_acs_url', '');
  await click(driver, btn('callIdp'));
  await driver.wait(async function () {
    var v = await valueOf(driver, 'saml_call_status');
    return v.indexOf('shire') >= 0;
  }, waitTime,
     "Call IdP should refuse when there is no ACS URL and say that shire is " +
     "the only way a SAML 1.1 relying party can name where the assertion " +
     "goes. With no request message there is no other place to put it, and " +
     "an identity provider that has to guess sends the assertion to its own " +
     "mock relying party — which looks exactly like this page never being " +
     "answered.");
  var after = await driver.getCurrentUrl();
  assert.strictEqual(after, before,
    "Call IdP must not navigate when it has refused.");
  log.debug("Leaving assertCallRefusedWithoutShire().");
}

async function assertLogoutRefused(driver) {
  log.debug("Entering assertLogoutRefused().");
  // The button is disabled, so it is called through the page's own global —
  // which is the guard BEHIND the disabled attribute and the thing that has to
  // hold if a handler ever re-enables the control.
  await driver.executeScript("window.saml_request.singleLogout();");
  await driver.wait(async function () {
    var v = await valueOf(driver, 'saml_call_status');
    return v.indexOf('no Single Logout') >= 0;
  }, waitTime,
     "singleLogout() must refuse on SAML 1.1 saying the PROTOCOL has none, " +
     "rather than reporting a missing endpoint or an unimplemented feature — " +
     "the two read completely differently to somebody deciding whether to " +
     "configure one.");
  var history = await textOf(driver, 'saml_operation_history');
  assert(history.indexOf('Single Logout') >= 0,
    "the refused Single Logout should be recorded in the Operations " +
    "History:\n" + history);
  log.debug("Leaving assertLogoutRefused().");
}

// The SP metadata this page builds. Read out of the page rather than off a
// downloaded file: the download goes through a browser save dialogue and what
// is under test is the DOCUMENT.
async function assertSpMetadataIsSaml11(driver) {
  log.debug("Entering assertSpMetadataIsSaml11().");
  var xml = await driver.executeScript(
    "return window.saml_request.buildSpMetadata ? " +
    "window.saml_request.buildSpMetadata() : null;");
  assert(xml, "saml_request must export buildSpMetadata() so the document " +
         "can be asserted without going through a browser save dialogue.");
  log.info("SP metadata (SAML 1.1):\n" + xml);
  assert(xml.indexOf(PROTOCOL_11) >= 0,
    "a SAML 1.1 SP descriptor must declare protocolSupportEnumeration=\"" +
    PROTOCOL_11 + "\":\n" + xml);
  assert(xml.indexOf(PROTOCOL_20) < 0,
    "it must not also claim the SAML 2.0 protocol:\n" + xml);
  assert(xml.indexOf(PROFILE_POST) >= 0 && xml.indexOf(PROFILE_ARTIFACT) >= 0,
    "the assertion consumer endpoints must be bound with the two SAML 1.1 " +
    "PROFILE URIs. In a 1.1 descriptor the Binding attribute carries a " +
    "profile identifier rather than a binding one — the 1.1 profiles bundle " +
    "their binding into the profile, which is what Shibboleth's own metadata " +
    "does. A document advertising the 2.0 binding URIs here describes " +
    "endpoints no SAML 1.1 identity provider will use, and looks perfectly " +
    "fine:\n" + xml);
  assert(xml.indexOf('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') < 0,
    "a SAML 1.1 descriptor must not advertise the SAML 2.0 POST binding:\n" +
        xml);
  assert(xml.indexOf('SingleLogoutService') < 0,
    "SAML 1.1 has no Single Logout, so its SP metadata must publish no " +
    "SingleLogoutService — declaring one invites a LogoutRequest this " +
    "service provider cannot answer:\n" + xml);
  assert(xml.indexOf('AuthnRequestsSigned') < 0,
    "AuthnRequestsSigned is a claim about a message SAML 1.1 does not have, " +
    "and an identity provider reads it and acts on it:\n" + xml);

  // And the 2.0 document is unchanged, which is the half that says this did not
  // become a regression for the version that already worked.
  await chooseVersion(driver, '2.0');
  var xml20 = await driver.executeScript(
    "return window.saml_request.buildSpMetadata();");
  assert(xml20.indexOf(PROTOCOL_20) >= 0 &&
         xml20.indexOf('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') >= 0,
    "the SAML 2.0 SP metadata must still declare the 2.0 protocol and the " +
    "2.0 binding URIs:\n" + xml20);
  assert(xml20.indexOf('AuthnRequestsSigned') >= 0,
    "the SAML 2.0 SP metadata must still declare AuthnRequestsSigned:\n" +
        xml20);
  assert(xml20.indexOf(PROFILE_POST) < 0,
    "the SAML 2.0 SP metadata must not carry SAML 1.1 profile URIs:\n" + xml20);
  log.debug("Leaving assertSpMetadataIsSaml11().");
}

async function optionActivities(driver) {
  log.debug("Entering optionActivities().");
  var its = 'http://localhost:8081/saml11/sso';
  var acs = 'http://localhost:4000/samlacs';
  var sp = 'http://localhost:3000/saml/sp';

  await driver.get(baseUrl + "/saml_request.html");
  await waitForBundle(driver);
  // A clean slate: this page persists every field, and a previous job's stored
  // state would otherwise decide half of what is asserted here.
  await driver.executeScript("window.localStorage.clear();");
  await driver.navigate().refresh();
  await waitForBundle(driver);

  // Everything a SAML 1.1 flow needs, typed rather than loaded — this test has
  // no identity provider to fetch metadata from, which is the point.
  await setInput(driver, 'saml_sso_redirect', its);
  await setInput(driver, 'saml_sso_post', its);
  await setInput(driver, 'saml_sso_artifact', its);
  await setInput(driver, 'saml_acs_url', acs);
  await setInput(driver, 'saml_sp_entity_id', sp);

  log.info("Select SAML 1.1.");
  await chooseVersion(driver, '1.1');
  await assertControlsOffForSaml11(driver);
  await assertVersionNoticeExplains(driver);

  for (var i = 0; i < ['redirect', 'post', 'artifact'].length; i++) {
    var binding = ['redirect', 'post', 'artifact'][i];
    await assertRequestPreview(driver, binding, its, acs, sp);
  }

  await assertLogoutRefused(driver);
  await assertCallRefusedWithoutShire(driver);
  await setInput(driver, 'saml_acs_url', acs);

  await assertSpMetadataIsSaml11(driver);

  // assertSpMetadataIsSaml11() left the page on 2.0; assert the way back.
  await assertControlsOnForSaml20(driver);
  log.info("SAML 1.1 option availability verified.");
  log.debug("Leaving optionActivities().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  // Date.now() alone is NOT unique: run-report.js runs jobs in a pool, and two
  // starting in the same millisecond would share a profile — one Chrome then
  // refuses to start on the other's.
  options.addArguments("--user-data-dir=/tmp/saml11-options-chrome-" +
                       Date.now() + "-" + process.pid);
  // THE STACK'S CERTIFICATE, AS AN EXACT KEY PIN. The client and the api serve
  // https (common/tls_listener.js), on a self-signed pair generated per run, so
  // without this Chrome stops on a certificate interstitial and every
  // assertion below reports a missing element on a page titled "Privacy
  // error". See browser_flags.js.
  browserFlags.addStsTrustFlags(options);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    log.info("Starting Test run.");
    await driver.manage().deleteAllCookies();
    await optionActivities(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
    } catch (e2) {
      /* ignore */
    }
    testFailed = true;
  } finally {
    await driver.quit();
  }
  if (testFailed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('saml11_options')
  .description("Assert which SP/Request settings apply to SAML 1.1 and which " +
               "are switched off (no IdP required).")
  .addOption(new Option("-u, --url <url>",
      "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser",
      "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl =
        options.url; }
    if (!!options.browser) { log.info("Using browser. " +
        "headless = false."); headless = false; }
  });
program.parse(process.argv).opts();

test();
