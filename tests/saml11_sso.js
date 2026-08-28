const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const path = require("path");
const { Command, Option } = require('commander');
// The SP key pair is generated per run and passed in through the environment;
// it is deliberately not stored in this repository. See common/sp_keypair.js.
const { readSpKeyPair } = require("../common/sp_keypair.js");
const browserFlags = require("./browser_flags.js");
const registry = require("./sts_applications.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'saml11_sso',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// ===========================================================================
// THE DEBUGGER'S SAML **1.1** SERVICE PROVIDER, END TO END, THROUGH THE PAGES.
//
// `saml_sso.js`'s sibling, and deliberately its mirror image: the same
// three-binding matrix, the same metadata load, the same key pair, the same
// sign-in screen, the same response page. Everything that differs below is
// marked `1.1:` and every one of those is a place SAML 1.1 is a DIFFERENT
// PROTOCOL rather than an older spelling of this one.
//
// **It is not `sts_saml11.js`, which used to have this name.** That file drives
// the mock STS directly over HTTP with a relying party it writes itself, and it
// is almost entirely negatives — the one-shot artifact, an `InResponseTo` on a
// profile with no request, a signature reference through the real
// `AssertionID`. This one proves the DEBUGGER builds a request that identity
// provider accepts and renders what comes back, which that file cannot say
// anything about. Neither replaces the other and both run.
//
// ---------------------------------------------------------------------------
// THE SIX THINGS THIS FILE ASSERTS THAT `saml_sso.js` CANNOT
//
// 1. **THE VERSION COMES OFF THE METADATA.** A SAML 1.1 descriptor declares
//    `protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"`, and
//    loading one moves the Protocol Version selector and says so on the status
//    line. Left on 2.0 the page would build an `<AuthnRequest>` and post it at
//    an inter-site transfer service, and the refusal would read as an identity
//    provider problem.
//
// 2. **THE REQUEST IS NOT A DOCUMENT.** What is sent is Shibboleth's request
//    profile — `TARGET`, `shire`, `providerId`, `time` — so the Generated
//    request box holds a URL or a form, never XML, and the test reads it for
//    those parameter names by hand. A page that quietly kept building an
//    AuthnRequest would still round-trip against a permissive identity
//    provider; this is what notices.
//
// 3. **FOUR SETTINGS ARE SWITCHED OFF, not merely greyed.** The username hint,
//    request signing, request encryption and Single Logout have no meaning in
//    SAML 1.1, and each is asserted DISABLED — the attribute, not the colour.
//    A block that only looks dead still submits on a Return keypress, which is
//    the failure this half exists to prevent. (`saml11_options.js` covers the
//    same ground without an identity provider and in more detail; it is here
//    too because a control can be disabled on load and re-enabled by a later
//    handler, and only a real round trip runs those handlers.)
//
// 4. **THE STATUS CODE IS A QName.** SAML 1.1's is `samlp:Success`, resolved
//    against the document's namespace declarations; SAML 2.0's is a URI ending
//    `:status:Success`. A reader written for one sees the other as a failure,
//    so a working sign-in renders red and its Operations History row closes as
//    a FAILURE. The Details tab and the history row are both asserted.
//
// 5. **THE CONFIRMATION METHOD IS THE PROFILE.** saml-profile-1.1 section
//    4.1.1.4 requires `cm:artifact` for Browser/Artifact and 4.2.1.4 requires
//    `cm:bearer` for Browser/POST. A relying party that does not check works
//    perfectly with either — which is exactly why this is asserted PER BINDING
//    rather than once. `DoNotCacheCondition` is checked the same way: the
//    Browser/POST profile's single-use policy, and absent from an artifact
//    assertion because that one never travelled through the browser.
//
// 6. **THE ASSERTION'S SIGNATURE VERIFIES THROUGH `AssertionID`.** SAML 1.1
//    spells its ids `AssertionID` / `ResponseID`, which is on none of the lists
//    a generic verifier searches — told nothing, one INVENTS an `Id` and points
//    the reference at that. `common/xmldsig.js`'s findById() was taught all
//    three; clicking Validate Signature here is what proves it, because a
//    verifier that cannot resolve the reference reports "referenced element not
//    found", which reads like a stripped element.
//
// ---------------------------------------------------------------------------
// WHAT IT NEEDS, AND WHY THERE IS NO KEYCLOAK HALF
//
// The mock STS and nothing else. **Keycloak has not spoken SAML 1.1 for years**
// — it dropped the profile — so unlike `saml_sso.js` and `wsfed_sso.js` there
// is no second identity provider to pair this with and there is not going to
// be one. Nothing has to be provisioned: that service accepts any relying party
// identifier, creates the application entry from the first request, and mints a
// metadata document for anything asked for.
//
//   SAML11_METADATA_URL   the mock's per-relying-party SAML 1.1 descriptor.
//                         Its absence is the skip.
//   SAML_SP_ENTITY_ID     this service provider, sent as `providerId`.
//   SAML_USER             who to sign in as.
//   SAML_BINDING          redirect | post | artifact.
//
// The HTTP Artifact profile additionally needs the API: resolving an artifact
// is a SOAP call over the back channel, which a browser cannot make. The runner
// skips it on a backend-less target rather than failing.
// ===========================================================================

// 1.1: the sign-in screen is `authn.js`'s, the same one the SAML 2.0, WS-Fed
// and OAuth flows reach — this profile has no screen of its own. Written as a
// list for the reason saml_sso.js gives: if a third identity provider ever
// turns up with the same fields and a third button, the failure names the
// button rather than the environment.
var LOGIN_BUTTONS = ["kc-login", "saml11-login", "saml2-login"];

// The two confirmation methods, and which profile each belongs to.
var CM_BEARER = "urn:oasis:names:tc:SAML:1.0:cm:bearer";
var CM_ARTIFACT = "urn:oasis:names:tc:SAML:1.0:cm:artifact";

async function elementExists(driver, id) {
  log.debug("Entering elementExists().");
  var found = await driver.findElements(By.id(id));
  log.debug("Leaving elementExists().");
  return found.length > 0;
}

async function loginAtIdp(driver, user, timeout) {
  log.debug("Entering loginAtIdp().");
  var username = By.id("username");
  await driver.wait(until.elementLocated(username), timeout,
    "the identity provider never showed its sign-in screen (no #username " +
        "field).");
  await driver.wait(until.elementIsVisible(driver.findElement(username)),
                    timeout);
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  await driver.findElement(By.id("password")).clear();
  await driver.findElement(By.id("password")).sendKeys(user);

  var clicked = null;
  for (var i = 0; i < LOGIN_BUTTONS.length; i++) {
    if (await elementExists(driver, LOGIN_BUTTONS[i])) {
      clicked = LOGIN_BUTTONS[i];
      await driver.findElement(By.id(clicked)).click();
      break;
    }
  }
  assert(clicked, "the sign-in screen carries none of the submit " +
      "buttons this test knows (" + LOGIN_BUTTONS.join(", ") + "). The " +
      "username field was there, so this is a new identity provider rather " +
      "than a broken page.");
  log.info("Signed in at the mock STS sign-in screen (" + clicked + ").");
  log.debug("Leaving loginAtIdp().");
}

// Poll a field's value until the predicate passes (or timeout).
//
// The timeout message carries the LAST value read, the way tests/wait_for.js's
// helper does. Without it a field that is filled in with something the
// predicate does not recognise — an error status, say — reads exactly like a
// field nothing ever wrote to, and the 15 seconds name neither. That cost a
// diagnosis: see assertSignatureValidates().
async function waitForValue(driver, locator, predicate, message, timeout) {
  log.debug("Entering waitForValue().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var last = null;
  try {
    await driver.wait(async function () {
      try {
        last = await driver.findElement(locator).getAttribute("value");
        return predicate(last || "");
      } catch (e) {
        return false;
      }
    }, timeout || waitTime);
  } catch (e) {
    e.message = message + " (last value: " +
        (last === null ? "<never read>" : JSON.stringify(last)) + ") — " +
        e.message;
    log.debug("Leaving waitForValue(). Timed out.");
    throw e;
  }
  log.debug("Leaving waitForValue().");
  return last;
}

async function clickByValue(driver, value) {
  log.debug("Entering clickByValue().");
  var locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  var target = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(target), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", target);
  await target.click();
  log.debug("Leaving clickByValue().");
}

// The same click, dispatched by the PAGE rather than by a synthetic mouse.
//
// For a button low on a tall page in the headless viewport (780x437 here), the
// native Selenium click intermittently lands off-target and fires nothing at
// all — no intercept error, no console error, no event: chromedriver scrolls,
// computes a point from the new layout, and dispatches it against a compositor
// frame that has not caught up, so it hit-tests whatever used to be there. It
// takes CPU contention to show, which is why it appears in the pool and never
// alone, and once a session is in that state every later click misses too. The
// Decrypt button on this same page hit it first and is fixed the same way —
// see the note in saml_encrypted_sso.js.
//
// What is NOT given up is the reason to click at all: a control covered by
// something drawn over it is a control nobody can use, and only a hit test says
// so. So the topmost element at the button's own centre is checked here, which
// is what a native click would have failed on, and then the real
// `onclick="…"` binding is invoked through the element itself.
async function clickByValueInPage(driver, value) {
  log.debug("Entering clickByValueInPage(). " + value);
  var locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(locator)),
                    waitTime);
  // Runs IN THE BROWSER, so it has no bunyan and no `log` — see the repo-root
  // CLAUDE.md. What is logged is what it returns.
  var outcome = await driver.executeScript(
    "var want = arguments[0], b = null, all = document.querySelectorAll(" +
    "'input');" +
    "for (var i = 0; i < all.length; i++) {" +
    "  if (all[i].value === want) { b = all[i]; break; }" +
    "}" +
    "if (!b) { return { ok: false, why: 'no input with that value' }; }" +
    "b.scrollIntoView({ block: 'center' });" +
    "var r = b.getBoundingClientRect();" +
    "var top = document.elementFromPoint(r.left + r.width / 2," +
    "                                    r.top + r.height / 2);" +
    "if (top !== b && !b.contains(top)) {" +
    "  return { ok: false, why: 'covered by ' + (top ? (top.tagName + '#' +" +
    "      top.id + '.' + top.className) : 'nothing (off-screen)') };" +
    "}" +
    "b.click();" +
    "return { ok: true };", value);
  assert(outcome && outcome.ok,
    "could not click the '" + value + "' button: " +
        ((outcome && outcome.why) || "no result from the page"));
  log.debug("Leaving clickByValueInPage().");
}

// Whether a control carries the `disabled` attribute. Read as a PROPERTY off
// the element rather than as a computed colour: the colour is what a reader
// sees and this is what a Return keypress obeys, and only one of the two stops
// a request being built.
async function isDisabled(driver, id) {
  log.debug("Entering isDisabled().");
  var v = await driver.executeScript(
    "var e = document.getElementById(arguments[0]); " +
    "return e ? !!e.disabled : null;", id);
  log.debug("Leaving isDisabled().");
  return v;
}

async function textOf(driver, id) {
  log.debug("Entering textOf().");
  var v = await driver.executeScript(
    "var e = document.getElementById(arguments[0]); " +
    "return e ? (e.textContent || '') : '';", id);
  log.debug("Leaving textOf().");
  return v || "";
}

async function loadIdpMetadata(driver, metadataUrl, metadataFile) {
  log.debug("Entering loadIdpMetadata().");
  if (metadataFile) {
    log.info("Upload the SAML 1.1 IdP metadata from a local file: " +
             metadataFile);
    var fileInput = By.id("saml_metadata_file");
    await driver.wait(until.elementLocated(fileInput), waitTime);
    await driver.findElement(fileInput).sendKeys(path.resolve(metadataFile));
  } else {
    log.info("Enter the SAML 1.1 metadata URL and load it.");
    var mdField = By.id("saml_metadata_url");
    await driver.wait(until.elementLocated(mdField), waitTime);
    await driver.findElement(mdField).clear();
    await driver.findElement(mdField).sendKeys(metadataUrl);
    await clickByValue(driver, "Load Metadata");
  }
  await waitForValue(driver, By.id("saml_metadata_status"),
    function (v) { return v.indexOf("Loaded and parsed") >= 0; },
    "The SAML 1.1 metadata was not loaded/parsed.");
  log.debug("Leaving loadIdpMetadata().");
}

// 1.1: THE DESCRIPTOR DECIDES THE VERSION. Asserted rather than assumed,
// because everything after it depends on the page having noticed — and because
// a page left on 2.0 in front of this document builds an <AuthnRequest>, posts
// it at an inter-site transfer service, and reports the refusal as though the
// identity provider were at fault.
async function assertVersionCameFromMetadata(driver) {
  log.debug("Entering assertVersionCameFromMetadata().");
  var status =
      await driver.findElement(By.id("saml_metadata_status"))
        .getAttribute("value");
  assert(status.indexOf("1.1") >= 0,
    "loading a SAML 1.1 descriptor should say on the status line that it " +
    "moved the Protocol Version selector; it said: " + status);
  var version =
      await driver.findElement(By.id("saml_version")).getAttribute("value");
  assert.strictEqual(version, "1.1",
    "the Protocol Version selector should have been set to 1.1 by the " +
    "metadata load (protocolSupportEnumeration says " +
    "urn:oasis:names:tc:SAML:1.1:protocol), and is " + version + ".");
  log.debug("Leaving assertVersionCameFromMetadata().");
}

// 1.1: A SAML 1.1 identity provider has ONE endpoint — the inter-site transfer
// service — which its metadata names once per profile it answers. All three SSO
// fields therefore hold the SAME address, and the artifact resolution field
// holds the SAML responder. Reading the document as though the fields were
// exclusive populates none of them, and the page then reports "no IdP endpoint
// for the selected binding" about a document that named it three times.
async function assertEndpointsFromMetadata(driver) {
  log.debug("Entering assertEndpointsFromMetadata().");
  var ids = ["saml_sso_redirect", "saml_sso_post", "saml_sso_artifact"];
  var seen = [];
  for (var i = 0; i < ids.length; i++) {
    seen.push(await driver.findElement(By.id(ids[i])).getAttribute("value"));
  }
  assert(seen[0], "the inter-site transfer service address was not read out " +
         "of the SAML 1.1 metadata (saml_sso_redirect is empty).");
  assert(seen[0].indexOf("/saml11/sso") >= 0,
    "the SSO endpoint should be the SAML 1.1 inter-site transfer service, " +
    "and is: " + seen[0]);
  assert.strictEqual(seen[1], seen[0],
    "SAML 1.1 has one SSO endpoint named once per profile, so all three " +
    "fields should hold it. redirect=" + seen[0] + " post=" + seen[1]);
  assert.strictEqual(seen[2], seen[0],
    "SAML 1.1 has one SSO endpoint named once per profile, so all three " +
    "fields should hold it. redirect=" + seen[0] + " artifact=" + seen[2]);
  var ars = await driver.findElement(By.id("saml_ars")).getAttribute("value");
  assert(ars.indexOf("/saml11/responder") >= 0,
    "the artifact resolution field should hold the SAML 1.1 SAML responder " +
    "(ArtifactResolutionService, SOAP binding), and holds: " + ars);
  // No Single Logout exists in this protocol, so the descriptor publishes none
  // and the three fields are cleared rather than left holding a previous
  // document's addresses.
  var sloEl = await driver.findElement(By.id("saml_slo_redirect"));
  var slo = await sloEl.getAttribute("value");
  assert.strictEqual(slo, "",
    "SAML 1.1 has no Single Logout, so loading its metadata must clear the " +
    "SLO endpoint fields; saml_slo_redirect holds: " + slo);
  log.debug("Leaving assertEndpointsFromMetadata(). its=" + seen[0]);
}

// 1.1: the four settings that have no meaning in this protocol. Each is
// asserted DISABLED — the attribute a keypress obeys — and the Logout button
// with them, because SAML 1.1 has no Single Logout at all.
async function assertUnavailableSettingsAreOff(driver) {
  log.debug("Entering assertUnavailableSettingsAreOff().");
  var offs = [
    ["saml_username_hint", "the username hint goes in <saml:Subject> on an " +
        "AuthnRequest, and SAML 1.1 has no request document"],
    ["saml_sign_request", "there is nothing to sign: Shibboleth's request " +
        "profile is unsigned query parameters"],
    ["saml_encrypt_request", "there is nothing to encrypt either"],
    ["saml_logout_btn", "SAML 1.1 has no Single Logout — it is absent from " +
        "the protocol, not unimplemented here"],
    ["saml_slo_redirect", "nothing publishes a logout endpoint in SAML 1.1"]
  ];
  for (var i = 0; i < offs.length; i++) {
    var off = await isDisabled(driver, offs[i][0]);
    assert.strictEqual(off, true, "#" + offs[i][0] + " should be disabled " +
      "when SAML 1.1 is selected — " + offs[i][1] + ". disabled=" + off);
  }
  // And the SP key pair is NOT disabled, which is the one that looks
  // inconsistent and is deliberate: it still signs the SOAP request that
  // resolves an artifact, and it is still the KeyDescriptor in the SP metadata
  // this page downloads. Greying it would take away two things that work.
  var keyOff = await isDisabled(driver, "saml_sp_private_key");
  assert.strictEqual(keyOff, false,
    "the SP key pair must stay usable in SAML 1.1: it signs the artifact " +
    "back-channel's SOAP request and is the SP metadata's KeyDescriptor.");
  log.debug("Leaving assertUnavailableSettingsAreOff().");
}

// The parameters read back out of the preview, decoded. Matched as a MAP
// rather than as substrings, and that is not fastidiousness: a URL
// percent-encodes its values, so `indexOf(acsUrl)` is false for a request
// carrying exactly the right `shire`. A check written that way passes only
// while every value happens to be free of reserved characters, which no real
// assertion consumer URL is.
function previewParams(text) {
  log.debug("Entering previewParams().");
  var out = {};
  if (text.indexOf('POST ') === 0) {
    // The form shape: a blank line, then `name=value` per line, unencoded —
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
  var q = text.indexOf('?');
  var body = q >= 0 ? text.substring(q + 1) : text;
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

// 1.1: THE REQUEST IS NOT A DOCUMENT. Whatever the binding, what goes out is
// Shibboleth's four parameters plus the two non-spec ones — so the Generated
// request box must hold them and must NOT hold an AuthnRequest.
async function assertRequestIsShibbolethShaped(driver, binding, spEntityId,
                                               acsUrl) {
  log.debug("Entering assertRequestIsShibbolethShaped(). binding=" + binding);
  var text =
      await driver.findElement(By.id("saml_authn_request")).getAttribute(
          "value");
  log.info("Generated SAML 1.1 request:\n" + (text || "").substring(0, 800));
  var params = previewParams(text);

  assert(text.indexOf('<samlp:AuthnRequest') < 0,
    "SAML 1.1 has no <samlp:AuthnRequest>; the page built one anyway:\n" +
        text.substring(0, 800));
  assert.strictEqual(params.shire, acsUrl,
    "the request must carry Shibboleth's shire parameter — the only way a " +
    "SAML 1.1 relying party can say where the assertion goes. want=" +
    acsUrl + " got=" + params.shire);
  assert.strictEqual(params.providerId, spEntityId,
    "the request must carry providerId, which is the only way a SAML 1.1 " +
    "relying party names itself. want=" + spEntityId + " got=" +
    params.providerId);
  assert(params.TARGET,
    "the request must carry TARGET, which is SAML 1.1's relay state:\n" +
        text);
  assert(/^[0-9]+$/.test(params.time || ''),
    "the request must carry Shibboleth's time parameter, in seconds since " +
    "the epoch; it is: " + params.time);
  // The profile parameter is what chooses between the two browser profiles.
  // Nothing in SAML 1.1 lets a relying party ask, so it is non-spec and named
  // as such on the page — but it has to be SENT, or the identity provider's own
  // default decides and the binding under test is not the one exercised.
  var wantProfile = binding === "artifact" ? "artifact" : "post";
  assert.strictEqual(params.profile, wantProfile,
    "the request should ask for the " + wantProfile + " browser profile " +
    "(binding=" + binding + "), and asks for: " + params.profile);
  if (binding === "post") {
    assert(text.indexOf("POST ") === 0,
      "with the POST binding the request is a form, so the box should show " +
      "the endpoint and the fields rather than a URL:\n" + text);
  } else {
    assert(text.indexOf("/saml11/sso") >= 0,
      "with the " + binding + " binding the request is a URL at the " +
      "inter-site transfer service:\n" + text);
  }
  log.debug("Leaving assertRequestIsShibbolethShaped().");
}

// 1.1: the response page, which reads a completely different document from the
// one saml_sso.js gets. Every check here is a field spelled differently in this
// version, and each was a blank cell before the page learned to read it.
async function assertResponsePage(driver, binding, spEntityId, loginWait) {
  log.debug("Entering assertResponsePage(). binding=" + binding);
  await waitForValue(driver, By.id("saml_resp_xml"),
    function (v) { return v.indexOf("Response") >= 0; },
    "The SAML 1.1 Response XML was not displayed.", loginWait);
  var respXml =
      await driver.findElement(By.id("saml_resp_xml")).getAttribute("value");
  log.info("SAML 1.1 Response (first 2500 chars):\n" +
           (respXml || "").substring(0, 2500));

  // The document really is SAML 1.1 and not something the mock fell back to.
  assert(respXml.indexOf('MajorVersion="1"') >= 0 &&
         respXml.indexOf('MinorVersion="1"') >= 0,
    "the Response should carry MajorVersion=\"1\" MinorVersion=\"1\" — SAML " +
    "1.1 has no Version attribute:\n" + respXml.substring(0, 600));

  await waitForValue(driver, By.id("saml_assertion_xml"),
    function (v) { return v.indexOf("Assertion") >= 0 &&
              v.indexOf("no <") < 0; },
    "No <saml:Assertion> in the SAML 1.1 Response — see the logged response " +
        "above.", loginWait);
  var assertionXml =
      await driver.findElement(By.id("saml_assertion_xml"))
        .getAttribute("value");
  assert(assertionXml.indexOf("AssertionID=") >= 0,
    "a SAML 1.1 assertion's id attribute is AssertionID, and the assertion " +
    "carries none:\n" + assertionXml.substring(0, 600));

  // THE DETAILS TAB. Four rows, and every one of them is read from a
  // differently-named attribute in this version — the status most of all, which
  // is a QName here and a URI in 2.0.
  await driver.wait(async function () {
    var t = await textOf(driver, "saml_resp_details");
    return t.indexOf("SAML Version") >= 0;
  }, loginWait, "The response Details table was never built.");
  var details = await textOf(driver, "saml_resp_details");
  log.info("Response details:\n" + details);
  assert(details.indexOf("1.1") >= 0,
    "the Details tab should report SAML Version 1.1, read from " +
    "MajorVersion/MinorVersion:\n" + details);
  assert(details.indexOf("Success") >= 0,
    "the Details tab should report a Success status. SAML 1.1's status code " +
    "is the QName samlp:Success, NOT a URI ending :status:Success — a reader " +
    "written for 2.0 renders this as a failure:\n" + details);
  assert(details.indexOf("Recipient") >= 0,
    "a SAML 1.1 Response says where it was sent with Recipient (there is no " +
    "Destination attribute):\n" + details);

  // THE ATTRIBUTES TAB.
  await driver.wait(async function () {
    var t = await textOf(driver, "saml_attrs_table");
    return t.indexOf("NameID") >= 0;
  }, loginWait,
     "The Attributes table never showed a NameID row. In SAML 1.1 the " +
     "subject is <saml:NameIdentifier>, not <saml:NameID> — a reader that " +
     "knows only " +
     "is <saml:NameIdentifier>, not <saml:NameID> — a reader that knows only " +
     "2.0 finds nothing and renders the table without it.");
  var attrs = await textOf(driver, "saml_attrs_table");
  log.info("Attributes table:\n" + attrs);

  // 1.1: THE CONFIRMATION METHOD IS THE PROFILE, and this is the check that
  // needs the binding matrix. A relying party that does not look works
  // perfectly with either method, so nothing fails until it meets one that
  // does — and the refusal then reads as a signature problem.
  var wantCm = binding === "artifact" ? CM_ARTIFACT : CM_BEARER;
  var wrongCm = binding === "artifact" ? CM_BEARER : CM_ARTIFACT;
  assert(attrs.indexOf(wantCm) >= 0,
    "the " + binding + " binding uses the " +
    (binding === "artifact" ? "Browser/Artifact" : "Browser/POST") +
    " profile, which saml-profile-1.1 requires be confirmed as " + wantCm +
    ". The assertion says otherwise:\n" + attrs);
  assert(attrs.indexOf(wrongCm) < 0,
    "the assertion carries " + wrongCm + " on the " + binding + " binding, " +
    "which claims it travelled a way it did not:\n" + attrs);

  // The audience restriction, which in SAML 1.1 is
  // <saml:AudienceRestrictionCondition> — a different element name, so the
  // whole condition is invisible to a 2.0-only reader.
  assert(attrs.indexOf("AudienceRestrictionCondition") >= 0,
    "the assertion should carry a SAML 1.1 AudienceRestrictionCondition:\n" +
        attrs);
  assert(attrs.indexOf(spEntityId) >= 0,
    "the audience should be this service provider (" + spEntityId +
    "), which the identity provider took from the providerId parameter:\n" +
        attrs);

  // 1.1: the Browser/POST profile's single-use policy. Present on a POSTed
  // assertion (it travelled through the browser) and absent on an artifact one
  // (it did not), which is the other per-binding difference in the document.
  if (binding === "artifact") {
    assert(attrs.indexOf("DoNotCacheCondition") < 0,
      "an artifact-profile assertion never passes through the browser, so " +
      "the Browser/POST single-use policy should not be on it:\n" + attrs);
  } else {
    assert(attrs.indexOf("DoNotCacheCondition") >= 0,
      "a Browser/POST assertion travels through the browser, so section " +
      "4.2's single-use policy (<saml:DoNotCacheCondition/>) should be on " +
      "it:\n" + attrs);
  }

  // The attribute statement itself: the identity provider's claims about the
  // person, whose names in SAML 1.1 are AttributeName + AttributeNamespace.
  assert(attrs.indexOf("AuthenticationMethod") >= 0,
    "a SAML 1.1 AuthenticationStatement carries the method as an attribute, " +
    "and the table should show it:\n" + attrs);

  // Exercise the tab UI itself, after the assertions — which are made on the
  // table's textContent, readable while the tab is the hidden one. A pass that
  // hinged on the click taking effect is what made the 2.0 POST case flake.
  try {
    await driver.findElement(By.id("tab_attrs_btn")).click();
    await driver.findElement(By.id("tab_resp_details_btn")).click();
  } catch (e) {
    /* best-effort UI exercise */
  }
  log.debug("Leaving assertResponsePage().");
}

// 1.1: the enveloped signature on the assertion, verified in the browser. The
// reference is `#<AssertionID>`, a name a generic verifier does not search —
// told nothing it invents an `Id`, and the reference then resolves to nothing
// here, reported as "referenced element not found".
async function assertSignatureValidates(driver, loginWait) {
  log.debug("Entering assertSignatureValidates().");
  await clickByValueInPage(driver, "Validate Signature");
  // EVERY status validateAssertionSignature() can write, not just the two that
  // mean it got as far as verifying. It also reports "No assertion available
  // to validate." and "Validation error: …", and a predicate blind to those
  // turns each of them into a fifteen-second timeout naming neither the status
  // nor the field — which is a slower and much quieter way to say what the
  // assert below would have said outright.
  var status = await waitForValue(driver, By.id("saml_sig_status"),
    function (v) { return v.indexOf("VALID") >= 0 ||
                          v.indexOf("INVALID") >= 0 ||
                          v.indexOf("Cannot validate") >= 0 ||
                          v.indexOf("No assertion available") >= 0 ||
                          v.indexOf("Validation error") >= 0; },
    "Validate Signature never reported anything.", loginWait);
  var detail = await textOf(driver, "saml_sig_details");
  assert(status.indexOf("VALID") >= 0 && status.indexOf("INVALID") < 0,
    "the SAML 1.1 assertion's signature should verify. Its reference is " +
    "#<AssertionID>, which is not one of the id attribute names a generic " +
    "verifier searches. status=" + status + "\n" + detail);
  log.info("Assertion signature: " + status);
  log.debug("Leaving assertSignatureValidates().");
}

// The Operations History row this round trip closed. It is written on the
// request page before the browser is handed over and resolved on the response
// page from the SAML status — so a status code read wrongly shows up HERE as a
// red row over a sign-in that worked, which is the worst way to be wrong about
// a working flow.
async function assertHistoryClosedAsSuccess(driver, binding, loginWait) {
  log.debug("Entering assertHistoryClosedAsSuccess().");
  await driver.wait(async function () {
    var t = await textOf(driver, "saml_operation_history");
    return t.indexOf("Success") >= 0;
  }, loginWait,
     "The Operations History row for this call never closed as Success. " +
     "It is resolved from <samlp:Status>, whose Value in SAML 1.1 is the " +
     "QName samlp:Success rather than a URI ending :status:Success.");
  var history = await textOf(driver, "saml_operation_history");
  log.info("Operations History:\n" + history);
  assert(history.indexOf("1.1") >= 0,
    "the Operations History row should record the protocol version as 1.1:\n" +
        history);
  var wantBinding = binding === "post" ? "HTTP-POST"
    : binding === "artifact" ? "HTTP-Artifact" : "HTTP-Redirect";
  assert(history.indexOf(wantBinding) >= 0,
    "the Operations History row should record the binding as " + wantBinding +
        ":\n" + history);
  log.debug("Leaving assertHistoryClosedAsSuccess().");
}

async function saml11Activities(driver, metadataUrl, spEntityId, user, binding,
                                metadataFile) {
  log.debug("Entering saml11Activities().");
  // The mock renders in milliseconds, but a POST-binding hop plus a sign-in
  // screen plus (for artifact) a server-side SOAP round trip is several
  // navigations, and a generous timeout costs nothing when nothing is slow.
  var loginWait = Math.max(waitTime, 15000);

  log.info("Load the SAML Test Tools page (SAML 1.1, binding=" + binding +
           ").");
  await driver.get(baseUrl + "/saml_request.html");

  await loadIdpMetadata(driver, metadataUrl, metadataFile);
  await assertVersionCameFromMetadata(driver);
  await assertEndpointsFromMetadata(driver);
  await assertUnavailableSettingsAreOff(driver);

  // The relying party identifier, which is what `providerId` carries and what
  // becomes the assertion's audience.
  var spField = By.id("saml_sp_entity_id");
  await driver.findElement(spField).clear();
  await driver.findElement(spField).sendKeys(spEntityId);

  // This run's SP key pair. Nothing verifies it here — SAML 1.1 has no request
  // to sign and the mock checks no signature on the SOAP back-channel either —
  // and it is loaded anyway for the artifact binding, where it is what the API
  // signs the <samlp:Request> with. That half is about the DEBUGGER rather than
  // about the identity provider, which is the same argument saml_sso.js makes.
  log.info("Load this run's SP signing key pair.");
  var spPair = readSpKeyPair();
  await driver.executeScript(
    "document.getElementById('saml_sp_private_key').value = arguments[0];" +
    "document.getElementById('saml_sp_public_key').value = arguments[1];",
    spPair.privateKey, spPair.certificate
  );

  // ---------------------------------------------------------------------
  // THE RELYING PARTY, IN THE MOCK'S REGISTRY, BEFORE THE FLOW STARTS.
  //
  // It matters more here than it does in SAML 2.0 and for a reason particular
  // to this profile: SAML 1.1 HAS NO REQUEST MESSAGE. A flow begins when a
  // browser arrives carrying a TARGET, and the relying party cannot identify
  // itself in the protocol at all — what stands in for an entityID is
  // Shibboleth's `providerId`, a path segment, or a GUESS at the TARGET's
  // origin. So the registry entry is not a convenience: it is the only place
  // this relying party's audience and its assertion consumer service are
  // written down as facts rather than inferred per request.
  //
  // ONE APPLICATION ACROSS BOTH PROFILES. `samlEntityId` is the identifier
  // attribute of SAML 2.0 and SAML 1.1 alike — one attribute rather than two
  // that would disagree the first time an application was declared for both —
  // so this run and tests/saml_sso.js's run land on the same entry, each
  // declaring its own family. That is why `saml11` is declared here and
  // `saml2` is not: what this job is entitled to assert is what IT did.
  // ---------------------------------------------------------------------
  var acsUrl = await driver.findElement(By.id("saml_acs_url"))
      .getAttribute("value");
  log.info("Assertion consumer service (Shibboleth's shire): " + acsUrl);
  await registry.provision(registry.stsBaseFor(metadataUrl), {
    identifier: spEntityId,
    name: "SAML 1.1 test relying party",
    protocols: ["saml11"],
    fields: Object.assign({
      samlEntityId: [spEntityId]
    }, acsUrl ? { samlAssertionConsumerService: [acsUrl] } : {}),
    why: "the relying party providerId names and the assertion is audienced to"
  });

  log.info("Select binding: " + binding);
  await driver.executeScript(
    "var s=document.getElementById('saml_binding'); if(s){ s.value = " +
        "arguments[0]; s.dispatchEvent(new Event('change')); }",
    binding
  );
  var selected =
      await driver.findElement(By.id("saml_binding")).getAttribute("value");
  assert.strictEqual(selected, binding, "Binding '" + binding +
                     "' is not available in the selector.");

  // The request is rebuilt by the change handler; wait for it to name the
  // profile this binding asks for rather than reading whatever was there
  // before the selection.
  var wantProfile = binding === "artifact" ? "artifact" : "post";
  await waitForValue(driver, By.id("saml_authn_request"),
    function (v) { return v.indexOf("profile=" + wantProfile) >= 0; },
    "The Generated request was not rebuilt for the " + binding + " binding.",
    loginWait);
  // Re-read rather than reusing the value the registration above took: the
  // binding selection rebuilds the request, and `shire` has to be asserted
  // against what the page holds NOW.
  acsUrl = await driver.findElement(By.id('saml_acs_url'))
      .getAttribute('value');
  await assertRequestIsShibbolethShaped(driver, binding, spEntityId, acsUrl);

  log.info("Call IdP (SAML 1.1, " + binding + ").");
  await clickByValue(driver, "Call IdP");

  log.info("Log in at the mock STS.");
  await loginAtIdp(driver, user, loginWait);

  log.info("Wait for the SAML Response page.");
  await driver.wait(until.urlContains("saml_response.html"), loginWait);

  await assertResponsePage(driver, binding, spEntityId, loginWait);
  await assertSignatureValidates(driver, loginWait);
  await assertHistoryClosedAsSuccess(driver, binding, loginWait);

  log.info("SAML 1.1 SSO round-trip succeeded (" + binding + ").");
  log.debug("Leaving saml11Activities().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");

  // The mock STS serves https on a certificate it generated at startup (see
  // STS_HTTPS in local-tests.yml). This trusts THAT KEY and no other, and adds
  // nothing when the run has no pin — browser_flags.js's addStsTrustFlags()
  // makes the whole argument. This file builds its Chrome options by hand
  // rather than through addBrowserAccessFlags(), which is why the call is here
  // instead of arriving with the rest.
  browserFlags.addStsTrustFlags(options);

    const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    const metadataUrl = process.env.SAML11_METADATA_URL;
    const metadataFile = process.env.SAML11_METADATA_FILE;
    const spEntityId = process.env.SAML_SP_ENTITY_ID;
    const user = process.env.SAML_USER || "saml";
    const binding = (process.env.SAML_BINDING || "redirect").toLowerCase();
    assert(metadataUrl || metadataFile,
      "Set SAML11_METADATA_URL (URL load) or SAML11_METADATA_FILE (file " +
      "upload). It names the mock STS's per-relying-party SAML 1.1 " +
      "descriptor; nothing has to be provisioned first, because that service " +
      "mints one for any identifier asked for.");
    assert(spEntityId, "SAML_SP_ENTITY_ID environment variable is not set.");
    assert(["redirect", "post", "artifact"].indexOf(binding) >= 0,
           "SAML_BINDING must be redirect, post, or artifact.");
    log.info("metadata=" + (metadataUrl || metadataFile) + " sp=" +
             spEntityId + " binding=" + binding);

    await saml11Activities(driver, metadataUrl, spEntityId, user, binding,
                           metadataFile);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
      var src = await driver.getPageSource();
      log.error("Page source (first 8000 chars):\n" + (src || "").substring(0,
                8000));
      var blogs = await driver.manage().logs().get("browser");
      if (blogs && blogs.length) {
        log.error("Browser console:\n" +
                  blogs.map(function (e) { return e.level.name + ": " +
                  e.message; }).join("\n"));
      }
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
  .name('saml11_sso')
  .description("Run the SAML 1.1 browser-profile SSO test against the " +
               "debugger's SAML workflow.")
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
