// File: saml_response_decoder_page.js
//
// The SAML Response Decoder (saml_response_decoder.html) — decode, validate,
// decrypt, in BOTH protocol versions and on all three bindings.
//
// NO IDENTITY PROVIDER IS NEEDED and that is the point of the page: it reads a
// response somebody else produced. Every fixture below is built HERE, in node,
// by the same two modules the page uses — common/xmldsig.js for the
// cryptography and client/src/saml_message.js for the wire format — so a
// fixture is a real signed, encrypted response rather than a recorded string
// that can rot.
//
// WHAT THIS TEST IS ACTUALLY FOR, because most of it would pass with both
// interesting assertions deleted:
//
//   1. SAML 1.1 IS NOT SAML 2.0 WITH OLDER NAMES, and the status code is the
//      difference that costs the most. 2.0 writes it as a URI ending
//      `:status:Success`; 1.1 writes it as a **QName** — `samlp:Success` —
//      resolved against the document's own namespace declarations. A reader
//      that checks for the URI suffix reads every 1.1 SUCCESS AS A FAILURE,
//      which is exactly what the SAML Response page did until 2026-08-25. So
//      the 1.1 case here asserts the verdict, not merely that a table
//      rendered: a page of correctly-populated cells over a red status is the
//      failure this catches.
//
//   2. THE TWO SIGNATURES ARE DIFFERENT CLAIMS. A response may be signed on
//      the <samlp:Response>, on each <saml:Assertion>, or both. An assertion
//      signature travels with the assertion and does NOT cover the Status or
//      the InResponseTo; a message signature covers both and is lost the
//      moment anything extracts the assertion. The page must report them
//      separately, so this asserts a response signed at ONE level reports the
//      other as absent by name — a decoder that collapsed the two into
//      "signed: VALID" would pass every other check in this file while
//      telling somebody their unsigned assertion is safe.
//
//   3. THE TAMPER CASES, in both places. A good signature verifying proves
//      nothing on its own: it passes with the digest computed over anything at
//      all, as long as it is computed consistently. So a byte is altered
//      inside the signed assertion, and a parameter is altered in a signed
//      redirect query, and both must go INVALID.
//
//   4. DECRYPTION PUTS THE ASSERTION BACK INTO THE RESPONSE. The status, the
//      InResponseTo and any other assertion have to survive — a decoder that
//      replaced the whole document with the plaintext would lose the half that
//      says whether the sign-in worked — and the decrypted assertion's own
//      signature must still verify afterwards, which it only does if it is
//      checked against the plaintext as decrypted rather than against the
//      assertion re-serialized out of the response it was spliced into.
//
//   5. THE KEY IS NEVER STORED, and 6. THE CONSOLE IS CLEAN, for the reasons
//      tests/saml_authnrequest_page.js gives at length: this page and that one
//      are the only two here that take a private key with no localStorage
//      opt-out, and the inflate that separates the two bindings is EXPECTED to
//      fail on every POST message.
//
//   7. THE EXPAND / COLLAPSE ALL TOGGLE on all four pages that carry one. It
//      is eight lines of inline script rather than a bundle export, precisely
//      so that it works before browserify's global exists — which is also why
//      nothing else in this suite would notice it silently doing nothing.
//
//   8. EVERY CONTROL, NOT ONLY THE PROTOCOL. The seven points above are about
//      SAML, and a test that stops there leaves the page's own furniture
//      unexercised — which is how a Copy button ships copying the wrong
//      field, or a Clear empties the input and leaves the previous message's
//      assertions on screen describing a message nobody is looking at any
//      more. So EVERY exported function is driven: the five collapsible pane
//      titles (which call the BUNDLE's togglePane, a DIFFERENT function from
//      the inline switch above them), each Copy button down both of its
//      branches, Clear, the SP key-pair prefill in both directions, the
//      certificate hand-off through to saml_cert.html and back, the Binding
//      selector overriding the detection, the three query parameters that
//      decode on load, the four refusals, and which TAB each kind of decode
//      lands on.
//
// Needs only the client, so it is never skipped.

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require("selenium-webdriver/lib/select");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const assert = require("assert");
const path = require("path");
const zlib = require("zlib");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "saml_response_decoder_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
// Pure-JS RSA: key generation and signing want room on a loaded host, and this
// suite runs in a pool.
var cryptoWait = Math.max(waitTime, 30000);

// The page's own modules, located the way every other test here locates them:
// beside this script in the tests image, in the source tree from a checkout.
const { requireSharedModule } = require("./module_paths.js");
const xmldom = require("@xmldom/xmldom");
global.DOMParser = xmldom.DOMParser;
global.XMLSerializer = xmldom.XMLSerializer;
const xd = requireSharedModule([
  path.join(__dirname, "xmldsig.js"),
  path.join(__dirname, "..", "common", "xmldsig.js"),
], "common/xmldsig.js");
const sm = requireSharedModule([
  path.join(__dirname, "saml_message.js"),
  path.join(__dirname, "..", "client", "src", "saml_message.js"),
], "client/src/saml_message.js");

const SIG_ALG_RSA_SHA256 =
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SP_ENTITY_ID = "https://decoder-test.example.com/sp";
const IDP_ENTITY_ID = "https://decoder-test.example.com/idp";
const ACS_URL = "https://decoder-test.example.com/sp/acs";
const SLO_URL = "https://decoder-test.example.com/sp/slo";
const CM_BEARER_2 = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const CM_BEARER_1 = "urn:oasis:names:tc:SAML:1.0:cm:bearer";
const STATUS_SUCCESS_2 = "urn:oasis:names:tc:SAML:2.0:status:Success";
const STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";
const STATUS_NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";

// ---------------------------------------------------------------------------
// The fixtures. Each is a real message, built here.
// ---------------------------------------------------------------------------

// A SAML 2.0 assertion carrying every field the Assertions tab claims to show,
// so that "the tab rendered" and "the tab rendered the right thing" are
// different assertions. It declares its own namespaces because an assertion is
// lifted out of its response to be verified, and one that relies on the
// response's declarations is a different (and much rarer) case.
function assertion20(id) {
  log.debug("Entering assertion20().");
  var xml =
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
    ' ID="' + id + '" Version="2.0" IssueInstant="2026-08-28T12:00:00Z">' +
    '<saml:Issuer>' + IDP_ENTITY_ID + '</saml:Issuer>' +
    '<saml:Subject>' +
    '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:' +
    'emailAddress">alice@decoder-test.example.com</saml:NameID>' +
    '<saml:SubjectConfirmation Method="' + CM_BEARER_2 + '">' +
    '<saml:SubjectConfirmationData Recipient="' + ACS_URL + '"' +
    ' NotOnOrAfter="2026-08-28T12:05:00Z" InResponseTo="_req_1"/>' +
    '</saml:SubjectConfirmation></saml:Subject>' +
    '<saml:Conditions NotBefore="2026-08-28T11:59:00Z"' +
    ' NotOnOrAfter="2026-08-28T12:05:00Z">' +
    '<saml:AudienceRestriction><saml:Audience>' + SP_ENTITY_ID +
    '</saml:Audience></saml:AudienceRestriction>' +
    '<saml:OneTimeUse/></saml:Conditions>' +
    '<saml:AuthnStatement AuthnInstant="2026-08-28T12:00:00Z"' +
    ' SessionIndex="session-index-1">' +
    '<saml:AuthnContext><saml:AuthnContextClassRef>' +
    'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' +
    '</saml:AuthnContextClassRef></saml:AuthnContext>' +
    '</saml:AuthnStatement>' +
    '<saml:AttributeStatement>' +
    '<saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3"' +
    ' FriendlyName="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:' +
    'attrname-format:uri"><saml:AttributeValue>' +
    'alice@decoder-test.example.com</saml:AttributeValue></saml:Attribute>' +
    '<saml:Attribute Name="urn:oid:2.5.4.11" FriendlyName="ou">' +
    '<saml:AttributeValue>engineering</saml:AttributeValue>' +
    '<saml:AttributeValue>platform</saml:AttributeValue>' +
    '</saml:Attribute>' +
    '</saml:AttributeStatement>' +
    '</saml:Assertion>';
  log.debug("Leaving assertion20().");
  return xml;
}

// A <samlp:Response> around whatever is handed to it. `status` is the top-level
// StatusCode; `sub` an optional second-level one.
function response20(inner, status, sub) {
  log.debug("Entering response20().");
  var statusXml = '<samlp:Status><samlp:StatusCode Value="' + status + '">' +
      (sub ? '<samlp:StatusCode Value="' + sub + '"/>' : '') +
      '</samlp:StatusCode>' +
      (sub ? '<samlp:StatusMessage>the responder would have had to ask the ' +
             'user something</samlp:StatusMessage>' : '') +
      '</samlp:Status>';
  var xml =
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
    ' ID="_response_1" Version="2.0" IssueInstant="2026-08-28T12:00:00Z"' +
    ' Destination="' + ACS_URL + '" InResponseTo="_req_1">' +
    '<saml:Issuer>' + IDP_ENTITY_ID + '</saml:Issuer>' +
    statusXml + (inner || '') +
    '</samlp:Response>';
  log.debug("Leaving response20().");
  return xml;
}

// SAML 1.1's Browser/POST response. Every field below is spelled differently
// from its 2.0 counterpart, and the status code is a QName rather than a URI.
function response11() {
  log.debug("Entering response11().");
  var xml =
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"' +
    ' xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"' +
    ' ResponseID="_response_11" MajorVersion="1" MinorVersion="1"' +
    ' IssueInstant="2026-08-28T12:00:00Z" Recipient="' + ACS_URL + '">' +
    '<samlp:Status><samlp:StatusCode Value="samlp:Success"/></samlp:Status>' +
    '<saml:Assertion AssertionID="_assertion_11" MajorVersion="1"' +
    ' MinorVersion="1" Issuer="' + IDP_ENTITY_ID + '"' +
    ' IssueInstant="2026-08-28T12:00:00Z">' +
    '<saml:Conditions NotBefore="2026-08-28T11:59:00Z"' +
    ' NotOnOrAfter="2026-08-28T12:05:00Z">' +
    '<saml:AudienceRestrictionCondition><saml:Audience>' + SP_ENTITY_ID +
    '</saml:Audience></saml:AudienceRestrictionCondition>' +
    '</saml:Conditions>' +
    '<saml:AuthenticationStatement' +
    ' AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password"' +
    ' AuthenticationInstant="2026-08-28T12:00:00Z">' +
    '<saml:Subject>' +
    '<saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:' +
    'nameid-format:emailAddress">bob@decoder-test.example.com' +
    '</saml:NameIdentifier>' +
    '<saml:SubjectConfirmation><saml:ConfirmationMethod>' + CM_BEARER_1 +
    '</saml:ConfirmationMethod></saml:SubjectConfirmation>' +
    '</saml:Subject>' +
    '<saml:SubjectLocality IPAddress="203.0.113.7"/>' +
    '</saml:AuthenticationStatement>' +
    '<saml:AttributeStatement><saml:Subject>' +
    '<saml:NameIdentifier>bob@decoder-test.example.com' +
    '</saml:NameIdentifier></saml:Subject>' +
    '<saml:Attribute AttributeName="emailAddress"' +
    ' AttributeNamespace="http://schemas.example.com/claims">' +
    '<saml:AttributeValue>bob@decoder-test.example.com' +
    '</saml:AttributeValue></saml:Attribute>' +
    '</saml:AttributeStatement>' +
    '</saml:Assertion></samlp:Response>';
  log.debug("Leaving response11().");
  return xml;
}

function logoutResponse20(status) {
  log.debug("Entering logoutResponse20().");
  var xml =
    '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
    ' ID="_logout_1" Version="2.0" IssueInstant="2026-08-28T12:00:00Z"' +
    ' Destination="' + SLO_URL + '" InResponseTo="_logoutreq_1">' +
    '<saml:Issuer>' + IDP_ENTITY_ID + '</saml:Issuer>' +
    '<samlp:Status><samlp:StatusCode Value="' + status +
    '"/></samlp:Status></samlp:LogoutResponse>';
  log.debug("Leaving logoutResponse20().");
  return xml;
}

// The POST binding: base64, NOT compressed, in a form body. What a response
// looks like once it reaches a proxy log.
function postBody(xml, relayState) {
  log.debug("Entering postBody().");
  var body = "SAMLResponse=" +
      encodeURIComponent(Buffer.from(xml, "utf8").toString("base64"));
  if (relayState) body += "&RelayState=" + encodeURIComponent(relayState);
  log.debug("Leaving postBody().");
  return body;
}

// The redirect binding, built the way an identity provider builds it: DEFLATE,
// base64, percent-encode, sign the query string with SigAlg already appended,
// and put Signature on the end.
function redirectUrl(xml, keyPair, relayState) {
  log.debug("Entering redirectUrl().");
  var deflated = zlib.deflateRawSync(Buffer.from(xml, "utf8"))
      .toString("base64");
  var qs = "SAMLResponse=" + encodeURIComponent(deflated);
  if (relayState) qs += "&RelayState=" + encodeURIComponent(relayState);
  qs += "&SigAlg=" + encodeURIComponent(SIG_ALG_RSA_SHA256);
  var sig = xd.signQueryString(qs, { privateKeyPem: keyPair.privateKeyPem,
                                     sigAlg: SIG_ALG_RSA_SHA256 });
  var url = SLO_URL + "?" + qs + "&Signature=" + encodeURIComponent(sig);
  log.debug("Leaving redirectUrl().");
  return url;
}

// A SAML 2.0 type 0x0004 artifact on a GET, which is what an identity provider
// hands the browser INSTEAD of the response on the Artifact binding.
function artifactUrl() {
  log.debug("Entering artifactUrl().");
  var bytes = Buffer.concat([
    Buffer.from([0x00, 0x04, 0x00, 0x03]),
    Buffer.alloc(20, 0x3c),
    Buffer.alloc(20, 0xc3)
  ]);
  var url = ACS_URL + "?SAMLart=" +
      encodeURIComponent(bytes.toString("base64")) +
      "&RelayState=" + encodeURIComponent("artifact-relay");
  log.debug("Leaving artifactUrl().");
  return url;
}

// ---------------------------------------------------------------------------
// Driving the page.
// ---------------------------------------------------------------------------
async function click(driver, locator) {
  log.debug("Entering click().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", el);
  // A scripted click rather than the native one. A native Selenium click on a
  // control low on a tall page lands off-target under pool load and fires
  // NOTHING, with no error — see the note in tests/CLAUDE.md.
  await driver.executeScript("arguments[0].click();", el);
  log.debug("Leaving click().");
}

async function setInput(driver, id, text) {
  log.debug("Entering setInput().");
  // sendKeys on a multi-kilobyte PEM or response is minutes of typing, so the
  // value is set directly and the change event dispatched by hand.
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "e.value = arguments[1];" +
    "e.dispatchEvent(new Event('change', { bubbles: true }));", id, text);
  log.debug("Leaving setInput().");
}

async function value(driver, id) {
  log.debug("Entering value().");
  log.debug("Leaving value().");
  return driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return e ? e.value : null;", id);
}

// A container's tables as a plain key -> value object. Rows with more than two
// cells (the attributes table) map their first cell to their second, which is
// name -> value(s) and is what a caller wants from those too.
async function tableOf(driver, containerId) {
  log.debug("Entering tableOf().");
  log.debug("Leaving tableOf().");
  return driver.executeScript(
    "var out = {};" +
    "var rows = document.querySelectorAll('#' + arguments[0] + ' tr');" +
    "for (var i = 0; i < rows.length; i++) {" +
    "  var c = rows[i].getElementsByTagName('td');" +
    "  if (c.length >= 2) out[c[0].textContent.trim()] = " +
        "c[1].textContent.trim();" +
    "}" +
    "return out;", containerId);
}

async function textOf(driver, containerId) {
  log.debug("Entering textOf().");
  log.debug("Leaving textOf().");
  return driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return e ? (e.textContent || '') : '';", containerId);
}

// The expand/collapse switch is a checkbox the stylesheet makes INVISIBLE —
// `opacity: 0; width: 0; height: 0`, with the slider drawn by the label beside
// it — so click() above cannot be used: its elementIsVisible wait can never
// come true for a control that is deliberately not visible. A native click on
// the input is what the label forwards to anyway, and it fires the change
// event the inline handler is bound to (setting .checked would not).
async function clickHidden(driver, id) {
  log.debug("Entering clickHidden().");
  await driver.wait(until.elementLocated(By.id(id)), waitTime);
  await driver.executeScript(
    "document.getElementById(arguments[0]).click();", id);
  log.debug("Leaving clickHidden().");
}

// A PEM as a textarea gives it back. node-forge writes CRLF and the HTML
// specification requires the API value of a textarea to normalise line breaks
// to LF, so a byte-for-byte comparison against what was stored fails on a
// prefill that worked perfectly.
function pem(text) {
  log.debug("Entering pem().");
  log.debug("Leaving pem().");
  return String(text || "").replace(/\r/g, "").trim();
}

async function checkBox(driver, id, on) {
  log.debug("Entering checkBox().");
  var isOn = await driver.findElement(By.id(id)).isSelected();
  if (isOn !== on) await click(driver, By.id(id));
  log.debug("Leaving checkBox().");
}

async function paneVisible(driver, id) {
  log.debug("Entering paneVisible().");
  log.debug("Leaving paneVisible().");
  // getComputedStyle, not the inline style: the markup hides these with the
  // saml-hidden class, so a reader that trusts the inline style agrees with
  // whatever set it rather than with the user.
  return driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return !!e && getComputedStyle(e).display !== 'none';", id);
}

async function openPage(driver) {
  log.debug("Entering openPage().");
  await driver.get(baseUrl + "/saml_response_decoder.html");
  await driver.wait(until.elementLocated(By.id("srd_input")), waitTime);
  // The inline handlers are the browserify --standalone global, which does not
  // exist until the bundle has run — a click before then is a silent no-op.
  await driver.wait(async function () {
    return driver.executeScript(
      "return typeof window.saml_response_decoder === 'object' && " +
      "typeof window.saml_response_decoder.decode === 'function';");
  }, waitTime, "the saml_response_decoder bundle never defined its global.");
  log.debug("Leaving openPage().");
}

// Decode a blob and wait for the status line to settle. Waiting on CONTENT
// rather than on an element: the decode is asynchronous (the inflate is a
// stream), so the elements are all present before the answer is.
async function decodeBlob(driver, blob, binding) {
  log.debug("Entering decodeBlob().");
  await setInput(driver, "srd_input", blob);
  if (binding) {
    await new Select(driver.findElement(By.id("srd_binding")))
        .selectByValue(binding);
  }
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_response_decoder.decode(')]"));
  await driver.wait(async function () {
    var s = await value(driver, "srd_status");
    return !!s && s.indexOf("Decoding") !== 0;
  }, cryptoWait, "the decode never produced a status.");
  var status = await value(driver, "srd_status");
  log.debug("Leaving decodeBlob().");
  return status;
}

async function validate(driver) {
  log.debug("Entering validate().");
  await checkBox(driver, "srd_verify_enabled", true);
  await click(driver, By.xpath("//input[contains(@onclick, " +
    "'saml_response_decoder.validateSignatures(')]"));
  await driver.wait(async function () {
    return !!(await value(driver, "srd_sig_status"));
  }, cryptoWait, "the signature check never produced a status.");
  var status = await value(driver, "srd_sig_status");
  log.debug("Leaving validate(). " + status);
  return status;
}

// ---------------------------------------------------------------------------
// The cases.
// ---------------------------------------------------------------------------

// A SAML 2.0 Browser/POST response, signed on BOTH levels: this is what
// Keycloak and most identity providers emit, and it is the case where the
// difference between the two signatures is invisible unless a page insists on
// reporting them separately.
async function post20BothSignatures(driver, keyPair) {
  log.debug("Entering post20BothSignatures().");
  log.info("=== SAML 2.0 HTTP-POST: two signatures, reported separately ===");
  await openPage(driver);
  var signedAssertion = xd.signEnveloped(assertion20("_assertion_1"), {
    privateKeyPem: keyPair.privateKeyPem,
    certPem: keyPair.certPem,
    sigAlg: SIG_ALG_RSA_SHA256,
    placement: "after-issuer"
  });
  var signed = xd.signEnveloped(response20(signedAssertion, STATUS_SUCCESS_2), {
    privateKeyPem: keyPair.privateKeyPem,
    certPem: keyPair.certPem,
    sigAlg: SIG_ALG_RSA_SHA256,
    placement: "after-issuer"
  });
  var status = await decodeBlob(driver, postBody(signed, "post-relay"));
  assert.ok(/Response/.test(status), "the status should name the decoded " +
    "message. Found: " + status);
  assert.ok(/Success/.test(status),
    "the status line should carry the SAML status. Found: " + status);

  // A readable response lands on the Assertions tab, because that is what
  // somebody opened a successful response to read. The tab a decode CHOOSES
  // is part of the feature: leaving the user on Original after a decode makes
  // the page look as though nothing happened.
  await assertTab(driver, "tab_srd_assertions", "a readable POST response");

  // The Original tab holds what was pasted and the parameter pulled out of it,
  // which is the only place the two can be compared.
  assert.strictEqual(await value(driver, "srd_original"),
    postBody(signed, "post-relay"),
    "the Original tab must hold the blob exactly as pasted.");
  assert.strictEqual(await value(driver, "srd_payload"),
    Buffer.from(signed, "utf8").toString("base64"),
    "the encoded message parameter was not pulled out of the body.");

  var params = await tableOf(driver, "srd_params");
  assert.strictEqual(params["Binding"], "HTTP-POST",
    "a form body with no SigAlg is the POST binding. Found: " +
    params["Binding"]);
  assert.ok(/^no/.test(params["DEFLATE-compressed"] || ""),
    "the POST binding does not compress. Found: " +
    params["DEFLATE-compressed"]);
  assert.strictEqual(params["RelayState"], "post-relay",
    "the RelayState was not read off the body: " + params["RelayState"]);

  var details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["Message Type"], "Response",
    "wrong message type: " + details["Message Type"]);
  assert.strictEqual(details["SAML Version"], "2.0",
    "wrong version: " + details["SAML Version"]);
  assert.strictEqual(details["ID"], "_response_1",
    "wrong ID: " + details["ID"]);
  assert.strictEqual(details["Destination"], ACS_URL,
    "wrong Destination: " + details["Destination"]);
  assert.ok((details["In Response To"] || "").indexOf("_req_1") === 0,
    "the InResponseTo was not read: " + details["In Response To"]);
  assert.strictEqual(details["Issuer"], IDP_ENTITY_ID,
    "wrong Issuer: " + details["Issuer"]);
  assert.strictEqual(details["Status Code"], STATUS_SUCCESS_2,
    "the full status URI belongs in the table: " + details["Status Code"]);
  assert.strictEqual(details["Assertions"], "1",
    "one assertion was carried: " + details["Assertions"]);
  assert.ok(/present/.test(details["Message Signature"] || ""),
    "the message signature was not reported: " + details["Message Signature"]);

  // The status banner, which is what a reader actually looks at.
  var banner = await textOf(driver, "srd_status_banner");
  assert.ok(/Success/.test(banner),
    "the status banner should say Success: " + banner);

  // The assertion, on its own tab.
  var assertions = await tableOf(driver, "srd_assertions");
  assert.strictEqual(assertions["Assertion ID"], "_assertion_1",
    "the assertion id was not read: " + assertions["Assertion ID"]);
  assert.strictEqual(assertions["NameID"],
    "alice@decoder-test.example.com",
    "the NameID was not read: " + assertions["NameID"]);
  assert.strictEqual(assertions["ConfirmationMethod"], CM_BEARER_2,
    "the SAML 2.0 confirmation method is an attribute on " +
    "<saml:SubjectConfirmation>: " + assertions["ConfirmationMethod"]);
  assert.strictEqual(assertions["Confirmation Recipient"], ACS_URL,
    "the bearer check's Recipient was not read: " +
    assertions["Confirmation Recipient"]);
  assert.strictEqual(assertions["Condition: AudienceRestriction"],
    SP_ENTITY_ID, "the audience was not read: " +
    assertions["Condition: AudienceRestriction"]);
  assert.strictEqual(assertions["SessionIndex"], "session-index-1",
    "the SessionIndex was not read: " + assertions["SessionIndex"]);
  assert.ok(/PasswordProtectedTransport/
    .test(assertions["AuthnContext Class/Decl Refs"] || ""),
    "the AuthnContext class ref was not read: " +
    assertions["AuthnContext Class/Decl Refs"]);
  // The attributes, including the multi-valued one — two values under one
  // name, which a reader that takes the first would silently halve.
  var assertionsText = await textOf(driver, "srd_assertions");
  assert.ok(assertionsText.indexOf("alice@decoder-test.example.com") >= 0,
    "the mail attribute value is missing from the Assertions tab.");
  assert.ok(/engineering/.test(assertionsText) && /platform/
    .test(assertionsText),
    "both values of the multi-valued attribute must be shown.");
  log.info("[post20/decode] OK — status, details and assertion all read.");

  // --- the signatures, separately -----------------------------------------
  var sig = await validate(driver);
  assert.ok(/2 of 2 signatures VALID/.test(sig),
    "both signatures should verify from their own KeyInfo. Found: " + sig);
  var sigTable = await tableOf(driver, "srd_sig_details");
  var messageRow = sigTable["Message <Response>"] || "";
  var assertionRow = sigTable["Assertion 1"] || "";
  assert.ok(/^VALID/.test(messageRow),
    "the message signature should verify: " + messageRow);
  assert.ok(/^VALID/.test(assertionRow),
    "the assertion signature should verify: " + assertionRow);
  // The two must be described differently — that is the whole point of
  // reporting them separately rather than as one verdict.
  assert.ok(/Status/.test(messageRow),
    "the message signature's line must say it covers the Status: " +
    messageRow);
  assert.ok(/travels with the assertion/.test(assertionRow),
    "the assertion signature's line must say what it does not cover: " +
    assertionRow);
  log.info("[post20/signatures] OK — both VALID, described separately.");

  // --- the tamper case, inside the assertion -------------------------------
  // The assertion's own signed subtree is altered. This must fail BOTH
  // signatures: the assertion's own digest, and the message's, which covers
  // the assertion.
  var broken = signed.replace("engineering", "engineerinX");
  assert.notStrictEqual(broken, signed, "the tamper changed nothing.");
  await decodeBlob(driver, postBody(broken));
  sig = await validate(driver);
  assert.ok(/0 of 2 signatures VALID/.test(sig),
    "a byte altered inside the assertion must fail both signatures. Found: " +
    sig);
  log.info("[post20/tamper] OK — an altered assertion fails both.");
  log.debug("Leaving post20BothSignatures().");
}

// A response signed at ONE level only. The page has to say which, by name: a
// decoder that answered "signed: VALID" here would be telling somebody their
// unsigned assertion is safe.
async function oneSignatureIsNotTheOther(driver, keyPair) {
  log.debug("Entering oneSignatureIsNotTheOther().");
  log.info("=== Signed on the message only, then on the assertion only ===");

  // (a) the message is signed and the assertion is not.
  await openPage(driver);
  var messageOnly = xd.signEnveloped(
    response20(assertion20("_assertion_2"), STATUS_SUCCESS_2), {
      privateKeyPem: keyPair.privateKeyPem,
      certPem: keyPair.certPem,
      sigAlg: SIG_ALG_RSA_SHA256,
      placement: "after-issuer"
    });
  await decodeBlob(driver, postBody(messageOnly));
  var assertions = await tableOf(driver, "srd_assertions");
  assert.ok(/no enveloped/.test(assertions["Assertion Signature"] || ""),
    "an unsigned assertion must be reported as unsigned: " +
    assertions["Assertion Signature"]);
  var sig = await validate(driver);
  assert.ok(/1 of 1 signature VALID/.test(sig),
    "only the message signature exists here. Found: " + sig);
  var sigText = await textOf(driver, "srd_sig_details");
  assert.ok(/carries no <ds:Signature> of its own/.test(sigText),
    "the report must say the assertion carries no signature: " + sigText);
  assert.ok(/only while it does/.test(sigText),
    "the report must say the message signature stops covering the " +
    "assertion once it is extracted: " + sigText);
  log.info("[onesig/message] OK — the assertion is named as unsigned.");

  // (b) the assertion is signed and the message is not — which is what an
  //     identity provider that signs assertions rather than responses emits,
  //     and is a different security claim again.
  await openPage(driver);
  var assertionOnly = response20(xd.signEnveloped(assertion20("_assertion_3"), {
    privateKeyPem: keyPair.privateKeyPem,
    certPem: keyPair.certPem,
    sigAlg: SIG_ALG_RSA_SHA256,
    placement: "after-issuer"
  }), STATUS_SUCCESS_2);
  await decodeBlob(driver, postBody(assertionOnly));
  var details = await tableOf(driver, "srd_details");
  assert.ok(/no enveloped/.test(details["Message Signature"] || ""),
    "an unsigned message must be reported as unsigned: " +
    details["Message Signature"]);
  sig = await validate(driver);
  assert.ok(/1 of 1 signature VALID/.test(sig),
    "only the assertion signature exists here. Found: " + sig);
  var sigTable = await tableOf(driver, "srd_sig_details");
  assert.ok(/^VALID/.test(sigTable["Assertion 1"] || ""),
    "the assertion signature should verify: " + sigTable["Assertion 1"]);
  assert.strictEqual(sigTable["Message <Response>"], undefined,
    "there is no message signature to report here: " +
    sigTable["Message <Response>"]);
  log.info("[onesig/assertion] OK — the message is named as unsigned.");

  // (c) neither is signed. The page must say so as a FINDING rather than
  //     silently reporting nothing, which reads as a check that did not run.
  await openPage(driver);
  await decodeBlob(driver,
    postBody(response20(assertion20("_assertion_4"), STATUS_SUCCESS_2)));
  sig = await validate(driver);
  assert.ok(/No signature was found/.test(sig),
    "an unsigned response must be reported: " + sig);
  sigText = await textOf(driver, "srd_sig_details");
  assert.ok(/accepts anything anybody posts/.test(sigText),
    "the page should say what an unsigned response means: " + sigText);
  log.info("[onesig/neither] OK — an unsigned response is a finding.");
  log.debug("Leaving oneSignatureIsNotTheOther().");
}

// SAML 1.1's Browser/POST response. THE ASSERTION THIS CASE EXISTS FOR is the
// status: `samlp:Success` is a QName, and a reader that checks a SAML 2.0 URI
// suffix reads it as a failure.
async function saml11Response(driver) {
  log.debug("Entering saml11Response().");
  log.info("=== SAML 1.1: a QName status and a differently-spelled " +
           "assertion ===");
  await openPage(driver);
  var status = await decodeBlob(driver, postBody(response11(), "relay-11"));
  assert.ok(/SAML 1\.1/.test(status),
    "the version must be read off MajorVersion/MinorVersion. Found: " +
    status);
  assert.ok(/Status: Success\./.test(status),
    "a SAML 1.1 samlp:Success is a SUCCESS. A reader written for 2.0's " +
    "`:status:Success` suffix reports it as a failure, which is the worst " +
    "possible way to be wrong about a sign-in that worked. Found: " + status);

  var details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["SAML Version"], "1.1",
    "wrong version: " + details["SAML Version"]);
  assert.strictEqual(details["ID"], "_response_11",
    "SAML 1.1 spells the message id ResponseID: " + details["ID"]);
  assert.strictEqual(details["Recipient"], ACS_URL,
    "SAML 1.1 has no Destination; it has Recipient: " + details["Recipient"]);
  assert.strictEqual(details["Destination"], undefined,
    "a SAML 1.1 response has no Destination attribute at all: " +
    details["Destination"]);
  assert.strictEqual(details["Status Code"], "samlp:Success",
    "the QName belongs in the table as written: " + details["Status Code"]);
  assert.ok((details["Status Code (resolved)"] || "")
    .indexOf("{urn:oasis:names:tc:SAML:1.0:protocol}Success") === 0,
    "the QName must be resolved against the document's own namespace " +
    "declarations, because that is what it MEANS: " +
    details["Status Code (resolved)"]);
  // The message names no issuer — the assertion does — and the page must say
  // where it got the one it shows rather than leaving the row blank.
  // startsWith rather than equality: this cell carries the value AND the note
  // saying where it came from, and textContent returns both.
  assert.ok((details["Issuer"] || "").indexOf(IDP_ENTITY_ID) === 0,
    "the assertion's issuer should stand in: " + details["Issuer"]);
  assert.ok(/read off the assertion/.test(
    await textOf(driver, "srd_details")),
    "the page must say the issuer came from the assertion.");

  var banner = await textOf(driver, "srd_status_banner");
  assert.ok(/Success/.test(banner),
    "the SAML 1.1 status banner should say Success: " + banner);

  var assertions = await tableOf(driver, "srd_assertions");
  assert.strictEqual(assertions["Assertion ID"], "_assertion_11",
    "SAML 1.1 spells the assertion id AssertionID: " +
    assertions["Assertion ID"]);
  assert.strictEqual(assertions["Assertion Issuer"], IDP_ENTITY_ID,
    "in SAML 1.1 the issuer is an ATTRIBUTE on the assertion: " +
    assertions["Assertion Issuer"]);
  assert.strictEqual(assertions["NameID"], "bob@decoder-test.example.com",
    "in SAML 1.1 the subject is <saml:NameIdentifier>, not <saml:NameID> — " +
    "a reader that knows only 2.0 finds nothing: " + assertions["NameID"]);
  assert.strictEqual(assertions["ConfirmationMethod"], CM_BEARER_1,
    "in SAML 1.1 the confirmation method is a CHILD element of " +
    "<saml:SubjectConfirmation>, not a Method attribute — and in the browser " +
    "profiles that method IS the profile: " +
    assertions["ConfirmationMethod"]);
  assert.strictEqual(assertions["Condition: AudienceRestrictionCondition"],
    SP_ENTITY_ID,
    "SAML 1.1 spells it AudienceRestrictionCondition, and the label must be " +
    "the element's OWN name rather than 2.0's: " +
    assertions["Condition: AudienceRestrictionCondition"]);
  assert.strictEqual(assertions["AuthenticationMethod"],
    "urn:oasis:names:tc:SAML:1.0:am:password",
    "the 1.1 authentication method was not read: " +
    assertions["AuthenticationMethod"]);
  assert.strictEqual(assertions["SubjectLocality"], "203.0.113.7",
    "the SubjectLocality was not read: " + assertions["SubjectLocality"]);
  // The attribute name: 1.1 splits into AttributeName + AttributeNamespace
  // what 2.0 writes as one Name, and the two halves belong back together.
  var text = await textOf(driver, "srd_assertions");
  assert.ok(text.indexOf("http://schemas.example.com/claims/emailAddress") >= 0,
    "a SAML 1.1 attribute's namespace and name must be rejoined into the " +
    "claim URI they came from. Assertions tab:\n" + text);
  log.info("[saml11] OK — the QName status and every 1.1 spelling.");
  log.debug("Leaving saml11Response().");
}

// A failed response. There is no assertion in one, so everything the page can
// say is in the status — and the second-level code is the part that says why.
async function failureResponse(driver) {
  log.debug("Entering failureResponse().");
  log.info("=== A failure: the status IS the whole message ===");
  await openPage(driver);
  var status = await decodeBlob(driver,
    postBody(response20("", STATUS_RESPONDER, STATUS_NO_PASSIVE)));
  assert.ok(/NOT a success/.test(status),
    "a Responder status is not a success and the line must say so: " +
    status);

  var details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["Status Code"], STATUS_RESPONDER,
    "wrong top-level status: " + details["Status Code"]);
  // startsWith: this cell carries the code AND the note explaining it.
  assert.ok((details["Sub-status 1"] || "").indexOf(STATUS_NO_PASSIVE) === 0,
    "the nested StatusCode is what says WHY: " + details["Sub-status 1"]);
  assert.strictEqual(details["Assertions"], "0",
    "a failed response carries no assertion: " + details["Assertions"]);
  // The second-level code is the one worth explaining, and NoPassive is the
  // one people misread most: it is not a refusal, it is "I would have had to
  // ask the user something".
  var text = await textOf(driver, "srd_details");
  assert.ok(/without interacting with the user/.test(text),
    "the page should say what NoPassive means:\n" + text);
  var banner = await textOf(driver, "srd_status_banner");
  assert.ok(/Responder/.test(banner) && /NoPassive/.test(banner),
    "the banner should carry both levels: " + banner);

  // A failed response has no assertion, so Details is where its whole content
  // is and where the decode must land.
  await assertTab(driver, "tab_srd_details", "a failed response");

  var assertionsText = await textOf(driver, "srd_assertions");
  assert.ok(/carries no assertion/.test(assertionsText),
    "the Assertions tab must say why it is empty rather than being blank: " +
    assertionsText);
  log.info("[failure] OK — both status levels, and no invented assertion.");
  log.debug("Leaving failureResponse().");
}

// The Redirect binding, which a LogoutResponse really does use. The signature
// is DETACHED — over the query string as sent — so it needs a certificate,
// and the tamper case is the one that catches octets rebuilt in the wrong
// order.
async function redirectLogoutResponse(driver, keyPair) {
  log.debug("Entering redirectLogoutResponse().");
  log.info("=== HTTP-Redirect: a detached query-string signature ===");
  await openPage(driver);
  var xml = logoutResponse20(STATUS_SUCCESS_2);
  var url = redirectUrl(xml, keyPair, "logout-relay");
  var status = await decodeBlob(driver, url);
  assert.ok(/LogoutResponse/.test(status),
    "the status should name the message: " + status);

  var params = await tableOf(driver, "srd_params");
  assert.strictEqual(params["Binding"], "HTTP-Redirect",
    "a GET carrying SAMLResponse is the Redirect binding: " +
    params["Binding"]);
  assert.ok(/^yes/.test(params["DEFLATE-compressed"] || ""),
    "a Redirect message is DEFLATE-compressed: " +
    params["DEFLATE-compressed"]);
  assert.strictEqual(params["Endpoint"], SLO_URL,
    "the endpoint was not shown: " + params["Endpoint"]);

  var details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["Message Type"], "LogoutResponse",
    "wrong message type: " + details["Message Type"]);
  assert.strictEqual(details["Assertions"], "0",
    "a LogoutResponse carries no assertion: " + details["Assertions"]);
  assert.ok(/no enveloped/.test(details["Message Signature"] || ""),
    "the document inside a Redirect message is not signed — the query " +
    "string is: " + details["Message Signature"]);

  await setInput(driver, "srd_signer_cert", keyPair.certPem);
  var sig = await validate(driver);
  assert.ok(/1 of 1 signature VALID/.test(sig),
    "the query-string signature should verify: " + sig);
  var sigTable = await tableOf(driver, "srd_sig_details");
  var row = sigTable["Query string (Redirect binding)"] || "";
  assert.ok(/^VALID/.test(row), "the detached signature failed: " + row);
  assert.ok(row.indexOf("SAMLResponse=") >= 0,
    "the signed octets are shown because they are the thing that goes " +
    "wrong: " + row);
  assert.ok(/SigAlg=[^&]+$/.test(row.substring(row.indexOf("SAMLResponse="))),
    "SigAlg is the last signed parameter and Signature is excluded: " + row);

  // THE TAMPER CASE. One parameter altered, everything else identical: this
  // is what a decoder that rebuilds the octets its own way cannot tell from
  // the good message above.
  var tampered = url.replace("RelayState=logout-relay",
                             "RelayState=logout-relaX");
  assert.notStrictEqual(tampered, url, "the tamper did not change the URL.");
  await decodeBlob(driver, tampered);
  await setInput(driver, "srd_signer_cert", keyPair.certPem);
  sig = await validate(driver);
  assert.ok(/0 of 1 signature VALID/.test(sig),
    "an altered RelayState must fail the signature: " + sig);
  log.info("[redirect] OK — VALID as sent, INVALID when altered.");
  log.debug("Leaving redirectLogoutResponse().");
}

// An encrypted assertion. The interesting half is what happens AFTER the
// decryption: the plaintext goes back into the response rather than replacing
// it, and its signature still verifies.
async function encryptedAssertion(driver, keyPair) {
  log.debug("Entering encryptedAssertion().");
  log.info("=== EncryptedAssertion: describe it, decrypt it, splice it ===");
  await openPage(driver);
  var signedAssertion = xd.signEnveloped(assertion20("_assertion_enc"), {
    privateKeyPem: keyPair.privateKeyPem,
    certPem: keyPair.certPem,
    sigAlg: SIG_ALG_RSA_SHA256,
    placement: "after-issuer"
  });
  var encrypted = xd.encryptXml(signedAssertion, { certPem: keyPair.certPem });
  var wrapped = '<saml:EncryptedAssertion xmlns:saml=' +
      '"urn:oasis:names:tc:SAML:2.0:assertion">' + encrypted +
      '</saml:EncryptedAssertion>';
  var response = response20(wrapped, STATUS_SUCCESS_2);
  var status = await decodeBlob(driver, postBody(response));
  assert.ok(/ENCRYPTED/i.test(status),
    "the status must say the response is encrypted: " + status);

  // Nothing about the assertion may be shown yet, and the STATUS must still
  // be — that is the half a page which replaced the document with the
  // ciphertext would lose.
  var details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["Message Type"], "Response",
    "the response around the ciphertext is still readable: " +
    details["Message Type"]);
  assert.strictEqual(details["Status Code"], STATUS_SUCCESS_2,
    "the status must survive an encrypted assertion: " +
    details["Status Code"]);
  assert.strictEqual(details["Encrypted assertions"], "1",
    "the encrypted assertion was not counted: " +
    details["Encrypted assertions"]);
  var assertionsText = await textOf(driver, "srd_assertions");
  assert.ok(/ENCRYPTED/.test(assertionsText),
    "the assertion must be labelled as encrypted: " + assertionsText);
  assert.ok(assertionsText.indexOf("alice@decoder-test.example.com") < 0,
    "nothing inside the ciphertext may be shown before it is decrypted.");
  // Ciphertext first: nothing else can be read until it is dealt with.
  await assertTab(driver, "tab_srd_encrypted", "an encrypted response");

  var enc = await value(driver, "srd_encrypted");
  assert.ok(enc.indexOf("EncryptedData") >= 0 &&
            enc.indexOf("CipherValue") >= 0,
    "the Encrypted tab should hold the ciphertext.");
  log.info("[encrypted/decode] OK — described, not guessed at.");

  // --- decrypt -------------------------------------------------------------
  await checkBox(driver, "srd_decrypt_enabled", true);
  await setInput(driver, "srd_dec_key", keyPair.privateKeyPem);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_response_decoder.decrypt(')]"));
  await driver.wait(async function () {
    return !!(await value(driver, "srd_dec_status"));
  }, cryptoWait, "the decryption never produced a status.");
  var decStatus = await value(driver, "srd_dec_status");
  assert.ok(/Decrypted/.test(decStatus),
    "the decryption should succeed: " + decStatus);
  assert.ok(/back into the response/.test(decStatus),
    "the plaintext should be spliced back rather than replacing the " +
    "response: " + decStatus);

  // The response is still a response, and the assertion is now readable.
  details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["Message Type"], "Response",
    "the envelope must survive the decryption: " + details["Message Type"]);
  assert.strictEqual(details["Status Code"], STATUS_SUCCESS_2,
    "the status must survive the decryption: " + details["Status Code"]);
  await assertTab(driver, "tab_srd_assertions", "a decrypted response");

  var assertions = await tableOf(driver, "srd_assertions");
  assert.strictEqual(assertions["Assertion ID"], "_assertion_enc",
    "the decrypted assertion was not read: " + assertions["Assertion ID"]);
  assert.strictEqual(assertions["NameID"], "alice@decoder-test.example.com",
    "the decrypted NameID was not read: " + assertions["NameID"]);

  // And its signature — which was made before the encryption — must still
  // verify. It only does if it is checked against the plaintext AS
  // DECRYPTED rather than against the assertion re-serialized out of the
  // response it was just spliced into.
  var sig = await validate(driver);
  assert.ok(/1 of 1 signature VALID/.test(sig),
    "the signature inside the ciphertext must verify after decryption: " +
    sig);
  log.info("[encrypted/decrypt] OK — spliced back, and still signed.");

  // --- the wrong key fails, and says so ------------------------------------
  await openPage(driver);
  await decodeBlob(driver, postBody(response));
  await checkBox(driver, "srd_decrypt_enabled", true);
  var other = xd.generateKeyPair(2048, "not-the-recipient");
  await setInput(driver, "srd_dec_key", other.privateKeyPem);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_response_decoder.decrypt(')]"));
  await driver.wait(async function () {
    return !!(await value(driver, "srd_dec_status"));
  }, cryptoWait, "the failed decryption never produced a status.");
  decStatus = await value(driver, "srd_dec_status");
  assert.ok(/failed/i.test(decStatus),
    "the wrong key must fail rather than silently do nothing: " + decStatus);
  log.info("[encrypted/wrongkey] OK — refused.");
  log.debug("Leaving encryptedAssertion().");
}

// The Artifact binding, on the response half of the exchange: the identity
// provider hands the browser 44 bytes instead of the assertion.
async function artifactBinding(driver) {
  log.debug("Entering artifactBinding().");
  log.info("=== HTTP-Artifact: 44 bytes instead of a response ===");
  await openPage(driver);
  var status = await decodeBlob(driver, artifactUrl());
  assert.ok(/artifact/i.test(status),
    "the status should say it read an artifact: " + status);

  var params = await tableOf(driver, "srd_params");
  assert.strictEqual(params["Binding"], "HTTP-Artifact",
    "a GET carrying SAMLart is the Artifact binding: " + params["Binding"]);

  var details = await tableOf(driver, "srd_details");
  assert.ok(/0x0004/.test(details["Artifact Type"] || ""),
    "the artifact type was not identified: " + details["Artifact Type"]);
  assert.strictEqual(details["EndpointIndex"], "3",
    "the EndpointIndex was not read: " + details["EndpointIndex"]);
  assert.strictEqual(details["MessageHandle"], "c3".repeat(20),
    "the MessageHandle was not read: " + details["MessageHandle"]);
  assert.strictEqual(details["Length"], "44 bytes",
    "a type 0x0004 artifact is 44 bytes: " + details["Length"]);
  // There is no message in an artifact, and the XML tab must stay empty
  // rather than showing the previous decode's.
  assert.strictEqual((await value(driver, "srd_xml")).trim(), "",
    "an artifact carries no message, so the XML tab must be empty.");
  log.info("[artifact] OK — the reference is read; no message is invented.");
  log.debug("Leaving artifactBinding().");
}

// A bare <saml:Assertion>, which is what somebody pastes after slicing one out
// of a log. It is not a response and the page must not pretend it is.
async function bareAssertion(driver, keyPair) {
  log.debug("Entering bareAssertion().");
  log.info("=== A bare assertion, pasted on its own ===");
  await openPage(driver);
  var signed = xd.signEnveloped(assertion20("_assertion_bare"), {
    privateKeyPem: keyPair.privateKeyPem,
    certPem: keyPair.certPem,
    sigAlg: SIG_ALG_RSA_SHA256,
    placement: "after-issuer"
  });
  var status = await decodeBlob(driver, signed);
  assert.ok(/Assertion/.test(status),
    "a bare assertion should decode as one: " + status);
  var details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["Message Type"], "Assertion",
    "wrong message type: " + details["Message Type"]);
  // There is no status in an assertion, and the page must not invent one or
  // complain about its absence as though a response were missing something.
  assert.strictEqual(details["Status"], undefined,
    "an assertion has no <samlp:Status> and none should be reported: " +
    details["Status"]);
  var assertions = await tableOf(driver, "srd_assertions");
  assert.strictEqual(assertions["Assertion ID"], "_assertion_bare",
    "the pasted assertion should appear on the Assertions tab: " +
    assertions["Assertion ID"]);
  var sig = await validate(driver);
  assert.ok(/1 of 1 signature VALID/.test(sig),
    "a bare signed assertion should verify from its own KeyInfo: " + sig);
  log.info("[bare] OK — read as an assertion, not as a response.");
  log.debug("Leaving bareAssertion().");
}

// Both crypto panes are genuinely optional, and the pasted key is never
// written. Same two claims tests/saml_authnrequest_page.js makes about the
// other decoder, and for the same reason: this page has no key-material
// opt-out because it never stores, and that claim is otherwise only prose.
async function optionalAndPrivate(driver, keyPair) {
  log.debug("Entering optionalAndPrivate().");
  log.info("=== Both crypto panes are optional, and the key is not stored ===");
  await openPage(driver);
  await driver.executeScript("window.localStorage.clear();" +
                             "window.sessionStorage.clear();");
  await openPage(driver);

  assert.strictEqual(
    await driver.findElement(By.id("srd_verify_enabled")).isSelected(), false,
    "signature validation must be off until it is asked for.");
  assert.strictEqual(
    await driver.findElement(By.id("srd_decrypt_enabled")).isSelected(), false,
    "decryption must be off until it is asked for.");
  assert.strictEqual(await paneVisible(driver, "srd_verify_body"), false,
    "the signature pane's body should be hidden while the box is clear.");
  assert.strictEqual(await paneVisible(driver, "srd_decrypt_body"), false,
    "the decryption pane's body should be hidden while the box is clear.");

  // A plain unsigned, unencrypted response still decodes with both off, which
  // is what "optional" has to mean.
  var plain = response20(assertion20("_assertion_plain"), STATUS_SUCCESS_2);
  var status = await decodeBlob(driver,
    Buffer.from(plain, "utf8").toString("base64"));
  assert.ok(/Response/.test(status),
    "an unsigned, unencrypted response must decode with both panes off: " +
    status);
  log.info("[optional] OK — decoding needs neither.");

  await checkBox(driver, "srd_verify_enabled", true);
  assert.strictEqual(await paneVisible(driver, "srd_verify_body"), true,
    "ticking the box must reveal the signature pane.");
  await checkBox(driver, "srd_decrypt_enabled", true);
  assert.strictEqual(await paneVisible(driver, "srd_decrypt_body"), true,
    "ticking the box must reveal the decryption pane.");

  // THE KEY IS NEVER WRITTEN. Paste it, use it, then search every stored
  // value for any part of it. A substring of the PEM body is used rather than
  // the whole string, because a page that stored a re-wrapped copy would
  // otherwise pass.
  var encrypted = xd.encryptXml(assertion20("_assertion_priv"),
                                { certPem: keyPair.certPem });
  var wrapped = '<saml:EncryptedAssertion xmlns:saml=' +
      '"urn:oasis:names:tc:SAML:2.0:assertion">' + encrypted +
      '</saml:EncryptedAssertion>';
  await decodeBlob(driver,
    postBody(response20(wrapped, STATUS_SUCCESS_2)));
  await checkBox(driver, "srd_decrypt_enabled", true);
  await setInput(driver, "srd_dec_key", keyPair.privateKeyPem);
  await setInput(driver, "srd_signer_cert", keyPair.certPem);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_response_decoder.decrypt(')]"));
  await driver.wait(async function () {
    return /Decrypted/.test(await value(driver, "srd_dec_status") || "");
  }, cryptoWait, "the decryption used to prove non-storage did not succeed.");

  var needle = keyPair.privateKeyPem.replace(/-----[^-]*-----/g, "")
      .replace(/\s+/g, "").substring(0, 60);
  assert.ok(needle.length === 60, "could not build a key needle to search.");
  var leaked = await driver.executeScript(
    "var needle = arguments[0], hits = [];" +
    "function scan(store, label) {" +
    "  for (var i = 0; i < store.length; i++) {" +
    "    var k = store.key(i);" +
    "    var v = store.getItem(k) || '';" +
    "    if (v.replace(/\\s+/g, '').indexOf(needle) >= 0) hits.push(label + " +
    "        ':' + k);" +
    "  }" +
    "}" +
    "scan(window.localStorage, 'local');" +
    "scan(window.sessionStorage, 'session');" +
    "return hits;", needle);
  assert.deepStrictEqual(leaked, [],
    "this page must never write a pasted private key to storage. Found in: " +
    leaked.join(", "));
  // A reload must not bring it back either — the field is the only place it
  // ever lived.
  await openPage(driver);
  assert.strictEqual((await value(driver, "srd_dec_key")).trim(), "",
    "the private key came back after a reload, so something stored it.");
  log.info("[private] OK — nothing pasted here reaches storage.");
  log.debug("Leaving optionalAndPrivate().");
}

// The Tools pane on every page that has one must reach this page. The link is
// the only route to it — there is no landing card — so a page that loses it
// makes the decoder unreachable while every test of the decoder still passes.
async function reachableFromToolsPanes(driver) {
  log.debug("Entering reachableFromToolsPanes().");
  log.info("=== The Tools pane links ===");
  var pages = ["saml_request.html", "saml_response.html",
               "saml_authnrequest.html", "wsfed_response.html"];
  for (var i = 0; i < pages.length; i++) {
    await driver.get(baseUrl + "/" + pages[i]);
    await driver.wait(until.elementLocated(By.id("pane_tools")), waitTime);
    var href = await driver.executeScript(
      "var a = document.querySelector('#pane_tools a[href*=" +
      "\"saml_response_decoder.html\"]');" +
      "return a ? a.getAttribute('href') : null;");
    assert.ok(href, "the Tools pane on " + pages[i] +
      " has no link to the SAML Response Decoder.");
    // Follow it: a link to a page that 404s is the failure this catches.
    await driver.get(baseUrl + href.replace(/^\//, "/"));
    await driver.wait(until.elementLocated(By.id("srd_input")), waitTime,
      "the link from " + pages[i] + " did not reach the decoder.");
    var back = await driver.findElement(By.id("return_link")).getText();
    assert.ok(back.length > 0, "the decoder has no return link.");
  }
  log.info("[tools] OK — linked from all " + pages.length + " Tools panes.");
  log.debug("Leaving reachableFromToolsPanes().");
}

// THE EXPAND / COLLAPSE ALL TOGGLE, on every page in this family that carries
// one. It is inline script rather than a bundle export precisely so that it
// works before browserify's global exists — which is also why nothing else
// here would notice it silently doing nothing.
async function expandCollapseAll(driver) {
  log.debug("Entering expandCollapseAll().");
  log.info("=== Expand / Collapse All ===");
  var pages = [
    { page: "saml_request.html",
      bodies: ["pane_metadata_body", "pane_config_body", "pane_request_body",
               "pane_tools_body", "pane_history_body"] },
    { page: "saml_response.html",
      bodies: ["pane_response_body", "pane_assertion_body", "pane_tools_body",
               "pane_history_body"] },
    { page: "saml_authnrequest.html",
      bodies: ["pane_input_body", "pane_signature_body", "pane_decrypt_body",
               "pane_decoded_body", "pane_tools_body"] },
    { page: "saml_response_decoder.html",
      bodies: ["pane_input_body", "pane_signature_body",
               "pane_decrypt_body_all", "pane_decoded_body",
               "pane_tools_body"] }
  ];
  for (var i = 0; i < pages.length; i++) {
    var spec = pages[i];
    await driver.get(baseUrl + "/" + spec.page);
    await driver.wait(until.elementLocated(By.id("saml_toggle_all")),
      waitTime, spec.page + " has no Expand / Collapse All toggle.");
    // Every pane it claims to control has to exist. A body id that no longer
    // matches is a pane the switch silently skips, which is invisible in a
    // screenshot: the other panes still move.
    var present = await driver.executeScript(
      "return arguments[0].filter(function (id) {" +
      "  return !document.getElementById(id);" +
      "});", spec.bodies);
    assert.deepStrictEqual(present, [],
      "on " + spec.page + " the toggle names pane bodies that do not " +
      "exist: " + present.join(", "));

    // It starts checked, meaning everything is expanded, and the label names
    // the action it will perform rather than the state it is in.
    assert.strictEqual(
      await driver.findElement(By.id("saml_toggle_all")).isSelected(), true,
      "on " + spec.page + " the panes should start expanded.");
    var label = await driver.executeScript(
      "var e = document.querySelector('.saml-toggle-text');" +
      "return e ? e.textContent.trim() : '';");
    assert.strictEqual(label, "Collapse all panes",
      "on " + spec.page + " the label should name its action: " + label);

    // Collapse: every body hidden, measured with getComputedStyle so a pane
    // hidden by a class rather than the inline style is still seen.
    await clickHidden(driver, "saml_toggle_all");
    var visible = await driver.executeScript(
      "return arguments[0].filter(function (id) {" +
      "  var e = document.getElementById(id);" +
      "  return e && getComputedStyle(e).display !== 'none';" +
      "});", spec.bodies);
    assert.deepStrictEqual(visible, [],
      "on " + spec.page + " these panes did not collapse: " +
      visible.join(", "));
    label = await driver.executeScript(
      "var e = document.querySelector('.saml-toggle-text');" +
      "return e ? e.textContent.trim() : '';");
    assert.strictEqual(label, "Expand all panes",
      "on " + spec.page + " the label should flip: " + label);

    // Expand again: everything back.
    await clickHidden(driver, "saml_toggle_all");
    var hidden = await driver.executeScript(
      "return arguments[0].filter(function (id) {" +
      "  var e = document.getElementById(id);" +
      "  return !e || getComputedStyle(e).display === 'none';" +
      "});", spec.bodies);
    assert.deepStrictEqual(hidden, [],
      "on " + spec.page + " these panes did not come back: " +
      hidden.join(", "));
    log.info("[toggle] OK — " + spec.page + ", " + spec.bodies.length +
             " panes.");
  }
  log.debug("Leaving expandCollapseAll().");
}

// Which tab the pane is showing, by the panel that is displayed rather than by
// the button that is highlighted — a decode SELECTS a tab from code, and a
// highlight that disagrees with the content is exactly the defect selectTab()
// exists to prevent, so both are read and compared.
async function activeTab(driver) {
  log.debug("Entering activeTab().");
  log.debug("Leaving activeTab().");
  return driver.executeScript(
    "var shown = [], active = [];" +
    "var panes = document.querySelectorAll('#pane_decoded .saml-tabcontent');" +
    "for (var i = 0; i < panes.length; i++) {" +
    "  if (getComputedStyle(panes[i]).display !== 'none') " +
    "      shown.push(panes[i].id);" +
    "}" +
    "var links = document.querySelectorAll('#pane_decoded .tablinks');" +
    "for (var k = 0; k < links.length; k++) {" +
    "  if (/\\bactive\\b/.test(links[k].className)) " +
    "      active.push(links[k].id.replace(/_btn$/, ''));" +
    "}" +
    "return { shown: shown, active: active };");
}

async function assertTab(driver, expected, where) {
  log.debug("Entering assertTab().");
  var tabs = await activeTab(driver);
  assert.deepStrictEqual(tabs.shown, [expected],
    where + ": the wrong panel is displayed: " + tabs.shown.join(", "));
  assert.deepStrictEqual(tabs.active, [expected],
    where + ": the highlighted tab disagrees with the panel on screen: " +
    tabs.active.join(", ") + " vs " + tabs.shown.join(", "));
  log.debug("Leaving assertTab().");
}

// Every control on the page that is not a decode, a signature check or a
// decryption: the four collapsible pane titles, the Copy buttons, and Clear.
// None of these has anything to do with SAML, which is exactly why a test
// written about the protocol leaves them out and a page ships with a Copy
// button that copies the wrong field.
async function paneControls(driver, keyPair) {
  log.debug("Entering paneControls().");
  log.info("=== The page's own controls: titles, Copy, Clear ===");
  await openPage(driver);

  // --- the four collapsible pane titles -----------------------------------
  // These call the BUNDLE's togglePane(), which is a different function from
  // the inline samlSetAllPanes() the switch at the top of the page uses. A
  // test that drives only the switch leaves all four of these unexercised.
  var panes = [
    ["pane_input", "pane_input_body"],
    ["pane_signature", "pane_signature_body"],
    ["pane_decrypt", "pane_decrypt_body_all"],
    ["pane_decoded", "pane_decoded_body"],
    ["pane_tools", "pane_tools_body"]
  ];
  for (var i = 0; i < panes.length; i++) {
    var legend = panes[i][0], body = panes[i][1];
    assert.strictEqual(await paneVisible(driver, body), true,
      body + " should start expanded.");
    await driver.executeScript(
      "document.querySelector('#' + arguments[0] + ' > .saml-legend')" +
      ".click();", legend);
    assert.strictEqual(await paneVisible(driver, body), false,
      "clicking the " + legend + " title did not collapse " + body + ".");
    await driver.executeScript(
      "document.querySelector('#' + arguments[0] + ' > .saml-legend')" +
      ".click();", legend);
    assert.strictEqual(await paneVisible(driver, body), true,
      "clicking the " + legend + " title again did not re-expand " + body +
      ".");
  }
  log.info("[controls/titles] OK — all " + panes.length +
           " pane titles collapse and expand.");

  // --- the Copy buttons ----------------------------------------------------
  // Both branches, because which one runs depends on the ORIGIN: this suite
  // drives the page over plain http on a DNS name in the containerized stack,
  // where navigator.clipboard does not exist at all and the execCommand
  // fallback is the only path that ever executes. Stubbing each in turn is
  // what makes the assertion "this button copies THIS field" rather than
  // "this button did not throw".
  var signed = xd.signEnveloped(
    response20(assertion20("_assertion_copy"), STATUS_SUCCESS_2), {
      privateKeyPem: keyPair.privateKeyPem,
      certPem: keyPair.certPem,
      sigAlg: SIG_ALG_RSA_SHA256,
      placement: "after-issuer"
    });
  var body = postBody(signed, "copy-relay");
  await decodeBlob(driver, body);
  await driver.executeScript(
    "window.__copied = null;" +
    "Object.defineProperty(window.navigator, 'clipboard', {" +
    "  configurable: true," +
    "  value: { writeText: function (t) { window.__copied = t;" +
    "      return Promise.resolve(); } }" +
    "});");
  var fields = ["srd_input", "srd_original", "srd_payload", "srd_xml"];
  for (var f = 0; f < fields.length; f++) {
    await driver.executeScript(
      "document.querySelector('button.saml-copy[onclick*=\"' + arguments[0] +" +
      " '\"]').click();", fields[f]);
    var copied = await driver.executeScript("return window.__copied;");
    var expected = await value(driver, fields[f]);
    assert.strictEqual(copied, expected,
      "the Copy button beside " + fields[f] + " copied something else: " +
      String(copied).substring(0, 80));
    assert.ok(expected && expected.length > 0,
      "the copy check on " + fields[f] + " read an empty field, so it would " +
      "have passed whatever the button did.");
  }
  log.info("[controls/copy] OK — " + fields.length +
           " Copy buttons each copy their own field.");

  // The fallback: no clipboard object at all, which is the containerized
  // stack's actual condition.
  await driver.executeScript(
    "Object.defineProperty(window.navigator, 'clipboard', {" +
    "  configurable: true, value: undefined });" +
    "window.__execCommands = [];" +
    "document.execCommand = function (name) {" +
    "  window.__execCommands.push({ name: name," +
    "      id: document.activeElement ? document.activeElement.id : '' });" +
    "  return true;" +
    "};");
  // On the XML tab first: the fallback path FOCUSES the field before copying
  // it, and focus() on an element inside a hidden panel does nothing — so a
  // check that clicks the button of a hidden tab records an activeElement of
  // <body> and proves nothing. A user is necessarily on the tab whose Copy
  // button they are pressing, so the check has to be too.
  await click(driver, By.id("tab_srd_xml_btn"));
  await driver.executeScript(
    "document.querySelector('button.saml-copy[onclick*=\"srd_xml\"]')" +
    ".click();");
  var commands = await driver.executeScript("return window.__execCommands;");
  assert.deepStrictEqual(commands, [{ name: "copy", id: "srd_xml" }],
    "with no navigator.clipboard the Copy button must select the field and " +
    "fall back to execCommand('copy'): " + JSON.stringify(commands));
  log.info("[controls/copy-fallback] OK — the no-clipboard path selects the " +
           "right field.");

  // --- Clear ---------------------------------------------------------------
  // Everything the page holds, including the two crypto panes' fields and the
  // tables a decode drew. A Clear that empties the input and leaves the
  // previous message's assertions on screen is worse than none: the page then
  // describes a message that is no longer in front of anybody.
  await openPage(driver);
  await decodeBlob(driver, body);
  await checkBox(driver, "srd_verify_enabled", true);
  await setInput(driver, "srd_signer_cert", keyPair.certPem);
  await checkBox(driver, "srd_decrypt_enabled", true);
  await setInput(driver, "srd_dec_key", keyPair.privateKeyPem);
  await setInput(driver, "srd_dec_cert", keyPair.certPem);
  assert.ok((await textOf(driver, "srd_assertions")).indexOf("_assertion_copy")
    >= 0, "the assertion should be on screen before Clear is pressed.");
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_response_decoder.clearAll(')]"));
  var emptied = ["srd_input", "srd_original", "srd_payload", "srd_xml",
                 "srd_encrypted", "srd_signer_cert", "srd_dec_key",
                 "srd_dec_cert", "srd_sig_status", "srd_dec_status"];
  for (var e = 0; e < emptied.length; e++) {
    assert.strictEqual((await value(driver, emptied[e]) || "").trim(), "",
      "Clear left " + emptied[e] + " filled.");
  }
  assert.strictEqual(await value(driver, "srd_status"), "Cleared.",
    "Clear must say so on the status line.");
  for (var c = 0; c < 3; c++) {
    var id = ["srd_details", "srd_assertions", "srd_params"][c];
    var text = (await textOf(driver, id)).replace(/\s| /g, "");
    assert.strictEqual(text, "",
      "Clear left the previous message's " + id + " on screen: " + text);
  }
  log.info("[controls/clear] OK — every field and every table emptied.");
  log.debug("Leaving paneControls().");
}

// The SP key pair prefill, which is the ONE thing this page reads out of
// localStorage. Both directions are asserted, because the interesting one is
// the empty one: the SAML Test Tools page's key-pair opt-out means there may
// legitimately be nothing to read, and an empty field with no explanation
// reads as a broken prefill rather than as a preference somebody set.
async function spKeyPairPrefill(driver, keyPair) {
  log.debug("Entering spKeyPairPrefill().");
  log.info("=== The SP key pair prefill, in both directions ===");
  await openPage(driver);
  await driver.executeScript("window.localStorage.clear();");
  await openPage(driver);

  // Nothing stored: the note has to say which of the two happened.
  await checkBox(driver, "srd_decrypt_enabled", true);
  assert.strictEqual((await value(driver, "srd_dec_key")).trim(), "",
    "there is nothing stored, so nothing should have been prefilled.");
  var note = await textOf(driver, "srd_dec_key_note");
  assert.ok(/Nothing was prefilled/.test(note),
    "an empty prefill must explain itself: " + note);
  assert.ok(/turned off there/.test(note),
    "the note must name the opt-out on the SAML Test Tools page as one of " +
    "the two reasons: " + note);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_response_decoder.loadSpKeyPair(')]"));
  assert.ok(/No SP key pair is stored/.test(
    await value(driver, "srd_dec_status")),
    "Load SP key pair must say when there is nothing to load: " +
    await value(driver, "srd_dec_status"));
  log.info("[prefill/empty] OK — the absence explains itself.");

  // A pair stored by the SAML Test Tools page, under its own keys.
  await driver.executeScript(
    "localStorage.setItem('samltools_saml_sp_private_key', arguments[0]);" +
    "localStorage.setItem('samltools_saml_sp_public_key', arguments[1]);",
    keyPair.privateKeyPem, keyPair.certPem);
  await openPage(driver);
  await checkBox(driver, "srd_decrypt_enabled", true);
  // Compared with the carriage returns taken out: node-forge writes a PEM
  // with CRLF line endings and the HTML specification requires a textarea's
  // API value to normalise those to LF, so the bytes that come back are
  // legitimately not the bytes that went in.
  assert.strictEqual(pem(await value(driver, "srd_dec_key")),
    pem(keyPair.privateKeyPem),
    "the stored SP private key was not prefilled.");
  assert.strictEqual(pem(await value(driver, "srd_dec_cert")),
    pem(keyPair.certPem),
    "the stored SP certificate was not prefilled.");
  // And the button re-reads rather than only filling an empty field.
  await setInput(driver, "srd_dec_key", "");
  await setInput(driver, "srd_dec_cert", "");
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_response_decoder.loadSpKeyPair(')]"));
  assert.strictEqual(pem(await value(driver, "srd_dec_key")),
    pem(keyPair.privateKeyPem),
    "Load SP key pair did not re-read the stored key.");
  assert.ok(/Loaded the SP key pair/.test(
    await value(driver, "srd_dec_status")),
    "Load SP key pair should say what it did: " +
    await value(driver, "srd_dec_status"));

  // Reading storage must not ADD to it — this page's whole claim about key
  // material is that it never writes any.
  var keys = await driver.executeScript(
    "var out = [];" +
    "for (var i = 0; i < localStorage.length; i++) out.push(localStorage" +
    "    .key(i));" +
    "return out.sort();");
  assert.deepStrictEqual(keys,
    ["samltools_saml_sp_private_key", "samltools_saml_sp_public_key"],
    "the prefill wrote something to storage: " + keys.join(", "));
  await driver.executeScript("window.localStorage.clear();");
  log.info("[prefill/stored] OK — read, re-read, and nothing written.");
  log.debug("Leaving spKeyPairPrefill().");
}

// The hand-off to the shared certificate-details page: both routes to it, the
// value it is handed, and the return link it draws — which is the entry this
// page had to add to saml_cert.js's caller map, and the one thing here that
// no other test in the suite would notice missing.
async function signerCertificateHandoff(driver, keyPair) {
  log.debug("Entering signerCertificateHandoff().");
  log.info("=== The signer certificate hand-off ===");
  await openPage(driver);
  var signed = xd.signEnveloped(
    response20(assertion20("_assertion_cert"), STATUS_SUCCESS_2), {
      privateKeyPem: keyPair.privateKeyPem,
      certPem: keyPair.certPem,
      sigAlg: SIG_ALG_RSA_SHA256,
      placement: "after-issuer"
    });
  await decodeBlob(driver, postBody(signed));
  // The link inside the Details table is GENERATED by the render, and only
  // when a certificate was actually found — so its presence is an assertion
  // about the decode as much as about the link.
  var link = await driver.executeScript(
    "var a = document.querySelector('#srd_details a[onclick*=" +
    "\"viewSignerCert\"]');" +
    "return a ? { href: a.getAttribute('href'), text: a.textContent } : null;");
  assert.ok(link, "a signed response should offer to show its certificate.");
  assert.ok(link.href.indexOf("from=saml_response_decoder.html") > 0,
    "the hand-off must name this page as the caller: " + link.href);

  var before = await driver.getAllWindowHandles();
  await driver.executeScript(
    "document.querySelector('#srd_details a[onclick*=\"viewSignerCert\"]')" +
    ".click();");
  await driver.wait(async function () {
    return (await driver.getAllWindowHandles()).length > before.length;
  }, waitTime, "clicking the certificate link opened no window.");
  var stashed = await driver.executeScript(
    "return localStorage.getItem('saml_cert_view');");
  var expected = keyPair.certPem.replace(/-----[^-]*-----/g, "")
      .replace(/\s+/g, "");
  assert.strictEqual(stashed, expected,
    "the certificate handed over is not the one in the message's KeyInfo.");

  var after = await driver.getAllWindowHandles();
  var opened = after.filter(function (h) { return before.indexOf(h) < 0; })[0];
  await driver.switchTo().window(opened);
  await driver.wait(until.elementLocated(By.id("return_link")), waitTime);
  await waitForCertPage(driver);
  var back = await driver.findElement(By.id("return_link")).getText();
  assert.ok(/SAML Response Decoder/.test(back),
    "the certificate page must offer a way back to THIS page, which is an " +
    "entry in saml_cert.js's caller map that nothing else here would miss: " +
    back);
  var shown = await driver.executeScript(
    "var e = document.getElementById('saml_cert_input');" +
    "return e ? e.value.replace(/\\s+/g, '') : '';");
  assert.ok(shown.indexOf(expected) >= 0,
    "the certificate page did not receive the certificate.");
  await driver.close();
  await driver.switchTo().window(before[0]);
  log.info("[cert] OK — handed over, opened, and linked back.");
  log.debug("Leaving signerCertificateHandoff().");
}

// The certificate page's own bundle, waited for the way openPage() waits for
// this one's: its inline handlers are a browserify global that does not exist
// until the bundle has run.
async function waitForCertPage(driver) {
  log.debug("Entering waitForCertPage().");
  await driver.wait(async function () {
    return driver.executeScript(
      "return typeof window.saml_cert === 'object';");
  }, waitTime, "the saml_cert bundle never defined its global.");
  log.debug("Leaving waitForCertPage().");
}

// The Binding selector, which exists for the blob auto-detection cannot
// settle. Forcing it must WIN over the detection — a user who knows what they
// have should get a straight answer rather than a guess.
async function bindingSelector(driver, keyPair) {
  log.debug("Entering bindingSelector().");
  log.info("=== The Binding selector overrides the detection ===");
  var xml = logoutResponse20(STATUS_SUCCESS_2);
  var b64 = Buffer.from(xml, "utf8").toString("base64");

  // A POST body forced to Redirect: the detection would say POST (the bytes
  // do not inflate), and the selector has to win.
  await openPage(driver);
  await decodeBlob(driver, "SAMLResponse=" + encodeURIComponent(b64),
                   "redirect");
  var params = await tableOf(driver, "srd_params");
  assert.strictEqual(params["Binding"], "HTTP-Redirect",
    "the selector must override the auto-detection: " + params["Binding"]);
  // The message still decodes — forcing the binding changes what is SAID
  // about it, not whether it can be read.
  assert.strictEqual((await tableOf(driver, "srd_details"))["Message Type"],
    "LogoutResponse", "forcing a binding must not stop the decode.");
  assert.ok(/^no/.test(params["DEFLATE-compressed"] || ""),
    "the DEFLATE row reports what the BYTES did, which is the one thing the " +
    "selector cannot change: " + params["DEFLATE-compressed"]);
  log.info("[binding/forced-redirect] OK — the selector wins, the bytes " +
           "still tell the truth.");

  // A deflated redirect message forced to POST.
  await openPage(driver);
  var deflated = zlib.deflateRawSync(Buffer.from(xml, "utf8"))
      .toString("base64");
  await decodeBlob(driver, "SAMLResponse=" + encodeURIComponent(deflated),
                   "post");
  params = await tableOf(driver, "srd_params");
  assert.strictEqual(params["Binding"], "HTTP-POST",
    "the selector must override the auto-detection: " + params["Binding"]);
  assert.ok(/^yes/.test(params["DEFLATE-compressed"] || ""),
    "the bytes were deflated and the row must still say so: " +
    params["DEFLATE-compressed"]);
  log.info("[binding/forced-post] OK.");

  // A BARE artifact with the Artifact binding chosen. classify() has no way
  // to know a bare blob is an artifact — there is no SAMLart= in front of
  // it — so this path exists only because the selector does.
  await openPage(driver);
  var artifact = Buffer.concat([
    Buffer.from([0x00, 0x04, 0x00, 0x01]),
    Buffer.alloc(20, 0x11),
    Buffer.alloc(20, 0x22)
  ]).toString("base64");
  var status = await decodeBlob(driver, artifact, "artifact");
  assert.ok(/artifact/i.test(status),
    "a bare blob with Artifact selected is the artifact itself: " + status);
  var details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["MessageHandle"], "22".repeat(20),
    "the bare artifact was not read: " + details["MessageHandle"]);
  await assertTab(driver, "tab_srd_details", "a forced artifact");
  log.info("[binding/forced-artifact] OK — a bare blob read as an artifact.");
  log.debug("Leaving bindingSelector().");
}

// Arriving with a response already in hand. The three query parameters are the
// only code path on this page that runs without anybody pressing anything, and
// each has to reach the SAME decode rather than a second implementation of it.
async function seededFromQuery(driver, keyPair) {
  log.debug("Entering seededFromQuery().");
  log.info("=== Seeded from the query string ===");
  var xml = response20(assertion20("_assertion_seed"), STATUS_SUCCESS_2);
  var b64 = Buffer.from(xml, "utf8").toString("base64");

  async function openSeeded(query, what) {
    log.debug("Entering openSeeded().");
    await driver.get(baseUrl + "/saml_response_decoder.html?" + query);
    await driver.wait(until.elementLocated(By.id("srd_input")), waitTime);
    await driver.wait(async function () {
      var s = await value(driver, "srd_status");
      return !!s && s.indexOf("Decoding") !== 0 &&
          s.indexOf("Paste a SAML response") !== 0;
    }, cryptoWait, what + ": the page never decoded what it was handed.");
    log.debug("Leaving openSeeded().");
    return value(driver, "srd_status");
  }

  // ?SAMLResponse=, with the parameters that travel beside it.
  var status = await openSeeded("SAMLResponse=" + encodeURIComponent(b64) +
    "&RelayState=" + encodeURIComponent("seeded-relay"), "?SAMLResponse=");
  assert.ok(/Response/.test(status) && /Success/.test(status),
    "?SAMLResponse= should decode on load: " + status);
  var params = await tableOf(driver, "srd_params");
  assert.strictEqual(params["RelayState"], "seeded-relay",
    "the RelayState beside it must be carried into the decode too: " +
    params["RelayState"]);
  assert.strictEqual((await tableOf(driver, "srd_assertions"))["Assertion ID"],
    "_assertion_seed", "the seeded response's assertion was not read.");

  // ?SAMLart=
  var artifact = Buffer.concat([
    Buffer.from([0x00, 0x04, 0x00, 0x07]),
    Buffer.alloc(20, 0x44),
    Buffer.alloc(20, 0x55)
  ]).toString("base64");
  status = await openSeeded("SAMLart=" + encodeURIComponent(artifact),
                            "?SAMLart=");
  assert.ok(/artifact/i.test(status), "?SAMLart= should be read as one: " +
    status);
  assert.strictEqual((await tableOf(driver, "srd_details"))["EndpointIndex"],
    "7", "the seeded artifact was not read.");

  // ?url= — a whole redirect URL, which is what somebody has on a clipboard.
  var url = redirectUrl(logoutResponse20(STATUS_SUCCESS_2), keyPair,
                        "seeded-url-relay");
  status = await openSeeded("url=" + encodeURIComponent(url), "?url=");
  assert.ok(/LogoutResponse/.test(status),
    "?url= should decode the whole URL: " + status);
  params = await tableOf(driver, "srd_params");
  assert.strictEqual(params["Binding"], "HTTP-Redirect",
    "a seeded URL is still classified: " + params["Binding"]);
  assert.strictEqual(params["Endpoint"], SLO_URL,
    "the seeded URL's endpoint was not read: " + params["Endpoint"]);
  // And the signature it carried is still checkable, which is the proof that
  // the seeding went through the ordinary decode rather than around it.
  await setInput(driver, "srd_signer_cert", keyPair.certPem);
  var sig = await validate(driver);
  assert.ok(/1 of 1 signature VALID/.test(sig),
    "a seeded URL's query-string signature should verify: " + sig);
  log.info("[seeded] OK — all three parameters reach the ordinary decode.");
  log.debug("Leaving seededFromQuery().");
}

// What the page says when it CANNOT do the thing. Each of these is a sentence
// somebody reads instead of a result, and a decoder whose refusals are vague
// is one that sends people looking in the wrong place.
async function refusals(driver) {
  log.debug("Entering refusals().");
  log.info("=== The refusals ===");
  await openPage(driver);

  // Nothing pasted.
  var status = await decodeBlob(driver, "");
  assert.ok(/Nothing to decode/.test(status),
    "an empty box should say so: " + status);

  // Binding parameters, but no message among them. This is the shape somebody
  // produces by copying half a form body.
  status = await decodeBlob(driver, "RelayState=abc&SigAlg=whatever");
  assert.ok(/No SAMLResponse/.test(status),
    "a parameter list with no message should say which parameters it " +
    "looked for: " + status);
  assert.ok(/whole value was pasted/.test(status),
    "and should suggest the likely cause: " + status);
  var params = await tableOf(driver, "srd_params");
  assert.strictEqual(params["RelayState"], "abc",
    "what WAS found should still be shown: " + params["RelayState"]);

  // Base64 that decodes to something that is not XML at all.
  status = await decodeBlob(driver, "SAMLResponse=" + encodeURIComponent(
    Buffer.from("this is not xml", "utf8").toString("base64")));
  assert.ok(/not well-formed XML/.test(status),
    "a decode that produced no XML should say so: " + status);
  assert.ok(/bytes are in the XML tab/.test(status),
    "and should say where the bytes went: " + status);
  await assertTab(driver, "tab_srd_xml", "a non-XML decode");
  assert.strictEqual((await value(driver, "srd_xml")).trim(),
    "this is not xml",
    "the undecodable bytes must still be shown: " +
    await value(driver, "srd_xml"));

  // A REQUEST pasted into the response decoder. It decodes — refusing would
  // be unhelpful — but the page has to say which page was written for it.
  var request =
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_areq"' +
    ' Version="2.0" IssueInstant="2026-08-28T12:00:00Z">' +
    '<saml:Issuer>' + SP_ENTITY_ID + '</saml:Issuer></samlp:AuthnRequest>';
  status = await decodeBlob(driver, "SAMLRequest=" + encodeURIComponent(
    Buffer.from(request, "utf8").toString("base64")));
  assert.ok(/AuthnRequest/.test(status),
    "a request pasted here should still decode: " + status);
  params = await tableOf(driver, "srd_params");
  assert.strictEqual(params["Parameter"], "SAMLRequest",
    "the page must say which parameter it found: " + params["Parameter"]);
  var note = await textOf(driver, "srd_params");
  assert.ok(/SAML\s*Request Decoder/.test(note),
    "and must point at the page written for a request: " + note);
  var href = await driver.executeScript(
    "var a = document.querySelector('#srd_params a[href*=" +
    "\"saml_authnrequest.html\"]');" +
    "return a ? a.getAttribute('href') : null;");
  assert.ok(href, "that pointer should be a link, not just words.");
  log.info("[refusals] OK — four refusals, each naming its own cause.");
  log.debug("Leaving refusals().");
}

// A <samlp:ArtifactResponse>, which is an ENVELOPE. Its own Status says only
// whether the artifact resolved; the answer being looked for is the status of
// the message inside it. Reporting the envelope's Success as the result is how
// a debugger reports a failed sign-in as a successful one.
async function artifactResponseEnvelope(driver) {
  log.debug("Entering artifactResponseEnvelope().");
  log.info("=== ArtifactResponse: the envelope is not the answer ===");
  await openPage(driver);
  var inner =
    '<samlp:Response ID="_inner_1" Version="2.0"' +
    ' IssueInstant="2026-08-28T12:00:00Z" InResponseTo="_req_1">' +
    '<saml:Issuer>' + IDP_ENTITY_ID + '</saml:Issuer>' +
    '<samlp:Status><samlp:StatusCode Value="' + STATUS_RESPONDER + '">' +
    '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:' +
    'UnknownPrincipal"/></samlp:StatusCode></samlp:Status>' +
    '</samlp:Response>';
  var envelope =
    '<samlp:ArtifactResponse' +
    ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
    ' ID="_artifact_response_1" Version="2.0"' +
    ' IssueInstant="2026-08-28T12:00:00Z" InResponseTo="_resolve_1">' +
    '<saml:Issuer>' + IDP_ENTITY_ID + '</saml:Issuer>' +
    '<samlp:Status><samlp:StatusCode Value="' + STATUS_SUCCESS_2 +
    '"/></samlp:Status>' + inner + '</samlp:ArtifactResponse>';
  var status = await decodeBlob(driver, postBody(envelope));
  assert.ok(/ArtifactResponse/.test(status),
    "the envelope should be named: " + status);

  // THE TWO TABLES ARE READ SEPARATELY, and that is the point of the case:
  // they carry the same row keys — Message Type, Status Code, Issuer — so a
  // reader that cannot tell them apart is a reader that reports the
  // envelope's Success as the sign-in's.
  var details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["Message Type"], "ArtifactResponse",
    "wrong message type: " + details["Message Type"]);
  assert.strictEqual(details["Status Code"], STATUS_SUCCESS_2,
    "the envelope's own status says the artifact resolved: " +
    details["Status Code"]);
  assert.ok((details["Carried message"] || "").indexOf("Response") === 0,
    "the page must say what the envelope carries: " +
    details["Carried message"]);

  var carried = await tableOf(driver, "srd_carried");
  assert.strictEqual(carried["Message Type"], "Response",
    "the carried message was not described: " + carried["Message Type"]);
  assert.strictEqual(carried["Status Code"], STATUS_RESPONDER,
    "the CARRIED message's status is the answer being looked for: " +
    carried["Status Code"]);
  assert.ok((carried["Sub-status 1"] || "").indexOf("UnknownPrincipal") > 0,
    "the carried message's second-level status is missing: " +
    carried["Sub-status 1"]);
  assert.strictEqual(carried["ID"], "_inner_1",
    "the carried message's own id was not read: " + carried["ID"]);
  var text = await textOf(driver, "srd_carried");
  assert.ok(/is an ENVELOPE/.test(text),
    "the page must say why there are two statuses:\n" + text);
  log.info("[artifactresponse] OK — both statuses, in tables that can be " +
           "told apart.");
  log.debug("Leaving artifactResponseEnvelope().");
}

// More than one assertion, and one of them inside an <saml:Advice> — which is
// SUPPORTING material rather than the subject of the response. An application
// reading its attributes is reading something it was never promised, and a
// decoder that lists it as an ordinary assertion is what lets that happen.
async function severalAssertions(driver, keyPair) {
  log.debug("Entering severalAssertions().");
  log.info("=== Several assertions, one of them advisory ===");
  await openPage(driver);
  var advice =
    '<saml:Advice><saml:Assertion' +
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
    ' ID="_advice_1" Version="2.0" IssueInstant="2026-08-28T12:00:00Z">' +
    '<saml:Issuer>https://third-party.example.com</saml:Issuer>' +
    '<saml:AttributeStatement><saml:Attribute Name="urn:oid:advice">' +
    '<saml:AttributeValue>not-a-promise</saml:AttributeValue>' +
    '</saml:Attribute></saml:AttributeStatement>' +
    '</saml:Assertion></saml:Advice>';
  // The advice goes INSIDE an assertion, which is where saml-core-2.0-os
  // section 2.6.1 puts it.
  var withAdvice = assertion20("_assertion_first")
      .replace("</saml:Assertion>", advice + "</saml:Assertion>");
  var second = assertion20("_assertion_second")
      .replace("alice@decoder-test.example.com",
               "carol@decoder-test.example.com");
  var signedSecond = xd.signEnveloped(second, {
    privateKeyPem: keyPair.privateKeyPem,
    certPem: keyPair.certPem,
    sigAlg: SIG_ALG_RSA_SHA256,
    placement: "after-issuer"
  });
  await decodeBlob(driver,
    postBody(response20(withAdvice + signedSecond, STATUS_SUCCESS_2)));

  var details = await tableOf(driver, "srd_details");
  assert.strictEqual(details["Assertions"], "3",
    "two assertions plus the one in the Advice: " + details["Assertions"]);
  var text = await textOf(driver, "srd_assertions");
  assert.ok(/inside <saml:Advice>/.test(text),
    "the advisory assertion must be labelled as one:\n" + text);
  assert.ok(/SUPPORTING material/.test(text),
    "and the page must say what that means:\n" + text);
  assert.ok(text.indexOf("Assertion 1 of 3") >= 0 &&
            text.indexOf("Assertion 3 of 3") >= 0,
    "each assertion should say which of how many it is:\n" + text);
  assert.ok(text.indexOf("carol@decoder-test.example.com") >= 0,
    "the second assertion's own subject is missing:\n" + text);
  assert.ok(text.indexOf("not-a-promise") >= 0,
    "the advisory assertion's attributes are still SHOWN — labelled, not " +
    "hidden:\n" + text);

  // Only one of the three is signed, and the report has to say which by
  // number rather than as one verdict over the lot.
  var sig = await validate(driver);
  assert.ok(/1 of 1 signature VALID/.test(sig),
    "exactly one of the three assertions is signed: " + sig);
  var sigTable = await tableOf(driver, "srd_sig_details");
  assert.ok(/carries no/.test(sigTable["Assertion 1"] || ""),
    "assertion 1 is unsigned and must be named: " + sigTable["Assertion 1"]);
  assert.ok(/carries no/.test(sigTable["Assertion 2"] || ""),
    "the advisory assertion is unsigned and must be named: " +
    sigTable["Assertion 2"]);
  assert.ok(/^VALID/.test(sigTable["Assertion 3"] || ""),
    "assertion 3 is signed and should verify: " + sigTable["Assertion 3"]);
  log.info("[assertions] OK — three assertions, one advisory, one signed.");
  log.debug("Leaving severalAssertions().");
}

// The wrong recipient certificate. When the sender NAMED a recipient — which
// is what an <xenc:EncryptedKey>'s KeyInfo is for — and the key supplied is
// somebody else's, this is the only place that can say why the decryption
// failed: forge's message for a key that cannot unwrap is "could not unwrap
// the session key", which reads identically to a corrupted message.
async function wrongRecipientCertificate(driver, keyPair) {
  log.debug("Entering wrongRecipientCertificate().");
  log.info("=== A key that is not the one the sender wrapped to ===");
  await openPage(driver);
  var encrypted = xd.encryptXml(assertion20("_assertion_mismatch"),
                                { certPem: keyPair.certPem });
  var response = response20('<saml:EncryptedAssertion xmlns:saml=' +
    '"urn:oasis:names:tc:SAML:2.0:assertion">' + encrypted +
    '</saml:EncryptedAssertion>', STATUS_SUCCESS_2);
  await decodeBlob(driver, postBody(response));
  await checkBox(driver, "srd_decrypt_enabled", true);
  var other = xd.generateKeyPair(2048, "somebody-else");
  await setInput(driver, "srd_dec_key", other.privateKeyPem);
  await setInput(driver, "srd_dec_cert", other.certPem);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_response_decoder.decrypt(')]"));
  await driver.wait(async function () {
    return !!(await value(driver, "srd_dec_status"));
  }, cryptoWait, "the failed decryption never produced a status.");
  var status = await value(driver, "srd_dec_status");
  assert.ok(/failed/i.test(status),
    "the wrong key must fail: " + status);
  assert.ok(/names a different recipient certificate/.test(status),
    "and the page must say WHY, because the crypto library's message for a " +
    "wrong key is indistinguishable from its message for a corrupted one: " +
    status);

  // With the RIGHT certificate beside the right key there is no warning —
  // otherwise the sentence above would appear on every decryption and mean
  // nothing.
  await setInput(driver, "srd_dec_key", keyPair.privateKeyPem);
  await setInput(driver, "srd_dec_cert", keyPair.certPem);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_response_decoder.decrypt(')]"));
  await driver.wait(async function () {
    return /Decrypted/.test(await value(driver, "srd_dec_status") || "");
  }, cryptoWait, "the matching key did not decrypt.");
  status = await value(driver, "srd_dec_status");
  assert.ok(!/different recipient/.test(status),
    "the mismatch warning must not appear when the certificate matches: " +
    status);
  log.info("[mismatch] OK — the warning appears once and only when true.");
  log.debug("Leaving wrongRecipientCertificate().");
}

// LAYOUT, MEASURED WITH CONTENT IN IT. A <pre> or a long unbroken token inside
// a <fieldset> sizes the PANE to its min-content — a base64 blob has made a
// pane 7511px wide in this tree before, and `overflow: auto` never fires
// because the fieldset simply grew. An empty page satisfies every geometry
// check trivially, so this runs after a decode has filled all five tabs, and
// it visits each: a hidden panel has no width at all, so measuring only the
// one on screen measures a fifth of the page.
async function layoutFits(driver, keyPair) {
  log.debug("Entering layoutFits().");
  log.info("=== Layout, with a decoded response in every tab ===");
  await openPage(driver);
  var signed = xd.signEnveloped(
    response20(assertion20("_assertion_layout"), STATUS_SUCCESS_2), {
      privateKeyPem: keyPair.privateKeyPem,
      certPem: keyPair.certPem,
      sigAlg: SIG_ALG_RSA_SHA256,
      placement: "after-issuer"
    });
  await decodeBlob(driver, postBody(signed, "layout-relay"));
  var tabs = ["tab_srd_original", "tab_srd_encrypted", "tab_srd_xml",
              "tab_srd_details", "tab_srd_assertions"];
  for (var i = 0; i < tabs.length; i++) {
    await click(driver, By.id(tabs[i] + "_btn"));
    var geometry = await driver.executeScript(
      "var doc = document.documentElement;" +
      "var over = [];" +
      "var panes = document.getElementsByClassName('saml-pane');" +
      "for (var i = 0; i < panes.length; i++) {" +
      "  var r = panes[i].getBoundingClientRect();" +
      "  if (r.right > doc.clientWidth + 1) over.push((panes[i].id || " +
      "      'pane ' + i) + ' right=' + Math.round(r.right));" +
      "}" +
      "return { scrollW: doc.scrollWidth, clientW: doc.clientWidth," +
      "         over: over };");
    assert.deepStrictEqual(geometry.over, [],
      "on tab " + tabs[i] + " a pane runs past the viewport: " +
      geometry.over.join(", "));
    assert.ok(geometry.scrollW <= geometry.clientW + 1,
      "on tab " + tabs[i] + " the page scrolls sideways: scrollWidth " +
      geometry.scrollW + " > clientWidth " + geometry.clientW);
  }
  // And again with ciphertext, which is the longest unbroken run of
  // characters this page can be given.
  var encrypted = xd.encryptXml(assertion20("_assertion_wide"),
                                { certPem: keyPair.certPem });
  await decodeBlob(driver, postBody(response20(
    '<saml:EncryptedAssertion xmlns:saml=' +
    '"urn:oasis:names:tc:SAML:2.0:assertion">' + encrypted +
    '</saml:EncryptedAssertion>', STATUS_SUCCESS_2)));
  await click(driver, By.id("tab_srd_encrypted_btn"));
  var wide = await driver.executeScript(
    "var doc = document.documentElement;" +
    "return { scrollW: doc.scrollWidth, clientW: doc.clientWidth };");
  assert.ok(wide.scrollW <= wide.clientW + 1,
    "ciphertext made the page scroll sideways: scrollWidth " + wide.scrollW +
    " > clientWidth " + wide.clientW);
  log.info("[layout] OK — nothing overflows on any of the five tabs.");
  log.debug("Leaving layoutFits().");
}

// Nothing on this page may write to the browser console. The inflate that
// separates the two bindings FAILS on every POST message by design, and the
// writable half of a DecompressionStream reports that separately from the
// readable half — left unhandled it is an unhandled rejection on a page that
// worked perfectly.
async function consoleIsClean(driver) {
  log.debug("Entering consoleIsClean().");
  var entries = await driver.manage().logs().get(logging.Type.BROWSER);
  var bad = entries.filter(function (e) {
    return e.level && (e.level.name === "SEVERE" || e.level.name === "ERROR");
  }).map(function (e) { return e.message; });
  // A favicon that did not load, and the other network noise every page in
  // this suite produces, is not this page's doing — the shared filter drops
  // exactly those.
  bad = browserFlags.withoutTransientLoadErrors(bad);
  assert.deepStrictEqual(bad, [],
    "the browser console must be clean.");
  log.info("[console] OK — no errors from " + entries.length + " entries.");
  log.debug("Leaving consoleIsClean().");
}

async function decoderActivities(driver) {
  log.debug("Entering decoderActivities().");
  log.info("Generating a test key pair (pure-JS RSA — this takes a moment).");
  var keyPair = xd.generateKeyPair(2048, "response-decoder-test");
  await post20BothSignatures(driver, keyPair);
  await oneSignatureIsNotTheOther(driver, keyPair);
  await saml11Response(driver);
  await failureResponse(driver);
  await redirectLogoutResponse(driver, keyPair);
  await encryptedAssertion(driver, keyPair);
  await wrongRecipientCertificate(driver, keyPair);
  await artifactBinding(driver);
  await artifactResponseEnvelope(driver);
  await bareAssertion(driver, keyPair);
  await severalAssertions(driver, keyPair);
  await bindingSelector(driver, keyPair);
  await seededFromQuery(driver, keyPair);
  await refusals(driver);
  await paneControls(driver, keyPair);
  await spKeyPairPrefill(driver, keyPair);
  await signerCertificateHandoff(driver, keyPair);
  await optionalAndPrivate(driver, keyPair);
  await layoutFits(driver, keyPair);
  await reachableFromToolsPanes(driver);
  await expandCollapseAll(driver);
  await consoleIsClean(driver);
  log.debug("Leaving decoderActivities().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  // The tests image gives Chrome no user namespaces for its sandbox and
  // docker's default 64MB /dev/shm, which a renderer outgrows. Without these
  // two the browser exits during startup and chromedriver reports
  // `session not created: ... DevToolsActivePort file doesn't exist`, which
  // names neither flag — and a host run passes.
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  // Date.now() alone is NOT unique: run-report.js runs jobs in a pool, and two
  // starting in the same millisecond would share a profile — one Chrome then
  // refuses to start on the other's.
  options.addArguments("--user-data-dir=/tmp/saml-respdec-chrome-" +
                       Date.now() + "-" + process.pid);
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  options.setLoggingPrefs(prefs);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    log.info("Starting Test run.");
    await driver.manage().deleteAllCookies();
    await decoderActivities(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
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
  .name("saml_response_decoder_page")
  .description("Run the SAML Response Decoder UI test (no IdP required).")
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
    test();
  });
program.parse();
