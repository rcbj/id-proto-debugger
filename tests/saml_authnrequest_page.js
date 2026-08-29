// File: saml_authnrequest_page.js
//
// The SAML Request Decoder (saml_authnrequest.html) — decode, validate,
// decrypt, on all three bindings.
//
// NO IDENTITY PROVIDER IS NEEDED and that is the point of the page: it reads a
// request somebody else built. Every fixture below is built HERE, in node, by
// the same two modules the page uses — common/xmldsig.js for the cryptography
// and client/src/saml_message.js for the wire format — so a fixture is a real
// message rather than a recorded string that can rot.
//
// WHAT THIS TEST IS ACTUALLY FOR, because most of it would pass with the
// signature check deleted:
//
//   1. THE REDIRECT SIGNATURE, AND SPECIFICALLY THE TAMPER CASE. A
//      redirect-binding signature is over the query string AS SENT
//      (saml-bindings-2.0-os section 3.4.4.1) — ordered, percent-encoded,
//      Signature itself excluded. A decoder that rebuilds those octets from
//      values it has decoded, or in its own order, reports INVALID on a
//      perfectly good signature, and in a browser that is indistinguishable
//      from a wrong certificate. So this asserts BOTH directions: a good
//      signature verifies, and a message with one parameter altered does not.
//      An assertion that only checks the first passes with the octets rebuilt
//      any which way, as long as they are rebuilt consistently.
//
//   2. THE TWO SIGNATURES ARE IN DIFFERENT PLACES. POST puts an enveloped
//      <ds:Signature> in the document; Redirect puts a detached one in the
//      query and the document inside is unsigned. Running the XML check on a
//      Redirect message reports "no signature" on a message that is signed.
//
//   3. THE KEY IS NEVER STORED. This page takes a private key, which no other
//      page in this family does without the localStorage opt-out the repo-root
//      CLAUDE.md describes. It has no opt-out because it never writes: that is
//      a claim in the page's own prose, and prose is not a check. So the key
//      is pasted, used, and then every localStorage and sessionStorage value
//      is searched for it.
//
//   4. THE CONSOLE IS CLEAN. The inflate that separates the two bindings is
//      EXPECTED to fail on every POST message, and the writable side of a
//      DecompressionStream reports that failure separately from the readable
//      side. Left alone it is an unhandled rejection on a page that worked —
//      which is what the copy of this decoder in saml_response.js did.
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
var log = bunyan.createLogger({ name: "saml_authnrequest_page",
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
const IDP_SSO = "https://decoder-test.example.com/idp/sso";
const ACS_URL = "https://decoder-test.example.com/sp/acs";

// A complete AuthnRequest — every field the Details table claims to show, so
// that "the table rendered" and "the table rendered the right thing" are
// different assertions.
function authnRequestXml() {
  log.debug("Entering authnRequestXml().");
  var xml =
    '<samlp:AuthnRequest' +
    ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
    ' ID="_decoder_test_1" Version="2.0"' +
    ' IssueInstant="2026-08-27T12:00:00Z"' +
    ' Destination="' + IDP_SSO + '"' +
    ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"' +
    ' AssertionConsumerServiceURL="' + ACS_URL + '"' +
    ' ForceAuthn="true" IsPassive="false" ProviderName="Decoder Test">' +
    '<saml:Issuer>' + SP_ENTITY_ID + '</saml:Issuer>' +
    '<samlp:NameIDPolicy' +
    ' Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"' +
    ' SPNameQualifier="' + SP_ENTITY_ID + '" AllowCreate="true"/>' +
    '<samlp:RequestedAuthnContext Comparison="exact">' +
    '<saml:AuthnContextClassRef>' +
    'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' +
    '</saml:AuthnContextClassRef>' +
    '</samlp:RequestedAuthnContext>' +
    '</samlp:AuthnRequest>';
  log.debug("Leaving authnRequestXml().");
  return xml;
}

// The redirect binding, built exactly as saml_request.js builds it: DEFLATE
// then base64 then percent-encode, sign the query string with SigAlg already
// appended, and put Signature on the end.
function redirectUrl(xml, keyPair, relayState) {
  log.debug("Entering redirectUrl().");
  var deflated = zlib.deflateRawSync(Buffer.from(xml, "utf8"))
      .toString("base64");
  var qs = "SAMLRequest=" + encodeURIComponent(deflated);
  if (relayState) qs += "&RelayState=" + encodeURIComponent(relayState);
  qs += "&SigAlg=" + encodeURIComponent(SIG_ALG_RSA_SHA256);
  var sig = xd.signQueryString(qs, { privateKeyPem: keyPair.privateKeyPem,
                                     sigAlg: SIG_ALG_RSA_SHA256 });
  var url = IDP_SSO + "?" + qs + "&Signature=" + encodeURIComponent(sig);
  log.debug("Leaving redirectUrl().");
  return url;
}

// The POST binding: an enveloped signature inside the document, base64, NOT
// compressed. What a form body looks like once it reaches a proxy log.
function postBody(xml, keyPair) {
  log.debug("Entering postBody().");
  var signed = xd.signEnveloped(xml, {
    privateKeyPem: keyPair.privateKeyPem,
    certPem: keyPair.certPem,
    sigAlg: SIG_ALG_RSA_SHA256,
    placement: "after-issuer"
  });
  var body = "SAMLRequest=" +
      encodeURIComponent(Buffer.from(signed, "utf8").toString("base64")) +
      "&RelayState=" + encodeURIComponent("post-relay");
  log.debug("Leaving postBody().");
  return { body: body, signed: signed };
}

// A SAML 2.0 type 0x0004 artifact, base64, on a GET.
function artifactUrl() {
  log.debug("Entering artifactUrl().");
  var bytes = Buffer.concat([
    Buffer.from([0x00, 0x04, 0x00, 0x02]),
    Buffer.alloc(20, 0x5a),
    Buffer.alloc(20, 0xa5)
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
  // sendKeys on a multi-kilobyte PEM or redirect URL is minutes of typing, so
  // the value is set directly and the change event dispatched by hand.
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

// The Details / Binding-parameters tables as a plain key -> value object.
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
  await driver.get(baseUrl + "/saml_authnrequest.html");
  await driver.wait(until.elementLocated(By.id("sar_input")), waitTime);
  // The inline handlers are the browserify --standalone global, which does not
  // exist until the bundle has run — a click before then is a silent no-op.
  await driver.wait(async function () {
    return driver.executeScript(
      "return typeof window.saml_authnrequest === 'object' && " +
      "typeof window.saml_authnrequest.decode === 'function';");
  }, waitTime, "the saml_authnrequest bundle never defined its global.");
  log.debug("Leaving openPage().");
}

// Decode a blob and wait for the status line to settle. Waiting on CONTENT
// rather than on an element: the decode is asynchronous (the inflate is a
// stream), so the elements are all present before the answer is.
async function decodeBlob(driver, blob, binding) {
  log.debug("Entering decodeBlob().");
  await setInput(driver, "sar_input", blob);
  if (binding) {
    await new Select(driver.findElement(By.id("sar_binding")))
        .selectByValue(binding);
  }
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_authnrequest.decode(')]"));
  await driver.wait(async function () {
    var s = await value(driver, "sar_status");
    return !!s && s.indexOf("Decoding") !== 0;
  }, cryptoWait, "the decode never produced a status.");
  var status = await value(driver, "sar_status");
  log.debug("Leaving decodeBlob().");
  return status;
}

async function validate(driver) {
  log.debug("Entering validate().");
  await checkBox(driver, "sar_verify_enabled", true);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_authnrequest.validateSignature(')]"));
  await driver.wait(async function () {
    return !!(await value(driver, "sar_sig_status"));
  }, cryptoWait, "the signature check never produced a status.");
  var status = await value(driver, "sar_sig_status");
  log.debug("Leaving validate(). " + status);
  return status;
}

// ---------------------------------------------------------------------------
// The cases.
// ---------------------------------------------------------------------------
async function redirectBinding(driver, keyPair, xml) {
  log.debug("Entering redirectBinding().");
  log.info("=== HTTP-Redirect: decode, then verify the query-string " +
           "signature ===");
  await openPage(driver);
  var url = redirectUrl(xml, keyPair, "redirect-relay");
  var status = await decodeBlob(driver, url);
  assert.ok(/AuthnRequest/.test(status),
    "the status should name the decoded message. Found: " + status);

  var params = await tableOf(driver, "sar_params");
  assert.strictEqual(params["Binding"], "HTTP-Redirect",
    "a GET carrying SAMLRequest is the Redirect binding. Found: " +
    params["Binding"]);
  assert.ok(/^yes/.test(params["DEFLATE-compressed"] || ""),
    "a Redirect message is DEFLATE-compressed. Found: " +
    params["DEFLATE-compressed"]);
  assert.strictEqual(params["RelayState"], "redirect-relay",
    "the RelayState was not read off the query: " + params["RelayState"]);
  assert.strictEqual(params["Endpoint"], IDP_SSO,
    "the endpoint the request was aimed at was not shown: " +
    params["Endpoint"]);

  // The XML tab holds the message that was actually compressed. Compare on
  // content rather than byte-for-byte: what is shown is pretty-printed.
  var shown = await value(driver, "sar_xml");
  assert.ok(shown.indexOf("<samlp:AuthnRequest") >= 0 &&
            shown.indexOf(SP_ENTITY_ID) >= 0,
    "the inflated AuthnRequest is not in the XML tab.");
  assert.ok(/\n/.test(shown), "the XML tab should be pretty-printed.");

  var details = await tableOf(driver, "sar_details");
  assert.strictEqual(details["Message Type"], "AuthnRequest",
    "wrong message type: " + details["Message Type"]);
  assert.strictEqual(details["SAML Version"], "2.0",
    "wrong version: " + details["SAML Version"]);
  assert.strictEqual(details["ID"], "_decoder_test_1",
    "wrong ID: " + details["ID"]);
  assert.strictEqual(details["Destination"], IDP_SSO,
    "wrong Destination: " + details["Destination"]);
  assert.strictEqual(details["Issuer"], SP_ENTITY_ID,
    "wrong Issuer: " + details["Issuer"]);
  assert.strictEqual(details["AssertionConsumerServiceURL"], ACS_URL,
    "wrong ACS URL: " + details["AssertionConsumerServiceURL"]);
  assert.strictEqual(details["ForceAuthn"], "true",
    "wrong ForceAuthn: " + details["ForceAuthn"]);
  assert.ok(/PasswordProtectedTransport/
    .test(details["AuthnContext Class/Decl Refs"] || ""),
    "the RequestedAuthnContext class ref is missing: " +
    details["AuthnContext Class/Decl Refs"]);
  // The document inside a Redirect message is NOT signed — the signature is
  // in the query string — and the table must say so rather than imply the
  // message is unsigned.
  assert.ok(/no enveloped/.test(details["Signature"] || ""),
    "a Redirect message's document carries no enveloped signature: " +
    details["Signature"]);
  log.info("[redirect/decode] OK — inflated, classified and summarised.");

  // --- the signature, both ways -------------------------------------------
  await setInput(driver, "sar_signer_cert", keyPair.certPem);
  var sig = await validate(driver);
  assert.ok(/VALID/.test(sig) && !/INVALID/.test(sig),
    "the query-string signature should verify. Found: " + sig);
  var sigTable = await tableOf(driver, "sar_sig_details");
  assert.strictEqual(sigTable["SigAlg"], SIG_ALG_RSA_SHA256,
    "the SigAlg was not reported: " + sigTable["SigAlg"]);
  assert.ok((sigTable["Signed octets"] || "").indexOf("SAMLRequest=") === 0,
    "the signed octets must start with SAMLRequest=, in the order sent: " +
    sigTable["Signed octets"]);
  assert.ok(/SigAlg=[^&]+$/.test(sigTable["Signed octets"] || ""),
    "SigAlg is the last signed parameter and Signature is excluded: " +
    sigTable["Signed octets"]);
  log.info("[redirect/signature] OK — VALID over the octets as sent.");

  // THE TAMPER CASE. One parameter altered, everything else identical: this
  // is what a decoder that rebuilds the octets its own way cannot tell from
  // the good message above.
  var tampered = url.replace("RelayState=redirect-relay",
                             "RelayState=redirect-relaX");
  assert.notStrictEqual(tampered, url, "the tamper did not change the URL.");
  await decodeBlob(driver, tampered);
  await setInput(driver, "sar_signer_cert", keyPair.certPem);
  sig = await validate(driver);
  assert.ok(/INVALID/.test(sig),
    "an altered RelayState must fail the signature. Found: " + sig);
  log.info("[redirect/tamper] OK — an altered parameter is INVALID.");

  // And with no certificate there is nothing to verify against — a detached
  // signature carries no KeyInfo, and the refusal has to say that rather than
  // report a failure.
  await decodeBlob(driver, url);
  await setInput(driver, "sar_signer_cert", "");
  sig = await validate(driver);
  assert.ok(/detached|certificate/.test(sig) && !/\bVALID\b/.test(sig),
    "with no certificate the page must say why it cannot check: " + sig);
  log.info("[redirect/nokey] OK — refused for the right reason.");
  log.debug("Leaving redirectBinding().");
}

async function postBinding(driver, keyPair, xml) {
  log.debug("Entering postBinding().");
  log.info("=== HTTP-POST: decode, then verify the enveloped signature ===");
  await openPage(driver);
  var post = postBody(xml, keyPair);
  var status = await decodeBlob(driver, post.body);
  assert.ok(/AuthnRequest/.test(status), "wrong status: " + status);

  var params = await tableOf(driver, "sar_params");
  assert.strictEqual(params["Binding"], "HTTP-POST",
    "a form body with no SigAlg is the POST binding. Found: " +
    params["Binding"]);
  assert.ok(/^no/.test(params["DEFLATE-compressed"] || ""),
    "the POST binding does not compress. Found: " +
    params["DEFLATE-compressed"]);

  var details = await tableOf(driver, "sar_details");
  assert.strictEqual(details["Message Type"], "AuthnRequest",
    "wrong message type: " + details["Message Type"]);
  assert.ok(/present/.test(details["Signature"] || ""),
    "the enveloped signature was not reported: " + details["Signature"]);
  assert.strictEqual(details["Signature Method"], SIG_ALG_RSA_SHA256,
    "wrong signature method: " + details["Signature Method"]);
  assert.ok(/present/.test(details["KeyInfo certificate"] || ""),
    "the KeyInfo certificate was not reported: " +
    details["KeyInfo certificate"]);

  // No certificate pasted: a POST signature carries its own in KeyInfo, which
  // is the whole difference from the redirect case above.
  await setInput(driver, "sar_signer_cert", "");
  var sig = await validate(driver);
  assert.ok(/VALID/.test(sig) && !/INVALID/.test(sig),
    "the enveloped signature should verify from its own KeyInfo. Found: " +
    sig);
  var sigTable = await tableOf(driver, "sar_sig_details");
  assert.strictEqual(sigTable["SignatureValue"], "verified",
    "the SignatureValue was not verified: " + sigTable["SignatureValue"]);
  assert.ok(/match \(1\)/.test(sigTable["Reference digests"] || ""),
    "the reference digest was not checked: " + sigTable["Reference digests"]);
  log.info("[post/signature] OK — VALID from the document's own KeyInfo.");

  // A byte changed inside the signed document must fail. The ID is in the
  // signed subtree and in the Reference URI, so this is a digest failure —
  // the half of the check the SignatureValue alone would not catch.
  var broken = post.signed.replace("Decoder Test", "Decoder Tesx");
  assert.notStrictEqual(broken, post.signed, "the tamper changed nothing.");
  await decodeBlob(driver, "SAMLRequest=" +
    encodeURIComponent(Buffer.from(broken, "utf8").toString("base64")));
  sig = await validate(driver);
  assert.ok(/INVALID/.test(sig),
    "an altered signed document must fail. Found: " + sig);
  log.info("[post/tamper] OK — an altered document is INVALID.");
  log.debug("Leaving postBinding().");
}

async function encryptedRequest(driver, keyPair, xml) {
  log.debug("Entering encryptedRequest().");
  log.info("=== Encrypted: the Encrypted tab, then decryption ===");
  await openPage(driver);
  var encrypted = xd.encryptXml(xml, { certPem: keyPair.certPem });
  var b64 = Buffer.from(encrypted, "utf8").toString("base64");
  var status = await decodeBlob(driver, "SAMLRequest=" +
                                encodeURIComponent(b64));
  assert.ok(/ENCRYPTED/i.test(status),
    "the status must say the message is encrypted. Found: " + status);

  var enc = await value(driver, "sar_encrypted");
  assert.ok(enc.indexOf("EncryptedData") >= 0,
    "the Encrypted tab should hold the <xenc:EncryptedData>.");
  assert.ok(enc.indexOf("CipherValue") >= 0,
    "the Encrypted tab should hold the ciphertext.");

  var details = await tableOf(driver, "sar_details");
  assert.strictEqual(details["Message Type"], "EncryptedData",
    "an encrypted message's type is EncryptedData: " +
    details["Message Type"]);
  assert.ok(/aes/.test(details["Encryption (data)"] || ""),
    "the data encryption algorithm was not reported: " +
    details["Encryption (data)"]);
  assert.ok(/rsa/.test(details["Encryption (key transport)"] || ""),
    "the key transport algorithm was not reported: " +
    details["Encryption (key transport)"]);
  // Nothing about the request can be shown yet, and the table must not invent
  // it: an AuthnRequest row here would be a value read off ciphertext.
  assert.ok(details["Issuer"] === undefined,
    "an encrypted message has no readable Issuer yet: " + details["Issuer"]);
  log.info("[encrypted/decode] OK — ciphertext described, not guessed.");

  // --- decrypt -------------------------------------------------------------
  await checkBox(driver, "sar_decrypt_enabled", true);
  await setInput(driver, "sar_dec_key", keyPair.privateKeyPem);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_authnrequest.decrypt(')]"));
  await driver.wait(async function () {
    return !!(await value(driver, "sar_dec_status"));
  }, cryptoWait, "the decryption never produced a status.");
  var decStatus = await value(driver, "sar_dec_status");
  assert.ok(/Decrypted/.test(decStatus),
    "the decryption should succeed. Found: " + decStatus);

  var shown = await value(driver, "sar_xml");
  assert.ok(shown.indexOf("<samlp:AuthnRequest") >= 0,
    "the plaintext AuthnRequest should replace the ciphertext in the XML " +
    "tab.");
  details = await tableOf(driver, "sar_details");
  assert.strictEqual(details["Message Type"], "AuthnRequest",
    "the Details table should re-render from the plaintext: " +
    details["Message Type"]);
  assert.strictEqual(details["Issuer"], SP_ENTITY_ID,
    "the plaintext Issuer was not read: " + details["Issuer"]);
  log.info("[encrypted/decrypt] OK — plaintext in both the XML and Details.");

  // --- the wrong key fails, and says so ------------------------------------
  await openPage(driver);
  await decodeBlob(driver, "SAMLRequest=" + encodeURIComponent(b64));
  await checkBox(driver, "sar_decrypt_enabled", true);
  var other = xd.generateKeyPair(2048, "not-the-recipient");
  await setInput(driver, "sar_dec_key", other.privateKeyPem);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_authnrequest.decrypt(')]"));
  await driver.wait(async function () {
    return !!(await value(driver, "sar_dec_status"));
  }, cryptoWait, "the failed decryption never produced a status.");
  decStatus = await value(driver, "sar_dec_status");
  assert.ok(/failed/i.test(decStatus),
    "the wrong key must fail rather than silently do nothing: " + decStatus);
  log.info("[encrypted/wrongkey] OK — refused.");
  log.debug("Leaving encryptedRequest().");
}

async function artifactBinding(driver) {
  log.debug("Entering artifactBinding().");
  log.info("=== HTTP-Artifact: 44 bytes that reference a message ===");
  await openPage(driver);
  var status = await decodeBlob(driver, artifactUrl());
  assert.ok(/artifact/i.test(status),
    "the status should say it read an artifact. Found: " + status);

  var params = await tableOf(driver, "sar_params");
  assert.strictEqual(params["Binding"], "HTTP-Artifact",
    "a GET carrying SAMLart is the Artifact binding. Found: " +
    params["Binding"]);

  var details = await tableOf(driver, "sar_details");
  assert.ok(/0x0004/.test(details["Artifact Type"] || ""),
    "the artifact type was not identified: " + details["Artifact Type"]);
  assert.strictEqual(details["EndpointIndex"], "2",
    "the EndpointIndex was not read: " + details["EndpointIndex"]);
  // startsWith rather than equality: this cell carries the value AND the note
  // explaining what a SourceID is, and textContent returns both.
  assert.ok((details["SourceID"] || "").indexOf("5a".repeat(20)) === 0,
    "the SourceID was not read: " + details["SourceID"]);
  assert.strictEqual(details["MessageHandle"], "a5".repeat(20),
    "the MessageHandle was not read: " + details["MessageHandle"]);
  assert.strictEqual(details["Length"], "44 bytes",
    "a type 0x0004 artifact is 44 bytes: " + details["Length"]);
  // There is no message in an artifact, and the XML tab must stay empty
  // rather than showing the previous decode's.
  assert.strictEqual((await value(driver, "sar_xml")).trim(), "",
    "an artifact carries no message, so the XML tab must be empty.");
  log.info("[artifact] OK — the reference is read; no message is invented.");
  log.debug("Leaving artifactBinding().");
}

async function optionalAndPrivate(driver, keyPair, xml) {
  log.debug("Entering optionalAndPrivate().");
  log.info("=== Both crypto panes are optional, and the key is not stored ===");
  await openPage(driver);
  await driver.executeScript("window.localStorage.clear();" +
                             "window.sessionStorage.clear();");
  await openPage(driver);

  // Off by default, and their bodies genuinely hidden — not merely unstyled.
  assert.strictEqual(
    await driver.findElement(By.id("sar_verify_enabled")).isSelected(), false,
    "signature validation must be off until it is asked for.");
  assert.strictEqual(
    await driver.findElement(By.id("sar_decrypt_enabled")).isSelected(), false,
    "decryption must be off until it is asked for.");
  assert.strictEqual(await paneVisible(driver, "sar_verify_body"), false,
    "the signature pane's body should be hidden while the box is clear.");
  assert.strictEqual(await paneVisible(driver, "sar_decrypt_body"), false,
    "the decryption pane's body should be hidden while the box is clear.");

  // A plain unsigned, unencrypted request still decodes with both off, which
  // is what "optional" has to mean.
  var b64 = Buffer.from(xml, "utf8").toString("base64");
  var status = await decodeBlob(driver, b64);
  assert.ok(/AuthnRequest/.test(status),
    "an unsigned, unencrypted request must decode with both panes off: " +
    status);
  var details = await tableOf(driver, "sar_details");
  assert.strictEqual(details["Message Type"], "AuthnRequest",
    "wrong message type: " + details["Message Type"]);
  log.info("[optional] OK — decoding needs neither.");

  await checkBox(driver, "sar_verify_enabled", true);
  assert.strictEqual(await paneVisible(driver, "sar_verify_body"), true,
    "ticking the box must reveal the signature pane.");
  await checkBox(driver, "sar_decrypt_enabled", true);
  assert.strictEqual(await paneVisible(driver, "sar_decrypt_body"), true,
    "ticking the box must reveal the decryption pane.");

  // THE KEY IS NEVER WRITTEN. Paste it, use it, then search every stored
  // value for any part of it. A substring of the PEM body is used rather than
  // the whole string, because a page that stored a re-wrapped copy would
  // otherwise pass.
  var encrypted = xd.encryptXml(xml, { certPem: keyPair.certPem });
  await decodeBlob(driver, "SAMLRequest=" + encodeURIComponent(
    Buffer.from(encrypted, "utf8").toString("base64")));
  await checkBox(driver, "sar_decrypt_enabled", true);
  await setInput(driver, "sar_dec_key", keyPair.privateKeyPem);
  await setInput(driver, "sar_signer_cert", keyPair.certPem);
  await click(driver, By.xpath(
    "//input[contains(@onclick, 'saml_authnrequest.decrypt(')]"));
  await driver.wait(async function () {
    return /Decrypted/.test(await value(driver, "sar_dec_status") || "");
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
  assert.strictEqual((await value(driver, "sar_dec_key")).trim(), "",
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
               "wsfed_response.html"];
  for (var i = 0; i < pages.length; i++) {
    await driver.get(baseUrl + "/" + pages[i]);
    await driver.wait(until.elementLocated(By.id("pane_tools")), waitTime);
    var href = await driver.executeScript(
      "var a = document.querySelector('#pane_tools a[href*=" +
      "\"saml_authnrequest.html\"]');" +
      "return a ? a.getAttribute('href') : null;");
    assert.ok(href, "the Tools pane on " + pages[i] +
      " has no link to the SAML Request Decoder.");
    // Follow it: a link to a page that 404s is the failure this catches.
    await driver.get(baseUrl + href.replace(/^\//, "/"));
    await driver.wait(until.elementLocated(By.id("sar_input")), waitTime,
      "the link from " + pages[i] + " did not reach the decoder.");
    var back = await driver.findElement(By.id("return_link")).getText();
    assert.ok(back.length > 0, "the decoder has no return link.");
  }
  log.info("[tools] OK — linked from all " + pages.length + " Tools panes.");
  log.debug("Leaving reachableFromToolsPanes().");
}

// LAYOUT, MEASURED WITH CONTENT IN IT. A <pre> or a long unbroken token inside
// a <fieldset> sizes the PANE to its min-content — a base64 blob has made a
// pane 7511px wide in this tree before, and `overflow: auto` never fires
// because the fieldset simply grew. An empty page satisfies every geometry
// check trivially, so this runs after a decode has filled all four tabs, and
// it visits each tab: a hidden panel has no width at all, so measuring only
// the one on screen measures a quarter of the page.
async function layoutFits(driver, keyPair, xml) {
  log.debug("Entering layoutFits().");
  log.info("=== Layout, with a decoded message in every tab ===");
  await openPage(driver);
  // The encrypted case is the worst one: base64 ciphertext in the Encrypted
  // tab AND long algorithm URIs in the Details table.
  var encrypted = xd.encryptXml(xml, { certPem: keyPair.certPem });
  await decodeBlob(driver, redirectUrl(xml, keyPair, "layout-relay"));
  var tabs = ["tab_sar_original", "tab_sar_encrypted", "tab_sar_xml",
              "tab_sar_details"];
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
  // And again with the ciphertext, which is the longest unbroken run of
  // characters this page can be given.
  await decodeBlob(driver, "SAMLRequest=" + encodeURIComponent(
    Buffer.from(encrypted, "utf8").toString("base64")));
  await click(driver, By.id("tab_sar_encrypted_btn"));
  var wide = await driver.executeScript(
    "var doc = document.documentElement;" +
    "return { scrollW: doc.scrollWidth, clientW: doc.clientWidth };");
  assert.ok(wide.scrollW <= wide.clientW + 1,
    "ciphertext made the page scroll sideways: scrollWidth " + wide.scrollW +
    " > clientWidth " + wide.clientW);
  log.info("[layout] OK — nothing overflows on any of the four tabs.");
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
  var keyPair = xd.generateKeyPair(2048, "decoder-test-sp");
  var xml = authnRequestXml();
  await redirectBinding(driver, keyPair, xml);
  await postBinding(driver, keyPair, xml);
  await encryptedRequest(driver, keyPair, xml);
  await artifactBinding(driver);
  await optionalAndPrivate(driver, keyPair, xml);
  await layoutFits(driver, keyPair, xml);
  await reachableFromToolsPanes(driver);
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
  options.addArguments("--user-data-dir=/tmp/saml-authnreq-chrome-" +
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
  .name("saml_authnrequest_page")
  .description("Run the SAML Request Decoder UI test (no IdP required).")
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
