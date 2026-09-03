const { Builder, By, until } = require("selenium-webdriver");
const browserFlags = require("./browser_flags.js");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

// The certificate authority, the key material and the JWS signer this test
// builds an x5c token with are the PAGE'S OWN modules, not a second
// implementation of any of them: in a checkout they are under client/src, and
// the tests image copies them flat beside these scripts. See module_paths.js.
const modulePaths = require("./module_paths.js");
function clientModule(name) {
  return modulePaths.requireSharedModule(
    [path.join(__dirname, "..", "client", "src", name),
     path.join(__dirname, name)],
    "client/src/" + name);
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'jwt_tools',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata, getAccessTokenAuthCode } =
       require("../common/tests.js")({ By, until, Select, waitTime, log, jwt,
       assert });


// Client-side crypto (key generation, signing, JWE, format conversion) is fast
// but can exceed the 2s element-wait on a busy CI host, so results get a
// generous, separate timeout.
var cryptoWait = Math.max(waitTime, 15000);

// Loaded after `log` exists, because requireSharedModule() reports a missing
// COPY through its own logger.
const keyMaterial = clientModule("key_material.js");
const x509 = clientModule("x509.js");
const jwsLib = clientModule("jws.js");
const cryptoBytes = clientModule("crypto_bytes.js");

function decodeJWT(jwt_) {
  log.debug("Entering decodeJWT().");
  log.debug("Leaving decodeJWT().");
  return jwt.decode(jwt_, { complete: true });
}

// ===========================================================================
// OIDC Authorization Code flow (adapted from oidc_authorization_code.js) — used
// only to obtain a real ID Token to feed into the JWT Tools "Encoded JWT" box.
// ===========================================================================

async function getIDToken(driver) {
  log.debug("Entering getIDToken().");
  log.info("Entering getIDToken().");
  var token_id_token = By.id("token_id_token");
  await driver.wait(until.elementLocated(token_id_token), waitTime);
  log.debug("Leaving getIDToken().");
  return await driver.findElement(token_id_token).getAttribute("value");
}

// ===========================================================================
// JWT Tools UI helpers
// ===========================================================================
async function click(driver, locator) {
  log.debug("Entering click().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", el);
  await el.click();
  log.debug("Leaving click().");
}

async function setInput(driver, locator, text) {
  log.debug("Entering setInput().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await el.clear();
  await el.sendKeys(text);
  log.debug("Leaving setInput().");
}

async function getValue(driver, locator) {
  log.debug("Entering getValue().");
  log.debug("Leaving getValue().");
  return await driver.findElement(locator).getAttribute("value");
}

// Wait until a field's value satisfies pred(value), then return the value.
async function waitForValue(driver, locator, pred, msg, timeout) {
  log.debug("Entering waitForValue().");
  await driver.wait(async function () {
    try {
      var v = await driver.findElement(locator).getAttribute("value");
      return pred(v || "");
    } catch (e) {
      return false;
    }
  }, timeout || cryptoWait, msg);
  log.debug("Leaving waitForValue().");
  return await getValue(driver, locator);
}

// Click a toggle-switch by its wrapping <label> (the checkbox itself is
// display:none, so it is not directly clickable).
async function clickToggle(driver, checkboxId) {
  log.debug("Entering clickToggle().");
  await click(driver, By.xpath("//label[.//input[@id='" + checkboxId + "']]"));
  log.debug("Leaving clickToggle().");
}

function onclickBtn(fn) {
  log.debug("Entering onclickBtn().");
  // Match on a substring rather than the exact attribute: the deployed static
  // site is HTML-minified, which strips the trailing ";" from inline handlers
  // ("...addClaim();" -> "...addClaim()"). The "jwt_tools.<fn>(" fragment is
  // present and unique in both the minified and unminified builds.
  log.debug("Leaving onclickBtn().");
  return By.xpath("//input[contains(@onclick, \"jwt_tools." + fn + "(\")]");
}

async function addCustomClaim(driver, name, value, type) {
  log.debug("Entering addCustomClaim().");
  log.info("Adding custom claim: name=" + name + ", value=" + value +
           ", type=" + type);
  await setInput(driver, By.id("custom_claim_name"), name);
  await setInput(driver, By.id("custom_claim_value"), value);
  await new Select(driver.findElement(By.id("custom_claim_type")))
                   .selectByValue(type);
  await new Select(driver.findElement(By.id("custom_claim_target")))
                   .selectByValue("jwt_tools_payload");
  await click(driver, onclickBtn("addClaim"));
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf('"' + name + '"') !== -1; },
    "Claim '" + name + "' was not added to the JWT Payload.");
  log.debug("Leaving addCustomClaim().");
}

// The original JWT Tools coverage: open Tools from the debugger, add claims,
// check compliance, sign + X.509-verify, and encrypt + decrypt.
async function jwtToolsActivities(driver) {
  log.debug("Entering jwtToolsActivities().");
  log.info("Navigate back to oauth2_oidc_1.html.");
  await driver.get(baseUrl + "/oauth2_oidc_1.html");

  log.info("Expand the Tools pane.");
  await click(driver, By.id("tools_expand_button"));

  log.info("Click the JWT Tools link.");
  var jwtToolsLink =
      By.css('a[href="/jwt_tools.html?from=oauth2_oidc_1.html"]');
  await driver.wait(until.elementLocated(jwtToolsLink), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(jwtToolsLink)),
                    waitTime);
  await click(driver, jwtToolsLink);

  log.info("Wait for JWT Tools page to load.");
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf('"iss"') !== -1; },
    "JWT Tools page did not load / default payload not populated.");

  // ---- Pane 1: add custom claims + RFC compliance -------------------------
  await addCustomClaim(driver, "customString", "hello world", "string");
  await addCustomClaim(driver, "customNumber", "42", "number");
  await addCustomClaim(driver, "customBool", "true", "boolean");

  log.info("Click Check RFC Compliance.");
  await click(driver, onclickBtn("checkCompliance"));
  var compliance = await waitForValue(driver, By.id("compliance_output"),
    function (v) { return v.indexOf("PASS") !== -1; },
    "Compliance output was not produced.");
  log.info("Compliance output:\n" + compliance);
  assert.ok(compliance.indexOf("PASS") !== -1,
            "Expected at least one PASS in compliance output.");
  assert.ok(compliance.indexOf("FAIL") === -1,
            "Compliance output contained a FAIL:\n" + compliance);
  log.info("Compliance check passed with no FAIL entries.");

  // ---- Pane 1: generate an RFC 9068 access token, then validate it --------
  // "Generate RFC 9068 Token" overwrites the Header/Payload/Encoded fields with
  // a sample OAuth2 JWT access token; "RFC 9068 Compliance" must then pass.
  log.info("Generate RFC 9068 access token.");
  await click(driver, onclickBtn("generateRfc9068Token"));
  await waitForValue(driver, By.id("jwt_tools_header"),
    function (v) { return v.indexOf('"at+jwt"') !== -1; },
    "Generate RFC 9068 Token did not populate the header with typ \"at+jwt\".");

  log.info("Check RFC 9068 compliance.");
  await click(driver, onclickBtn("checkRfc9068Compliance"));
  // Wait for the RFC 9068 output specifically (distinguishes it from the prior
  // JWT-RFC output already sitting in the box).
  var rfc9068 = await waitForValue(driver, By.id("compliance_output"),
    function (v) { return v.indexOf("RFC 9068") !== -1; },
    "RFC 9068 compliance output was not produced.");
  log.info("RFC 9068 compliance output:\n" + rfc9068);
  assert.ok(rfc9068.indexOf("PASS") !== -1,
            "Expected at least one PASS in RFC 9068 output.");
  assert.ok(rfc9068.indexOf("FAIL") === -1,
            "RFC 9068 compliance reported a FAIL:\n" + rfc9068);
  log.info("RFC 9068 compliance passed with no FAIL entries.");

  // ---- Pane 2: signing (JWS) ----------------------------------------------
  log.info("Generate signing keys.");
  await click(driver, onclickBtn("generateSigningKeys"));
  // Diagnostics: Web Crypto (crypto.subtle) is only available in a secure
  // context. Capture the context/crypto state and any error the page reported.
  await driver.sleep(2000);
  var cryptoDiag = await driver.executeScript(
    "return JSON.stringify({" +
    "  href: location.href," +
    "  isSecureContext: window.isSecureContext," +
    "  cryptoType: (typeof window.crypto)," +
    "  subtleType: (typeof (window.crypto && window.crypto.subtle))," +
    "  signStatus: ((document.getElementById('sign_status') || " +
        "{}).value || '')" +
    "});");
  log.info("CRYPTO DIAG: " + cryptoDiag);
  var diag = JSON.parse(cryptoDiag);
  if (diag.subtleType === "undefined") {
    throw new Error("crypto.subtle is unavailable (isSecureContext=" +
                    diag.isSecureContext +
      ", origin=" + diag.href +
          "). Web Crypto requires a secure context. signStatus=" +
          diag.signStatus);
  }
  await waitForValue(driver, By.id("sign_public_key"),
    function (v) { return v.indexOf("BEGIN PUBLIC KEY") !== -1; },
    "Signing public key (PEM) was not generated. sign_status=" +
        diag.signStatus);

  log.info("Toggle keys to JWK.");
  await clickToggle(driver, "sign_key_jwk");
  await waitForValue(driver, By.id("sign_private_key"),
    function (v) { return v.trim().charAt(0) === "{"; },
    "Signing private key did not convert to JWK.");

  log.info("Toggle keys back to PEM.");
  await clickToggle(driver, "sign_key_jwk");
  await waitForValue(driver, By.id("sign_private_key"),
    function (v) { return v.indexOf("BEGIN PRIVATE KEY") !== -1; },
    "Signing private key did not convert back to PEM.");

  log.info("Download signing keys in PEM format.");
  await new Select(driver.findElement(By.id("sign_ks_format")))
                   .selectByValue("pem");
  await click(driver, onclickBtn("downloadSigningKeys"));
  await waitForValue(driver, By.id("sign_status"),
    function (v) { return v.indexOf("Downloaded PEM") !== -1; },
    "Signing keys were not downloaded in PEM format.");

  log.info("Generate Signed JWT.");
  await click(driver, onclickBtn("signJWT"));
  var signedJwt = await waitForValue(driver, By.id("jwt_tools_signed"),
    function (v) { return v.split(".").length === 3; },
    "Signed JWT was not produced.");
  log.info("Signed JWT produced (" + signedJwt.length + " chars).");

  log.info("Select X.509 verification type.");
  await new Select(driver.findElement(By.id("jwt_verification_type")))
                   .selectByValue("x509");
  await waitForValue(driver, By.id("jwt_verification_key"),
    function (v) { return v.indexOf("BEGIN PUBLIC KEY") !== -1; },
    "X.509 verification key was not auto-populated with the public key.");

  log.info("Verify the signature.");
  await click(driver, onclickBtn("verifyJWT"));
  var verifyOut = await waitForValue(driver, By.id("jwt_verification_output"),
    function (v) { return v.indexOf("Signature Verified:") !== -1; },
    "Verification output was not produced.");
  log.info("Verification output: " + verifyOut);
  assert.ok(verifyOut.indexOf("Signature Verified: true") !== -1,
    "Expected signature verification to succeed. Output: " + verifyOut);
  log.info("Signature verification succeeded.");

  // ---- Pane 3: encryption (JWE) -------------------------------------------
  log.info("Generate encryption keys.");
  await click(driver, onclickBtn("generateEncryptionKeys"));
  await waitForValue(driver, By.id("jwe_public_key"),
    function (v) { return v.indexOf("BEGIN PUBLIC KEY") !== -1; },
    "Encryption public key (PEM) was not generated.");

  log.info("Toggle encryption keys to JWK.");
  await clickToggle(driver, "jwe_key_jwk");
  await waitForValue(driver, By.id("jwe_private_key"),
    function (v) { return v.trim().charAt(0) === "{"; },
    "Encryption private key did not convert to JWK.");

  log.info("Toggle encryption keys back to PEM.");
  await clickToggle(driver, "jwe_key_jwk");
  await waitForValue(driver, By.id("jwe_private_key"),
    function (v) { return v.indexOf("BEGIN PRIVATE KEY") !== -1; },
    "Encryption private key did not convert back to PEM.");

  log.info("Download encryption keys.");
  await click(driver, onclickBtn("downloadEncryptionKeys"));
  await waitForValue(driver, By.id("jwe_status"),
    function (v) { return v.indexOf("Downloaded") !== -1; },
    "Encryption keys were not downloaded.");

  var plaintext = (await getValue(driver, By.id("jwe_plaintext"))).trim();
  assert.ok(plaintext.length > 0, "Payload to Encrypt is empty.");

  log.info("Encrypt the JWT.");
  await click(driver, onclickBtn("encryptJWT"));
  await waitForValue(driver, By.id("jwt_tools_jwe"),
    function (v) { return v.split(".").length === 5; },
    "JWE (5-part compact) was not produced.");

  log.info("Decrypt the JWT.");
  await click(driver, onclickBtn("decryptJWT"));
  var decrypted = await waitForValue(driver, By.id("jwe_decrypt_output"),
    function (v) { return v.trim().length > 0; },
    "Decryption output was not produced.");

  assert.strictEqual(decrypted.trim(), plaintext,
    "Decryption output does not match the Payload to Encrypt value.");
  log.info("Decryption output matches the Payload to Encrypt value.");

  // ---- every key-management algorithm the pane offers ---------------------
  // The steps above exercise whichever alg the page defaults to. That leaves
  // the key-agreement algorithms untested through the page — and they are the
  // ones with the interesting failure mode: ECDH-ES derives its key through the
  // Concat KDF (RFC 7518 section 4.6), where a mistake produces a key that is
  // wrong in a way nothing notices until decryption fails. The JWE code is
  // shared with the OID4VCI issuance panes (client/src/jose_jwe.js), so a
  // wiring mistake here would be a wiring mistake there too.
  var offered = await driver.executeScript(
    "return Array.prototype.slice.call(document.getElementById('jwe_alg').options)" +
    "  .map(function (o) { return { value: o.value, disabled: o.disabled, " +
        "label: o.textContent }; });");
  var algs = offered.filter(function (o) { return !o.disabled; })
      .map(function (o) { return o.value; });
  var unusable = offered.filter(function (o) { return o.disabled; });
  assert.ok(algs.length >= 3,
    "the encryption pane should offer several usable key-management " +
        "algorithms. Got: " +
    JSON.stringify(offered));

  // NOTHING IN EITHER MENU MAY BE GREYED OUT, and that is the reverse of what
  // this test asserted until 2026-08-28. RFC 7518 defines AES-192 and Chrome's
  // Web Crypto refuses it, so ECDH-ES+A192KW, A192GCM and A192CBC-HS384 were
  // marked "unsupported here" and could not be selected. jose_jwe.js performs
  // all three in JavaScript now (symmetric_crypto.js), so the browser's
  // refusal changes which engine runs and nothing a user can see — and greying
  // a registered algorithm this project implements would hide it in the one
  // place somebody looking for it would look.
  //
  // The check is kept rather than deleted, inverted: `encUnsupportedReason()`
  // is still called per option and still has somewhere to put an answer, so an
  // algorithm that genuinely cannot be performed here would still say so. What
  // must not come back is a greyed AES-192.
  var encOptions = await driver.executeScript(
    "return Array.prototype.slice.call(document.getElementById('jwe_enc').options)" +
    "  .map(function (o) { return { value: o.value, disabled: o.disabled, " +
        "label: o.textContent }; });");
  assert.deepStrictEqual(unusable, [],
    "no key-management algorithm should be greyed out: every one this pane " +
        "offers has an implementation in jose_jwe.js. Got: " +
    JSON.stringify(unusable));
  assert.deepStrictEqual(
    encOptions.filter(function (o) { return o.disabled; }), [],
    "and no content encryption algorithm should be greyed out either — " +
        "AES-192 is the one Web Crypto refuses and the one this project " +
        "implements itself. Got: " +
    JSON.stringify(encOptions));
  ["A192GCM", "A192CBC-HS384"].forEach(function (name) {
    var found =
        encOptions.filter(function (o) { return o.value === name; })[0];
    assert.ok(found && !found.disabled && !/unsupported/.test(found.label),
      name + " is what Chrome's Web Crypto will not do and what this page " +
          "must offer anyway. Got: " +
      JSON.stringify(found));
  });
  var encs = encOptions.map(function (o) { return o.value; });
  log.info("Offered and none greyed: alg " + algs.join(", ") + "; enc " +
           encs.join(", "));
  log.info("Round-tripping every usable key-management algorithm: " +
           algs.join(", "));

  for (var i = 0; i < algs.length; i++) {
    var alg = algs[i];
    // Fresh key material per algorithm: RSA-OAEP needs an RSA key and ECDH-ES
    // an EC one, so reusing the previous pair would fail for reasons that have
    // nothing to do with the encryption.
    await driver.executeScript(
      "document.getElementById('jwe_alg').value = arguments[0];", alg);
    await click(driver, onclickBtn("generateEncryptionKeys"));
    await waitForValue(driver, By.id("jwe_status"),
      function (v) { return v.indexOf("Generated") !== -1 ||
                v.indexOf("Error") !== -1; },
      "Key generation for " + alg + " produced no status.");
    var keyStatus = await getValue(driver, By.id("jwe_status"));
    assert.ok(keyStatus.indexOf("Error") === -1,
      "Key generation failed for " + alg + ": " + keyStatus);

    await driver.executeScript(
      "document.getElementById('jwe_decrypt_output').value = '';" +
      "document.getElementById('jwt_tools_jwe').value = '';");
    await click(driver, onclickBtn("encryptJWT"));
    var produced = await waitForValue(driver, By.id("jwt_tools_jwe"),
      function (v) { return v.split(".").length === 5; },
      "No 5-part JWE was produced for " + alg + ".");

    // ECDH-ES "direct" agrees the content key rather than wrapping one, so its
    // encrypted_key segment is empty; every other alg carries a wrapped key.
    var segments = produced.split(".");
    if (alg === "ECDH-ES") {
      assert.strictEqual(segments[1], "",
        "ECDH-ES is direct key agreement, so the encrypted_key segment must " +
            "be empty. Got: " +
        segments[1].slice(0, 40));
    } else {
      assert.ok(segments[1].length > 0,
        alg + " wraps a content encryption key, so encrypted_key must not " +
            "be empty.");
    }
    var header = JSON.parse(Buffer.from(segments[0],
        "base64url").toString("utf8"));
    assert.strictEqual(header.alg, alg,
      "the protected header should name the algorithm used. Got: " +
          JSON.stringify(header));
    if (alg.indexOf("ECDH-ES") === 0) {
      assert.ok(header.epk && header.epk.crv,
        alg + " must publish the ephemeral public key it agreed with " +
            "(epk). Got: " +
        JSON.stringify(header));
    }

    await click(driver, onclickBtn("decryptJWT"));
    var back = await waitForValue(driver, By.id("jwe_decrypt_output"),
      function (v) { return v.trim().length > 0; },
      "No decryption output for " + alg + ".");
    assert.strictEqual(back.trim(), plaintext,
      alg + " did not round-trip: the decrypted text differs from what was " +
          "encrypted.");
    log.info("  " + alg + ": round-tripped" + (header.epk ? " (epk " +
             header.epk.crv + ")" : "") + ".");
  }
  log.info("Every key-management algorithm the pane offers round-trips.");

  // ---- and every CONTENT encryption algorithm it offers -------------------
  // A192GCM and A192CBC-HS384 are why this loop exists. An option that is
  // offered and cannot be performed is worse than one that is greyed, because
  // the failure arrives as an OperationError from inside a key import and
  // names nothing — which is exactly what greying them out used to prevent.
  // So the menu's own list is driven rather than a list typed here, and the
  // protected header is read back: `enc` is chosen by the sender and a page
  // that quietly encrypted with the default would pass every other assertion
  // in this file.
  //
  // ONE key pair for the lot, deliberately. `alg` is what needs fresh key
  // material and it was varied above; here it is held at RSA-OAEP-256 so that
  // what changes between passes is the content encryption and nothing else.
  await driver.executeScript(
    "document.getElementById('jwe_alg').value = 'RSA-OAEP-256';");
  await click(driver, onclickBtn("generateEncryptionKeys"));
  await waitForValue(driver, By.id("jwe_status"),
    function (v) { return v.indexOf("Generated") !== -1 ||
              v.indexOf("Error") !== -1; },
    "Key generation for the content encryption pass produced no status.");
  for (var e = 0; e < encs.length; e++) {
    var enc = encs[e];
    await driver.executeScript(
      "document.getElementById('jwe_enc').value = arguments[0];" +
      "document.getElementById('jwe_decrypt_output').value = '';" +
      "document.getElementById('jwt_tools_jwe').value = '';", enc);
    await click(driver, onclickBtn("encryptJWT"));
    var encProduced = await waitForValue(driver, By.id("jwt_tools_jwe"),
      function (v) { return v.split(".").length === 5; },
      "No 5-part JWE was produced for enc=" + enc + ".");
    var encHeader = JSON.parse(Buffer.from(encProduced.split(".")[0],
        "base64url").toString("utf8"));
    assert.strictEqual(encHeader.enc, enc,
      "the protected header should name the content encryption algorithm " +
          "used. Got: " +
      JSON.stringify(encHeader));
    await click(driver, onclickBtn("decryptJWT"));
    var encBack = await waitForValue(driver, By.id("jwe_decrypt_output"),
      function (v) { return v.trim().length > 0; },
      "No decryption output for enc=" + enc + ".");
    assert.strictEqual(encBack.trim(), plaintext,
      enc + " did not round-trip: the decrypted text differs from what was " +
          "encrypted.");
    log.info("  " + enc + ": round-tripped.");
  }
  log.info("Every content encryption algorithm the pane offers round-trips, " +
           "the two AES-192 ones included.");
  log.debug("Leaving jwtToolsActivities().");
}

// Obtain a real ID Token via the OIDC Authorization Code grant, paste it into
// the JWT Tools "Encoded JWT" field, and confirm the decoded Payload matches.
async function idTokenDecodeActivities(driver, id_token) {
  log.debug("Entering idTokenDecodeActivities().");
  log.info("Navigate to jwt_tools.html to paste the ID Token.");
  await driver.get(baseUrl + "/jwt_tools.html");

  // Wait for the page's own onload to populate the default payload first.
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf("garbage") !== -1; },
    "JWT Tools default payload did not load.");

  log.info("Paste the ID Token into the Encoded JWT field.");
  await driver.executeScript(
    "var el = document.getElementById('jwt_tools_encoded');" +
    "el.value = arguments[0];" +
    "el.dispatchEvent(new Event('input', { bubbles: true }));",
    id_token);

  // The derived payload the field should now show.
  var expectedPayload = JSON.stringify(decodeJWT(id_token).payload, null, 2);

  var actualPayload = await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v === expectedPayload; },
    "JWT Payload field did not match the ID Token's decoded payload.");

  assert.strictEqual(actualPayload, expectedPayload,
    "JWT Payload field does not match the ID Token's derived payload.");
  log.info("JWT Payload field matches the ID Token's derived payload.");

  // The signed ID Token should also have populated the Sign pane fields.
  var signed = await getValue(driver, By.id("jwt_tools_signed"));
  assert.strictEqual(signed, id_token,
                     "Signed JWT field was not populated with the ID Token.");
  var verifyInput = await getValue(driver, By.id("verify_input"));
  assert.strictEqual(verifyInput, id_token,
      "JWT to Verify field was not populated with the ID Token.");
  log.info("Sign pane fields populated from the pasted ID Token.");
  log.debug("Leaving idTokenDecodeActivities().");
}

// The Encoded JWT field takes a FILE as well as a paste, behind a "Load from
// file" checkbox, for tokens too large to paste comfortably — a real 10MB one
// is what prompted it. Two things are asserted here that a paste cannot show:
// that a multi-megabyte token arrives intact and decodes, and that a file over
// the 15MB cap is refused before a byte of it is read, leaving the field
// alone.
async function encodedFileLoadActivities(driver) {
  log.debug("Entering encodedFileLoadActivities().");
  const fileDir = fs.mkdtempSync(path.join(os.tmpdir(),
      "idptools-jwt-upload-"));
  try {
    log.info("Navigate to jwt_tools.html for the file-load pane.");
    await driver.get(baseUrl + "/jwt_tools.html");
    await waitForValue(driver, By.id("jwt_tools_payload"),
      function (v) { return v.indexOf("garbage") !== -1; },
      "JWT Tools default payload did not load.");

    log.info("The chooser is hidden until the checkbox asks for it.");
    var chooser = By.id("jwt_tools_encoded_file");
    var shown = await driver.findElement(chooser).isDisplayed();
    assert.strictEqual(shown, false,
      "The file chooser should be hidden until Load from file is ticked.");

    await click(driver, By.id("jwt_tools_load_from_file"));
    await driver.wait(until.elementIsVisible(driver.findElement(chooser)),
                      waitTime,
                      "Ticking Load from file did not reveal the chooser.");

    // ~2MB of payload: past anything a person would paste, and far enough
    // below the cap that this asserts the loading rather than the limit. The
    // trailing newline is deliberate — a token saved to a file almost always
    // has one, and it must not reach the field, where it would make the last
    // segment fail to decode.
    var big = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" }))
        .toString("base64url") + "." +
        Buffer.from(JSON.stringify({ iss: "https://big.example.com",
                                     sub: "big-subject-1",
                                     data: "x".repeat(2 * 1024 * 1024) }))
            .toString("base64url") + ".";
    var bigPath = path.join(fileDir, "big.jwt");
    fs.writeFileSync(bigPath, big + "\n");
    log.info("Load " + bigPath + " (" + big.length + " chars).");
    await driver.findElement(chooser).sendKeys(bigPath);

    var loaded = await waitForValue(driver, By.id("jwt_tools_sync_status"),
      function (v) { return v.indexOf("Loaded big.jwt") !== -1; },
      "The file was not loaded into the Encoded JWT field.");
    log.info("Status: " + loaded);

    // Read a DESCRIPTION of the field rather than the field: getAttribute
    // would drag the whole multi-megabyte value across the WebDriver wire on
    // every poll.
    var state = await driver.executeScript(
      "var v = document.getElementById('jwt_tools_encoded').value;" +
      "var p = document.getElementById('jwt_tools_payload').value;" +
      "return { length: v.length, tail: v.slice(-1)," +
      " decoded: p.indexOf('big.example.com') !== -1 };");
    assert.strictEqual(state.length, big.length,
      "The Encoded JWT field does not hold the whole token: expected " +
          big.length + " characters, got " + state.length + ".");
    assert.strictEqual(state.tail, ".",
      "The file's trailing newline reached the Encoded JWT field.");
    assert.ok(state.decoded,
      "The loaded token was not decoded into the JWT Payload field.");
    log.info("A 2MB token loaded from a file, intact and decoded.");

    // Over the cap: refused before it is read, and the field keeps what the
    // first file put there.
    var tooBigPath = path.join(fileDir, "too-big.jwt");
    fs.writeFileSync(tooBigPath, Buffer.alloc(16 * 1024 * 1024, 0x41));
    log.info("Offer a 16MB file, which is over the 15MB cap.");
    await driver.findElement(chooser).sendKeys(tooBigPath);
    var refused = await waitForValue(driver, By.id("jwt_tools_sync_status"),
      function (v) { return v.indexOf("Nothing was loaded") !== -1; },
      "The oversize file was not refused.");
    log.info("Status: " + refused);
    assert.ok(refused.indexOf("15.0 MB") !== -1,
      "The refusal should name the 15MB limit. Got: " + refused);
    var after = await driver.executeScript(
      "return document.getElementById('jwt_tools_encoded').value.length;");
    assert.strictEqual(after, big.length,
      "A refused file must leave the Encoded JWT field alone; its length " +
          "changed from " + big.length + " to " + after + ".");
    log.info("The oversize file was refused and the field was left alone.");

    // Unticking hides the chooser again.
    await click(driver, By.id("jwt_tools_load_from_file"));
    await driver.wait(until.elementIsNotVisible(driver.findElement(chooser)),
                      waitTime,
                      "Unticking Load from file did not hide the chooser.");
    log.info("Unticking Load from file hides the chooser again.");
  } finally {
    try {
      fs.rmSync(fileDir, { recursive: true, force: true });
    } catch (e) {
      /* ignore */
    }
  }
  log.debug("Leaving encodedFileLoadActivities().");
}

// A three-tier hierarchy and a token that carries it, built with the page's
// own modules — a Root CA, an Issuing CA beneath it, and a signer certificate
// beneath that, plus an unrelated root for the case where the chain offered
// is somebody else's. P-256 throughout: this asserts what the page does with
// a chain, and an RSA key pair per tier would be most of the test's runtime.
async function buildX5cFixture() {
  log.debug("Entering buildX5cFixture().");
  const rootKey = await keyMaterial.generateKeyPair("ec-p256");
  const caKey = await keyMaterial.generateKeyPair("ec-p256");
  const signerKey = await keyMaterial.generateKeyPair("ec-p256");
  const otherKey = await keyMaterial.generateKeyPair("ec-p256");

  const root = await x509.issueCertificate({
    profile: "root-ca",
    subject: "CN=JWT Tools Test Root CA,O=idptools",
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem,
    signatureAlg: "sha256-ecdsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  const ca = await x509.issueCertificate({
    profile: "issuing-ca",
    subject: "CN=JWT Tools Test Issuing CA,O=idptools",
    subjectPublicKey: caKey.publicPem,
    issuer: { certificatePem: root.pem, privateKeyPem: rootKey.privatePem,
              keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa",
    extensions: x509.defaultExtensions("issuing-ca")
  });
  const signer = await x509.issueCertificate({
    profile: "tls-server",
    subject: "CN=jwt-tools-signer.example,O=idptools",
    subjectPublicKey: signerKey.publicPem,
    issuer: { certificatePem: ca.pem, privateKeyPem: caKey.privatePem,
              keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa",
    extensions: x509.defaultExtensions("tls-server")
  });
  const other = await x509.issueCertificate({
    profile: "root-ca",
    subject: "CN=Somebody Else Root CA,O=elsewhere",
    subjectPublicKey: otherKey.publicPem,
    issuerPrivateKey: otherKey.privatePem,
    signatureAlg: "sha256-ecdsa",
    extensions: x509.defaultExtensions("root-ca")
  });

  // The SAME key, certified for encipherment instead — KeyUsage
  // keyEncipherment and dataEncipherment, and no digitalSignature. A token
  // signed with that key and carrying this certificate verifies
  // cryptographically and must still be refused: the certificate says the
  // key is not for signing, which is a fact no amount of correct arithmetic
  // over the signing input can overrule.
  const noSign = await x509.issueCertificate({
    profile: "key-encipherment",
    subject: "CN=jwt-tools-encipherment-only.example,O=idptools",
    subjectPublicKey: signerKey.publicPem,
    issuer: { certificatePem: ca.pem, privateKeyPem: caKey.privatePem,
              keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa",
    extensions: x509.defaultExtensions("key-encipherment")
  });

  // RFC 7515 section 4.1.6: base64 DER — NOT base64url — signer first, each
  // certificate after it certifying the one before.
  function der64(pem) {
    return cryptoBytes.bytesToB64(cryptoBytes.pemToDer(pem));
  }
  const signed = await jwsLib.signJwsAsync({
    algId: "ES256",
    protectedHeader: { alg: "ES256", typ: "JWT",
        x5c: [der64(signer.pem), der64(ca.pem), der64(root.pem)] },
    payload: { iss: "https://x5c.example.com", sub: "x5c-subject-1" },
    privateKey: signerKey.privatePem
  });
  // Same key, same issuers, same everything — except the certificate at the
  // head of the x5c, which forbids signing.
  const noSignSigned = await jwsLib.signJwsAsync({
    algId: "ES256",
    protectedHeader: { alg: "ES256", typ: "JWT",
        x5c: [der64(noSign.pem), der64(ca.pem), der64(root.pem)] },
    payload: { iss: "https://x5c.example.com", sub: "x5c-subject-2" },
    privateKey: signerKey.privatePem
  });
  log.debug("Leaving buildX5cFixture().");
  return { jwt: signed.serialized, signer: signer.pem, ca: ca.pem,
           root: root.pem, other: other.pem,
           noSignJwt: noSignSigned.serialized, noSign: noSign.pem };
}

// Put a token into the Encoded JWT field the way a paste does. setInput()
// would send it a key at a time, which for a token carrying three
// certificates is thousands of round trips.
async function pasteEncoded(driver, text) {
  log.debug("Entering pasteEncoded().");
  await driver.executeScript(
    "var el = document.getElementById('jwt_tools_encoded');" +
    "el.value = arguments[0];" +
    "el.dispatchEvent(new Event('input', { bubbles: true }));", text);
  log.debug("Leaving pasteEncoded().");
}

// Click Verify and return what the pane says. The output box is emptied
// first, so this waits for THIS click's answer rather than reading the
// previous one back.
async function clickVerify(driver) {
  log.debug("Entering clickVerify().");
  await driver.executeScript(
    "document.getElementById('jwt_verification_output').value = '';");
  await click(driver, onclickBtn("verifyJWT"));
  var out = await waitForValue(driver, By.id("jwt_verification_output"),
    function (v) { return v.trim().length > 0; },
    "Verify produced no output.");
  log.debug("Leaving clickVerify().");
  return out;
}

async function setChainBox(driver, pem) {
  log.debug("Entering setChainBox().");
  await driver.executeScript(
    "document.getElementById('verify_chain_pem').value = arguments[0];", pem);
  log.debug("Leaving setChainBox().");
}

async function setKeyBox(driver, pem) {
  log.debug("Entering setKeyBox().");
  await driver.executeScript(
    "document.getElementById('jwt_verification_key').value = arguments[0];",
    pem);
  log.debug("Leaving setKeyBox().");
}

// x5c, and the trust chain that turns it into an answer.
//
// A certificate a token carries about itself proves nothing on its own — a
// signature that verifies against it says only that the token is internally
// consistent, which is exactly what a forger's own certificate would also
// say. So the assertions below are as much about the FALSE cases as the true
// one: an intact chain missing its root, and a chain belonging to somebody
// else, must both refuse the signature the page has just found to be
// cryptographically valid.
async function x5cTrustChainActivities(driver) {
  log.debug("Entering x5cTrustChainActivities().");
  log.info("Build a Root CA, an Issuing CA, a signer and an x5c token.");
  var fixture = await buildX5cFixture();

  await driver.get(baseUrl + "/jwt_tools.html");
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf("garbage") !== -1; },
    "JWT Tools default payload did not load.");

  log.info("Paste the x5c token into the Encoded JWT field.");
  await pasteEncoded(driver, fixture.jwt);
  await waitForValue(driver, By.id("jwt_verification_key"),
    function (v) { return v.indexOf("BEGIN CERTIFICATE") !== -1; },
    "The header's x5c did not populate the Verification Key field.");

  var type = await getValue(driver, By.id("jwt_verification_type"));
  assert.strictEqual(type, "x509",
    "An x5c should switch the Verification Type to the certificate one. " +
        "Got: " + type);
  var keyField = await getValue(driver, By.id("jwt_verification_key"));
  assert.strictEqual(keyField.trim(), fixture.signer.trim(),
    "The Verification Key field should hold the SIGNER certificate — the " +
        "first entry of x5c — and holds something else.");
  var ticked = await driver.findElement(By.id("verify_chain_enabled"))
      .isSelected();
  assert.ok(ticked,
    "An x5c carrying CA certificates should tick the trust-chain box.");
  var chainShown = await driver.findElement(By.id("verify_chain_field"))
      .isDisplayed();
  assert.ok(chainShown,
    "Ticking the trust-chain box should reveal the CA Trust Chain field.");
  var chainField = await getValue(driver, By.id("verify_chain_pem"));
  assert.strictEqual(chainField.trim(),
    (fixture.ca + fixture.root).trim(),
    "The CA Trust Chain field should hold everything in x5c EXCEPT the " +
        "signer certificate, converted to PEM.");
  log.info("x5c populated the signer certificate and the CA chain " +
           "separately, in PEM.");

  log.info("Verify with the whole chain present.");
  var good = await clickVerify(driver);
  log.info("Verification output:\n" + good);
  assert.ok(good.indexOf("Signature Verified: true") === 0,
    "A signature whose chain reaches a self-signed root should verify. " +
        "Got:\n" + good);
  assert.ok(good.indexOf("trust anchor") !== -1,
    "The output should say the signer certificate reached a trust anchor. " +
        "Got:\n" + good);
  assert.ok(good.indexOf("JWT Tools Test Root CA") !== -1,
    "Every link of the chain should be reported, the root included. Got:\n" +
        good);

  log.info("Verify with the root removed — the chain no longer reaches one.");
  await setChainBox(driver, fixture.ca);
  var noAnchor = await clickVerify(driver);
  log.info("Verification output:\n" + noAnchor);
  assert.ok(noAnchor.indexOf("Signature Verified: false") === 0,
    "A chain that reaches no anchor must not report a verified signature. " +
        "Got:\n" + noAnchor);
  assert.ok(noAnchor.indexOf("NO TRUST ANCHOR") !== -1,
    "The output should name the missing anchor. Got:\n" + noAnchor);
  assert.ok(noAnchor.indexOf("cryptographically valid") !== -1,
    "The output should still say the signature itself verified — that " +
        "distinction is the whole point of the pane. Got:\n" + noAnchor);

  log.info("Verify against somebody else's CA.");
  await setChainBox(driver, fixture.other);
  var wrongCa = await clickVerify(driver);
  log.info("Verification output:\n" + wrongCa);
  assert.ok(wrongCa.indexOf("Signature Verified: false") === 0,
    "A chain that does not belong to this signer must not verify it. Got:\n" +
        wrongCa);
  assert.ok(wrongCa.indexOf("does not belong to this signer") !== -1,
    "The output should say the chain is not this signer's. Got:\n" + wrongCa);

  // A bundle is pasted in whatever order its source wrote it, and an unused
  // certificate in it is not an error — so this is the same chain, shuffled,
  // with a stranger's root added.
  log.info("Verify with the chain out of order and a spare certificate.");
  await setChainBox(driver, fixture.root + fixture.other + fixture.ca);
  var shuffled = await clickVerify(driver);
  log.info("Verification output:\n" + shuffled);
  assert.ok(shuffled.indexOf("Signature Verified: true") === 0,
    "A correct chain in the wrong order should still validate — the path " +
        "is built by name. Got:\n" + shuffled);
  assert.ok(shuffled.indexOf("not part of this path") !== -1,
    "The spare certificate should be reported as unused. Got:\n" + shuffled);

  // A chain is usually distributed as ONE PEM file, signer first, and that
  // is how it gets pasted. The two fields are concatenated for the check —
  // the first certificate is the one the signature is verified with and
  // everything after it, in either field, is offered as its issuers — so
  // this must reach the same verdict as the same certificates split across
  // the two boxes above.
  log.info("Verify with the signer and its whole chain in one field.");
  await setChainBox(driver, "");
  await setKeyBox(driver, fixture.signer + fixture.ca + fixture.root);
  var bundled = await clickVerify(driver);
  log.info("Verification output:\n" + bundled);
  assert.ok(bundled.indexOf("Signature Verified: true") === 0,
    "A whole chain pasted into the Verification Key field should verify — " +
        "the signer certificate and the CA chain are checked together. " +
        "Got:\n" + bundled);
  assert.ok(bundled.indexOf("3 certificate(s)") !== -1,
    "All three certificates should be in the path. Got:\n" + bundled);
  assert.ok(bundled.indexOf("JWT Tools Test Root CA") !== -1,
    "The root pasted with the signer should have been reached. Got:\n" +
        bundled);
  await setKeyBox(driver, fixture.signer);
  await setChainBox(driver, fixture.ca + fixture.root);

  log.info("Untick the box: the same token verifies with no chain check.");
  await click(driver, By.id("verify_chain_enabled"));
  var unchecked = await clickVerify(driver);
  log.info("Verification output:\n" + unchecked);
  assert.ok(unchecked.indexOf("Signature Verified: true") === 0,
    "With the trust chain unchecked, the signature alone decides. Got:\n" +
        unchecked);
  assert.ok(unchecked.indexOf("Trust chain") === -1,
    "With the box unticked no chain should be reported at all. Got:\n" +
        unchecked);

  // KEY USAGE. The certificate at the head of this token's x5c was issued
  // for encipherment and asserts no digitalSignature bit, so the key in it
  // may not sign — and the signature is nonetheless correct, because it was
  // made with that key. pkijs verifies signatures and says nothing about
  // what a key is permitted to do, so this is the case that would pass
  // against a chain check built only out of the library.
  log.info("A signer certificate whose KeyUsage forbids signing.");
  await pasteEncoded(driver, fixture.noSignJwt);
  var wanted = fixture.noSign.trim();
  await waitForValue(driver, By.id("jwt_verification_key"),
    function (v) { return v.trim() === wanted; },
    "The encipherment-only token did not replace the Verification Key — " +
        "the field already held a certificate, so this waits for THIS " +
        "token's one rather than for any.");
  var badUsage = await clickVerify(driver);
  log.info("Verification output:\n" + badUsage);
  assert.ok(badUsage.indexOf("Signature Verified: false") === 0,
    "A certificate whose KeyUsage forbids digitalSignature must not verify " +
        "a JWS, however good the signature is. Got:\n" + badUsage);
  assert.ok(badUsage.indexOf("KEY USAGE FORBIDS SIGNING") !== -1,
    "The output should say which check refused it. Got:\n" + badUsage);
  assert.ok(badUsage.indexOf("keyEncipherment") !== -1,
    "The output should name the usages the certificate DOES assert. Got:\n" +
        badUsage);
  assert.ok(badUsage.indexOf("cryptographically valid") !== -1,
    "The output should still say the signature itself verified — the " +
        "certificate is what refused it. Got:\n" + badUsage);
  assert.ok(badUsage.indexOf("JWT Tools Test Root CA") !== -1,
    "The chain still reaches the root; only the key usage refused it. " +
        "Got:\n" + badUsage);

  log.info("Untick the box: the key usage check goes with the rest of it.");
  await click(driver, By.id("verify_chain_enabled"));
  var usageUnchecked = await clickVerify(driver);
  assert.ok(usageUnchecked.indexOf("Signature Verified: true") === 0,
    "With the box unticked the signature alone decides, key usage " +
        "included. Got:\n" + usageUnchecked);

  log.info("Load a token with no x5c: what x5c filled in is cleared.");
  await pasteEncoded(driver, fixture.jwt);
  await waitForValue(driver, By.id("jwt_verification_key"),
    function (v) { return v.indexOf("BEGIN CERTIFICATE") !== -1; },
    "The x5c token did not repopulate the Verification Key field.");
  await pasteEncoded(driver, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJwbGFpbiJ9.");
  await waitForValue(driver, By.id("jwt_verification_key"),
    function (v) { return v.trim() === ""; },
    "A token with no x5c must clear the certificate the previous one left " +
        "behind — a stale chain would be checked against the new token.");
  var leftover = await getValue(driver, By.id("verify_chain_pem"));
  assert.strictEqual(leftover.trim(), "",
    "The CA Trust Chain field should have been cleared with it.");
  log.debug("Leaving x5cTrustChainActivities().");
}

// ---------------------------------------------------------------------------
// A COMPLETE CA TRUST CHAIN, and the six ways a token still fails against one.
//
// x5cTrustChainActivities() above asks what happens when the CHAIN is wrong:
// truncated below its root, or somebody else's altogether. This asks the
// harder question. Here the chain is COMPLETE and CORRECT every time — four
// certificates, each really issued by the one above it, ending at a
// self-signed root the path actually reaches — and the token must still be
// refused, because reaching an anchor is not the only thing a validator has to
// be satisfied about. Validity dates, the KeyUsage of an ISSUER rather than of
// the signer, an impostor CA carrying the right NAME and the wrong key, and a
// signature that is simply not the signer's each get a case, and each case
// leaves exactly ONE thing wrong: a checker that refused everything would pass
// a test that only read the verdict, so every assertion below names the
// particular thing that should have been objected to.
//
// The positives are here for the same reason. A three-certificate chain is the
// shortest one that has a middle at all, so it cannot show that the path
// building walks further than one hop; these run four deep, and pass the same
// four certificates in the wrong order and buried in the commentary an
// `openssl x509 -text` dump puts between PEM blocks, which is how a CA bundle
// is actually distributed.
// ---------------------------------------------------------------------------

// A profile's own extensions with one thing about them changed. The page's
// defaults are the starting point deliberately: a certificate hand-built here
// would be a second issuer implementation, and every case below turns on the
// single field this alters.
function extensionsFor(profile, mutate) {
  log.debug("Entering extensionsFor(). profile=" + profile);
  var extensions = x509.defaultExtensions(profile);
  if (mutate) {
    mutate(extensions);
  }
  log.debug("Leaving extensionsFor().");
  return extensions;
}

// Root CA -> Intermediate CA -> Issuing CA -> signer, and the six tokens that
// hang off it. Everything is P-256: this asserts what the page does with a
// chain, and an RSA key pair per tier would be most of the test's runtime.
async function buildDeepChainFixture() {
  log.debug("Entering buildDeepChainFixture().");
  var rootKey = await keyMaterial.generateKeyPair("ec-p256");
  var interKey = await keyMaterial.generateKeyPair("ec-p256");
  var issuingKey = await keyMaterial.generateKeyPair("ec-p256");
  var signerKey = await keyMaterial.generateKeyPair("ec-p256");
  var noCertSignKey = await keyMaterial.generateKeyPair("ec-p256");
  var impostorKey = await keyMaterial.generateKeyPair("ec-p256");
  var strangerKey = await keyMaterial.generateKeyPair("ec-p256");

  var root = await x509.issueCertificate({
    profile: "root-ca",
    subject: "CN=JWT Tools Deep Root CA,O=idptools",
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem,
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("root-ca")
  });
  var rootIssuer = { certificatePem: root.pem,
                     privateKeyPem: rootKey.privatePem, keyAlg: "ec-p256" };
  var inter = await x509.issueCertificate({
    profile: "intermediate-ca",
    subject: "CN=JWT Tools Deep Intermediate CA,O=idptools",
    subjectPublicKey: interKey.publicPem,
    issuer: rootIssuer,
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("intermediate-ca")
  });
  var interIssuer = { certificatePem: inter.pem,
                      privateKeyPem: interKey.privatePem, keyAlg: "ec-p256" };
  var issuing = await x509.issueCertificate({
    profile: "issuing-ca",
    subject: "CN=JWT Tools Deep Issuing CA,O=idptools",
    subjectPublicKey: issuingKey.publicPem,
    issuer: interIssuer,
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("issuing-ca")
  });
  var issuingIssuer = { certificatePem: issuing.pem,
                        privateKeyPem: issuingKey.privatePem,
                        keyAlg: "ec-p256" };

  // The signer, on the profile a JWS signer should actually be issued under:
  // digitalSignature and nonRepudiation, no serverAuth.
  var signer = await x509.issueCertificate({
    profile: "digital-signature",
    subject: "CN=jwt-tools-deep-signer.example,O=idptools",
    subjectPublicKey: signerKey.publicPem,
    issuer: issuingIssuer,
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("digital-signature")
  });

  // THE SAME KEY AND THE SAME ISSUER, certified for a window that has closed.
  // Nothing about the chain changes: the certificate was genuinely issued by
  // that CA, and the CA is genuinely under the root. Only the clock refuses
  // it, which is a fact no amount of correct arithmetic over the signing
  // input can overrule.
  var now = Date.now();
  var day = 24 * 60 * 60 * 1000;
  var expired = await x509.issueCertificate({
    profile: "digital-signature",
    subject: "CN=jwt-tools-expired-signer.example,O=idptools",
    subjectPublicKey: signerKey.publicPem,
    issuer: issuingIssuer,
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("digital-signature"),
    notBefore: new Date(now - 900 * day).toISOString(),
    notAfter: new Date(now - 30 * day).toISOString()
  });
  // And the other end of the same mistake: a certificate whose window has not
  // opened. It is a separate case because it is a separate BUG to write —
  // a comparison in the wrong direction reports one of these correctly and
  // the other not at all.
  var future = await x509.issueCertificate({
    profile: "digital-signature",
    subject: "CN=jwt-tools-future-signer.example,O=idptools",
    subjectPublicKey: signerKey.publicPem,
    issuer: issuingIssuer,
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("digital-signature"),
    notBefore: new Date(now + 30 * day).toISOString(),
    notAfter: new Date(now + 400 * day).toISOString()
  });

  // AN ISSUER WHOSE KEYUSAGE FORBIDS ISSUING. The bit that matters here is
  // keyCertSign and it is the CA's, not the signer's — so this is the case a
  // key-usage check written only about the leaf passes. Everything else about
  // it is in order: the intermediate really issued it, and it really issued
  // the certificate below.
  var noCertSign = await x509.issueCertificate({
    profile: "issuing-ca",
    subject: "CN=JWT Tools No CertSign CA,O=idptools",
    subjectPublicKey: noCertSignKey.publicPem,
    issuer: interIssuer,
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("issuing-ca", function (extensions) {
      extensions.keyUsage.usages = ["digitalSignature", "cRLSign"];
    })
  });
  var underNoCertSign = await x509.issueCertificate({
    profile: "digital-signature",
    subject: "CN=jwt-tools-under-nocertsign.example,O=idptools",
    subjectPublicKey: signerKey.publicPem,
    issuer: { certificatePem: noCertSign.pem,
              privateKeyPem: noCertSignKey.privatePem, keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("digital-signature")
  });

  // AN IMPOSTOR CA: the Issuing CA's distinguished name exactly, a different
  // key, and a complete chain of its own to a root it self-signed. Offered as
  // the signer's chain it is the one forgery that survives every check made
  // by NAME — the issuer name matches, the path is built, an anchor is
  // reached — and only verifying the signature on the signer certificate
  // catches it.
  var impostorRoot = await x509.issueCertificate({
    profile: "root-ca",
    subject: "CN=Impostor Root CA,O=elsewhere",
    subjectPublicKey: strangerKey.publicPem,
    issuerPrivateKey: strangerKey.privatePem,
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("root-ca")
  });
  var impostor = await x509.issueCertificate({
    profile: "issuing-ca",
    subject: "CN=JWT Tools Deep Issuing CA,O=idptools",
    subjectPublicKey: impostorKey.publicPem,
    issuer: { certificatePem: impostorRoot.pem,
              privateKeyPem: strangerKey.privatePem, keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa",
    extensions: extensionsFor("issuing-ca")
  });

  // RFC 7515 section 4.1.6: base64 DER — NOT base64url — signer first, each
  // certificate after it certifying the one before.
  function der64(pem) {
    return cryptoBytes.bytesToB64(cryptoBytes.pemToDer(pem));
  }
  async function tokenFor(chain, privateKeyPem, subject) {
    var signed = await jwsLib.signJwsAsync({
      algId: "ES256",
      protectedHeader: { alg: "ES256", typ: "JWT", x5c: chain.map(der64) },
      payload: { iss: "https://deep-chain.example.com", sub: subject },
      privateKey: privateKeyPem
    });
    return signed.serialized;
  }
  var above = [issuing.pem, inter.pem, root.pem];
  var fixture = {
    root: root.pem,
    inter: inter.pem,
    issuing: issuing.pem,
    signer: signer.pem,
    impostor: impostor.pem,
    impostorRoot: impostorRoot.pem,
    expiredSigner: expired.pem,
    futureSigner: future.pem,
    underNoCertSign: underNoCertSign.pem,
    jwt: await tokenFor([signer.pem].concat(above), signerKey.privatePem,
                        "deep-chain-good"),
    expiredJwt: await tokenFor([expired.pem].concat(above),
                               signerKey.privatePem, "deep-chain-expired"),
    futureJwt: await tokenFor([future.pem].concat(above),
                              signerKey.privatePem, "deep-chain-future"),
    noCertSignJwt: await tokenFor(
        [underNoCertSign.pem, noCertSign.pem, inter.pem, root.pem],
        signerKey.privatePem, "deep-chain-nocertsign"),
    // The good certificates, and a signature made with a key that is not the
    // one inside any of them. The chain is beyond reproach and the token is
    // still not this signer's.
    strangerSignedJwt: await tokenFor([signer.pem].concat(above),
                                      strangerKey.privatePem,
                                      "deep-chain-stranger")
  };
  log.debug("Leaving buildDeepChainFixture().");
  return fixture;
}

// Wrap PEM blocks in the commentary `openssl x509 -text` writes around them,
// which is how a CA bundle usually arrives. Nothing between an END and the
// next BEGIN may reach the parser.
function withOpensslCommentary(pems) {
  log.debug("Entering withOpensslCommentary().");
  var out = "# This bundle was written by `openssl x509 -text`.\n";
  for (var i = 0; i < pems.length; i++) {
    out += "Certificate:\n    Data:\n        Version: 3 (0x2)\n" +
        "        Serial Number: (see below)\n" +
        "    Signature Algorithm: ecdsa-with-SHA256\n" + pems[i] + "\n";
  }
  log.debug("Leaving withOpensslCommentary().");
  return out;
}

// Paste a token and wait for the page to have finished with it. The `sub`
// claim is what is waited on rather than the certificate field: two of these
// tokens carry the SAME signer certificate and differ only in who signed
// them, so a wait for "a certificate appeared" would pass on the previous
// token's one.
async function pasteAndSettle(driver, token, subject) {
  log.debug("Entering pasteAndSettle(). sub=" + subject);
  await pasteEncoded(driver, token);
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf(subject) !== -1; },
    "The token whose sub is " + subject + " was not decoded into the " +
        "JWT Payload field.");
  await waitForValue(driver, By.id("jwt_verification_key"),
    function (v) { return v.indexOf("BEGIN CERTIFICATE") !== -1; },
    "The header's x5c did not populate the Verification Key field.");
  log.debug("Leaving pasteAndSettle().");
}

async function deepTrustChainActivities(driver) {
  log.debug("Entering deepTrustChainActivities().");
  log.info("Build a four-tier hierarchy and the tokens that hang off it.");
  var fixture = await buildDeepChainFixture();

  await driver.get(baseUrl + "/jwt_tools.html");
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf("garbage") !== -1; },
    "JWT Tools default payload did not load.");

  // ---- POSITIVE: the whole hierarchy, signer first ------------------------
  log.info("A token whose x5c carries all four certificates.");
  await pasteAndSettle(driver, fixture.jwt, "deep-chain-good");
  var signerField = await getValue(driver, By.id("jwt_verification_key"));
  assert.strictEqual(signerField.trim(), fixture.signer.trim(),
    "The Verification Key field should hold the signer certificate.");
  var chainField = await getValue(driver, By.id("verify_chain_pem"));
  assert.strictEqual(chainField.trim(),
    (fixture.issuing + fixture.inter + fixture.root).trim(),
    "The CA Trust Chain field should hold the three certificates above the " +
        "signer, in x5c order.");

  var good = await clickVerify(driver);
  log.info("Verification output:\n" + good);
  assert.ok(good.indexOf("Signature Verified: true") === 0,
    "A four-certificate chain reaching a self-signed root should verify. " +
        "Got:\n" + good);
  assert.ok(good.indexOf("4 certificate(s)") !== -1,
    "All four certificates should be in the reported path — a three-deep " +
        "chain cannot show that the path walks past the first CA. Got:\n" +
        good);
  assert.ok(good.indexOf("JWT Tools Deep Intermediate CA") !== -1,
    "The MIDDLE of the chain should be reported, not just its ends. Got:\n" +
        good);
  assert.ok(good.indexOf("(self-signed root)") !== -1,
    "The output should say which certificate was the anchor. Got:\n" + good);
  assert.ok(good.indexOf("nonRepudiation") !== -1,
    "The signer's own key usages should be reported beside its link. Got:\n" +
        good);

  // ---- POSITIVE: the same bundle as a CA download actually arrives --------
  log.info("The same three CAs, out of order and full of openssl commentary.");
  await setChainBox(driver, withOpensslCommentary(
    [fixture.root, fixture.issuing, fixture.inter]));
  var messy = await clickVerify(driver);
  log.info("Verification output:\n" + messy);
  assert.ok(messy.indexOf("Signature Verified: true") === 0,
    "A bundle in the wrong order, with text between its PEM blocks, holds " +
        "the same chain and should reach the same verdict. Got:\n" + messy);
  assert.ok(messy.indexOf("4 certificate(s)") !== -1,
    "The path built from the messy bundle should still be four deep. " +
        "Got:\n" + messy);
  assert.ok(messy.indexOf("not part of this path") === -1,
    "Every certificate in that bundle belongs to this path; none should be " +
        "reported as unused. Got:\n" + messy);

  // ---- NEGATIVE: the box is ticked and nothing is offered -----------------
  log.info("Ticked, with no CA certificate anywhere.");
  await setChainBox(driver, "");
  var noCa = await clickVerify(driver);
  log.info("Verification output:\n" + noCa);
  assert.ok(noCa.indexOf("Signature Verified: false") === 0,
    "With the check asked for and no CA supplied, nothing is established " +
        "and the answer must not be true. Got:\n" + noCa);
  assert.ok(noCa.indexOf("no CA certificate was supplied") !== -1,
    "The output should say the chain field was empty rather than blame the " +
        "signer certificate. Got:\n" + noCa);

  // ---- NEGATIVE: an expired signer under a chain that is beyond reproach --
  log.info("An EXPIRED signer certificate, chain otherwise intact.");
  await pasteAndSettle(driver, fixture.expiredJwt, "deep-chain-expired");
  var expired = await clickVerify(driver);
  log.info("Verification output:\n" + expired);
  assert.ok(expired.indexOf("Signature Verified: false") === 0,
    "A signer certificate whose validity window has closed must not verify " +
        "a JWS, however good its chain. Got:\n" + expired);
  assert.ok(expired.indexOf("EXPIRED") !== -1,
    "The output should say which check refused it. Got:\n" + expired);
  assert.ok(expired.indexOf("cryptographically valid") !== -1,
    "The output should still say the signature itself verified — the " +
        "certificate is what refused it. Got:\n" + expired);
  assert.ok(expired.indexOf("4 certificate(s)") !== -1 &&
            expired.indexOf("(self-signed root)") !== -1,
    "The chain still reaches the root; only the dates refused it. Got:\n" +
        expired);

  // ---- NEGATIVE: and the same mistake the other way round ----------------
  log.info("A signer certificate whose window has not opened yet.");
  await pasteAndSettle(driver, fixture.futureJwt, "deep-chain-future");
  var future = await clickVerify(driver);
  log.info("Verification output:\n" + future);
  assert.ok(future.indexOf("Signature Verified: false") === 0,
    "A signer certificate that is not valid yet must not verify a JWS. " +
        "Got:\n" + future);
  assert.ok(future.indexOf("NOT YET VALID") !== -1,
    "The output should say the certificate is not valid YET rather than " +
        "that it expired — a comparison written the wrong way round reports " +
        "one of these and not the other. Got:\n" + future);
  assert.ok(future.indexOf("EXPIRED") === -1,
    "A certificate that is not valid yet has not expired. Got:\n" + future);

  // ---- NEGATIVE: the ISSUER may not issue --------------------------------
  log.info("An intermediate whose KeyUsage forbids issuing certificates.");
  await pasteAndSettle(driver, fixture.noCertSignJwt,
                       "deep-chain-nocertsign");
  var noIssue = await clickVerify(driver);
  log.info("Verification output:\n" + noIssue);
  assert.ok(noIssue.indexOf("Signature Verified: false") === 0,
    "A CA whose KeyUsage omits keyCertSign may not issue the certificate " +
        "below it, so nothing under it is trusted. Got:\n" + noIssue);
  assert.ok(noIssue.indexOf("KEY USAGE FORBIDS ISSUING") !== -1,
    "The output should say which check refused it — and it is the CA's key " +
        "usage, not the signer's, which is the case a check written only " +
        "about the leaf would pass. Got:\n" + noIssue);
  assert.ok(noIssue.indexOf("JWT Tools No CertSign CA") !== -1,
    "The output should name the certificate that may not issue. Got:\n" +
        noIssue);
  assert.ok(noIssue.indexOf("KEY USAGE FORBIDS SIGNING") === -1,
    "The signer's own key usage permits signing; only its issuer was " +
        "refused. Got:\n" + noIssue);
  assert.ok(noIssue.indexOf("cryptographically valid") !== -1,
    "The output should still say the signature itself verified. Got:\n" +
        noIssue);

  // ---- NEGATIVE: the right name over the wrong key ------------------------
  log.info("An impostor CA carrying the Issuing CA's name and another key.");
  await pasteAndSettle(driver, fixture.jwt, "deep-chain-good");
  await setChainBox(driver, fixture.impostor + fixture.impostorRoot);
  var impostor = await clickVerify(driver);
  log.info("Verification output:\n" + impostor);
  assert.ok(impostor.indexOf("Signature Verified: false") === 0,
    "A chain whose names line up and whose signatures do not must not " +
        "verify. Got:\n" + impostor);
  assert.ok(impostor.indexOf("SIGNATURE INVALID") !== -1,
    "The output should say the signature on the signer certificate is what " +
        "failed. Got:\n" + impostor);
  assert.ok(impostor.indexOf("does not belong to this signer") === -1,
    "This chain DOES name this signer's issuer — that is what makes it a " +
        "forgery rather than a mix-up, and reporting it as the wrong chain " +
        "would send the reader looking for the wrong mistake. Got:\n" +
        impostor);
  assert.ok(impostor.indexOf("Impostor Root CA") !== -1,
    "The impostor's own anchor was reached and should be reported: an " +
        "anchor is not the same thing as a trustworthy one. Got:\n" +
        impostor);

  // ---- NEGATIVE: an impeccable chain over somebody else's signature -------
  //
  // The mirror image of every case above: there the signature was good and
  // the certificates were not. This token carries the real signer's whole
  // hierarchy and was signed by a key that is in none of it.
  log.info("The real chain, and a signature made with a stranger's key.");
  await pasteAndSettle(driver, fixture.strangerSignedJwt,
                       "deep-chain-stranger");
  var stranger = await clickVerify(driver);
  log.info("Verification output:\n" + stranger);
  assert.ok(stranger.indexOf("Signature Verified: false") === 0,
    "A signature that is not the signer certificate's must not verify, " +
        "however good that certificate's chain is. Got:\n" + stranger);
  assert.ok(stranger.indexOf("cryptographically valid") === -1,
    "Nothing here was cryptographically valid — that sentence belongs to " +
        "the cases where the certificate refused a good signature, and " +
        "printing it for a bad one would invert the finding. Got:\n" +
        stranger);
  assert.ok(stranger.indexOf("4 certificate(s)") !== -1 &&
            stranger.indexOf("(self-signed root)") !== -1,
    "The chain is impeccable and should be reported as such; the two " +
        "checks are independent and a failure of one must not suppress the " +
        "other. Got:\n" + stranger);
  log.debug("Leaving deepTrustChainActivities().");
}

async function test() {
  log.debug("Entering test().");
  // JWT Tools clicks key-download buttons. On host runs the browser is the
  // user's real Chrome (default download dir ~/Downloads); redirect downloads
  // to a throwaway temp dir (removed below) so nothing lands in the home
  // directory. The test asserts only on the in-page status, never the
  // downloaded file.
  const downloadDir = fs.mkdtempSync(path.join(os.tmpdir(),
      "idptools-selenium-dl-"));
  const options = new chrome.Options();
  options.setUserPreferences({
    "download.default_directory": downloadDir,
    "download.prompt_for_download": false,
    "download.directory_upgrade": true,
    "safebrowsing.enabled": true,
  });
  if (headless) {
    // Use "new" headless: unlike the legacy --headless mode, it honors the
    // --unsafely-treat-insecure-origin-as-secure override below, which is what
    // makes crypto.subtle (Web Crypto) available on the http://client:3000
    // origin.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages (e.g. jwt_tools) under coverage.
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  // JWT Tools uses the Web Crypto API (crypto.subtle), which browsers expose
  // only in a "secure context". http://localhost is treated as secure, but the
  // containerized runs serve the client at http://client:3000 (a non-secure
  // origin), where crypto.subtle would be undefined and key generation fails.
  // Treat the debugger origin as trustworthy so crypto.subtle is available.
  // (This flag only takes effect when a --user-data-dir is also set.)
  var secureOrigin = baseUrl.replace(/\/+$/, "");
  options.addArguments("--unsafely-treat-insecure-origin-as-secure=" +
                       secureOrigin);
  // Date.now() alone is NOT unique: run-report.js runs jobs in a pool,
  // and two starting in the same millisecond would share a profile —
  // one Chrome then refuses to start on the other's. See CONCURRENCY
  // in run-report.js.
  options.addArguments("--user-data-dir=/tmp/jwt-tools-chrome-" +
                       Date.now() + "-" + process.pid);
  // THE STACK'S CERTIFICATE, AS AN EXACT KEY PIN. The client and the api serve
  // https (common/tls_listener.js), on a self-signed pair generated per run, so
  // without this Chrome stops on a certificate interstitial and every
  // assertion below reports a missing element on a page titled "Privacy
  // error". See browser_flags.js.
  browserFlags.addStsTrustFlags(options);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  // Belt-and-suspenders: also pin the download dir via CDP (independent of the
  // profile prefs, which a custom --user-data-dir can bypass), so downloads
  // never fall back to ~/Downloads.
  try {
    await driver.sendDevToolsCommand("Browser.setDownloadBehavior",
      { behavior: "allow", downloadPath: downloadDir, eventsEnabled: false });
  } catch (e) {
    /* older Chrome/driver — the user-preferences download dir applies */
  }

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    log.info("Starting Test run.");

    // ---- OIDC Authorization Code flow config ------------------------------
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    let pkce_enabled = process.env.PKCE_ENABLED;

    assert(discovery_endpoint,
           "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");
    pkce_enabled = (pkce_enabled === "true");

    // ---- Obtain an ID Token via OIDC Authorization Code -------------------
    log.info("Clear all cookies.");
    await driver.manage().deleteAllCookies();
    log.info("Load the debugger and run the OIDC Authorization Code flow.");
    await driver.get(baseUrl + "/oauth2_oidc_1.html");
    await populateMetadata(driver, discovery_endpoint);
    let access_token = await getAccessTokenAuthCode(driver, client_id,
        client_secret, scope, pkce_enabled, { baseUrl });
    let decoded_access = decodeJWT(access_token);
    assert.notStrictEqual(decoded_access, null,
        "Could not obtain/decode an access token from the OIDC flow.");
    let id_token = await getIDToken(driver);
    assert.notStrictEqual(decodeJWT(id_token), null,
        "Could not obtain/decode an ID token from the OIDC flow.");
    log.info("Obtained ID Token (" + id_token.length + " chars).");

    // ---- Paste the ID Token into JWT Tools and verify the decoded payload -
    await idTokenDecodeActivities(driver, id_token);

    // ---- Load the Encoded JWT from a file, and refuse an oversize one -----
    await encodedFileLoadActivities(driver);

    // ---- x5c: the signer certificate, its CA chain, and the trust check ---
    await x5cTrustChainActivities(driver);

    // ---- A COMPLETE chain, and the things that refuse a token anyway ------
    await deepTrustChainActivities(driver);

    // ---- Run the standard JWT Tools activities ----------------------------
    await jwtToolsActivities(driver);

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    testFailed = true;
  } finally {
    await driver.quit();
    try {
      fs.rmSync(downloadDir, { recursive: true, force: true });
    } catch (e) {
      /* ignore */
    }
  }
  if (testFailed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('jwt_tools')
  .description("Run JWT Tools UI test.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
  )
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
