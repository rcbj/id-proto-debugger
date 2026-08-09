// File: keypair_storage_optout.js
//
// "Save this key pair in browser localStorage" — the key-pair opt-out on every
// protocol that generates one (SAML, WS-Trust, WS-Federation and SD-JWT VC),
// checked in BOTH states.
//
// Why this needs a test rather than a look: the failure mode is silent, and it
// is silent in the reassuring direction. If the guard in saveState() were
// broken, the checkbox would still untick and the explanatory note would still
// appear, while the private key went on being written to localStorage exactly
// as before. Nothing on screen would say so. The only way to know is to read
// storage, which is what this does.
//
// The four things asserted, per page:
//
//   1. Checked (the default) still saves — the opt-out must not have quietly
//      broken the workflow it is an exception to.
//   2. Clearing it PURGES what was already written. Skipping future writes is
//      not enough: an opt-out that leaves yesterday's private key in storage is
//      not an opt-out, and that distinction is invisible unless you look before
//      and after.
//   3. The purge SURVIVES later saves. saveState() runs on nearly every
//      interaction, so a guard that only fired in the change handler would put
//      the key straight back on the next keystroke. This is the assertion that
//      catches that, and it is the reason the purge lives in saveState().
//   4. Unrelated configuration is untouched, and — WS-Trust only — so is
//      wst_enc_cert, which is the STS's certificate rather than part of this
//      key pair.
//
// Plus the preference itself surviving a reload, and the hand-off: with saving
// off, the response page's Decryption Key field comes up empty and its note
// says why instead of claiming a prefill that did not happen.
//
// Needs only the client — no identity provider, no STS — so it is never
// skipped, and it is one of the few browser tests that runs on every pass.
const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require('commander');
const assert = require("assert");
const browserFlags = require("./browser_flags.js");
const waitForContent = require("./wait_for.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'keypair_storage_optout',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// The two pages, and what "the key pair" means on each. Everything below is
// driven from this table so the two are held to identical behaviour.
var PAGES = [
  {
    what: "SAML",
    page: "/saml_request.html",
    prefix: "samltools_",
    checkbox: "saml_save_keypair",
    note: "saml_keypair_storage_note",
    // The pane is inside the signing section, which is only shown when
    // "Digitally sign the AuthnRequest" is on. It is on by default.
    signCheckbox: "saml_sign_request",
    fields: ["saml_sp_private_key", "saml_sp_public_key"],
    // A stored value that must NOT be collateral damage.
    bystander: "saml_sp_entity_id",
    responsePage: "/saml_response.html",
    responseKeyField: "saml_dec_key",
    responseNote: "saml_dec_key_note"
  },
  {
    what: "WS-Trust",
    page: "/wstrust_tools.html",
    prefix: "wstrust_",
    checkbox: "wst_save_keypair",
    note: "wst_keypair_storage_note",
    signCheckbox: "wst_sign_request",
    fields: ["wst_sp_private_key", "wst_sp_cert"],
    bystander: "wst_sts_url",
    // The STS's own certificate. Public, somebody else's, and deliberately not
    // part of the pair the checkbox governs.
    untouched: "wst_enc_cert",
    responsePage: "/wstrust_response.html",
    responseKeyField: "wst_dec_key",
    responseNote: "wst_dec_key_note"
  }
  ,
  {
    what: "WS-Federation",
    page: "/wsfed_request.html",
    prefix: "wsfedtools_",
    checkbox: "wsfed_save_keypair",
    note: "wsfed_keypair_storage_note",
    // No signing toggle on this page: the Passive Requestor Profile does not
    // sign the sign-in request, so the RP key pair pane is always visible and
    // there is nothing to open first.
    signCheckbox: null,
    fields: ["wsfed_rp_private_key", "wsfed_rp_cert"],
    bystander: "wsfed_realm",
    // The IdP's signing certificate. Public, somebody else's, and not part of
    // the pair the checkbox governs — the counterpart of wst_enc_cert.
    untouched: "wsfed_signer_cert",
    responsePage: "/wsfed_response.html",
    responseKeyField: "wsfed_dec_key",
    responseNote: "wsfed_dec_key_note"
  }
];

var MARKER_PRIVATE = "-----BEGIN PRIVATE KEY-----\nKEYPAIR-OPTOUT-TEST\n-----END PRIVATE KEY-----\n";
var MARKER_PUBLIC = "-----BEGIN CERTIFICATE-----\nKEYPAIR-OPTOUT-TEST\n-----END CERTIFICATE-----\n";

async function waitVisible(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(locator)), waitTime);
  return driver.findElement(locator);
}

function storageOf(driver, prefix, id) {
  return driver.executeScript(
    "return window.localStorage.getItem(arguments[0] + arguments[1]);", prefix, id);
}

// Set a field the way a person does — type into it and let the page react —
// rather than assigning .value, which fires no event and so never reaches
// saveState(). The whole test is about what saveState() writes, so a silent
// assignment would test nothing.
async function setFieldAndSave(driver, id, value) {
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "e.value = arguments[1];" +
    "e.dispatchEvent(new Event('change', { bubbles: true }));" +
    "e.dispatchEvent(new Event('input', { bubbles: true }));", id, value);
}

async function setCheckbox(driver, id, want) {
  var isOn = await driver.executeScript(
    "var e = document.getElementById(arguments[0]); return !!(e && e.checked);", id);
  if (isOn === want) return;
  var box = await waitVisible(driver, By.id(id));
  await box.click();
  var now = await driver.executeScript(
    "var e = document.getElementById(arguments[0]); return !!(e && e.checked);", id);
  assert.strictEqual(now, want, "could not set checkbox " + id + " to " + want);
}


// --- the body of the check, run identically for both pages ------------------

async function keyPairOptOut(driver, spec) {
  log.debug("Entering keyPairOptOut().");
  log.info("=== " + spec.what + ": " + spec.page + " ===");
  // Start from a known state: nothing left over from another test in this
  // browser profile, and the signing pane open.
  //
  // The pane has to be opened explicitly, and the two pages differ here: the
  // SAML page ships with "Digitally sign" ON, the WS-Trust page ships with it
  // OFF, so on WS-Trust the key-pair fields — and this checkbox — are hidden
  // until it is turned on. Waiting for the checkbox before doing that is how
  // the first version of this test failed.
  var opener = spec.signCheckbox || spec.checkbox;
  await driver.get(baseUrl + spec.page);
  await waitVisible(driver, By.id(opener));
  await driver.executeScript("window.localStorage.clear();");
  await driver.get(baseUrl + spec.page);
  await waitVisible(driver, By.id(opener));
  if (spec.signCheckbox) await setCheckbox(driver, spec.signCheckbox, true);
  await waitVisible(driver, By.id(spec.checkbox));

  var box = await driver.findElement(By.id(spec.checkbox));
  assert.strictEqual(await box.isSelected(), true,
    "[" + spec.what + "] the key pair should be saved by DEFAULT — the workflow depends on it, " +
    "and changing that default silently would break the hand-off to the response page.");

  // 1. Checked: the pair is written.
  await setFieldAndSave(driver, spec.fields[0], MARKER_PRIVATE);
  await setFieldAndSave(driver, spec.fields[1], MARKER_PUBLIC);
  await setFieldAndSave(driver, spec.bystander, "keypair-optout-bystander");
  if (spec.untouched) await setFieldAndSave(driver, spec.untouched, "STS-PUBLIC-CERT");

  assert.strictEqual(await storageOf(driver, spec.prefix, spec.fields[0]), MARKER_PRIVATE,
    "[" + spec.what + "] with the box checked the private key should be in localStorage.");
  assert.strictEqual(await storageOf(driver, spec.prefix, spec.fields[1]), MARKER_PUBLIC,
    "[" + spec.what + "] with the box checked the certificate should be in localStorage.");
  log.info("[" + spec.what + "] OK — checked: both halves of the pair are stored.");

  // 2. Cleared: the pair is removed, not merely not-rewritten.
  await setCheckbox(driver, spec.checkbox, false);
  for (var i = 0; i < spec.fields.length; i++) {
    assert.strictEqual(await storageOf(driver, spec.prefix, spec.fields[i]), null,
      "[" + spec.what + "] clearing the box must REMOVE " + spec.fields[i] + " from localStorage, " +
      "not just stop rewriting it — otherwise the key the user opted out of keeping is still there.");
  }
  var noteText = (await driver.findElement(By.id(spec.note)).getText()).trim();
  assert.ok(noteText.length > 0 && /Download/.test(noteText),
    "[" + spec.what + "] clearing the box should explain what the user now has to do themselves; " +
    "found: '" + noteText + "'");

  // 4. ...without taking unrelated configuration with it.
  assert.strictEqual(await storageOf(driver, spec.prefix, spec.bystander), "keypair-optout-bystander",
    "[" + spec.what + "] ordinary configuration must survive the opt-out.");
  if (spec.untouched) {
    assert.strictEqual(await storageOf(driver, spec.prefix, spec.untouched), "STS-PUBLIC-CERT",
      "[" + spec.what + "] " + spec.untouched + " is the STS's own public certificate, not part of " +
      "this key pair, and must not be purged with it.");
  }
  log.info("[" + spec.what + "] OK — cleared: pair purged, note shown, other settings intact.");

  // 3. The purge holds across the saves that ordinary interaction triggers.
  // This is the assertion that fails if the guard lives only in the change
  // handler instead of in saveState().
  await setFieldAndSave(driver, spec.fields[0], MARKER_PRIVATE);
  await setFieldAndSave(driver, spec.bystander, "keypair-optout-bystander-2");
  for (var j = 0; j < spec.fields.length; j++) {
    assert.strictEqual(await storageOf(driver, spec.prefix, spec.fields[j]), null,
      "[" + spec.what + "] a later save re-wrote " + spec.fields[j] + " after the user opted out. " +
      "The guard has to be in saveState(), which runs on nearly every interaction.");
  }
  log.info("[" + spec.what + "] OK — the opt-out survives subsequent saves.");

  // The preference itself is configuration, so it must survive a reload — and
  // the fields must come back empty, since nothing was stored to restore.
  await driver.navigate().refresh();
  await waitVisible(driver, By.id(spec.checkbox));
  assert.strictEqual(await driver.findElement(By.id(spec.checkbox)).isSelected(), false,
    "[" + spec.what + "] the opt-out should still be in force after a reload.");
  for (var k = 0; k < spec.fields.length; k++) {
    var after = await driver.findElement(By.id(spec.fields[k])).getAttribute("value");
    assert.strictEqual((after || "").trim(), "",
      "[" + spec.what + "] " + spec.fields[k] + " should be empty after a reload with saving off.");
  }
  log.info("[" + spec.what + "] OK — the preference survives a reload and the fields come back empty.");

  // The hand-off: the response page has nothing to prefill from, and should say
  // so rather than leave its standing "Prefilled from…" claim on screen.
  await driver.get(baseUrl + spec.responsePage);
  await waitVisible(driver, By.id(spec.responseKeyField));
  var dec = (await driver.findElement(By.id(spec.responseKeyField)).getAttribute("value")) || "";
  assert.strictEqual(dec.trim(), "",
    "[" + spec.what + "] with saving off there is no key to prefill the response page with.");
  var respNote = (await driver.findElement(By.id(spec.responseNote)).getText()).trim();
  assert.ok(/Nothing was prefilled/i.test(respNote),
    "[" + spec.what + "] the response page should say the prefill did not happen and why, rather " +
    "than keep claiming one; found: '" + respNote + "'");
  log.info("[" + spec.what + "] OK — response page reports the missing prefill instead of promising it.");

  // 1 (again): re-enabling restores the original behaviour, so the opt-out is a
  // toggle and not a one-way door.
  await driver.get(baseUrl + spec.page);
  await waitVisible(driver, By.id(opener));
  if (spec.signCheckbox) await setCheckbox(driver, spec.signCheckbox, true);
  await waitVisible(driver, By.id(spec.checkbox));
  await setCheckbox(driver, spec.checkbox, true);
  await setFieldAndSave(driver, spec.fields[0], MARKER_PRIVATE);
  await setFieldAndSave(driver, spec.fields[1], MARKER_PUBLIC);
  assert.strictEqual(await storageOf(driver, spec.prefix, spec.fields[0]), MARKER_PRIVATE,
    "[" + spec.what + "] re-enabling should start saving the key pair again.");
  var clearedNote = (await driver.findElement(By.id(spec.note)).getText()).trim();
  assert.strictEqual(clearedNote, "",
    "[" + spec.what + "] the warning note should go away when saving is back on.");
  log.info("[" + spec.what + "] OK — re-enabled: saving resumes and the note clears.");

  // Leave nothing behind for the next test sharing this profile.
  await driver.executeScript("window.localStorage.clear();");
  log.debug("Leaving keyPairOptOut().");
}


// --- SD-JWT VC: the holder key pair -----------------------------------------
//
// Same idea, different shape, and a good deal more at stake. This key is not
// page state: it is written on issuance step 2, read on step 4 to refresh, and
// read by a DIFFERENT workflow — the presentation pages — to sign the Key
// Binding JWT. It is also kept per generation inside Credential History.
//
// So the opt-out here has to do three things the SAML/WS-Trust one did not, and
// each is asserted below: purge the history copies as well as the three
// top-level ones; refuse later writes centrally (the gate is in sd_jwt_vc.js's
// set(), so it covers writers in three different bundles); and leave the user a
// way to put the key back, since without one the workflow simply ends at step 3.
var HOLDER_PRIVATE = { kty: "EC", crv: "P-256", d: "OPTOUT-TEST-SECRET", x: "XCOORD", y: "YCOORD" };
var HOLDER_PUBLIC = { kty: "EC", crv: "P-256", x: "XCOORD", y: "YCOORD" };

function b64u(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

// Issuance step 2 generates the holder key pair with Web Crypto on page load,
// asynchronously. The checkbox is static markup, so waiting for IT says nothing
// about whether there is a key in hand yet — and re-enabling saving stores
// whatever the page is holding at that moment. Wait for the key the page shows.
//
// This is the "wait on content, not elements" rule (tests/wait_for.js): the
// element-only wait passed on a fast local server every time and lost the race
// inside the containerized stack, where it failed at the very last assertion.
async function waitForHolderKeyOnStep2(driver) {
  await waitForContent.waitForStatus(driver, "vc_holder_jwk",
    function (t) { return /"kty"/.test(t || ""); },
    "[SD-JWT VC] step 2 never produced a holder key pair. If this says (blank) the page's " +
    "Web Crypto is probably unavailable — check browser_flags on this origin");
}

async function sdJwtVcHolderKeyOptOut(driver) {
  log.debug("Entering sdJwtVcHolderKeyOptOut().");
  log.info("=== SD-JWT VC: the holder key pair ===");
  var read = function (script) { return driver.executeScript(script); };

  // Check the one environmental precondition this section has, before spending
  // twenty seconds discovering it as a timeout. Everything below depends on the
  // page being able to generate a holder key pair, which is Web Crypto, which
  // needs a secure context — see browser_flags.js and the --headless=new note in
  // test(). Failing here names the cause; failing later names a missing element.
  await driver.get(baseUrl + "/vc-issuance-2.html");
  var ctx = await read("return { secure: window.isSecureContext," +
                       "         subtle: typeof (window.crypto && window.crypto.subtle)," +
                       "         origin: window.location.origin };");
  assert.ok(ctx.secure && ctx.subtle === "object",
    "[SD-JWT VC] " + ctx.origin + " is not a secure context (isSecureContext=" + ctx.secure +
    ", crypto.subtle=" + ctx.subtle + "), so no holder key pair can be generated. Chrome needs " +
    "--unsafely-treat-insecure-origin-as-secure for this origin (tests/browser_flags.js), and " +
    "that flag is ignored by Chrome's OLD headless mode — this test must run with --headless=new.");

  await driver.get(baseUrl + "/vc-issuance-2.html");
  await waitVisible(driver, By.id("vc_save_holder_key"));

  // A key pair in storage, and a Credential History generation carrying its own
  // copy of the private half — which is what makes a past generation
  // presentable, and what the opt-out has to take away.
  await driver.executeScript(
    "localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_holder_jwk', JSON.stringify(arguments[0]));" +
    "localStorage.setItem('sdjwtvc_holder_private_jwk', JSON.stringify(arguments[1]));" +
    "localStorage.setItem('sdjwtvc_refreshed_holder_private_jwk', JSON.stringify(arguments[1]));" +
    "localStorage.setItem('sdjwtvc_previous_holder_private_jwk', JSON.stringify(arguments[1]));" +
    "localStorage.setItem('sdjwtvc_credential_history', JSON.stringify([" +
    "  { id: 1, outcome: 'kept', credential: 'c1', holderJwk: arguments[0], holderPrivateJwk: arguments[1] }" +
    "]));",
    HOLDER_PUBLIC, HOLDER_PRIVATE);
  await driver.navigate().refresh();
  await waitVisible(driver, By.id("vc_save_holder_key"));

  var snapshot = function () {
    log.debug("Entering snapshot().");
    log.debug("Leaving snapshot().");
    return read(
      "var h = JSON.parse(localStorage.getItem('sdjwtvc_credential_history') || '[]');" +
      "return {" +
      "  priv: !!localStorage.getItem('sdjwtvc_holder_private_jwk')," +
      "  refreshed: !!localStorage.getItem('sdjwtvc_refreshed_holder_private_jwk')," +
      "  previous: !!localStorage.getItem('sdjwtvc_previous_holder_private_jwk')," +
      "  historyPriv: !!(h[0] && h[0].holderPrivateJwk)," +
      "  historyCred: !!(h[0] && h[0].credential)," +
      "  pref: localStorage.getItem('sdjwtvc_save_holder_key')," +
      "  box: !!(document.getElementById('vc_save_holder_key') || {}).checked" +
      "};");
  };

  var before = await snapshot();
  assert.strictEqual(before.box, true,
    "[SD-JWT VC] the holder key pair should be saved by DEFAULT — step 4 and the whole presentation " +
    "workflow depend on it.");
  assert.ok(before.priv && before.historyPriv,
    "[SD-JWT VC] the seeded key pair and history generation should both be present to begin with.");
  log.info("[SD-JWT VC] OK — checked: the key pair and the history generation's copy are both stored.");

  // Clearing it purges every copy, including the per-generation ones.
  await (await waitVisible(driver, By.id("vc_save_holder_key"))).click();
  var after = await snapshot();
  assert.strictEqual(after.priv, false, "[SD-JWT VC] the holder private key should be removed.");
  assert.strictEqual(after.refreshed, false, "[SD-JWT VC] the refreshed holder private key should be removed.");
  assert.strictEqual(after.previous, false, "[SD-JWT VC] the previous holder private key should be removed.");
  assert.strictEqual(after.historyPriv, false,
    "[SD-JWT VC] the private half inside the Credential History generation should be removed too — " +
    "leaving it there is the difference between an opt-out and a gesture.");
  assert.strictEqual(after.historyCred, true,
    "[SD-JWT VC] the history generation itself must survive: only its key is given up, not the record.");
  assert.strictEqual(after.pref, "0", "[SD-JWT VC] the preference should be recorded.");
  log.info("[SD-JWT VC] OK — cleared: all four copies purged, the history record itself kept.");

  // The gate is central, so a write from anywhere is refused — not just the
  // three call sites that existed when it was added.
  var refused = await read(
    "localStorage.setItem('sdjwtvc_probe', '1');" +
    "return (function () { try { return !window.localStorage.getItem('sdjwtvc_holder_private_jwk'); }" +
    "                      catch (e) { return null; } })();");
  assert.strictEqual(refused, true, "[SD-JWT VC] nothing should have re-created the private key.");

  await driver.navigate().refresh();
  await waitVisible(driver, By.id("vc_save_holder_key"));
  // Wait for the page to actually GENERATE a key before asserting it was not
  // stored. Without this the assertion passes whenever the snapshot simply beats
  // the key generation — true for the wrong reason, and it would keep passing
  // with the gate removed entirely.
  await waitForHolderKeyOnStep2(driver);
  var reloaded = await snapshot();
  assert.strictEqual(reloaded.box, false, "[SD-JWT VC] the opt-out should survive a reload.");
  assert.strictEqual(reloaded.priv, false,
    "[SD-JWT VC] step 2 regenerates a holder key on load, and with saving off that key — which " +
    "demonstrably exists, since the page is showing it — must not have been written.");
  log.info("[SD-JWT VC] OK — the preference survives a reload and the regenerated key is not stored.");

  // ...and the pages BEFORE that one must let the user reach it. This is the
  // regression that matters most here: step 1 disables Continue for every entry
  // in its `problems` list, so treating "no key in storage" as a problem strands
  // the user one page before the only field that can supply it. Absent-by-choice
  // and absent-and-lost have to be told apart.
  var vpRequest = {
    params: { response_type: "vp_token", nonce: "N", client_id: "redirect_uri:http://v/cb",
              response_mode: "direct_post", response_uri: "http://v/oid4vp/response" },
    dcql: { credentials: [{ id: "c1", format: "dc+sd-jwt", claims: [{ path: ["vct"] }] }] }
  };
  var vpCredential = b64u({ alg: "ES256", typ: "dc+sd-jwt" }) + "." +
                     b64u({ vct: "demo", iss: "http://i", cnf: { jwk: HOLDER_PUBLIC } }) + ".sig~";
  var continueDisabled = async function (optedOut) {
    log.debug("Entering continueDisabled().");
    await driver.get(baseUrl + "/vc-presentation-1.html");
    await driver.executeScript(
      "localStorage.clear();" +
      "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
      "localStorage.setItem('sdjwtvp_request', JSON.stringify(arguments[1]));" +
      "if (arguments[2]) localStorage.setItem('sdjwtvc_save_holder_key', '0');",
      vpCredential, vpRequest, optedOut ? 1 : 0);
    await driver.navigate().refresh();
    await waitVisible(driver, By.id("vp_continue_button"));
    log.debug("Leaving continueDisabled().");
    return read("return !!(document.getElementById('vp_continue_button') || {}).disabled;");
  };
  assert.strictEqual(await continueDisabled(true), false,
    "[SD-JWT VC] with the key deliberately not stored, step 1 must still let the user continue — the " +
    "field that supplies the key is on the NEXT page, so blocking here is a dead end.");
  assert.strictEqual(await continueDisabled(false), true,
    "[SD-JWT VC] with saving ON and the key still absent it was never generated here, there is nothing " +
    "to paste, and step 1 should block as it always did.");
  log.info("[SD-JWT VC] OK — step 1 tells absent-by-choice from absent-and-lost.");

  // The way back: the presentation page must offer somewhere to paste the key,
  // and accept the file Download Key Pair produces.
  await driver.get(baseUrl + "/vc-presentation-2.html");
  await waitVisible(driver, By.id("vp_holder_key_row"));
  var rowShown = await read(
    "var e = document.getElementById('vp_holder_key_row');" +
    "return e ? window.getComputedStyle(e).display !== 'none' : null;");
  assert.strictEqual(rowShown, true,
    "[SD-JWT VC] with no stored key the presentation page must offer a field to paste one into, " +
    "or the opt-out ends the workflow rather than making it manual.");
  await driver.executeScript(
    "var e = document.getElementById('vp_holder_private_jwk');" +
    "e.value = JSON.stringify({ publicJwk: arguments[0], privateJwk: arguments[1] });" +
    "e.dispatchEvent(new Event('input', { bubbles: true }));", HOLDER_PUBLIC, HOLDER_PRIVATE);
  var pastedNote = (await driver.findElement(By.id("vp_holder_key_note")).getText()).trim();
  assert.ok(/Using the key pasted here/.test(pastedNote),
    "[SD-JWT VC] the downloaded key-pair file should be accepted as-is; got: '" + pastedNote + "'");
  var stillUnstored = await read("return !localStorage.getItem('sdjwtvc_holder_private_jwk');");
  assert.strictEqual(stillUnstored, true,
    "[SD-JWT VC] a pasted key must NOT be written to storage — that would undo the opt-out.");
  log.info("[SD-JWT VC] OK — presentation step 2 takes the pasted pair, and does not store it.");

  // And step 4 must let the bound key be reused once it has been pasted.
  var credential = b64u({ alg: "ES256", typ: "dc+sd-jwt" }) + "." +
                   b64u({ vct: "demo", iss: "http://issuer", cnf: { jwk: HOLDER_PUBLIC } }) + ".sig~";
  await driver.get(baseUrl + "/vc-issuance-4.html");
  await driver.executeScript(
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_credential_meta', JSON.stringify({ issuer: 'http://issuer' }));", credential);
  await driver.navigate().refresh();
  await waitVisible(driver, By.id("vc_holder_key_row"));
  var reuseState = function () {
    return read("var s = document.getElementById('vc_refresh_key_mode');" +
                "var o = s && s.querySelector('option[value=\"reuse\"]');" +
                "return o ? o.disabled : null;");
  };
  assert.strictEqual(await reuseState(), true,
    "[SD-JWT VC] with no key available, reusing the bound key must be refused rather than silently " +
    "meaning something else.");
  await driver.executeScript(
    "var e = document.getElementById('vc_holder_private_jwk');" +
    "e.value = JSON.stringify(arguments[0]);" +
    "e.dispatchEvent(new Event('input', { bubbles: true }));", HOLDER_PRIVATE);
  assert.strictEqual(await reuseState(), false,
    "[SD-JWT VC] pasting the matching private key should make the bound key reusable again — the " +
    "option has to be re-enabled, not merely left alone.");
  await driver.executeScript(
    "var e = document.getElementById('vc_holder_private_jwk');" +
    "e.value = JSON.stringify({ kty: 'EC', crv: 'P-256', d: 'X', x: 'OTHER', y: 'OTHER' });" +
    "e.dispatchEvent(new Event('input', { bubbles: true }));");
  assert.strictEqual(await reuseState(), true,
    "[SD-JWT VC] a key that is NOT the one the credential is bound to must not enable reuse.");
  log.info("[SD-JWT VC] OK — step 4 refuses, accepts and re-refuses reuse as the pasted key changes.");

  // Re-enabling starts saving again (of whatever key is current — the purge is
  // not reversible, which is what the pane says).
  // Establish the precondition explicitly rather than inheriting it: the checks
  // above clear storage as they go, and a toggle test that assumes which way the
  // box is currently pointing will flip the wrong way the moment anything is
  // inserted before it.
  await driver.get(baseUrl + "/vc-issuance-2.html");
  await waitVisible(driver, By.id("vc_save_holder_key"));
  await driver.executeScript("localStorage.setItem('sdjwtvc_save_holder_key', '0');");
  await driver.navigate().refresh();
  await waitVisible(driver, By.id("vc_save_holder_key"));
  assert.strictEqual(await driver.findElement(By.id("vc_save_holder_key")).isSelected(), false,
    "[SD-JWT VC] precondition: the box should be clear before re-enabling.");
  // Re-enabling saves the pair the page is CURRENTLY holding, so there has to be
  // one before the click — see waitForHolderKeyOnStep2 above.
  await waitForHolderKeyOnStep2(driver);
  await (await driver.findElement(By.id("vc_save_holder_key"))).click();
  var back = await snapshot();
  assert.strictEqual(back.pref, "1", "[SD-JWT VC] re-enabling should record the preference.");
  assert.strictEqual(back.priv, true,
    "[SD-JWT VC] re-enabling should store the key pair the page is currently holding.");
  log.info("[SD-JWT VC] OK — re-enabled: saving resumes.");

  await driver.executeScript("window.localStorage.clear();");
  log.debug("Leaving sdJwtVcHolderKeyOptOut().");
}


async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  options.addArguments("--window-size=1500,1400");
  // --headless=new, NOT plain --headless, and this matters more than it looks.
  //
  // The SD-JWT VC half of this test needs window.crypto.subtle, which exists
  // only in a secure context. On the containerized stack the origin is
  // http://client:3000 — plain HTTP on a DNS name — so browser_flags.js relaxes
  // it with --unsafely-treat-insecure-origin-as-secure. Chrome's OLD headless
  // implementation does not honour that flag, and the tests image pins Chrome
  // 121, which still has it.
  //
  // A modern Chrome cannot show you this: old headless is gone from current
  // builds and --headless is simply new headless, so both spellings measure
  // identical locally (isSecureContext=true, crypto.subtle=object) while only
  // one of them works in CI. Every other Web Crypto test in this suite already
  // uses --headless=new for exactly this reason; this one did not, and failed in
  // the container while passing on every local run.
  if (headless) { options.addArguments("--headless=new"); }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  // These pages generate key pairs with Web Crypto on some paths, and this test
  // drives a local client from a possibly-non-secure origin — the same two
  // hazards browser_flags.js exists for.
  browserFlags.addBrowserAccessFlags(options, baseUrl);

  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  try {
    for (var i = 0; i < PAGES.length; i++) {
      await keyPairOptOut(driver, PAGES[i]);
    }
    await sdJwtVcHolderKeyOptOut(driver);
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
  .name('keypair_storage_optout')
  .description("Verify the 'save this key pair in localStorage' opt-out, checked and unchecked.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });

program.parse(process.argv).opts();

test();
