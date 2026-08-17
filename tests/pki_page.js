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
//   * and the TLS pane growing a browser-side option, which is the one thing
//     the design of this page forbids.
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

// ---------------------------------------------------------------------------
// 1. The page loads, offers what the modules define, and offers no TLS option
//    the browser could not honour.
// ---------------------------------------------------------------------------
async function thePageOffersWhatTheModulesDefine(driver) {
  log.debug("Entering thePageOffersWhatTheModulesDefine().");
  await driver.get(baseUrl + PAGE);
  await waitVisible(driver, By.id("pki_key_alg"));
  await driver.executeScript("window.localStorage.clear();");
  await driver.get(baseUrl + PAGE);
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
// 2. The workflow: a root, an intermediate, an issuing CA and a leaf, built
//    entirely through the form.
// ---------------------------------------------------------------------------
async function generateKeyPair(driver, algId) {
  log.debug("Entering generateKeyPair(). alg=" + algId);
  const before = await textOf(driver, "pki_status");
  await selectOption(driver, "pki_key_alg", algId);
  await click(driver, "pki_generate");
  await driver.wait(async function () {
    const priv = await valueOf(driver, "pki_private_key");
    return priv && priv.indexOf("-----BEGIN") === 0;
  }, CRYPTO_WAIT, "the key pair fields never filled for " + algId);
  const status = await textOf(driver, "pki_status");
  assert.notStrictEqual(status, before,
    "the status line did not change after generating a key pair");
  const publicPem = await valueOf(driver, "pki_public_key");
  assert.ok(publicPem.indexOf("-----BEGIN PUBLIC KEY-----") === 0,
    algId + ": the public key field does not hold a SubjectPublicKeyInfo PEM");
  log.debug("Leaving generateKeyPair().");
}

async function issueThrough(driver, spec) {
  log.debug("Entering issueThrough(). subject=" + spec.cn);
  await generateKeyPair(driver, spec.keyAlg);
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

  const before = await textOf(driver, "pki_status");
  await click(driver, "pki_issue");
  const status = await waitForStatusChange(driver, "pki_status", before,
      "the certificate for " + spec.cn + " to be issued");
  assert.ok(status.indexOf("Issued") >= 0,
    "issuing " + spec.cn + " failed: " + status);
  assert.ok(status.indexOf(spec.cn) >= 0,
    "the status line names a different subject than the one issued: " +
    status);
  log.debug("Leaving issueThrough().");
  return status;
}

async function theHierarchyIsBuiltThroughTheForm(driver) {
  log.debug("Entering theHierarchyIsBuiltThroughTheForm().");
  await driver.get(baseUrl + PAGE);
  await waitVisible(driver, By.id("pki_key_alg"));
  await driver.executeScript("window.localStorage.clear();");
  await driver.get(baseUrl + PAGE);
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
// 3. The store survives a reload. A "certificate authority" that does not is
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
// 4. The private-key opt-out, in both states — the same four things
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
// 5. The list fields' syntax, which is what the extension editor is made of.
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
// 6. The TLS test, end to end through the api.
//
// It is pointed at the CLIENT's own plain-HTTP port, which is a deliberate
// choice: a handshake that FAILS with a real alert proves the whole round trip
// — page to api, api to socket, report back to page — and needs no TLS service
// of its own. A handshake that succeeds against a service this suite happens
// to have would prove less and skip more often.
// ---------------------------------------------------------------------------
async function theTlsTestGoesThroughTheApi(driver) {
  log.debug("Entering theTlsTestGoesThroughTheApi().");
  await driver.get(baseUrl + PAGE);
  await waitVisible(driver, By.id("pki_tls_host"));

  const backendNoticeShown = await driver.executeScript(
    "var e = document.getElementById('pki_backend_notice');" +
    "return !!e && e.style.display !== 'none';");
  if (backendNoticeShown) {
    log.info("SKIPPING the TLS section: this build has no api behind it " +
      "(backendAvailable is false), and this test is only made by an api.");
    log.debug("Leaving theTlsTestGoesThroughTheApi(). Skipped.");
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
// 7. The browser console must be clean. A page that throws on load looks
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
  if (headless) { options.addArguments("--headless=new"); }
  // The secure-context and private-network hazards. This page is ALL Web
  // Crypto, so it is exactly the kind that fails without these.
  browserFlags.addBrowserAccessFlags(options, baseUrl);

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
    await theListFieldSyntaxIsWhatThePageDocuments(driver);
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
