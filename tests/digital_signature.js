const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'digital_signature',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
var cryptoWait = Math.max(waitTime, 20000);
// node-forge RSA 2048-bit key generation is pure JS and can take several
// seconds.
var rsaWait = Math.max(waitTime, 60000);
// SLH-DSA signing (small-signature / high-security sets) can take many seconds.
var slhWait = Math.max(waitTime, 240000);

// Every hash the RSA and ECC panes offer.
var HASHES = ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384',
    'SHA3-512',
              'BLAKE2b-512', 'BLAKE3-256', 'RIPEMD-160', 'SHA-1', 'MD5'];
// Hashes with no PKCS#1 v1.5 DigestInfo OID — PSS only.
var RSA_V15_UNSUPPORTED = { 'BLAKE2b-512': true, 'BLAKE3-256': true };
var SLH_PARAMS = [
  "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s",
      "SLH-DSA-SHA2-192f",
  "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s",
      "SLH-DSA-SHAKE-128f",
  "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s",
      "SLH-DSA-SHAKE-256f"
];
var ECC_ECDSA_CURVES = ['P-256', 'P-384', 'P-521', 'secp256k1'];
var ECC_EDDSA_CURVES = ['Ed25519', 'Ed448'];
// Schemes that hash the message themselves (no Hash selection applies).
var ECC_OTHER_SCHEMES = ['secp256k1-schnorr', 'bls12-381'];
var ML_PARAMS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
// BBS: both ciphersuites the draft defines. They are not two spellings of one
// scheme — different expand_message, different fixed P1 — so everything below
// is done once per suite and a signature from one must NOT verify under the
// other.
var BBS_SUITES = ['BLS12-381-SHA-256', 'BLS12-381-SHAKE-256'];
// The draft's own test vectors, vendored as tests/bbs_vectors.json. Driving
// them through the PAGE is what says the pane's field handling — its message
// splitting, its hex mode, its KeyGen inputs — produces the draft's bytes and
// not merely bytes the page itself agrees with.
var BBS_VECTORS = require("./bbs_vectors.json");
var BBS_MESSAGES = ['given_name:Alice', 'family_name:Smith',
                    'birthdate:1980-01-01', 'country:US'];
// RSA is the one pane with an explicit key-size dropdown; the others vary size
// via their parameter set / curve. Two common sizes (3072 keygen is the slower,
// pure-JS one); 4096 is available in the app but omitted here to bound runtime.
var RSA_KEY_SIZES = ['2048', '3072'];
// Symmetric MAC panes (prefix + algorithms), grouped by family.
var MAC_FAMILIES = [
  { name: 'Keyed-Hash MACs', prefix: 'khmac',
    algs: ['HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512', 'HMAC-SHA3-256',
           'HMAC-SHA3-512',
           'HMAC-SHA1', 'KMAC128', 'KMAC256', 'BLAKE2b', 'BLAKE2s', 'BLAKE3'] },
  { name: 'Block-Cipher MACs', prefix: 'bcmac', algs: ['AES-CMAC',
   'AES-CBC-MAC', 'AES-GMAC'] },
  { name: 'Universal-Hash MACs', prefix: 'uhmac', algs: ['Poly1305',
   'SipHash-2-4'] }
];

// ===========================================================================
// UI helpers
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
async function waitForValue(driver, locator, pred, msg, timeout) {
  log.debug("Entering waitForValue().");
  await driver.wait(async function () {
    try {
      return pred((await driver.findElement(locator).getAttribute("value")) ||
                  "");
    } catch (e) {
      return false;
    }
  }, timeout || cryptoWait, msg);
  log.debug("Leaving waitForValue().");
  return await getValue(driver, locator);
}
async function selectValue(driver, id, value) {
  log.debug("Entering selectValue().");
  await new Select(driver.findElement(By.id(id))).selectByValue(value);
  log.debug("Leaving selectValue().");
}
// The inline handlers read "return digital_signature.<fn>(...)". Match with the
// "digital_signature." prefix so e.g. "sign" does not also match "rsaSign".
function onclickBtn(fn) {
  log.debug("Entering onclickBtn().");
  log.debug("Leaving onclickBtn().");
  return By.xpath("//input[contains(@onclick, \"digital_signature." + fn +
                  "(\")]");
}
// MAC buttons pass a pane prefix, e.g. digital_signature.macCompute('khmac').
// Match the call and the pane prefix without assuming a quote style: the live
// site's HTML is minified, which rewrites the inline-attribute quotes from
// single to double (macGenerateKey('khmac') -> macGenerateKey("khmac")). Each
// of macGenerateKey/macCompute/macVerify references a single prefix, so the
// conjunction still identifies exactly one button per pane.
function macBtn(fn, prefix) {
  log.debug("Entering macBtn().");
  log.debug("Leaving macBtn().");
  return By.xpath("//input[contains(@onclick, \"digital_signature." + fn +
                  "(\") and contains(@onclick, \"" + prefix + "\")]");
}

// Generate a key pair for a pane and wait until both key fields populate.
async function generateKeys(driver, cfg) {
  log.debug("Entering generateKeys().");
  await click(driver, onclickBtn(cfg.gen));
  await waitForValue(driver, By.id(cfg.privId),
                     function (v) { return v.trim().length > 0; },
    "[" + cfg.name + "] private key was not generated.", cfg.wait);
  await waitForValue(driver, By.id(cfg.pubId),
                     function (v) { return v.trim().length > 0; },
    "[" + cfg.name + "] public key was not generated.", cfg.wait);
  log.debug("Leaving generateKeys().");
}

// Assuming a key pair is present, set a fresh value, sign, and validate.
async function signAndValidate(driver, cfg, label) {
  log.debug("Entering signAndValidate().");
  var value = "Digital signature test :: " + label + " :: " +
      new Date().toISOString();
  await setInput(driver, By.id(cfg.valueId), value);

  await driver.findElement(By.id(cfg.signatureId)).clear();
  await click(driver, onclickBtn(cfg.sign));
  var sig = await waitForValue(driver, By.id(cfg.signatureId),
      function (v) { return v.trim().length > 0; },
    "[" + label + "] signature was not produced.", cfg.wait);

  await click(driver, onclickBtn(cfg.validate));
  var status = await waitForValue(driver, By.id(cfg.statusId),
    function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
    "[" + label + "] validation did not complete.", cfg.wait);
  assert.ok(status.indexOf("VALID ✓") !== -1,
    "[" + label + "] signature did not validate. Status: " + status);
  log.info("[" + label + "] OK — signature (" + sig.length +
           " b64 chars) validated.");
  log.debug("Leaving signAndValidate().");
}

// ===========================================================================
// Panes
// ===========================================================================
var SLH = { name: 'SLH-DSA', valueId: 'ds_value', signatureId: 'ds_signature',
  privId: 'ds_private_key', pubId: 'ds_public_key', statusId: 'ds_status',
  gen: 'generateKeys', sign: 'sign', validate: 'validate', wait: slhWait,
  download: 'downloadKeys', ksFormatId: 'ds_slh_ks_format',
      ksPwId: 'ds_slh_ks_password' };
var RSA = { name: 'RSA', valueId: 'ds_rsa_value',
    signatureId: 'ds_rsa_signature',
  privId: 'ds_rsa_private_key', pubId: 'ds_rsa_public_key',
      statusId: 'ds_rsa_status',
  gen: 'rsaGenerateKeys', sign: 'rsaSign', validate: 'rsaValidate',
      wait: rsaWait,
  download: 'rsaDownloadKeys', ksFormatId: 'ds_rsa_ks_format',
      ksPwId: 'ds_rsa_ks_password' };
var ECC = { name: 'ECC', valueId: 'ds_ecc_value',
    signatureId: 'ds_ecc_signature',
  privId: 'ds_ecc_private_key', pubId: 'ds_ecc_public_key',
      statusId: 'ds_ecc_status',
  gen: 'eccGenerateKeys', sign: 'eccSign', validate: 'eccValidate',
      wait: cryptoWait,
  download: 'eccDownloadKeys', ksFormatId: 'ds_ecc_ks_format',
      ksPwId: 'ds_ecc_ks_password' };
var ML = { name: 'ML-DSA', valueId: 'ds_ml_value',
    signatureId: 'ds_ml_signature',
  privId: 'ds_ml_private_key', pubId: 'ds_ml_public_key',
      statusId: 'ds_ml_status',
  gen: 'mldsaGenerateKeys', sign: 'mldsaSign', validate: 'mldsaValidate',
      wait: cryptoWait,
  download: 'mldsaDownloadKeys', ksFormatId: 'ds_ml_ks_format',
      ksPwId: 'ds_ml_ks_password' };

var BBS = { name: 'BBS', valueId: 'ds_bbs_messages',
    signatureId: 'ds_bbs_signature',
  privId: 'ds_bbs_private_key', pubId: 'ds_bbs_public_key',
      statusId: 'ds_bbs_status',
  gen: 'bbsGenerateKeys', sign: 'bbsSign', validate: 'bbsValidate',
      wait: cryptoWait,
  download: 'bbsDownloadKeys', ksFormatId: 'ds_bbs_ks_format',
      ksPwId: 'ds_bbs_ks_password' };

// Pane #1 — SLH-DSA: key generation depends on the parameter set, so generate
// keys for each one, then sign + validate.
async function testSlhDsa(driver) {
  log.debug("Entering testSlhDsa().");
  log.info("=== Pane #1 SLH-DSA — " + SLH_PARAMS.length +
           " parameter sets ===");
  for (var i = 0; i < SLH_PARAMS.length; i++) {
    var alg = SLH_PARAMS[i];
    await selectValue(driver, 'ds_param', alg);
    await generateKeys(driver, SLH);
    await signAndValidate(driver, SLH, 'SLH-DSA ' + alg);
  }
  log.debug("Leaving testSlhDsa().");
}

// Pane #2 — RSA: keys are independent of padding/hash, so generate once, then
// test every padding × hash combination (v1.5 + BLAKE2b-512 has no DigestInfo
// OID and is intentionally excluded — that combination uses PSS instead).
async function testRsa(driver) {
  log.debug("Entering testRsa().");
  log.info("=== Pane #2 RSA — key size × padding × hash ===");
  var paddings = [['v1_5', 'PKCS#1 v1.5'], ['pss', 'PSS']];
  for (var s = 0; s < RSA_KEY_SIZES.length; s++) {
    var size = RSA_KEY_SIZES[s];
    await selectValue(driver, 'ds_rsa_bits', size);
    await generateKeys(driver, RSA);   // keys are independent of padding/hash
    for (var p = 0; p < paddings.length; p++) {
      for (var h = 0; h < HASHES.length; h++) {
        var padVal = paddings[p][0], hash = HASHES[h];
        if (padVal === 'v1_5' && RSA_V15_UNSUPPORTED[hash]) {
          log.info("[RSA " + size + "-bit " + paddings[p][1] + " / " + hash +
                   "] skipped (no PKCS#1 v1.5 OID; PSS covers it).");
          continue;
        }
        await selectValue(driver, 'ds_rsa_padding', padVal);
        await selectValue(driver, 'ds_rsa_hash', hash);
        await signAndValidate(driver, RSA, 'RSA ' + size + '-bit ' +
                              paddings[p][1] + ' / ' + hash);
      }
    }
  }
  log.debug("Leaving testRsa().");
}

// Pane #3 — ECC: keys depend on the curve, so generate once per curve. ECDSA
// curves test every hash; EdDSA curves fix their own hash (tested once).
async function testEcc(driver) {
  log.debug("Entering testEcc().");
  log.info("=== Pane #3 ECC — curve × hash combinations ===");
  for (var c = 0; c < ECC_ECDSA_CURVES.length; c++) {
    var curve = ECC_ECDSA_CURVES[c];
    await selectValue(driver, 'ds_ecc_curve', curve);
    await generateKeys(driver, ECC);
    for (var h = 0; h < HASHES.length; h++) {
      await selectValue(driver, 'ds_ecc_hash', HASHES[h]);
      await signAndValidate(driver, ECC, 'ECDSA ' + curve + ' / ' + HASHES[h]);
    }
  }
  for (var e = 0; e < ECC_EDDSA_CURVES.length; e++) {
    var ed = ECC_EDDSA_CURVES[e];
    await selectValue(driver, 'ds_ecc_curve', ed);
    await generateKeys(driver, ECC);
    await signAndValidate(driver, ECC, 'EdDSA ' + ed);
  }
  for (var s = 0; s < ECC_OTHER_SCHEMES.length; s++) {
    var scheme = ECC_OTHER_SCHEMES[s];
    await selectValue(driver, 'ds_ecc_curve', scheme);
    await generateKeys(driver, ECC);
    await signAndValidate(driver, ECC, scheme);
  }
  log.debug("Leaving testEcc().");
}

// Pane #4 — ML-DSA: key generation depends on the parameter set (fast lattice
// scheme), so generate keys for each set, then sign + validate.
async function testMldsa(driver) {
  log.debug("Entering testMldsa().");
  log.info("=== Pane #4 ML-DSA — " + ML_PARAMS.length + " parameter sets ===");
  for (var i = 0; i < ML_PARAMS.length; i++) {
    await selectValue(driver, 'ds_ml_param', ML_PARAMS[i]);
    await generateKeys(driver, ML);
    await signAndValidate(driver, ML, 'ML-DSA ' + ML_PARAMS[i]);
  }
  log.debug("Leaving testMldsa().");
}

// ===========================================================================
// Pane #5 — BBS over BLS12-381
// ===========================================================================
// A textarea holds the message LIST, so setInput's sendKeys would have to
// carry newlines through the browser; set the value directly and fire the
// events a real edit would, which is both faster and unambiguous about what
// ended up in the field. (Runs in the BROWSER: no bunyan in here.)
async function setTextarea(driver, id, text) {
  log.debug("Entering setTextarea().");
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]); e.value = arguments[1]; " +
    "e.dispatchEvent(new Event('input', { bubbles: true })); " +
    "e.dispatchEvent(new Event('change', { bubbles: true }));", id, text);
  log.debug("Leaving setTextarea().");
}

// Click a BBS button and wait for the status line it produces. The pane defers
// its work so the "…" status paints first, so waiting for the *field* a button
// fills is not enough on its own — every check here waits on the status.
async function bbsClickAndWait(driver, fn, pred, message) {
  log.debug("Entering bbsClickAndWait().");
  await driver.executeScript("var e = document.getElementById('ds_bbs_" +
                             "status'); if (e) e.value = '';");
  await click(driver, onclickBtn(fn));
  var status = await waitForValue(driver, By.id('ds_bbs_status'), pred,
                                  message, cryptoWait);
  log.debug("Leaving bbsClickAndWait().");
  return status;
}
// Every one of this pane's in-progress messages ENDS with an ellipsis, and
// only those do — testing for one anywhere in the string would also match the
// finished messages that quote a range ("index (0…3)"), and then the wait
// would hang on a status the page had already produced.
function settled(v) {
  log.debug("Entering settled().");
  log.debug("Leaving settled().");
  return v.length > 0 && !/…\s*$/.test(v);
}
function verdict(v) {
  log.debug("Entering verdict().");
  log.debug("Leaving verdict().");
  return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1;
}

// Fill the pane's octet-string fields. Everything except the message list is a
// single-line input, so a plain sendKeys is fine for those.
async function bbsSetInputs(driver, opts) {
  log.debug("Entering bbsSetInputs().");
  if (opts.encoding) await selectValue(driver, 'ds_bbs_encoding',
                                       opts.encoding);
  if (opts.messages !== undefined) await setTextarea(driver,
      'ds_bbs_messages', opts.messages);
  var singles = [['header', 'ds_bbs_header'], ['ph', 'ds_bbs_ph'],
    ['disclosed', 'ds_bbs_disclosed'], ['keyMaterial', 'ds_bbs_key_material'],
    ['keyInfo', 'ds_bbs_key_info'], ['keyDst', 'ds_bbs_key_dst']];
  for (var i = 0; i < singles.length; i++) {
    var key = singles[i][0], id = singles[i][1];
    if (opts[key] === undefined) continue;
    if (opts[key] === '') {
      await driver.findElement(By.id(id)).clear();
    } else {
      await setInput(driver, By.id(id), opts[key]);
    }
  }
  log.debug("Leaving bbsSetInputs().");
}

// One suite's full round: derive a key pair, sign the list, validate it, then
// every way the draft says it must fail, then derived proofs.
async function testBbsSuite(driver, suite) {
  log.debug("Entering testBbsSuite().");
  log.info("=== Pane #5 BBS — " + suite + " ===");
  await selectValue(driver, 'ds_bbs_suite', suite);
  await bbsSetInputs(driver, { encoding: 'text',
    messages: BBS_MESSAGES.join("\n"), header: 'BBS test header',
    ph: 'verifier nonce 12345', disclosed: '0, 2', keyMaterial: '',
    keyInfo: '', keyDst: '' });

  // KeyGen. An empty key material field means "32 random bytes, and show me
  // which", so the pair on screen stays reproducible from what is on screen.
  var gen = await bbsClickAndWait(driver, 'bbsGenerateKeys',
    function (v) { return v.indexOf("Derived ") !== -1 ||
              v.indexOf("error") !== -1; },
    "[BBS " + suite + "] key generation did not report.");
  // Assert on the STATUS, not only on the key fields: a failed generation
  // leaves the previous suite's key sitting in them, and a key the pane then
  // both signs and verifies with is perfectly self-consistent.
  assert.ok(gen.indexOf("Derived ") !== -1,
    "[BBS " + suite + "] key generation failed. Status: " + gen);
  var sk = (await getValue(driver, By.id('ds_bbs_private_key'))).trim();
  var pk = (await getValue(driver, By.id('ds_bbs_public_key'))).trim();
  var ikm = (await getValue(driver, By.id('ds_bbs_key_material'))).trim();
  assert.ok(/^[0-9a-f]{64}$/i.test(sk),
    "[BBS " + suite + "] private key is not a 32-byte scalar in hex: " + sk);
  assert.ok(/^[0-9a-f]{192}$/i.test(pk),
    "[BBS " + suite + "] public key is not a compressed 96-byte G2 point.");
  assert.ok(/^[0-9a-f]{64}$/i.test(ikm),
    "[BBS " + suite + "] the generated key material was not shown.");
  log.info("[BBS " + suite + "] OK — key pair derived from shown material.");

  // KeyGen is a derivation, not a random draw: the same material and key_info
  // must give the same key, and changing key_info must change it.
  await bbsClickAndWait(driver, 'bbsGenerateKeys', settled,
    "[BBS " + suite + "] second key generation did not report.");
  assert.strictEqual((await getValue(driver,
      By.id('ds_bbs_private_key'))).trim(), sk,
    "[BBS " + suite + "] KeyGen is not deterministic for the same material.");
  await bbsSetInputs(driver, { keyInfo: 'some key info' });
  await bbsClickAndWait(driver, 'bbsGenerateKeys', settled,
    "[BBS " + suite + "] key generation with key_info did not report.");
  assert.notStrictEqual((await getValue(driver,
      By.id('ds_bbs_private_key'))).trim(), sk,
    "[BBS " + suite + "] key_info was ignored — it must change the key.");
  await bbsSetInputs(driver, { keyInfo: '' });
  await bbsClickAndWait(driver, 'bbsGenerateKeys', settled,
    "[BBS " + suite + "] key generation did not report.");
  assert.strictEqual((await getValue(driver,
      By.id('ds_bbs_private_key'))).trim(), sk,
    "[BBS " + suite + "] clearing key_info did not restore the key.");
  log.info("[BBS " + suite + "] OK — KeyGen deterministic; key_info bound in.");

  // Sign the list, then validate it.
  var signed = await bbsClickAndWait(driver, 'bbsSign',
    function (v) { return v.indexOf("Signed") !== -1 ||
              v.indexOf("error") !== -1; },
    "[BBS " + suite + "] signing did not report.");
  assert.ok(signed.indexOf("signature is 80 bytes") !== -1,
    "[BBS " + suite + "] a BBS signature is 80 bytes. Status: " + signed);
  var sig = (await getValue(driver, By.id('ds_bbs_signature'))).trim();
  assert.ok(sig.length > 0, "[BBS " + suite + "] no signature was produced.");
  var st = await bbsClickAndWait(driver, 'bbsValidate', verdict,
    "[BBS " + suite + "] validation did not complete.");
  assert.ok(st.indexOf("VALID ✓") !== -1,
    "[BBS " + suite + "] signature did not validate. Status: " + st);
  log.info("[BBS " + suite + "] OK — signed " + BBS_MESSAGES.length +
           " messages and validated.");

  // What the signature binds: every message, their ORDER, their COUNT, and the
  // header. Each is a separate way a holder could otherwise cheat.
  var refusals = [
    { label: 'a changed message',
      set: { messages: ['given_name:Mallory'].concat(
          BBS_MESSAGES.slice(1)).join("\n") } },
    { label: 'a reordered list',
      set: { messages: [BBS_MESSAGES[1], BBS_MESSAGES[0]].concat(
          BBS_MESSAGES.slice(2)).join("\n") } },
    { label: 'a dropped message',
      set: { messages: BBS_MESSAGES.slice(0, 3).join("\n") } },
    { label: 'an added message',
      set: { messages: BBS_MESSAGES.concat(['role:admin']).join("\n") } },
    { label: 'a changed header', set: { header: 'a different header' } }
  ];
  for (var r = 0; r < refusals.length; r++) {
    await bbsSetInputs(driver, refusals[r].set);
    var bad = await bbsClickAndWait(driver, 'bbsValidate', verdict,
      "[BBS " + suite + " / " + refusals[r].label +
          "] validation did not complete.");
    assert.ok(bad.indexOf("INVALID ✗") !== -1,
      "[BBS " + suite + "] " + refusals[r].label +
          " must not validate. Status: " + bad);
    log.info("[BBS " + suite + " / " + refusals[r].label +
             "] correctly refused.");
    await bbsSetInputs(driver, { messages: BBS_MESSAGES.join("\n"),
                                 header: 'BBS test header' });
  }
  // The control: after all that, the untouched signature still validates, so
  // the refusals above are about the defects and not about the verifier.
  var control = await bbsClickAndWait(driver, 'bbsValidate', verdict,
    "[BBS " + suite + " control] validation did not complete.");
  assert.ok(control.indexOf("VALID ✓") !== -1,
    "[BBS " + suite + " control] the restored inputs must still validate. " +
        "Status: " + control);

  // Derived proofs — what BBS is for.
  var proofStatus = await bbsClickAndWait(driver, 'bbsProofGen', settled,
    "[BBS " + suite + "] proof derivation did not report.");
  assert.ok(proofStatus.indexOf("disclosing 2 of 4") !== -1,
    "[BBS " + suite + "] expected a proof disclosing 2 of 4. Status: " +
        proofStatus);
  var proof = (await getValue(driver, By.id('ds_bbs_proof'))).trim();
  assert.ok(proof.length > 0, "[BBS " + suite + "] no proof was produced.");
  var pv = await bbsClickAndWait(driver, 'bbsProofVerify', verdict,
    "[BBS " + suite + "] proof verification did not complete.");
  assert.ok(pv.indexOf("Proof VALID ✓") !== -1,
    "[BBS " + suite + "] the derived proof did not verify. Status: " + pv);
  log.info("[BBS " + suite + "] OK — proof over 2 of 4 messages verified.");

  // Unlinkability: a second derivation of the SAME signature must differ, and
  // must also verify. This is the property an SD-JWT cannot offer.
  await bbsClickAndWait(driver, 'bbsProofGen', settled,
    "[BBS " + suite + "] second proof derivation did not report.");
  var proof2 = (await getValue(driver, By.id('ds_bbs_proof'))).trim();
  assert.notStrictEqual(proof2, proof,
    "[BBS " + suite + "] two derivations of one signature were IDENTICAL — " +
        "the proofs would be linkable.");
  var pv2 = await bbsClickAndWait(driver, 'bbsProofVerify', verdict,
    "[BBS " + suite + "] second proof verification did not complete.");
  assert.ok(pv2.indexOf("Proof VALID ✓") !== -1,
    "[BBS " + suite + "] the second derived proof did not verify.");
  log.info("[BBS " + suite + "] OK — fresh randomness per derivation, both " +
           "proofs valid.");

  // A proof must be refused when the verifier's nonce differs (replay), when a
  // disclosed message is claimed to be something else, and when the disclosure
  // set does not match the one the proof was derived for.
  var proofRefusals = [
    { label: 'replay under another presentation header',
      set: { ph: 'a different nonce' },
      restore: { ph: 'verifier nonce 12345' } },
    { label: 'a substituted disclosed message',
      set: { messages: BBS_MESSAGES.slice(0, 2).concat(['country:FR'],
          BBS_MESSAGES.slice(3)).join("\n") },
      restore: { messages: BBS_MESSAGES.join("\n") } },
    { label: 'a different disclosure set',
      set: { disclosed: '1, 3' }, restore: { disclosed: '0, 2' } }
  ];
  for (var p = 0; p < proofRefusals.length; p++) {
    await bbsSetInputs(driver, proofRefusals[p].set);
    var bad2 = await bbsClickAndWait(driver, 'bbsProofVerify', verdict,
      "[BBS " + suite + " / " + proofRefusals[p].label +
          "] proof verification did not complete.");
    assert.ok(bad2.indexOf("INVALID ✗") !== -1,
      "[BBS " + suite + "] " + proofRefusals[p].label +
          " must be refused. Status: " + bad2);
    log.info("[BBS " + suite + " / " + proofRefusals[p].label +
             "] correctly refused.");
    await bbsSetInputs(driver, proofRefusals[p].restore);
  }

  // The two ends of the disclosure range are both legal: reveal nothing (still
  // a proof that a signature exists over the whole list) and reveal everything.
  var extremes = [['', 'disclosing 0 of 4'], ['0 1 2 3', 'disclosing 4 of 4']];
  for (var x = 0; x < extremes.length; x++) {
    await bbsSetInputs(driver, { disclosed: extremes[x][0] });
    var made = await bbsClickAndWait(driver, 'bbsProofGen', settled,
      "[BBS " + suite + "] proof derivation did not report.");
    assert.ok(made.indexOf(extremes[x][1]) !== -1,
      "[BBS " + suite + "] expected \"" + extremes[x][1] + "\", got: " + made);
    var okx = await bbsClickAndWait(driver, 'bbsProofVerify', verdict,
      "[BBS " + suite + "] proof verification did not complete.");
    assert.ok(okx.indexOf("Proof VALID ✓") !== -1,
      "[BBS " + suite + "] the " + extremes[x][1] +
          " proof did not verify. Status: " + okx);
    log.info("[BBS " + suite + "] OK — " + extremes[x][1] + ".");
  }

  // An index that is not a message index is refused by the pane rather than
  // handed to the library.
  await bbsSetInputs(driver, { disclosed: '9' });
  var refused = await bbsClickAndWait(driver, 'bbsProofGen', settled,
    "[BBS " + suite + "] out-of-range index did not report.");
  assert.ok(refused.indexOf("not a message index") !== -1,
    "[BBS " + suite + "] an out-of-range disclosed index must be named. " +
        "Status: " + refused);
  await bbsSetInputs(driver, { disclosed: '0, 2' });
  log.debug("Leaving testBbsSuite().");
}

// The draft's own vectors, driven through the page in hex mode. This is the
// check that cannot be satisfied by the page agreeing with itself: BBS has
// several constants (each suite's fixed P1, the API id the DSTs are built
// from, the generator derivation) where a signer and a verifier can share a
// mistake and agree perfectly with each other and with nobody else.
async function testBbsDraftVectors(driver, suite) {
  log.debug("Entering testBbsDraftVectors().");
  var vectors = BBS_VECTORS.suites[suite];
  assert.ok(vectors, "no vendored test vectors for " + suite +
            " in tests/bbs_vectors.json.");
  log.info("=== Pane #5 BBS — " + suite + " against the draft's vectors ===");
  await selectValue(driver, 'ds_bbs_suite', suite);
  var kp = vectors.keypair;
  await bbsSetInputs(driver, { encoding: 'hex', keyMaterial: kp.keyMaterial,
    keyInfo: kp.keyInfo, keyDst: kp.keyDst });
  await bbsClickAndWait(driver, 'bbsGenerateKeys', settled,
    "[BBS " + suite + " vectors] key generation did not report.");
  assert.strictEqual((await getValue(driver,
      By.id('ds_bbs_private_key'))).trim().toLowerCase(), kp.secretKey,
    "[BBS " + suite + " vectors] KeyGen did not reproduce the draft's " +
        "secret key.");
  assert.strictEqual((await getValue(driver,
      By.id('ds_bbs_public_key'))).trim().toLowerCase(), kp.publicKey,
    "[BBS " + suite + " vectors] the draft's public key was not derived.");
  log.info("[BBS " + suite + " vectors] OK — KeyGen matches the draft.");

  for (var i = 0; i < vectors.signatures.length; i++) {
    var v = vectors.signatures[i];
    // The draft's multi-message vector ENDS with an empty message, and the
    // pane expresses one as an extra newline (one trailing newline is the
    // line terminator). Joining with a trailing newline covers both shapes.
    await bbsSetInputs(driver, { encoding: 'hex',
      messages: v.messages.join("\n") + "\n", header: v.header });
    await setTextarea(driver, 'ds_bbs_public_key', v.publicKey);
    await setTextarea(driver, 'ds_bbs_signature', v.signature ?
        Buffer.from(v.signature, "hex").toString("base64") : '');
    var st = await bbsClickAndWait(driver, 'bbsValidate', verdict,
      "[BBS " + suite + " / " + v.name + "] validation did not complete.");
    var expected = v.valid ? "VALID ✓" : "INVALID ✗";
    assert.ok(st.indexOf(expected) !== -1,
      "[BBS " + suite + " / " + v.name + "] " + v.caseName + " must be " +
          expected + ". Status: " + st);
    log.info("[BBS " + suite + " / " + v.name + "] OK — " + v.caseName + ".");

    // For the valid ones, the page must also PRODUCE the draft's bytes:
    // accepting a correct signature is much weaker than emitting one.
    if (!v.valid) continue;
    await setTextarea(driver, 'ds_bbs_private_key', v.secretKey);
    await driver.findElement(By.id('ds_bbs_signature')).clear();
    await bbsClickAndWait(driver, 'bbsSign', settled,
      "[BBS " + suite + " / " + v.name + "] signing did not report.");
    var made = (await getValue(driver, By.id('ds_bbs_signature'))).trim();
    assert.strictEqual(Buffer.from(made, "base64").toString("hex"),
        v.signature,
      "[BBS " + suite + " / " + v.name + "] the page produced a different " +
          "signature from the draft's. BBS signing is deterministic, so a " +
          "correct implementation emits these exact bytes.");
    log.info("[BBS " + suite + " / " + v.name +
             "] OK — byte-identical signature.");
  }

  for (var j = 0; j < vectors.proofs.length; j++) {
    var pv = vectors.proofs[j];
    var disclosed = pv.disclosedIndexes.join(", ");
    await bbsSetInputs(driver, { encoding: 'hex',
      messages: pv.messages.join("\n") + "\n", header: pv.header,
      ph: pv.presentationHeader, disclosed: disclosed });
    await setTextarea(driver, 'ds_bbs_public_key', pv.publicKey);
    await setTextarea(driver, 'ds_bbs_proof',
        Buffer.from(pv.proof, "hex").toString("base64"));
    var st2 = await bbsClickAndWait(driver, 'bbsProofVerify', verdict,
      "[BBS " + suite + " / " + pv.name +
          "] proof verification did not complete.");
    assert.ok(st2.indexOf(pv.valid ? "Proof VALID ✓" : "INVALID ✗") !== -1,
      "[BBS " + suite + " / " + pv.name + "] " + pv.caseName +
          " did not get the draft's verdict. Status: " + st2);
    log.info("[BBS " + suite + " / " + pv.name + "] OK — " + pv.caseName +
             ".");
  }
  // Leave the pane on text input for whatever runs next.
  await bbsSetInputs(driver, { encoding: 'text', keyMaterial: '',
      keyInfo: '', keyDst: '' });
  log.debug("Leaving testBbsDraftVectors().");
}

// A key and a signature belong to ONE ciphersuite. Nothing about the fields on
// screen says which, so the page must refuse the pairing rather than quietly
// verify it — this is the mistake that a self-consistent implementation makes
// invisibly.
async function testBbsSuiteSeparation(driver) {
  log.debug("Entering testBbsSuiteSeparation().");
  log.info("=== Pane #5 BBS — the two ciphersuites do not interoperate ===");
  await selectValue(driver, 'ds_bbs_suite', BBS_SUITES[0]);
  await bbsSetInputs(driver, { encoding: 'text',
    messages: BBS_MESSAGES.join("\n"), header: 'BBS test header',
    keyMaterial: '', keyInfo: '', keyDst: '' });
  await bbsClickAndWait(driver, 'bbsGenerateKeys', settled,
    "[BBS separation] key generation did not report.");
  await bbsClickAndWait(driver, 'bbsSign', settled,
    "[BBS separation] signing did not report.");
  var ok = await bbsClickAndWait(driver, 'bbsValidate', verdict,
    "[BBS separation] validation did not complete.");
  assert.ok(ok.indexOf("VALID ✓") !== -1,
    "[BBS separation] the control signature must validate. Status: " + ok);
  await selectValue(driver, 'ds_bbs_suite', BBS_SUITES[1]);
  var st = await bbsClickAndWait(driver, 'bbsValidate',
    function (v) { return verdict(v) || v.indexOf("error") !== -1; },
    "[BBS separation] cross-suite validation did not complete.");
  assert.ok(st.indexOf("INVALID ✗") !== -1 || st.indexOf("error") !== -1,
    "[BBS separation] a " + BBS_SUITES[0] + " signature verified under " +
        BBS_SUITES[1] + ". Status: " + st);
  log.info("[BBS separation] OK — " + st);
  await selectValue(driver, 'ds_bbs_suite', BBS_SUITES[0]);
  log.debug("Leaving testBbsSuiteSeparation().");
}

async function testBbs(driver) {
  log.debug("Entering testBbs().");
  for (var i = 0; i < BBS_SUITES.length; i++) {
    await testBbsSuite(driver, BBS_SUITES[i]);
    await testBbsDraftVectors(driver, BBS_SUITES[i]);
  }
  await testBbsSuiteSeparation(driver);
  log.debug("Leaving testBbs().");
}

// Symmetric MAC panes: for every algorithm, generate a key, compute a tag, and
// verify it (positive). For the first algorithm in each family, also confirm a
// modified value fails verification (tamper / negative).
async function testMacs(driver) {
  log.debug("Entering testMacs().");
  for (var f = 0; f < MAC_FAMILIES.length; f++) {
    var fam = MAC_FAMILIES[f];
    log.info("=== Symmetric " + fam.name + " — " + fam.algs.length +
             " algorithm(s) ===");
    for (var a = 0; a < fam.algs.length; a++) {
      var alg = fam.algs[a], label = fam.name + " / " + alg;
      // Selecting the algorithm auto-generates a key (onchange); click the
      // button too to exercise it explicitly.
      await selectValue(driver, 'ds_' + fam.prefix + '_alg', alg);
      await click(driver, macBtn('macGenerateKey', fam.prefix));
      await waitForValue(driver, By.id('ds_' + fam.prefix + '_key'),
        function (v) { return v.trim().length > 0; }, "[" + label +
                  "] key was not generated.", cryptoWait);

      await setInput(driver, By.id('ds_' + fam.prefix + '_value'),
        "MAC test :: " + alg + " :: " + new Date().toISOString());
      await driver.findElement(By.id('ds_' + fam.prefix + '_mac')).clear();
      await click(driver, macBtn('macCompute', fam.prefix));
      var tag = await waitForValue(driver, By.id('ds_' + fam.prefix + '_mac'),
        function (v) { return v.trim().length > 0; }, "[" + label +
                  "] MAC tag was not produced.", cryptoWait);

      await click(driver, macBtn('macVerify', fam.prefix));
      var st = await waitForValue(driver, By.id('ds_' + fam.prefix + '_status'),
        function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
        "[" + label + "] verify did not complete.", cryptoWait);
      assert.ok(st.indexOf("VALID ✓") !== -1, "[" + label +
                "] MAC did not validate. Status: " + st);
      log.info("[" + label + "] OK — tag (" + tag.length +
               " b64 chars) verified.");

      if (a === 0) {
        // Tamper: change the value, re-verify against the old tag -> INVALID.
        await setInput(driver, By.id('ds_' + fam.prefix + '_value'),
                       "tampered — different message");
        await click(driver, macBtn('macVerify', fam.prefix));
        var st2 = await waitForValue(driver, By.id('ds_' + fam.prefix +
            '_status'),
          function (v) { return v.indexOf("✓") !== -1 ||
                    v.indexOf("✗") !== -1; },
          "[" + label + " tamper] verify did not complete.", cryptoWait);
        assert.ok(st2.indexOf("INVALID ✗") !== -1,
          "[" + label + " tamper] expected INVALID, got: " + st2);
        log.info("[" + label + " tamper] correctly rejected.");
      }
    }
  }
  log.debug("Leaving testMacs().");
}

// Select a keystore format, optionally set a password, click Download Keys, and
// assert the status line reports the expected outcome. (Consistent with the
// jwt_tools test, this verifies the reported result — not the file on disk.)
async function downloadKeystore(driver, cfg, format, password, expectSubstr,
                                label) {
  log.debug("Entering downloadKeystore().");
  await selectValue(driver, cfg.ksFormatId, format);
  var pwEl = driver.findElement(By.id(cfg.ksPwId));
  await pwEl.clear();
  if (password) await pwEl.sendKeys(password);
  // Blank the status so we detect the message produced by THIS click.
  await driver.executeScript("var e=document.getElementById(arguments[0]); " +
                             "if(e) e.value='';", cfg.statusId);
  await click(driver, onclickBtn(cfg.download));
  var status = await waitForValue(driver, By.id(cfg.statusId),
    function (v) { return v.indexOf(expectSubstr) !== -1; },
    "[" + label + "] download status did not contain \"" + expectSubstr + "\".",
        cfg.wait);
  log.info("[" + label + "] " + status);
  log.debug("Leaving downloadKeystore().");
}

// Exercise every keystore format + optional password on all three panes,
// including the intentionally-unsupported combinations (which must report a
// clear message rather than silently do nothing).
async function testDownloads(driver) {
  log.debug("Entering testDownloads().");
  log.info("=== Keystore downloads ===");

  // SLH-DSA — reuse keys from the sign/validate phase. PEM + JWK (+password);
  // DER/PKCS#12 unsupported; PEM+password steered to JWK.
  await downloadKeystore(driver, SLH, 'pem', '',
                         'Downloaded key pair (slh-dsa-keys.pem)',
                         'SLH-DSA PEM');
  await downloadKeystore(driver, SLH, 'pem', 'pw123', 'only available in JWK',
                         'SLH-DSA PEM+pw (steered)');
  await downloadKeystore(driver, SLH, 'jwk', '', 'Downloaded JWK set',
                         'SLH-DSA JWK');
  await downloadKeystore(driver, SLH, 'jwk', 'pw123', 'PBES2-encrypted JWK',
                         'SLH-DSA JWK+pw');
  await downloadKeystore(driver, SLH, 'der', '', 'not supported',
                         'SLH-DSA DER (unsupported)');
  await downloadKeystore(driver, SLH, 'pkcs12', '', 'not supported',
                         'SLH-DSA PKCS#12 (unsupported)');

  // RSA — reuse the key pair generated in testRsa. Full format support.
  await downloadKeystore(driver, RSA, 'pem', '',
                         'Downloaded PEM (private + public key)', 'RSA PEM');
  await downloadKeystore(driver, RSA, 'pem', 'pw123', 'encrypted private key',
                         'RSA PEM+pw');
  await downloadKeystore(driver, RSA, 'der', '',
                         'Downloaded DER (private + public)', 'RSA DER');
  await downloadKeystore(driver, RSA, 'der', 'pw123', 'encrypted private',
                         'RSA DER+pw');
  await downloadKeystore(driver, RSA, 'jwk', '', 'Downloaded JWK set',
                         'RSA JWK');
  await downloadKeystore(driver, RSA, 'jwk', 'pw123', 'PBES2-encrypted JWK',
                         'RSA JWK+pw');
  await downloadKeystore(driver, RSA, 'pkcs12', '', 'requires a password',
                         'RSA PKCS#12 (password required)');
  await downloadKeystore(driver, RSA, 'pkcs12', 'pw123',
                         'Downloaded password-protected PKCS#12',
                         'RSA PKCS#12');

  // ECC — JWK for an ECDSA curve (EC JWK) and an EdDSA curve (OKP JWK);
  // PEM/DER/PKCS#12 unsupported.
  await selectValue(driver, 'ds_ecc_curve', 'P-256');
  await generateKeys(driver, ECC);
  await downloadKeystore(driver, ECC, 'jwk', '', 'Downloaded JWK set',
                         'ECC EC JWK');
  await downloadKeystore(driver, ECC, 'jwk', 'pw123', 'PBES2-encrypted JWK',
                         'ECC EC JWK+pw');
  await downloadKeystore(driver, ECC, 'pem', '', 'not supported',
                         'ECC PEM (unsupported)');
  await downloadKeystore(driver, ECC, 'pkcs12', '', 'not supported',
                         'ECC PKCS#12 (unsupported)');
  await selectValue(driver, 'ds_ecc_curve', 'Ed25519');
  await generateKeys(driver, ECC);
  await downloadKeystore(driver, ECC, 'jwk', '', 'Downloaded JWK set',
                         'ECC OKP JWK (Ed25519)');
  // Schnorr/BLS have no standard JWK — export must report that.
  await selectValue(driver, 'ds_ecc_curve', 'secp256k1-schnorr');
  await generateKeys(driver, ECC);
  await downloadKeystore(driver, ECC, 'jwk', '', 'JWK is not defined',
                         'Schnorr JWK (unsupported)');

  // ML-DSA: PEM + JWK (+password); DER/PKCS#12 unsupported.
  await selectValue(driver, 'ds_ml_param', 'ML-DSA-65');
  await generateKeys(driver, ML);
  await downloadKeystore(driver, ML, 'pem', '',
                         'Downloaded key pair (ml-dsa-keys.pem)', 'ML-DSA PEM');
  await downloadKeystore(driver, ML, 'jwk', '', 'Downloaded JWK set',
                         'ML-DSA JWK');
  await downloadKeystore(driver, ML, 'jwk', 'pw123', 'PBES2-encrypted JWK',
                         'ML-DSA JWK+pw');
  await downloadKeystore(driver, ML, 'pkcs12', '', 'not supported',
                         'ML-DSA PKCS#12 (unsupported)');

  // BBS: a JWK (OKP / Bls12381G2) with an optional PBES2 password, like the
  // ECC pane; PEM/DER/PKCS#12 have no standard BBS representation and must say
  // so. Reuses the key pair testBbs left in the pane.
  await downloadKeystore(driver, BBS, 'jwk', '', 'Downloaded JWK set',
                         'BBS JWK');
  await downloadKeystore(driver, BBS, 'jwk', 'pw123', 'PBES2-encrypted JWK',
                         'BBS JWK+pw');
  await downloadKeystore(driver, BBS, 'pem', '', 'not supported',
                         'BBS PEM (unsupported)');
  await downloadKeystore(driver, BBS, 'der', '', 'not supported',
                         'BBS DER (unsupported)');
  await downloadKeystore(driver, BBS, 'pkcs12', '', 'not supported',
                         'BBS PKCS#12 (unsupported)');
  log.debug("Leaving testDownloads().");
}

async function digitalSignatureActivities(driver) {
  log.debug("Entering digitalSignatureActivities().");
  log.info("Load the Digital Signature page.");
  await driver.get(baseUrl + "/digital_signature.html");
  await waitForValue(driver, By.id("ds_value"),
                     function (v) { return v.length > 0; },
    "Digital Signature page did not load / defaults not populated.");

  // Panes are collapsible; flip the "Expand all panes" switch so every field is
  // visible/interactable. Click the visible slider (the checkbox itself is
  // visually hidden); as a <label> descendant it toggles the checkbox, whose
  // onchange calls digital_signature.expandAll().
  await click(driver, By.id("ds_toggle_all_switch"));

  await testSlhDsa(driver);
  await testRsa(driver);
  await testEcc(driver);
  await testMldsa(driver);
  await testBbs(driver);
  await testMacs(driver);
  await testDownloads(driver);
  log.debug("Leaving digitalSignatureActivities().");
}

async function test() {
  log.debug("Entering test().");
  // This test clicks keystore-download buttons. On host runs (local/remote) the
  // browser is the user's real Chrome, whose default download dir is
  // ~/Downloads. Point downloads at a throwaway temp dir (removed below) so
  // nothing lands in the home directory; the test only asserts on the in-page
  // status, never the downloaded file, so the location is irrelevant to the
  // checks.
  const downloadDir = fs.mkdtempSync(path.join(os.tmpdir(),
      "idptools-selenium-dl-"));
  const options = new chrome.Options();
  options.setUserPreferences({
    "download.default_directory": downloadDir,
    "download.prompt_for_download": false,
    "download.directory_upgrade": true,
    "safebrowsing.enabled": true,
  });
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages (e.g. jwt_tools) under coverage.
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  // The signing panes are pure-JS (no crypto.subtle), and BBS proof derivation
  // needs only crypto.getRandomValues, which every context has — so signing
  // does not need a secure context. The KEYSTORE downloads do: a
  // password-protected JWK is a PBES2 JWE and that is Web Crypto. These flags
  // are what make the containerized origin (http://client:3000, plain HTTP on
  // a DNS name) trustworthy enough for it; without them the download section
  // fails reporting an error nothing else on the page would produce.
  var secureOrigin = baseUrl.replace(/\/+$/, "");
  options.addArguments("--unsafely-treat-insecure-origin-as-secure=" +
                       secureOrigin);
  options.addArguments("--user-data-dir=/tmp/digital-signature-chrome-" +
                       Date.now());
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

  try {
    log.info("Starting Test run.");
    await driver.manage().deleteAllCookies();
    await digitalSignatureActivities(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
    try {
      fs.rmSync(downloadDir, { recursive: true, force: true });
    } catch (e) {
      /* ignore */
    }
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('digital_signature')
  .description("Run Digital Signature UI test (SLH-DSA, RSA, ECC, ML-DSA, " +
      "BBS — all hashes, both BBS ciphersuites, plus the symmetric MACs).")
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
