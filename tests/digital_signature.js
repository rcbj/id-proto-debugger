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
// Building a tree is not filling in a field: even the smallest parameter sets
// this pane offers are 32 one-time key pairs, and the pool runs four browsers
// at once. `waitTime` is 2000ms and would be a coin toss here.
var hbsWait = Math.max(waitTime * 15, 30000);
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

var COMPOSITE = { name: 'Composite ML-DSA', valueId: 'ds_comp_value',
    signatureId: 'ds_comp_signature',
  privId: 'ds_comp_private_key', pubId: 'ds_comp_public_key',
      statusId: 'ds_comp_status',
  gen: 'compositeGenerateKeys', sign: 'compositeSign',
      validate: 'compositeValidate', wait: cryptoWait,
  download: 'compositeDownloadKeys', ksFormatId: 'ds_comp_ks_format',
      ksPwId: 'ds_comp_ks_password' };

var COMPOSITE_ALGS = ['ML-DSA-44-ES256', 'ML-DSA-65-ES256',
                      'ML-DSA-87-ES384', 'ML-DSA-44-Ed25519',
                      'ML-DSA-65-Ed25519', 'ML-DSA-87-Ed448'];

// The eleven post-quantum `alg` values the JWS pane offers. Kept apart from
// JWS_ALGS because they are driven once each in the compact serialization
// rather than across all three: SLH-DSA signing is seconds of pure JS, and
// what these need to prove is that the pane can carry them at all — the
// serializations are already exercised by the sixteen classical algorithms.
var JWS_PQ_ALGS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87',
                   'SLH-DSA-SHA2-128s', 'SLH-DSA-SHAKE-128s',
                   'ML-DSA-44-ES256', 'ML-DSA-65-ES256', 'ML-DSA-87-ES384',
                   'ML-DSA-44-Ed25519', 'ML-DSA-65-Ed25519',
                   'ML-DSA-87-Ed448'];

// Every fieldset the page carries, in order. THIS LIST IS THE POINT OF THE
// STRUCTURE CHECK BELOW: this job had no such assertion, and a whole new
// signing pane was added to the page without anybody noticing that nothing
// drove it. A pane list the page can outgrow silently is not a check.
var ALL_PANES = ['pane_signature', 'pane_hbs_signature',
                 'pane_rsa_signature', 'pane_ecc_signature',
                 'pane_mldsa_signature', 'pane_composite_signature',
                 'pane_bbs_signature', 'pane_jws_signature',
                 'pane_xml_signature', 'pane_khmac', 'pane_bcmac',
                 'pane_uhmac'];

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

// A checkbox, set directly. Nothing on this page listens for a change event on
// one — every option is read at the moment Sign or Validate runs — so this is
// the state the handler will see, without depending on where the label happens
// to sit in the layout.
async function setCheckbox(driver, id, on) {
  log.debug("Entering setCheckbox().");
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]); e.checked = arguments[1];",
    id, !!on);
  log.debug("Leaving setCheckbox().");
}

// A status line that has stopped moving. Both new panes paint a "…" line
// first and replace it when the work finishes, so waiting for a non-empty
// value would read the "…" and go on to assert against it.
function statusSettled(v) {
  log.debug("Entering statusSettled().");
  log.debug("Leaving statusSettled().");
  return v.trim().length > 0 && v.slice(-1) !== "\u2026";
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

// ===========================================================================
// The page carries exactly the panes this job knows about.
// ===========================================================================
// Added after a post-quantum pane reached the page with no test behind it.
// The cost of not having this was not hypothetical: `pane_composite_signature`
// shipped, worked, and was driven by nothing here.
async function testPageStructure(driver) {
  log.debug("Entering testPageStructure().");
  log.info("=== Page structure ===");
  const panes = await driver.executeScript(
    "var out = [];" +
    "var f = document.querySelectorAll('.ds-grid > fieldset');" +
    "for (var i = 0; i < f.length; i++) { out.push(f[i].id); }" +
    "return out;");
  assert.deepStrictEqual(panes, ALL_PANES,
    "the page carries " + panes.join(", ") + " but this test knows about " +
    ALL_PANES.join(", ") + ". A pane added without a case here is a pane " +
    "nothing drives.");

  // The JWS pane's algorithm list, likewise. The eleven post-quantum values
  // are the ones this most needs to hold: they were added to the dropdown
  // and, until this assertion existed, driven by nothing.
  const jwsAlgs = await driver.executeScript(
    "return Array.from(document.getElementById('ds_jws_alg').options)" +
    ".map(function (o) { return o.value; });");
  const known = JWS_ALGS.concat(JWS_PQ_ALGS).sort();
  assert.deepStrictEqual(jwsAlgs.slice().sort(), known,
    "the JWS pane offers " + jwsAlgs.join(", ") + " but this test drives " +
    known.join(", ") + ". Either an algorithm was added without a case " +
    "here, or one was removed.");
  log.info("[structure] OK — " + panes.length + " panes and " +
           jwsAlgs.length + " JWS algorithms, all known to this test.");
  log.debug("Leaving testPageStructure().");
}

// ===========================================================================
// Pane #5 — Composite ML-DSA (draft-ietf-jose-pq-composite-sigs-03)
// ===========================================================================
// The round trip is the easy half. What this pane exists to demonstrate is
// that a composite needs BOTH components, so the negative below matters more
// than the six positives: a composite that verified on its ML-DSA half alone
// would be strictly worse than plain ML-DSA, because it would carry a
// traditional signature nothing checks.
async function testComposite(driver) {
  log.debug("Entering testComposite().");
  log.info("=== Pane #5 Composite ML-DSA — " + COMPOSITE_ALGS.length +
           " algorithms ===");
  for (var i = 0; i < COMPOSITE_ALGS.length; i++) {
    await selectValue(driver, 'ds_comp_param', COMPOSITE_ALGS[i]);
    await generateKeys(driver, COMPOSITE);
    await signAndValidate(driver, COMPOSITE, 'Composite ' + COMPOSITE_ALGS[i]);
  }

  // The status line must name WHICH half failed. Corrupting the last bytes
  // of the signature hits the traditional component, which sits after the
  // fixed-length ML-DSA one — so the ML-DSA half must still report as valid.
  // A pane that said only "INVALID" would hide the difference between a
  // stripped component and a corrupt message, which is the one distinction
  // somebody debugging a composite actually needs.
  const corrupted = await driver.executeScript(
    "var t = document.getElementById('ds_comp_signature');" +
    "var s = atob(t.value); var b = s.split('');" +
    "b[s.length - 3] = String.fromCharCode(b[s.length - 3].charCodeAt(0) ^ 255);" +
    "t.value = btoa(b.join('')); return t.value.length;");
  assert.ok(corrupted > 0, "[Composite] could not corrupt the signature.");
  await click(driver, onclickBtn('compositeValidate'));
  var half = await waitForValue(driver, By.id('ds_comp_status'),
    function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
    "[Composite] validation of the corrupted signature did not complete.",
    cryptoWait);
  assert.ok(half.indexOf("INVALID ✗") !== -1,
    "[Composite] a signature with a corrupted traditional half must be " +
    "rejected. Status: " + half);
  assert.ok(/ML-DSA-87 half VERIFIES/.test(half),
    "[Composite] the untouched ML-DSA half should be reported as verifying, " +
    "so that a stripped component is distinguishable from a corrupt " +
    "message. Status: " + half);
  assert.ok(/Ed448 half does NOT verify/.test(half),
    "[Composite] the corrupted traditional half should be named. Status: " +
    half);
  log.info("[Composite half-failure] OK — " + half);

  // A truncated signature is MALFORMED, not "invalid": nothing was verified,
  // and saying "invalid" would imply something was.
  await driver.executeScript(
    "var t = document.getElementById('ds_comp_signature');" +
    "t.value = t.value.slice(0, t.value.length - 8);");
  await click(driver, onclickBtn('compositeValidate'));
  var malformed = await waitForValue(driver, By.id('ds_comp_status'),
    function (v) { return v.indexOf("✗") !== -1; },
    "[Composite] validation of the truncated signature did not complete.",
    cryptoWait);
  assert.ok(/MALFORMED/.test(malformed),
    "[Composite] a truncated signature must be reported as malformed rather " +
    "than merely invalid. Status: " + malformed);
  log.info("[Composite malformed] OK — " + malformed);
  log.debug("Leaving testComposite().");
}

// ===========================================================================
// The context string and the pre-hash are ALGORITHM CHANGES.
// ===========================================================================
// Both post-quantum panes gained two controls that a reader could easily take
// for options. They are not: a signature made under one context does not
// verify under another, and HashML-DSA is a different algorithm from ML-DSA.
// The page claims that in prose; this is what checks the wiring behind it.
async function testPqVariants(driver) {
  log.debug("Entering testPqVariants().");
  log.info("=== Post-quantum variants — context string and pre-hash ===");
  await selectValue(driver, 'ds_ml_param', 'ML-DSA-44');
  await generateKeys(driver, ML);

  // A context string separates contexts.
  await setInput(driver, By.id('ds_ml_ctx'), 'application-A');
  await setInput(driver, By.id(ML.valueId), 'context separation test');
  await driver.findElement(By.id(ML.signatureId)).clear();
  await click(driver, onclickBtn('mldsaSign'));
  await waitForValue(driver, By.id(ML.signatureId),
    function (v) { return v.trim().length > 0; },
    "[ML-DSA ctx] signature was not produced.", cryptoWait);
  await click(driver, onclickBtn('mldsaValidate'));
  var same = await waitForValue(driver, By.id(ML.statusId),
    function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
    "[ML-DSA ctx] validation did not complete.", cryptoWait);
  assert.ok(same.indexOf("VALID ✓") !== -1,
    "[ML-DSA ctx] the same context must verify. Status: " + same);

  await setInput(driver, By.id('ds_ml_ctx'), 'application-B');
  await click(driver, onclickBtn('mldsaValidate'));
  var other = await waitForValue(driver, By.id(ML.statusId),
    function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
    "[ML-DSA ctx] validation under the other context did not complete.",
    cryptoWait);
  assert.ok(other.indexOf("INVALID ✗") !== -1,
    "[ML-DSA ctx] a signature made for one context MUST NOT verify under " +
    "another — that separation is the whole reason the control exists. " +
    "Status: " + other);

  await setInput(driver, By.id('ds_ml_ctx'), '');
  await click(driver, onclickBtn('mldsaValidate'));
  var none = await waitForValue(driver, By.id(ML.statusId),
    function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
    "[ML-DSA ctx] validation with no context did not complete.", cryptoWait);
  assert.ok(none.indexOf("INVALID ✗") !== -1,
    "[ML-DSA ctx] nor as a pure signature with no context. Status: " + none);
  log.info("[ML-DSA ctx] OK — one context verifies, another does not, and " +
           "neither does none.");

  // The pre-hash selects HashML-DSA, which is a different algorithm.
  await selectValue(driver, 'ds_ml_prehash', 'SHA-256');
  await driver.findElement(By.id(ML.signatureId)).clear();
  await click(driver, onclickBtn('mldsaSign'));
  var hashedStatus = await waitForValue(driver, By.id(ML.statusId),
    function (v) { return v.indexOf("Signed") !== -1; },
    "[ML-DSA prehash] signing did not complete.", cryptoWait);
  assert.ok(/pre-hash/.test(hashedStatus),
    "[ML-DSA prehash] the status must say which variant ran, since a pure " +
    "and a pre-hashed signature are different algorithms. Status: " +
    hashedStatus);
  await click(driver, onclickBtn('mldsaValidate'));
  var hashedOk = await waitForValue(driver, By.id(ML.statusId),
    function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
    "[ML-DSA prehash] validation did not complete.", cryptoWait);
  assert.ok(hashedOk.indexOf("VALID ✓") !== -1,
    "[ML-DSA prehash] the same pre-hash must verify. Status: " + hashedOk);

  await selectValue(driver, 'ds_ml_prehash', 'SHA-512');
  await click(driver, onclickBtn('mldsaValidate'));
  var wrongHash = await waitForValue(driver, By.id(ML.statusId),
    function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
    "[ML-DSA prehash] validation under another hash did not complete.",
    cryptoWait);
  assert.ok(wrongHash.indexOf("INVALID ✗") !== -1,
    "[ML-DSA prehash] HashML-DSA with SHA-512 must not accept a SHA-256 " +
    "signature — the hash OID is inside the signed message. Status: " +
    wrongHash);

  await selectValue(driver, 'ds_ml_prehash', 'pure');
  await click(driver, onclickBtn('mldsaValidate'));
  var pure = await waitForValue(driver, By.id(ML.statusId),
    function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
    "[ML-DSA prehash] pure validation did not complete.", cryptoWait);
  assert.ok(pure.indexOf("INVALID ✗") !== -1,
    "[ML-DSA prehash] pure ML-DSA must not accept a pre-hashed signature. " +
    "Status: " + pure);
  log.info("[ML-DSA prehash] OK — HashML-DSA is a different algorithm in " +
           "both directions.");
  log.debug("Leaving testPqVariants().");
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
  // JWS: an RSA key takes the shared keystore matrix; a raw curve key or a
  // shared secret exports as the JWK that JOSE defines for it, and says so
  // for anything else rather than emitting a file nothing can read.
  await selectValue(driver, 'ds_jws_alg', 'ES256');
  await jwsClickAndWait(driver, 'jwsGenerateKeys', "[JWS] download key.");
  await downloadKeystore(driver, JWS, 'jwk', '', 'Downloaded JWK set',
                         'JWS EC JWK');
  await downloadKeystore(driver, JWS, 'jwk', 'pw123', 'PBES2-encrypted JWK',
                         'JWS EC JWK+pw');
  await downloadKeystore(driver, JWS, 'pem', '', 'not supported',
                         'JWS EC PEM (unsupported)');
  await selectValue(driver, 'ds_jws_alg', 'HS256');
  await jwsClickAndWait(driver, 'jwsGenerateKeys', "[JWS] secret download.");
  await downloadKeystore(driver, JWS, 'jwk', '', 'Downloaded JWK set',
                         'JWS oct JWK');
  await selectValue(driver, 'ds_jws_alg', 'RS256');
  await jwsClickAndWait(driver, 'jwsGenerateKeys', "[JWS] RSA download key.");
  await downloadKeystore(driver, JWS, 'pem', '',
                         'Downloaded PEM (private + public key)', 'JWS PEM');
  await downloadKeystore(driver, JWS, 'jwk', '', 'Downloaded JWK set',
                         'JWS RSA JWK');
  await downloadKeystore(driver, JWS, 'pkcs12', '', 'requires a password',
                         'JWS PKCS#12 (password required)');
  await downloadKeystore(driver, JWS, 'pkcs12', 'pw123',
                         'Downloaded password-protected PKCS#12',
                         'JWS PKCS#12');

  // XML Signature: the same split, plus the shared secret that has no
  // keystore format at all — which has to be said rather than silently
  // producing nothing.
  await selectValue(driver, 'ds_xml_sigalg', XML_SIG_RSA);
  await xmlClickAndWait(driver, 'xmlGenerateKeys', "[XML] download key.");
  await downloadKeystore(driver, XMLSIG, 'pem', '',
                         'Downloaded PEM (private + public key)', 'XML PEM');
  await downloadKeystore(driver, XMLSIG, 'jwk', '', 'Downloaded JWK set',
                         'XML RSA JWK');
  await downloadKeystore(driver, XMLSIG, 'pkcs12', 'pw123',
                         'Downloaded password-protected PKCS#12',
                         'XML PKCS#12');
  await selectValue(driver, 'ds_xml_sigalg', XML_SIG_ECDSA);
  await selectValue(driver, 'ds_xml_curve', 'P-256');
  await xmlClickAndWait(driver, 'xmlGenerateKeys', "[XML] EC download key.");
  await downloadKeystore(driver, XMLSIG, 'jwk', '', 'Downloaded JWK set',
                         'XML EC JWK');
  await downloadKeystore(driver, XMLSIG, 'pem', '', 'not supported',
                         'XML EC PEM (unsupported)');
  await selectValue(driver, 'ds_xml_sigalg', XML_SIG_HMAC);
  await xmlClickAndWait(driver, 'xmlGenerateKeys', "[XML] secret download.");
  await downloadKeystore(driver, XMLSIG, 'jwk', '',
                         'no keystore format', 'XML HMAC (no keystore)');
  await selectValue(driver, 'ds_xml_sigalg', XML_SIG_RSA);
  log.debug("Leaving testDownloads().");
}

// ===========================================================================
// Pane #6 — JWS
//
// Every registered algorithm through every serialization, then the parts of
// RFC 7515 that are rules rather than bytes. The BYTES are asserted elsewhere:
// tests/jws_engine.js hands each signature to node's own OpenSSL and to
// `jsonwebtoken`, because a round trip through this page agrees with itself
// whatever the implementation does. What only a browser can say is that the
// PANE is wired to the engine — that a checkbox reaches the option it names,
// and that a refusal reaches the status line.
// ===========================================================================
var JWS_ALGS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512',
                'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512',
                'EdDSA-Ed25519', 'EdDSA-Ed448', 'ES256K', 'none'];
var JWS_SERIALIZATIONS = ['compact', 'flattened', 'general'];

async function jwsClickAndWait(driver, fn, message) {
  log.debug("Entering jwsClickAndWait().");
  await click(driver, onclickBtn(fn));
  var status = await waitForValue(driver, By.id('ds_jws_status'),
      statusSettled, message, rsaWait);
  log.debug("Leaving jwsClickAndWait().");
  return status;
}

async function jwsGenerate(driver, alg, label) {
  log.debug("Entering jwsGenerate().");
  await selectValue(driver, 'ds_jws_alg', alg);
  var status = await jwsClickAndWait(driver, 'jwsGenerateKeys',
      "[JWS " + label + "] key generation did not finish.");
  assert.ok(/Generated|has no key/.test(status),
    "[JWS " + label + "] key generation reported: " + status);
  log.debug("Leaving jwsGenerate().");
}

async function testJws(driver) {
  log.debug("Entering testJws().");
  log.info("=== JWS (RFC 7515) ===");
  await setTextarea(driver, 'ds_jws_payload',
      JSON.stringify({ iss: 'https://as.example.com', sub: 'alice' }, null, 2));

  // The RSA key pair is generated ONCE and reused across RS*/PS*: six 2048-bit
  // generations in pure JS is a minute of runtime that asserts the same thing
  // six times. Changing the algorithm does not touch the key fields.
  var rsaReady = false;
  for (var a = 0; a < JWS_ALGS.length; a++) {
    var alg = JWS_ALGS[a];
    var isRsa = /^(RS|PS)/.test(alg);
    if (!isRsa || !rsaReady) {
      await jwsGenerate(driver, alg, alg);
      if (isRsa) rsaReady = true;
    } else {
      await selectValue(driver, 'ds_jws_alg', alg);
    }
    for (var t = 0; t < JWS_SERIALIZATIONS.length; t++) {
      var serialization = JWS_SERIALIZATIONS[t];
      await selectValue(driver, 'ds_jws_serialization', serialization);
      var signed = await jwsClickAndWait(driver, 'jwsSign',
          "[JWS " + alg + "/" + serialization + "] signing did not finish.");
      assert.ok(/^Signed/.test(signed),
        "[JWS " + alg + "/" + serialization + "] sign reported: " + signed);
      var verified = await jwsClickAndWait(driver, 'jwsValidate',
          "[JWS " + alg + "/" + serialization + "] validation did not " +
          "finish.");
      assert.ok(/VALID \u2713|Unsecured JWS/.test(verified),
        "[JWS " + alg + "/" + serialization + "] validate reported: " +
        verified);
    }
    await selectValue(driver, 'ds_jws_serialization', 'compact');
    log.info("[JWS " + alg + "] OK — signed and validated in all three " +
             "serializations.");
  }

  // The eleven post-quantum algorithms, compact only — see JWS_PQ_ALGS for
  // why. Each gets its own key pair: unlike the RSA family there is nothing
  // to reuse, because every one of these has a different key length.
  //
  // The header assertion is the one that matters. RFC 9964 and the two drafts
  // register these `alg` values verbatim, so what a peer sees in the
  // protected header has to be the registered string and not a label this
  // page invented for its dropdown.
  for (var q = 0; q < JWS_PQ_ALGS.length; q++) {
    var pqAlg = JWS_PQ_ALGS[q];
    await jwsGenerate(driver, pqAlg, pqAlg);
    var pqSigned = await jwsClickAndWait(driver, 'jwsSign',
        "[JWS " + pqAlg + "] signing did not finish.");
    assert.ok(/^Signed/.test(pqSigned),
      "[JWS " + pqAlg + "] sign reported: " + pqSigned);

    var decoded = await getValue(driver, By.id('ds_jws_decoded'));
    assert.ok(decoded.indexOf('"alg": "' + pqAlg + '"') !== -1,
      "[JWS " + pqAlg + "] the protected header must carry the registered " +
      "algorithm identifier verbatim. Decoded header was: " +
      decoded.slice(0, 200));

    var pqVerified = await jwsClickAndWait(driver, 'jwsValidate',
        "[JWS " + pqAlg + "] validation did not finish.");
    assert.ok(/VALID \u2713/.test(pqVerified),
      "[JWS " + pqAlg + "] validate reported: " + pqVerified);
    log.info("[JWS " + pqAlg + "] OK — signed and validated.");
  }

  // The rule this pane exists for: the payload must be JSON, and Sign says so
  // rather than signing whatever is in the box.
  await selectValue(driver, 'ds_jws_alg', 'HS256');
  await jwsGenerate(driver, 'HS256', 'HS256');
  await setTextarea(driver, 'ds_jws_payload', '{not json');
  var status = await jwsClickAndWait(driver, 'jwsSign',
      "[JWS] the non-JSON refusal did not finish.");
  assert.ok(/Refusing to sign/.test(status),
    "[JWS] a payload that is not JSON must be refused. Status: " + status);
  status = await jwsClickAndWait(driver, 'jwsValidatePayload',
      "[JWS] Validate JSON did not finish.");
  assert.ok(/NOT valid JSON/.test(status),
    "[JWS] Validate JSON must report an invalid payload. Status: " + status);
  await setTextarea(driver, 'ds_jws_payload', '{"a":1,"b":[1,2]}');
  status = await jwsClickAndWait(driver, 'jwsValidatePayload',
      "[JWS] Validate JSON did not finish on a good payload.");
  assert.ok(/is valid JSON \u2713/.test(status),
    "[JWS] Validate JSON must accept a good payload. Status: " + status);
  await click(driver, onclickBtn('jwsFormatPayload'));
  await waitForValue(driver, By.id('ds_jws_payload'),
      function (v) { return v.indexOf("\n") > 0; },
      "[JWS] Format JSON did not re-indent the payload.");
  log.info("[JWS] OK — a payload that is not JSON is refused by name.");

  // A changed payload must not verify. The signature is left alone and only
  // the middle part is swapped, so what fails is the signature rather than
  // the parsing.
  await jwsClickAndWait(driver, 'jwsSign', "[JWS] sign before tampering.");
  var jwsValue = await getValue(driver, By.id('ds_jws_signature'));
  var parts = jwsValue.split(".");
  await setTextarea(driver, 'ds_jws_signature', parts[0] + "." +
      Buffer.from('{"a":2}').toString("base64url") + "." + parts[2]);
  status = await jwsClickAndWait(driver, 'jwsValidate',
      "[JWS] the tampered validation did not finish.");
  assert.ok(/INVALID \u2717/.test(status),
    "[JWS] a tampered payload must not validate. Status: " + status);
  log.info("[JWS] OK — a tampered payload is refused.");

  // RFC 7515 App. F — a detached payload leaves the middle part empty, and
  // Validate reads it back out of the Payload box.
  await setCheckbox(driver, 'ds_jws_detached', true);
  await jwsClickAndWait(driver, 'jwsSign', "[JWS] detached signing.");
  jwsValue = await getValue(driver, By.id('ds_jws_signature'));
  assert.strictEqual(jwsValue.split(".")[1], "",
    "[JWS] a detached compact JWS must have an empty payload part.");
  status = await jwsClickAndWait(driver, 'jwsValidate',
      "[JWS] detached validation.");
  assert.ok(/VALID \u2713/.test(status),
    "[JWS] a detached JWS must validate against the Payload box. Status: " +
    status);
  await setCheckbox(driver, 'ds_jws_detached', false);
  log.info("[JWS] OK — detached payload (RFC 7515 App. F).");

  // RFC 7797 — an unencoded payload cannot ride in the compact serialization
  // when it contains a period, and a JSON payload hits that on any decimal
  // number. The refusal is the interesting half.
  await setTextarea(driver, 'ds_jws_payload', '{"pi":3.14}');
  await setCheckbox(driver, 'ds_jws_unencoded', true);
  status = await jwsClickAndWait(driver, 'jwsSign',
      "[JWS] the RFC 7797 compact refusal did not finish.");
  assert.ok(/RFC 7797/.test(status),
    "[JWS] an unencoded compact payload containing a period must be refused " +
    "by name. Status: " + status);
  await selectValue(driver, 'ds_jws_serialization', 'flattened');
  status = await jwsClickAndWait(driver, 'jwsSign',
      "[JWS] the RFC 7797 JSON signing did not finish.");
  assert.ok(/unencoded payload/.test(status),
    "[JWS] an unencoded payload must sign in a JSON serialization. Status: " +
    status);
  var doc = JSON.parse(await getValue(driver, By.id('ds_jws_signature')));
  var header = JSON.parse(Buffer.from(doc.protected,
      "base64url").toString("utf8"));
  assert.strictEqual(header.b64, false,
    "[JWS] b64 must be in the PROTECTED header (RFC 7797 §3).");
  assert.ok(header.crit && header.crit.indexOf("b64") >= 0,
    "[JWS] b64 MUST be listed in crit, so a recipient that does not " +
    "implement RFC 7797 rejects the JWS instead of verifying it against a " +
    "base64url that was never produced.");
  status = await jwsClickAndWait(driver, 'jwsValidate',
      "[JWS] the RFC 7797 validation did not finish.");
  assert.ok(/VALID \u2713/.test(status),
    "[JWS] an unencoded payload must validate. Status: " + status);
  await setCheckbox(driver, 'ds_jws_unencoded', false);
  await selectValue(driver, 'ds_jws_serialization', 'compact');
  log.info("[JWS] OK — RFC 7797 unencoded payload, and its compact refusal.");

  // RFC 7515 §7.1 — the compact serialization has nowhere to put an
  // unprotected header, so asking for one is an error rather than a silent
  // drop. A dropped member is one the caller believes is present.
  await setTextarea(driver, 'ds_jws_payload', '{"a":1}');
  await setTextarea(driver, 'ds_jws_unprotected', '{"note":"not signed"}');
  status = await jwsClickAndWait(driver, 'jwsSign',
      "[JWS] the unprotected-header refusal did not finish.");
  assert.ok(/unprotected header/.test(status),
    "[JWS] an unprotected header in the compact serialization must be " +
    "refused. Status: " + status);
  await selectValue(driver, 'ds_jws_serialization', 'flattened');
  status = await jwsClickAndWait(driver, 'jwsSign',
      "[JWS] the unprotected-header signing did not finish.");
  assert.ok(/^Signed/.test(status),
    "[JWS] an unprotected header belongs in a JSON serialization. Status: " +
    status);
  doc = JSON.parse(await getValue(driver, By.id('ds_jws_signature')));
  assert.strictEqual(doc.header.note, "not signed",
    "[JWS] the unprotected header must reach the serialization.");
  await setTextarea(driver, 'ds_jws_unprotected', '');
  await selectValue(driver, 'ds_jws_serialization', 'compact');
  log.info("[JWS] OK — the unprotected header, and where it may not go.");

  // The header fields, and the embedded jwk — which must be the PUBLIC half.
  await jwsGenerate(driver, 'ES256', 'ES256');
  await setInput(driver, By.id('ds_jws_typ'), 'JWT');
  await setInput(driver, By.id('ds_jws_cty'), 'application/json');
  await setInput(driver, By.id('ds_jws_kid'), 'key-1');
  await setTextarea(driver, 'ds_jws_header_extra', '{"custom":"yes"}');
  await setCheckbox(driver, 'ds_jws_embed_jwk', true);
  await jwsClickAndWait(driver, 'jwsSign', "[JWS] header signing.");
  header = JSON.parse(Buffer.from(
      (await getValue(driver, By.id('ds_jws_signature'))).split(".")[0],
      "base64url").toString("utf8"));
  assert.strictEqual(header.typ, 'JWT');
  assert.strictEqual(header.cty, 'application/json');
  assert.strictEqual(header.kid, 'key-1');
  assert.strictEqual(header.custom, 'yes');
  assert.strictEqual(header.jwk.crv, 'P-256',
    "[JWS] the embedded jwk must describe the signing key.");
  assert.strictEqual(header.jwk.d, undefined,
    "[JWS] an embedded jwk must NEVER carry the private key.");
  await setCheckbox(driver, 'ds_jws_embed_jwk', false);
  await setInput(driver, By.id('ds_jws_typ'), '');
  await setInput(driver, By.id('ds_jws_cty'), '');
  await setInput(driver, By.id('ds_jws_kid'), '');
  await setTextarea(driver, 'ds_jws_header_extra', '');
  log.info("[JWS] OK — typ/cty/kid, extra header members, embedded jwk.");

  // RFC 8725 §3.1 — the VERIFIER decides the algorithm. Selecting one and
  // being handed a token that names another is refused, because accommodating
  // it is the algorithm-confusion attack.
  await selectValue(driver, 'ds_jws_alg', 'ES384');
  status = await jwsClickAndWait(driver, 'jwsValidate',
      "[JWS] the algorithm-mismatch validation did not finish.");
  assert.ok(/INVALID \u2717/.test(status),
    "[JWS] a token naming an algorithm the verifier did not choose must be " +
    "refused. Status: " + status);
  await selectValue(driver, 'ds_jws_alg', 'ES256');
  log.info("[JWS] OK — an algorithm the verifier did not choose is refused.");

  // The three ways a shared secret can be written down. Reading one as
  // another produces a valid signature under a key that is not the one on the
  // screen, which is exactly why the selector exists.
  await selectValue(driver, 'ds_jws_alg', 'HS256');
  await setTextarea(driver, 'ds_jws_payload', '{"a":1}');
  var encodings = ['hex', 'b64u', 'text'];
  for (var e = 0; e < encodings.length; e++) {
    await selectValue(driver, 'ds_jws_secret_encoding', encodings[e]);
    if (encodings[e] === 'text') {
      await setTextarea(driver, 'ds_jws_private_key', 'correct horse battery');
      await setTextarea(driver, 'ds_jws_public_key', 'correct horse battery');
    } else {
      await jwsClickAndWait(driver, 'jwsGenerateKeys',
          "[JWS] secret generation (" + encodings[e] + ").");
    }
    await jwsClickAndWait(driver, 'jwsSign',
        "[JWS] signing with a " + encodings[e] + " secret.");
    status = await jwsClickAndWait(driver, 'jwsValidate',
        "[JWS] validating with a " + encodings[e] + " secret.");
    assert.ok(/VALID \u2713/.test(status),
      "[JWS] an HMAC secret read as " + encodings[e] + " did not round-trip. " +
      "Status: " + status);
  }
  await selectValue(driver, 'ds_jws_secret_encoding', 'hex');
  log.info("[JWS] OK — a shared secret read as hex, base64url and text.");
  log.debug("Leaving testJws().");
}

// ===========================================================================
// Pane #7 — XML Digital Signature
//
// The choices, rather than the bytes: the bytes are tests/xmlsec_interop.js's,
// which hands what this engine produces to xml-crypto and drives its ECDSA and
// HMAC halves with node's own OpenSSL. What only a browser can do is the two
// XPath transforms — they are evaluated by the DOM's own XPath engine, which
// @xmldom does not have — and the wiring of every selector to the URI it
// writes into the document.
// ===========================================================================
var XML_SIG_RSA = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
var XML_SIG_PSS = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
var XML_SIG_ECDSA = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
var XML_SIG_HMAC = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256';
var XML_C14N = [
  'http://www.w3.org/2001/10/xml-exc-c14n#',
  'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments'
];
var XML_DIGESTS = [
  'http://www.w3.org/2001/04/xmlenc#sha256',
  'http://www.w3.org/2001/04/xmldsig-more#sha384',
  'http://www.w3.org/2001/04/xmlenc#sha512',
  'http://www.w3.org/2000/09/xmldsig#sha1'
];
// The comment is not decoration: it is the ONLY thing that tells a
// canonicalization method from its "#WithComments" twin, and a document
// without one passes under either.
var XML_DOC = '<Order xmlns="urn:example:order" ID="order-1">' +
  '<!-- the comment that separates the two canonicalizations -->' +
  '<Item sku="A1">Widget</Item>' +
  '<Total currency="USD">42.00</Total></Order>';

async function xmlClickAndWait(driver, fn, message) {
  log.debug("Entering xmlClickAndWait().");
  await click(driver, onclickBtn(fn));
  var status = await waitForValue(driver, By.id('ds_xml_status'),
      statusSettled, message, rsaWait);
  log.debug("Leaving xmlClickAndWait().");
  return status;
}

async function xmlSignAndValidate(driver, label) {
  log.debug("Entering xmlSignAndValidate().");
  var signed = await xmlClickAndWait(driver, 'xmlSign',
      "[XML " + label + "] signing did not finish.");
  assert.ok(/^Signed/.test(signed),
    "[XML " + label + "] sign reported: " + signed);
  var verified = await xmlClickAndWait(driver, 'xmlValidate',
      "[XML " + label + "] validation did not finish.");
  assert.ok(/VALID \u2713/.test(verified),
    "[XML " + label + "] validate reported: " + verified);
  log.debug("Leaving xmlSignAndValidate().");
  return verified;
}

async function testXmlSignature(driver) {
  log.debug("Entering testXmlSignature().");
  log.info("=== XML Digital Signature (W3C XMLDSIG) ===");

  // The rule this pane exists for, in both directions.
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  var status = await xmlClickAndWait(driver, 'xmlValidateDocument',
      "[XML] the well-formedness check did not finish.");
  assert.ok(/well-formed \u2713/.test(status),
    "[XML] a well-formed document must be reported as one. Status: " + status);
  await setTextarea(driver, 'ds_xml_value', '<a><b></a>');
  status = await xmlClickAndWait(driver, 'xmlValidateDocument',
      "[XML] the malformed check did not finish.");
  assert.ok(/NOT well-formed \u2717/.test(status),
    "[XML] malformed XML must be reported as such. Status: " + status);
  status = await xmlClickAndWait(driver, 'xmlSign',
      "[XML] the malformed signing refusal did not finish.");
  assert.ok(/Sign error/.test(status),
    "[XML] malformed XML must be refused before anything is signed. " +
    "Status: " + status);
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  log.info("[XML] OK — XML that is not well-formed is refused by name.");

  // RSA, and all three signature types. The RSA key pair carries a
  // certificate, which is what KeyInfo/X509Data needs.
  await selectValue(driver, 'ds_xml_sigalg', XML_SIG_RSA);
  await selectValue(driver, 'ds_xml_keyinfo', 'x509');
  await xmlClickAndWait(driver, 'xmlGenerateKeys',
      "[XML] RSA key generation did not finish.");
  var cert = await getValue(driver, By.id('ds_xml_cert'));
  assert.ok(cert.indexOf('BEGIN CERTIFICATE') >= 0,
    "[XML] the RSA key pair must come with a certificate for KeyInfo.");
  var modes = ['enveloped', 'enveloping', 'detached'];
  for (var m = 0; m < modes.length; m++) {
    await selectValue(driver, 'ds_xml_mode', modes[m]);
    await setCheckbox(driver, 'ds_xml_t_enveloped', modes[m] === 'enveloped');
    await setTextarea(driver, 'ds_xml_value', XML_DOC);
    await xmlSignAndValidate(driver, modes[m]);
    log.info("[XML " + modes[m] + "] OK — signed and validated.");
  }

  // A changed element must not validate.
  await selectValue(driver, 'ds_xml_mode', 'enveloped');
  await setCheckbox(driver, 'ds_xml_t_enveloped', true);
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  await xmlClickAndWait(driver, 'xmlSign', "[XML] signing before tampering.");
  var signedXml = await getValue(driver, By.id('ds_xml_signature'));
  await setTextarea(driver, 'ds_xml_signature',
      signedXml.replace('Widget', 'Gadget'));
  status = await xmlClickAndWait(driver, 'xmlValidate',
      "[XML] the tampered validation did not finish.");
  assert.ok(/INVALID \u2717/.test(status),
    "[XML] a modified document must not validate. Status: " + status);
  log.info("[XML] OK — a modified document is refused.");

  // The four canonicalization methods. What is asserted is not only that each
  // verifies — it is that the two halves of each pair produce DIFFERENT
  // reference digests, because otherwise the WithComments option would be a
  // label on a control that does nothing.
  var digests = [];
  for (var c = 0; c < XML_C14N.length; c++) {
    await selectValue(driver, 'ds_xml_c14n', XML_C14N[c]);
    await selectValue(driver, 'ds_xml_t_c14n', XML_C14N[c]);
    await setTextarea(driver, 'ds_xml_value', XML_DOC);
    // The digest is read BETWEEN Sign and Validate. One detail pane serves
    // both, and Validate replaces what Sign wrote — so reading it afterwards
    // finds the verification report and no DigestValue at all.
    var signedC14n = await xmlClickAndWait(driver, 'xmlSign',
        "[XML c14n " + XML_C14N[c] + "] signing did not finish.");
    assert.ok(/^Signed/.test(signedC14n),
      "[XML c14n " + XML_C14N[c] + "] sign reported: " + signedC14n);
    var report = await getValue(driver, By.id('ds_xml_report'));
    var match = report.match(/DigestValue: (\S+)/);
    assert.ok(match, "[XML] the detail pane must report the DigestValue " +
      "after Sign. Detail pane held: " + report.slice(0, 200));
    digests.push(match[1]);
    var verifiedC14n = await xmlClickAndWait(driver, 'xmlValidate',
        "[XML c14n " + XML_C14N[c] + "] validation did not finish.");
    assert.ok(/VALID \u2713/.test(verifiedC14n),
      "[XML c14n " + XML_C14N[c] + "] validate reported: " + verifiedC14n);
  }
  assert.notStrictEqual(digests[0], digests[1],
    "[XML] exclusive C14N with and without comments produced the SAME " +
    "digest over a document that contains one — the option does nothing.");
  assert.notStrictEqual(digests[2], digests[3],
    "[XML] inclusive C14N with and without comments produced the SAME " +
    "digest over a document that contains one — the option does nothing.");
  await selectValue(driver, 'ds_xml_c14n', XML_C14N[0]);
  await selectValue(driver, 'ds_xml_t_c14n', XML_C14N[0]);
  log.info("[XML] OK — four canonicalization methods, and comments really " +
           "change the digest.");

  // Every DigestMethod.
  for (var d = 0; d < XML_DIGESTS.length; d++) {
    await selectValue(driver, 'ds_xml_digest', XML_DIGESTS[d]);
    await setTextarea(driver, 'ds_xml_value', XML_DOC);
    await xmlSignAndValidate(driver, 'digest ' + XML_DIGESTS[d]);
  }
  await selectValue(driver, 'ds_xml_digest', XML_DIGESTS[0]);
  log.info("[XML] OK — every DigestMethod.");

  // RSASSA-PSS, ECDSA over every curve, and HMAC. The last is a MAC and the
  // pane says so; what is checked here is that its KeyInfo choice is a
  // KeyName, since a shared secret has no public half to publish.
  await selectValue(driver, 'ds_xml_sigalg', XML_SIG_PSS);
  await xmlClickAndWait(driver, 'xmlGenerateKeys', "[XML] PSS key.");
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  await xmlSignAndValidate(driver, 'RSASSA-PSS');
  var curves = ['P-256', 'P-384', 'P-521', 'secp256k1'];
  await selectValue(driver, 'ds_xml_sigalg', XML_SIG_ECDSA);
  await selectValue(driver, 'ds_xml_keyinfo', 'keyvalue');
  for (var v = 0; v < curves.length; v++) {
    await selectValue(driver, 'ds_xml_curve', curves[v]);
    await xmlClickAndWait(driver, 'xmlGenerateKeys',
        "[XML] ECDSA " + curves[v] + " key generation.");
    await setTextarea(driver, 'ds_xml_value', XML_DOC);
    await xmlSignAndValidate(driver, 'ECDSA ' + curves[v]);
  }
  signedXml = await getValue(driver, By.id('ds_xml_signature'));
  assert.ok(signedXml.indexOf('ECKeyValue') > 0,
    "[XML] an EC public key belongs in a dsig11:ECKeyValue.");
  await selectValue(driver, 'ds_xml_sigalg', XML_SIG_HMAC);
  await selectValue(driver, 'ds_xml_keyinfo', 'keyname');
  await setInput(driver, By.id('ds_xml_keyname'), 'shared-key-1');
  await xmlClickAndWait(driver, 'xmlGenerateKeys', "[XML] HMAC secret.");
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  await xmlSignAndValidate(driver, 'HMAC-SHA256');
  signedXml = await getValue(driver, By.id('ds_xml_signature'));
  assert.ok(signedXml.indexOf('<ds:KeyName>shared-key-1</ds:KeyName>') > 0,
    "[XML] a MAC key is identified by a KeyName, not published.");
  log.info("[XML] OK — RSASSA-PSS, ECDSA over four curves, HMAC.");

  // An X.509 KeyInfo over a key that has no certificate must be refused
  // rather than producing a Signature with an empty X509Data.
  await selectValue(driver, 'ds_xml_keyinfo', 'x509');
  status = await xmlClickAndWait(driver, 'xmlSign',
      "[XML] the KeyInfo mismatch refusal did not finish.");
  assert.ok(/no X.509 certificate/.test(status),
    "[XML] an X509Data KeyInfo over an HMAC key must be refused. Status: " +
    status);
  log.info("[XML] OK — a KeyInfo that does not fit the key is refused.");

  // Back to RSA for the transform work.
  await selectValue(driver, 'ds_xml_sigalg', XML_SIG_RSA);
  await selectValue(driver, 'ds_xml_keyinfo', 'x509');
  await xmlClickAndWait(driver, 'xmlGenerateKeys', "[XML] RSA key (2).");

  // THE XPATH TRANSFORMS, which only a browser can run: they are evaluated by
  // the DOM's own XPath engine, and the node-side job asserts that it says so
  // by name where there is none.
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  await selectValue(driver, 'ds_xml_t_xpath_kind', 'xpath');
  await setInput(driver, By.id('ds_xml_t_xpath'),
      'not(ancestor-or-self::ds:Signature)');
  await xmlSignAndValidate(driver, 'XPath transform');
  log.info("[XML] OK — the XPath transform of RFC 3275 §6.6.3.");

  // XPath Filter 2.0, and the assertion that makes it mean something: a
  // SUBTRACTED subtree is genuinely outside the signature, and everything
  // else is genuinely inside it. Checking only that it verifies would pass
  // just as happily if the filter had been ignored.
  await selectValue(driver, 'ds_xml_t_xpath_kind', 'filter2');
  await selectValue(driver, 'ds_xml_t_filter', 'subtract');
  await setInput(driver, By.id('ds_xml_t_xpath'),
      "//*[local-name()='Total']");
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  await xmlSignAndValidate(driver, 'XPath Filter 2.0');
  signedXml = await getValue(driver, By.id('ds_xml_signature'));
  await setTextarea(driver, 'ds_xml_signature',
      signedXml.replace('42.00', '99.00'));
  status = await xmlClickAndWait(driver, 'xmlValidate',
      "[XML] the subtracted-subtree validation did not finish.");
  assert.ok(/VALID \u2713/.test(status),
    "[XML] a SUBTRACTED subtree must not be covered by the signature — " +
    "changing it invalidated the signature, so the filter did nothing. " +
    "Status: " + status);
  await setTextarea(driver, 'ds_xml_signature',
      signedXml.replace('Widget', 'Gadget'));
  status = await xmlClickAndWait(driver, 'xmlValidate',
      "[XML] the kept-subtree validation did not finish.");
  assert.ok(/INVALID \u2717/.test(status),
    "[XML] everything the filter KEPT must still be covered. Status: " +
    status);
  await selectValue(driver, 'ds_xml_t_xpath_kind', 'none');
  log.info("[XML] OK — XPath Filter 2.0 subtract, proved in both " +
           "directions.");

  // The base64 transform digests the DECODED octets, and it ends the chain —
  // so the Reference canonicalization is dropped and the pane says so rather
  // than leaving a transform silently missing.
  await selectValue(driver, 'ds_xml_mode', 'enveloping');
  await setCheckbox(driver, 'ds_xml_t_enveloped', false);
  await setCheckbox(driver, 'ds_xml_t_base64', true);
  await setTextarea(driver, 'ds_xml_value',
      '<Data ID="d1">' + Buffer.from('hello world').toString('base64') +
      '</Data>');
  status = await xmlClickAndWait(driver, 'xmlSign', "[XML] base64 signing.");
  assert.ok(/base64 transform ends the chain/.test(status),
    "[XML] dropping the Reference canonicalization must be said out loud. " +
    "Status: " + status);
  status = await xmlClickAndWait(driver, 'xmlValidate',
      "[XML] base64 validation.");
  assert.ok(/VALID \u2713/.test(status),
    "[XML] the base64 transform must round-trip. Status: " + status);
  await setCheckbox(driver, 'ds_xml_t_base64', false);
  await selectValue(driver, 'ds_xml_mode', 'enveloped');
  await setCheckbox(driver, 'ds_xml_t_enveloped', true);
  log.info("[XML] OK — the base64 transform, and the note it forces.");

  // Every KeyInfo form.
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  var keyInfos = ['x509', 'keyvalue', 'x509+keyvalue', 'keyname', 'none'];
  for (var k = 0; k < keyInfos.length; k++) {
    await selectValue(driver, 'ds_xml_keyinfo', keyInfos[k]);
    await setInput(driver, By.id('ds_xml_keyname'), 'demo-key');
    await setTextarea(driver, 'ds_xml_value', XML_DOC);
    await xmlSignAndValidate(driver, 'KeyInfo ' + keyInfos[k]);
  }
  await selectValue(driver, 'ds_xml_keyinfo', 'x509');
  await setInput(driver, By.id('ds_xml_keyname'), '');
  log.info("[XML] OK — every KeyInfo form, including none at all.");

  // The InclusiveNamespaces PrefixList must reach the document: it is the
  // difference between a signed subtree that keeps a prefix used only inside
  // an attribute VALUE and one that loses it.
  await setInput(driver, By.id('ds_xml_c14n_prefixes'), 'soap #default');
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  await xmlSignAndValidate(driver, 'PrefixList');
  signedXml = await getValue(driver, By.id('ds_xml_signature'));
  assert.ok(signedXml.indexOf('PrefixList="soap #default"') > 0,
    "[XML] the PrefixList must be written into the CanonicalizationMethod.");
  await setInput(driver, By.id('ds_xml_c14n_prefixes'), '');
  log.info("[XML] OK — InclusiveNamespaces PrefixList.");

  // An enveloped signature whose Reference does not remove itself can never
  // verify, so the transform is added and the pane reports that it was.
  await setCheckbox(driver, 'ds_xml_t_enveloped', false);
  await setTextarea(driver, 'ds_xml_value', XML_DOC);
  status = await xmlClickAndWait(driver, 'xmlSign',
      "[XML] the auto-added transform signing did not finish.");
  assert.ok(/Added the enveloped-signature transform/.test(status),
    "[XML] a missing enveloped-signature transform must be added, and said. " +
    "Status: " + status);
  status = await xmlClickAndWait(driver, 'xmlValidate',
      "[XML] the auto-added transform validation did not finish.");
  assert.ok(/VALID \u2713/.test(status),
    "[XML] the repaired transform chain must verify. Status: " + status);
  await setCheckbox(driver, 'ds_xml_t_enveloped', true);
  log.info("[XML] OK — a missing enveloped-signature transform is repaired " +
           "and reported.");
  log.debug("Leaving testXmlSignature().");
}

// Pane descriptors for the keystore-download helper. The two new panes have no
// single "the key pair" — the JWS one holds an RSA PEM, a raw curve key or a
// shared secret depending on the algorithm, and the XML one the same — so the
// download cases below select the algorithm first and these only name the
// fields.
var JWS = { name: 'JWS', statusId: 'ds_jws_status',
  ksFormatId: 'ds_jws_ks_format', ksPwId: 'ds_jws_ks_password',
  download: 'jwsDownloadKeys', wait: rsaWait };
var XMLSIG = { name: 'XML Signature', statusId: 'ds_xml_status',
  ksFormatId: 'ds_xml_ks_format', ksPwId: 'ds_xml_ks_password',
  download: 'xmlDownloadKeys', wait: rsaWait };

// ===========================================================================
// Stateful hash-based signatures — LMS/HSS and XMSS/XMSS^MT (SP 800-208).
//
// tests/hbs_signatures.js proves the BYTES against RFC 8554's, RFC 9858's and
// the XMSS reference implementation's own vectors. What this proves is the
// PANE — and one thing about this pane that no other one here has, and that
// no node test can see: signing REWRITES THE PRIVATE KEY BOX. RFC 8554
// section 5.4.1 requires the new index to be stored before the signature is
// released, and a pane that produced a signature while leaving the key on
// screen unchanged would be teaching the exact opposite.
//
// The parameter sets are deliberately the cheapest ones: an H5 LMS tree is 32
// leaves and an XMSSMT 20/4 tree is 32, where XMSS-SHA2_10_256 would be 1,024
// and five seconds. The expensive end is refused by the engine and asserted
// there.
// ===========================================================================
async function testHbs(driver) {
  log.debug("Entering testHbs().");
  log.info("[HBS] LMS/HSS: generate an L=1 H5/W8 key pair.");
  await selectValue(driver, "ds_hbs_scheme", "hss");
  await selectValue(driver, "ds_hbs_lms", "LMS_SHA256_M32_H5");
  await selectValue(driver, "ds_hbs_lmots", "LMOTS_SHA256_N32_W8");
  await selectValue(driver, "ds_hbs_levels", "1");
  await click(driver, onclickBtn("hbsGenerateKeys"));
  await waitForValue(driver, By.id("ds_hbs_public_key"),
                     function (v) { return v.trim().length > 0; },
    "[HBS] no HSS public key was generated.", hbsWait);
  var privateBefore = await getValue(driver, By.id("ds_hbs_private_key"));
  assert.ok(privateBefore.length > 0, "[HBS] no HSS private key.");

  // The state line is the pane's whole subject, so it is asserted before and
  // after rather than merely being present.
  var stateBefore = await waitForValue(driver, By.id("ds_hbs_state"),
      function (v) { return /32 of 32/.test(v); },
    "[HBS] the state line does not report 32 unused one-time keys for an " +
        "H5 tree.", hbsWait);
  assert.ok(/index 0 is next/.test(stateBefore),
      "[HBS] a fresh key does not report index 0 as next: " + stateBefore);

  log.info("[HBS] Sign, and check that the PRIVATE KEY changed with it.");
  await setTextarea(driver, "ds_hbs_value", "firmware 9.9.9 for the suite");
  await click(driver, onclickBtn("hbsSign"));
  var signature = await waitForValue(driver, By.id("ds_hbs_signature"),
                                     function (v) { return v.length > 100; },
    "[HBS] signing produced no signature.", hbsWait);
  var privateAfter = await getValue(driver, By.id("ds_hbs_private_key"));
  assert.notStrictEqual(privateAfter, privateBefore,
      "[HBS] the private key box is unchanged after signing. RFC 8554 " +
      "section 5.4.1 requires the incremented index to be stored BEFORE the " +
      "signature is released; a pane that leaves the old key on screen is " +
      "showing the reader the thing the specification forbids.");
  var stateAfter = await waitForValue(driver, By.id("ds_hbs_state"),
      function (v) { return /31 of 32/.test(v); },
    "[HBS] the state line does not report one one-time key spent.", hbsWait);
  assert.ok(/index 1 is next/.test(stateAfter),
      "[HBS] after one signature the next index is not 1: " + stateAfter);

  log.info("[HBS] Validate, then validate against a value it did not sign.");
  await click(driver, onclickBtn("hbsValidate"));
  await waitForValue(driver, By.id("ds_hbs_status"),
                     function (v) { return /^VALID/.test(v); },
    "[HBS] a signature this pane just made does not validate.", hbsWait);
  await setTextarea(driver, "ds_hbs_value", "firmware 9.9.9 for the suite!");
  await click(driver, onclickBtn("hbsValidate"));
  await waitForValue(driver, By.id("ds_hbs_status"),
                     function (v) { return /^INVALID/.test(v); },
    "[HBS] a signature validated against a value it did not sign.", hbsWait);
  await setTextarea(driver, "ds_hbs_value", "firmware 9.9.9 for the suite");

  log.info("[HBS] Describe parses the key and the signature without " +
           "verifying.");
  await click(driver, onclickBtn("hbsDescribe"));
  var described = await waitForValue(driver, By.id("ds_hbs_describe"),
      function (v) { return v.indexOf("LMOTS_SHA256_N32_W8") > 0; },
    "[HBS] Describe did not name the LM-OTS parameter set.", hbsWait);
  assert.ok(described.indexOf("LMS_SHA256_M32_H5") > 0,
      "[HBS] Describe did not name the LMS parameter set.");
  assert.ok(/leaf q = 0/.test(described),
      "[HBS] Describe did not report which leaf signed the message.");
  assert.ok(/Auth path:\s+5 node/.test(described),
      "[HBS] Describe did not report an authentication path of 5 nodes for " +
      "a height-5 tree: " + described);

  log.info("[HBS] The reuse demonstration: both signatures must VERIFY.");
  await setTextarea(driver, "ds_hbs_value_b", "firmware 9.9.9, but tampered");
  await click(driver, onclickBtn("hbsDemonstrateReuse"));
  var reuse = await waitForValue(driver, By.id("ds_hbs_status"),
      function (v) { return /used twice/.test(v); },
    "[HBS] the reuse demonstration did not report a reused index.", hbsWait);
  assert.ok(/Both signatures verify/.test(reuse),
      "[HBS] the reuse demonstration did not report both signatures as " +
      "verifying, which is the entire point of it: " + reuse);
  var reuseFields = await getValue(driver, By.id("ds_hbs_describe"));
  assert.ok(/VALID/.test(reuseFields) && /forg/i.test(reuseFields),
      "[HBS] the reuse readout does not say what an attacker gains.");
  // ...and it must NOT have spent an index: the state line is unchanged.
  var stateAfterReuse = await getValue(driver, By.id("ds_hbs_state"));
  assert.strictEqual(stateAfterReuse, stateAfter,
      "[HBS] the reuse demonstration advanced the index; it exists to show " +
      "what happens when the index does NOT advance.");

  log.info("[HBS] XMSS^MT: a 2^20 hypertree out of 32-leaf trees.");
  await selectValue(driver, "ds_hbs_scheme", "xmss");
  await selectValue(driver, "ds_hbs_xmss", "XMSSMT-SHA2_20/4_256");
  await click(driver, onclickBtn("hbsGenerateKeys"));
  await waitForValue(driver, By.id("ds_hbs_public_key"),
                     function (v) { return v.trim().length > 0; },
    "[HBS] no XMSS^MT public key was generated.", hbsWait);
  await click(driver, onclickBtn("hbsSign"));
  await waitForValue(driver, By.id("ds_hbs_status"),
                     function (v) { return /which is now spent/.test(v); },
    "[HBS] XMSS^MT signing did not report a spent one-time key.", hbsWait);
  await click(driver, onclickBtn("hbsValidate"));
  await waitForValue(driver, By.id("ds_hbs_status"),
                     function (v) { return /^VALID/.test(v); },
    "[HBS] an XMSS^MT signature this pane just made does not validate.",
    hbsWait);
  await click(driver, onclickBtn("hbsDescribe"));
  var xmssFields = await waitForValue(driver, By.id("ds_hbs_describe"),
      function (v) { return v.indexOf("XMSSMT-SHA2_20/4_256") > 0; },
    "[HBS] Describe did not name the XMSS^MT parameter set.", hbsWait);
  assert.ok(/4 layer\(s\) of height 5/.test(xmssFields),
      "[HBS] Describe did not report the hypertree's shape: " + xmssFields);
  assert.ok(/2\^20 signatures/.test(xmssFields),
      "[HBS] Describe did not report the key's capacity.");
  assert.ok(/Layer 3:/.test(xmssFields),
      "[HBS] Describe did not walk all four layers of the signature.");
  log.info("[HBS] pane verified in both schemes.");
  log.debug("Leaving testHbs().");
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

  await testPageStructure(driver);
  await testSlhDsa(driver);
  await testRsa(driver);
  await testEcc(driver);
  await testMldsa(driver);
  await testHbs(driver);
  await testComposite(driver);
  await testPqVariants(driver);
  await testBbs(driver);
  await testJws(driver);
  await testXmlSignature(driver);
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
  // Date.now() alone is NOT unique: run-report.js runs jobs in a pool,
  // and two starting in the same millisecond would share a profile —
  // one Chrome then refuses to start on the other's. See CONCURRENCY
  // in run-report.js.
  options.addArguments("--user-data-dir=/tmp/digital-signature-chrome-" +
                       Date.now() + "-" + process.pid);
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
    await driver.manage().deleteAllCookies();
    await digitalSignatureActivities(driver);
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
  .name('digital_signature')
  .description("Run Digital Signature UI test (SLH-DSA, RSA, ECC, ML-DSA, " +
      "BBS — all hashes, both BBS ciphersuites; JWS in every registered " +
      "algorithm and all three serializations; XML Signature in all three " +
      "types with every canonicalization, digest and transform; plus the " +
      "symmetric MACs).")
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
