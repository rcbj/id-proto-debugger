const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
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
// node-forge RSA 2048-bit key generation is pure JS and can take several seconds.
var rsaWait = Math.max(waitTime, 60000);
// SLH-DSA signing (small-signature / high-security sets) can take many seconds.
var slhWait = Math.max(waitTime, 240000);

// Every hash the RSA and ECC panes offer.
var HASHES = ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512',
              'BLAKE2b-512', 'BLAKE3-256', 'RIPEMD-160', 'SHA-1', 'MD5'];
// Hashes with no PKCS#1 v1.5 DigestInfo OID — PSS only.
var RSA_V15_UNSUPPORTED = { 'BLAKE2b-512': true, 'BLAKE3-256': true };
var SLH_PARAMS = [
  "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
  "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
  "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
];
var ECC_ECDSA_CURVES = ['P-256', 'P-384', 'P-521', 'secp256k1'];
var ECC_EDDSA_CURVES = ['Ed25519', 'Ed448'];
// Schemes that hash the message themselves (no Hash selection applies).
var ECC_OTHER_SCHEMES = ['secp256k1-schnorr', 'bls12-381'];
var ML_PARAMS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
// RSA is the one pane with an explicit key-size dropdown; the others vary size
// via their parameter set / curve. Two common sizes (3072 keygen is the slower,
// pure-JS one); 4096 is available in the app but omitted here to bound runtime.
var RSA_KEY_SIZES = ['2048', '3072'];
// Symmetric MAC panes (prefix + algorithms), grouped by family.
var MAC_FAMILIES = [
  { name: 'Keyed-Hash MACs', prefix: 'khmac',
    algs: ['HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512', 'HMAC-SHA3-256', 'HMAC-SHA3-512',
           'HMAC-SHA1', 'KMAC128', 'KMAC256', 'BLAKE2b', 'BLAKE2s', 'BLAKE3'] },
  { name: 'Block-Cipher MACs', prefix: 'bcmac', algs: ['AES-CMAC', 'AES-CBC-MAC', 'AES-GMAC'] },
  { name: 'Universal-Hash MACs', prefix: 'uhmac', algs: ['Poly1305', 'SipHash-2-4'] }
];

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
async function setInput(driver, locator, text) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await el.clear();
  await el.sendKeys(text);
}
async function getValue(driver, locator) {
  return await driver.findElement(locator).getAttribute("value");
}
async function waitForValue(driver, locator, pred, msg, timeout) {
  await driver.wait(async function () {
    try { return pred((await driver.findElement(locator).getAttribute("value")) || ""); }
    catch (e) { return false; }
  }, timeout || cryptoWait, msg);
  return await getValue(driver, locator);
}
async function selectValue(driver, id, value) {
  await new Select(driver.findElement(By.id(id))).selectByValue(value);
}
// The inline handlers read "return digital_signature.<fn>(...)". Match with the
// "digital_signature." prefix so e.g. "sign" does not also match "rsaSign".
function onclickBtn(fn) {
  return By.xpath("//input[contains(@onclick, \"digital_signature." + fn + "(\")]");
}
// MAC buttons pass a pane prefix, e.g. digital_signature.macCompute('khmac').
function macBtn(fn, prefix) {
  return By.xpath("//input[contains(@onclick, \"digital_signature." + fn + "('" + prefix + "')\")]");
}

// Generate a key pair for a pane and wait until both key fields populate.
async function generateKeys(driver, cfg) {
  await click(driver, onclickBtn(cfg.gen));
  await waitForValue(driver, By.id(cfg.privId), function (v) { return v.trim().length > 0; },
    "[" + cfg.name + "] private key was not generated.", cfg.wait);
  await waitForValue(driver, By.id(cfg.pubId), function (v) { return v.trim().length > 0; },
    "[" + cfg.name + "] public key was not generated.", cfg.wait);
}

// Assuming a key pair is present, set a fresh value, sign, and validate.
async function signAndValidate(driver, cfg, label) {
  var value = "Digital signature test :: " + label + " :: " + new Date().toISOString();
  await setInput(driver, By.id(cfg.valueId), value);

  await driver.findElement(By.id(cfg.signatureId)).clear();
  await click(driver, onclickBtn(cfg.sign));
  var sig = await waitForValue(driver, By.id(cfg.signatureId), function (v) { return v.trim().length > 0; },
    "[" + label + "] signature was not produced.", cfg.wait);

  await click(driver, onclickBtn(cfg.validate));
  var status = await waitForValue(driver, By.id(cfg.statusId),
    function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
    "[" + label + "] validation did not complete.", cfg.wait);
  assert.ok(status.indexOf("VALID ✓") !== -1,
    "[" + label + "] signature did not validate. Status: " + status);
  log.info("[" + label + "] OK — signature (" + sig.length + " b64 chars) validated.");
}

// ===========================================================================
// Panes
// ===========================================================================
var SLH = { name: 'SLH-DSA', valueId: 'ds_value', signatureId: 'ds_signature',
  privId: 'ds_private_key', pubId: 'ds_public_key', statusId: 'ds_status',
  gen: 'generateKeys', sign: 'sign', validate: 'validate', wait: slhWait,
  download: 'downloadKeys', ksFormatId: 'ds_slh_ks_format', ksPwId: 'ds_slh_ks_password' };
var RSA = { name: 'RSA', valueId: 'ds_rsa_value', signatureId: 'ds_rsa_signature',
  privId: 'ds_rsa_private_key', pubId: 'ds_rsa_public_key', statusId: 'ds_rsa_status',
  gen: 'rsaGenerateKeys', sign: 'rsaSign', validate: 'rsaValidate', wait: rsaWait,
  download: 'rsaDownloadKeys', ksFormatId: 'ds_rsa_ks_format', ksPwId: 'ds_rsa_ks_password' };
var ECC = { name: 'ECC', valueId: 'ds_ecc_value', signatureId: 'ds_ecc_signature',
  privId: 'ds_ecc_private_key', pubId: 'ds_ecc_public_key', statusId: 'ds_ecc_status',
  gen: 'eccGenerateKeys', sign: 'eccSign', validate: 'eccValidate', wait: cryptoWait,
  download: 'eccDownloadKeys', ksFormatId: 'ds_ecc_ks_format', ksPwId: 'ds_ecc_ks_password' };
var ML = { name: 'ML-DSA', valueId: 'ds_ml_value', signatureId: 'ds_ml_signature',
  privId: 'ds_ml_private_key', pubId: 'ds_ml_public_key', statusId: 'ds_ml_status',
  gen: 'mldsaGenerateKeys', sign: 'mldsaSign', validate: 'mldsaValidate', wait: cryptoWait,
  download: 'mldsaDownloadKeys', ksFormatId: 'ds_ml_ks_format', ksPwId: 'ds_ml_ks_password' };

// Pane #1 — SLH-DSA: key generation depends on the parameter set, so generate
// keys for each one, then sign + validate.
async function testSlhDsa(driver) {
  log.info("=== Pane #1 SLH-DSA — " + SLH_PARAMS.length + " parameter sets ===");
  for (var i = 0; i < SLH_PARAMS.length; i++) {
    var alg = SLH_PARAMS[i];
    await selectValue(driver, 'ds_param', alg);
    await generateKeys(driver, SLH);
    await signAndValidate(driver, SLH, 'SLH-DSA ' + alg);
  }
}

// Pane #2 — RSA: keys are independent of padding/hash, so generate once, then
// test every padding × hash combination (v1.5 + BLAKE2b-512 has no DigestInfo
// OID and is intentionally excluded — that combination uses PSS instead).
async function testRsa(driver) {
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
          log.info("[RSA " + size + "-bit " + paddings[p][1] + " / " + hash + "] skipped (no PKCS#1 v1.5 OID; PSS covers it).");
          continue;
        }
        await selectValue(driver, 'ds_rsa_padding', padVal);
        await selectValue(driver, 'ds_rsa_hash', hash);
        await signAndValidate(driver, RSA, 'RSA ' + size + '-bit ' + paddings[p][1] + ' / ' + hash);
      }
    }
  }
}

// Pane #3 — ECC: keys depend on the curve, so generate once per curve. ECDSA
// curves test every hash; EdDSA curves fix their own hash (tested once).
async function testEcc(driver) {
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
}

// Pane #4 — ML-DSA: key generation depends on the parameter set (fast lattice
// scheme), so generate keys for each set, then sign + validate.
async function testMldsa(driver) {
  log.info("=== Pane #4 ML-DSA — " + ML_PARAMS.length + " parameter sets ===");
  for (var i = 0; i < ML_PARAMS.length; i++) {
    await selectValue(driver, 'ds_ml_param', ML_PARAMS[i]);
    await generateKeys(driver, ML);
    await signAndValidate(driver, ML, 'ML-DSA ' + ML_PARAMS[i]);
  }
}

// Symmetric MAC panes: for every algorithm, generate a key, compute a tag, and
// verify it (positive). For the first algorithm in each family, also confirm a
// modified value fails verification (tamper / negative).
async function testMacs(driver) {
  for (var f = 0; f < MAC_FAMILIES.length; f++) {
    var fam = MAC_FAMILIES[f];
    log.info("=== Symmetric " + fam.name + " — " + fam.algs.length + " algorithm(s) ===");
    for (var a = 0; a < fam.algs.length; a++) {
      var alg = fam.algs[a], label = fam.name + " / " + alg;
      // Selecting the algorithm auto-generates a key (onchange); click the
      // button too to exercise it explicitly.
      await selectValue(driver, 'ds_' + fam.prefix + '_alg', alg);
      await click(driver, macBtn('macGenerateKey', fam.prefix));
      await waitForValue(driver, By.id('ds_' + fam.prefix + '_key'),
        function (v) { return v.trim().length > 0; }, "[" + label + "] key was not generated.", cryptoWait);

      await setInput(driver, By.id('ds_' + fam.prefix + '_value'),
        "MAC test :: " + alg + " :: " + new Date().toISOString());
      await driver.findElement(By.id('ds_' + fam.prefix + '_mac')).clear();
      await click(driver, macBtn('macCompute', fam.prefix));
      var tag = await waitForValue(driver, By.id('ds_' + fam.prefix + '_mac'),
        function (v) { return v.trim().length > 0; }, "[" + label + "] MAC tag was not produced.", cryptoWait);

      await click(driver, macBtn('macVerify', fam.prefix));
      var st = await waitForValue(driver, By.id('ds_' + fam.prefix + '_status'),
        function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
        "[" + label + "] verify did not complete.", cryptoWait);
      assert.ok(st.indexOf("VALID ✓") !== -1, "[" + label + "] MAC did not validate. Status: " + st);
      log.info("[" + label + "] OK — tag (" + tag.length + " b64 chars) verified.");

      if (a === 0) {
        // Tamper: change the value, re-verify against the old tag -> INVALID.
        await setInput(driver, By.id('ds_' + fam.prefix + '_value'), "tampered — different message");
        await click(driver, macBtn('macVerify', fam.prefix));
        var st2 = await waitForValue(driver, By.id('ds_' + fam.prefix + '_status'),
          function (v) { return v.indexOf("✓") !== -1 || v.indexOf("✗") !== -1; },
          "[" + label + " tamper] verify did not complete.", cryptoWait);
        assert.ok(st2.indexOf("INVALID ✗") !== -1,
          "[" + label + " tamper] expected INVALID, got: " + st2);
        log.info("[" + label + " tamper] correctly rejected.");
      }
    }
  }
}

// Select a keystore format, optionally set a password, click Download Keys, and
// assert the status line reports the expected outcome. (Consistent with the
// jwt_tools test, this verifies the reported result — not the file on disk.)
async function downloadKeystore(driver, cfg, format, password, expectSubstr, label) {
  await selectValue(driver, cfg.ksFormatId, format);
  var pwEl = driver.findElement(By.id(cfg.ksPwId));
  await pwEl.clear();
  if (password) await pwEl.sendKeys(password);
  // Blank the status so we detect the message produced by THIS click.
  await driver.executeScript("var e=document.getElementById(arguments[0]); if(e) e.value='';", cfg.statusId);
  await click(driver, onclickBtn(cfg.download));
  var status = await waitForValue(driver, By.id(cfg.statusId),
    function (v) { return v.indexOf(expectSubstr) !== -1; },
    "[" + label + "] download status did not contain \"" + expectSubstr + "\".", cfg.wait);
  log.info("[" + label + "] " + status);
}

// Exercise every keystore format + optional password on all three panes,
// including the intentionally-unsupported combinations (which must report a
// clear message rather than silently do nothing).
async function testDownloads(driver) {
  log.info("=== Keystore downloads ===");

  // SLH-DSA — reuse keys from the sign/validate phase. PEM + JWK (+password);
  // DER/PKCS#12 unsupported; PEM+password steered to JWK.
  await downloadKeystore(driver, SLH, 'pem', '', 'Downloaded key pair (slh-dsa-keys.pem)', 'SLH-DSA PEM');
  await downloadKeystore(driver, SLH, 'pem', 'pw123', 'only available in JWK', 'SLH-DSA PEM+pw (steered)');
  await downloadKeystore(driver, SLH, 'jwk', '', 'Downloaded JWK set', 'SLH-DSA JWK');
  await downloadKeystore(driver, SLH, 'jwk', 'pw123', 'PBES2-encrypted JWK', 'SLH-DSA JWK+pw');
  await downloadKeystore(driver, SLH, 'der', '', 'not supported', 'SLH-DSA DER (unsupported)');
  await downloadKeystore(driver, SLH, 'pkcs12', '', 'not supported', 'SLH-DSA PKCS#12 (unsupported)');

  // RSA — reuse the key pair generated in testRsa. Full format support.
  await downloadKeystore(driver, RSA, 'pem', '', 'Downloaded PEM (private + public key)', 'RSA PEM');
  await downloadKeystore(driver, RSA, 'pem', 'pw123', 'encrypted private key', 'RSA PEM+pw');
  await downloadKeystore(driver, RSA, 'der', '', 'Downloaded DER (private + public)', 'RSA DER');
  await downloadKeystore(driver, RSA, 'der', 'pw123', 'encrypted private', 'RSA DER+pw');
  await downloadKeystore(driver, RSA, 'jwk', '', 'Downloaded JWK set', 'RSA JWK');
  await downloadKeystore(driver, RSA, 'jwk', 'pw123', 'PBES2-encrypted JWK', 'RSA JWK+pw');
  await downloadKeystore(driver, RSA, 'pkcs12', '', 'requires a password', 'RSA PKCS#12 (password required)');
  await downloadKeystore(driver, RSA, 'pkcs12', 'pw123', 'Downloaded password-protected PKCS#12', 'RSA PKCS#12');

  // ECC — JWK for an ECDSA curve (EC JWK) and an EdDSA curve (OKP JWK);
  // PEM/DER/PKCS#12 unsupported.
  await selectValue(driver, 'ds_ecc_curve', 'P-256');
  await generateKeys(driver, ECC);
  await downloadKeystore(driver, ECC, 'jwk', '', 'Downloaded JWK set', 'ECC EC JWK');
  await downloadKeystore(driver, ECC, 'jwk', 'pw123', 'PBES2-encrypted JWK', 'ECC EC JWK+pw');
  await downloadKeystore(driver, ECC, 'pem', '', 'not supported', 'ECC PEM (unsupported)');
  await downloadKeystore(driver, ECC, 'pkcs12', '', 'not supported', 'ECC PKCS#12 (unsupported)');
  await selectValue(driver, 'ds_ecc_curve', 'Ed25519');
  await generateKeys(driver, ECC);
  await downloadKeystore(driver, ECC, 'jwk', '', 'Downloaded JWK set', 'ECC OKP JWK (Ed25519)');
  // Schnorr/BLS have no standard JWK — export must report that.
  await selectValue(driver, 'ds_ecc_curve', 'secp256k1-schnorr');
  await generateKeys(driver, ECC);
  await downloadKeystore(driver, ECC, 'jwk', '', 'JWK is not defined', 'Schnorr JWK (unsupported)');

  // ML-DSA: PEM + JWK (+password); DER/PKCS#12 unsupported.
  await selectValue(driver, 'ds_ml_param', 'ML-DSA-65');
  await generateKeys(driver, ML);
  await downloadKeystore(driver, ML, 'pem', '', 'Downloaded key pair (ml-dsa-keys.pem)', 'ML-DSA PEM');
  await downloadKeystore(driver, ML, 'jwk', '', 'Downloaded JWK set', 'ML-DSA JWK');
  await downloadKeystore(driver, ML, 'jwk', 'pw123', 'PBES2-encrypted JWK', 'ML-DSA JWK+pw');
  await downloadKeystore(driver, ML, 'pkcs12', '', 'not supported', 'ML-DSA PKCS#12 (unsupported)');
}

async function digitalSignatureActivities(driver) {
  log.info("Load the Digital Signature page.");
  await driver.get(baseUrl + "/digital_signature.html");
  await waitForValue(driver, By.id("ds_value"), function (v) { return v.length > 0; },
    "Digital Signature page did not load / defaults not populated.");

  // Panes are collapsible; expand them all so every field is visible/interactable.
  await click(driver, onclickBtn("expandAll"));

  await testSlhDsa(driver);
  await testRsa(driver);
  await testEcc(driver);
  await testMldsa(driver);
  await testMacs(driver);
  await testDownloads(driver);
}

async function test() {
  const options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  // All three panes are pure-JS (no crypto.subtle), so a secure context is not
  // strictly required, but keep the trustworthy-origin flags for parity with the
  // other tool tests (harmless if unused).
  var secureOrigin = baseUrl.replace(/\/+$/, "");
  options.addArguments("--unsafely-treat-insecure-origin-as-secure=" + secureOrigin);
  options.addArguments("--user-data-dir=/tmp/digital-signature-chrome-" + Date.now());
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

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
  }
}

const program = new Command();
program
  .name('digital_signature')
  .description("Run Digital Signature UI test (SLH-DSA, RSA, ECC — all hashes).")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });
program.parse(process.argv).opts();

test();
