// File: algorithm_menus.js
//
// EVERY ALGORITHM MENU ON EVERY PAGE OFFERS WHAT THE ENGINE BEHIND IT CAN DO.
//
// The engines here are complete and the pages were not, and the gap was
// invisible from either side. `client/src/jws.js` has grown to twenty-seven
// algorithms and `client/src/jose_jwe.js` to six key-management algorithms over
// six content encryptions — and on 2026-08-28 an audit found the JWT Tools
// signing menu offering thirteen of the twenty-seven, the Encryption page's JWE
// pane offering three of the six content encryptions, and the DPoP pane
// offering TWO of the twenty-three asymmetric signature algorithms.
//
// None of that was a bug anybody could see. Each menu was a hand-written list
// of `<option>` elements that was correct on the day it was typed, and each
// engine gained algorithms afterwards. The page kept working; it just quietly
// stopped being able to reproduce cases it was perfectly capable of.
//
// So this reads the MENUS out of the HTML and the CAPABILITY out of the engine
// and requires them to agree. It is a source-level check with no browser,
// which is what lets it run in the ordinary pool in milliseconds — and the
// failure names the page, the select and the missing algorithms, which is the
// one thing a person needs to fix it.
//
// WHY NOT BUILD THE MENUS FROM THE ENGINE AT PAGE LOAD instead, and delete this
// file? Because a `<select>` filled by script is empty in the HTML, and several
// tests here — and every person reading the page source — find an algorithm by
// looking for its `<option>`. Keeping the options in the markup and asserting
// they are complete costs one test and changes nothing else; moving them into
// script would change how every one of those tests locates a control. If that
// trade is ever revisited, this file is what has to be rewritten with it.

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const paths = require("./module_paths");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "algorithm_menus",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var jws = paths.requireSharedModule(
  [__dirname + "/../client/src/jws.js", __dirname + "/jws.js"], "jws.js");
var jose = paths.requireSharedModule(
  [__dirname + "/../client/src/jose_jwe.js", __dirname + "/jose_jwe.js"],
   "jose_jwe.js");

// The pages live beside the tests in the image and one level up in a checkout,
// the same way rfc9700_client.js finds client/src.
function publicDir() {
  log.debug("Entering publicDir().");
  var candidates = [path.join(__dirname, "..", "client", "public"),
                    path.join(__dirname, "..", "public"),
                    "/usr/src/client/public"];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(candidates[i])) {
      log.debug("Leaving publicDir(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving publicDir(). Not found.");
  return null;
}

// The values of one <select>, in document order.
function optionsOf(html, selectId, page) {
  log.debug("Entering optionsOf(). id=" + selectId);
  var re = new RegExp('<select[^>]*id="' + selectId + '"[\\s\\S]*?</select>');
  var block = html.match(re);
  assert.ok(block, page + ' has no <select id="' + selectId + '">. If the ' +
    "control was renamed, rename it here too — a menu this test cannot find " +
    "is a menu it cannot check, and it would pass for ever.");
  var values = [];
  var optionRe = /value="([^"]*)"/g;
  var found;
  while ((found = optionRe.exec(block[0])) !== null) {
    values.push(found[1]);
  }
  assert.ok(values.length, page + "/" + selectId + " has no options at all.");
  log.debug("Leaving optionsOf(). " + values.length + " option(s).");
  return values;
}

function assertMenuOffers(page, selectId, expected, why) {
  log.debug("Entering assertMenuOffers(). " + page + "/" + selectId);
  var dir = publicDir();
  var file = path.join(dir, page);
  assert.ok(fs.existsSync(file), "no such page: " + file);
  var offered = optionsOf(fs.readFileSync(file, "utf8"), selectId, page);
  var missing = expected.filter(function (alg) {
    return offered.indexOf(alg) === -1;
  });
  assert.strictEqual(missing.length, 0,
    page + " / " + selectId + " is missing " + missing.length +
    " algorithm(s) the engine behind it can perform: " + missing.join(", ") +
    ". " + why + " Add an <option> for each, or the page cannot reproduce a " +
    "case this tool is able to handle.");
  // And the other direction, which is the one that produces a control that
  // fails when it is used: an option the engine cannot perform.
  var unknown = offered.filter(function (alg) {
    return expected.indexOf(alg) === -1;
  });
  assert.strictEqual(unknown.length, 0,
    page + " / " + selectId + " offers " + unknown.join(", ") +
    ", which the engine behind it does not implement. An option that cannot " +
    "be performed is worse than a missing one: it fails at the moment " +
    "somebody chooses it.");
  log.info("[menus] OK — " + page + " / " + selectId + ": " +
           offered.length + " algorithm(s), exactly what the engine offers.");
  log.debug("Leaving assertMenuOffers().");
}

// The algorithms jwt_tools.js can actually GENERATE A KEY for, read out of its
// own SIGN_ALGS table. Parsed rather than required: this test must not load a
// browser bundle, and the table is the page's own statement of capability.
function signAlgsOf() {
  log.debug("Entering signAlgsOf().");
  var candidates = [path.join(__dirname, "..", "client", "src",
                              "jwt_tools.js"),
                    path.join(__dirname, "jwt_tools_module.js"),
                    "/usr/src/client/src/jwt_tools.js"];
  var file = candidates.filter(function (one) {
    return fs.existsSync(one);
  })[0];
  assert.ok(file, "client/src/jwt_tools.js was not found; this check reads " +
    "its SIGN_ALGS table.");
  var source = fs.readFileSync(file, "utf8");
  var table = source.match(/var SIGN_ALGS = \{[\s\S]*?\n\};/);
  assert.ok(table, "jwt_tools.js has no SIGN_ALGS table where this test " +
    "expects one. If it was renamed, rename it here too — a capability list " +
    "this test cannot find is one it cannot check.");
  var algs = [];
  var row = /^ {2}'?([A-Za-z0-9-]+)'?:\s*\{/gm;
  var found;
  while ((found = row.exec(table[0])) !== null) {
    algs.push(found[1]);
  }
  assert.ok(algs.length, "SIGN_ALGS parsed to nothing.");
  log.debug("Leaving signAlgsOf(). " + algs.length + " algorithm(s).");
  return algs;
}

function everySignatureMenuIsComplete() {
  log.debug("Entering everySignatureMenuIsComplete().");
  var all = jws.algIds();
  // The Digital Signature page's pane IS keyed by the engine's identifiers —
  // it offers Ed25519 and Ed448 as separate choices, which is the whole reason
  // the engine distinguishes them — so it is compared against `algIds()`
  // directly where JWT Tools is compared against registered values.
  assertMenuOffers("digital_signature.html", "ds_jws_alg", all,
    "This pane is the JWS engine's own front end, so it offers everything.");
  // JWT TOOLS IS MEASURED AGAINST ITS OWN CAPABILITY AND NOT THE ENGINE'S, and
  // the difference between the two is a real and CURRENT gap rather than an
  // oversight in this test.
  //
  // The engine signs twenty-seven algorithms. This page can only generate KEY
  // MATERIAL for thirteen: `SIGN_ALGS` in jwt_tools.js drives
  // generateSigningKeys() through key_material.js, which deals in PEM key
  // pairs — and the post-quantum algorithms have no PEM form at all, their
  // keys being AKP JWKs. Widening the menu past that list was tried on
  // 2026-08-28 and produced fourteen options that answered "No key was
  // supplied for alg=..." when chosen, which is worse than not offering them:
  // algorithm_panes.js drives every option and caught it.
  //
  // So the menu must equal SIGN_ALGS, and SIGN_ALGS must be a subset of the
  // engine — an option the engine cannot perform is still wrong. Closing the
  // gap means teaching this page's key panes about AKP keys, and until that
  // happens this is the honest boundary.
  var pageAlgs = signAlgsOf();
  assertMenuOffers("jwt_tools.html", "sign_alg", pageAlgs,
    "JWT Tools can only offer what generateSigningKeys() can make a key for.");
  // Compared as REGISTERED values. The page's table is keyed by JOSE `alg`
  // and the engine's by algorithm AND curve, because RFC 8037 gives Ed25519
  // and Ed448 the same `alg` — so `EdDSA` in SIGN_ALGS is the engine's
  // `EdDSA-Ed25519` and `EdDSA-Ed448`, and a plain string comparison reports
  // the page naming an algorithm the engine cannot sign, which is false.
  var registered = {};
  all.forEach(function (id) {
    registered[jws.algSpec(id).alg] = true;
  });
  var beyondEngine = pageAlgs.filter(function (alg) {
    return !registered[alg];
  });
  assert.strictEqual(beyondEngine.length, 0,
    "jwt_tools.js names " + beyondEngine.join(", ") + " in SIGN_ALGS and " +
    "jws.js cannot sign it.");
  log.info("[menus] NOTE — JWT Tools offers " + pageAlgs.length + " of the " +
           "engine's " + all.length + ": the other " +
           (all.length - pageAlgs.length) + " have no PEM key form and this " +
           "page's key panes are PEM-based. See the comment above.");
  log.debug("Leaving everySignatureMenuIsComplete().");
}

function everyEncryptionMenuIsComplete() {
  log.debug("Entering everyEncryptionMenuIsComplete().");
  var algs = jose.supportedAlgs();
  var encs = jose.supportedEncs();
  assertMenuOffers("jwt_tools.html", "jwe_alg", algs,
    "JWT Tools encrypts with jose_jwe.js.");
  assertMenuOffers("jwt_tools.html", "jwe_enc", encs,
    "The CBC-HMAC family is the DEFAULT for an encrypted OpenID Connect " +
    "response, so a menu without it cannot read the commonest encrypted " +
    "response there is.");
  assertMenuOffers("encryption_tools.html", "enc_jwe_alg", algs,
    "The Encryption page's JWE pane is jose_jwe.js's own front end.");
  assertMenuOffers("encryption_tools.html", "enc_jwe_enc", encs,
    "Same engine as the JWT Tools pane above; the two must agree.");
  log.debug("Leaving everyEncryptionMenuIsComplete().");
}

function theDpopMenuIsComplete() {
  log.debug("Entering theDpopMenuIsComplete().");
  var dpop = paths.requireSharedModule(
    [__dirname + "/../client/src/dpop.js", __dirname + "/dpop.js"], "dpop.js");
  // RFC 9449 section 4.2: asymmetric only. dpop.js derives that list from
  // jws.js rather than keeping one, and this asserts the derivation as well as
  // the menu — an `ALGS` that stopped filtering would show `none` on a page.
  assert.ok(dpop.ALGS.indexOf("none") === -1,
    "DPoP must never offer the unsecured algorithm: RFC 9449 section 4.2 " +
    "requires an asymmetric one, and a proof signed with `none` proves " +
    "possession of nothing.");
  assert.ok(!dpop.ALGS.some(function (a) { return a.indexOf("HS") === 0; }),
    "DPoP must never offer a MAC: both ends would have to know the key, so " +
    "the proof would prove nothing about who holds it.");
  assertMenuOffers("vc-issuance-2.html", "vc_dpop_alg", dpop.ALGS,
    "The DPoP pane offered ES256 and RS256 alone until 2026-08-28 while the " +
    "engine could do twenty-three, because it kept a key-generation table of " +
    "its own.");
  log.debug("Leaving theDpopMenuIsComplete().");
}

function test() {
  log.debug("Entering test().");
  assert.ok(publicDir(), "client/public was not found beside this test or in " +
    "the checkout — this test reads the pages, so it cannot run without them.");
  log.info("Starting Test run. Reading the algorithm menus out of the pages.");
  everySignatureMenuIsComplete();
  everyEncryptionMenuIsComplete();
  theDpopMenuIsComplete();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("algorithm_menus")
  .description("Every algorithm menu offers exactly what its engine can do.")
  .addOption(new Option("-u, --url <url>",
      "ignored; this test needs no browser"))
  .parse(process.argv);

try {
  test();
} catch (e) {
  log.error(e.stack || e.message);
  process.exit(1);
}
