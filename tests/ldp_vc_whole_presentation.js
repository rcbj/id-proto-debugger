// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: ldp_vc_whole_presentation.js
//
// ---------------------------------------------------------------------------
// The wallet's presentation pages, in Chrome, presenting an ldp_vc that is
// NOT bbs-2023 (#475), with what they build checked by implementations that
// share no code with the wallet.
//
// There is no outside Verifier for this in the suite: iya-sts's OpenID4VP
// Verifier reads an ldp_vc presentation only as its bbs-2023 envelope. So the
// credentials are made in node by released outside implementations, handed
// to the wallet the way issuance leaves one in storage, and the Verifier's
// request is handed to step 1 by value. Step 2 builds the presentation; this
// test reads it off the page and verifies it in node:
//
//   1. an eddsa-rdfc-2022 credential (Digital Bazaar), Ed25519 holder key, a
//      Verifier that states no constraint: the whole credential goes inside
//      a VerifiablePresentation whose holder proof is eddsa-jcs-2022 — the
//      suite an Ed25519 key signs first — verified by Digital Bazaar with
//      the request's nonce as challenge and its Client Identifier as domain,
//      and the credential inside verified by Digital Bazaar too;
//   2. the same credential, a P-256 holder key, and a Verifier whose
//      vp_formats_supported accepts only ecdsa-rdfc-2019: the holder proof is
//      ecdsa-rdfc-2019, chosen for the user, and verifies the same way;
//   3. a BbsBlsSignature2020 credential (MATTR), asked for one claim of two:
//      the wallet derives a BbsBlsSignatureProof2020 disclosing that claim
//      only, which MATTR's verifier accepts, inside a holder VP Digital
//      Bazaar accepts;
//   4. an ecdsa-sd-2023 credential (Digital Bazaar), asked for one claim of
//      two: the wallet derives an ecdsa-sd-2023 proof disclosing that claim
//      and the mandatory ones only, which Digital Bazaar verifies, inside a
//      holder VP it also verifies (#476).
//
// Needs only the client: nothing is posted to anybody.
// ---------------------------------------------------------------------------

// MATTR's WASM build, always: tests/package.json overrides its optional
// native module (@mattrglobal/node-bbs-signatures, whose install script
// downloads a prebuilt binary from a GitHub repository that no longer
// exists) with the WASM package itself, so native mode must never be tried.
process.env.BBS_SIGNATURES_MODE = "wasm";
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
const waitForContent = require("./wait_for.js");
const { waitForStatus, waitForValue } = require("./wait_for");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "ldp_vc_whole_presentation",
    level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var stepWait = waitTime * 4;

function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}
const SRC = path.join(repoRoot(), "client", "src");
const contexts = paths.requireSharedModule(
  [path.join(SRC, "jsonld_contexts.js")], "client/src/jsonld_contexts.js");
const didLib = paths.requireSharedModule([path.join(SRC, "did.js")],
                                         "client/src/did.js");

const VERIFIER = "https://verifier.example/response";
const CLIENT_ID = "redirect_uri:" + VERIFIER;

// What Digital Bazaar's and MATTR's verifiers resolve: controller documents
// and verification methods published here, everything else a context the
// wallet ships.
const docs = {};
async function loader(url) {
  log.debug("Entering loader(). " + url);
  var bare = url.split("#")[0];
  if (docs[url] || docs[bare]) {
    log.debug("Leaving loader(). Published.");
    return { contextUrl: null, documentUrl: url,
             document: docs[url] || docs[bare] };
  }
  log.debug("Leaving loader(). Shipped context.");
  return contexts.documentLoader(url);
}

const CONTROLLER_CONTEXT = [{ "@version": 1.1, id: "@id",
  assertionMethod: { "@id": "https://w3id.org/security#assertionMethod",
                     "@type": "@id", "@container": "@set" },
  authentication: { "@id": "https://w3id.org/security#authenticationMethod",
                    "@type": "@id", "@container": "@set" } }];

// Publish a Multikey under `controller`, for assertion and authentication.
function publish(controller, method) {
  log.debug("Entering publish(). " + method.id);
  docs[method.id] = Object.assign(
    { "@context": "https://w3id.org/security/multikey/v1" }, method);
  docs[controller] = docs[controller] || { "@context": CONTROLLER_CONTEXT,
    id: controller, assertionMethod: [], authentication: [] };
  docs[controller].assertionMethod.push(method.id);
  docs[controller].authentication.push(method.id);
  log.debug("Leaving publish().");
}

function didJwk(jwk) {
  log.debug("Entering didJwk().");
  log.debug("Leaving didJwk().");
  return "did:jwk:" + Buffer.from(JSON.stringify(jwk)).toString("base64url");
}

let db = null;
async function digitalBazaar() {
  log.debug("Entering digitalBazaar().");
  if (!db) {
    db = {
      jsigs: require("jsonld-signatures"),
      DataIntegrityProof: (await import("@digitalbazaar/data-integrity"))
        .DataIntegrityProof,
      eddsaRdfc: (await import("@digitalbazaar/eddsa-rdfc-2022-cryptosuite"))
        .cryptosuite,
      ecdsaRdfc: (await import("@digitalbazaar/ecdsa-rdfc-2019-cryptosuite"))
        .cryptosuite,
      eddsaJcs: await import("@digitalbazaar/eddsa-jcs-2022-cryptosuite"),
      ecdsaSd: await import("@digitalbazaar/ecdsa-sd-2023-cryptosuite"),
      ecdsaJcs: await import("@digitalbazaar/ecdsa-jcs-2019-cryptosuite"),
      Ed25519Multikey: await import("@digitalbazaar/ed25519-multikey"),
      EcdsaMultikey: await import("@digitalbazaar/ecdsa-multikey")
    };
  }
  log.debug("Leaving digitalBazaar().");
  return db;
}

// A holder key the wallet will hold, published as its did:jwk's #0.
async function holderKey(kind) {
  log.debug("Entering holderKey(). " + kind);
  var d = await digitalBazaar();
  var pair = kind === "Ed25519" ?
    nodeCrypto.generateKeyPairSync("ed25519") :
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var pub = pair.publicKey.export({ format: "jwk" });
  var priv = pair.privateKey.export({ format: "jwk" });
  var did = didJwk(pub);
  var mk = kind === "Ed25519" ?
    await d.Ed25519Multikey.fromJwk({ jwk: pub, id: did + "#0",
                                      controller: did }) :
    await d.EcdsaMultikey.fromJwk({ jwk: pub, id: did + "#0",
                                    controller: did });
  publish(did, await mk.export({ publicKey: true }));
  log.debug("Leaving holderKey().");
  return { did: did, publicJwk: pub, privateJwk: priv };
}

function credential(issuer, subjectId, extra) {
  log.debug("Entering credential().");
  log.debug("Leaving credential().");
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"].concat(extra || [])
      .concat([{ given_name: "https://schema.org/givenName",
                 family_name: "https://schema.org/familyName" }]),
    type: ["VerifiableCredential"], issuer: issuer,
    issuanceDate: "2026-01-01T00:00:00Z",
    credentialSubject: { id: subjectId, given_name: "Alice",
                         family_name: "Liddell" }
  };
}

async function eddsaCredential(holder) {
  log.debug("Entering eddsaCredential().");
  var d = await digitalBazaar();
  var issuer = "https://issuer.example/issuers/eddsa";
  var kp = await d.Ed25519Multikey.generate({ controller: issuer });
  publish(issuer, await kp.export({ publicKey: true }));
  log.debug("Leaving eddsaCredential().");
  return d.jsigs.sign(credential(issuer, holder.did), {
    suite: new d.DataIntegrityProof({ signer: kp.signer(),
                                      cryptosuite: d.eddsaRdfc }),
    purpose: new d.jsigs.purposes.AssertionProofPurpose(),
    documentLoader: loader });
}

// Digital Bazaar's ecdsa-sd-2023 base proof, with the issuer and validity
// mandatory.
async function ecdsaSdCredential(holder) {
  log.debug("Entering ecdsaSdCredential().");
  var d = await digitalBazaar();
  var issuer = "https://issuer.example/issuers/ecdsa-sd";
  var kp = await d.EcdsaMultikey.generate({ curve: "P-256",
                                            controller: issuer });
  publish(issuer, await kp.export({ publicKey: true }));
  var unsigned = credential(issuer, holder.did);
  log.debug("Leaving ecdsaSdCredential().");
  return d.jsigs.sign(unsigned, {
    suite: new d.DataIntegrityProof({ signer: kp.signer(),
      cryptosuite: d.ecdsaSd.createSignCryptosuite({
        mandatoryPointers: ["/issuer", "/issuanceDate"] }) }),
    purpose: new d.jsigs.purposes.AssertionProofPurpose(),
    documentLoader: loader });
}

async function bbsCredential(holder) {
  log.debug("Entering bbsCredential().");
  var mattr = require("@mattrglobal/jsonld-signatures-bbs");
  var jsigs7 = require(require.resolve("jsonld-signatures", { paths:
    [path.dirname(require.resolve("@mattrglobal/jsonld-signatures-bbs"))] }));
  // A did:key (bls12_381-g2-pub, multicodec 0xeb), because the wallet
  // resolves the issuer's key to derive from it, and a page resolves a
  // did:key in place where it could not resolve a made-up method.
  var kp = await mattr.Bls12381G2KeyPair.generate();
  var raw = didLib.base58Decode(kp.publicKey);
  var mb = "z" + didLib.base58Encode(Uint8Array.from([0xeb, 0x01]
    .concat(Array.from(raw))));
  var issuer = "did:key:" + mb;
  kp.id = issuer + "#" + mb;
  kp.controller = issuer;
  docs[issuer] = { "@context": CONTROLLER_CONTEXT.concat(
    ["https://w3id.org/security/bbs/v1"]), id: issuer,
    assertionMethod: [{ id: kp.id, type: "Bls12381G2Key2020",
      controller: issuer, publicKeyBase58: kp.publicKey }] };
  var signed = await jsigs7.sign(credential(issuer, holder.did,
    ["https://w3id.org/security/bbs/v1"]), {
    suite: new mattr.BbsBlsSignature2020({ key: kp }),
    purpose: new jsigs7.purposes.AssertionProofPurpose(),
    documentLoader: loader });
  log.debug("Leaving bbsCredential().");
  return { signed: signed, mattr: mattr, jsigs7: jsigs7 };
}

function requestQuery(nonce, ldpAccepts) {
  log.debug("Entering requestQuery().");
  var dcql = { credentials: [{ id: "ld", format: "ldp_vc",
    meta: { type_values: [["VerifiableCredential"]] },
    claims: [{ path: ["credentialSubject", "given_name"] }] }] };
  var meta = { vp_formats_supported: { ldp_vc: ldpAccepts ||
    { proof_type_values: ["DataIntegrityProof"] } } };
  var q = new URLSearchParams({ client_id: CLIENT_ID,
    response_type: "vp_token", response_mode: "direct_post",
    response_uri: VERIFIER, nonce: nonce, state: "st-" + nonce,
    dcql_query: JSON.stringify(dcql), client_metadata: JSON.stringify(meta) });
  log.debug("Leaving requestQuery().");
  return q.toString();
}

// Hand the wallet its credential and holder key, read the request by value
// on step 1, and answer what step 2 builds.
async function presentThroughThePages(driver, held, holder, query) {
  log.debug("Entering presentThroughThePages().");
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html");
  await waitForContent.waitForPageBundle(driver, "step 1");
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_holder_jwk', arguments[1]);" +
    "localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[2]);",
    JSON.stringify(held), JSON.stringify(holder.publicJwk),
    JSON.stringify(holder.privateJwk));
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html?" + query);
  await waitForContent.waitForPageBundle(driver, "step 1, with the request");
  await waitForStatus(driver, "vp_request_status", function (s) {
    return /Request read/.test(s);
  }, "step 1 should read the ldp_vc request", stepWait);
  await driver.executeScript(
    "var b=document.getElementById('vp_continue_button'); if (b) b.click();");
  await driver.wait(until.urlContains("vc-presentation-2.html"), stepWait,
                    "Continue should reach step 2");
  await waitForContent.waitForPageBundle(driver, "step 2");
  var text;
  try {
    text = await waitForValue(driver, "vp_presentation", function (v) {
      return /"VerifiablePresentation"/.test(v);
    }, "step 2 should build a holder-signed VerifiablePresentation",
       stepWait);
  } catch (e) {
    // What step 2 said is the reason; the timeout alone names nothing.
    var said = await driver.executeScript(
      "var e=document.getElementById('vp_present_status');" +
      "return e ? e.textContent : '(no status)';");
    log.debug("Leaving presentThroughThePages(). Step 2 said: " + said);
    throw new Error(e.message + " — step 2 says: " + said);
  }
  log.debug("Leaving presentThroughThePages().");
  return JSON.parse(text);
}

async function verifyHolderProof(vp, nonce, cryptosuite, label) {
  log.debug("Entering verifyHolderProof(). " + label);
  var d = await digitalBazaar();
  assert.strictEqual(vp.proof.cryptosuite, cryptosuite,
                     label + ": the holder proof is " + cryptosuite);
  var verifySuite = cryptosuite === "eddsa-jcs-2022" ?
    d.eddsaJcs.createVerifyCryptosuite() :
    cryptosuite === "ecdsa-jcs-2019" ?
      d.ecdsaJcs.createVerifyCryptosuite() :
      cryptosuite === "ecdsa-rdfc-2019" ? d.ecdsaRdfc : null;
  assert.ok(verifySuite, label + ": a verify suite for " + cryptosuite);
  var r = await d.jsigs.verify(vp, {
    suite: new d.DataIntegrityProof({ cryptosuite: verifySuite }),
    purpose: new d.jsigs.purposes.AuthenticationProofPurpose({
      challenge: nonce, domain: CLIENT_ID }),
    documentLoader: loader });
  assert.ok(r.verified, label + ": Digital Bazaar verifies the holder's " +
    cryptosuite + " VP with this request's nonce and Client Identifier: " +
    (r.error ? String((r.error.errors || [r.error])[0].message) : ""));
  log.debug("Leaving verifyHolderProof().");
}

async function test() {
  log.debug("Entering test().");
  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    var d = await digitalBazaar();

    log.info("=== 1. eddsa-rdfc-2022, Ed25519 holder, no constraint ===");
    var edHolder = await holderKey("Ed25519");
    var edCred = await eddsaCredential(edHolder);
    var nonce1 = "n-" + nodeCrypto.randomBytes(8).toString("hex");
    var vp1 = await presentThroughThePages(driver, edCred, edHolder,
                                           requestQuery(nonce1));
    await verifyHolderProof(vp1, nonce1, "eddsa-jcs-2022", "case 1");
    var inner = vp1.verifiableCredential[0];
    assert.deepStrictEqual(inner, edCred, "the whole credential goes, " +
                           "exactly as the issuer signed it");
    var r = await d.jsigs.verify(inner, {
      suite: new d.DataIntegrityProof({ cryptosuite: d.eddsaRdfc }),
      purpose: new d.jsigs.purposes.AssertionProofPurpose(),
      documentLoader: loader });
    assert.ok(r.verified, "Digital Bazaar verifies the credential inside");
    log.info("PASS the wallet presented the whole eddsa-rdfc-2022 " +
             "credential in an eddsa-jcs-2022 VP; Digital Bazaar verifies " +
             "both.");

    log.info("=== 2. a Verifier that accepts only ecdsa-rdfc-2019 ===");
    var ecHolder = await holderKey("P-256");
    var ecCred = await eddsaCredential(ecHolder);
    var nonce2 = "n-" + nodeCrypto.randomBytes(8).toString("hex");
    var vp2 = await presentThroughThePages(driver, ecCred, ecHolder,
      requestQuery(nonce2, { proof_type_values: ["DataIntegrityProof"],
                             cryptosuite_values: ["ecdsa-rdfc-2019"] }));
    await verifyHolderProof(vp2, nonce2, "ecdsa-rdfc-2019", "case 2");
    log.info("PASS with a P-256 key and a Verifier taking only " +
             "ecdsa-rdfc-2019, the wallet chose ecdsa-rdfc-2019 itself.");

    log.info("=== 3. BbsBlsSignature2020, one claim of two ===");
    var bbsHolder = await holderKey("Ed25519");
    var bbs = await bbsCredential(bbsHolder);
    var nonce3 = "n-" + nodeCrypto.randomBytes(8).toString("hex");
    var vp3 = await presentThroughThePages(driver, bbs.signed, bbsHolder,
                                           requestQuery(nonce3));
    await verifyHolderProof(vp3, nonce3, "eddsa-jcs-2022", "case 3");
    var derived = vp3.verifiableCredential[0];
    assert.strictEqual(derived.proof.type, "BbsBlsSignatureProof2020",
                       "the wallet derived a BbsBlsSignatureProof2020");
    assert.strictEqual(derived.credentialSubject.given_name, "Alice",
                       "the asked-for claim is disclosed");
    assert.ok(!("family_name" in derived.credentialSubject),
              "the claim nobody asked for is not");
    assert.strictEqual(Buffer.from(derived.proof.nonce, "base64")
      .toString(), nonce3, "the derived proof's nonce is the request's");
    var v3 = await bbs.jsigs7.verify(derived, {
      suite: new bbs.mattr.BbsBlsSignatureProof2020(),
      purpose: new bbs.jsigs7.purposes.AssertionProofPurpose(),
      documentLoader: loader });
    assert.ok(v3.verified, "MATTR verifies the derived proof: " +
              (v3.error ? String(v3.error.errors || v3.error) : ""));
    log.info("PASS the wallet derived a BbsBlsSignatureProof2020 " +
             "disclosing given_name only; MATTR verifies it.");

    log.info("=== 4. ecdsa-sd-2023, one claim of two ===");
    var sdHolder = await holderKey("P-256");
    var sdCred = await ecdsaSdCredential(sdHolder);
    var nonce4 = "n-" + nodeCrypto.randomBytes(8).toString("hex");
    var vp4 = await presentThroughThePages(driver, sdCred, sdHolder,
                                           requestQuery(nonce4));
    await verifyHolderProof(vp4, nonce4, "ecdsa-jcs-2019", "case 4");
    var sdDerived = vp4.verifiableCredential[0];
    assert.strictEqual(sdDerived.proof.cryptosuite, "ecdsa-sd-2023",
                       "the wallet derived an ecdsa-sd-2023 proof");
    assert.strictEqual(sdDerived.credentialSubject.given_name, "Alice",
                       "the asked-for claim is disclosed");
    assert.ok(!("family_name" in sdDerived.credentialSubject),
              "the claim nobody asked for is not");
    assert.strictEqual(sdDerived.issuer, sdCred.issuer,
                       "the mandatory issuer is disclosed");
    var v4 = await d.jsigs.verify(sdDerived, {
      suite: new d.DataIntegrityProof({
        cryptosuite: d.ecdsaSd.createVerifyCryptosuite() }),
      purpose: new d.jsigs.purposes.AssertionProofPurpose(),
      documentLoader: loader });
    assert.ok(v4.verified, "Digital Bazaar verifies the derived " +
      "ecdsa-sd-2023 credential: " + (v4.error ? String((v4.error.errors ||
      [v4.error])[0].message) : ""));
    log.info("PASS the wallet derived an ecdsa-sd-2023 proof disclosing " +
             "given_name and the mandatory claims; Digital Bazaar verifies " +
             "it and the holder's VP.");
    log.info("ldp_vc_whole_presentation: all checks passed.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                             "base url of the debugger's client"));
program.addOption(new Option("-h, --headless <headless>",
                             "run Chrome headless (default true)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) {
  baseUrl = opts.url;
  log.info("Setting url to " + baseUrl);
}
if (opts.headless === "false") headless = false;

test().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
