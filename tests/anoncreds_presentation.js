// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: anoncreds_presentation.js
//
// ---------------------------------------------------------------------------
// The wallet's presentation pages, in Chrome, presenting an AnonCreds
// credential (#479), verified by anoncreds-rs (tests/anoncreds_witness.js).
//
// anoncreds-rs is the issuer: a schema with a spaced attribute name, a CL
// credential definition and an offer. The holder's credential request and
// processing are client/src/anoncreds.js in node, and the bundle (credential,
// schema, credential definition) and the link secret (as an oct JWK) are
// handed to the wallet as issuance leaves them in storage. An OpenID4VP
// request asks, by DCQL, for two of three attributes with a non-numeric
// nonce; step 2 builds the presentation, and anoncreds-rs verifies it
// against the AnonCreds request this test derives itself from the same
// OpenID4VP request (an attribute per claim, the nonce's SHA-256 cut to 80
// bits — the mapping the wallet documents, recomputed here with node's
// crypto). The third attribute must not be revealed.
//
// Needs only the client, and the witness.
// ---------------------------------------------------------------------------

const { Builder, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const path = require("path");
const fs = require("fs");
const os = require("os");
const nodeCrypto = require("crypto");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
const waitForContent = require("./wait_for.js");
const { waitForStatus, waitForValue } = require("./wait_for");
const paths = require("./module_paths.js");
const witness = require("./anoncreds_witness.js");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "anoncreds_presentation",
    level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var stepWait = waitTime * 4;

const VERIFIER = "https://verifier.example/response";
const CLIENT_ID = "redirect_uri:" + VERIFIER;
const ISSUER = "did:example:issuer";
const ours = paths.requireSharedModule([path.join(__dirname, "..", "client",
  "src", "anoncreds.js")], "client/src/anoncreds.js");

function anoncredsNonce(nonce) {
  log.debug("Entering anoncredsNonce().");
  var d = nodeCrypto.createHash("sha256").update(nonce, "utf8").digest()
    .subarray(0, 10);
  log.debug("Leaving anoncredsNonce().");
  return BigInt("0x" + d.toString("hex")).toString(10);
}

// One case: anoncreds-rs issues (revocable or not) to our holder, the pages
// present two of three attributes, anoncreds-rs verifies.
async function oneCase(driver, ac, revocable, w3cForm) {
  var label = w3cForm ? "w3c" : revocable ? "revocable" : "plain";
  log.debug("Entering oneCase(). " + label);
  var sid = ISSUER + "/schema/" + label;
  var cid = ISSUER + "/creddef/" + label;
  var rid = ISSUER + "/revreg/" + label;
  var schema = ac.Schema.create({ name: "person-" + label, version: "1.0",
    issuerId: ISSUER, attributeNames: ["name", "Given Name", "age"] });
  var made = ac.CredentialDefinition.create({ schemaId: sid,
    issuerId: ISSUER, schema: schema, signatureType: "CL", tag: label,
    supportRevocation: revocable });
  var cdO = made.credentialDefinition;
  var cd = cdO.toJson();
  var offer = ac.CredentialOffer.create({ schemaId: sid,
    credentialDefinitionId: cid,
    keyCorrectnessProof: made.keyCorrectnessProof }).toJson();
  var ls = ours.createLinkSecret();
  var req = ours.createCredentialRequest({ credentialOffer: offer,
    credentialDefinition: cd, linkSecret: ls, linkSecretId: "ls",
    entropy: "wallet-" + label });
  var t0 = 1700000000;
  var revocation = null;
  var createOpts = { credentialDefinition: cdO,
    credentialDefinitionPrivate: made.credentialDefinitionPrivate,
    credentialOffer: offer, credentialRequest: req.credentialRequest,
    attributeRawValues: { name: "Alice", "Given Name": "Al", age: "28" } };
  if (revocable) {
    var tailsDir = fs.mkdtempSync(path.join(os.tmpdir(), "ac-tails-"));
    var reg = ac.RevocationRegistryDefinition.create({
      credentialDefinition: cdO, credentialDefinitionId: cid, tag: label,
      issuerId: ISSUER, revocationRegistryType: "CL_ACCUM",
      maximumCredentialNumber: 6, tailsDirectoryPath: tailsDir });
    var slO = ac.RevocationStatusList.create({ credentialDefinition: cdO,
      revocationRegistryDefinitionId: rid,
      revocationRegistryDefinition: reg.revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate:
        reg.revocationRegistryDefinitionPrivate,
      issuerId: ISSUER, issuanceByDefault: true, timestamp: t0 });
    createOpts.revocationConfiguration = new ac.CredentialRevocationConfig({
      registryDefinition: reg.revocationRegistryDefinition,
      registryDefinitionPrivate: reg.revocationRegistryDefinitionPrivate,
      statusList: slO, registryIndex: 2 });
    revocation = { rrdO: reg.revocationRegistryDefinition, slO: slO,
      tails: fs.readFileSync(reg.revocationRegistryDefinition
        .getTailsLocation()), dir: tailsDir };
  }
  var cred;
  if (w3cForm) {
    // The W3C form: anoncreds-rs issues and processes a W3C credential
    // (anoncreds-2023) for our link secret, and the wallet holds that.
    cred = ac.W3cCredential.create(createOpts).process({
      credentialRequestMetadata: req.credentialRequestMetadata,
      linkSecret: ls, credentialDefinition: cdO }).toJson();
  } else {
    var issued = ac.Credential.create(createOpts).toJson();
    cred = ours.processCredential(issued, { credentialRequestMetadata:
      req.credentialRequestMetadata, linkSecret: ls,
      credentialDefinition: cd, revocationRegistryDefinition: revocation ?
        revocation.rrdO.toJson() : undefined });
  }
  var held = { format: "anoncreds", credential: cred,
    schema: schema.toJson(), schema_id: sid, credential_definition: cd,
    cred_def_id: cid };
  if (revocation) {
    held.revocation = { registry_definition: revocation.rrdO.toJson(),
      status_list: revocation.slO.toJson(),
      tails: revocation.tails.toString("base64url") };
  }
  var lsHex = BigInt(ls).toString(16);
  if (lsHex.length % 2) lsHex = "0" + lsHex;
  var lsJwk = { kty: "oct", alg: "AnonCreds-link-secret",
                k: Buffer.from(lsHex, "hex").toString("base64url") };
  var nonce = "n-" + nodeCrypto.randomBytes(8).toString("hex");
  var dcql = { credentials: [{ id: "cred", format: "anoncreds", claims: [
    { path: ["name"] }, { path: ["Given Name"] }] }] };
  var q = new URLSearchParams({ client_id: CLIENT_ID,
    response_type: "vp_token", response_mode: "direct_post",
    response_uri: VERIFIER, nonce: nonce, state: "st",
    dcql_query: JSON.stringify(dcql),
    client_metadata: JSON.stringify({ vp_formats_supported: {} }) });
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html");
  await waitForContent.waitForPageBundle(driver, "step 1");
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[1]);",
    JSON.stringify(held), JSON.stringify(lsJwk));
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html?" + q);
  await waitForContent.waitForPageBundle(driver, "step 1, with request");
  await waitForStatus(driver, "vp_request_status", function (st) {
    return /Request read/.test(st);
  }, "step 1 should read the request", stepWait);
  await driver.executeScript("var b=document.getElementById(" +
    "'vp_continue_button'); if (b) b.click();");
  await driver.wait(until.urlContains("vc-presentation-2.html"), stepWait,
                    "Continue should reach step 2");
  await waitForContent.waitForPageBundle(driver, "step 2");
  var text;
  try {
    text = await waitForValue(driver, "vp_presentation", function (v) {
      return v.trim().length > 40;
    }, "step 2 should build a presentation", stepWait);
  } catch (e) {
    var said = await driver.executeScript("var e=document.getElementById(" +
      "'vp_present_status'); return e ? e.textContent : '(no status)';");
    throw new Error(e.message + " — step 2 says: " + said);
  }
  var pres = JSON.parse(text.trim());
  var preq = { nonce: anoncredsNonce(nonce), name: "OpenID4VP request",
    version: "1.0", requested_attributes: {
      "name": { name: "name" }, "Given Name": { name: "Given Name" } },
    requested_predicates: {} };
  var schemas = {};
  schemas[sid] = schema.toJson();
  var cds = {};
  cds[cid] = cd;
  var ctx = { presentationRequest: preq, schemas: schemas,
              credentialDefinitions: cds };
  if (revocation) {
    preq.non_revoked = { from: t0, to: t0 };
    var defs = {};
    defs[rid] = revocation.rrdO;
    ctx.revocationRegistryDefinitions = defs;
    ctx.revocationStatusLists = [revocation.slO];
    assert.ok(pres.proof.proofs[0].non_revoc_proof, "revocable: a " +
              "non-revocation proof went");
    assert.strictEqual(pres.identifiers[0].timestamp, t0, "revocable: it " +
                       "names the status list's timestamp");
  }
  if (w3cForm) {
    assert.strictEqual(pres.proof && pres.proof.cryptosuite,
                       "anoncreds-2023", "w3c: the wallet presents in the " +
                       "W3C form");
    assert.ok(ac.W3cPresentation.fromJson(pres).verify(ctx), label +
              ": anoncreds-rs verifies the wallet's W3C presentation");
    assert.deepStrictEqual(Object.keys(pres.verifiableCredential[0]
      .credentialSubject).sort(), ["Given Name", "name"],
      "w3c: name and Given Name revealed, age not");
  } else {
    assert.ok(ac.Presentation.fromJson(pres).verify(ctx), label +
              ": anoncreds-rs verifies the wallet's presentation");
    var revealed = pres.proof.proofs[0].primary_proof.eq_proof
      .revealed_attrs;
    assert.deepStrictEqual(Object.keys(revealed).sort(),
                           ["givenname", "name"],
                           label + ": name and Given Name revealed, age not");
  }
  if (revocation) fs.rmSync(revocation.dir, { recursive: true, force: true });
  log.info("PASS AnonCreds " + label + " (anoncreds-rs issuer, our " +
           "holder): two of three attributes revealed under the OpenID4VP " +
           "nonce" + (revocable ? ", with a non-revocation proof" : "") +
           "; anoncreds-rs verifies it.");
  log.debug("Leaving oneCase().");
}

async function test() {
  log.debug("Entering test().");
  var ac = (await witness.load()).ac;
  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await oneCase(driver, ac, false);
    await oneCase(driver, ac, true);
    await oneCase(driver, ac, false, true);
    log.info("anoncreds_presentation: all checks passed.");
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
