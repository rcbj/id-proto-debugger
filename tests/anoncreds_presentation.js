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

async function test() {
  log.debug("Entering test().");
  var ac = (await witness.load()).ac;
  var sid = ISSUER + "/schema/1";
  var cid = ISSUER + "/creddef/1";
  var schema = ac.Schema.create({ name: "person", version: "1.0",
    issuerId: ISSUER, attributeNames: ["name", "Given Name", "age"] });
  var made = ac.CredentialDefinition.create({ schemaId: sid,
    issuerId: ISSUER, schema: schema, signatureType: "CL", tag: "t",
    supportRevocation: false });
  var cd = made.credentialDefinition.toJson();
  var offer = ac.CredentialOffer.create({ schemaId: sid,
    credentialDefinitionId: cid,
    keyCorrectnessProof: made.keyCorrectnessProof }).toJson();
  var ls = ours.createLinkSecret();
  var req = ours.createCredentialRequest({ credentialOffer: offer,
    credentialDefinition: cd, linkSecret: ls, linkSecretId: "ls",
    entropy: "wallet" });
  var issued = ac.Credential.create({ credentialDefinition: cd,
    credentialDefinitionPrivate: made.credentialDefinitionPrivate,
    credentialOffer: offer, credentialRequest: req.credentialRequest,
    attributeRawValues: { name: "Alice", "Given Name": "Al", age: "28" } })
    .toJson();
  var cred = ours.processCredential(issued, { credentialRequestMetadata:
    req.credentialRequestMetadata, linkSecret: ls, credentialDefinition: cd });
  var bundle = JSON.stringify({ format: "anoncreds", credential: cred,
    schema: schema.toJson(), schema_id: sid, credential_definition: cd,
    cred_def_id: cid });
  var lsHex = BigInt(ls).toString(16);
  if (lsHex.length % 2) lsHex = "0" + lsHex;
  var lsBytes = Buffer.from(lsHex, "hex");
  var lsJwk = { kty: "oct", alg: "AnonCreds-link-secret",
                k: lsBytes.toString("base64url") };

  var nonce = "n-" + nodeCrypto.randomBytes(8).toString("hex");
  var dcql = { credentials: [{ id: "cred", format: "anoncreds", claims: [
    { path: ["name"] }, { path: ["Given Name"] }] }] };
  var q = new URLSearchParams({ client_id: CLIENT_ID,
    response_type: "vp_token", response_mode: "direct_post",
    response_uri: VERIFIER, nonce: nonce, state: "st",
    dcql_query: JSON.stringify(dcql),
    client_metadata: JSON.stringify({ vp_formats_supported: {} }) });

  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await loadUrl(driver, baseUrl + "/vc-presentation-1.html");
    await waitForContent.waitForPageBundle(driver, "step 1");
    await driver.executeScript(
      "window.localStorage.clear();" +
      "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
      "localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[1]);",
      bundle, JSON.stringify(lsJwk));
    await loadUrl(driver, baseUrl + "/vc-presentation-1.html?" + q);
    await waitForContent.waitForPageBundle(driver, "step 1, with request");
    await waitForStatus(driver, "vp_request_status", function (s) {
      return /Request read/.test(s);
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
    assert.ok(ac.Presentation.fromJson(pres).verify({
      presentationRequest: preq, schemas: schemas,
      credentialDefinitions: cds }),
      "anoncreds-rs verifies the wallet's presentation");
    var revealed = pres.proof.proofs[0].primary_proof.eq_proof.revealed_attrs;
    assert.deepStrictEqual(Object.keys(revealed).sort(),
                           ["givenname", "name"],
                           "name and Given Name revealed, age not");
    assert.strictEqual(pres.requested_proof.revealed_attrs.name.raw, "Alice",
                       "the raw value travels");
    log.info("PASS AnonCreds (anoncreds-rs issuer, our holder): two of " +
             "three attributes revealed under the OpenID4VP nonce; " +
             "anoncreds-rs verifies the wallet's presentation.");
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
