// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_predicates_browser.js
//
// ---------------------------------------------------------------------------
// The predicate query page (vc-predicates.html) and the wallet's query
// handling, in Chrome (#474).
//
//   1. anoncreds-rs issues an AnonCreds credential (name, age 28) to our
//      holder; the page composes "reveal name, prove age >= 18" — once as a
//      DIF Presentation Exchange presentation_definition (OpenID4VP drafts),
//      once as DCQL with the debugger's critical predicate extension — and
//      sends it to the wallet. Step 1 shows the predicate as proven in zero
//      knowledge and age as not revealed; step 2 builds the proof, the age
//      row cannot be ticked, and (PE) a presentation_submission goes with
//      it. anoncreds-rs verifies what step 2 built, against the request
//      this test derives in node; the age is not in it. Present answers by
//      fragment back to the page, which verifies it with anoncreds.js.
//   2. OpenID4VP 1.0 section 6.4.1 in the wallet: a DCQL request for
//      age_over_18 with values [true], against an SD-JWT VC holding true
//      (answered, the claim selected) and one holding false (refused at
//      step 1, saying why, and nothing built at step 2).
//   3. The Verifier page builds the same predicate as the DCQL extension
//      and as a presentation_definition.
//
// Needs only the client, and the anoncreds witness.
// ---------------------------------------------------------------------------

const { Builder, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const path = require("path");
const fs = require("fs");
const nodeCrypto = require("crypto");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
// The user guide's pictures (docs/v0.9.5/vc/). Inert unless DOC_SCREENSHOT_DIR
// is set, so an ordinary run takes none.
const docShots = require("./doc_screenshots.js");
const waitForContent = require("./wait_for.js");
const { waitForStatus, waitForValue } = require("./wait_for");
const paths = require("./module_paths.js");
const witness = require("./anoncreds_witness.js");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_predicates_browser",
    level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var stepWait = waitTime * 4;

const ISSUER = "did:example:predicates";

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

function load(name) {
  log.debug("Entering load(). " + name);
  log.debug("Leaving load().");
  return paths.requireSharedModule([path.join(repoRoot(), "client", "src",
                                              name)], "client/src/" + name);
}
const ours = load("anoncreds.js");
const vpQuery = load("vp_query.js");

function anoncredsNonce(nonce) {
  log.debug("Entering anoncredsNonce().");
  var d = nodeCrypto.createHash("sha256").update(nonce, "utf8").digest()
    .subarray(0, 10);
  log.debug("Leaving anoncredsNonce().");
  return BigInt("0x" + d.toString("hex")).toString(10);
}

async function statusOf(driver, id) {
  log.debug("Entering statusOf(). " + id);
  var t = await driver.executeScript("var e=document.getElementById(" +
    "arguments[0]); return e ? e.textContent : '(none)';", id);
  log.debug("Leaving statusOf().");
  return t;
}

async function click(driver, id) {
  log.debug("Entering click(). " + id);
  await driver.executeScript("var b=document.getElementById(arguments[0]);" +
                             " if (b) b.click();", id);
  log.debug("Leaving click().");
}

// anoncreds-rs issues; our holder processes; the bundle and link secret go
// where issuance leaves them.
function issueAnoncreds(ac) {
  log.debug("Entering issueAnoncreds().");
  var sid = ISSUER + "/schema/person";
  var cid = ISSUER + "/creddef/person";
  var schema = ac.Schema.create({ name: "person", version: "1.0",
    issuerId: ISSUER, attributeNames: ["name", "age"] });
  var made = ac.CredentialDefinition.create({ schemaId: sid,
    issuerId: ISSUER, schema: schema, signatureType: "CL", tag: "p",
    supportRevocation: false });
  var cd = made.credentialDefinition.toJson();
  var offer = ac.CredentialOffer.create({ schemaId: sid,
    credentialDefinitionId: cid,
    keyCorrectnessProof: made.keyCorrectnessProof }).toJson();
  var ls = ours.createLinkSecret();
  var req = ours.createCredentialRequest({ credentialOffer: offer,
    credentialDefinition: cd, linkSecret: ls, linkSecretId: "ls",
    entropy: "predicates" });
  var issued = ac.Credential.create({ credentialDefinition: cd,
    credentialDefinitionPrivate: made.credentialDefinitionPrivate.toJson(),
    credentialOffer: offer, credentialRequest: req.credentialRequest,
    attributeRawValues: { name: "Alice", age: "28" } }).toJson();
  var cred = ours.processCredential(issued, { credentialRequestMetadata:
    req.credentialRequestMetadata, linkSecret: ls, credentialDefinition: cd });
  var lsHex = BigInt(ls).toString(16);
  if (lsHex.length % 2) lsHex = "0" + lsHex;
  log.debug("Leaving issueAnoncreds().");
  return { sid: sid, cid: cid, schema: schema.toJson(), cd: cd,
    held: { format: "anoncreds", credential: cred, schema: schema.toJson(),
            schema_id: sid, credential_definition: cd, cred_def_id: cid },
    lsJwk: { kty: "oct", alg: "AnonCreds-link-secret",
             k: Buffer.from(lsHex, "hex").toString("base64url") } };
}

async function plant(driver, credential, holderJwk) {
  log.debug("Entering plant().");
  await loadUrl(driver, baseUrl + "/vc-presentation-0.html");
  await waitForContent.waitForPageBundle(driver, "step 0");
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[1]);",
    credential, JSON.stringify(holderJwk));
  log.debug("Leaving plant().");
}

// One round trip: compose on the page, prove in the wallet, verify back.
async function roundTrip(driver, ac, iss, language) {
  log.debug("Entering roundTrip(). " + language);
  docShots.setPrefix("vc-predicates-" + language);
  await plant(driver, JSON.stringify(iss.held), iss.lsJwk);
  await loadUrl(driver, baseUrl + "/vc-predicates.html");
  await waitForContent.waitForPageBundle(driver, "the predicates page");
  await driver.executeScript(
    "document.getElementById('vcp_language').value = arguments[0];" +
    "vcpredicatespage.onLanguage();" +
    "document.getElementById('vcp_format').value = 'anoncreds';" +
    "document.getElementById('vcp_reveal').value = 'name';" +
    "document.getElementById('vcp_predicates').value = 'age >= 18';",
    language);
  await click(driver, "vcp_build_button");
  var queryText = await waitForValue(driver, "vcp_query", function (v) {
    return v.indexOf(language === "pe" ? "\"predicate\"" :
                     "x_debugger_crit") !== -1;
  }, language + ": Build should write the query", stepWait);
  var mapping = await statusOf(driver, "vcp_mapping");
  assert.match(mapping, /requested_predicates[\s\S]*"p_type": ">="/,
               language + ": the page shows the AnonCreds request with the " +
               "predicate");
  await docShots.snap(driver, "01-compose", { ids: ["pane_vcp_compose"] });
  await docShots.snap(driver, "02-anoncreds-request",
                      { ids: ["pane_vcp_mapping"] });
  await click(driver, "vcp_send_button");
  await driver.wait(until.urlContains("vc-presentation-1.html"), stepWait,
                    language + ": Send should open the wallet");
  await waitForContent.waitForPageBundle(driver, "step 1");
  await waitForStatus(driver, "vp_request_status", function (st) {
    return /Request read|cannot be answered/.test(st);
  }, language + ": step 1 should read the request", stepWait);
  var st1 = await statusOf(driver, "vp_request_status");
  assert.match(st1, /Request read/, language + ": step 1 answers: " + st1);
  assert.match(st1, /1 predicate\(s\) proven without disclosing age/,
               language + ": step 1 says what is proven and not disclosed");
  var preds = await statusOf(driver, "vp_predicates_table");
  assert.match(preds, /age >= 18[\s\S]*proven \(zero knowledge\)/,
               language + ": the predicates table: " + preds);
  var lang = await statusOf(driver, "vp_query_language");
  assert.match(lang, language === "pe" ? /removed in 1\.0/ : /DCQL/,
               language + ": the query language is labelled");
  await docShots.snap(driver, "03-wallet-what-is-asked",
                      { ids: ["pane_requested"] });
  await click(driver, "vp_continue_button");
  await driver.wait(until.urlContains("vc-presentation-2.html"), stepWait,
                    language + ": Continue should reach step 2");
  await waitForContent.waitForPageBundle(driver, "step 2");
  var text;
  try {
    text = await waitForValue(driver, "vp_presentation", function (v) {
      return v.trim().length > 40;
    }, language + ": step 2 should build a presentation", stepWait);
  } catch (e) {
    throw new Error(e.message + " — step 2 says: " +
                    await statusOf(driver, "vp_present_status"));
  }
  var summary = await statusOf(driver, "vp_predicates_summary");
  assert.match(summary, /proven in zero knowledge[\s\S]*Not revealed: age/,
               language + ": step 2 shows the predicate and what is not " +
               "revealed: " + summary);
  var ageRow = await driver.executeScript(
    "var rows = document.querySelectorAll('#vp_disclosures_table tr');" +
    "for (var i = 0; i < rows.length; i++) {" +
    "  var c = rows[i].querySelectorAll('td');" +
    "  if (c.length > 1 && c[1].textContent === 'age') {" +
    "    var b = rows[i].querySelector('input');" +
    "    return { disabled: b.disabled, checked: b.checked }; } }" +
    "return null;");
  assert.deepStrictEqual(ageRow, { disabled: true, checked: false },
                         language + ": the age row cannot be ticked");
  await docShots.snap(driver, "04-wallet-choose", { ids: ["pane_choose"] });
  await docShots.snap(driver, "05-wallet-presentation",
                      { ids: ["pane_presentation"] });
  var pres = JSON.parse(text.trim());
  assert.deepStrictEqual(Object.keys(pres.requested_proof.revealed_attrs),
                         ["name"], language + ": only name is revealed");
  // anoncreds-rs verifies it against the request derived here, in node.
  var params = new URL(await driver.getCurrentUrl());
  var stored = await driver.executeScript(
    "return JSON.parse(localStorage.getItem('sdjwtvp_request'));");
  var nonce = stored.params.nonce;
  var model = vpQuery.normalise(language === "pe" ?
    { presentation_definition: stored.params.presentation_definition } :
    { dcql_query: stored.params.dcql_query });
  var preq = vpQuery.anoncredsRequestFor(vpQuery.nominalPlan(
    model.items[0]), { nonce: anoncredsNonce(nonce) });
  var schemas = {};
  schemas[iss.sid] = iss.schema;
  var cds = {};
  cds[iss.cid] = iss.cd;
  assert.ok(ac.Presentation.fromJson(pres).verify({ presentationRequest:
    preq, schemas: schemas, credentialDefinitions: cds }), language +
    ": anoncreds-rs verifies the wallet's predicate proof");
  if (language === "pe") {
    var sub = JSON.parse(await statusOf(driver,
                                        "vp_presentation_submission"));
    assert.strictEqual(sub.descriptor_map[0].format, "anoncreds");
    assert.strictEqual(sub.descriptor_map[0].path, "$");
    assert.strictEqual(sub.definition_id, model.definition.id);
  }
  log.debug("step 2 at " + params.pathname);
  // Present: the answer goes back to the page by fragment.
  await driver.wait(async function () {
    return driver.executeScript("var b=document.getElementById(" +
      "'vp_present_button'); return !!b && !b.disabled;");
  }, stepWait, language + ": Present should be enabled");
  await click(driver, "vp_present_button");
  await driver.wait(until.urlContains("vc-predicates.html#"), stepWait,
                    language + ": the answer should come back to the page");
  await waitForContent.waitForPageBundle(driver, "the predicates page, " +
                                         "answered");
  await waitForStatus(driver, "vcp_inspect_status", function (st) {
    return /Every check passed|does not verify|Could not/.test(st);
  }, language + ": the page should verify the answer", stepWait);
  var verdict = await statusOf(driver, "vcp_inspect_status");
  assert.match(verdict, /Every check passed: 1 predicate\(s\) proven, 1 /,
               language + ": the page verifies: " + verdict +
               " — " + await statusOf(driver, "vcp_inspect_result"));
  var result = await statusOf(driver, "vcp_inspect_result");
  assert.match(result, /PROVEN in zero knowledge/);
  await docShots.snap(driver, "06-verified", { ids: ["pane_vcp_inspect"] });
  if (language === "pe") {
    assert.match(result, /presentation_submissionmatches the definition/);
  }
  log.info("PASS " + language + ": composed on the page, age >= 18 proven " +
           "by the wallet without revealing age, verified by anoncreds-rs " +
           "and by the page.");
  log.debug("Leaving roundTrip().");
}

// --- OpenID4VP 1.0 section 6.4.1 in the wallet ---------------------------
function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

// An SD-JWT VC holding age_over_18 = `value` as a Disclosure, issued here.
function sdJwtWith(value, holderPub) {
  log.debug("Entering sdJwtWith().");
  var issuer = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var disclosure = b64u(JSON.stringify([b64u(nodeCrypto.randomBytes(16)),
                                        "age_over_18", value]));
  var nameDisc = b64u(JSON.stringify([b64u(nodeCrypto.randomBytes(16)),
                                      "given_name", "Erika"]));
  var digest = function (d) {
    log.debug("Entering digest().");
    log.debug("Leaving digest().");
    return b64u(nodeCrypto.createHash("sha256").update(d).digest());
  };
  var header = { alg: "ES256", typ: "dc+sd-jwt" };
  var payload = { iss: "https://issuer.example", vct: "urn:example:pid",
    iat: Math.floor(Date.now() / 1000), _sd_alg: "sha-256",
    _sd: [digest(disclosure), digest(nameDisc)], cnf: { jwk: holderPub } };
  var input = b64u(JSON.stringify(header)) + "." +
    b64u(JSON.stringify(payload));
  var sig = nodeCrypto.sign("sha256", Buffer.from(input), { key:
    issuer.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving sdJwtWith().");
  return input + "." + b64u(sig) + "~" + disclosure + "~" + nameDisc + "~";
}

async function valuesCase(driver, value) {
  log.debug("Entering valuesCase(). " + value);
  var holder = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var priv = holder.privateKey.export({ format: "jwk" });
  var pub = holder.publicKey.export({ format: "jwk" });
  await plant(driver, sdJwtWith(value, pub), priv);
  var target = "https://verifier.example/response";
  var dcql = { credentials: [{ id: "pid", format: "dc+sd-jwt",
    meta: { vct_values: ["urn:example:pid"] },
    claims: [{ path: ["age_over_18"], values: [true] }] }] };
  var q = new URLSearchParams({ client_id: "redirect_uri:" + target,
    response_type: "vp_token", response_mode: "direct_post",
    response_uri: target, nonce: "n-" + value, state: "st",
    dcql_query: JSON.stringify(dcql),
    client_metadata: JSON.stringify({ vp_formats_supported: {} }) });
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html?" + q);
  await waitForContent.waitForPageBundle(driver, "step 1, values");
  await waitForStatus(driver, "vp_request_status", function (st) {
    return /Request read|cannot be answered/.test(st);
  }, "step 1 should read the values request", stepWait);
  var st = await statusOf(driver, "vp_request_status");
  var claims = await statusOf(driver, "vp_requested_table");
  if (value === true) {
    assert.match(st, /Request read/, "true matches [true]: " + st);
    await click(driver, "vp_continue_button");
    await driver.wait(until.urlContains("vc-presentation-2.html"), stepWait,
                      "Continue should reach step 2");
    await waitForContent.waitForPageBundle(driver, "step 2, values");
    var chosen = await driver.executeScript(
      "var rows = document.querySelectorAll('#vp_disclosures_table tr');" +
      "var out = {};" +
      "for (var i = 0; i < rows.length; i++) {" +
      "  var c = rows[i].querySelectorAll('td');" +
      "  var b = rows[i].querySelector('input');" +
      "  if (c.length > 1 && b) out[c[1].textContent] = b.checked; }" +
      "return out;");
    assert.deepStrictEqual(chosen, { age_over_18: true, given_name: false },
                           "age_over_18 is selected, given_name is not");
  } else {
    assert.match(st, /cannot be answered/, "false does not match [true]");
    assert.match(st, /holds false.*treated as if it did not exist/,
                 "and step 1 says why: " + st);
    assert.match(claims, /value-mismatch/, "the claim row says why");
    docShots.setPrefix("vc-predicates-values");
    await docShots.snap(driver, "01-false-refused",
                        { ids: ["pane_requested"] });
    var off = await driver.executeScript("var b=document.getElementById(" +
      "'vp_continue_button'); return !!b && b.disabled;");
    assert.strictEqual(off, true, "Continue is off: the credential is not " +
                       "returned (section 6.4.1)");
  }
  log.info("PASS OpenID4VP 1.0 section 6.4.1 in the wallet: age_over_18 " +
           "values [true] against a credential holding " + value + ".");
  log.debug("Leaving valuesCase().");
}

// The Verifier page builds predicate requests in both languages (its query
// builder; the engine half, verification included, is vp_query_engine.js).
async function verifierPage(driver) {
  log.debug("Entering verifierPage().");
  await loadUrl(driver, baseUrl + "/vc-verifier.html");
  await waitForContent.waitForPageBundle(driver, "the Verifier page");
  await driver.executeScript(
    "document.getElementById('vpv_format').value = 'anoncreds';" +
    "document.getElementById('vpv_claims').value = 'name';" +
    "document.getElementById('vpv_predicates').value = 'age >= 18';" +
    "document.getElementById('vpv_query_language').value = 'dcql';" +
    "vcverifier.regenerateDcql();");
  var dcql = JSON.parse(await waitForValue(driver, "vpv_dcql", function (v) {
    return v.indexOf("x_debugger_crit") !== -1;
  }, "the Verifier should build the DCQL extension", stepWait));
  assert.deepStrictEqual(dcql.credentials[0].claims, [{ path: ["name"] }],
                         "the predicated claim is not in claims");
  assert.match(await statusOf(driver, "vpv_dcql_status"), /non-standard/);
  docShots.setPrefix("vc-predicates-verifier");
  await docShots.snap(driver, "01-dcql-extension", { ids: ["pane_query"] });
  await driver.executeScript(
    "document.getElementById('vpv_query_language').value = 'pe';" +
    "vcverifier.regenerateDcql();");
  var pd = JSON.parse(await waitForValue(driver, "vpv_dcql", function (v) {
    return v.indexOf("input_descriptors") !== -1;
  }, "the Verifier should build a presentation_definition", stepWait));
  var fields = pd.input_descriptors[0].constraints.fields;
  assert.deepStrictEqual(fields[1].filter, { type: "integer", minimum: 18 });
  assert.strictEqual(fields[1].predicate, "required");
  assert.match(await statusOf(driver, "vpv_dcql_status"),
               /removed in 1\.0/);
  await docShots.snap(driver, "02-presentation-definition",
                      { ids: ["pane_query"] });
  log.info("PASS the Verifier page builds age >= 18 as the DCQL " +
           "extension and as a presentation_definition.");
  log.debug("Leaving verifierPage().");
}

async function test() {
  log.debug("Entering test().");
  var ac = (await witness.load()).ac;
  var iss = issueAnoncreds(ac);
  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await roundTrip(driver, ac, iss, "pe");
    await roundTrip(driver, ac, iss, "dcql");
    await valuesCase(driver, true);
    await valuesCase(driver, false);
    await verifierPage(driver);
    log.info("vc_predicates_browser: all checks passed.");
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
