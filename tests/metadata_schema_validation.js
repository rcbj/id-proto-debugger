// File: metadata_schema_validation.js
//
// ---------------------------------------------------------------------------
// The metadata schema check on sd-jwt-vc-issuance-1.html, for both panes.
//
// Two layers, because they can fail independently and a single layer would let
// one of them rot unnoticed:
//
//   RULES    client/src/metadata_schema.js is loaded directly and fed documents.
//            No browser and no services, so this half never skips. Every rule
//            gets a case that BREAKS it and a case that satisfies it, which is
//            the part that matters: a validator that accepts everything passes
//            any test suite made only of valid documents.
//
//   WIRING   the page is driven, because a perfect validator nothing calls is
//            worth nothing. Populate Meta Data must run the check, and the
//            verdict must reach the pane.
//
// A note on what is being validated against. Neither specification publishes a
// machine-readable schema — OpenID4VCI 1.0 defines its metadata in prose and
// tables (section 12.2) and ships only examples; RFC 8414 does the same in
// section 2 with an IANA registry. So the module transcribes their normative
// rules, and these tests pin that transcription. Where a case below asserts an
// ERROR it is because the specification says MUST; where it asserts a WARNING
// the specification says SHOULD, RECOMMENDED, or nothing at all. Getting that
// split wrong in either direction is the failure this file is really guarding
// against: an error on a legal document teaches people to ignore the checker,
// and a warning on an illegal one is why the document reached production.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const path = require("path");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "metadata_schema_test",
                                level: appconfig.logLevel || "info" });

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 15000;

// NOTE the file name. This test is metadata_schema_VALIDATION.js, not
// metadata_schema.js, because the tests image copies client/src modules FLAT
// into the same directory as the test scripts — so a test named after the module
// it loads would be silently overwritten by that module (or overwrite it),
// depending on which COPY ran last.
var schema = paths.requireSharedModule(
  [path.join(__dirname, "metadata_schema.js"),
   path.join(__dirname, "..", "client", "src", "metadata_schema.js")],
  "the metadata schema module");

// --- documents that satisfy every rule --------------------------------------
// Deliberately https and complete, so any error at all is the validator's fault
// rather than the fixture's. The negatives below each break exactly one thing.
function validVci() {
  return {
    credential_issuer: "https://issuer.example.com",
    credential_endpoint: "https://issuer.example.com/oid4vci/credential",
    nonce_endpoint: "https://issuer.example.com/oid4vci/nonce",
    deferred_credential_endpoint: "https://issuer.example.com/oid4vci/deferred",
    notification_endpoint: "https://issuer.example.com/oid4vci/notification",
    authorization_servers: ["https://issuer.example.com"],
    batch_credential_issuance: { batch_size: 4 },
    credential_response_encryption: {
      alg_values_supported: ["RSA-OAEP-256"],
      enc_values_supported: ["A128GCM"],
      encryption_required: false
    },
    display: [{ name: "Example Issuer", locale: "en-US" }],
    credential_configurations_supported: {
      IdentityCredential: {
        format: "dc+sd-jwt",
        scope: "identity_credential",
        vct: "urn:example:identity",
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: ["ES256"],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ["ES256"] } },
        claims: [{ path: ["given_name"] }]
      },
      IdentityCredentialJwtVcJson: {
        format: "jwt_vc_json",
        scope: "identity_credential_jwt",
        credential_definition: { type: ["VerifiableCredential", "IdentityCredential"] },
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: ["ES256"],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ["ES256"] } }
      }
    }
  };
}

function validAs() {
  return {
    issuer: "https://as.example.com",
    authorization_endpoint: "https://as.example.com/authorize",
    token_endpoint: "https://as.example.com/token",
    jwks_uri: "https://as.example.com/jwks",
    scopes_supported: ["openid"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["client_secret_basic"],
    token_endpoint_auth_signing_alg_values_supported: ["RS256"],
    code_challenge_methods_supported: ["S256"],
    registration_endpoint: "https://as.example.com/register",
    revocation_endpoint: "https://as.example.com/revoke",
    introspection_endpoint: "https://as.example.com/introspect"
  };
}

function membersReported(result) {
  return result.errors.concat(result.warnings).map(function (x) { return x.member; });
}
function errorOn(result, member) {
  return result.errors.some(function (e) { return e.member === member; });
}
function warningOn(result, member) {
  return result.warnings.some(function (w) { return w.member === member; });
}

// --- the positive cases -----------------------------------------------------
function validDocumentsPass() {
  log.info("=== A document that satisfies the specification is reported clean ===");

  var vci = schema.validateVciMetadata(validVci());
  assert.strictEqual(vci.errors.length, 0,
    "a valid credential issuer metadata document should produce no errors. Got: " +
    JSON.stringify(vci.errors));
  assert.strictEqual(vci.warnings.length, 0,
    "and no warnings either — every member of this fixture is https and present, so a warning here " +
    "means the validator is complaining about something legal. Got: " + JSON.stringify(vci.warnings));

  var as = schema.validateAsMetadata(validAs());
  assert.strictEqual(as.errors.length, 0,
    "a valid RFC 8414 document should produce no errors. Got: " + JSON.stringify(as.errors));
  assert.strictEqual(as.warnings.length, 0,
    "and no warnings. Got: " + JSON.stringify(as.warnings));

  log.info("[positive] OK — both valid documents report 0 errors and 0 warnings.");
}

// A valid document is still valid with every OPTIONAL member removed. This is
// the case that catches a validator quietly promoting an optional member to
// required, which is the most common way one of these becomes wrong over time.
function minimalDocumentsPass() {
  log.info("=== The minimum each specification actually requires ===");

  var vci = schema.validateVciMetadata({
    credential_issuer: "https://issuer.example.com",
    credential_endpoint: "https://issuer.example.com/credential",
    credential_configurations_supported: {
      Only: { format: "dc+sd-jwt", vct: "urn:example:identity" }
    }
  });
  assert.strictEqual(vci.errors.length, 0,
    "credential_issuer, credential_endpoint and one credential configuration are all OpenID4VCI " +
    "requires. Got errors: " + JSON.stringify(vci.errors));

  var as = schema.validateAsMetadata({
    issuer: "https://as.example.com",
    authorization_endpoint: "https://as.example.com/authorize",
    token_endpoint: "https://as.example.com/token",
    jwks_uri: "https://as.example.com/jwks",
    scopes_supported: ["openid"],
    response_types_supported: ["code"]
  });
  assert.strictEqual(as.errors.length, 0,
    "issuer and response_types_supported are what RFC 8414 requires outright. Got errors: " +
    JSON.stringify(as.errors));

  log.info("[positive] OK — minimal documents are accepted; nothing optional has been made mandatory.");
}

// --- the negative cases -----------------------------------------------------
// Table-driven: each case takes a valid document, breaks ONE thing, and names
// the member that must be reported and whether it is an error or a warning.
var VCI_NEGATIVES = [
  { what: "credential_issuer missing",
    member: "credential_issuer", kind: "error",
    break: function (d) { delete d.credential_issuer; } },
  { what: "credential_issuer not a URL",
    member: "credential_issuer", kind: "error",
    break: function (d) { d.credential_issuer = "not a url"; } },
  { what: "credential_endpoint missing",
    member: "credential_endpoint", kind: "error",
    break: function (d) { delete d.credential_endpoint; } },
  { what: "credential_configurations_supported missing",
    member: "credential_configurations_supported", kind: "error",
    break: function (d) { delete d.credential_configurations_supported; } },
  { what: "credential_configurations_supported empty",
    member: "credential_configurations_supported", kind: "error",
    break: function (d) { d.credential_configurations_supported = {}; } },
  { what: "credential_configurations_supported an array",
    member: "credential_configurations_supported", kind: "error",
    break: function (d) { d.credential_configurations_supported = []; } },
  { what: "a configuration with no format",
    member: 'credential_configurations_supported["IdentityCredential"].format', kind: "error",
    break: function (d) { delete d.credential_configurations_supported.IdentityCredential.format; } },
  { what: "an SD-JWT VC configuration with no vct",
    member: 'credential_configurations_supported["IdentityCredential"].vct', kind: "error",
    break: function (d) { delete d.credential_configurations_supported.IdentityCredential.vct; } },
  { what: "a jwt_vc_json configuration with no credential_definition",
    member: 'credential_configurations_supported["IdentityCredentialJwtVcJson"].credential_definition',
    kind: "error",
    break: function (d) {
      delete d.credential_configurations_supported.IdentityCredentialJwtVcJson.credential_definition;
    } },
  { what: "a jwt_vc_json configuration whose credential_definition has no type",
    member: 'credential_configurations_supported["IdentityCredentialJwtVcJson"].credential_definition.type',
    kind: "error",
    break: function (d) {
      d.credential_configurations_supported.IdentityCredentialJwtVcJson.credential_definition = {};
    } },
  // The two formats naming each other's identifier: legal JSON, wrong document.
  { what: "an SD-JWT VC configuration carrying credential_definition",
    member: 'credential_configurations_supported["IdentityCredential"].credential_definition',
    kind: "warning",
    break: function (d) {
      d.credential_configurations_supported.IdentityCredential.credential_definition =
        { type: ["VerifiableCredential"] };
    } },
  { what: "a jwt_vc_json configuration carrying a vct",
    member: 'credential_configurations_supported["IdentityCredentialJwtVcJson"].vct', kind: "warning",
    break: function (d) {
      d.credential_configurations_supported.IdentityCredentialJwtVcJson.vct = "urn:example:identity";
    } },
  { what: "an mso_mdoc configuration with no doctype",
    member: 'credential_configurations_supported["Mdl"].doctype', kind: "error",
    break: function (d) { d.credential_configurations_supported.Mdl = { format: "mso_mdoc" }; } },
  { what: "an unknown format",
    member: 'credential_configurations_supported["Odd"].format', kind: "warning",
    break: function (d) { d.credential_configurations_supported.Odd = { format: "made_up_format" }; } },
  { what: "proof_types_supported with no algorithms",
    member: 'credential_configurations_supported["IdentityCredential"].proof_types_supported.jwt' +
            ".proof_signing_alg_values_supported", kind: "error",
    break: function (d) {
      d.credential_configurations_supported.IdentityCredential.proof_types_supported = { jwt: {} };
    } },
  { what: "authorization_servers not an array",
    member: "authorization_servers", kind: "error",
    break: function (d) { d.authorization_servers = "https://as.example.com"; } },
  { what: "batch_credential_issuance.batch_size zero",
    member: "batch_credential_issuance.batch_size", kind: "error",
    break: function (d) { d.batch_credential_issuance = { batch_size: 0 }; } },
  { what: "credential_response_encryption missing encryption_required",
    member: "credential_response_encryption.encryption_required", kind: "error",
    break: function (d) { delete d.credential_response_encryption.encryption_required; } },
  { what: "credential_response_encryption missing alg_values_supported",
    member: "alg_values_supported", kind: "error",
    break: function (d) { delete d.credential_response_encryption.alg_values_supported; } },
  { what: "claims as an object (the pre-1.0 shape)",
    member: 'credential_configurations_supported["IdentityCredential"].claims', kind: "error",
    break: function (d) {
      d.credential_configurations_supported.IdentityCredential.claims = { given_name: {} };
    } },
  { what: "signed_metadata that is not a compact JWS",
    member: "signed_metadata", kind: "error",
    break: function (d) { d.signed_metadata = "not.a-jws"; } },
  { what: "a plain http endpoint",
    member: null, kind: "warning",   // folded into one line naming every http member
    break: function (d) { d.credential_endpoint = "http://issuer.example.com/credential"; } }
];

var AS_NEGATIVES = [
  { what: "issuer missing", member: "issuer", kind: "error",
    break: function (d) { delete d.issuer; } },
  { what: "issuer with a query string", member: "issuer", kind: "error",
    break: function (d) { d.issuer = "https://as.example.com/?tenant=1"; } },
  { what: "issuer with a fragment", member: "issuer", kind: "error",
    break: function (d) { d.issuer = "https://as.example.com/#here"; } },
  { what: "response_types_supported missing", member: "response_types_supported", kind: "error",
    break: function (d) { delete d.response_types_supported; } },
  { what: "response_types_supported not an array", member: "response_types_supported", kind: "error",
    break: function (d) { d.response_types_supported = "code"; } },
  { what: "response_types_supported empty", member: "response_types_supported", kind: "error",
    break: function (d) { d.response_types_supported = []; } },
  { what: "grant_types_supported not an array", member: "grant_types_supported", kind: "error",
    break: function (d) { d.grant_types_supported = "authorization_code"; } },
  { what: 'token_endpoint_auth_signing_alg_values_supported including "none"',
    member: "token_endpoint_auth_signing_alg_values_supported", kind: "error",
    break: function (d) { d.token_endpoint_auth_signing_alg_values_supported = ["RS256", "none"]; } },
  { what: "a malformed endpoint URL", member: "token_endpoint", kind: "error",
    break: function (d) { d.token_endpoint = ":::not a url:::"; } },
  { what: "signed_metadata that is not a compact JWS", member: "signed_metadata", kind: "error",
    break: function (d) { d.signed_metadata = "two.parts"; } },
  // Absences the RFC allows but a reader should be told about.
  { what: "authorization_endpoint absent", member: "authorization_endpoint", kind: "warning",
    break: function (d) { delete d.authorization_endpoint; } },
  { what: "token_endpoint absent", member: "token_endpoint", kind: "warning",
    break: function (d) { delete d.token_endpoint; } },
  { what: "jwks_uri absent", member: "jwks_uri", kind: "warning",
    break: function (d) { delete d.jwks_uri; } },
  { what: "scopes_supported absent", member: "scopes_supported", kind: "warning",
    break: function (d) { delete d.scopes_supported; } }
];

function runNegatives(label, makeValid, validate, cases) {
  log.info("=== " + label + ": each rule, broken on purpose ===");
  cases.forEach(function (c) {
    var doc = makeValid();
    c.break(doc);
    var result = validate(doc);
    if (c.kind === "error") {
      assert.ok(result.errors.length > 0,
        label + " / " + c.what + ": should be reported as an ERROR and was not. Reported: " +
        JSON.stringify(membersReported(result)));
      if (c.member) {
        assert.ok(errorOn(result, c.member),
          label + " / " + c.what + ': the error should name "' + c.member + '". Reported: ' +
          JSON.stringify(result.errors));
      }
    } else {
      assert.ok(result.warnings.length > 0,
        label + " / " + c.what + ": should be reported as a WARNING and was not. Reported: " +
        JSON.stringify(membersReported(result)));
      assert.strictEqual(result.errors.length, 0,
        label + " / " + c.what + ": the specification permits this, so it must NOT be an error — " +
        "calling a legal document invalid is how a checker gets ignored. Reported: " +
        JSON.stringify(result.errors));
      if (c.member) {
        assert.ok(warningOn(result, c.member),
          label + " / " + c.what + ': the warning should name "' + c.member + '". Reported: ' +
          JSON.stringify(result.warnings));
      }
    }
  });
  log.info("[negative] OK — " + cases.length + " " + label + " rule(s), each caught, each with the " +
           "severity the specification implies.");
}

// A non-object is not a document at all, whichever pane it reached.
function nonObjectsAreRejected() {
  log.info("=== Something that is not a JSON object ===");
  [null, "a string", 42, [1, 2], undefined].forEach(function (v) {
    ["validateVciMetadata", "validateAsMetadata"].forEach(function (fn) {
      var r = schema[fn](v);
      assert.ok(r.errors.length > 0,
        fn + " should refuse " + JSON.stringify(v) + " outright.");
    });
  });
  log.info("[negative] OK — non-objects are refused by both validators.");
}

// The http warning is FOLDED into one line. Asserted because the first version
// emitted one per member — ten warnings on a perfectly good local document,
// which is how a reader learns to skip them.
function plainHttpIsOneWarning() {
  log.info("=== Plain http is reported once, not once per member ===");
  var doc = validAs();
  ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
   "registration_endpoint", "revocation_endpoint", "introspection_endpoint"].forEach(function (m) {
    doc[m] = String(doc[m]).replace("https://", "http://");
  });
  var r = schema.validateAsMetadata(doc);
  var httpWarnings = r.warnings.filter(function (w) { return /http:\/\//.test(w.message); });
  assert.strictEqual(httpWarnings.length, 1,
    "seven plain-http members should produce ONE warning naming them all, not one each. Got " +
    httpWarnings.length + ": " + JSON.stringify(r.warnings.map(function (w) { return w.member; })));
  assert.ok(/issuer/.test(httpWarnings[0].message) && /token_endpoint/.test(httpWarnings[0].message),
    "and that one warning should name the members. Said: " + httpWarnings[0].message);
  assert.strictEqual(r.errors.length, 0,
    "plain http is not an error — every local deployment this tool is used against serves it.");
  log.info("[negative] OK — 7 http members produce exactly 1 warning, and no error.");
}

// Every finding cites where the rule comes from, so a disagreement is settled by
// reading the specification rather than this code.
function everyFindingCitesTheSpec() {
  log.info("=== Every finding cites a specification section ===");
  var doc = validVci();
  delete doc.credential_endpoint;
  doc.credential_configurations_supported.Odd = { format: "made_up_format" };
  var r = schema.validateVciMetadata(doc);
  r.errors.concat(r.warnings).forEach(function (f) {
    assert.ok(f.cite && String(f.cite).trim() !== "",
      'the finding on "' + f.member + '" carries no citation.');
  });
  log.info("[cite] OK — all " + (r.errors.length + r.warnings.length) + " findings cite a section.");
}

// --- the wiring -------------------------------------------------------------
async function populateRunsTheCheck() {
  log.info("=== Populate Meta Data runs the check and shows it ===");
  const { Builder, By, until } = require("selenium-webdriver");
  const chrome = require("selenium-webdriver/chrome");
  const browserFlags = require("./browser_flags.js");

  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage", "--window-size=1500,1400");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();
  try {
    var plant = async function (vci, as) {
      await driver.get(baseUrl + "/sd-jwt-vc-issuance-1.html");
      await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")), waitTime);
      await driver.executeScript(
        "window.localStorage.clear();" +
        "localStorage.setItem('vci_info', arguments[0]);" +
        "localStorage.setItem('discovery_info', arguments[1]);",
        JSON.stringify(vci), JSON.stringify(as));
      await driver.navigate().refresh();
      await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")), waitTime);
      await driver.sleep(700);
    };
    var clickPopulate = async function (buttonId, reportId) {
      await driver.executeScript(
        "var b = document.getElementById(arguments[0]); if (b) b.click();", buttonId);
      await driver.sleep(700);
      return await driver.executeScript(
        "var host = document.getElementById(arguments[0]);" +
        "if (!host) return null;" +
        "var head = host.querySelector('p');" +
        "return { text: head ? head.textContent.trim() : ''," +
        "         rows: host.querySelectorAll('tbody tr').length," +
        "         errors: host.querySelectorAll('td.vc-bad').length };", reportId);
    };

    // A clean document: the pane should say so, with no findings listed.
    await plant(validVci(), validAs());
    var okVci = await clickPopulate("vci_populate_button", "vci_schema_report");
    assert.ok(okVci, "the credential issuer pane should have a schema report element.");
    assert.strictEqual(okVci.rows, 0,
      "a valid document should list no findings. The pane said: " + okVci.text);
    assert.ok(/satisfies every rule/.test(okVci.text),
      "and should say the document is clean. Said: " + okVci.text);

    var okAs = await clickPopulate("as_populate_button", "as_schema_report");
    assert.ok(okAs, "the authorization server pane should have a schema report element.");
    assert.strictEqual(okAs.rows, 0,
      "a valid RFC 8414 document should list no findings. The pane said: " + okAs.text);

    // A broken pair: the findings must reach the pane, and the pane must still
    // have populated — this is a debugger, not a gate.
    var badVci = validVci();
    delete badVci.credential_endpoint;
    delete badVci.credential_configurations_supported.IdentityCredential.vct;
    var badAs = validAs();
    delete badAs.response_types_supported;
    badAs.issuer = "https://as.example.com/?tenant=1";

    await plant(badVci, badAs);
    var failVci = await clickPopulate("vci_populate_button", "vci_schema_report");
    assert.ok(failVci.errors >= 2,
      "two broken MUSTs should show as two errors in the pane. Got " + failVci.errors +
      ": " + failVci.text);
    assert.ok(/error/i.test(failVci.text),
      "and the summary should say so. Said: " + failVci.text);

    var failAs = await clickPopulate("as_populate_button", "as_schema_report");
    assert.ok(failAs.errors >= 2,
      "the RFC 8414 pane should show its two errors. Got " + failAs.errors + ": " + failAs.text);

    // Populated regardless. The authorization_endpoint of the broken AS document
    // is still valid, so it should have reached the field.
    var populated = await driver.executeScript(
      "var e = document.getElementById('authorization_endpoint'); return e ? e.value : '';");
    assert.strictEqual(populated, badAs.authorization_endpoint,
      "an out-of-spec document must still populate: refusing would take away the one thing someone " +
      "debugging an out-of-spec server needs. Got: '" + populated + "'");

    log.info("[wiring] OK — Populate runs the check on both panes, shows the findings, and populates " +
             "either way.");
  } finally {
    await driver.quit();
  }
}

async function test() {
  validDocumentsPass();
  minimalDocumentsPass();
  runNegatives("OpenID4VCI", validVci, schema.validateVciMetadata, VCI_NEGATIVES);
  runNegatives("RFC 8414", validAs, schema.validateAsMetadata, AS_NEGATIVES);
  nonObjectsAreRejected();
  plainHttpIsOneWarning();
  everyFindingCitesTheSpec();
  await populateRunsTheCheck();
  log.info("Test completed successfully.");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "base url of the debugger under test"));
program.addOption(new Option("-h, --headless <headless>", "run headless (true/false)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) { baseUrl = opts.url; log.info("Setting url to " + baseUrl); }
if (opts.headless === "false") { headless = false; }

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
