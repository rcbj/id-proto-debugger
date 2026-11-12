// File: rp_metadata_choices.js
//
// ---------------------------------------------------------------------------
// OpenID Connect RP Metadata Choices 1.0, driven in node with no browser
// and no network. The rules under test are the relying party's:
//
//   * a section 4 request is clean when the partner sits inside the array
//     and every value is one this client can use
//   * a partner outside its array fails checkRequest
//   * applyChoices writes pairs with that property and omits the members
//     whose supported set is empty
//   * a response that returns a different offered partner and no arrays
//     adopts that partner
//   * a response that returns the arrays adopts the partner and records
//     section 2
//   * a returned partner outside the offered array is not adopted
//   * revocation_endpoint_auth_methods_supported is the section 3 finding
//
// A provider's behaviour is not an input and not a pass condition.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`. This job parses no arguments, so
// node ignores that pair. Do not add commander here without declaring
// `--url`.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "rp_metadata_choices",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

const REPO = path.resolve(__dirname, "..");
const SRC = path.join(REPO, "client", "src");
const PUBLIC = path.join(REPO, "client", "public");
const paths = require("./module_paths.js");
const choices = paths.requireSharedModule(
    [path.join(SRC, "rp_metadata_choices.js")],
    "client/src/rp_metadata_choices.js");
const jws = paths.requireSharedModule(
    [path.join(SRC, "jws.js")], "client/src/jws.js");
const jose = paths.requireSharedModule(
    [path.join(SRC, "jose_jwe.js")], "client/src/jose_jwe.js");

// The thirteen members this client omits. They stay in the catalogue.
const OMITTED = [
  "id_token_encryption_alg_values_supported",
  "id_token_encryption_enc_values_supported",
  "request_object_signing_alg_values_supported",
  "request_object_encryption_alg_values_supported",
  "request_object_encryption_enc_values_supported",
  "token_endpoint_auth_signing_alg_values_supported",
  "backchannel_authentication_request_signing_alg_values_supported",
  "authorization_signing_alg_values_supported",
  "authorization_encryption_alg_values_supported",
  "authorization_encryption_enc_values_supported",
  "introspection_signing_alg_values_supported",
  "introspection_encryption_alg_values_supported",
  "introspection_encryption_enc_values_supported"
];

function rules(findings) {
  log.debug("Entering rules().");
  log.debug("Leaving rules().");
  return findings.map(function (f) { return f.rule; });
}

function hasRule(findings, rule) {
  log.debug("Entering hasRule().");
  log.debug("Leaving hasRule().");
  return findings.some(function (f) { return f.rule === rule; });
}

function headerAlgsExceptNone() {
  log.debug("Entering headerAlgsExceptNone().");
  var seen = {};
  var values = [];
  jws.algIds().forEach(function (id) {
    var spec = jws.algSpec(id);
    if (!spec || spec.alg === "none" || spec.family === "none") {
      return;
    }
    if (seen[spec.alg]) {
      return;
    }
    seen[spec.alg] = true;
    values.push(spec.alg);
  });
  log.debug("Leaving headerAlgsExceptNone().");
  return values;
}

function rowNamed(name) {
  log.debug("Entering rowNamed().");
  var rows = choices.supportedChoices();
  var i;
  for (i = 0; i < rows.length; i++) {
    if (rows[i].choice === name) {
      log.debug("Leaving rowNamed().");
      return rows[i];
    }
  }
  log.debug("Leaving rowNamed(). Missing.");
  return null;
}

function section4ExampleIsClean() {
  log.debug("Entering section4ExampleIsClean().");
  var example = {
    id_token_signing_alg_values_supported: ["ES256", "PS256", "RS256"],
    id_token_signed_response_alg: "RS256"
  };
  assert.ok(example.id_token_signing_alg_values_supported
      .indexOf(example.id_token_signed_response_alg) >= 0,
      "The section 4 partner is not inside its array.");
  assert.deepStrictEqual(choices.checkRequest(example), [],
      "The section 4 example is a clean request.");
  log.info("OK — the section 4 example is clean and the partner is " +
      "inside the array.");
  log.debug("Leaving section4ExampleIsClean().");
}

function partnerOutsideItsArrayFails() {
  log.debug("Entering partnerOutsideItsArrayFails().");
  var metadata = {
    id_token_signing_alg_values_supported: ["ES256", "PS256", "RS256"],
    id_token_signed_response_alg: "HS256"
  };
  var findings = choices.checkRequest(metadata);
  assert.ok(hasRule(findings, "partner-not-in-list"),
      "A partner outside its array was accepted: " +
      JSON.stringify(findings));
  assert.ok(!hasRule(findings, "outside-supported-set"),
      "HS256 is a value this client can use. The failure is that it " +
      "is not in the offered array.");
  log.info("OK — a partner outside its array fails checkRequest.");
  log.debug("Leaving partnerOutsideItsArrayFails().");
}

function applyChoicesWritesUsablePairs() {
  log.debug("Entering applyChoicesWritesUsablePairs().");
  var input = {
    client_name: "OAuth2 OIDC Debugger Client",
    scope: "openid profile email",
    redirect_uris: ["https://client.example.org/callback"],
    revocation_endpoint_auth_methods_supported: ["client_secret_basic"]
  };
  var before = JSON.stringify(input);
  var doc = choices.applyChoices(input);
  var supported = choices.supportedChoices();
  var signing = headerAlgsExceptNone();
  var userinfoSigning = signing.slice();
  var i;
  assert.strictEqual(JSON.stringify(input), before,
      "applyChoices mutated its input.");
  assert.strictEqual(doc.client_name, input.client_name);
  assert.strictEqual(doc.scope, input.scope);
  assert.strictEqual(supported.length, 6);
  assert.strictEqual(choices.CHOICES.length, 19);
  for (i = 0; i < supported.length; i++) {
    assert.ok(supported[i].values.indexOf(supported[i].preferred) >= 0,
        supported[i].partner + " is not inside " + supported[i].choice);
    assert.deepStrictEqual(doc[supported[i].choice], supported[i].values);
    assert.strictEqual(doc[supported[i].partner], supported[i].preferred);
  }
  userinfoSigning.push("none");
  assert.deepStrictEqual(rowNamed(
      "id_token_signing_alg_values_supported").values, signing);
  assert.deepStrictEqual(rowNamed(
      "userinfo_signing_alg_values_supported").values, userinfoSigning);
  assert.strictEqual(rowNamed(
      "userinfo_signing_alg_values_supported").preferred, "RS256");
  assert.deepStrictEqual(rowNamed(
      "userinfo_encryption_alg_values_supported").values,
      jose.supportedAlgs());
  assert.strictEqual(rowNamed(
      "userinfo_encryption_alg_values_supported").preferred,
      "RSA-OAEP-256");
  assert.deepStrictEqual(rowNamed(
      "userinfo_encryption_enc_values_supported").values,
      jose.supportedEncs());
  assert.strictEqual(rowNamed(
      "userinfo_encryption_enc_values_supported").preferred,
      "A128CBC-HS256");
  assert.deepStrictEqual(rowNamed(
      "token_endpoint_auth_methods_supported").values,
      ["client_secret_basic"]);
  assert.deepStrictEqual(rowNamed("subject_types_supported").values,
      ["public", "pairwise"]);
  assert.deepStrictEqual(choices.omittedChoices(), OMITTED);
  for (i = 0; i < OMITTED.length; i++) {
    assert.ok(!Object.prototype.hasOwnProperty.call(doc, OMITTED[i]),
        OMITTED[i] + " was written.");
  }
  assert.ok(!Object.prototype.hasOwnProperty.call(doc,
      "revocation_endpoint_auth_methods_supported"));
  assert.ok(!Object.prototype.hasOwnProperty.call(doc,
      "sector_identifier_uri"),
      "One redirect URI does not require sector_identifier_uri.");
  assert.deepStrictEqual(choices.checkRequest(doc), [],
      "The generated request is not clean: " +
      JSON.stringify(choices.checkRequest(doc)));
  log.info("OK — applyChoices writes six pairs and omits the empty sets.");
  log.debug("Leaving applyChoicesWritesUsablePairs().");
}

function emptyAndForeignValuesAreFindings() {
  log.debug("Entering emptyAndForeignValuesAreFindings().");
  var empty = choices.checkRequest({ subject_types_supported: [] });
  var typed = choices.checkRequest({
    subject_types_supported: "public"
  });
  var item = choices.checkRequest({
    subject_types_supported: ["public", ""]
  });
  var foreign = choices.checkRequest({
    token_endpoint_auth_methods_supported: ["private_key_jwt"],
    token_endpoint_auth_method: "private_key_jwt"
  });
  var encryptedId = choices.checkRequest({
    id_token_encryption_alg_values_supported: ["RSA-OAEP-256"],
    id_token_encrypted_response_alg: "RSA-OAEP-256"
  });
  assert.deepStrictEqual(rules(empty), ["empty-array"]);
  assert.deepStrictEqual(rules(typed), ["not-array"]);
  assert.deepStrictEqual(rules(item), ["not-array"]);
  assert.ok(hasRule(foreign, "outside-supported-set"));
  assert.ok(!hasRule(foreign, "partner-not-in-list"));
  assert.ok(hasRule(encryptedId, "outside-supported-set"),
      "An ID Token encryption value was treated as usable.");
  log.info("OK — empty arrays, bad items and unusable values are " +
      "findings.");
  log.debug("Leaving emptyAndForeignValuesAreFindings().");
}

function section3NamesAreNotClientMetadata() {
  log.debug("Entering section3NamesAreNotClientMetadata().");
  var metadata = {
    revocation_endpoint_auth_methods_supported: ["client_secret_basic"],
    introspection_endpoint_auth_methods_supported: ["client_secret_basic"]
  };
  var findings = choices.checkRequest(metadata);
  assert.deepStrictEqual(rules(findings), ["section-3", "section-3"]);
  assert.strictEqual(findings[0].member,
      "revocation_endpoint_auth_methods_supported");
  assert.strictEqual(findings[1].member,
      "introspection_endpoint_auth_methods_supported");
  var applied = choices.applyChoices(metadata);
  assert.ok(!Object.prototype.hasOwnProperty.call(applied,
      "revocation_endpoint_auth_methods_supported"));
  assert.ok(!Object.prototype.hasOwnProperty.call(applied,
      "introspection_endpoint_auth_methods_supported"));
  assert.deepStrictEqual(JSON.parse(JSON.stringify(metadata))
      .revocation_endpoint_auth_methods_supported,
      ["client_secret_basic"]);
  log.info("OK — section 3 auth-method names are findings and are " +
      "removed from a generated request.");
  log.debug("Leaving section3NamesAreNotClientMetadata().");
}

function sectorIdentifierFollowsTheRedirectCount() {
  log.debug("Entering sectorIdentifierFollowsTheRedirectCount().");
  var one = choices.applyChoices({
    redirect_uris: ["https://client.example.org/callback"]
  });
  var two = choices.applyChoices({
    redirect_uris: [
      "https://client.example.org/callback",
      "https://client.example.org/callback2"
    ]
  });
  var kept = choices.applyChoices({
    redirect_uris: ["https://a.example/cb", "https://b.example/cb"],
    sector_identifier_uri: "https://rp.example/sector.json"
  });
  var blank = choices.applyChoices({
    redirect_uris: ["https://a.example/cb", "https://b.example/cb"],
    sector_identifier_uri: "   "
  });
  var bare = {
    redirect_uris: ["https://a.example/cb", "https://b.example/cb"],
    subject_types_supported: ["public", "pairwise"],
    subject_type: "public"
  };
  var single = {
    redirect_uris: ["https://a.example/cb"],
    subject_types_supported: ["public", "pairwise"],
    subject_type: "public"
  };
  assert.ok(!Object.prototype.hasOwnProperty.call(one,
      "sector_identifier_uri"));
  assert.strictEqual(two.sector_identifier_uri,
      choices.SECTOR_IDENTIFIER_URI);
  assert.strictEqual(kept.sector_identifier_uri,
      "https://rp.example/sector.json");
  assert.strictEqual(blank.sector_identifier_uri,
      choices.SECTOR_IDENTIFIER_URI);
  assert.ok(hasRule(choices.checkRequest(bare),
      "sector-identifier-required"));
  assert.ok(!hasRule(choices.checkRequest(single),
      "sector-identifier-required"));
  assert.deepStrictEqual(choices.checkRequest(two), []);
  log.info("OK — sector_identifier_uri follows the redirect count.");
  log.debug("Leaving sectorIdentifierFollowsTheRedirectCount().");
}

function differentOfferedPartnerIsAdopted() {
  log.debug("Entering differentOfferedPartnerIsAdopted().");
  var sent = {
    client_name: "n",
    id_token_signing_alg_values_supported: ["ES256", "PS256", "RS256"],
    id_token_signed_response_alg: "RS256"
  };
  var received = {
    client_id: "abc",
    client_secret: "sek",
    client_name: "n",
    id_token_signed_response_alg: "ES256"
  };
  var sentBefore = JSON.stringify(sent);
  var receivedBefore = JSON.stringify(received);
  var result = choices.readResponse(sent, received);
  assert.strictEqual(JSON.stringify(sent), sentBefore);
  assert.strictEqual(JSON.stringify(received), receivedBefore);
  assert.strictEqual(result.metadata.client_id, "abc");
  assert.strictEqual(result.metadata.client_secret, "sek");
  assert.strictEqual(result.metadata.id_token_signed_response_alg,
      "ES256");
  assert.deepStrictEqual(
      result.metadata.id_token_signing_alg_values_supported,
      ["ES256", "PS256", "RS256"]);
  assert.ok(!hasRule(result.findings, "section-2-output"));
  assert.ok(!hasRule(result.findings, "partner-outside-offered"));
  assert.strictEqual(result.rows.length, 1);
  assert.strictEqual(result.rows[0].adopted, "ES256");
  assert.strictEqual(result.rows[0].preferred, "RS256");
  assert.strictEqual(result.rows[0].returned, "ES256");
  log.info("OK — a different offered partner is adopted and the " +
      "array stays.");
  log.debug("Leaving differentOfferedPartnerIsAdopted().");
}

function echoedArraysAreNotAdopted() {
  log.debug("Entering echoedArraysAreNotAdopted().");
  var sent = {
    id_token_signing_alg_values_supported: ["ES256", "PS256", "RS256"],
    id_token_signed_response_alg: "RS256"
  };
  var received = {
    client_id: "abc",
    id_token_signing_alg_values_supported: ["RS256"],
    id_token_signed_response_alg: "RS256"
  };
  var result = choices.readResponse(sent, received);
  assert.ok(hasRule(result.findings, "section-2-output"));
  assert.strictEqual(result.findings[0].member,
      "id_token_signing_alg_values_supported");
  assert.strictEqual(result.metadata.client_id, "abc");
  assert.strictEqual(result.metadata.id_token_signed_response_alg,
      "RS256");
  assert.deepStrictEqual(
      result.metadata.id_token_signing_alg_values_supported,
      ["ES256", "PS256", "RS256"]);
  log.info("OK — an echoed choice array is a section 2 finding and " +
      "the sent array is what the next request keeps.");
  log.debug("Leaving echoedArraysAreNotAdopted().");
}

function partnerOutsideTheOfferIsNotAdopted() {
  log.debug("Entering partnerOutsideTheOfferIsNotAdopted().");
  var sent = {
    id_token_signing_alg_values_supported: ["ES256", "PS256", "RS256"],
    id_token_signed_response_alg: "RS256"
  };
  var received = {
    client_id: "abc",
    id_token_signed_response_alg: "none"
  };
  var result = choices.readResponse(sent, received);
  assert.ok(hasRule(result.findings, "partner-outside-offered"));
  assert.strictEqual(result.metadata.id_token_signed_response_alg,
      "RS256");
  assert.strictEqual(result.metadata.client_id, "abc");
  assert.strictEqual(result.rows[0].adopted, "RS256");
  assert.strictEqual(result.rows[0].returned, "none");
  log.info("OK — a partner outside the offered array is not adopted.");
  log.debug("Leaving partnerOutsideTheOfferIsNotAdopted().");
}

function omittedPartnerIsRestored() {
  log.debug("Entering omittedPartnerIsRestored().");
  var sent = {
    userinfo_signed_response_alg: "RS256",
    userinfo_signing_alg_values_supported: ["RS256", "none"]
  };
  var received = { client_id: "abc", client_name: "kept" };
  var result = choices.readResponse(sent, received);
  assert.strictEqual(result.metadata.client_id, "abc");
  assert.strictEqual(result.metadata.client_name, "kept");
  assert.strictEqual(result.metadata.userinfo_signed_response_alg,
      "RS256");
  assert.deepStrictEqual(
      result.metadata.userinfo_signing_alg_values_supported,
      ["RS256", "none"]);
  assert.strictEqual(result.rows[0].returned, null);
  assert.deepStrictEqual(result.findings, []);
  log.info("OK — a response that omits the partner keeps the sent one.");
  log.debug("Leaving omittedPartnerIsRestored().");
}

function codeLines(source) {
  log.debug("Entering codeLines().");
  log.debug("Leaving codeLines().");
  return source.replace(/\/\*[\s\S]*?\*\//g, "")
      .split("\n").filter(function (line) {
        return !/^\s*\/\//.test(line);
      }).join("\n");
}

function theEngineReachesNoDom() {
  log.debug("Entering theEngineReachesNoDom().");
  var source = fs.readFileSync(
      path.join(SRC, "rp_metadata_choices.js"), "utf8");
  var code = codeLines(source);
  var forbidden = ["document", "window", "localStorage", "sessionStorage",
      "jQuery", "DOMPurify", "innerHTML"];
  var i;
  for (i = 0; i < forbidden.length; i++) {
    assert.ok(code.indexOf(forbidden[i]) < 0,
        "client/src/rp_metadata_choices.js reaches " + forbidden[i]);
  }
  log.info("OK — the engine reaches no DOM.");
  log.debug("Leaving theEngineReachesNoDom().");
}

function thePaneCallsTheEngine() {
  log.debug("Entering thePaneCallsTheEngine().");
  var page = fs.readFileSync(
      path.join(SRC, "oauth2_oidc_1.js"), "utf8");
  var html = fs.readFileSync(
      path.join(PUBLIC, "oauth2_oidc_1.html"), "utf8");
  assert.ok(page.indexOf('require("./rp_metadata_choices")') >= 0,
      "The registration page does not load the choices engine.");
  assert.ok(page.indexOf("applyRpMetadataChoices") >= 0,
      "The registration page does not export the Apply handler.");
  assert.ok(html.indexOf("Apply RP metadata choices") >= 0,
      "The registration pane has no Apply button.");
  assert.ok(html.indexOf("dcr_choices_verdict") >= 0,
      "The registration pane has no choices verdict.");
  assert.ok(html.indexOf("dcr_choices_result") >= 0,
      "The registration pane has no choices result.");
  assert.ok(page.indexOf("discoveryInfo.subject_types_supported") < 0,
      "subject_type is still taken from the provider's discovery.");
  assert.ok(page.indexOf(
      "discoveryInfo.token_endpoint_auth_methods_supported") < 0,
      "token_endpoint_auth_method is still taken from discovery.");
  assert.ok(page.indexOf(
      "discoveryInfo.id_token_signing_alg_values_supported") < 0,
      "id_token_signed_response_alg is still taken from discovery.");
  assert.ok(page.indexOf("discoveryInfo.scopes_supported") >= 0,
      "Scope is no longer taken from discovery.");
  log.info("OK — the pane calls the engine and the three partners " +
      "no longer follow discovery.");
  log.debug("Leaving thePaneCallsTheEngine().");
}

function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  section4ExampleIsClean();
  partnerOutsideItsArrayFails();
  applyChoicesWritesUsablePairs();
  emptyAndForeignValuesAreFindings();
  section3NamesAreNotClientMetadata();
  sectorIdentifierFollowsTheRedirectCount();
  differentOfferedPartnerIsAdopted();
  echoedArraysAreNotAdopted();
  partnerOutsideTheOfferIsNotAdopted();
  omittedPartnerIsRestored();
  theEngineReachesNoDom();
  thePaneCallsTheEngine();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

try {
  test();
} catch (e) {
  log.error(e.message);
  process.exit(1);
}
