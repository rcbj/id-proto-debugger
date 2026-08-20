// File: oauth2_metadata_rfc8414.js
//
// RFC 8414 (OAuth 2.0 Authorization Server Metadata) support, end to end:
//
//   Part 1 (no browser) — the metadata endpoint the STS mock serves at
//     /.well-known/oauth-authorization-server: every member RFC 8414 section 2
//     defines is present and populated, the issuer tracks the host the request
//     arrived on, signed_metadata is a real JWT that verifies against the STS
//     certificate and matches the document, the advertised jwks_uri resolves,
//     the section 3.1 issuer-with-path form answers, and CORS is open (the
//     debugger fetches it from the browser).
//
//   Part 2 (browser) — the Metadata Source radio on oauth2_oidc_1.html: OIDC
//     Discovery vs RFC 8414, the well-known suffix / hint / spec link swap,
//     retrieving the RFC 8414 document populates the Configuration Parameters
//     pane, members RFC 8414 does not define show the -->not defined<-- note,
//     the Validate Signature button verifies signed_metadata against the
//     document's jwks_uri (and rejects a tampered one), the table is labelled
//     with the metadata type and the URL it came from, the choice and the
//     document survive a reload, and Clear resets both.
//
// The STS mock is located from WSTRUST_STS_URL (as the other STS-backed tests
// are); OAUTH_METADATA_URL overrides the metadata URL outright.

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const logging = require("selenium-webdriver/lib/logging");
const assert = require("assert");
const http = require("http");
const https = require("https");
const jwt = require("jsonwebtoken");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_metadata_rfc8414',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
// The dummy URL the OIDC source offers when nothing is configured —
// METADATA_SOURCES.oidc.defaultUrl in client/src/oauth2_oidc_1.js. Its presence
// after selecting RFC 8414 is how this test tells "this deployment configures
// no RFC 8414 default" apart from "the selector failed to offer the one it
// has".
var OIDC_DUMMY_DEFAULT = "https://localhost/oidc/.well-known";

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
var fetchWait = Math.max(waitTime, 15000);

// The STS mock serves WS-Trust at <base>/sts and the metadata at the well-known
// path off the same base.
var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var stsBase = stsUrl.replace(/\/sts\/?$/, "");
var metadataUrl = process.env.OAUTH_METADATA_URL || (stsBase +
    "/.well-known/oauth-authorization-server");

// Every member RFC 8414 section 2 defines.
const RFC8414_MEMBERS = [
  "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
      "registration_endpoint",
  "scopes_supported", "response_types_supported", "response_modes_supported",
  "grant_types_supported", "token_endpoint_auth_methods_supported",
  "token_endpoint_auth_signing_alg_values_supported", "service_documentation",
  "ui_locales_supported", "op_policy_uri", "op_tos_uri", "revocation_endpoint",
  "revocation_endpoint_auth_methods_supported",
      "revocation_endpoint_auth_signing_alg_values_supported",
  "introspection_endpoint", "introspection_endpoint_auth_methods_supported",
  "introspection_endpoint_auth_signing_alg_values_supported",
      "code_challenge_methods_supported",
  "signed_metadata",
];

// Members OIDC Discovery defines that RFC 8414 does not: they must end up
// showing the "not defined" note rather than a stale or blank value.
const OIDC_ONLY_FIELDS = ["oidc_userinfo_endpoint", "claims_supported",
    "subject_types_supported",
                          "id_token_signing_alg_values_supported",
                              "acr_values_supported"];
// Members RFC 8414 defines that OpenID Connect Discovery 1.0 does not. The
// Configuration Parameters pane carries a field for each, so an RFC 8414
// document populates them like any other member — and an OIDC document leaves
// them showing the "not defined" note.
const RFC8414_ONLY_FIELDS = [
  "revocation_endpoint_auth_methods_supported",
  "revocation_endpoint_auth_signing_alg_values_supported",
  "introspection_endpoint_auth_methods_supported",
  "introspection_endpoint_auth_signing_alg_values_supported",
  "code_challenge_methods_supported",
  "signed_metadata",
];
const NOT_DEFINED_NOTE = "-->not defined<--";

// ===========================================================================
// Part 1 — the endpoint itself
// ===========================================================================
function get(url, headers) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return new Promise(function (resolve, reject) {
    var mod = url.indexOf("https:") === 0 ? https : http;
    var req = mod.get(url, { headers: headers || {} }, function (res) {
      var body = "";
      res.on("data", function (c) { body += c; });
      res.on("end", function () { resolve({ status: res.statusCode,
             headers: res.headers, body: body }); });
    });
    req.on("error", reject);
    req.setTimeout(fetchWait,
                   function () { req.destroy(new Error("timed out fetching " +
                   url)); });
  });
}

async function testMetadataDocument() {
  log.debug("Entering testMetadataDocument().");
  log.info("=== RFC 8414 metadata document (" + metadataUrl + ") ===");
  var res = await get(metadataUrl);
  assert.strictEqual(res.status, 200,
                     "the metadata endpoint did not answer 200: " + res.status);
  assert.ok(/application\/json/.test(res.headers["content-type"] || ""),
    "metadata must be served as JSON, got: " + res.headers["content-type"]);
  // The debugger fetches this straight from the browser.
  assert.strictEqual(res.headers["access-control-allow-origin"], "*",
    "the metadata endpoint must allow cross-origin reads.");

  var doc;
  try {
    doc = JSON.parse(res.body);
  } catch (e) {
    throw new Error("metadata is not valid JSON: " + e.message);
  }

  var missing = RFC8414_MEMBERS.filter(function (m) { return !(m in doc); });
  assert.strictEqual(missing.length, 0,
                     "metadata is missing RFC 8414 members: " +
                     missing.join(", "));
  var empty = RFC8414_MEMBERS.filter(function (m) {
    var v = doc[m];
    return v === null || v === undefined || v === "" || (Array.isArray(v) &&
        v.length === 0);
  });
  assert.strictEqual(empty.length, 0,
                     "these members are present but not populated: " +
                     empty.join(", "));
  log.info("[document] OK — all " + RFC8414_MEMBERS.length +
           " RFC 8414 members present and populated.");

  // The issuer identifies the server, and the endpoints must belong to it.
  assert.ok(/^https?:\/\//.test(doc.issuer), "issuer must be a URL: " +
            doc.issuer);
  ["authorization_endpoint", "token_endpoint", "jwks_uri",
   "revocation_endpoint",
   "introspection_endpoint", "registration_endpoint"].forEach(function (m) {
    assert.ok(String(doc[m]).indexOf(doc.issuer) === 0,
      m + " (" + doc[m] + ") should live under the issuer (" + doc.issuer +
          ")");
  });
  log.info("[document] OK — every endpoint sits under the issuer " +
           doc.issuer + ".");

  log.debug("Leaving testMetadataDocument().");
  return doc;
}

// The document must describe the host it was asked for, so it is correct both
// on the compose network and from the host.
async function testIssuerTracksHost(doc) {
  log.debug("Entering testIssuerTracksHost().");
  var probeHost = "sts.test:9999";
  var res = await get(metadataUrl, { Host: probeHost });
  var other = JSON.parse(res.body);
  assert.strictEqual(other.issuer.replace(/^https?:\/\//, ""), probeHost,
    "the issuer should follow the requested host, got: " + other.issuer);
  assert.ok(other.token_endpoint.indexOf(other.issuer) === 0,
    "endpoints should follow the issuer, got: " + other.token_endpoint);
  log.info("[host] OK — issuer follows the request host (" + other.issuer +
           ").");
  log.debug("Leaving testIssuerTracksHost().");
}

// RFC 8414 section 2.1: signed_metadata is a JWT of the metadata, signed by the
// issuer, carrying iss (and here sub).
async function testSignedMetadata(doc) {
  log.debug("Entering testSignedMetadata().");
  var certRes = await get(stsBase + "/sts/cert");
  assert.strictEqual(certRes.status, 200,
                     "could not fetch the STS certificate for verification.");
  var claims;
  try {
    claims = jwt.verify(doc.signed_metadata, certRes.body,
        { algorithms: ["RS256"] });
  } catch (e) {
    throw new Error("signed_metadata does not verify against the STS " +
                    "certificate: " + e.message);
  }

  assert.strictEqual(claims.iss, doc.issuer,
                     "signed_metadata iss must be the issuer.");
  assert.ok(!("signed_metadata" in claims),
            "signed_metadata must not contain itself.");
  var mismatched = Object.keys(doc).filter(function (k) {
    return k !== "signed_metadata" &&
        JSON.stringify(doc[k]) !== JSON.stringify(claims[k]);
  });
  assert.strictEqual(mismatched.length, 0,
    "signed_metadata claims disagree with the document: " +
        mismatched.join(", "));
  log.info("[signed_metadata] OK — verifies against the STS certificate and " +
           "matches all " +
    (Object.keys(doc).length - 1) + " members.");
  log.debug("Leaving testSignedMetadata().");
}

// The advertised jwks_uri has to resolve, or the document points at nothing.
async function testJwksResolves(doc) {
  log.debug("Entering testJwksResolves().");
  var res = await get(doc.jwks_uri);
  assert.strictEqual(res.status, 200, "jwks_uri did not answer 200: " +
                     res.status);
  var jwks = JSON.parse(res.body);
  assert.ok(jwks.keys && jwks.keys.length > 0, "the JWKS carries no keys.");
  var k = jwks.keys[0];
  assert.strictEqual(k.kty, "RSA", "expected an RSA key, got: " + k.kty);
  assert.ok(k.n && k.e, "the JWK is missing its modulus/exponent.");
  log.info("[jwks_uri] OK — resolves to a usable " + k.kty + " key (alg " +
           k.alg + ").");
  log.debug("Leaving testJwksResolves().");
}

// RFC 8414 section 3.1 also allows the issuer's path to follow the well-known
// segment.
async function testIssuerPathForm() {
  log.debug("Entering testIssuerPathForm().");
  var res = await get(metadataUrl + "/tenant1");
  assert.strictEqual(res.status, 200,
                     "the issuer-with-path form did not answer 200: " +
                     res.status);
  JSON.parse(res.body);
  log.info("[path form] OK — " +
           "/.well-known/oauth-authorization-server/<path> answers.");
  log.debug("Leaving testIssuerPathForm().");
}

// ===========================================================================
// Part 3 — a member whose value is a JSON structure
//
// RFC 8414's own members are all strings and flat arrays, but an authorization
// server can define a structured one (mtls_endpoint_aliases, a distributed
// claims_supported), and OID4VCI documents are full of them. Wherever such a
// value is shown it should be pretty-printed — which for a Configuration
// Parameters field means a textarea, since a one-line input cannot show it.
//
// The document here is synthetic: what is under test is the display, on both
// debugger pages, from the same stored document.
// ===========================================================================
const STRUCTURED_DOC = {
  issuer: "https://structured.example.com",
  authorization_endpoint: "https://structured.example.com/authorize",
  token_endpoint: "https://structured.example.com/token",
  scopes_supported: ["openid", "profile", "email"],
  claims_supported: {
    normal: ["sub", "email"],
    distributed: { src1: { endpoint: "https://claims.example.com/userinfo" } }
  }
};

async function structuredValuesActivities(driver) {
  log.debug("Entering structuredValuesActivities().");
  log.info("=== A metadata member whose value is a JSON structure ===");

  // Only the DOCUMENT is planted; every displayed value below is produced by
  // the page itself (Populate Meta Data, then the shared storage
  // oauth2_oidc_2.html reads), so this covers the formatting and not just the
  // field type.
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await driver.wait(until.elementLocated(By.id("issuer")), waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('initialized', true);" +
    "localStorage.setItem('debugger_initialized', true);" +
    "localStorage.setItem('metadata_source', 'rfc8414');" +
    "localStorage.setItem('discovery_info', JSON.stringify(arguments[0]));" +
    "localStorage.setItem('discovery_info_source', JSON.stringify({ source: " +
        "'rfc8414'," +
    "   docLabel: 'OAuth 2.0 Authorization Server Metadata (RFC 8414)'," +
    "   url: 'https://structured.example.com/.well-known/oauth-authorization-server' }));",
    STRUCTURED_DOC);
  await openDebugger(driver);

  // In the table the document is rendered from: indented, and still the value.
  var cell = await driver.executeScript(
    "var rows = document.querySelectorAll('#discovery_info_table tr'), " +
        "out = null;" +
    "for (var i = 1; i < rows.length; i++) {" +
    "  var td = rows[i].querySelectorAll('td');" +
    "  if (td[0].textContent.trim() === 'claims_supported') {" +
    "    out = { pretty: !!td[1].querySelector('pre.metadata-json'), text: " +
        "td[1].textContent };" +
    "  }" +
    "} return out;");
  assert.ok(cell, "the restored table should list claims_supported.");
  assert.ok(cell.pretty,
            "a structured value should be pretty-printed in the table.");
  assert.ok(cell.text.indexOf("\n  ") !== -1,
    "the table's JSON should be indented, not one line. Got: " +
        cell.text.slice(0, 60));
  assert.deepStrictEqual(JSON.parse(cell.text), STRUCTURED_DOC.claims_supported,
    "the table's pretty-printed value should still be the document's value.");
  var geom = await driver.executeScript(
    "var t = document.querySelector('#discovery_info_table table');" +
    "var pane = document.getElementById('oidc_fieldset');" +
    "var tr = t.getBoundingClientRect(), pr = pane.getBoundingClientRect();" +
    "return { overflow: Math.round(tr.right - pr.right) };");
  assert.ok(geom.overflow <= 1,
    "pretty-printed JSON must wrap inside the pane, not widen the table by " +
        geom.overflow + "px.");
  log.info("[table] OK — indented in the table, and still inside the pane.");

  // Then let the PAGE populate the pane from it, and look at both pages.
  await driver.executeScript(
      "oauth2_oidc_1.onSubmitPopulateFormsWithDiscoveryInformation();");
  await driver.sleep(500);
  for (const page of ["oauth2_oidc_1.html", "oauth2_oidc_2.html"]) {
    if (page !== "oauth2_oidc_1.html") {
      await driver.get(baseUrl + "/" + page);
      await driver.wait(until.elementLocated(By.id("claims_supported")),
                        waitTime);
      await driver.sleep(700);
    }
    var state = await driver.executeScript(
      "var s = document.getElementById('claims_supported');" +
      "var i = document.getElementById('issuer');" +
      "var a = document.getElementById('scopes_supported');" +
      "return { structuredTag: s.tagName, structuredRows: s.rows || 0, " +
          "structuredValue: s.value," +
      "         scalarTag: i.tagName, scalarValue: i.value, arrayTag: " +
          "a.tagName, arrayValue: a.value };");
    assert.strictEqual(state.structuredTag, "TEXTAREA",
      page + ": a member holding a JSON structure needs a textarea to show " +
          "it. Got: " + state.structuredTag);
    assert.ok(state.structuredValue.indexOf("\n  ") !== -1,
      page + ": the structure should be pretty-printed. Got: " +
          state.structuredValue.slice(0, 60));
    assert.deepStrictEqual(JSON.parse(state.structuredValue),
                           STRUCTURED_DOC.claims_supported,
      page +
          ": the pretty-printed value should still be the document's value.");
    assert.ok(state.structuredRows >= 3, page +
              ": the textarea should be tall enough to read.");
    assert.strictEqual(state.scalarTag, "INPUT", page +
                       ": a scalar member should stay a one-line input.");
    assert.strictEqual(state.scalarValue, STRUCTURED_DOC.issuer, page +
                       ": the scalar value should be shown.");
    assert.strictEqual(state.arrayTag, "INPUT", page +
                       ": a flat array should stay a one-line input.");
    assert.strictEqual(state.arrayValue, "openid, profile, email",
      page + ": a flat array should stay comma-separated. Got: " +
          state.arrayValue);
    log.info("[" + page + "] OK — the structured member is a pretty-printed " +
             "textarea, the others unchanged.");
  }

  await openDebugger(driver);
  await driver.executeScript("oauth2_oidc_1.onClickClearAllForms();");
  await driver.sleep(300);
  log.debug("Leaving structuredValuesActivities().");
}

// ===========================================================================
// Part 2 — the Metadata Source radio on oauth2_oidc_1.html
// ===========================================================================
async function click(driver, locator) {
  log.debug("Entering click().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", el);
  await driver.sleep(150);
  try {
    await el.click();
  } catch (e) {
    // Something is overlapping the element; click it through the DOM instead.
    await driver.executeScript("arguments[0].click();", el);
  }
  await driver.sleep(300);
  log.debug("Leaving click().");
}
function paneState(driver) {
  log.debug("Entering paneState().");
  log.debug("Leaving paneState().");
  return driver.executeScript(
    "return {" +
    "  url: document.getElementById('oidc_discovery_endpoint').value," +
    "  hint: document.getElementById('metadata_source_hint').textContent.trim()," +
    "  link: (document.querySelector('#metadata_source_hint a') || " +
        "{}).href || ''," +
    "  oidc: document.getElementById('metadata_source_oidc').checked," +
    "  rfc: document.getElementById('metadata_source_rfc8414').checked," +
    "  rows: document.querySelectorAll('#discovery_info_table tr').length," +
    "  note: (document.querySelector('#discovery_info_table " +
        ".discovery-info-note') || {}).textContent || ''" +
    "};");
}
function fieldValues(driver, ids) {
  log.debug("Entering fieldValues().");
  log.debug("Leaving fieldValues().");
  return driver.executeScript(
    "var out = {};" + JSON.stringify(ids) + ".forEach(function (i) {" +
    "  var e = document.getElementById(i);" +
    "  out[i] = e ? { value: e.value, note: e.placeholder || '' } : null;" +
    "}); return out;", ids);
}
function validateButtonShown(driver) {
  log.debug("Entering validateButtonShown().");
  log.debug("Leaving validateButtonShown().");
  return driver.executeScript(
    "var r = document.getElementById('signed_metadata_row');" +
    "return !!(r && r.offsetParent !== null);");
}

// Click Validate Signature and wait for the verdict to settle.
async function validateSignature(driver) {
  log.debug("Entering validateSignature().");
  await driver.executeScript(
      "document.getElementById('signed_metadata_status').textContent = '';");
  await click(driver, By.id('validate_signed_metadata_button'));
  var text = "";
  await driver.wait(async function () {
    text = await driver.executeScript(
      "return document.getElementById('signed_metadata_status').textContent.trim();");
    return text && text.indexOf("Fetching") !== 0 && text.length > 1;
  }, fetchWait, "the signature validation produced no verdict.");
  log.debug("Leaving validateSignature().");
  return text;
}

async function openDebugger(driver) {
  log.debug("Entering openDebugger().");
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await driver.wait(until.elementLocated(By.id('metadata_source_rfc8414')),
                    waitTime);
  await driver.sleep(600);
  log.debug("Leaving openDebugger().");
}

async function metadataSourceActivities(driver, doc) {
  log.debug("Entering metadataSourceActivities().");
  await openDebugger(driver);
  await driver.executeScript("window.localStorage.clear();");
  await openDebugger(driver);

  // ---- The source selector -------------------------------------------------
  log.info("=== Metadata Source selector ===");
  var s = await paneState(driver);
  assert.ok(s.oidc && !s.rfc, "OIDC Discovery should be the default source.");
  assert.strictEqual(await validateButtonShown(driver), false,
    "the Validate Signature button is RFC 8414-only and must be hidden for " +
        "OIDC Discovery.");
  assert.ok(s.hint.indexOf("/.well-known/openid-configuration") !== -1,
    "the default hint should name the OIDC well-known path: " + s.hint);

  // With the field still holding the OIDC default, selecting RFC 8414 offers
  // the configured RFC 8414 endpoint — the default value of the field for that
  // source. (This runs before the URL is overwritten below.)
  var oidcDefaultUrl = s.url;
  await click(driver, By.id('metadata_source_rfc8414'));
  var offered = (await paneState(driver)).url;
  if (offered === oidcDefaultUrl && offered === OIDC_DUMMY_DEFAULT) {
    // The field still holds the OIDC source's own dummy default, which means
    // the RFC 8414 source had nothing to offer —
    // `METADATA_SOURCES.rfc8414.defaultUrl`
    // in client/src/oauth2_oidc_1.js is `appconfig.rfc8414MetadataUrlDefault || ""`, and
    // the deployed configs (prod.js, test-idptools-com.js) set that to ""
    // because a public site has no business defaulting to somebody's localhost
    // STS. So the default-offering rules below do not apply here.
    //
    // This is deliberately narrow: it is the OIDC DUMMY that says "nothing was
    // offered". A configured default that failed to appear would leave some
    // other value in the field and still fail below, which is what this check
    // is for.
    log.info("[default] this deployment configures no RFC 8414 " +
             "endpoint default " +
             "(rfc8414MetadataUrlDefault is empty), so the selector has " +
                 "nothing to offer; " +
             "skipping the default-offering checks.");
  } else {
    assert.notStrictEqual(offered, oidcDefaultUrl,
      "selecting RFC 8414 should offer an RFC 8414 endpoint, not leave the " +
          "OIDC default in place.");
    assert.ok(offered.indexOf("/.well-known/oauth-authorization-server") !== -1,
      "the offered default should be an RFC 8414 endpoint, got: " + offered);
    log.info("[default] OK — selecting RFC 8414 offers " + offered + ".");
    // Switching back keeps that host and swaps the path — the long-standing
    // rule for a field that holds a real endpoint, which it now does.
    await click(driver, By.id('metadata_source_oidc'));
    assert.strictEqual((await paneState(driver)).url,
      offered.replace("/.well-known/oauth-authorization-server",
                      "/.well-known/openid-configuration"),
      "switching back should keep the host and swap the well-known path.");
  }

  // Selecting RFC 8414 retunes the hint, the spec link, and the well-known
  // path.
  await driver.executeScript(
    "document.getElementById('oidc_discovery_endpoint').value = arguments[0];",
    stsBase + "/.well-known/openid-configuration");
  await click(driver, By.id('metadata_source_rfc8414'));
  s = await paneState(driver);
  assert.ok(s.rfc && !s.oidc,
    "clicking the RFC 8414 radio must select it (the enclosing form's " +
        "onclick must not cancel it).");
  assert.strictEqual(s.url, metadataUrl,
    "switching sources should swap the well-known suffix, got: " + s.url);
  assert.ok(s.hint.indexOf("/.well-known/oauth-authorization-server") !== -1,
    "the hint should name the RFC 8414 well-known path: " + s.hint);
  assert.ok(/rfc8414/.test(s.link),
            "the hint should link RFC 8414 for reference, got: " + s.link);
  assert.strictEqual(s.rows, 0,
      "selecting a source must not retrieve anything on its own.");
  assert.strictEqual(await validateButtonShown(driver), true,
    "the Validate Signature button should appear once RFC 8414 is selected.");
  log.info("[selector] OK — radio holds, URL/hint/spec link follow, Validate " +
           "Signature appears, nothing fetched yet.");

  // ---- Retrieve the RFC 8414 document -------------------------------------
  log.info("=== Retrieve + populate from the RFC 8414 endpoint ===");
  await driver.executeScript(
    "oauth2_oidc_1.OnSubmitOIDCDiscoveryEndpointForm();");
  await driver.wait(async function () {
    return (await paneState(driver)).rows > 1;
  }, fetchWait,
      "the metadata table was not rendered from the RFC 8414 document.");
  await driver.executeScript(
      "oauth2_oidc_1.onSubmitPopulateFormsWithDiscoveryInformation();");
  await driver.sleep(600);

  // The table says what it is showing and where it came from.
  s = await paneState(driver);
  assert.ok(s.note.indexOf("RFC 8414") !== -1,
    "the note above the table should name the metadata type. Got: " +
        JSON.stringify(s.note));
  assert.ok(s.note.indexOf(metadataUrl) !== -1,
    "the note above the table should name the URL it was retrieved " +
        "from. Got: " + JSON.stringify(s.note));
  log.info("[note] OK — " + s.note.trim());

  // Every member of the document that the pane has a field for must be filled
  // with the document's value.
  var mapped = {
    issuer: "issuer", authorization_endpoint: "authorization_endpoint",
    token_endpoint: "token_endpoint", jwks_endpoint: "jwks_uri",
    registration_endpoint: "registration_endpoint",
        revocation_endpoint: "revocation_endpoint",
    introspection_endpoint: "introspection_endpoint",
        service_documentation: "service_documentation",
    op_policy_uri: "op_policy_uri", op_tos_uri: "op_tos_uri"
  };
  var ids = Object.keys(mapped);
  var got = await fieldValues(driver, ids);
  var wrong = ids.filter(function (id) { return !got[id] ||
      got[id].value !== doc[mapped[id]]; });
  assert.strictEqual(wrong.length, 0,
                     "these fields do not carry the document's value: " +
    wrong.map(function (id) { return id + "=" + JSON.stringify(got[id] &&
              got[id].value); }).join(", "));

  // Arrays arrive comma-separated.
  var arrays = await fieldValues(driver, ["scopes_supported",
      "response_types_supported",
                                          "grant_types_supported", "token_endpoint_auth_methods_supported"]);
  Object.keys(arrays).forEach(function (id) {
    assert.strictEqual(arrays[id].value, doc[id].join(", "),
      id + " should be the document's array, comma-separated. Got: " +
          arrays[id].value);
  });
  log.info("[populate] OK — " + (ids.length + 4) +
           " fields carry the document's values.");

  // The six members RFC 8414 adds to OIDC Discovery's set.
  var rfcOnly = await fieldValues(driver, RFC8414_ONLY_FIELDS);
  RFC8414_ONLY_FIELDS.forEach(function (id) {
    assert.ok(rfcOnly[id],
              "the pane should have a field for the RFC 8414 member " + id +
              ".");
    if (id === "signed_metadata") return; // checked below — it is re-signed per request
    var expected = Object.prototype.toString.call(doc[id]) === "[object Array]"
      ? doc[id].join(", ") : String(doc[id]);
    assert.strictEqual(rfcOnly[id].value, expected,
      id + " should carry the document's value. Got: " + rfcOnly[id].value);
  });
  // The issuer re-signs the document on every request, so the browser's copy is
  // a DIFFERENT JWT from the one this test fetched (different iat/exp). What
  // must hold is that the field carries the JWT of THIS document.
  var signedField = rfcOnly.signed_metadata.value;
  assert.strictEqual(signedField.split(".").length, 3,
    "signed_metadata should carry a three-part JWS. Got: " +
        signedField.slice(0, 40));
  var signedClaims = JSON.parse(Buffer.from(signedField.split(".")[1],
      "base64url").toString("utf8"));
  assert.strictEqual(signedClaims.issuer, doc.issuer,
    "the signed_metadata field should hold the JWT of this document.");
  log.info("[populate] OK — all " + RFC8414_ONLY_FIELDS.length +
           " RFC 8414-only members carry the document's values " +
               "(signed_metadata is a " +
           signedField.length + "-character JWT of the document).");

  // ---- Members RFC 8414 does not define ------------------------------------
  var oidcOnly = await fieldValues(driver, OIDC_ONLY_FIELDS);
  var badNotes = OIDC_ONLY_FIELDS.filter(function (id) {
    return !oidcOnly[id] || oidcOnly[id].value !== "" ||
                     oidcOnly[id].note !== NOT_DEFINED_NOTE;
  });
  assert.strictEqual(badNotes.length, 0,
    "members RFC 8414 does not define should be empty and annotated: " +
    badNotes.map(function (id) { return id + "=" +
                 JSON.stringify(oidcOnly[id]); }).join(", "));
  log.info("[not defined] OK — " + OIDC_ONLY_FIELDS.length +
           " OIDC-only members show the note.");

  // ---- The generated table stays inside the pane --------------------------
  var geom = await driver.executeScript(
    "var t = document.querySelector('#discovery_info_table table');" +
    "var pane = document.getElementById('oidc_fieldset');" +
    "if (!t) return null;" +
    "var tr = t.getBoundingClientRect(), pr = pane.getBoundingClientRect();" +
    "return { overflow: Math.round(tr.right - pr.right), width: " +
        "Math.round(tr.width)," +
    "         paneWidth: Math.round(pr.width) };");
  assert.ok(geom, "the metadata table was not rendered.");
  assert.ok(geom.overflow <= 1,
    "the metadata table overflows its pane by " + geom.overflow + "px (table " +
        geom.width +
    " vs pane " + geom.paneWidth + ") — long values must wrap, not widen it.");
  log.info("[layout] OK — the table fits its pane (" + geom.width + "px in " +
           geom.paneWidth + "px).");

  // ---- Validate the signature on signed_metadata --------------------------
  log.info("=== Validate Signature (RFC 8414 signed_metadata) ===");
  var verdict = await validateSignature(driver);
  assert.ok(verdict.indexOf("VALID") === 0,
    "signed_metadata should verify against the document's jwks_uri. Got: " +
        verdict);
  assert.ok(verdict.indexOf("iss matches the issuer") !== -1,
    "the verdict should confirm the iss claim is the issuer. Got: " + verdict);
  assert.ok(verdict.indexOf("Every signed claim matches") !== -1,
    "the signed claims should match the JSON document. Got: " + verdict);
  log.info("[signature] OK — " + verdict);

  // A tampered signature must be rejected (negative control).
  await driver.executeScript(
    "var doc = JSON.parse(localStorage.getItem('discovery_info'));" +
    "var p = doc.signed_metadata.split('.');" +
    "p[2] = p[2].slice(0, -4) + 'AAAA';" +
    "doc.signed_metadata = p.join('.');" +
    "localStorage.setItem('discovery_info', JSON.stringify(doc));");
  await openDebugger(driver);
  verdict = await validateSignature(driver);
  assert.ok(verdict.indexOf("INVALID") === 0,
    "a tampered signed_metadata must be rejected. Got: " + verdict);
  log.info("[signature] OK — a tampered signature is rejected.");

  // Tampering the JSON instead: the signature still verifies, but the signed
  // claim disagrees with the JSON, which is what the client must notice.
  await driver.executeScript("oauth2_oidc_1.onClickClearAllForms();");
  await driver.sleep(300);
  // Clear resets the source to OIDC, which hides the button — select RFC 8414
  // again before retrieving.
  await click(driver, By.id('metadata_source_rfc8414'));
  await driver.executeScript(
    "document.getElementById('oidc_discovery_endpoint').value = arguments[0];" +
    "oauth2_oidc_1.OnSubmitOIDCDiscoveryEndpointForm();", metadataUrl);
  await driver.sleep(1500);
  await driver.executeScript(
    "var doc = JSON.parse(localStorage.getItem('discovery_info'));" +
    "doc.issuer = 'https://evil.example.com';" +
    "localStorage.setItem('discovery_info', JSON.stringify(doc));");
  await openDebugger(driver);
  verdict = await validateSignature(driver);
  assert.ok(verdict.indexOf("VALID") === 0 &&
            verdict.indexOf("MISMATCH") !== -1,
    "a JSON member edited away from its signed claim must be reported. Got: " +
        verdict);
  log.info("[signature] OK — a JSON member that disagrees with its signed " +
           "claim is reported.");

  // Restore a clean document for the checks that follow.
  await driver.executeScript("oauth2_oidc_1.onClickClearAllForms();");
  await driver.sleep(300);
  await click(driver, By.id('metadata_source_rfc8414'));
  await driver.executeScript(
    "document.getElementById('oidc_discovery_endpoint').value = arguments[0];" +
    "oauth2_oidc_1.OnSubmitOIDCDiscoveryEndpointForm();", metadataUrl);
  await driver.sleep(1500);
  await driver.executeScript(
      "oauth2_oidc_1.onSubmitPopulateFormsWithDiscoveryInformation();");
  await driver.sleep(500);

  // ---- The choice and the document survive a reload ------------------------
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id('metadata_source_rfc8414')),
                    waitTime);
  await driver.sleep(700);
  s = await paneState(driver);
  assert.ok(s.rfc,
            "the RFC 8414 source should still be selected after a reload.");
  assert.strictEqual(s.url, metadataUrl,
                     "the metadata URL should survive a reload.");
  assert.ok(s.rows > 1, "the metadata table should survive a reload.");
  assert.ok(s.note.indexOf("RFC 8414") !== -1 &&
            s.note.indexOf(metadataUrl) !== -1,
    "the note naming the metadata type and URL should survive a reload. Got: " +
        JSON.stringify(s.note));
  var afterReload = await fieldValues(driver, ["issuer"]);
  assert.strictEqual(afterReload.issuer.value, doc.issuer,
                     "the populated issuer should survive a reload.");
  log.info("[persistence] OK — source, URL, table, and values all survive " +
           "a reload.");

  // Switching back swaps the suffix the other way.
  await click(driver, By.id('metadata_source_oidc'));
  s = await paneState(driver);
  assert.ok(s.oidc, "the OIDC radio should select.");
  assert.ok(s.url.indexOf("/.well-known/openid-configuration") !== -1,
    "switching back should restore the OIDC well-known path, got: " + s.url);
  assert.ok(s.note.indexOf("RFC 8414") !== -1,
    "the note describes the document on display, so changing the radio must " +
        "not rewrite it. Got: " +
    JSON.stringify(s.note));

  // The same holds when the table is rebuilt from storage: the form now says
  // OIDC Discovery, but what is on display is still the RFC 8414 document.
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id('metadata_source_rfc8414')),
                    waitTime);
  await driver.sleep(700);
  s = await paneState(driver);
  assert.ok(s.oidc, "the OIDC source should have persisted.");
  assert.ok(s.note.indexOf("RFC 8414") !== -1 &&
            s.note.indexOf(metadataUrl) !== -1,
    "a table rebuilt from storage must be labelled with how ITS document was " +
        "retrieved, " +
    "not with the form's current state. Got: " + JSON.stringify(s.note));

  // Retrieve again as OIDC Discovery to check the other label. The pane does
  // not care which spec the JSON conforms to, so the RFC 8414 URL serves as the
  // document here — what is under test is how the retrieval is labelled.
  await driver.executeScript(
    "document.getElementById('oidc_discovery_endpoint').value = arguments[0];" +
    "oauth2_oidc_1.OnSubmitOIDCDiscoveryEndpointForm();", metadataUrl);
  await driver.sleep(1500);
  s = await paneState(driver);
  assert.ok(s.note.indexOf("OpenID Connect Discovery 1.0") !== -1 &&
            s.note.indexOf("RFC 8414") === -1,
    "a document retrieved as OIDC Discovery should be labelled as such. Got: " +
        JSON.stringify(s.note));
  assert.ok(s.note.indexOf(metadataUrl) !== -1,
    "the OIDC note should name its URL too. Got: " + JSON.stringify(s.note));
  log.info("[note] OK — the note follows the retrieval, not the form: " +
           s.note.trim());

  // ---- The same pane on oauth2_oidc_2.html
  // ------------------------------------ Both debugger pages carry the
  // identical Configuration Parameters pane over the same storage, so what was
  // populated here must be there too.
  await driver.get(baseUrl + "/oauth2_oidc_2.html");
  await driver.wait(until.elementLocated(By.id("issuer")), waitTime);
  await driver.sleep(700);
  var onTwo = await fieldValues(driver, ["issuer"].concat(RFC8414_ONLY_FIELDS));
  var missingOnTwo =
      RFC8414_ONLY_FIELDS.filter(function (id) { return !onTwo[id]; });
  assert.strictEqual(missingOnTwo.length, 0,
    "oauth2_oidc_2.html's pane is missing fields oauth2_oidc_1.html has: " +
        missingOnTwo.join(", "));
  assert.strictEqual(onTwo.issuer.value, doc.issuer,
    "oauth2_oidc_2.html should show the same populated issuer.");
  assert.strictEqual(onTwo.code_challenge_methods_supported.value,
    doc.code_challenge_methods_supported.join(", "),
    "oauth2_oidc_2.html should show the same RFC 8414 members. Got: " +
    onTwo.code_challenge_methods_supported.value);
  log.info("[oauth2_oidc_2] OK — the same pane, the same values, including " +
           "the RFC 8414-only members.");
  await openDebugger(driver);

  // ---- Clear ---------------------------------------------------------------
  await driver.executeScript("oauth2_oidc_1.onClickClearAllForms();");
  await driver.sleep(400);
  s = await paneState(driver);
  assert.ok(s.oidc && !s.rfc,
            "Clear should return the source to OIDC Discovery.");
  assert.strictEqual(s.url, "", "Clear should empty the metadata URL.");
  assert.strictEqual(s.rows, 0, "Clear should remove the metadata table.");
  assert.strictEqual(s.note, "",
                     "Clear should remove the note above the table.");
  var cleared = await fieldValues(driver, ["issuer", "revocation_endpoint"]);
  assert.strictEqual(cleared.issuer.value, "",
                     "Clear should empty the populated fields.");
  assert.strictEqual(cleared.issuer.note, "",
                     "Clear should remove the not-defined notes.");
  assert.strictEqual(await validateButtonShown(driver), false,
    "Clear returns the source to OIDC, so the Validate Signature button " +
        "should be hidden again.");
  log.info("[clear] OK — source, URL, table, values, and notes all cleared.");
  await structuredValuesActivities(driver);
  log.debug("Leaving metadataSourceActivities().");
}

async function test() {
  log.debug("Entering test().");
  var doc = await testMetadataDocument();
  await testIssuerTracksHost(doc);
  await testSignedMetadata(doc);
  await testJwksResolves(doc);
  await testIssuerPathForm();

  const options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  options.addArguments("--unsafely-treat-insecure-origin-as-secure=" +
                       baseUrl.replace(/\/+$/, ""));
  options.addArguments("--user-data-dir=/tmp/rfc8414-chrome-" + Date.now());
  try {
    const prefs = new logging.Preferences();
    prefs.setLevel(logging.Type.BROWSER, logging.Level.SEVERE);
    options.setLoggingPrefs(prefs);
  } catch (e) {
    // Browser logs are a bonus; a driver that cannot collect them still runs
    // the test.
    log.info("browser logging preferences unavailable: " + e.message);
  }
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    log.info("Starting Test run. metadata=" + metadataUrl);
    await driver.manage().deleteAllCookies();
    await metadataSourceActivities(driver, doc);
    var severe = [];
    try {
      severe = (await driver.manage().logs().get(logging.Type.BROWSER))
        .filter(function (e) { return e.level && e.level.name === "SEVERE"; });
    } catch (e) {
      // No browser log on this driver, so there is nothing to assert about.
      log.info("the browser log is unavailable here: " + e.message);
    }
    assert.strictEqual(severe.length, 0,
      "the page logged console errors:\n  " +
          severe.map(function (e) { return e.message; }).join("\n  "));
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('oauth2_metadata_rfc8414')
  .description("Run the RFC 8414 metadata test (STS endpoint + the " +
      "debugger's Metadata Source option).")
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

test().catch(function (e) {
  log.error(e && e.stack ? e.stack : String(e));
  process.exit(1);
});
