// File: sd_jwt_vc_issuance.js
//
// The SD-JWT VC issuance workflow, end to end:
//
//   step 0 (vc-issuance-0.html)
//     the use-case chooser: which OID4VCI Appendix H flow to run. The
//     wallet-initiated one (H.6) is what most of this file drives; the
//     issuer-initiated Credential Offer (H.1) has its own section at the end.
//
//   step 1 (vc-issuance-1.html)
//     retrieve the OID4VCI Credential Issuer Metadata, validate its
//     signed_metadata, populate the Configuration Parameters pane from it;
//     retrieve the authorization server's RFC 8414 metadata and populate the
//     same pane from that, under the localStorage names oauth2_oidc_1.html
// uses;     then hand off with ?sdjwtvc=1.
//
//   the OIDC leg (oauth2_oidc_1.html -> Keycloak -> oauth2_oidc_2.html)
//     the user authenticates and the authorization code is exchanged for
//     tokens WITHOUT further interaction, because the workflow drives it.
//
//   step 2 (vc-issuance-2.html)
//     the tokens are shown, a holder key pair is generated, and approving the
//     issuance fetches a c_nonce, signs an openid4vci-proof+jwt and POSTs the
//     Credential Request.
//
//   step 3 (vc-issuance-3.html)
//     the returned SD-JWT VC is parsed and verified: issuer signature, media
//     type, vct, cnf binding to the holder key, and every Disclosure's digest
//     against _sd. The credential is independently re-checked here in the test,
//     so a page that merely CLAIMS the credential is fine cannot pass.
//
//   step 4 (vc-issuance-4.html)
//     refreshing it (OID4VCI section 14.5): the refresh token is exchanged for
//     a fresh access token, the Credential Endpoint is asked again, and the two
//     credentials are compared — here as well as by the page, because what the
//     issuer changed (the signature only, or the claims too) is the issuer's
//     choice and a wallet must read it rather than assume it. Keeping the
//     refreshed credential is a decision the holder makes, so that is checked
//     too, along with the routes that remain when the refresh token is dead.
//     Its Credential History pane — oauth2_oidc_2.html's Token History, for
//     credentials — is navigated backwards and forwards, and activating a
//     generation has to put that credential AND its holder key back in hand,
//     not merely highlight a row.
//
//   negatives
//     denying issuance sends nothing; a replayed c_nonce and a request with no
//     access token are both refused by the issuer; a refresh token the server
//     rejects, and no refresh token at all, are both reported rather than
//     offered as a button that cannot work.
//
// Needs the mock credential issuer (the STS service) and Keycloak, as the other
// STS-backed tests do: WSTRUST_STS_URL locates the issuer,
// OID4VCI_ISSUER_URL overrides it outright, and KEYCLOAK_BASE_URL the IdP.

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const logging = require("selenium-webdriver/lib/logging");
const assert = require("assert");
const browserFlags = require("./browser_flags.js");
const crypto = require("crypto");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'sd_jwt_vc_issuance',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
var fetchWait = Math.max(waitTime, 20000);
// The budget every waitFor* in ./wait_for.js uses. Set once: one test file
// runs per process.
require("./wait_for").configure({ timeout: fetchWait });

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/,
    "");
var issuerMetadataUrl = issuerBase + "/.well-known/openid-credential-issuer";
var keycloakBase = process.env.KEYCLOAK_BASE_URL || "http://localhost:8080";
var realmBase = keycloakBase + "/realms/debugger-testing";
var asMetadataUrl = realmBase + "/.well-known/oauth-authorization-server";
// The OIDC Authorization Code public client the debugger suite provisions. Its
// user has the same name and password.
var clientId = process.env.SD_JWT_VC_CLIENT_ID ||
    "oidc-authorization-code-public";

// The credential configuration this issuer offers, named in requests and in
// authorization_details.
var VCI_CONFIG_ID = process.env.OID4VCI_CONFIG_ID || "IdentityCredential";
// Whoever signs in at the mock authorization server; no password is checked,
// and the username becomes the identity in the tokens.
var MOCK_AS_USER = "authz.details.user";
var EXPECTED_VCT = "urn:idptools:sd-jwt-vc:identity";
var SD_JWT_VC_TYP = "dc+sd-jwt";
// OID4VCI's pre-authorized code grant, used by the cross-device use cases.
var PRE_AUTHORIZED_GRANT =
    "urn:ietf:params:oauth:grant-type:pre-authorized_code";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function b64uDecode(s) {
  log.debug("Entering b64uDecode().");
  log.debug("Leaving b64uDecode().");
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function jsonFromB64u(s) {
  log.debug("Entering jsonFromB64u().");
  log.debug("Leaving jsonFromB64u().");
  return JSON.parse(b64uDecode(s).toString("utf8"));
}

function httpJson(url, options) {
  log.debug("Entering httpJson().");
  options = options || {};
  log.debug("Leaving httpJson().");
  return fetch(url, options).then(function (r) {
    return r.text().then(function (text) {
      var body = null;
      try {
        body = JSON.parse(text);
      } catch (e) {
        // Not JSON: the caller gets the raw text instead.
      }
      return { status: r.status, ok: r.ok, body: body, raw: text };
    });
  });
}

async function click(driver, locator) {
  log.debug("Entering click().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var e = driver.findElement(locator);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", e);
  await driver.sleep(120);
  try {
    await e.click();
  } catch (err) {
    // Something is overlapping the element; click it through the DOM instead.
    await driver.executeScript("arguments[0].click();", e);
  }
  await driver.sleep(250);
  log.debug("Leaving click().");
}

// text()/value() and the waitFor* family live in ./wait_for.js — one
// implementation, shared with the other SD-JWT VC suites. See that file for why
// waiting on CONTENT rather than on the element (plus a fixed sleep) matters:
// these fields are all static markup, so locating them proves nothing, and the
// fixed sleep this suite used to rely on lost the race twice.
const {
  text, value, waitFor, waitForStatus, waitForValue, waitForFilled, waitForJson
} = require("./wait_for");

function severeErrors(driver) {
  log.debug("Entering severeErrors().");
  log.debug("Leaving severeErrors().");
  return driver.manage().logs().get(logging.Type.BROWSER)
                       .then(function (entries) {
    return entries.filter(function (e) { return e.level.name === "SEVERE"; })
      // A favicon that is not there is not a page error.
      .filter(function (e) { return !/favicon/.test(e.message); })
      .map(function (e) { return e.message; });
  });
}

// ---------------------------------------------------------------------------
// Step 1 — discovery and configuration
// ---------------------------------------------------------------------------
async function stepOne(driver) {
  log.debug("Entering stepOne().");
  log.info("=== Step 1: discover the issuer ===");
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript("window.localStorage.clear();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.sleep(500);

  // The Configuration Parameters pane must cover BOTH documents, not just one.
  var coverage = await driver.executeScript(
    "return { rows: document.querySelectorAll('#config_rows tr').length," +
    "         fields: document.querySelectorAll('#config_rows input, " +
        "#config_rows select').length," +
    "         groups: document.querySelectorAll(" +
    "           '#config_rows tr.vc-group-heading, #config_rows " +
        ".vc-config-group').length };");
  assert.ok(coverage.groups >= 4,
    "the Configuration Parameters pane should be grouped by document, got " +
        coverage.groups + " groups.");
  assert.ok(coverage.fields > 50,
    "the pane should carry every member both documents define, got " +
        coverage.fields + " fields.");
  log.info("[step1] Configuration Parameters pane: " + coverage.fields +
           " fields in " +
           coverage.groups + " groups.");

  // The RFC 8414 pane starts on the authorization server metadata endpoint this
  // deployment configures, so the workflow is usable without pasting a URL in —
  // WHERE one is configured. `client/src/env/local.js` and `docker-tests.js`
  // name this suite's STS; `prod.js` and `test-idptools-com.js` deliberately
  // name nothing, because a public site has no business defaulting to
  // somebody's localhost. So the SHAPE is asserted when a default is there, and
  // its absence is recorded rather than failed: every pane this test drives is
  // filled from the URLs the test was given, a few lines below.
  var asDefault = await value(driver, "oidc_discovery_endpoint");
  if (asDefault) {
    assert.ok(asDefault.indexOf(
              "/.well-known/oauth-authorization-server") !== -1,
      "a configured default for the RFC 8414 pane must be an RFC 8414 " +
          "endpoint, got: " +
      JSON.stringify(asDefault));
    log.info("[step1] the RFC 8414 pane defaults to " + asDefault + ".");
  } else {
    log.info("[step1] this deployment configures no default RFC 8414 " +
             "endpoint " +
             "(rfc8414MetadataUrlDefault is unset in its client env, as it " +
                 "is for the deployed sites); " +
             "the test supplies the URL itself.");
  }

  // ...and a value another page left in storage does NOT become that default.
  // `oidc_discovery_endpoint` is shared with oauth2_oidc_1.html on purpose, and
  // that page's metadata pane offers an OpenID Connect Discovery URL — its
  // https://localhost/oidc/.well-known placeholder on a browser that merely
  // loaded it — under this same name. Before asMetadataUrlAtLoad() this pane
  // adopted whatever it found, so a browser that had visited the OAuth2 / OIDC
  // workflow once arrived here with an openid-configuration URL sitting in a
  // field the pane says is an RFC 8414 endpoint. Whatever the deployment
  // configures, seeding that value must leave the pane exactly where a fresh
  // browser found it — which is why this compares against asDefault rather
  // than against a URL of its own, and so asserts the empty case too.
  await driver.executeScript(
    "window.localStorage.setItem('oidc_discovery_endpoint', arguments[0]);",
        "https://localhost/oidc/.well-known");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.sleep(500);
  var asSeeded = await value(driver, "oidc_discovery_endpoint");
  assert.strictEqual(asSeeded, asDefault,
    "an OIDC Discovery URL left in shared storage by oauth2_oidc_1.html must " +
        "not become the RFC 8414 pane's value; expected " +
        JSON.stringify(asDefault) + ", got " + JSON.stringify(asSeeded));
  // The other page's URL is its own: this page must not have rewritten it.
  var asStillStored = await driver.executeScript(
    "return window.localStorage.getItem('oidc_discovery_endpoint');");
  assert.strictEqual(asStillStored, "https://localhost/oidc/.well-known",
    "vc-issuance-1 must leave oauth2_oidc_1.html's stored metadata URL " +
        "alone, found " + JSON.stringify(asStillStored));
  log.info("[step1] a foreign metadata URL in shared storage is ignored by " +
           "the RFC 8414 pane and left in place for oauth2_oidc_1.html.");
  // Back to the clean slate the rest of this step assumes.
  await driver.executeScript("window.localStorage.clear();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.sleep(500);

  // ---- pane 1: the credential issuer metadata -----------------------------
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];",
        issuerMetadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
              "the credential issuer metadata was not retrieved");

  var note = await driver.executeScript(
    "var n = document.querySelector('#vci_metadata_table " +
        ".discovery-info-note');" +
    "return n ? n.textContent.trim() : '';");
  assert.ok(note.indexOf("OID4VCI Credential Issuer Metadata") !== -1 &&
            note.indexOf(issuerMetadataUrl) !== -1,
    "the table should say which document it is showing and where it came " +
        "from. Got: " + note);
  var rows = await driver.executeScript(
    "return document.querySelectorAll('#vci_metadata_table tr').length;");
  assert.ok(rows > 5, "the credential issuer metadata table should list the " +
            "document's members, got " + rows);
  log.info("[step1] " + note);

  // Its signed_metadata must verify — the same check oauth2_oidc_1.html runs
  // on an RFC 8414 document, against keys resolved the SD-JWT VC way.
  await click(driver, By.id("vci_validate_signed_metadata_button"));
  var verdict = await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^(VALID|INVALID|Could not)/.test(s); },
    "the credential issuer signed_metadata produced no verdict");
  // On failure, say which documents the page actually fetched. The keys for an
  // OID4VCI document are resolved indirectly — the credential issuer metadata
  // defines no jwks_uri, so it goes through /.well-known/jwt-vc-issuer — and a
  // verdict of "no key verified it" is unreadable without knowing which JWKS
  // was reached. This is the difference between "the mock is inconsistent" and
  // "the page asked the wrong issuer for keys".
  var fetchedDocs = await driver.executeScript(
    "return performance.getEntriesByType('resource').map(function (r) { " +
        "return r.name; })" +
    "  .filter(function (n) { return /well-known|jwks|certs/.test(n); });");
  assert.ok(verdict.indexOf("VALID") === 0,
    "the credential issuer's signed_metadata should verify. Got: " + verdict +
    " — documents the page fetched: " + JSON.stringify(fetchedDocs));
  assert.ok(verdict.indexOf("iss matches the issuer") !== -1,
    "the verdict should confirm iss is the credential issuer. Got: " + verdict);
  log.info("[step1] signed_metadata: " + verdict);

  // Retrieving fills the pane on its own; the Populate button only re-applies
  // the document. Check the values BEFORE clicking it.
  var onRetrieveAlone = await driver.executeScript(
    "return ['vci_credential_endpoint','vci_nonce_endpoint','vci_vct']" +
    "  .map(function (i) { return document.getElementById(i).value; });");
  assert.ok(onRetrieveAlone.every(Boolean),
    "retrieving the credential issuer metadata should populate the pane " +
        "without a further click. Got: " +
    JSON.stringify(onRetrieveAlone));
  log.info("[step1] OK — retrieving the issuer metadata populated the pane " +
           "on its own.");

  await click(driver, By.id("vci_populate_button"));
  await driver.sleep(400);
  var populated = await driver.executeScript(
    "return ['vci_credential_issuer','vci_credential_endpoint'," +
        "'vci_nonce_endpoint'," +
    "        'vci_credential_configuration_id','vci_format','vci_vct']" +
    "  .map(function (i) { return document.getElementById(i).value; });");
  assert.strictEqual(populated[0], issuerBase,
                     "credential_issuer should be the mock issuer.");
  assert.strictEqual(populated[1], issuerBase + "/oid4vci/credential",
                     "credential_endpoint should be populated.");
  assert.strictEqual(populated[2], issuerBase + "/oid4vci/nonce",
                     "nonce_endpoint should be populated.");
  assert.strictEqual(populated[4], "dc+sd-jwt",
                     "the credential format should be dc+sd-jwt.");
  assert.strictEqual(populated[5], EXPECTED_VCT,
                     "the vct should come from the credential configuration.");
  log.info("[step1] OID4VCI values populated: " + populated.join(", "));

  // A member whose value is a JSON structure is pretty-printed, in the table
  // and in the pane. A flat array of scalars stays on one line.
  var cells = await driver.executeScript(
    "var rows = document.querySelectorAll('#vci_metadata_table tr'), " +
        "out = {};" +
    "for (var i = 1; i < rows.length; i++) {" +
    "  var td = rows[i].querySelectorAll('td');" +
    "  out[td[0].textContent.trim()] = { pretty: " +
        "!!td[1].querySelector('pre.metadata-json')," +
    "                                    text: td[1].textContent };" +
    "} return out;");
  var structured = ["credential_configurations_supported", "display",
      "credential_response_encryption",
                    "batch_credential_issuance"];
  structured.forEach(function (member) {
    assert.ok(cells[member], "the table should list " + member + ".");
    assert.ok(cells[member].pretty,
      member +
          " is a JSON structure and should be pretty-printed in the table.");
    assert.ok(cells[member].text.indexOf("\n  ") !== -1,
      member + " should be indented, not one line. Got: " +
          cells[member].text.slice(0, 60));
    JSON.parse(cells[member]
               .text);   // throws if the pretty printing mangled it
  });
  assert.strictEqual(cells.credential_endpoint.pretty, false,
    "a plain string should not be turned into a JSON block.");
  assert.strictEqual(cells.authorization_servers.pretty, false,
    "a flat array of scalars should stay on one line rather than " +
        "becoming taller.");
  log.info("[step1] OK — " + structured.length +
           " structured members are pretty-printed in the table; " +
           "strings and flat arrays are not.");

  var jsonFields = await driver.executeScript(
    "var out = {};" +
    "['vci_display','vci_batch_credential_issuance'," +
        "'vci_credential_response_encryption'," +
    " 'vci_credential_issuer'," +
        "'vci_authorization_servers'].forEach(function (id) {" +
    "  var e = document.getElementById(id);" +
    "  out[id] = { tag: e.tagName, rows: e.rows || 0, value: e.value };" +
    "}); return out;");
  ["vci_display", "vci_batch_credential_issuance",
   "vci_credential_response_encryption"].forEach(function (id) {
    assert.strictEqual(jsonFields[id].tag, "TEXTAREA",
      id + " holds JSON, so it needs a textarea — a one-line input cannot " +
          "show it. Got: " + jsonFields[id].tag);
    assert.ok(jsonFields[id].value.indexOf("\n  ") !== -1,
      id + " should hold pretty-printed JSON. Got: " +
          jsonFields[id].value.slice(0, 60));
    JSON.parse(jsonFields[id].value);
    assert.ok(jsonFields[id].rows >= 3, id + " should be tall enough to read.");
  });
  assert.strictEqual(jsonFields.vci_credential_issuer.tag, "INPUT",
    "a scalar member should stay a one-line input.");
  assert.strictEqual(jsonFields.vci_authorization_servers.tag, "INPUT",
    "a flat array should stay a one-line input.");
  log.info("[step1] OK — the JSON members are pretty-printed textareas, the " +
           "scalar ones plain inputs.");

  // ... and that survives a reload, where the values come back out of local
  // storage as plain strings.
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_display")), waitTime);
  await driver.sleep(700);
  var afterReload = await driver.executeScript(
    "var e = document.getElementById('vci_display');" +
    "return { tag: e.tagName, value: e.value };");
  assert.strictEqual(afterReload.tag, "TEXTAREA",
      "the JSON field should still be a textarea after a reload.");
  assert.ok(afterReload.value.indexOf("\n  ") !== -1,
            "and should still be pretty-printed.");
  log.info("[step1] OK — pretty-printed JSON survives a reload.");

  // The issuer names its authorization server, so pane 2's URL is offered.
  var asUrl = await value(driver, "oidc_discovery_endpoint");
  assert.ok(asUrl &&
            asUrl.indexOf("/.well-known/oauth-authorization-server") !== -1,
    "retrieving the issuer metadata should offer its authorization server's " +
        "RFC 8414 URL, got: " + asUrl);
  log.info("[step1] authorization server URL defaulted to " + asUrl);

  // ---- pane 2: the authorization server metadata --------------------------
  await driver.executeScript(
    "document.getElementById('oidc_discovery_endpoint').value = arguments[0];",
        asMetadataUrl);
  await click(driver, By.id("as_retrieve_button"));
  await waitForStatus(driver, "as_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
              "the authorization server metadata was not retrieved");
  // Same for the authorization server document: every endpoint field the
  // document defines is filled by the retrieval itself.
  var endpointsOnRetrieve = await driver.executeScript(
    "var out = {};" +
    "['authorization_endpoint','token_endpoint','jwks_endpoint'," +
        "'registration_endpoint'," +
    " 'introspection_endpoint','revocation_endpoint'," +
        "'device_authorization_endpoint'," +
    " 'oidc_userinfo_endpoint'].forEach(function (i) {" +
    "  out[i] = document.getElementById(i).value;" +
    "}); return out;");
  var unfilled = Object.keys(endpointsOnRetrieve)
      .filter(function (id) { return !endpointsOnRetrieve[id]; });
  assert.strictEqual(unfilled.length, 0,
    "retrieving the RFC 8414 document should populate every endpoint field " +
        "it defines, without a further " +
    "click. These are still empty: " + unfilled.join(", "));
  log.info("[step1] OK — retrieving the RFC 8414 document filled all " +
           Object.keys(endpointsOnRetrieve).length +
                       " endpoint fields on its own.");

  await click(driver, By.id("as_populate_button"));
  await driver.sleep(400);

  var oidcValues = await driver.executeScript(
    "return { authorization_endpoint: " +
        "document.getElementById('authorization_endpoint').value," +
    "         token_endpoint: " +
        "document.getElementById('token_endpoint').value," +
    "         issuer: document.getElementById('issuer').value," +
    "         scope: document.getElementById('scope').value };");
  assert.ok(oidcValues.authorization_endpoint.indexOf(realmBase) === 0,
    "the authorization endpoint should come from the authorization server " +
        "metadata, got: " +
    oidcValues.authorization_endpoint);
  assert.ok(oidcValues.token_endpoint.indexOf(realmBase) === 0,
    "the token endpoint should come from the authorization server metadata.");
  assert.strictEqual(oidcValues.issuer, realmBase,
                     "the issuer should be the realm.");
  log.info("[step1] authorization server values populated: " +
           JSON.stringify(oidcValues));

  // The six members RFC 8414 adds to OIDC Discovery's set have fields here (and
  // on the debugger pages) too: the ones this server publishes are populated,
  // and the one it does not is marked rather than left blank and ambiguous.
  var rfc8414Only = await driver.executeScript(
    "var out = {};" +
    "['revocation_endpoint_auth_methods_supported'," +
        "'introspection_endpoint_auth_methods_supported'," +
    " 'code_challenge_methods_supported'," +
        "'signed_metadata'].forEach(function (i) {" +
    "  var e = document.getElementById(i);" +
    "  out[i] = e ? { value: e.value, note: e.placeholder || '' } : null;" +
    "}); return out;");
  Object.keys(rfc8414Only).forEach(function (id) {
    assert.ok(rfc8414Only[id], "the pane should carry the RFC 8414 member " +
              id + ".");
  });
  assert.ok(rfc8414Only.code_challenge_methods_supported.value.indexOf(
            "S256") !== -1,
    "code_challenge_methods_supported should be populated from the " +
        "document. Got: " +
    rfc8414Only.code_challenge_methods_supported.value);
  assert.ok(rfc8414Only.revocation_endpoint_auth_methods_supported.value,
    "revocation_endpoint_auth_methods_supported should be populated from the " +
        "document.");
  assert.strictEqual(rfc8414Only.signed_metadata.value, "",
    "this authorization server publishes no signed_metadata, so the field " +
        "should be empty.");
  assert.strictEqual(rfc8414Only.signed_metadata.note, "-->not defined<--",
    "a member the document omits should be marked, not left blank. Got: " +
    JSON.stringify(rfc8414Only.signed_metadata));
  log.info("[step1] OK — the RFC 8414-only members are populated, and " +
           "signed_metadata is marked not defined.");

  // The whole point of pane 2: this is the SAME storage oauth2_oidc_1.html
  // reads.
  var shared = await driver.executeScript(
    "return { authorization_endpoint: " +
        "localStorage.getItem('authorization_endpoint')," +
    "         token_endpoint: localStorage.getItem('token_endpoint')," +
    "         document: !!localStorage.getItem('discovery_info')," +
    "         source: localStorage.getItem('metadata_source') };");
  assert.strictEqual(shared.authorization_endpoint,
                     oidcValues.authorization_endpoint,
    "the authorization endpoint must be stored under the name " +
        "oauth2_oidc_1.html reads.");
  assert.strictEqual(shared.token_endpoint, oidcValues.token_endpoint,
    "the token endpoint must be stored under the name oauth2_oidc_1.html " +
        "reads.");
  assert.ok(shared.document, "the retrieved document must be stored under " +
            "oauth2_oidc_1.html's discovery_info key.");
  assert.strictEqual(shared.source, "rfc8414",
                     "the stored metadata source should say RFC 8414.");
  log.info("[step1] OK — the configuration is shared with " +
           "oauth2_oidc_1.html.");

  // ---- the client settings the authorization request needs ----------------
  // The redirect URI is the deployment's own /callback — the debugger pages pin
  // it to their configured origin, and this pane defaults it the same way.
  var redirectUri = await value(driver, "redirect_uri");
  assert.ok(redirectUri && /\/callback$/.test(redirectUri),
    "the pane should default the redirect URI to this deployment's " +
        "/callback, got: " + redirectUri);
  await driver.executeScript(
    "document.getElementById('client_id').value = arguments[0];" +
    "document.getElementById('scope').value = 'openid profile email';",
        clientId);
  await click(driver, By.id("config_save_button"));
  await waitForStatus(driver, "config_status",
                      function (s) { return s === "Saved."; },
    "the configuration should save");

  var summary = await text(driver, "handoff_credential");
  assert.ok(summary.indexOf("IdentityCredential") !== -1 &&
            summary.indexOf(EXPECTED_VCT) !== -1,
    "the hand-off pane should say which credential will be requested, got: " +
        summary);
  log.info("[step1] OK — hand-off summary: " + summary);
  log.debug("Leaving stepOne().");
}

// ---------------------------------------------------------------------------
// The OIDC leg — driven by the workflow, so the only interaction is the login
// ---------------------------------------------------------------------------
async function oidcLeg(driver) {
  log.debug("Entering oidcLeg().");
  log.info("=== The OIDC Authorization Code leg ===");
  var handoffUrl = await text(driver, "handoff_url");
  assert.ok(handoffUrl.indexOf("/oauth2_oidc_1.html?sdjwtvc=1") !== -1,
    "the hand-off pane should name the URL it goes to, got: " + handoffUrl);
  await click(driver, By.id("start_issuance_button"));

  // oauth2_oidc_1.html is only a waypoint: it marks the workflow active and
  // issues the authorization request straight away, so the next thing to appear
  // is the IdP's login form.
  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "the workflow should have started the authorization request without a " +
        "further click.");
  var url = await driver.getCurrentUrl();
  assert.ok(url.indexOf(realmBase + "/protocol/openid-connect/auth") === 0,
    "the browser should be at the authorization endpoint from the " +
        "metadata, got: " + url);
  assert.ok(url.indexOf("client_id=" + encodeURIComponent(clientId)) !== -1,
    "the authorization request should carry the configured client_id, got: " +
        url);
  assert.ok(url.indexOf("response_type=code") !== -1,
    "the workflow should use the Authorization Code flow, got: " + url);
  log.info("[oidc] the authorization request started on its own and " +
           "reached the IdP.");
  await driver.findElement(By.id("username")).sendKeys(clientId);
  await driver.findElement(By.id("password")).sendKeys(clientId);
  await click(driver, By.id("kc-login"));

  // ... through oauth2_oidc_2.html, which exchanges the code and comes back.
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
    "oauth2_oidc_2.html should have exchanged the code for tokens and " +
        "returned to step 2.");
  log.info("[oidc] OK — oauth2_oidc_2.html exchanged the code and returned " +
           "to step 2.");
  log.debug("Leaving oidcLeg().");
}

// ---------------------------------------------------------------------------
// Step 2 — the tokens, the approval, and the credential request
// ---------------------------------------------------------------------------
async function stepTwo(driver) {
  log.debug("Entering stepTwo().");
  log.info("=== Step 2: approve and request the credential ===");
  await driver.wait(until.elementLocated(By.id("vc_access_token")), waitTime);
  // The fields exist before the page restores them; wait for the values.
  var accessToken = await waitForFilled(driver, "vc_access_token",
    "step 2 never showed the access token");
  var idToken = await waitForFilled(driver, "vc_id_token",
      "step 2 never showed the id token");
  assert.ok(accessToken && accessToken.split(".").length === 3,
    "step 2 should show the access token the OIDC leg obtained.");
  assert.ok(idToken && idToken.split(".").length === 3,
            "step 2 should show the ID token.");
  var idClaims = jsonFromB64u(idToken.split(".")[1]);
  assert.strictEqual(idClaims.azp, clientId,
                     "the ID token should belong to the client under test.");
  log.info("[step2] tokens present; the authenticated user is " +
           idClaims.preferred_username + ".");

  // The holder key pair is generated in the browser, before any approval.
  var holderJwk = JSON.parse(await text(driver, "vc_holder_jwk"));
  assert.strictEqual(holderJwk.kty, "EC",
                     "the holder key should be an EC key.");
  assert.strictEqual(holderJwk.crv, "P-256",
                     "the holder key should be P-256 (ES256).");
  assert.ok(!holderJwk.d,
            "the PUBLIC holder key must not carry the private component d.");
  log.info("[step2] holder key generated: " + holderJwk.kty + " " +
           holderJwk.crv + ".");

  // The whole request is built up front, so the pane shows what Approve will
  // send rather than filling in after the fact — by which point this page has
  // already handed over to step 3.
  var preview = await driver.executeScript(
    "return { nonce: document.getElementById('vc_nonce').textContent.trim()," +
    "         proof: document.getElementById('vc_proof_jwt').value," +
    "         body: " +
        "document.getElementById('vc_request_body').textContent.trim() };");
  assert.ok(preview.nonce && preview.nonce !== "—",
    "the c_nonce should be fetched and shown before approving. Got: " +
        JSON.stringify(preview.nonce));
  assert.strictEqual(preview.proof.split(".").length, 3,
    "the proof of possession should be signed and shown before " +
        "approving. Got: " + preview.proof.slice(0, 40));
  var proofHeader = jsonFromB64u(preview.proof.split(".")[0]);
  var proofClaims = jsonFromB64u(preview.proof.split(".")[1]);
  // The pane also shows that proof taken back out of the request body and
  // decoded, so the header and payload can be read without copying it anywhere.
  var decoded = await driver.executeScript(
    "return { header: document.getElementById('jwt_header').value," +
    "         payload: document.getElementById('jwt_payload').value };");
  assert.deepStrictEqual(JSON.parse(decoded.header), proofHeader,
    "the JWT Header box should be the decoded header of the proof in " +
        "proofs.jwt.");
  assert.deepStrictEqual(JSON.parse(decoded.payload), proofClaims,
    "the JWT Payload box should be the decoded payload of the proof in " +
        "proofs.jwt.");
  assert.ok(decoded.header.indexOf("\n  ") !== -1 &&
            decoded.payload.indexOf("\n  ") !== -1,
    "both should be pretty-printed.");
  log.info("[step2] OK — the proof from proofs.jwt is decoded into the JWT " +
           "Header and JWT Payload boxes.");
  assert.strictEqual(proofHeader.typ, "openid4vci-proof+jwt",
                     "the proof should carry the OID4VCI proof type.");
  assert.strictEqual(proofHeader.alg, "ES256",
                     "the proof should be signed ES256.");
  assert.deepStrictEqual(proofHeader.jwk, holderJwk,
                         "the proof should carry the holder public key.");
  assert.strictEqual(proofClaims.nonce, preview.nonce,
                     "the proof should carry the c_nonce that was fetched.");
  assert.strictEqual(proofClaims.aud, await text(driver,
                     "vc_credential_issuer"),
    "the proof's audience must be the credential issuer. Got: " +
        proofClaims.aud);
  var requestBody = JSON.parse(preview.body);
  assert.strictEqual(requestBody.credential_configuration_id,
                     "IdentityCredential",
    "the request body should name the credential being asked for.");
  assert.deepStrictEqual(requestBody.proofs.jwt, [preview.proof],
    "the request body should carry the proof shown above it.");
  log.info("[step2] OK — the c_nonce, the signed proof and the request body " +
           "are all shown before approving.");

  // The Approve pane spells out the whole call: method, URL, headers, body.
  var assembled = await value(driver, "vc_approval_request");
  assert.ok(assembled,
            "the Approve pane should show the call that Approve will make.");
  var endpoint = await text(driver, "vc_credential_endpoint");
  var firstLine = assembled.split("\n")[0];
  assert.strictEqual(firstLine, "POST " + endpoint,
    "the first line should be the method and the full URL. Got: " + firstLine);
  assert.ok(/^Content-Type: application\/json$/m.test(assembled),
    "the assembled call should show the content type. Got: " +
        assembled.slice(0, 120));
  assert.ok(assembled.indexOf("Authorization: Bearer " + (await value(driver,
            "vc_access_token"))) !== -1,
    "the assembled call should show the access token being presented as a " +
        "Bearer credential.");
  var assembledBody = JSON.parse(assembled.slice(assembled.indexOf("\n{") + 1));
  assert.deepStrictEqual(assembledBody, requestBody,
    "the body in the assembled call should be the request body shown " +
        "above it.");
  log.info("[step2] OK — the Approve pane shows the assembled call: " +
           firstLine +
           " with " + assembled.split("\n").length + " lines.");

  // Denying must send nothing at all.
  await click(driver, By.id("vc_deny_button"));
  await driver.wait(until.urlContains("vc-issuance-1.html"), waitTime,
    "denying should return to step 1.");
  var afterDeny = await driver.executeScript(
      "return localStorage.getItem('sdjwtvc_credential');");
  assert.strictEqual(afterDeny, null, "denying must not obtain a credential.");
  log.info("[step2] OK — Deny returned to step 1 with no credential.");

  // Back to step 2 to approve. The tokens are still in storage, so the page
  // stands on its own.
  await driver.get(baseUrl + "/vc-issuance-2.html");
  await driver.wait(until.elementLocated(By.id("vc_approve_button")), waitTime);
  await driver.sleep(600);
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "approving should obtain the credential and open step 3.");
  log.info("[step2] OK — approving fetched a nonce, signed a proof, and got " +
           "a credential.");
  log.debug("Leaving stepTwo().");
  return { accessToken: accessToken, holderJwk: holderJwk, idClaims: idClaims };
}

// ---------------------------------------------------------------------------
// Step 3 — the credential, checked by the page AND by this test
// ---------------------------------------------------------------------------
async function stepThree(driver, context) {
  log.debug("Entering stepThree().");
  log.info("=== Step 3: the issued credential ===");
  await driver.wait(until.elementLocated(By.id("vc_credential_raw")), waitTime);
  var raw = await waitForFilled(driver, "vc_credential_raw",
      "step 3 should show the credential");

  // ---- what the page says --------------------------------------------------
  var checks = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_checks " +
        "tbody tr')).map(function (tr) {" +
    "  var td = tr.querySelectorAll('td');" +
    "  return { name: td[0].textContent.trim(), result: " +
        "td[1].textContent.trim(), detail: td[2].textContent.trim() };" +
    "});");
  assert.ok(checks.length >= 7, "step 3 should report its checks, got " +
            checks.length + ".");
  var failed = checks.filter(function (c) { return c.result === "FAILED"; });
  assert.strictEqual(failed.length, 0,
    "no check should fail: " + failed.map(function (c) { return c.name + " — " +
        c.detail; }).join("; "));
  var signature =
      checks.filter(function (c) { return c.name === "Issuer signature"; })[0];
  assert.ok(signature && signature.result === "OK",
    "the page must verify the issuer signature against the issuer's " +
        "published keys. Got: " +
    JSON.stringify(signature));
  var binding =
      checks.filter(function (c) { return c.name === "Key binding (cnf)"; })[0];
  assert.ok(binding &&
            binding.detail.indexOf("the holder key generated in step 2") !== -1,
    "the credential must be bound to the holder key from step 2. Got: " +
        JSON.stringify(binding));
  var digests = checks.filter(function (c) {
      return c.name === "Disclosure digests"; })[0];
  assert.ok(digests && digests.result === "OK",
    "every Disclosure's digest must be found in _sd. Got: " +
        JSON.stringify(digests));
  log.info("[step3] the page's checks all pass (" + checks.length +
           " of them).");

  var disclosureRows = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_disclosures tbody tr')).map(function (tr) {" +
    "  var td = tr.querySelectorAll('td');" +
    "  return { claim: td[1].textContent.trim(), value: " +
        "td[2].textContent.trim()," +
    "           salt: td[3].textContent.trim(), digest: " +
        "td[4].textContent.trim()," +
    "           inSd: td[5].textContent.trim() };" +
    "});");
  assert.ok(disclosureRows.length >= 4,
    "the issuer offers several selectively-disclosable claims, got " +
        disclosureRows.length + ".");
  assert.ok(disclosureRows.every(function (r) { return r.inSd === "yes"; }),
    "every Disclosure shown should be matched to a digest in _sd.");
  log.info("[step3] disclosures shown: " +
           disclosureRows.map(function (r) { return r.claim; }).join(", "));

  // ---- what the CREDENTIAL says, checked here, independently ---------------
  var parts = raw.split("~");
  assert.ok(raw.endsWith("~"),
    "RFC 9901: the Combined Serialization must end in ~ when there is no Key " +
        "Binding JWT.");
  var issuerJwt = parts[0];
  var encodedDisclosures = parts.slice(1).filter(Boolean);
  var header = jsonFromB64u(issuerJwt.split(".")[0]);
  var payload = jsonFromB64u(issuerJwt.split(".")[1]);

  assert.strictEqual(header.typ, SD_JWT_VC_TYP,
                     "the issuer-signed JWT should carry typ " + SD_JWT_VC_TYP +
                     ".");
  assert.strictEqual(payload.vct, EXPECTED_VCT,
                     "the credential's vct should be the configured one.");
  assert.strictEqual(payload.iss, issuerBase,
      "the credential should be issued by the mock credential issuer.");
  assert.strictEqual(payload._sd_alg, "sha-256", "_sd_alg should be sha-256.");
  assert.ok(Array.isArray(payload._sd) &&
            payload._sd.length >= encodedDisclosures.length,
    "_sd should carry at least one digest per Disclosure.");
  assert.ok(payload.cnf && payload.cnf.jwk,
            "the credential should be bound to a holder key (cnf.jwk).");
  assert.strictEqual(payload.cnf.jwk.x, context.holderJwk.x,
    "cnf.jwk must be the holder key generated in the browser.");
  assert.strictEqual(payload.cnf.jwk.y, context.holderJwk.y,
                     "cnf.jwk must be the holder key (y).");
  assert.ok(payload.exp > Math.floor(Date.now() / 1000),
            "the credential should not already be expired.");

  // Each Disclosure hashes to a digest in _sd — recomputed here rather than
  // trusting the page's arithmetic.
  var seen = {};
  encodedDisclosures.forEach(function (enc) {
    var digest = b64u(crypto.createHash("sha256").update(enc,
        "ascii").digest());
    assert.ok(payload._sd.indexOf(digest) >= 0,
      "the digest of Disclosure " + enc + " is not in _sd.");
    var arr = JSON.parse(b64uDecode(enc).toString("utf8"));
    assert.strictEqual(arr.length, 3,
                       "an object-property Disclosure is [salt, name, value].");
    assert.ok(b64uDecode(arr[0]).length >= 16,
              "a Disclosure salt should carry at least 128 bits of entropy.");
    seen[arr[1]] = arr[2];
  });
  assert.ok(payload._sd.length > encodedDisclosures.length,
    "the issuer should add at least one decoy digest, so _sd does not reveal " +
        "the claim count.");
  log.info("[step3] the credential carries " + encodedDisclosures.length +
           " Disclosure(s) and " +
           (payload._sd.length - encodedDisclosures.length) +
            " decoy digest(s).");

  // The credential describes whoever authenticated.
  assert.ok(!("given_name" in payload),
      "given_name must NOT be a plain claim — it is selectively disclosable.");
  assert.ok("given_name" in seen && "email" in seen,
    "the credential should disclose the identity claims the issuer " +
        "advertised, got: " +
    Object.keys(seen).join(", "));
  var expectedEmail = context.idClaims.email;
  if (expectedEmail) {
    assert.strictEqual(seen.email, expectedEmail,
      "the credential should describe the user who authenticated (" +
          expectedEmail + ").");
  }
  log.info("[step3] the credential describes " + seen.email + ".");

  // The issuer's signature, verified here against its published JWKS.
  var jwtVcIssuer = await httpJson(issuerBase + "/.well-known/jwt-vc-issuer");
  assert.ok(jwtVcIssuer.ok && jwtVcIssuer.body.jwks_uri,
    "the issuer must publish JWT VC Issuer Metadata naming its jwks_uri.");
  var jwks = await httpJson(jwtVcIssuer.body.jwks_uri);
  var key = crypto.createPublicKey({ key: jwks.body.keys[0], format: "jwk" });
  var signed = issuerJwt.split(".").slice(0, 2).join(".");
  assert.ok(crypto.verify("sha256", Buffer.from(signed), key,
            b64uDecode(issuerJwt.split(".")[2])),
    "the credential's issuer signature must verify against the issuer's " +
        "published key.");
  log.info("[step3] OK — the issuer signature verifies independently of " +
           "the page.");

  // The resulting claim set is what a verifier would see.
  var claims = JSON.parse(await text(driver, "vc_claims"));
  assert.ok(!("_sd" in claims) && !("_sd_alg" in claims),
    "the resulting claim set should not carry the SD-JWT machinery.");
  Object.keys(seen).forEach(function (name) {
    assert.deepStrictEqual(claims[name], seen[name],
      "the resulting claim set should include the disclosed claim " + name +
          ".");
  });
  log.info("[step3] OK — the resulting claim set matches the disclosures.");
  log.debug("Leaving stepThree().");
}

// ---------------------------------------------------------------------------
// Step 4 — refreshing the credential (OID4VCI section 14.5)
//
// Two calls: the Refresh Token for a fresh Access Token (RFC 6749 section 6),
// then the Credential Endpoint again. Neither involves the End-User, which is
// the whole point of the mechanism.
//
// What is actually being tested is not "a credential came back" — the issuer
// would return one for any well-formed request — but that the page reports
// truthfully what the issuer DID: section 14.5 leaves it to the issuer whether
// the claim values change, the signature changes, or nothing does, and a wallet
// that guesses instead of comparing is what this catches. The two credentials
// are therefore compared here as well, independently of the page.
// ---------------------------------------------------------------------------
async function stepFour(driver, context) {
  log.debug("Entering stepFour().");
  log.info("=== Step 4: refresh the credential ===");

  // Step 3 has to offer the way in; a page that can be reached only by typing
  // its URL is not part of the workflow.
  var before = await driver.executeScript(
    "return { credential: localStorage.getItem('sdjwtvc_credential')," +
    "         accessToken: localStorage.getItem('token_access_token')," +
    "         refreshToken: localStorage.getItem('token_refresh_token')," +
    "         holderJwk: localStorage.getItem('sdjwtvc_holder_jwk') };");
  assert.ok(before.refreshToken,
    "the OIDC leg should have obtained a refresh token; without one there is " +
        "nothing to refresh with.");
  await click(driver, By.id("vc_goto_refresh_button"));
  await driver.wait(until.urlContains("vc-issuance-4.html"), waitTime,
    "step 3 should offer a way to step 4.");
  await driver.wait(until.elementLocated(By.id("vc_refresh_request")),
                    waitTime);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_reissue_proof"));
  }, fetchWait, "step 4 should build the Credential Request on load, the way " +
      "step 2 does.");

  // ---- the credential in hand ---------------------------------------------
  var held = await driver.executeScript(
    "return { validity: " +
        "document.getElementById('vc_current_validity').textContent.trim()," +
    "         binding: " +
        "document.getElementById('vc_current_binding').textContent.trim()," +
    "         status: " +
        "document.getElementById('vc_current_status').textContent.trim() };");
  assert.ok(/exp /.test(held.validity) &&
            /expires|EXPIRED|does not expire/.test(held.validity),
    "the pane should say when the credential in hand expires. Got: " +
        held.validity);
  assert.ok(/the holder key this browser generated/.test(held.binding),
    "and that its private key is here, since a refresh in place needs " +
        "it. Got: " + held.binding);
  log.info("[step4] holding: " + held.validity);

  // ---- the refresh call, before it is sent --------------------------------
  var refreshCall = await value(driver, "vc_refresh_request");
  var tokenEndpoint = await driver.executeScript(
      "return localStorage.getItem('token_endpoint');");
  assert.strictEqual(refreshCall.split("\n")[0], "POST " + tokenEndpoint,
    "the first line should be the method and the token endpoint. Got: " +
        refreshCall.split("\n")[0]);
  assert.ok(/^Content-Type: application\/x-www-form-urlencoded$/m.test(
            refreshCall),
    "a Token Request is form-encoded. Got: " + refreshCall);
  var refreshBody =
      new URLSearchParams(refreshCall.slice(refreshCall.indexOf("\n\n") + 2));
  assert.strictEqual(refreshBody.get("grant_type"), "refresh_token",
    "the grant must be refresh_token. Got: " + refreshBody.get("grant_type"));
  assert.strictEqual(refreshBody.get("refresh_token"), before.refreshToken,
    "the refresh token in the call should be the one the OIDC leg obtained.");
  assert.strictEqual(refreshBody.get("client_id"), clientId,
    "a public client identifies itself on the refresh. Got: " +
        refreshBody.get("client_id"));
  assert.strictEqual(refreshBody.get("client_secret"), null,
    "no client_secret is configured, so none should be invented.");
  log.info("[step4] the refresh call is assembled: " +
           refreshCall.split("\n")[0] +
           " with " + Array.from(refreshBody.keys()).join(", "));

  // ---- the Credential Request, before it is sent ---------------------------
  var reissue = await driver.executeScript(
    "return { nonce: " +
        "document.getElementById('vc_reissue_nonce').textContent.trim()," +
    "         proof: document.getElementById('vc_reissue_proof').value," +
    "         body: " +
        "document.getElementById('vc_reissue_body').textContent.trim()," +
    "         call: document.getElementById('vc_reissue_request').value };");
  var proofHeader = jsonFromB64u(reissue.proof.split(".")[0]);
  var proofClaims = jsonFromB64u(reissue.proof.split(".")[1]);
  assert.strictEqual(proofHeader.typ, "openid4vci-proof+jwt",
                     "the proof carries the OID4VCI proof type.");
  assert.strictEqual(proofHeader.alg, "ES256", "the proof is signed ES256.");
  assert.deepStrictEqual(proofHeader.jwk, JSON.parse(before.holderJwk),
    "reusing the bound key means the proof carries the holder key the " +
        "credential already uses.");
  assert.strictEqual(proofClaims.nonce, reissue.nonce,
    "the proof should carry the c_nonce shown above it.");
  assert.strictEqual(proofClaims.aud, issuerBase,
                     "the proof's audience is the credential issuer.");
  assert.notStrictEqual(reissue.nonce, "",
    "a fresh c_nonce is needed: the one step 2 used was spent on the " +
        "original issuance.");
  assert.strictEqual(JSON.parse(reissue.body).credential_configuration_id,
                     VCI_CONFIG_ID,
    "the request names the same credential — a refresh is not a way to ask " +
        "for a different one.");
  assert.ok(reissue.call.indexOf("Authorization: Bearer " +
            before.accessToken) !== -1,
    "the assembled call should present the access token in hand.");
  log.info("[step4] the Credential Request is assembled with a fresh c_nonce " +
           "and a proof for the bound key.");

  // ---- send the refresh ---------------------------------------------------
  await click(driver, By.id("vc_refresh_button"));
  var refreshStatus = await waitForStatus(driver, "vc_refresh_status",
    function (s) { return /fresh access token|refused|failed/.test(s); },
    "the refresh produced no verdict");
  assert.ok(/fresh access token/.test(refreshStatus),
    "the refresh should succeed. Got: " + refreshStatus);
  var afterRefresh = await driver.executeScript(
    "return { accessToken: localStorage.getItem('token_access_token')," +
    "         refreshToken: localStorage.getItem('token_refresh_token') };");
  assert.notStrictEqual(afterRefresh.accessToken, before.accessToken,
    "a refresh has to produce a different access token, or nothing was " +
        "refreshed.");
  assert.ok(jsonFromB64u(afterRefresh.accessToken.split(".")[1]).iat >=
            jsonFromB64u(before.accessToken.split(".")[1]).iat,
    "the new access token should not be older than the one it replaces.");
  // Whether the refresh token rotates is the server's choice; the page has to
  // report which happened rather than assume one.
  var rotated = afterRefresh.refreshToken !== before.refreshToken;
  assert.ok(rotated ?
      /rotated/.test(refreshStatus) : /same refresh token/.test(refreshStatus),
    "the page should say whether the refresh token rotated (it " + (rotated ?
        "did" : "did not") +
    "). Got: " + refreshStatus);
  // And the call being shown must have been updated to the new state.
  assert.ok((await value(driver, "vc_reissue_request"))
              .indexOf("Authorization: Bearer " +
                  afterRefresh.accessToken) !== -1,
    "the Credential Request should now present the refreshed access token.");
  log.info("[step4] OK — refreshed the access token" + (rotated ?
           " and the refresh token." : "."));

  // ---- ask the Credential Endpoint again ----------------------------------
  await click(driver, By.id("vc_reissue_button"));
  var reissueStatus = await waitForStatus(driver, "vc_reissue_status",
    function (s) { return /returned a credential|refused|failed|not ready/.test(
              s); },
    "the Credential Request produced no verdict");
  assert.ok(/returned a credential/.test(reissueStatus),
    "the issuer should return a refreshed credential. Got: " + reissueStatus);
  // Nothing may have been replaced yet: that decision is the holder's.
  var stillHeld = await driver.executeScript(
      "return localStorage.getItem('sdjwtvc_credential');");
  assert.strictEqual(stillHeld, before.credential,
    "the credential in hand must not be overwritten before the holder " +
        "chooses (section 14.5).");
  var refreshed = await value(driver, "vc_compare_refreshed_raw");
  assert.ok(refreshed && refreshed !== before.credential,
    "the refreshed credential should be a different credential.");

  // ---- what the page says changed, checked against the credentials ---------
  var rows = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_compare_table tbody tr'))" +
    "  .map(function (tr) {" +
    "    var td = tr.querySelectorAll('td');" +
    "    return { name: td[0].textContent.trim(), before: " +
        "td[1].textContent.trim()," +
    "             after: td[2].textContent.trim(), changed: " +
        "td[3].textContent.trim() };" +
    "  });");
  function row(name) {
    log.debug("Entering row().");
    log.debug("Leaving row().");
    return rows.filter(function (r) { return r.name === name; })[0];
  }
  assert.ok(rows.length >= 8,
            "the comparison should cover the members that can change, got " +
            rows.length);
  assert.strictEqual(row("Issuer signature").changed, "yes",
    "a reissued credential is signed again, so the signature must be " +
        "reported as changed.");
  assert.strictEqual(row("Bound key (cnf.jwk)").changed, "no",
    "reusing the holder key means the binding must be reported as unchanged.");
  assert.strictEqual(row("vct").changed, "no",
                     "a refresh returns the same kind of credential.");

  var oldPayload = jsonFromB64u(before.credential.split("~")[0].split(".")[1]);
  var newPayload = jsonFromB64u(refreshed.split("~")[0].split(".")[1]);
  assert.notStrictEqual(before.credential.split("~")[0].split(".")[2],
                        refreshed.split("~")[0].split(".")[2],
    "the two credentials should carry different signatures.");
  assert.deepStrictEqual(newPayload.cnf, oldPayload.cnf,
    "the refreshed credential should be bound to the same holder key.");
  assert.strictEqual(newPayload.vct, oldPayload.vct,
                     "and be the same credential type.");
  assert.strictEqual(newPayload.sub, oldPayload.sub,
                     "and describe the same subject.");

  // The salts — and therefore every Disclosure — are new whatever else changed,
  // and the page has to say so rather than reporting them as changed claims.
  var oldDisclosures = before.credential.split("~").slice(1).filter(Boolean);
  var newDisclosures = refreshed.split("~").slice(1).filter(Boolean);
  assert.strictEqual(newDisclosures.length, oldDisclosures.length,
    "the same claims should be disclosable in the refreshed credential.");
  newDisclosures.forEach(function (d) {
    assert.strictEqual(oldDisclosures.indexOf(d), -1,
      "every Disclosure should be freshly salted, so none should be " +
          "byte-identical to an old one.");
  });
  function claimsOf(parts) {
    log.debug("Entering claimsOf().");
    var out = {};
    parts.forEach(function (enc) {
      var arr = JSON.parse(b64uDecode(enc).toString("utf8"));
      if (arr.length === 3) out[arr[1]] = arr[2];
    });
    log.debug("Leaving claimsOf().");
    return out;
  }
  assert.deepStrictEqual(claimsOf(newDisclosures), claimsOf(oldDisclosures),
    "this issuer refreshes the signature, not the End-User's data, so the " +
        "claim VALUES should be identical.");
  var verdict = await text(driver, "vc_compare_status");
  assert.ok(/only the signature|claim value\(s\) changed/.test(verdict),
    "the verdict should say which of section 14.5's two cases this was. Got: " +
        verdict);
  assert.ok(/only the signature/.test(verdict),
    "with identical claim values it is the \"only the signature\" case. Got: " +
        verdict);
  var claimDiff = await text(driver, "vc_compare_claims");
  assert.ok(/Not one disclosed claim VALUE differs/.test(claimDiff),
    "and the claim comparison should say the values are unchanged rather " +
        "than listing new salts. Got: " +
    claimDiff.slice(0, 120));
  log.info("[step4] verdict: " + verdict);

  // The refreshed credential must verify on its own terms, checked here rather
  // than taken from the page.
  var jwtVcIssuer = await httpJson(issuerBase + "/.well-known/jwt-vc-issuer");
  var jwks = await httpJson(jwtVcIssuer.body.jwks_uri);
  var key = crypto.createPublicKey({ key: jwks.body.keys[0], format: "jwk" });
  var signedPart = refreshed.split("~")[0].split(".").slice(0, 2).join(".");
  assert.ok(crypto.verify("sha256", Buffer.from(signedPart), key,
                          b64uDecode(refreshed.split("~")[0].split(".")[2])),
    "the refreshed credential's issuer signature must verify against the " +
        "issuer's published key.");
  newDisclosures.forEach(function (enc) {
    assert.ok(newPayload._sd.indexOf(b64u(crypto.createHash("sha256")
              .update(enc, "ascii").digest())) >= 0,
      "every Disclosure of the refreshed credential must hash to a digest " +
          "in its _sd.");
  });
  log.info("[step4] OK — the refreshed credential verifies independently of " +
           "the page.");

  // ---- the history pane must react to the RETRIEVAL, not only to keeping ---
  // A credential the issuer has just returned is in the pane immediately,
  // marked as not kept: a history that only moves when something is kept looks
  // broken, which is what a manual run of this page found.
  var pendingRow = await driver.executeScript(
    "var tr = document.querySelector('#vc_history_table tbody " +
        "tr.vc-history-pending');" +
    "if (!tr) return null;" +
    "var td = tr.querySelectorAll('td');" +
    "return { n: td[0].textContent.trim(), gen: td[1].textContent.trim()," +
    "         attempt: td[3].textContent.trim(), outcome: " +
        "td[4].textContent.trim()," +
    "         detail: td[5].textContent.trim()," +
    "         buttons: " +
        "Array.prototype.slice.call(td[7].querySelectorAll('input'))" +
    "                    .map(function (b) { return b.value; }) };");
  assert.ok(pendingRow, "the credential just returned should appear in the " +
            "Credential History pane at once.");
  assert.strictEqual(pendingRow.attempt, "Credential Request",
    "the row should name what was attempted. Got: " + pendingRow.attempt);
  assert.ok(/not kept yet/.test(pendingRow.outcome),
    "and its outcome should say it is not kept. Got: " + pendingRow.outcome);
  assert.ok(/^[0-9]+$/.test(pendingRow.n),
    "every row is numbered by attempt, including this one. Got: " +
        pendingRow.n);
  assert.strictEqual(pendingRow.gen, "—",
                     "but it has no generation number until it is kept.");
  assert.deepStrictEqual(pendingRow.buttons, ["Keep", "Discard"],
    "and it should be actionable from the pane. Got: " +
        JSON.stringify(pendingRow.buttons));
  assert.ok(/waiting to be kept/.test(await text(driver,
            "vc_history_position")),
    "the position should say something is waiting. Got: " + (await text(driver,
        "vc_history_position")));

  // The access-token refresh above must be in the log too — every attempt is.
  var logRows = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_history_table tbody tr'))" +
    "  .map(function (tr) {" +
    "    var td = tr.querySelectorAll('td');" +
    "    return { n: td[0].textContent.trim(), gen: td[1].textContent.trim()," +
    "             attempt: td[3].textContent.trim(), outcome: " +
        "td[4].textContent.trim()," +
    "             detail: td[5].textContent.trim() };" +
    "  });");
  // Every row carries an attempt number — the first column is never blank.
  assert.ok(logRows.every(function (r) { return /^[0-9]+$/.test(r.n); }),
    "every row should be numbered in the first column. Got: " +
    JSON.stringify(logRows.map(function (r) { return r.n; })));
  assert.deepStrictEqual(logRows.map(function (r) { return Number(r.n); }),
    logRows.map(function (r, i) { return logRows.length - i; }),
    "and numbered by attempt order, newest first.");
  var tokenRows = logRows.filter(function (r) {
      return r.attempt === "Access token refresh"; });
  assert.strictEqual(tokenRows.length, 1,
    "the access token refresh should be one row in the log. Got: " +
        JSON.stringify(logRows));
  assert.strictEqual(tokenRows[0].outcome, "success",
                     "and be recorded as a success.");
  assert.ok(/access token/.test(tokenRows[0].detail),
    "with what came back. Got: " + tokenRows[0].detail);
  assert.strictEqual(tokenRows[0].gen, "—",
                     "a token refresh is not a credential generation.");
  log.info("[step4] OK — the history records every attempt: " +
           logRows.map(function (r) { return r.attempt + "/" +
                       r.outcome; }).join(", "));

  // ---- keep it ------------------------------------------------------------
  // Keeping does not navigate: the pane the holder acted in is the pane that
  // has to show what the action did.
  await click(driver, By.id("vc_replace_button"));
  await driver.wait(async function () {
    return /^generation 2 of 2/.test(await text(driver, "vc_history_position"));
  }, fetchWait, "keeping the credential should add a generation to the " +
      "history, in place.");
  assert.ok((await driver.getCurrentUrl()).indexOf("vc-issuance-4.html") !== -1,
    "and should stay on step 4 rather than navigating away from the pane it " +
        "just changed.");
  var afterKeep = await driver.executeScript(
    "return { pending: document.querySelectorAll('#vc_history_table tbody " +
        "tr.vc-history-pending').length," +
    "         rows: document.querySelectorAll('#vc_history_table tbody " +
        "tr').length," +
    "         outcome: (document.querySelector('#vc_history_table tbody " +
        "tr.vc-history-active td:nth-child(5)')" +
    "                    || {}).textContent," +
    "         inHand: (document.querySelector('#vc_history_table tbody " +
        "tr.vc-history-active td:nth-child(2)')" +
    "                   || {}).textContent," +
    "         status: " +
        "document.getElementById('vc_history_status').textContent.trim() };");
  assert.strictEqual(afterKeep.pending, 0,
                     "the waiting row should have become a generation.");
  assert.strictEqual(afterKeep.rows, logRows.length,
    "keeping resolves that attempt's row rather than adding another — one " +
        "row per attempt. Got " +
    afterKeep.rows + " rows, was " + logRows.length);
  assert.strictEqual(String(afterKeep.outcome).trim(), "kept",
    "and its outcome should now read kept. Got: " + afterKeep.outcome);
  assert.strictEqual(String(afterKeep.inHand).trim(), "2",
    "and generation 2 should be the one in hand. Got: " + afterKeep.inHand);
  assert.ok(/go back to it/.test(afterKeep.status),
    "the pane should say the replaced generation is still there. Got: " +
        afterKeep.status);
  // The credential in hand changed, so the request this page would send next
  // has to be rebuilt against it.
  await waitForStatus(driver, "vc_reissue_status",
                      function (s) { return /^Kept/.test(s); },
    "the request should be rebuilt for the credential now in hand");
  log.info("[step4] OK — keeping it updated the history in place: " +
           afterKeep.status);

  await click(driver, By.id("vc_goto_step3_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "\"Verify in step 3\" should open step 3.");
  await driver.sleep(900);
  var promoted = await driver.executeScript(
    "return { held: localStorage.getItem('sdjwtvc_credential')," +
    "         previous: localStorage.getItem('sdjwtvc_previous_credential')," +
    "         pending: localStorage.getItem('sdjwtvc_refreshed_credential')," +
    "         meta: localStorage.getItem('sdjwtvc_credential_meta') };");
  assert.strictEqual(promoted.held, refreshed,
                     "the wallet should now hold the refreshed credential.");
  assert.strictEqual(promoted.previous, before.credential,
    "the credential it replaced should be kept, or 'what changed' has " +
        "nothing to compare against.");
  assert.strictEqual(promoted.pending, null,
    "and the pending refresh should be consumed rather than left to be " +
        "promoted twice.");
  assert.strictEqual(JSON.parse(promoted.meta).refreshGeneration, 1,
    "the metadata should record that this credential is a refresh.");
  assert.strictEqual(await value(driver, "vc_credential_raw"), refreshed,
    "step 3 should now show the refreshed credential.");
  await assertStepThreeIsHappy(driver, "the refreshed credential");
  assert.ok(/refreshed 1 time/.test(await text(driver, "vc_meta_request")),
    "step 3 should say this credential is a refresh rather than reading as " +
        "the original issuance.");
  log.info("[step4] OK — the refreshed credential was kept, and step 3 " +
           "verifies it.");
  // Handed to the history section, which checks that going back to generation 1
  // really restores this credential AND the key it is bound to.
  log.debug("Leaving stepFour().");
  return { original: before.credential, refreshed: refreshed,
          holderJwk: before.holderJwk };
}

// ---------------------------------------------------------------------------
// Every page of the workflow links to every step, at the top, on ONE row.
//
// The row is shared markup (partials/vc_steps.html), so what can break is the
// layout: five items in a flex row that is allowed to wrap put the last step on
// a second line, which is what happened when step 4 was added. "One row" is a
// geometric claim, so it is checked geometrically — every item on the same top
// edge — rather than by looking at the CSS.
// ---------------------------------------------------------------------------
// The DID Configuration pane (DIF Well Known DID Configuration), modelled on
// the authorization server pane: a URL, Retrieve, Upload, Clear, a table, the
// values pushed into Configuration Parameters, and a schema report.
//
// What makes it worth a section of its own is that this document can be checked
// two ways that do not imply each other, and the pane does both:
//
//   * the SCHEMA — is it well formed. Transcribed rules, covered exhaustively
//     (and cheaply) by tests/metadata_schema_validation.js; here it is checked
//     that the pane runs them and shows the result.
//   * the LINKAGE — is it TRUE. Resolve the DID it names, verify the
//     credential's signature against the keys that DID authorises to assert,
//     and check the origin it claims is the origin it came from.
//
// The case that earns the section is a document that passes the first and fails
// the second: perfectly well formed, retrieved from an origin it does not name.
// A pane that ran only the schema check would call it good. Save the whole of
// localStorage, and give back a function that puts it back.
//
// Sections that run AFTER the workflow and need a clean page to measure must
// restore what they cleared: later sections run on the state the workflow left
// behind, and presentationHandoff() in particular asserts that a credential is
// still there to hand off. metadataSignatureValidation() and
// presentationHandoff() already did this by hand; the two sections below share
// this one so they cannot drift apart in how they do it.
//
// This is the convention for this file and it is not optional — clearing
// without restoring fails a LATER section, several hundred lines away, with a
// message about a missing credential that says nothing about who removed it.
async function preservingLocalStorage(driver) {
  log.debug("Entering preservingLocalStorage().");
  var saved = await driver.executeScript(
    "var out = {};" +
    "for (var i = 0; i < localStorage.length; i++) { var k = " +
        "localStorage.key(i); out[k] = localStorage.getItem(k); }" +
    "return out;");
  log.debug("Leaving preservingLocalStorage(). " + Object.keys(saved).length +
            " key(s) held.");
  return async function () {
    await driver.executeScript(
      "localStorage.clear();" +
      "var o = arguments[0];" +
      "Object.keys(o).forEach(function (k) { localStorage.setItem(k, " +
          "o[k]); });", saved);
    log.debug("localStorage restored: " + Object.keys(saved).length +
              " key(s).");
  };
}

async function didConfigurationPane(driver) {
  log.debug("Entering didConfigurationPane().");
  log.info("=== The DID Configuration pane ===");
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("didcfg_url")), waitTime * 4);
  // This section needs an empty pane to measure, and the sections after it need
  // the credential the workflow issued. See preservingLocalStorage().
  var restoreStorage = await preservingLocalStorage(driver);
  await driver.executeScript("localStorage.clear();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("didcfg_url")), waitTime * 4);

  // The resource's path is fixed by the specification, so the pane should offer
  // the URL once it knows the issuer's origin rather than asking for it.
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];",
    issuerMetadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (t) { return /^Retrieved/.test(t); },
              "the credential issuer metadata did not load");
  var offered = await value(driver, "didcfg_url");
  assert.ok(/\/\.well-known\/did-configuration\.json$/.test(offered),
    "retrieving the issuer metadata should offer the DID Configuration URL — " +
        "its path is fixed by " +
    'the specification, so only the origin was ever unknown. Got "' + offered +
        '".');

  await click(driver, By.id("didcfg_retrieve_button"));
  var loaded = await waitForStatus(driver, "didcfg_status",
    function (t) { return /^Retrieved|^Could not/.test(t); },
              "the DID Configuration did not load");
  assert.ok(/^Retrieved a DID Configuration linking \d+ DID\(s\)/.test(loaded),
    "the pane should say what it loaded and how many DIDs it links. Got: " +
        loaded);
  var report = await driver.executeScript(
    "return document.getElementById('didcfg_schema_report').textContent;");
  assert.ok(/satisfies every rule/.test(report),
    "and the STS's own document should satisfy every rule the specification " +
        "states. Got: " +
    report.slice(0, 200));

  // The new Configuration Parameters section: the resource's two members plus
  // the facts derived from the credential, which are otherwise buried in a JWT.
  var expected = {
    "didcfg_@context": /^https:\/\/identity\.foundation\/\.well-known\/did-configuration\/v1$/,
    didcfg_linked_did: /^did:web:/,
    didcfg_origin: /^https?:\/\//,
    didcfg_credential_form: /^JWT$|^Linked Data Proof$/,
    didcfg_verification_method: /#/,
    didcfg_valid_from: /\d{4}-\d\d-\d\d|^\d+$/,
    didcfg_valid_until: /\d{4}-\d\d-\d\d|^\d+$/
  };
  for (var id of Object.keys(expected)) {
    var v = await value(driver, id);
    assert.ok(expected[id].test(String(v || "")),
      "the DID Configuration section of Configuration Parameters " +
          "should carry " + id + "; got " +
      JSON.stringify(v));
  }
  assert.ok(String(await value(driver, "didcfg_linked_dids") ||
            "").indexOf("[") === 0,
    "and linked_dids itself, as the JSON the resource carries.");
  log.info("[didcfg] OK — retrieved, schema-checked, and the Configuration " +
           "section populated.");

  // The linkage: the check the schema cannot make.
  await click(driver, By.id("didcfg_verify_button"));
  var linked = await waitForStatus(driver, "didcfg_status",
    function (t) { return /^LINKED|^NOT LINKED|^The linkage/.test(t); },
    "Verify Linkage produced no verdict");
  assert.ok(/^LINKED:/.test(linked),
    "the STS publishes a Domain Linkage Credential for its own DID at its " +
        "own origin, so this must " +
    "come back linked. Got: " + linked);
  var checks = await driver.executeScript(
    "return document.getElementById('didcfg_verify_table').textContent;");
  assert.ok(/Issuer signature/.test(checks) && /Origin/.test(checks),
    "and the per-check table should show which checks passed, not just " +
        "a verdict.");
  log.info("[didcfg] OK — the linkage verifies, check by check.");

  // Well formed, and not true: the same document read from an origin it does
  // not name. This is the pair of checks doing different work.
  //
  // The wrong origin is http rather than https ON PURPOSE. This pane derives
  // the scheme for resolving the linked did:web from the origin it is checking
  // against — did:web mandates https and this project's stacks do not have it —
  // so an https origin here would make the DID resolve over https to a
  // plain-HTTP STS, fail with ERR_SSL_PROTOCOL_ERROR, and be counted by
  // severeErrors() as a browser error that fails the whole run. The scheme is
  // not what this case is about: the ORIGIN MISMATCH is, and an http origin
  // exercises exactly that.
  await driver.executeScript(
    "document.getElementById('didcfg_url').value = " +
        "'http://somewhere.else.example" +
    "/.well-known/did-configuration.json';");
  await click(driver, By.id("didcfg_verify_button"));
  var wrong = await waitForStatus(driver, "didcfg_status",
    function (t) { return /^LINKED|^NOT LINKED|^The linkage/.test(t); },
    "no verdict for the wrong-origin case");
  assert.ok(/^NOT LINKED/.test(wrong),
    "a document is not linked to an origin it does not name, however well " +
        "formed it is — this is the " +
    "case a schema check alone would pass. Got: " + wrong);
  var stillClean = await driver.executeScript(
    "return document.getElementById('didcfg_schema_report').textContent;");
  assert.ok(/satisfies every rule/.test(stillClean),
    "and the schema verdict should still say the document is well formed: " +
        "the two checks answer " +
    "different questions and must not be conflated.");
  log.info("[didcfg] OK — a well-formed document read from the wrong origin " +
           "is NOT linked.");

  await click(driver, By.id("didcfg_clear_button"));
  await driver.sleep(300);
  assert.strictEqual(await value(driver, "didcfg_linked_did"), "",
    "Clear should empty the Configuration section it populated.");
  assert.strictEqual(await value(driver, "didcfg_url"), "",
    "and the URL field.");
  log.info("[didcfg] OK — Clear empties the pane and its " +
           "Configuration section.");

  await restoreStorage();
  log.debug("Leaving didConfigurationPane().");
}

// Step 0 is a CHOOSER, and a chooser that scrolls cannot do its job: you cannot
// compare four options by scrolling between them. So everything it offers — the
// four use-case cards, the selected-use-case line, and the VC Tools pane at the
// foot — has to be visible at once on an ordinary laptop.
//
// It did not start that way. Four full-width cards stacked in a 1100px column
// ran to 757px of the page's 1450px total, against a viewport of 839px on a
// 1512x982 display, while the horizontal space beyond the cards sat empty. The
// fix was a grid plus a denser vertical rhythm scoped to that page (.vc-fit in
// css/sd_jwt_vc.css); this is what stops the next paragraph or use case quietly
// undoing it.
//
// Measured at 839px of VIEWPORT height, which is what a 1512x982 screen leaves
// after the browser's own chrome — note that setRect() sets the OUTER height,
// so the window is opened at 982 to get 839 inside it. Headless has no toolbar,
// so measuring the window height rather than the viewport would flatter the
// result by ~143px.
//
// The FOOTER is deliberately not included: it is 200px of shared site furniture
// on every page in the project, and requiring it above the fold would be a
// constraint on the footer rather than on this page.
// ---------------------------------------------------------------------------
// Step 1's metadata panes sit FOUR ACROSS in one row, and the row's height must
// not depend on what has been retrieved into it.
//
// The row is what makes the page usable without scrolling: stacked full-width,
// its four discovery panes spent 1,234px on content that fits in a quarter of
// the width. But a quarter of the width wraps every value over several lines,
// and a row is as tall as its tallest pane — the credential issuer metadata
// document measured 23,299px in a 287px pane against roughly 4,000 at full
// width, so ONE retrieved document made the page TEN TIMES longer than the
// layout the row replaced. That is the failure this section exists for, and it
// is invisible on an empty page: every geometry check here passed before the
// ceiling was added, because nothing had been retrieved yet. So the panes are
// filled first and measured second.
//
// Checked, in order of what has actually gone wrong:
//   * the four panes are on ONE row at a desktop width (a fold means the grid's
//     minmax no longer fits, and the page silently doubles in height)
//   * with all four documents loaded, each pane still CONTAINS its table, and
//     the row is bounded — the assertion the ceiling exists for
//   * no member name in the Configuration Parameters columns overlaps its
//     input. At a third of the width a 40-character identifier with no break
//     opportunity ran straight over the field beside it and BOTH were
//     unreadable, which no height or containment check can see.
async function stepOneFitsInOneRow(driver) {
  log.debug("Entering stepOneFitsInOneRow().");
  log.info("=== Step 1's metadata panes, four across, bounded ===");
  var before = await driver.manage().window().getRect();
  await driver.manage().window().setRect({ width: 1512, height: 982 });
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("didcfg_url")), waitTime * 4);
  // Measured empty first and populated second, so the workflow's own state has
  // to be put back before the sections that need it. See
  // preservingLocalStorage().
  var restoreStorage = await preservingLocalStorage(driver);
  await driver.executeScript("localStorage.clear();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("didcfg_url")), waitTime * 4);
  await driver.sleep(300);

  var MEASURE =
    "var ids = ['pane_vci','pane_did','pane_as','pane_didcfg'];" +
    "var doc = document.documentElement;" +
    "var row = document.querySelector('.vc-pane-row');" +
    "var tops = [], panes = [];" +
    "ids.forEach(function (id) {" +
    "  var p = document.getElementById(id), pr = p.getBoundingClientRect();" +
    "  var top = Math.round(pr.top + window.scrollY);" +
    "  if (tops.indexOf(top) === -1) tops.push(top);" +
    "  var over = 0, tables = 0;" +
    "  Array.prototype.slice.call(p.querySelectorAll('*')).forEach(function (el) {" +
    "    var r = el.getBoundingClientRect();" +
    "    if (r.width) over = Math.max(over, Math.round(r.right - pr.right));" +
    "  });" +
    "  Array.prototype.slice.call(p.querySelectorAll('.discovery_info_table table'))" +
    "    .forEach(function () { tables++; });" +
    "  panes.push({ id: id, w: Math.round(pr.width), h: " +
        "Math.round(pr.height)," +
    "               over: over, tables: tables });" +
    "});" +
    "return { panes: panes, lines: tops.length," +
    "         rowHeight: Math.round(row.getBoundingClientRect().height)," +
    "         sideways: doc.scrollWidth > doc.clientWidth + 2 };";

  var empty = await driver.executeScript(MEASURE);
  assert.strictEqual(empty.lines, 1,
    "step 1's four metadata panes should be on ONE row at 1512px — " +
        "they are on " +
    empty.lines + " lines, so the grid folded and the page is about " +
    "1,200px taller than it needs to be. Widths: " +
    empty.panes.map(function (p) { return p.id + "=" + p.w; }).join(", "));
  assert.strictEqual(empty.sideways, false,
    "and the row must not have bought that height with sideways scroll.");

  // Now fill all four, which is the state the ceiling exists for.
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];",
    issuerMetadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (t) { return /^Retrieved/.test(t); },
              "the credential issuer metadata did not load");
  await click(driver, By.id("didcfg_retrieve_button"));
  await waitForStatus(driver, "didcfg_status",
    function (t) { return /^Retrieved|^Could not/.test(t); },
              "the DID Configuration did not load");
  var didOrigin = issuerMetadataUrl.replace(/\/\.well-known\/.*$/, "");
  await driver.executeScript(
    "document.getElementById('did_resolution_url').value = arguments[0];",
    didOrigin + "/.well-known/did.json");
  await click(driver, By.id("did_retrieve_button"));
  await waitForStatus(driver, "did_status",
    function (t) { return /^Retrieved|^Could not|^That/.test(t); },
              "the DID document did not load");

  var full = await driver.executeScript(MEASURE);
  var loaded = full.panes.filter(function (p) { return p.tables > 0; });
  assert.ok(loaded.length >= 3,
    "this section proves nothing unless the panes actually hold " +
        "documents: only " +
    loaded.length + " of 4 rendered a table. " +
    full.panes.map(function (p) { return p.id + "=" + p.tables; }).join(", "));
  full.panes.forEach(function (p) {
    assert.ok(p.over <= 2,
      p.id + " lets its content out of the pane by " + p.over +
          "px once a document is " +
      "loaded. At a quarter of the width the values are base64url and long " +
          "member names, " +
      "so a table that is not table-layout: fixed sizes itself to its " +
          "longest line.");
  });
  assert.strictEqual(full.lines, 1,
    "and the four panes must STAY on one row once they hold documents; " +
        "they are on " +
    full.lines + " lines.");
  assert.ok(full.rowHeight <= 1100,
    "the row is " + full.rowHeight +
        "px tall with all four documents loaded. Each pane's " +
    "retrieved-document table is meant to be bounded and scrolled, because " +
        "the row is as " +
    "tall as its tallest pane: unbounded, the credential issuer metadata " +
        "alone measured " +
    "23,299px here and the page came to 25,846px — ten times the stacked " +
        "layout this row " +
    "replaced. The readable full-width rendering of the same values is the " +
        "Configuration " +
    "Parameters pane below.");

  // The Configuration Parameters columns: a name must not sit on top of its
  // value.
  //
  // Measured FRAGMENT BY FRAGMENT, which is the whole difficulty. This pane is
  // a CSS multi-column layout, so an element that crosses a column break is
  // laid out as two boxes in two different columns — and
  // getBoundingClientRect(), on both the element and a Range, returns the UNION
  // of those boxes. A wrapped member name split across a break therefore
  // reports a rect running from the left of one column to the right of the
  // next, which duly "overlaps" its input and reads as exactly the defect this
  // check is for, while nothing whatsoever is overlapping. That false positive
  // is not hypothetical: it is what this assertion reported before
  // .vc-config-table td got `break-inside: avoid`. Comparing the individual
  // client rects instead means an overlap has to be real — the two boxes must
  // meet on BOTH axes, i.e. be on the same line in the same column.
  var overlap = await driver.executeScript(
    "var bad = [];" +
    "var fragmented = [];" +
    "Array.prototype.slice.call(document.querySelectorAll('#config_rows " +
        "tr')).forEach(function (tr) {" +
    "  var td = tr.children[0];" +
    "  var field = tr.querySelector('input, textarea, select');" +
    "  if (!td || !field) return;" +
    "  var fieldRects = Array.prototype.slice.call(field.getClientRects())" +
    "    .filter(function (r) { return r.width > 0; });" +
    "  if (!fieldRects.length) return;" +
    "  var range = document.createRange();" +
    "  range.selectNodeContents(td);" +
    "  var textRects = Array.prototype.slice.call(range.getClientRects())" +
    "    .filter(function (r) { return r.width > 0; });" +
    "  range.detach();" +
    "  if (!textRects.length) return;" +
    "  if (td.getClientRects().length > 1) {" +
    "    fragmented.push(td.textContent.trim().slice(0, 48));" +
    "  }" +
    "  var worst = 0;" +
    "  textRects.forEach(function (a) {" +
    "    fieldRects.forEach(function (b) {" +
    "      if (a.right > b.left + 1 && a.left < b.right - 1 &&" +
    "          a.top < b.bottom - 1 && a.bottom > b.top + 1) {" +
    "        worst = Math.max(worst, Math.round(a.right - b.left));" +
    "      }" +
    "    });" +
    "  });" +
    "  if (worst > 0) {" +
    "    bad.push(td.textContent.trim().slice(0, 48) + ' (over by ' + worst " +
        "+ 'px)');" +
    "  }" +
    "});" +
    // `rows` is read by the two assertions below AND by this section's log
    // line. It was dropped from this object when `fragmented` was added, which
    // made the very next assertion `undefined > 40` — false — so the section
    // could only ever fail, with a message ("it has undefined rows") that
    // accuses the PAGE of not having built the pane. Everything a script like
    // this returns has a reader; check the readers when editing the shape.
    "return { bad: bad, fragmented: fragmented," +
    "         rows: document.querySelectorAll('#config_rows tr').length," +
    "         columns: document.querySelectorAll('#config_rows " +
        ".vc-config-group').length };");
  assert.ok(overlap.rows > 40,
    "the Configuration Parameters pane should have been built by now; it has " +
    overlap.rows + " rows.");
  assert.ok(overlap.columns >= 5,
    "and it should be grouped by document — found " + overlap.columns +
        " groups.");
  assert.deepStrictEqual(overlap.bad, [],
    "these member names are drawn on top of their own input in the " +
        "Configuration " +
    "Parameters columns: " + overlap.bad.join(", ") +
        ". A long identifier with no break " +
    "opportunity has to WRAP in a third of the width; without that both the " +
        "name and the " +
    "value are unreadable, and nothing about the page's height or " +
        "containment shows it.");
  // The other half of the same rule, and the reason the check above measures
  // each fragment separately rather than the union of them. A name cell that
  // crosses a column break puts the tail of a wrapped identifier at the top of
  // the NEXT column, a column away from the input it labels — as bad to read as
  // an overlap, and invisible to the overlap check now that the check is
  // fragment-aware. The css declares `break-inside: avoid` on the row, the
  // cells and the tbody to stop it; on the row alone Chrome keeps the row box
  // together and fragments the cell contents anyway.
  assert.deepStrictEqual(overlap.fragmented, [],
    "these Configuration Parameters name cells are split across a column " +
        "break, so " +
    "the rest of the name is at the top of the next column rather than " +
        "beside its " +
    "input: " + overlap.fragmented.join(", ") +
        ". `break-inside: avoid` needs to be " +
    "on .vc-config-table td, not only on the tr.");

  log.info("[step 1] OK — four panes on one row (" + full.panes[0].w +
           "px each), row " +
           full.rowHeight + "px tall with " + loaded.length +
               " documents loaded, " +
           overlap.rows + " configuration rows in " + overlap.columns +
           " groups, no name over its value and none split across a column.");

  await restoreStorage();
  await driver.manage().window().setRect({ width: before.width,
                      height: before.height });
  log.debug("Leaving stepOneFitsInOneRow().");
}

async function chooserFitsOnOneScreen(driver) {
  log.debug("Entering chooserFitsOnOneScreen().");
  log.info("=== Step 0 fits on one screen ===");
  var before = await driver.manage().window().getRect();
  await driver.manage().window().setRect({ width: 1512, height: 982 });
  await driver.get(baseUrl + "/vc-issuance-0.html");
  await driver.wait(until.elementLocated(By.id("vc_usecases")), waitTime * 4);
  await driver.sleep(300);

  var m = await driver.executeScript(
    "var doc = document.documentElement;" +
    "var cards = Array.prototype.slice.call(document.querySelectorAll('button.vc-usecase'));" +
    "var tops = [];" +
    "cards.forEach(function (c) {" +
    "  var t = Math.round(c.getBoundingClientRect().top);" +
    "  if (tops.indexOf(t) === -1) tops.push(t);" +
    "});" +
    "var tools = document.getElementById('pane_vc_tools');" +
    "var status = document.getElementById('vc_usecase_status');" +
    "var bottom = function (el) { return " +
        "Math.round(el.getBoundingClientRect().bottom + window.scrollY); };" +
    "return { viewport: doc.clientHeight, cards: cards.length, rows: " +
        "tops.length," +
    "         cardWidth: Math.round(cards[0].getBoundingClientRect().width)," +
    "         panesEnd: Math.max(bottom(tools), bottom(status))," +
    "         toolsEnd: bottom(tools), toolsHeight: " +
        "Math.round(tools.getBoundingClientRect().height)," +
    "         sideways: doc.scrollWidth > doc.clientWidth + 2 };");

  assert.ok(m.cards >= 4, "step 0 should offer the use cases; found " +
            m.cards + " cards.");
  assert.ok(m.rows < m.cards,
    "the cards should be laid out in a GRID, using the horizontal room — " +
        m.cards +
    " cards on " + m.rows + " rows means they are still stacked one per row, " +
        "which is what made this " +
    "page scroll.");
  assert.ok(m.cardWidth >= 380,
    "and the columns must stay wide enough to read: " + m.cardWidth +
        "px per card. Squeezing in more " +
    "columns buys height back only by making every card taller.");
  // When this fails, the page it names is usually not the page that changed:
  // the last pane is the SHARED VC Tools pane, which every workflow page
  // carries and which grows a row whenever a tool is added — that is how it
  // broke on 2026-08-17, from a partial two directories away, with nothing on
  // this page touched. So the message says whose height it is.
  assert.ok(m.panesEnd <= m.viewport,
    "everything step 0 offers must fit in one screen: its last pane ends at " +
        m.panesEnd +
    "px against a viewport of " + m.viewport + "px, so " + (m.panesEnd -
        m.viewport) +
    "px of it is below the fold. A chooser you have to scroll cannot be used " +
        "to compare. " +
    (m.toolsEnd === m.panesEnd
      ? "The pane that ends there is the SHARED VC Tools pane (" +
        m.toolsHeight + "px, partials/vc_tools.html), which all nine " +
        "workflow pages carry — check whether it gained a tool or a longer " +
        "description before looking at this page. See the budget table in " +
        "docs/sd-jwt-vc-issuance.md."
      : "The lowest thing on the page is the use-case status line, not the " +
        "VC Tools pane, so the chooser's own content is what grew."));
  assert.strictEqual(m.sideways, false,
    "and it must not have gained sideways scroll in exchange for the height.");
  log.info("[step 0] OK — " + m.cards + " cards on " + m.rows + " rows at " +
           m.cardWidth +
           "px each; everything ends " + (m.viewport - m.panesEnd) +
               "px above the fold.");

  await driver.manage().window().setRect({ width: before.width,
                      height: before.height });
  log.debug("Leaving chooserFitsOnOneScreen().");
}

async function stepLinksOnEveryPage(driver) {
  log.debug("Entering stepLinksOnEveryPage().");
  log.info("=== The step links, on every page, on one row ===");
  var pages = ["vc-issuance-0.html", "vc-issuance-1.html", "vc-issuance-2.html",
               "vc-issuance-3.html", "vc-issuance-4.html"];
  for (var i = 0; i < pages.length; i++) {
    await driver.get(baseUrl + "/" + pages[i]);
    await driver.wait(until.elementLocated(By.id("vc_steps")), waitTime);
    await driver.sleep(400);
    var row = await driver.executeScript(
      "var ol = document.getElementById('vc_steps');" +
      "var items = Array.prototype.slice.call(ol.querySelectorAll('li'));" +
      "var title = document.querySelector('h3.vc-title');" +
      "return { count: items.length," +
      "         hrefs: items.map(function (li) { var a = " +
          "li.querySelector('a');" +
      "                                         return a ? " +
          "a.getAttribute('href') : null; })," +
      "         labels: items.map(function (li) { var a = " +
          "li.querySelector('a');" +
      "                                          return a ? " +
          "a.textContent.trim() : ''; })," +
      "         tops: items.map(function (li) { return " +
          "Math.round(li.getBoundingClientRect().top); })," +
      "         rowHeight: Math.round(ol.getBoundingClientRect().height)," +
      "         itemHeight: " +
          "Math.round(items[0].getBoundingClientRect().height)," +
      "         current: items.filter(function (li) { return " +
          "/vc-step-current/.test(li.className); })" +
      "                    .map(function (li) { return li.id; })," +
      "         aboveTitle: title ? ol.getBoundingClientRect().top < " +
          "title.getBoundingClientRect().top : null," +
      "         overflow: document.documentElement.scrollWidth - " +
          "document.documentElement.clientWidth };");
    assert.strictEqual(row.count, 5,
      pages[i] + " should link to all five steps, got " + row.count + ".");
    for (var step = 0; step < 5; step++) {
      assert.ok(row.hrefs.indexOf("/vc-issuance-" + step + ".html") !== -1,
        pages[i] + " should link to step " + step + ". Got: " +
              JSON.stringify(row.hrefs));
    }
    // One row: every item shares a top edge, and the row is no taller than one
    // item.
    assert.strictEqual(Math.max.apply(null, row.tops) - Math.min.apply(null,
                       row.tops), 0,
      pages[i] + ": the step links should all be on one row. Tops: " +
            JSON.stringify(row.tops));
    assert.ok(row.rowHeight - row.itemHeight <= 2,
      pages[i] + ": the row should be one item tall (" + row.rowHeight +
            " vs " + row.itemHeight + "px).");
    assert.ok(row.aboveTitle,
      pages[i] + ": the step links belong at the top, above the page title.");
    assert.ok(row.overflow <= 0,
      pages[i] +
            ": a single row of links must not make the page scroll sideways.");
    // And the page marks which step it is.
    assert.deepStrictEqual(row.current, ["vc_step_" + i],
      pages[i] + " should mark its own step as the current one. Got: " +
            JSON.stringify(row.current));
    log.info("[steps] " + pages[i] + ": " + row.labels.join(" | ") + " (one " +
             row.rowHeight + "px row)");
  }
  log.info("[steps] OK — all five links, on one row, at the top of all " +
           "five pages.");
  log.debug("Leaving stepLinksOnEveryPage().");
}

// ---------------------------------------------------------------------------
// Validate Signature on step 1's two metadata panes.
//
// Two independent things are pinned here, and the second one is the reason this
// section exists at all.
//
// FIRST, the button must work whenever a table is on screen — not only during
// the visit that pressed Retrieve. It reads the document this page holds,
// falling back to the stored copy, so returning to a page whose table was
// restored is enough. Before that, the in-memory copy was the only source and
// coming back to the page left the button answering "retrieve the metadata
// first" beside a fully populated table.
//
// SECOND — and this is the trap — it must validate the document THE PAGE IS
// USING, never a pristine copy of the bytes that arrived. Caching the raw
// response and validating that instead looks like an obvious improvement and is
// actively wrong: signed_metadata is a JWT signed over its OWN payload, not
// over the surrounding JSON, so the original bytes add nothing to the signature
// check, while the claim-by-claim comparison is what catches a member edited
// away from its signed claim. Validate the pristine bytes and every tampered
// document reports clean. tests/oauth2_metadata_rfc8414.js has those controls
// for oauth2_oidc_1.html's pane; these two panes had none, which is how the
// mistake got as far as a working build.
//
// Both panes are pointed at the mock STS, because it emits signed_metadata on
// both documents and Keycloak emits it on neither.
//
// Scope, honestly: the two assertions above are what this section earns its
// keep with, and mutation testing says so — re-introducing the cached-response
// mistake, and reverting the orphaned-table message, are both caught. The last
// two checks below (an unreachable jwks_uri, a table with no document) cover
// branches that are DEFENSIVE rather than reachable by using the page, so they
// pin the messages without proving the branches are load-bearing.
// ---------------------------------------------------------------------------
async function metadataSignatureValidation(driver) {
  log.debug("Entering metadataSignatureValidation().");
  log.info("=== Validate Signature on the step 1 metadata panes ===");
  var asUrl = issuerBase + "/.well-known/oauth-authorization-server";
  var panes = [
    // `tamperMember` is a member the signed_metadata covers and that key
    // RESOLUTION does not depend on. credential_issuer would be the obvious
    // choice for the first pane and is the wrong one: this pane finds the
    // issuer's keys by fetching /.well-known/jwt-vc-issuer UNDER that value, so
    // editing it fails at "no jwks_uri" before any claim is compared, and the
    // test would pass for a reason unrelated to what it is checking.
    { name: "credential issuer", statusId: "vci_signed_metadata_status",
     tableId: "vci_metadata_table",
      buttonId: "vci_validate_signed_metadata_button", storeKey: "vci_info",
      tamperMember: "credential_endpoint" },
    { name: "authorization server", statusId: "as_signed_metadata_status",
     tableId: "discovery_info_table",
      buttonId: "as_validate_signed_metadata_button",
          storeKey: "discovery_info",
      tamperMember: "issuer" }
  ];

  var saved = null;
  var openStep1 = async function () {
    log.debug("Entering openStep1().");
    await driver.get(baseUrl + "/vc-issuance-1.html");
    await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                      waitTime);
    log.debug("Leaving openStep1().");
  };
  // A verdict, however it turns out. Every one of these ends in a full stop,
  // and none of the intermediate "… " progress lines do — which is what tells a
  // finished verdict from a pane still working. Waiting on content rather than
  // sleeping also means a hung promise fails HERE, naming the pane, instead of
  // somewhere downstream.
  var verdictOf = async function (pane, why) {
    log.debug("Entering verdictOf().");
    await click(driver, By.id(pane.buttonId));
    log.debug("Leaving verdictOf().");
    return await waitForStatus(driver, pane.statusId,
      function (s) { return s !== "" && !/…$/.test(s); },
      "the " + pane.name + " pane never reached a verdict " + why);
  };
  // Rewrite the stored document, then reload so the page picks it up.
  var tamperStored = async function (pane, mutate) {
    log.debug("Entering tamperStored().");
    await driver.executeScript(
      "var doc = JSON.parse(localStorage.getItem(arguments[0]));" +
      "(" + mutate + ")(doc);" +
      "localStorage.setItem(arguments[0], JSON.stringify(doc));",
          pane.storeKey);
    await openStep1();
    await driver.sleep(500);
    log.debug("Leaving tamperStored().");
  };

  // Everything the WORKFLOW left behind, captured BEFORE this section clears
  // storage to get a clean pair of metadata documents. It has to be put back at
  // the end: the sections after this one still need the credential and the
  // access token the issuance produced, and restoring only the metadata state
  // this section created leaves them with neither. That is exactly how this
  // broke refreshNegatives — "there is no access token to present" — one
  // section later and with nothing pointing back here.
  await openStep1();
  var original = await driver.executeScript(
    "var out = {};" +
    "for (var i = 0; i < localStorage.length; i++) { var k = " +
        "localStorage.key(i); out[k] = localStorage.getItem(k); }" +
    "return out;");
  var putBack = async function (snapshot) {
    log.debug("Entering putBack().");
    await driver.executeScript(
      "localStorage.clear();" +
      "var o = arguments[0];" +
      "Object.keys(o).forEach(function (k) { localStorage.setItem(k, " +
          "o[k]); });", snapshot);
    log.debug("Leaving putBack().");
  };

  await driver.executeScript("window.localStorage.clear();");
  await openStep1();
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];" +
    "document.getElementById('oidc_discovery_endpoint').value = arguments[1];",
    issuerMetadataUrl, asUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
                      function (s) { return /^Retrieved/.test(s); },
    "the credential issuer metadata was not retrieved");
  await click(driver, By.id("as_retrieve_button"));
  await waitForStatus(driver, "as_signed_metadata_status",
                      function (s) { return /^Retrieved/.test(s); },
    "the authorization server metadata was not retrieved");
  saved = await driver.executeScript(
    "var out = {};" +
    "for (var i = 0; i < localStorage.length; i++) { var k = " +
        "localStorage.key(i); out[k] = localStorage.getItem(k); }" +
    "return out;");
  var restore = async function () {
    log.debug("Entering restore().");
    await driver.executeScript(
      "localStorage.clear();" +
      "var o = arguments[0];" +
      "Object.keys(o).forEach(function (k) { localStorage.setItem(k, " +
          "o[k]); });", saved);
    await openStep1();
    await driver.sleep(500);
    log.debug("Leaving restore().");
  };

  for (var i = 0; i < panes.length; i++) {
    var pane = panes[i];

    // --- in the visit that retrieved it ------------------------------------
    await restore();
    var fresh = await verdictOf(pane, "right after retrieval");
    assert.ok(fresh.indexOf("VALID") === 0,
      pane.name +
          ": signed_metadata should verify right after retrieval. Got: " +
          fresh);

    // --- THE FIX: navigate away, come back, do not retrieve ----------------
    await driver.get(baseUrl + "/vc-issuance-0.html");
    await driver.sleep(400);
    await openStep1();
    await driver.sleep(600);
    var rows = await driver.executeScript(
      "var t = document.getElementById(arguments[0]);" +
      "return t ? t.querySelectorAll('tr').length : 0;", pane.tableId);
    assert.ok(rows > 0, pane.name +
              ": the table should be restored on returning to the page.");
    var returned = await verdictOf(pane, "after returning to the page");
    assert.ok(returned.indexOf("VALID") === 0,
      pane.name + ": with a table on screen the button must validate WITHOUT " +
          "the document being retrieved " +
      "again — that is the whole regression. Got: " + returned);

    // --- THE TRAP: the document in use is what gets validated -------------- A
    // member edited away from its signed claim must be reported. This fails if
    // validation is ever pointed at a pristine copy of the response instead.
    await restore();
    await tamperStored(pane, "function (d) { d." + pane.tamperMember +
                       " = 'https://evil.example.com'; }");
    var edited = await verdictOf(pane, "with an edited member");
    // The member has to be NAMED. "Every signed claim matches" is the exact
    // sentence a pristine-bytes implementation would produce here, so asserting
    // only that the verdict is not clean would not distinguish the two.
    assert.ok(/Signed claims that differ from the JSON/.test(edited) &&
              edited.indexOf(pane.tamperMember) !== -1,
      pane.name + ": " + pane.tamperMember +
          " was edited away from its signed claim and must be named as " +
      "differing. Validating a pristine copy of the response instead of the " +
          "document in use would report " +
      "this as clean. Got: " + edited);
    assert.ok(edited.indexOf("Every signed claim matches") === -1,
      pane.name + ": a tampered document must not be reported as fully " +
          "matching. Got: " + edited);

    // A broken signature must be rejected outright.
    await restore();
    await tamperStored(pane,
      "function (d) { var p = d.signed_metadata.split('.'); p[2] = " +
          "p[2].slice(0, -4) + 'AAAA';" +
      " d.signed_metadata = p.join('.'); }");
    var broken = await verdictOf(pane, "with a broken signature");
    assert.ok(broken.indexOf("INVALID") === 0,
      pane.name + ": a tampered signed_metadata must be rejected. Got: " +
          broken);

    log.info("[signature] " + pane.name +
             ": valid fresh and after returning; edited member and broken " +
             "signature both caught.");
  }

  // --- the keys cannot be fetched: a verdict, not a pane stuck on "Fetching …"
  // Every failure here used to be an unhandled rejection, so the pane sat on
  // its progress line for ever and read as a button that does nothing.
  await restore();
  await tamperStored(panes[1],
    "function (d) { d.jwks_uri = 'http://127.0.0.1:1/nowhere/jwks.json'; }");
  var unreachable = await verdictOf(panes[1],
      "when its keys cannot be fetched");
  assert.ok(/INVALID|Could not validate/.test(unreachable),
    "an unreachable jwks_uri must produce a verdict rather than leaving the " +
        "pane on a progress line. Got: " +
    unreachable);
  log.info("[signature] an unreachable jwks_uri is reported instead " +
           "of hanging.");

  // --- a table with nothing behind it says so -----------------------------
  // Defensive: with the restore in place this state is not reachable by using
  // the page. It is asserted because the message it replaced ("retrieve the
  // metadata first", beside a full table) is what sent people to press
  // Retrieve.
  await driver.executeScript("window.localStorage.clear();");
  await openStep1();
  // A whole <table>: that element is a CONTAINER the pane writes a table into,
  // not a <table> itself, and the parser drops a bare <tr> in that context —
  // which would leave the "is a table displayed" check false and test nothing.
  await driver.executeScript(
    "var t = document.getElementById(arguments[0]);" +
    "t.innerHTML = '<table><tr><td>credential_issuer</td><td>https://example.test</td></tr></table>';",
    panes[0].tableId);
  var orphaned = await verdictOf(panes[0], "with a table but no document");
  assert.ok(/no longer has/.test(orphaned),
    "a table with no document behind it should say so, not ask for a " +
        "retrieval it already looks like it has. " +
    "Got: " + orphaned);
  log.info("[signature] a table with no document behind it is named as such.");

  // Hand the workflow's own state back to the sections that follow.
  await putBack(original);
  await openStep1();
  var handedBack = await driver.executeScript(
    "return !!localStorage.getItem('token_access_token') || " +
        "!!localStorage.getItem('sdjwtvc_credential');");
  assert.ok(handedBack,
    "this section clears storage and must hand back what the workflow left; " +
        "the sections after it need " +
    "the credential and the access token.");
  log.info("[signature] OK — Validate Signature survives navigation and " +
           "still catches tampering.");
  log.debug("Leaving metadataSignatureValidation().");
}

// ---------------------------------------------------------------------------
// The hand-off from issuance into the PRESENTATION workflow (steps 3 and 4).
//
// The thing worth pinning is what the offer does NOT do: it copies nothing. The
// two workflows meet at the same storage keys, so a hand-off that duplicated
// the credential would be a second copy that goes stale — this asserts the
// click adds no such copy.
//
// The rest is the preflight, and its point is that it agrees with what
// presentation step 1 will decide. The case that earns its keep is the pair of
// missing-key states, which must come out DIFFERENTLY: a key that was never
// generated here is a dead end (step 1 refuses), while a key deliberately not
// kept is fine (step 2 has a field to paste it into). Collapsing them to "no
// key → blocked" is the plausible simplification, and it strands the user two
// pages before the only field that fixes it.
//
// Seeded states are restored afterwards, because later sections run on the
// state the workflow left behind.
// ---------------------------------------------------------------------------
async function presentationHandoff(driver, generations) {
  log.debug("Entering presentationHandoff().");
  log.info("=== The hand-off into the presentation workflow ===");
  var pages = ["vc-issuance-3.html", "vc-issuance-4.html"];

  // Everything the seeded states below would otherwise destroy.
  await driver.get(baseUrl + "/" + pages[0]);
  var saved = await driver.executeScript(
    "var out = {};" +
    "for (var i = 0; i < localStorage.length; i++) { var k = " +
        "localStorage.key(i); out[k] = localStorage.getItem(k); }" +
    "return out;");
  var restore = async function () {
    log.debug("Entering restore().");
    await driver.executeScript(
      "localStorage.clear();" +
      "var o = arguments[0];" +
      "Object.keys(o).forEach(function (k) { localStorage.setItem(k, " +
          "o[k]); });", saved);
    log.debug("Leaving restore().");
  };
  var credential = saved["sdjwtvc_credential"] || "";
  assert.ok(credential,
    "there is no credential in storage to hand off. stepFour() left one, so " +
        "it was removed by a " +
    "section between there and here: the layout and pane sections clear " +
        "localStorage to measure " +
    "an empty page and MUST restore it (see preservingLocalStorage()). Keys " +
        "present: " +
    (Object.keys(saved).sort().join(", ") || "(none at all)"));

  // What the offer reports, on either page.
  var offerOn = async function (page) {
    log.debug("Entering offerOn().");
    await driver.get(baseUrl + "/" + page);
    await driver.wait(until.elementLocated(By.id("vc_present_button")),
                      waitTime,
      page + " should carry a Present It button.");
    // The offer is rendered from storage on load, so wait for it to say
    // something rather than sleeping and hoping.
    await waitForStatus(driver, "vc_present_status",
                        function (v) { return v.trim() !== ""; },
      page + ": the presentation offer never said anything", waitTime);
    log.debug("Leaving offerOn().");
    return await driver.executeScript(
      "var b = document.getElementById('vc_present_button');" +
      "var s = document.getElementById('vc_present_status');" +
      // The offer must be the last thing the WORKFLOW says on the page. Every
      // page now also ends with the shared VC Tools pane
      // (partials/vc_tools.html), which belongs to no step and is deliberately
      // below everything — so it is excluded here rather than the assertion
      // being dropped. Its presence is checked too: without that, this would
      // still pass if the tools pane vanished.
      "var all = Array.prototype.slice.call(document.querySelectorAll('.dbg-pane'));" +
      "var panes = all.filter(function (p) { return p.id !== " +
          "'pane_vc_tools'; });" +
      "return { disabled: b.disabled, message: s.textContent.trim(), cls: " +
          "s.className," +
      "         inLastPane: panes[panes.length - 1].contains(b)," +
      "         toolsPaneIsBelow: all.length === panes.length + 1 &&" +
      "                           all[all.length - 1].id === " +
          "'pane_vc_tools' };");
  };

  for (var i = 0; i < pages.length; i++) {
    // --- the credential the workflow actually issued -----------------------
    await restore();
    var ready = await offerOn(pages[i]);
    assert.ok(ready.inLastPane,
      pages[i] + ": the offer belongs in the last pane the workflow itself " +
            "puts on the page.");
    assert.ok(ready.toolsPaneIsBelow,
      pages[i] + ": the shared VC Tools pane should be the one pane below " +
            "the offer. If it is " +
      "missing, the exclusion above is hiding a real regression rather than " +
          "accommodating it.");
    assert.strictEqual(ready.disabled, false,
      pages[i] + ": a held credential with its holder key should be " +
            "presentable. Said: " + ready.message);
    assert.ok(/vc-ok/.test(ready.cls),
      pages[i] + ": a presentable credential should read as OK, got class " +
            ready.cls);
    assert.ok(ready.message.indexOf(EXPECTED_VCT) !== -1,
      pages[i] +
          ": the offer should name the credential type being offered. Said: " +
          ready.message);

    // --- nothing held ------------------------------------------------------ A
    // FRESH wallet: no credential and no history. Clearing only the credential
    // would leave step 4's history table populated, and step 4 renders this
    // offer from the same pass that draws that table — so the empty-history
    // path would never be taken and an offer rendered only on the populated
    // path would look correct here while being blank on the state a first-time
    // user arrives in.
    await driver.executeScript("localStorage.clear();");
    var empty = await offerOn(pages[i]);
    assert.strictEqual(empty.disabled, true,
      pages[i] + ": with nothing held there is nothing to present. Said: " +
            empty.message);
    // Belt and braces: the handler must refuse too, or re-enabling the button
    // (a later edit, a browser extension) would navigate to an empty workflow.
    await driver.executeScript(
      "var b = document.getElementById('vc_present_button'); b.disabled = " +
          "false; b.click();");
    await driver.sleep(500);
    assert.ok((await driver.getCurrentUrl()).indexOf(pages[i]) !== -1,
      pages[i] + ": a forced click with nothing held should not navigate.");

    // --- the two missing-key states, which must NOT come out the same ------
    await restore();
    await driver.executeScript(
        "localStorage.removeItem('sdjwtvc_holder_private_jwk');");
    var lost = await offerOn(pages[i]);
    assert.strictEqual(lost.disabled, true,
      pages[i] + ": a key that was never generated here is a dead end — " +
            "presentation step 1 refuses it. " +
      "Said: " + lost.message);

    await restore();
    await driver.executeScript(
      "localStorage.removeItem('sdjwtvc_holder_private_jwk');" +
      "localStorage.setItem('sdjwtvc_save_holder_key', '0');");
    var optedOut = await offerOn(pages[i]);
    assert.strictEqual(optedOut.disabled, false,
      pages[i] + ": a holder key deliberately not kept is pasted in on " +
            "presentation step 2, so the hand-off " +
      "must stay open. Said: " + optedOut.message);
    assert.ok(/vc-pending/.test(optedOut.cls),
      pages[i] + ": absent-by-choice should read as an advisory, got class " +
            optedOut.cls);
    assert.ok(/paste/i.test(optedOut.message),
      pages[i] +
            ": the advisory should say the key will have to be pasted. Said: " +
            optedOut.message);

    // --- something that cannot be parsed -----------------------------------
    await restore();
    await driver.executeScript("localStorage.setItem('sdjwtvc_credential', " +
                               "'not-a-credential');");
    var broken = await offerOn(pages[i]);
    assert.strictEqual(broken.disabled, true,
      pages[i] + ": an unparseable credential cannot be presented. Said: " +
            broken.message);

    log.info("[handoff] " + pages[i] +
        ": ready / empty / key-lost / opted-out / unparseable all distinct.");
  }

  // --- step 4 only: which generation would go ------------------------------
  // Read the history that is actually in storage rather than trusting the array
  // stepFour returned: credentialHistoryNavigation() ends by clearing the
  // history, so by the time this runs there is usually one generation and a
  // check written against the passed-in count SKIPS ITSELF SILENTLY — which is
  // exactly what it did on its first real run, while passing.
  await restore();
  var heldCount = await driver.executeScript(
    "try {" +
    "  var h = JSON.parse(localStorage.getItem('sdjwtvc_credential_history') " +
        "|| '[]');" +
    "  return h.filter(function (e) { return e.outcome === 'kept' && " +
        "e.credential; }).length;" +
    "} catch (e) { return 0; }");
  if (heldCount < 2) {
    // Give it two generations of its own.
    //
    // Cloning an existing kept row is not enough: credentialHistoryNavigation()
    // ends with Clear History, so by the time this runs there is often NO kept
    // row to clone — and a seed guarded on finding one quietly seeds nothing,
    // leaves a single generation, and the assertion below then fails for a
    // reason that has nothing to do with the offer. That is exactly how this
    // failed on its first full-suite run. So the rows are built from the
    // credential the wallet is actually holding, which is always there.
    //
    // HISTORY_INDEX points at the FIRST of them, so the offer has to say "not
    // the newest one" — the more interesting of the two branches.
    await driver.executeScript(
      "var credential = localStorage.getItem('sdjwtvc_credential') || '';" +
      "if (credential) {" +
      "  var pub = null, prv = null;" +
      "  try { pub = JSON.parse(localStorage.getItem('sdjwtvc_holder_jwk') " +
          "|| 'null'); } catch (e) { pub = null; }" +
      "  try { prv = " +
          "JSON.parse(localStorage.getItem('sdjwtvc_holder_private_jwk') || " +
          "'null'); } catch (e) { prv = null; }" +
      "  var h = " +
          "JSON.parse(localStorage.getItem('sdjwtvc_credential_history') " +
          "|| '[]');" +
      "  var nextId = h.reduce(function (m, e) { return Math.max(m, e.id || " +
          "0); }, 0);" +
      "  var row = function (id, source) {" +
      "    return { id: id, at: new Date().toISOString(), kind: 'issuance', " +
          "outcome: 'kept'," +
      "             detail: '', source: source, credential: credential, " +
          "credentials: [credential]," +
      "             meta: {}, holderJwk: pub, holderPrivateJwk: prv };" +
      "  };" +
      "  h.push(row(nextId + 1, 'issued'));" +
      "  h.push(row(nextId + 2, 'refreshed'));" +
      "  localStorage.setItem('sdjwtvc_credential_history', " +
          "JSON.stringify(h));" +
      "  localStorage.setItem('sdjwtvc_credential_history_index', " +
          "String(nextId + 1));" +
      "}");
    // The seed has to have worked, or the assertion below would fail for a
    // reason unrelated to what it is testing.
    var seeded = await driver.executeScript(
      "try {" +
      "  var h = " +
          "JSON.parse(localStorage.getItem('sdjwtvc_credential_history') " +
          "|| '[]');" +
      "  return h.filter(function (e) { return e.outcome === 'kept' && " +
          "e.credential; }).length;" +
      "} catch (e) { return 0; }");
    assert.ok(seeded >= 2,
      "this section needs two held generations to check that step 4 names " +
          "the one in hand; it could only " +
      "make " + seeded + ". Is a credential still in storage at this point?");
  }
  var named = await offerOn(pages[1]);
  assert.ok(/generation \d+ of \d+/.test(named.message),
    "with more than one generation held, step 4 must say which one would be " +
        "presented. Said: " + named.message);
  log.info("[handoff] step 4 names the generation in hand: " +
    (named.message.match(/generation \d+ of \d+[^.]*/) || [""])[0]);

  // --- step 4 only: a refresh retrieved but not kept ------------------------
  // It is the newest thing on the screen and is NOT in storage, so it is not
  // what a Verifier would see. Saying nothing here would let the page imply
  // otherwise.
  await restore();
  await driver.executeScript(
    "localStorage.setItem('sdjwtvc_refreshed_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_refreshed_credentials', " +
        "JSON.stringify([arguments[0]]));" +
    "localStorage.setItem('sdjwtvc_refreshed_meta', JSON.stringify({ " +
        "tokenRefreshed: true }));", credential);
  var pending = await offerOn(pages[1]);
  assert.ok(/not been kept/i.test(pending.message) &&
            /NOT what would be presented/i.test(pending.message),
    "step 4 with a refresh pending must say the unkept credential is not " +
        "what would go. Said: " + pending.message);
  assert.ok(/vc-pending/.test(pending.cls),
    "a pending refresh should mark the offer as pending, got class " +
        pending.cls);
  log.info("[handoff] step 4 disowns a refreshed credential that has not " +
           "been kept.");

  // --- the click navigates, and copies nothing ------------------------------
  await restore();
  await driver.get(baseUrl + "/" + pages[0]);
  await driver.wait(until.elementLocated(By.id("vc_present_button")), waitTime);
  var before = await driver.executeScript(
    "var out = {};" +
    "for (var i = 0; i < localStorage.length; i++) { var k = " +
        "localStorage.key(i); out[k] = localStorage.getItem(k); }" +
    "return out;");
  await click(driver, By.id("vc_present_button"));
  await driver.wait(until.urlContains("vc-presentation-0.html"), waitTime,
    "Present It should land on the presentation workflow.");
  var after = await driver.executeScript(
    "var out = {};" +
    "for (var i = 0; i < localStorage.length; i++) { var k = " +
        "localStorage.key(i); out[k] = localStorage.getItem(k); }" +
    "return out;");
  assert.strictEqual(after["sdjwtvc_credential"], before["sdjwtvc_credential"],
    "the hand-off must not rewrite the credential it hands off.");
  // No NEW key may hold the credential: the workflows share one copy, and a
  // second one is a copy that can go stale.
  var duplicates = Object.keys(after).filter(function (k) {
    return !(k in before) && String(after[k]).indexOf(credential) !== -1;
  });
  assert.deepStrictEqual(duplicates, [],
    "the hand-off copies nothing — the presentation workflow reads the same " +
        "keys. New copies: " +
    JSON.stringify(duplicates));
  log.info("[handoff] OK — Present It navigates and copies nothing.");

  await driver.get(baseUrl + "/" + pages[0]);
  await restore();
  log.debug("Leaving presentationHandoff().");
}

// ---------------------------------------------------------------------------
// Nothing may run off the side of a pane.
//
// Every value these pages show is base64url — a c_nonce, an access token, a
// JWK's coordinates, a pretty-printed request body — and base64url has no space
// in it to break at. bootstrap.css also sets `code { white-space: nowrap }`.
// Together those two facts pushed the panes (and on one of them the whole page)
// out to the right, which is what a manual run of the workflow found.
//
// So this checks the geometry with values far longer than the real ones: no
// element wider than the pane that contains it, and no horizontal page scroll.
// Cheap, and it fails on the exact regression rather than on a screenshot diff.
//
// The page-scroll half of that used to report only a pixel count ("Got 8px."),
// which is not enough to act on: it names neither the element nor the box model
// that produced it, so an overflow that appears in one environment and not
// another — the containerized suite renders at http://client:3000 in a Chrome
// with a different font set than a host run has — cannot be chased without
// reproducing the environment first. SPILL_SCAN therefore collects every
// element whose right edge passes the viewport, and records whether an ancestor
// clips it: an element inside an `overflow-x: hidden` box (the header and
// footer bars both are) sticks out in the geometry but cannot scroll the
// document, so those are listed last and marked, and the unclipped ones — the
// ones that actually caused the failure — come first.
// ---------------------------------------------------------------------------
var SPILL_SCAN =
  "var vw = document.documentElement.clientWidth;" +
  "var past = [];" +
  "Array.prototype.slice.call(document.querySelectorAll('body " +
      "*')).forEach(function (e) {" +
  "  var r = e.getBoundingClientRect();" +
  "  if (r.width <= 0 && r.height <= 0) return;" +
  "  var spill = Math.round(r.right - vw);" +
  "  if (spill <= 0) return;" +
  "  var clippedBy = '';" +
  "  for (var p = e.parentElement; p && p !== document.body; p = " +
      "p.parentElement) {" +
  "    var pov = getComputedStyle(p).overflowX;" +
  "    if (pov !== 'visible') {" +
  "      clippedBy = p.tagName + (p.id ? '#' + p.id : '') +" +
  "                  (p.className ? '.' + String(p.className).split(' " +
      "')[0] : '');" +
  "      break;" +
  "    }" +
  "  }" +
  "  var cs = getComputedStyle(e);" +
  "  past.push({ tag: e.tagName, id: e.id || '', cls: String(e.className || " +
      "'').slice(0, 40)," +
  "              left: Math.round(r.left), right: Math.round(r.right)," +
  "              width: Math.round(r.width), spill: spill, clippedBy: " +
      "clippedBy," +
  "              pos: cs.position, ws: cs.whiteSpace, ovx: cs.overflowX," +
  "              text: (e.textContent || '').replace(/\\s+/g, ' " +
      "').trim().slice(0, 40) });" +
  "});" +
  "past.sort(function (a, b) {" +
  "  if (!a.clippedBy !== !b.clippedBy) return a.clippedBy ? 1 : -1;" +
  "  return b.spill - a.spill;" +
  "});" +
  "past = past.slice(0, 12);";

// Renders what SPILL_SCAN found into the assertion message. Everything here is
// for a failure that has already happened, so it errs towards saying too much.
function spillReport(result) {
  log.debug("Entering spillReport().");
  var head = "(viewport " + result.vw + "px, window " + result.iw +
      "px, content " +
             result.sw + "px, body margin " + result.bodyMargin + ")";
  if (!result.past || !result.past.length) {
    log.debug("Leaving spillReport().");
    return head +
        " — but no element's right edge passes the viewport, so the width " +
           "comes from the box model (a margin, a negative offset or a " +
               "transform) " +
           "rather than from any one box.";
  }
  var lines = result.past.map(function (o) {
    return "    " + o.tag + (o.id ? "#" + o.id : "") + (o.cls ? "." +
        o.cls : "") +
           " spills " + o.spill + "px (left " + o.left + ", width " + o.width +
           ", position " + o.pos + ", white-space " + o.ws + ", overflow-x " +
               o.ovx + ")" +
           (o.clippedBy ? " [clipped by " + o.clippedBy +
            " — cannot scroll the page]" : "") +
           (o.text ? " “" + o.text + "”" : "");
  });
  log.debug("Leaving spillReport().");
  return head + " past the right edge:\n" + lines.join("\n");
}

async function panesContainTheirContent(driver) {
  log.debug("Entering panesContainTheirContent().");
  log.info("=== Nothing overflows its pane ===");
  var pages = ["vc-issuance-1.html", "vc-issuance-2.html",
               "vc-issuance-3.html", "vc-issuance-4.html"];
  for (var i = 0; i < pages.length; i++) {
    await driver.get(baseUrl + "/" + pages[i]);
    await driver.wait(until.elementLocated(By.css(".dbg-pane")), waitTime);
    await driver.sleep(700);
    var result = await driver.executeScript(
      // A value longer than anything an issuer would really send, in every
      // <code> the page has: that is the case that overflowed.
      "var long = new Array(24).join('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9');" +
      "Array.prototype.slice.call(document.querySelectorAll('.dbg-pane " +
          "code')).forEach(function (c) {" +
      "  if (c.id) c.textContent = long;" +
      "});" +
      "var out = [];" +
      "Array.prototype.slice.call(document.querySelectorAll('.dbg-pane')).forEach(function (pane) {" +
      "  var pr = pane.getBoundingClientRect();" +
      "  Array.prototype.slice.call(pane.querySelectorAll('code, pre, " +
          "textarea, table')).forEach(function (e) {" +
      "    var r = e.getBoundingClientRect();" +
      "    if (r.width <= 0) return;" +
          // a collapsed pane has no geometry
      "    var over = Math.round(r.right - (pr.right - 12));" +
      "    if (over > 0) out.push({ pane: pane.id, tag: e.tagName, id: e.id " +
          "|| '(none)', over: over });" +
      "  });" +
      "});" +
      SPILL_SCAN +
      "return { overflowing: out, past: past," +
      "         vw: document.documentElement.clientWidth," +
      "         iw: window.innerWidth," +
      "         sw: document.documentElement.scrollWidth," +
      "         bodyMargin: " +
          "getComputedStyle(document.body).marginLeft + '/' +" +
      "                     getComputedStyle(document.body).marginRight," +
      "         doc: document.documentElement.scrollWidth - " +
          "document.documentElement.clientWidth };");
    assert.strictEqual(result.overflowing.length, 0,
      pages[i] + ": these elements extend past the pane that contains them — " +
      result.overflowing.map(function (o) {
        return o.id + " (" + o.tag + " in " + o.pane + ", " + o.over + "px)";
      }).join(", "));
    assert.ok(result.doc <= 0,
      pages[i] +
          " should not scroll horizontally, even with values this long. Got " +
      result.doc + "px. " + spillReport(result));
    log.info("[layout] " + pages[i] +
             ": every box fits its pane, no horizontal scroll.");
  }

  // And the boxes in a pane line up on both edges rather than each being its
  // own width — a <pre> and a <textarea> in the same pane must come out the
  // same.
  await driver.get(baseUrl + "/vc-issuance-2.html");
  await driver.wait(until.elementLocated(By.id("vc_request_body")), waitTime);
  await driver.sleep(700);
  var boxes = await driver.executeScript(
    "return ['vc_holder_jwk','vc_request_body','vc_proof_jwt','jwt_header'," +
        "'jwt_payload']" +
    "  .map(function (id) {" +
    "    var r = document.getElementById(id).getBoundingClientRect();" +
    "    return { id: id, left: Math.round(r.left), right: " +
        "Math.round(r.right) };" +
    "  });");
  var lefts = boxes.map(function (b) { return b.left; });
  var rights = boxes.map(function (b) { return b.right; });
  assert.ok(Math.max.apply(null, lefts) - Math.min.apply(null, lefts) <= 1,
    "the boxes in the Credential Request pane should share a left edge. Got: " +
        JSON.stringify(boxes));
  assert.ok(Math.max.apply(null, rights) - Math.min.apply(null, rights) <= 2,
    "and a right edge. Got: " + JSON.stringify(boxes));
  log.info("[layout] OK — the request pane's boxes align on both edges.");
  log.debug("Leaving panesContainTheirContent().");
}

// ---------------------------------------------------------------------------
// Step 4's Credential History pane.
//
// The same idea as oauth2_oidc_2.html's Token History, for credentials: every
// generation the wallet has held, with the one in hand marked and any of them
// activatable. What has to be true is that activating a generation really puts
// THAT credential in hand — with the holder key it is bound to, or the wallet
// would hold something it cannot present — and that moving backwards works, not
// just forwards, because "the refresh made things worse" is a real outcome.
//
// Runs on the history stepFour left behind: generation 1 from the issuance and
// generation 2 from the refresh that was kept.
// ---------------------------------------------------------------------------
async function credentialHistoryNavigation(driver, generations) {
  log.debug("Entering credentialHistoryNavigation().");
  log.info("=== Step 4: the Credential History pane ===");
  await driver.get(baseUrl + "/vc-issuance-4.html");
  await driver.wait(until.elementLocated(By.id("vc_history_table")), waitTime);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_reissue_proof"));
  }, fetchWait,
      "step 4 should have built its request before the history is used.");

  function historyRows() {
    log.debug("Entering historyRows().");
    log.debug("Leaving historyRows().");
    return driver.executeScript(
      "return Array.prototype.slice.call(document.querySelectorAll('#vc_history_table tbody tr'))" +
      "  .map(function (tr) {" +
      "    var td = tr.querySelectorAll('td');" +
      "    return { n: td[0].textContent.trim(), gen: " +
          "td[1].textContent.trim()," +
      "             attempt: td[3].textContent.trim(), outcome: " +
          "td[4].textContent.trim()," +
      "             detail: td[5].textContent.trim(), credential: " +
          "td[6].textContent.trim()," +
      "             inHand: td[7].textContent.trim() === 'In hand'," +
      "             activatable: !!td[7].querySelector('input')," +
      "             logOnly: /log only/.test(td[7].textContent)," +
      "             active: /vc-history-active/.test(tr.className) };" +
      "  });");
  }
  // The generations (kept rows) only, newest first — what the navigation moves
  // over.
  function generationRows(rows) {
    log.debug("Entering generationRows().");
    log.debug("Leaving generationRows().");
    return rows.filter(function (r) { return r.outcome === "kept"; });
  }
  function navState() {
    log.debug("Entering navState().");
    log.debug("Leaving navState().");
    return driver.executeScript(
      "return { position: " +
          "document.getElementById('vc_history_position').textContent.trim()," +
      "         oldest: " +
          "document.getElementById('vc_history_oldest_button').disabled," +
      "         older: " +
          "document.getElementById('vc_history_older_button').disabled," +
      "         newer: " +
          "document.getElementById('vc_history_newer_button').disabled," +
      "         latest: " +
          "document.getElementById('vc_history_latest_button').disabled };");
  }
  function heldCredential() {
    log.debug("Entering heldCredential().");
    log.debug("Leaving heldCredential().");
    return driver.executeScript(
        "return localStorage.getItem('sdjwtvc_credential');");
  }
  function heldKey() {
    log.debug("Entering heldKey().");
    log.debug("Leaving heldKey().");
    return driver.executeScript(
        "return localStorage.getItem('sdjwtvc_holder_jwk');");
  }

  // ---- what the issuance and the refresh recorded --------------------------
  var rows = await historyRows();
  var gens = generationRows(rows);
  assert.ok(rows.length > gens.length,
    "the log should carry more than the generations — the access token " +
        "refresh is in it too. Got: " +
    JSON.stringify(rows.map(function (r) { return r.attempt + "/" +
                   r.outcome; })));
  assert.strictEqual(gens.length, 2,
    "the issuance and the kept refresh should both be generations, got " +
        gens.length + ".");
  // Newest first, the way oauth2_oidc_2's Token History lists token sets.
  assert.deepStrictEqual(gens.map(function (r) { return r.gen; }), ["2", "1"],
    "the newest generation should be listed first.");
  assert.strictEqual(gens[1].attempt, "Issuance (step 2)",
    "generation 1 is the issuance. Got: " + gens[1].attempt);
  assert.strictEqual(gens[0].attempt, "Credential Request",
    "generation 2 came from a Credential Request. Got: " + gens[0].attempt);
  assert.ok(gens[0].inHand && gens[0].active,
    "the credential in hand should be the marked row.");
  assert.ok(gens[1].activatable && !gens[1].inHand,
    "the earlier generation should be activatable rather than marked " +
        "as in hand.");
  assert.notStrictEqual(gens[0].credential, gens[1].credential,
    "the two generations differ (signature, validity), and the table should " +
        "show that.");
  // A log row is not a place you can navigate to, and says so.
  var logRows = rows.filter(function (r) { return r.gen === "—"; });
  assert.ok(logRows.length >= 1 &&
            logRows.every(function (r) { return r.logOnly; }),
    "a row that is not a generation should be marked 'log only'. Got: " +
        JSON.stringify(logRows));
  assert.ok(rows.every(function (r) { return /^[0-9]+$/.test(r.n); }),
    "and every row — generation or not — carries an attempt number. Got: " +
    JSON.stringify(rows.map(function (r) { return r.n; })));
  var nav = await navState();
  assert.ok(/^generation 2 of 2/.test(nav.position),
    "the position should say where you are. Got: " + nav.position);
  assert.ok(/attempt\(s\) recorded/.test(nav.position),
    "and how many attempts are on record. Got: " + nav.position);
  assert.deepStrictEqual([nav.newer, nav.latest], [true, true],
    "at the newest generation, forwards must be disabled.");
  assert.deepStrictEqual([nav.older, nav.oldest], [false, false],
    "and backwards must be available.");
  assert.strictEqual(await heldCredential(), generations.refreshed,
    "the credential in hand is the refreshed one stepFour kept.");
  log.info("[history] " + nav.position + ": " +
           rows.map(function (r) { return r.attempt + "/" +
                    r.outcome; }).join(", "));

  // ---- backwards ----------------------------------------------------------
  await click(driver, By.id("vc_history_older_button"));
  await driver.wait(async function () {
    return /^generation 1 of 2/.test((await navState()).position);
  }, fetchWait, "Older should move to the previous generation.");
  assert.strictEqual(await heldCredential(), generations.original,
    "going back a generation should put THAT credential in hand, not merely " +
        "highlight a row.");
  assert.strictEqual(await heldKey(), generations.holderJwk,
    "and bring back the holder key it is bound to — without it the " +
        "credential cannot be presented.");
  var backNav = await navState();
  assert.deepStrictEqual([backNav.older, backNav.oldest], [true, true],
    "at the oldest generation, backwards must be disabled.");
  assert.deepStrictEqual([backNav.newer, backNav.latest], [false, false],
    "and forwards must be available.");
  var backGens = generationRows(await historyRows());
  assert.ok(backGens[1].inHand && !backGens[0].inHand,
    "the marked row should have moved with it.");
  // The pane that describes the credential in hand, and the request built from
  // it, must both follow: a proof of possession for the wrong key would be
  // refused by the issuer.
  await driver.wait(async function () {
    var proof = await value(driver, "vc_reissue_proof");
    if (!proof) return false;
    return JSON.stringify(jsonFromB64u(proof.split(".")[0])
                          .jwk) === generations.holderJwk;
  }, fetchWait, "the Credential Request should be rebuilt for the holder key " +
      "now in hand.");
  var status = await text(driver, "vc_history_status");
  assert.ok(/not the newest/.test(status),
    "and the page should say you are on an older generation. Got: " + status);
  log.info("[history] OK — Older put generation 1 back in hand, with its " +
           "key, and rebuilt the request.");

  // ---- forwards, and the two ends ----------------------------------------
  await click(driver, By.id("vc_history_newer_button"));
  await driver.wait(async function () {
    return /^generation 2 of 2/.test((await navState()).position);
  }, fetchWait, "Newer should move forward again.");
  assert.strictEqual(await heldCredential(), generations.refreshed,
    "and put the refreshed credential back in hand.");
  await click(driver, By.id("vc_history_oldest_button"));
  await driver.wait(async function () {
    return /^generation 1 of 2/.test((await navState()).position);
  }, fetchWait, "Oldest should jump to the first generation.");
  await click(driver, By.id("vc_history_latest_button"));
  await driver.wait(async function () {
    return /^generation 2 of 2/.test((await navState()).position);
  }, fetchWait, "Latest should jump to the newest generation.");
  log.info("[history] OK — Older/Newer/Oldest/Latest all move the " +
           "credential in hand.");

  // ---- an activated generation is a real state, not a page-local one ------
  await click(driver, By.id("vc_history_older_button"));
  await driver.wait(async function () {
    return /^generation 1 of 2/.test((await navState()).position);
  }, fetchWait, "Older should move back again.");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_history_table")), waitTime);
  // The table element is in the HTML; the pane renders into it from
  // localStorage after load. Wait for the position to say so, the same as the
  // clicks above do.
  await waitFor(driver,
                async function () { return (await navState()).position || ""; },
    function (pos) { return /^generation 1 of 2/.test(pos); },
    "the activated generation should survive a reload");
  // ... and step 3 verifies whatever the history activated, including the cnf
  // binding, which is the check that would fail if the key had not travelled.
  await driver.get(baseUrl + "/vc-issuance-3.html");
  await driver.wait(until.elementLocated(By.id("vc_credential_raw")), waitTime);
  // Waiting for the RIGHT value, not just any value: this is the assertion.
  await waitForValue(driver, "vc_credential_raw",
    function (v) { return v === generations.original; },
    "step 3 should show the generation the history activated");
  await assertStepThreeIsHappy(driver,
                               "the generation activated from the history");
  log.info("[history] OK — the activated generation survives a reload and " +
           "still verifies in step 3.");

  // ---- a long log: fixed height, scrolling, and capped at 100 -------------
  // Seeded rather than made by 120 real refreshes: what is under test is the
  // pane's behaviour with a long log, not the issuer's patience.
  await driver.get(baseUrl + "/vc-issuance-4.html");
  await driver.wait(until.elementLocated(By.id("vc_history_table")), waitTime);
  await driver.executeScript(
    "var real = " +
        "JSON.parse(localStorage.getItem('sdjwtvc_credential_history') " +
        "|| '[]');" +
    "var padded = [];" +
    "for (var i = 0; i < 120; i++) {" +
    "  padded.push({ id: 10000 + i, at: new Date(Date.now() - (120 - i) * " +
        "60000).toISOString()," +
    "                kind: 'token_refresh', outcome: (i % 7 === 0) ? " +
        "'failed' : 'success'," +
    "                detail: 'seeded attempt ' + (i + 1) });" +
    "}" +
    "localStorage.setItem('sdjwtvc_credential_history', " +
        "JSON.stringify(padded.concat(real)));");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_history_table")), waitTime);
  await driver.sleep(900);
  var longLog = await driver.executeScript(
    "var box = document.getElementById('vc_history_table');" +
    "var rows = box.querySelectorAll('tbody tr');" +
    "var head = box.querySelector('thead th');" +
    "return { rows: rows.length," +
    "         first: rows.length ? " +
        "rows[0].querySelectorAll('td')[0].textContent.trim() : ''," +
    "         last: rows.length ? rows[rows.length - " +
        "1].querySelectorAll('td')[0].textContent.trim() : ''," +
    "         numbered: " +
        "Array.prototype.slice.call(rows).every(function (tr) {" +
    "           return /^[0-9]+$/.test(tr.querySelectorAll('td')[0].textContent.trim()); })," +
    "         clientHeight: box.clientHeight, scrollHeight: box.scrollHeight," +
    "         overflowY: getComputedStyle(box).overflowY," +
    "         stickyHead: head ? getComputedStyle(head).position : ''," +
    "         note: box.textContent.indexOf('older one(s) are no longer " +
        "kept') !== -1 };");
  assert.strictEqual(longLog.rows, 100,
    "the pane should show the newest 100 attempts, got " + longLog.rows + ".");
  assert.ok(longLog.numbered,
            "and number every one of them in the first column.");
  assert.ok(Number(longLog.first) > Number(longLog.last),
    "newest first, so the first row carries the highest attempt number. Got " +
    longLog.first + " then " + longLog.last + ".");
  assert.ok(longLog.note,
            "and it should say that older attempts are no longer kept.");
  assert.strictEqual(longLog.overflowY, "auto",
                     "the list should scroll rather than grow.");
  assert.ok(longLog.scrollHeight > longLog.clientHeight,
    "with 100 rows there should be something to scroll: " +
        longLog.scrollHeight + " into " +
    longLog.clientHeight + "px.");
  assert.ok(longLog.clientHeight > 200 && longLog.clientHeight < 700,
    "and the box should keep a fixed, readable height. Got " +
        longLog.clientHeight + "px.");
  assert.strictEqual(longLog.stickyHead, "sticky",
    "the header should stay put while the rows scroll under it.");
  // The height is FIXED: it must not depend on how many rows there are.
  await driver.executeScript(
    "var one = JSON.parse(localStorage.getItem('sdjwtvc_credential_history')).slice(-1);" +
    "localStorage.setItem('sdjwtvc_credential_history', JSON.stringify(one));");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_history_table")), waitTime);
  await driver.sleep(700);
  var shortLog = await driver.executeScript(
    "var box = document.getElementById('vc_history_table');" +
    "return { rows: box.querySelectorAll('tbody tr').length, clientHeight: " +
        "box.clientHeight };");
  assert.strictEqual(shortLog.clientHeight, longLog.clientHeight,
    "the pane's height is fixed, so one row and a hundred must occupy the " +
        "same box. Got " +
    shortLog.clientHeight + " vs " + longLog.clientHeight + "px.");
  log.info("[history] OK — 100 of 120 attempts shown, all numbered, " +
           "scrolling in a fixed " +
           longLog.clientHeight + "px box with a sticky header.");

  // ---- clearing forgets the list, not the credential ----------------------
  await driver.get(baseUrl + "/vc-issuance-4.html");
  await driver.wait(until.elementLocated(By.id("vc_history_clear_button")),
                    waitTime);
  await driver.sleep(600);
  await click(driver, By.id("vc_history_clear_button"));
  await driver.wait(async function () {
    return (await historyRows()).length === 0;
  }, fetchWait, "Clear History should empty the list.");
  assert.strictEqual(await heldCredential(), generations.original,
    "clearing the history must not touch the credential in hand.");
  var cleared = await text(driver, "vc_history_status");
  assert.ok(/untouched/.test(cleared),
    "and should say the credential is untouched. Got: " + cleared);
  var clearedNav = await navState();
  assert.ok(clearedNav.older && clearedNav.newer,
    "with nothing recorded there is nowhere to navigate. Got: " +
        JSON.stringify(clearedNav));
  log.info("[history] OK — Clear History forgets the generations and keeps " +
           "the credential.");
  log.debug("Leaving credentialHistoryNavigation().");
}

// ---------------------------------------------------------------------------
// What step 4 does when the first of section 14.5's mechanisms is not
// available.
//
// A refresh token that has expired or been revoked, and no refresh token at all
// (which is the normal state after the pre-authorized code grant), both leave
// the wallet with the other routes: ask the Credential Endpoint again with the
// access token it still has (section 14.3), or start the issuance over. The
// page has to say so instead of offering a button that cannot work.
//
// Runs AFTER the browser-console check: a refused refresh legitimately earns a
// 400, which Chrome logs as a page error.
// ---------------------------------------------------------------------------
async function refreshNegatives(driver) {
  log.debug("Entering refreshNegatives().");
  log.info("=== Step 4 without a usable refresh token ===");

  // A refresh token the authorization server will not accept. Poisoned rather
  // than removed: "the server refused it" and "there is none" are different
  // states and the page has to distinguish them.
  await driver.get(baseUrl + "/vc-issuance-4.html");
  await driver.wait(until.elementLocated(By.id("vc_refresh_button")), waitTime);
  await driver.executeScript(
    "localStorage.setItem('token_refresh_token', arguments[0]);",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJub3QtYS1yZWFsLXJlZnJlc2gtdG9rZW4ifQ.bm90LWEtc2lnbmF0dXJl");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_refresh_button")), waitTime);
  await driver.sleep(500);
  await click(driver, By.id("vc_refresh_button"));
  var refused = await waitForStatus(driver, "vc_refresh_status",
    function (s) { return /refused|failed/.test(s); },
              "a bad refresh token produced no verdict");
  assert.ok(/refused the refresh/.test(refused),
    "the page should report the server's refusal. Got: " + refused);
  assert.ok(/start the issuance\s+again from step 1/.test(refused),
    "and should name the route that remains when a refresh token is dead " +
        "(section 14.5). Got: " + refused);
  var responseShown = await text(driver, "vc_refresh_response");
  assert.ok(/invalid_grant|error/.test(responseShown),
    "the authorization server's answer should be shown verbatim. Got: " +
        responseShown.slice(0, 120));
  // A failed attempt is still an attempt, and the log is where it has to show
  // up.
  var failedRow = await driver.executeScript(
    "var rows = Array.prototype.slice.call(document.querySelectorAll('#vc_history_table tbody tr'));" +
    "for (var i = 0; i < rows.length; i++) {" +
    "  var td = rows[i].querySelectorAll('td');" +
    "  if (td[3].textContent.trim() === 'Access token refresh' && " +
        "td[4].textContent.trim() === 'FAILED') {" +
    "    return { n: td[0].textContent.trim(), gen: td[1].textContent.trim()," +
    "             detail: td[5].textContent.trim()," +
    "             logOnly: /log only/.test(td[7].textContent) };" +
    "  }" +
    "} return null;");
  assert.ok(failedRow,
      "the refused refresh should be recorded in the Credential History pane.");
  assert.ok(/invalid_grant|HTTP 4/.test(failedRow.detail),
    "with what the server said. Got: " + failedRow.detail);
  assert.ok(/^[0-9]+$/.test(failedRow.n),
            "it is numbered like every other attempt. Got: " + failedRow.n);
  assert.strictEqual(failedRow.gen, "—",
                     "but a failed refresh is not a credential generation.");
  assert.ok(failedRow.logOnly, "and cannot be activated.");
  assert.ok(/failed/.test(await text(driver, "vc_history_position")),
    "the position line should count the failure. Got: " + (await text(driver,
        "vc_history_position")));
  log.info("[step4] OK — a refused refresh is reported and recorded: " +
           failedRow.detail.replace(/\s+/g, " ").slice(0, 90));

  // No refresh token at all — the state OID4VCI's pre-authorized code grant
  // normally leaves behind.
  await driver.executeScript("localStorage.removeItem('token_refresh_token');");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_reissue_button")), waitTime);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_reissue_proof"));
  }, fetchWait, "with no refresh token, step 4 should still build the " +
      "Credential Request.");
  var none = await driver.executeScript(
    "return { status: " +
        "document.getElementById('vc_refresh_status').textContent.trim()," +
    "         call: document.getElementById('vc_refresh_request').value," +
    "         disabled: " +
        "document.getElementById('vc_refresh_button').disabled };");
  assert.strictEqual(none.disabled, true,
    "with nothing to refresh with, the button must not offer a call it " +
        "cannot make.");
  assert.strictEqual(none.call, "",
                     "and no call should be shown, because there is none.");
  assert.ok(/no refresh token/i.test(none.status) && /14\.3/.test(none.status),
    "the page should say what is missing and which routes remain. Got: " +
        none.status);
  log.info("[step4] OK — with no refresh token: " + none.status.replace(/\s+/g,
           " ").slice(0, 120));

  // Section 14.3: the Credential Endpoint may still be asked with the access
  // token already in hand, and that is a refresh too.
  var heldBefore = await driver.executeScript(
      "return localStorage.getItem('sdjwtvc_credential');");
  await click(driver, By.id("vc_reissue_button"));
  var status14_3 = await waitForStatus(driver, "vc_reissue_status",
    function (s) { return /returned a credential|refused|failed/.test(s); },
    "the section 14.3 request produced no verdict");
  assert.ok(/returned a credential/.test(status14_3),
    "with a valid access token the Credential Endpoint may be asked " +
        "again. Got: " + status14_3);
  var second = await value(driver, "vc_compare_refreshed_raw");
  assert.ok(second && second !== heldBefore,
            "and it should produce another credential.");
  assert.strictEqual(await driver.executeScript(
                     "return localStorage.getItem('sdjwtvc_credential');"),
    heldBefore, "which again must not replace the one in hand on its own.");

  // Declining it must leave the wallet exactly as it was — including the holder
  // key, which a discarded refresh must not rotate.
  var keyBefore = await driver.executeScript(
      "return localStorage.getItem('sdjwtvc_holder_jwk');");
  await click(driver, By.id("vc_discard_button"));
  await driver.sleep(400);
  var afterDiscard = await driver.executeScript(
    "return { held: localStorage.getItem('sdjwtvc_credential')," +
    "         pending: localStorage.getItem('sdjwtvc_refreshed_credential')," +
    "         pendingKey: " +
        "localStorage.getItem('sdjwtvc_refreshed_holder_private_jwk')," +
    "         key: localStorage.getItem('sdjwtvc_holder_jwk') };");
  assert.strictEqual(afterDiscard.held, heldBefore,
                     "discarding must not touch the credential in hand.");
  assert.strictEqual(afterDiscard.pending, null,
                     "the discarded credential should be gone.");
  assert.strictEqual(afterDiscard.pendingKey, null,
                     "and so should any key it would have bound.");
  assert.strictEqual(afterDiscard.key, keyBefore,
    "a discarded refresh must not rotate the holder key — the credential in " +
        "hand still needs it.");
  // Discarding does not erase the fact that the issuer returned one.
  var discardedRow = await driver.executeScript(
    "var rows = Array.prototype.slice.call(document.querySelectorAll('#vc_history_table tbody tr'));" +
    "for (var i = 0; i < rows.length; i++) {" +
    "  var td = rows[i].querySelectorAll('td');" +
    "  if (td[4].textContent.trim() === 'discarded') {" +
    "    return { n: td[0].textContent.trim(), gen: td[1].textContent.trim()," +
    "             attempt: td[3].textContent.trim()," +
    "             detail: td[5].textContent.trim(), credential: " +
        "td[6].textContent.trim() };" +
    "  }" +
    "} return null;");
  assert.ok(discardedRow, "the discarded credential should stay in the log " +
            "as a discarded attempt.");
  assert.strictEqual(discardedRow.attempt, "Credential Request",
    "named as the attempt it was. Got: " + discardedRow.attempt);
  assert.ok(/^[0-9]+$/.test(discardedRow.n),
            "numbered like every other attempt. Got: " + discardedRow.n);
  assert.strictEqual(discardedRow.gen, "—",
    "and it is not a generation, because it was never held.");
  assert.strictEqual(discardedRow.credential, "—",
    "the credential itself should be gone — discarded has to mean " +
        "discarded. Got: " + discardedRow.credential);
  log.info("[step4] OK — section 14.3 works without a refresh token, " +
           "declining changes nothing, and both " +
           "attempts are on record.");
  log.debug("Leaving refreshNegatives().");
}

// ---------------------------------------------------------------------------
// The Inspect links on step 2 lead to the JWT detail page, which has to show
// the token step 2 is showing and come BACK to step 2 — not to oauth2_oidc_2.html,
// which is where it goes by default.
// ---------------------------------------------------------------------------
async function inspectLinksReturnHere(driver) {
  log.debug("Entering inspectLinksReturnHere().");
  log.info("=== The Inspect links on step 2 ===");
  await driver.get(baseUrl + "/vc-issuance-2.html");
  await driver.wait(until.elementLocated(By.id("vc_access_token")), waitTime);
  // Both fields exist in the HTML before the page restores them from
  // localStorage, so wait for the values rather than for the elements.
  var onPage2 = {
    access: await waitForFilled(driver, "vc_access_token",
      "step 2 never showed the access token, so there is nothing to inspect"),
    id: await waitForFilled(driver, "vc_id_token",
      "step 2 never showed the id token, so there is nothing to inspect")
  };

  for (const which of ["access", "id"]) {
    var index = which === "access" ? 0 : 1;
    var links = await driver.findElements(By.linkText("Inspect"));
    assert.ok(links.length > index,
              "step 2 should offer an Inspect link for the " + which +
              " token.");
    var href = await links[index].getAttribute("href");
    assert.ok(href.indexOf("from=vc-issuance-2.html") !== -1,
      "the Inspect link should name the page it came from, so the detail " +
          "page can come back. Got: " + href);
    await driver.executeScript("arguments[0].click();", links[index]);
    // #jwt_payload is in the static HTML, so locating it proves nothing. The
    // page fills it only after fetching /claimdescription and walking the whole
    // IANA claim registry, which takes a variable few hundred milliseconds —
    // the fixed sleep this replaced lost that race twice.
    var shown = await waitForJson(driver, "jwt_payload",
      "the token detail page never decoded the " + which + " token");
    var expected = jsonFromB64u(onPage2[which].split(".")[1]);
    assert.deepStrictEqual(shown, expected,
      "the detail page should decode the " + which +
          " token step 2 is showing.");

    var returnLinks = await driver.findElements(By.css("a.return_link"));
    assert.ok(returnLinks.length,
              "the detail page should offer a return link.");
    var target = await returnLinks[0].getAttribute("href");
    assert.ok(/vc-issuance-2\.html$/.test(target),
      "the return link should come back to step 2, got: " + target);
    assert.ok(/step 2/i.test(await returnLinks[0].getText()),
      "the return link should say where it goes: " +
          (await returnLinks[0].getText()));
    await driver.executeScript("arguments[0].click();", returnLinks[0]);
    await driver.wait(until.elementLocated(By.id("vc_approve_button")),
                      waitTime,
      "the return link did not come back to step 2.");
    log.info("[inspect] OK — the " + which +
             " token is decoded there and the link returns to step 2.");
  }

  // Everything else still returns to oauth2_oidc_2.html, and the parameter
  // cannot be turned into a redirect somewhere else.
  for (const query of ["?type=access",
       "?type=access&from=https://evil.example.com",
       "?type=access&from=nope"]) {
    await driver.get(baseUrl + "/token_detail.html" + query);
    await driver.wait(until.elementLocated(By.css("a.return_link")), waitTime);
    await driver.sleep(200);
    var link = (await driver.findElements(By.css("a.return_link")))[0];
    assert.ok(/\/oauth2_oidc_2\.html\?redirectFromTokenDetail=true$/.test(
              await link.getAttribute("href")),
      "with " + query + " the return link should stay on the default. Got: " +
          (await link.getAttribute("href")));
  }
  log.info("[inspect] OK — an unknown or hostile from= falls back to " +
           "oauth2_oidc_2.html.");
  log.debug("Leaving inspectLinksReturnHere().");
}

// ---------------------------------------------------------------------------
// Step 2 stands on its own: opened directly, with an issuer configured but no
// tokens yet, it still shows the request it would make. Only the access token
// is missing, and it says so.
// ---------------------------------------------------------------------------
async function stepTwoWithoutTokens(driver) {
  log.debug("Entering stepTwoWithoutTokens().");
  log.info("=== Step 2 opened directly, before authenticating ===");
  await driver.executeScript(
    "localStorage.removeItem('token_access_token');" +
    "localStorage.removeItem('token_id_token');" +
    "localStorage.removeItem('token_refresh_token');");
  await driver.get(baseUrl + "/vc-issuance-2.html");
  await driver.wait(until.elementLocated(By.id("vc_approve_button")), waitTime);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "with no access token, step 2 still has to show the request " +
      "it would make.");

  var state = await driver.executeScript(
    "return { nonce: document.getElementById('vc_nonce').textContent.trim()," +
    "         body: " +
        "document.getElementById('vc_request_body').textContent.trim()," +
    "         tokens: " +
        "document.getElementById('tokens_status').textContent.trim()," +
    "         approval: " +
        "document.getElementById('vc_approval_status').textContent.trim() };");
  assert.ok(state.nonce && state.nonce.indexOf("—") !== 0,
    "the c_nonce should be fetched even before authenticating. Got: " +
        JSON.stringify(state.nonce));
  assert.ok(JSON.parse(state.body).proofs.jwt[0],
            "the request body should be built and shown.");
  assert.ok(/no access token/i.test(state.tokens),
    "the tokens pane should say the access token is missing. Got: " +
        state.tokens);
  assert.ok(/no access token/i.test(state.approval),
    "the approval status should say what is missing rather than showing " +
        "three blank boxes. Got: " +
    state.approval);
  log.info("[step2] OK — the request is shown without tokens, and the " +
           "missing token is named.");
  log.debug("Leaving stepTwoWithoutTokens().");
}

// ---------------------------------------------------------------------------
// Preparing the request up front means the c_nonce in it can be spent — or can
// expire — before the user gets around to approving. The page has to notice and
// rebuild rather than fail. Here the nonce is spent behind the page's back,
// using the holder key it generated, and Approve must still work.
//
// Runs AFTER the browser-console check: the first attempt legitimately earns a
// 400 from the issuer, which Chrome logs as a page error.
// ---------------------------------------------------------------------------
async function staleProofRecovery(driver) {
  log.debug("Entering staleProofRecovery().");
  log.info("=== A proof that went stale before Approve ===");
  await driver.get(baseUrl + "/vc-issuance-2.html");
  await driver.wait(until.elementLocated(By.id("vc_approve_button")), waitTime);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 never prepared a proof.");
  await driver.sleep(300);

  var state = await driver.executeScript(
    "return { privateJwk: localStorage.getItem('sdjwtvc_holder_private_jwk')," +
    "         nonce: document.getElementById('vc_nonce').textContent.trim()," +
    "         issuer: " +
        "document.getElementById('vc_credential_issuer').textContent.trim()," +
    "         endpoint: document.getElementById('vc_credential_endpoint').textContent.trim() };");

  // Spend the page's nonce: a second proof over the same nonce, signed with the
  // same holder key, sent straight to the issuer.
  var priv = crypto.createPrivateKey({ key: JSON.parse(state.privateJwk),
      format: "jwk" });
  var pub = crypto.createPublicKey(priv).export({ format: "jwk" });
  var head = b64u(JSON.stringify({ typ: "openid4vci-proof+jwt", alg: "ES256",
    jwk: { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y } }));
  var claims = b64u(JSON.stringify({ iss: clientId, aud: state.issuer,
    iat: Math.floor(Date.now() / 1000), nonce: state.nonce }));
  var sig = b64u(crypto.sign("sha256", Buffer.from(head + "." + claims),
    { key: priv, dsaEncoding: "ieee-p1363" }));
  var stolen = await httpJson(state.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json",
              "Authorization": "Bearer spender" },
    body: JSON.stringify({ credential_configuration_id: "IdentityCredential",
                           proofs: { jwt: [head + "." + claims + "." + sig] } })
  });
  assert.ok(stolen.ok,
      "the setup for this check failed: the issuer refused the second proof (" +
      stolen.raw + ").");

  // The page's own proof is now unusable. Approving must still get a
  // credential.
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "approving with a spent c_nonce should rebuild the proof and retry, " +
        "not fail.");
  var credential = await value(driver, "vc_credential_raw");
  assert.ok(credential && credential.indexOf("~") > 0,
    "the retry should have produced a credential.");
  log.info("[stale proof] OK — a spent c_nonce is rebuilt and the " +
           "request retried.");
  log.debug("Leaving staleProofRecovery().");
}

// ---------------------------------------------------------------------------
// OID4VCI Appendix H.1, Credential Offer - Same-Device.
//
// "While browsing the university's home page, the End-User finds a link
// 'request your digital diploma' ... and is redirected to a digital Wallet. The
// Wallet notifies the End-User that a Credential Issuer offered to issue a
// diploma Credential."
//
// So this starts at the ISSUER, not at the wallet, and the whole thing runs on
// the STS mock, which is the credential issuer, the authorization server and
// the issuer's web page at once. Nothing is configured beforehand: a fresh
// browser gets everything from the offer.
// ---------------------------------------------------------------------------
// Point the wallet at the WRONG issuer before the offer arrives. Clearing the
// settings is not enough to prove an offer configured anything: the fields fall
// back to this deployment's defaults, which name the same issuer the offer came
// from, so the assertions would pass either way (a mutation of applyOffer()
// proved exactly that). Deliberately wrong values cannot be satisfied by
// accident — whatever is right afterwards was put there by the offer.
var WRONG_ISSUER = "http://localhost:8181/not-the-offering-issuer";

async function misconfigureTheWallet(driver) {
  log.debug("Entering misconfigureTheWallet().");
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "var wrong = {" +
    "  vci_metadata_endpoint: arguments[0] + " +
        "'/.well-known/openid-credential-issuer'," +
    "  vci_credential_issuer: arguments[0]," +
    "  vci_credential_endpoint: arguments[0] + '/credential'," +
    "  vci_deferred_credential_endpoint: arguments[0] + " +
        "'/deferred_credential'," +
    "  vci_credential_configuration_id: 'NotTheOfferedCredential'," +
    "  authorization_endpoint: arguments[0] + '/authorize'," +
    "  token_endpoint: arguments[0] + '/token'" +
    "};" +
    "Object.keys(wrong).forEach(function (k) { " +
        "window.localStorage.setItem(k, wrong[k]); });",
    WRONG_ISSUER);
  log.debug("Leaving misconfigureTheWallet(). The wallet now points at " +
            WRONG_ISSUER + ".");
}

async function credentialOfferSameDevice(driver) {
  log.debug("Entering credentialOfferSameDevice().");
  log.info("=== H.1: Credential Offer - Same-Device ===");

  // ---- step 0: the chooser ------------------------------------------------
  await driver.get(baseUrl + "/vc-issuance-0.html");
  await driver.wait(until.elementLocated(By.css("button.vc-usecase")),
                    waitTime);
  // Start with no use case chosen and no offer in hand — and then say which
  // issuer this wallet is configured for, because that is what step 0 needs to
  // know to send the End-User to the issuer's own page. Leaving it to whatever
  // an earlier section happened to store (or to the build-time default) is how
  // this section silently starts testing a different issuer.
  await driver.executeScript(
    "window.localStorage.clear();" +
    "window.localStorage.setItem('vci_credential_issuer', arguments[0]);" +
    "window.localStorage.setItem('vci_metadata_endpoint', arguments[0] + " +
    "  '/.well-known/openid-credential-issuer');", issuerBase);
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.css("button.vc-usecase")),
                    waitTime);
  await driver.sleep(300);

  var cards = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('button.vc-usecase')).map(function (b) {" +
    "  return { id: b.id, disabled: b.disabled," +
    "           spec: b.querySelector('.vc-usecase-spec').textContent.trim()," +
    "           title: " +
        "b.querySelector('.vc-usecase-title').textContent.trim()," +
    "           summary: " +
        "b.querySelector('.vc-usecase-summary').textContent.trim()," +
    "           mechanics: " +
        "b.querySelector('.vc-usecase-mechanics').textContent.trim() };" +
    "});");
  assert.strictEqual(cards.length, 4,
                     "step 0 should offer all four use cases, got " +
                     cards.length + ".");
  assert.deepStrictEqual(cards.map(function (c) { return c.spec; }), ["H.6",
                         "H.1", "H.2", "H.3"],
    "the use cases should be listed by their Appendix H section.");
  cards.forEach(function (c) {
    assert.ok(c.summary.length > 40, c.spec +
              " should be described, not just named.");
    assert.ok(c.mechanics.length > 20, c.spec +
              " should say what it does on the wire.");
  });
  assert.deepStrictEqual(cards.filter(function (c) { return !c.disabled; })
                         .map(function (c) { return c.spec; }),
    ["H.6", "H.1", "H.2", "H.3"],
     "every use case this workflow implements should be choosable.");
  assert.strictEqual(cards.filter(function (c) { return c.disabled; }).length,
                     0,
    "nothing on step 0 should be listed as unavailable now that all four are " +
        "implemented.");
  log.info("[H.1] OK — step 0 describes all four use cases, and all four are " +
           "choosable.");

  // ---- the issuer's web page ----------------------------------------------
  await click(driver, By.id("vc_usecase_offer-same-device"));
  await driver.wait(until.urlContains("/issuer"), fetchWait,
    "choosing the offer use case should take the End-User to the ISSUER, not " +
        "the wallet.");
  var issuerPage = await driver.getCurrentUrl();
  assert.ok(issuerPage.indexOf(issuerBase) === 0,
    "the issuer page should belong to the configured credential issuer. Got: " +
        issuerPage);
  assert.ok((await driver.findElements(By.linkText("Request your " +
            "digital diploma"))).length,
    "the issuer page should carry the offer link H.1 describes.");
  log.info("[H.1] OK — the flow starts on the issuer page at " + issuerPage +
           ".");

  // Everything the offer is supposed to supply is pointed somewhere WRONG
  // first, so the assertions below cannot be satisfied by what step 1 left
  // behind or by this deployment's defaults.
  await misconfigureTheWallet(driver);
  await driver.get(issuerPage);
  await driver.wait(until.elementLocated(By.linkText("Request your " +
                    "digital diploma")), waitTime);

  // ---- following the link hands the wallet an offer ------------------------
  await click(driver, By.linkText("Request your digital diploma"));
  // If the hand-off does not arrive, say WHERE the browser ended up. The issuer
  // builds that URL from OID4VCI_WALLET_URL, whose default
  // (http://localhost:3000) is right only when the browser and the wallet share
  // a host — in the containerized stack the browser is in the tests container,
  // where localhost:3000 is nothing at all. On its own the wait below just
  // times out, which says the hand-off failed but not that it was aimed at the
  // wrong host.
  try {
    await driver.wait(until.elementLocated(By.id("pane_offer")), fetchWait);
  } catch (e) {
    var landed = await driver.getCurrentUrl();
    throw new Error("the link should take the End-User back to the wallet " +
                    "with a Credential Offer, but the " +
      "browser ended up at " + landed + " and the wallet under test is " +
          baseUrl + ". The issuer builds " +
      "that URL from OID4VCI_WALLET_URL: set it to the base URL the BROWSER " +
          "uses (the containerized stack " +
      "needs http://client:3000). Original error: " + e.message);
  }
  await driver.wait(async function () {
    return !!(await value(driver, "authorization_endpoint"));
  }, fetchWait, "the wallet should discover the offering issuer and its " +
      "authorization server by itself.");
  await driver.sleep(300);

  var shown = await driver.executeScript(
    "return { url: location.href," +
    "         visible: document.getElementById('pane_offer').style.display " +
        "!== 'none'," +
    "         grant: " +
        "document.getElementById('offer_grant').textContent.trim()," +
    "         source: " +
        "document.getElementById('offer_source').textContent.trim()," +
    "         json: document.getElementById('offer_json').textContent," +
    "         badge: (document.getElementById('vc_use_case_badge') || " +
        "{}).textContent || '' };");
  assert.ok(shown.visible,
            "the offer pane should be shown when an offer arrives.");
  assert.ok(shown.url.indexOf("credential_offer=") !== -1,
    "the offer should arrive in the URL, by value. Got: " + shown.url.slice(0,
        80));
  var offer = JSON.parse(shown.json);
  assert.strictEqual(offer.credential_issuer, issuerBase,
                     "the offer should name the issuer.");
  assert.deepStrictEqual(offer.credential_configuration_ids,
                         ["IdentityCredential"],
    "the offer should name the credential on offer.");
  var issuerState = ((offer.grants || {}).authorization_code ||
      {}).issuer_state;
  assert.ok(issuerState, "an H.1 offer uses the authorization_code grant and " +
            "carries an issuer_state.");
  assert.ok(shown.grant.indexOf("authorization_code") === 0 &&
            shown.grant.indexOf(issuerState) !== -1,
    "the pane should show the grant and its issuer_state. Got: " + shown.grant);
  assert.ok(shown.source.indexOf("by value") !== -1,
    "the pane should say how the offer arrived. Got: " + shown.source);
  assert.ok(shown.badge.indexOf("H.1") !== -1,
    "every page should say which use case is running. Got: " + shown.badge);

  var applied = await driver.executeScript(
    "return { metadataUrl: " +
        "document.getElementById('vci_metadata_endpoint').value," +
    "         credentialId: " +
        "document.getElementById('vci_credential_configuration_id').value," +
    "         credentialEndpoint: " +
        "document.getElementById('vci_credential_endpoint').value," +
    "         authorization: " +
        "document.getElementById('authorization_endpoint').value," +
    "         token: document.getElementById('token_endpoint').value };");
  assert.strictEqual(applied.metadataUrl, issuerBase +
                     "/.well-known/openid-credential-issuer",
    "the offer should point the metadata URL at the offering issuer.");
  assert.strictEqual(applied.credentialId, "IdentityCredential",
    "the offered credential should be the one selected.");
  assert.ok(applied.credentialEndpoint && applied.authorization &&
            applied.token,
    "the wallet should have discovered the issuer AND its " +
        "authorization server: " + JSON.stringify(applied));
  log.info("[H.1] OK — the offer is shown as received, and it configured the " +
           "issuer, the credential and " +
           "the authorization server with nothing typed in.");

  // ---- authorize: the issuer_state must go back with the request ----------
  //
  // Which authorization server this reaches depends on what the issuer's
  // metadata advertises: the STS mock itself when it is standalone, or Keycloak
  // in the containerized suite. The issuer_state assertion holds either way;
  // the ones about what the login screen SAYS only make sense for the mock,
  // which is the one that knows it issued the offer.
  var mockIsTheAs = applied.authorization.indexOf(issuerBase) === 0;
  var signInUser = mockIsTheAs ? "diploma.student" : clientId;
  var signInPassword = mockIsTheAs ? "any-password" : clientId;

  // An earlier part of this run signed in at that authorization server, and the
  // session would carry straight through without a prompt — correct behaviour,
  // but it hides the authorization request this section exists to inspect.
  // (driver.manage().deleteAllCookies() is no help: it only clears the origin
  // the browser is currently on, which is the wallet, not the server.)
  var logoutUrl = applied.authorization
    .replace(/\/protocol\/openid-connect\/auth$/,
             "/protocol/openid-connect/logout")
    .replace(/\/oauth2\/authorize$/, "/oauth2/logout");
  log.info("[H.1] Signing out of " + logoutUrl +
           " so the authorization request is made afresh.");
  await driver.get(logoutUrl);
  await driver.sleep(600);
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("start_issuance_button")),
                    waitTime);
  await driver.sleep(400);

  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "the workflow should reach the authorization server's login screen.");
  var authzUrl = await driver.getCurrentUrl();
  assert.ok(authzUrl.indexOf("issuer_state=" + issuerState) !== -1,
    "the authorization request MUST carry the offer's issuer_state (OID4VCI " +
        "section 4.1.1). Got: " + authzUrl);
  if (mockIsTheAs) {
    var loginText =
        await driver.executeScript("return document.body.innerText;");
    assert.ok(loginText.indexOf(issuerState) !== -1,
      "the authorization server should show the issuer_state it received.");
    assert.ok(loginText.indexOf("from a Credential Offer this " +
              "issuer made") !== -1,
      "the authorization server should recognise its own issuer_state.");
    log.info("[H.1] OK — issuer_state travelled into the authorization " +
             "request, and the issuer " +
             "recognised it as its own.");
  } else {
    log.info("[H.1] OK — issuer_state travelled into the authorization " +
             "request (the authorization " +
             "server here is " + applied.authorization.split("/protocol")[0] +
                 ", not the mock, so what it " +
             "displays is not asserted).");
  }

  // ---- and then the flow the other use case already proved ----------------
  await driver.findElement(By.id("username")).sendKeys(signInUser);
  await driver.findElement(By.id("password")).sendKeys(signInPassword);
  await click(driver, By.id("kc-login"));
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
    "after signing in the workflow should come back to step 2.");
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 should prepare the credential request.");
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "approving should produce the credential.");
  var credential = await waitForFilled(driver, "vc_credential_raw",
    "H.1 should end with a credential");
  var payload = jsonFromB64u(credential.split("~")[0].split(".")[1]);
  assert.strictEqual(payload.iss, issuerBase,
      "the credential should come from the issuer that made the offer.");
  assert.strictEqual(payload.vct, EXPECTED_VCT,
                     "it should be the credential that was offered.");
  assert.ok(String(payload.sub).length > 0 && String(payload.username ||
            payload.sub).length > 0,
    "the credential should describe a subject. Got: " + payload.sub);
  if (mockIsTheAs) {
    assert.ok(String(payload.sub).indexOf(signInUser) !== -1,
      "it should describe the user who signed in. Got: " + payload.sub);
  }
  var failed = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_checks " +
        "tbody tr'))" +
    "  .filter(function (tr) { return " +
        "tr.querySelectorAll('td')[1].textContent.trim() === 'FAILED'; })" +
    "  .map(function (tr) { return " +
        "tr.querySelectorAll('td')[0].textContent.trim(); });");
  assert.strictEqual(failed.length, 0,
                     "no check should fail on the H.1 credential: " +
                     failed.join(", "));
  log.info("[H.1] OK — the offered credential was issued to " + payload.sub +
           " and verifies.");

  // ---- the offer can also travel by reference -----------------------------
  await driver.get(issuerBase + "/issuer");
  await click(driver, By.linkText("Request it (offer by reference)"));
  await driver.wait(until.elementLocated(By.id("pane_offer")), fetchWait);
  await driver.wait(async function () {
    return (await text(driver, "offer_issuer")) === issuerBase;
  }, fetchWait, "an offer passed by reference should be fetched and shown.");
  var byRef = await driver.executeScript(
    "return { url: location.href, source: " +
        "document.getElementById('offer_source').textContent.trim() };");
  assert.ok(byRef.url.indexOf("credential_offer_uri=") !== -1,
    "the by-reference link should pass credential_offer_uri. Got: " +
        byRef.url.slice(0, 90));
  assert.ok(byRef.source.indexOf("by reference") !== -1,
    "the pane should say the offer was fetched by reference. Got: " +
        byRef.source);
  log.info("[H.1] OK — an offer passed by reference (credential_offer_uri) " +
           "is fetched and shown too.");

  // ---- discarding it returns to the wallet-initiated use case -------------
  await click(driver, By.id("offer_discard_button"));
  await driver.sleep(300);
  var afterDiscard = await driver.executeScript(
    "return { visible: document.getElementById('pane_offer').style.display " +
        "!== 'none'," +
    "         badge: (document.getElementById('vc_use_case_badge') || " +
        "{}).textContent || ''," +
    "         stored: localStorage.getItem('sdjwtvc_credential_offer') };");
  assert.strictEqual(afterDiscard.visible, false,
                     "discarding should hide the offer pane.");
  assert.strictEqual(afterDiscard.stored, null,
                     "discarding should forget the offer.");
  assert.ok(afterDiscard.badge.indexOf("H.6") !== -1,
    "discarding should fall back to the wallet-initiated use case. Got: " +
        afterDiscard.badge);
  log.info("[H.1] OK — the offer can be discarded, and the workflow falls " +
           "back to wallet-initiated.");
  log.debug("Leaving credentialOfferSameDevice().");
}

// ---------------------------------------------------------------------------
// The issuer's own defences — a mock that accepts anything would make the
// checks above meaningless.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// H.2 — Credential Offer, cross-device.
//
// The issuer shows a QR code on its own screen; the wallet is somewhere else,
// so nothing navigates it here. The offer carries a pre-authorized code instead
// of sending anyone to a login page — there is NO authorization request at all
// — and a Transaction Code that reached the End-User by a different channel is
// what ties the wallet on the other device to them.
//
// The Transaction Code is the part worth being strict about: it is the only
// thing standing between a photographed QR code and someone else's credential,
// so this section checks that the wallet refuses to send without it, that the
// issuer refuses a wrong one, and that the code is single use.
// ---------------------------------------------------------------------------
async function crossDeviceOffer(driver) {
  log.debug("Entering crossDeviceOffer().");
  log.info("=== H.2: Credential Offer - Cross-Device ===");

  // Step 0 needs to know which issuer to send the End-User to; the offer that
  // comes back is what configures everything else.
  await driver.get(baseUrl + "/vc-issuance-0.html");
  await driver.wait(until.elementLocated(By.css("button.vc-usecase")),
                    waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "window.localStorage.setItem('vci_credential_issuer', arguments[0]);" +
    "window.localStorage.setItem('vci_metadata_endpoint', arguments[0] + " +
    "  '/.well-known/openid-credential-issuer');", issuerBase);
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id(
                    "vc_usecase_offer-cross-device")), waitTime);
  await click(driver, By.id("vc_usecase_offer-cross-device"));

  // ---- the issuer's screen -------------------------------------------------
  await driver.wait(until.elementLocated(By.id("tx_code")), fetchWait,
    "the cross-device use case should show the issuer's QR screen, not send " +
        "the browser to the wallet.");
  var screen = await driver.executeScript(
    "var qr = document.getElementById('offer_qr');" +
    "return { url: location.href," +
    "         txCode: document.getElementById('tx_code').textContent.trim()," +
    "         offerUri: " +
        "document.getElementById('offer_uri').textContent.trim()," +
    "         qr: qr ? qr.src.slice(0, 21) : ''," +
    "         page: document.body.textContent };");
  assert.ok(screen.url.indexOf(issuerBase) === 0,
    "the QR screen belongs to the issuer, not the wallet. Got: " + screen.url);
  assert.strictEqual(screen.qr, "data:image/png;base64",
    "a cross-device offer is handed over as a QR code, so there should be " +
        "one on the issuer's screen.");
  assert.ok(/^\d{5}$/.test(screen.txCode),
    "the issuer should display a Transaction Code on its own screen. Got: " +
        screen.txCode);
  assert.ok(screen.offerUri.indexOf("openid-credential-offer://") === 0,
    "the QR code should carry the openid-credential-offer URI OID4VCI " +
        "registers. Got: " +
    screen.offerUri.slice(0, 60));
  assert.ok(screen.page.indexOf(screen.txCode) !== -1 &&
            screen.offerUri.indexOf(screen.txCode) === -1,
    "the Transaction Code must be shown on the screen and NOT travel in the " +
        "offer — that separation is " +
    "the whole point of it.");
  log.info("[H.2] OK — the issuer shows a QR code and a Transaction Code " +
           "that is not in the offer.");

  // ---- the wallet takes the scanned offer ---------------------------------
  // Poisoned first, so what the pane shows afterwards can only have come from
  // the offer itself (see misconfigureTheWallet).
  await misconfigureTheWallet(driver);
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("scan_offer_input")), waitTime);
  await driver.executeScript(
    "document.getElementById('scan_offer_input').value = arguments[0];",
        screen.offerUri);
  await click(driver, By.id("scan_offer_button"));
  // The expected value, not just any value: the wallet was pointed at a wrong
  // issuer on purpose, so "not empty" is already true.
  await driver.wait(async function () {
    return (await value(driver, "vci_credential_endpoint")) === issuerBase +
            "/oid4vci/credential";
  }, fetchWait, "taking the offer should discover the issuer it names.");
  await driver.sleep(400);

  var taken = await driver.executeScript(
    "return { offerShown: " +
        "document.getElementById('pane_offer').style.display !== 'none'," +
    "         grant: " +
        "document.getElementById('offer_grant').textContent.trim()," +
    "         metadataUrl: " +
        "document.getElementById('vci_metadata_endpoint').value," +
    "         credentialEndpoint: " +
        "document.getElementById('vci_credential_endpoint').value," +
    "         badge: (document.getElementById('vc_use_case_badge') || " +
        "{}).textContent || '' };");
  assert.ok(taken.offerShown, "the offer pane should show what was scanned.");
  assert.ok(taken.grant.indexOf("pre-authorized_code") !== -1,
    "the offer should be shown as using the pre-authorized code grant. Got: " +
        taken.grant);
  assert.ok(/Transaction Code is required/.test(taken.grant),
    "the pane should say a Transaction Code is required before anything is " +
        "sent. Got: " + taken.grant);
  assert.strictEqual(taken.metadataUrl, issuerBase +
                     "/.well-known/openid-credential-issuer",
    "the scanned offer names only the issuer, so the wallet has to derive " +
        "its metadata URL.");
  assert.strictEqual(taken.credentialEndpoint, issuerBase +
                     "/oid4vci/credential",
    "the wallet should have read the issuer's metadata off the back of " +
        "the offer.");
  assert.ok(taken.badge.indexOf("H.2") !== -1,
    "the workflow should say which use case it is running. Got: " +
        taken.badge);
  log.info("[H.2] OK — a pasted offer configured the wallet, with the issuer " +
           "poisoned beforehand.");

  // ---- no authorization request --------------------------------------------
  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
    "a pre-authorized offer must NOT go through the authorization server — " +
        "the End-User was already " +
    "identified, so the workflow should go straight to the Token Request.");
  await driver.wait(async function () {
    return !!(await text(driver, "vc_pre_authorized_code"));
  }, fetchWait,
      "step 2 should show the pre-authorized code it is about to redeem.");

  var pane = await driver.executeScript(
    "return { shown: " +
        "document.getElementById('pane_pre_authorized').style.display " +
        "!== 'none'," +
    "         code: document.getElementById('vc_pre_authorized_code').textContent.trim()," +
    "         hint: " +
        "document.getElementById('vc_tx_code_hint').textContent.trim()," +
    "         request: document.getElementById('vc_token_request').value," +
    "         accessToken: " +
        "document.getElementById('vc_access_token').value };");
  assert.ok(pane.shown,
      "the Token Request pane should be shown for a pre-authorized offer.");
  assert.ok(pane.code && pane.code.length > 10,
            "the pre-authorized code should be shown. Got: " + pane.code);
  assert.ok(/5 digits/.test(pane.hint),
    "the pane should say what Transaction Code the issuer wants. Got: " +
        pane.hint);
  assert.ok(pane.request.indexOf("grant_type=" +
            encodeURIComponent(PRE_AUTHORIZED_GRANT)) !== -1,
    "the assembled call should use the pre-authorized code grant. Got: " +
        pane.request.slice(0, 200));
  assert.ok(pane.request.indexOf("POST " + issuerBase + "/oauth2/token") === 0,
    "the assembled call should name the token endpoint. Got: " +
        pane.request.slice(0, 80));
  assert.strictEqual(pane.accessToken, "",
    "there should be no access token yet: nothing has been redeemed.");
  log.info("[H.2] OK — step 2 shows the Token Request before sending it, and " +
           "there is no access token yet.");

  // ---- the Transaction Code is not optional --------------------------------
  await click(driver, By.id("vc_token_request_button"));
  var refusedLocally = await waitForStatus(driver, "vc_token_status",
    function (s) { return s.trim() !== ""; },
    "the wallet said nothing when asked to send without a Transaction Code");
  assert.ok(/Transaction Code/i.test(refusedLocally) &&
            /type it in/i.test(refusedLocally),
    "with no Transaction Code typed the wallet should refuse to send at " +
        "all. Got: " + refusedLocally);
  assert.strictEqual(await value(driver, "vc_access_token"), "",
    "nothing should have been issued.");

  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = '00000'; " +
        "vcissuance2.onTxCodeChange();");
  await click(driver, By.id("vc_token_request_button"));
  await driver.wait(async function () {
    return /refused/i.test((await text(driver, "vc_token_status")) || "");
  }, fetchWait, "the issuer should refuse a wrong Transaction Code.");
  var refusedByIssuer = await text(driver, "vc_token_status");
  assert.ok(/not correct|invalid/i.test(refusedByIssuer),
    "the refusal should say the Transaction Code is wrong. Got: " +
        refusedByIssuer);
  assert.strictEqual(await value(driver, "vc_access_token"), "",
    "a wrong Transaction Code must not produce an access token.");
  log.info("[H.2] OK — no Transaction Code is refused by the wallet, a wrong " +
           "one by the issuer.");

  // ---- the right one -------------------------------------------------------
  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = arguments[0]; " +
        "vcissuance2.onTxCodeChange();", screen.txCode);
  await click(driver, By.id("vc_token_request_button"));
  await driver.wait(async function () {
    return !!(await value(driver, "vc_access_token"));
  }, fetchWait, "the right Transaction Code should redeem the pre-authorized " +
      "code for an access token.");
  var accessToken = await value(driver, "vc_access_token");
  var claims = jsonFromB64u(accessToken.split(".")[1]);
  assert.ok(String(claims.sub || "").indexOf("urn:sts-mock:user:") === 0,
    "the access token should describe the End-User the issuer already knew " +
        "about. Got: " + claims.sub);
  log.info("[H.2] OK — the pre-authorized code was redeemed for an access " +
           "token describing " + claims.sub + ".");

  // The code is single use: a second redemption of the same offer must fail.
  var replay = await httpJson(issuerBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=" + encodeURIComponent(PRE_AUTHORIZED_GRANT) +
          "&pre-authorized_code=" + encodeURIComponent(pane.code) +
          "&tx_code=" + encodeURIComponent(screen.txCode)
  });
  assert.strictEqual(replay.status, 400,
    "a pre-authorized code is single use; replaying it should be refused. " +
        "Got HTTP " + replay.status);
  assert.ok(/already-used|Unknown/i.test(replay.raw),
    "the refusal should say the code has been used. Got: " + replay.raw.slice(0,
        160));
  log.info("[H.2] OK — the pre-authorized code cannot be redeemed twice.");

  // ---- and the credential --------------------------------------------------
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "approving should get the credential the offer was for.");
  await driver.sleep(800);
  await assertStepThreeIsHappy(driver, "H.2");
  log.info("[H.2] OK — the offered credential was issued with no " +
           "authorization request anywhere in the flow.");
  log.debug("Leaving crossDeviceOffer().");
}

// ---------------------------------------------------------------------------
// H.3 — Credential Offer, cross-device and deferred.
//
// Everything H.2 does, and then the issuer cannot produce the credential yet:
// the Credential Response is 202 with a transaction_id, and the wallet collects
// the credential from the Deferred Credential Endpoint once it is ready
// (OID4VCI section 9).
// ---------------------------------------------------------------------------
async function deferredIssuance(driver) {
  log.debug("Entering deferredIssuance().");
  log.info("=== H.3: Credential Offer - Cross-Device & Deferred ===");

  var meta = (await httpJson(issuerMetadataUrl)).body;
  assert.ok(meta.deferred_credential_endpoint,
    "an issuer that can defer says so with deferred_credential_endpoint; " +
        "this one should.");

  await driver.get(baseUrl + "/vc-issuance-0.html");
  await driver.wait(until.elementLocated(By.css("button.vc-usecase")),
                    waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "window.localStorage.setItem('vci_credential_issuer', arguments[0]);" +
    "window.localStorage.setItem('vci_metadata_endpoint', arguments[0] + " +
    "  '/.well-known/openid-credential-issuer');", issuerBase);
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_usecase_offer-deferred")),
                    waitTime);
  await click(driver, By.id("vc_usecase_offer-deferred"));

  await driver.wait(until.elementLocated(By.id("tx_code")), fetchWait,
    "the deferred use case also starts at the issuer's QR screen.");
  var screen = await driver.executeScript(
    "return { txCode: document.getElementById('tx_code').textContent.trim()," +
    "         offerUri: " +
        "document.getElementById('offer_uri').textContent.trim() };");

  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("scan_offer_input")), waitTime);
  await driver.executeScript(
    "document.getElementById('scan_offer_input').value = arguments[0];",
        screen.offerUri);
  await click(driver, By.id("scan_offer_button"));
  await driver.wait(async function () {
    return !!(await value(driver, "vci_deferred_credential_endpoint"));
  }, fetchWait, "the wallet should read the deferred endpoint out of the " +
      "issuer's metadata.");
  assert.strictEqual(await value(driver, "vci_deferred_credential_endpoint"),
    issuerBase + "/oid4vci/deferred_credential",
    "the deferred endpoint should be the one the issuer publishes.");

  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("vc_tx_code")), fetchWait);
  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = arguments[0]; " +
        "vcissuance2.onTxCodeChange();", screen.txCode);
  await click(driver, By.id("vc_token_request_button"));
  await driver.wait(async function () {
    return !!(await value(driver, "vc_access_token"));
  }, fetchWait, "the Transaction Code should redeem the pre-authorized code.");

  // ---- the issuer defers ---------------------------------------------------
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(async function () {
    return await driver.executeScript(
      "var e = document.getElementById('pane_deferred'); return !!e && " +
          "e.style.display !== 'none';");
  }, fetchWait, "a 202 with a transaction_id should put the workflow into " +
      "the deferred pane.");

  var deferred = await driver.executeScript(
    "return { transactionId: " +
        "document.getElementById('vc_transaction_id').textContent.trim()," +
    "         endpoint: " +
        "document.getElementById('vc_deferred_endpoint').textContent.trim()," +
    "         request: document.getElementById('vc_deferred_request').value," +
    "         response: " +
        "document.getElementById('vc_response_body').textContent };");
  assert.ok(deferred.transactionId && deferred.transactionId !== "—",
    "the deferred pane should show the transaction_id the issuer returned.");
  assert.strictEqual(deferred.endpoint, issuerBase +
                     "/oid4vci/deferred_credential",
    "it should name the endpoint it is going to poll.");
  assert.ok(deferred.request.indexOf("POST " + issuerBase +
            "/oid4vci/deferred_credential") === 0,
    "the assembled Deferred Credential Request should be shown. Got: " +
        deferred.request.slice(0, 80));
  assert.ok(deferred.request.indexOf('"transaction_id"') !== -1,
    "the request body is the transaction_id (OID4VCI section 9.1). Got: " +
        deferred.request);
  assert.ok(deferred.request.indexOf("Authorization: Bearer ") !== -1,
    "the deferred request must present the access token too.");
  assert.ok(deferred.response.indexOf(deferred.transactionId) !== -1,
    "the Credential Response that deferred the issuance should still be on " +
        "screen. Got: " +
    deferred.response.slice(0, 160));
  log.info("[H.3] OK — the issuer deferred the issuance and the wallet " +
           "showed the transaction it will poll.");

  // A transaction_id this issuer never made must be refused, or "pending" and
  // "there is no such thing" would be indistinguishable to a wallet.
  var bogus = await httpJson(issuerBase + "/oid4vci/deferred_credential", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + (await value(driver, "vc_access_token"))
    },
    body: JSON.stringify({
                         transaction_id: "not-a-transaction-this-issuer-made" })
  });
  assert.strictEqual(bogus.status, 400,
    "an unknown transaction_id should be refused. Got HTTP " + bogus.status);
  assert.ok(bogus.body && bogus.body.error === "invalid_transaction_id",
    "OID4VCI section 9.3 names that error invalid_transaction_id. Got: " +
        bogus.raw.slice(0, 160));

  // ---- the wallet waits, and collects --------------------------------------
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "the wallet should keep polling until the issuer has the " +
        "credential ready.");
  await driver.sleep(800);
  await assertStepThreeIsHappy(driver, "H.3");

  var record = await driver.executeScript(
    "return JSON.parse(window.localStorage.getItem('sdjwtvc_credential_meta') || '{}');");
  assert.strictEqual(record.deferred, true,
    "the workflow should record that this credential came from a deferred " +
        "issuance.");
  assert.ok(record.deferredAttempts >= 1,
    "it should record how many attempts that took. Got: " +
        record.deferredAttempts);
  assert.strictEqual(record.deferredEndpoint, issuerBase +
                     "/oid4vci/deferred_credential",
    "and where it collected the credential from.");
  log.info("[H.3] OK — the credential was collected from the deferred " +
           "endpoint after " +
           record.deferredAttempts + " attempt(s), and the workflow says so.");

  // Spent: the issuer invalidates the transaction_id once the credential has
  // been handed over, so the same poll must not yield a second copy.
  var replay = await httpJson(issuerBase + "/oid4vci/deferred_credential", {
    method: "POST",
    headers: { "Content-Type": "application/json",
              "Authorization": "Bearer replayed" },
    body: JSON.stringify({ transaction_id: deferred.transactionId })
  });
  assert.strictEqual(replay.status, 400,
    "a collected transaction_id must stop working (OID4VCI section 9). " +
        "Got HTTP " + replay.status);
  assert.ok(replay.body && replay.body.error === "invalid_transaction_id",
    "and the error should be invalid_transaction_id. Got: " +
        JSON.stringify(replay.body));
  log.info("[H.3] OK — the transaction_id stopped working once the " +
           "credential had been collected.");
  log.debug("Leaving deferredIssuance().");
}

// Step 3's verdicts, for a credential that a working issuer has just issued.
async function assertStepThreeIsHappy(driver, label) {
  log.debug("Entering assertStepThreeIsHappy(). label=" + label);
  var checks = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_checks " +
        "tbody tr')).map(function (tr) {" +
    "  var td = tr.querySelectorAll('td');" +
    "  return { name: td[0].textContent.trim(), result: " +
        "td[1].textContent.trim()," +
    "           detail: td[2].textContent.trim() };" +
    "});");
  assert.ok(checks.length >= 7, "step 3 should report its checks, got " +
            checks.length + ".");
  var failed = checks.filter(function (c) { return c.result === "FAILED"; });
  assert.strictEqual(failed.length, 0,
    label + ": no check should fail — " +
    failed.map(function (c) { return c.name + " — " + c.detail; }).join("; "));
  var signature =
      checks.filter(function (c) { return c.name === "Issuer signature"; })[0];
  assert.ok(signature && signature.result === "OK",
    label + ": the issuer signature should verify. Got: " +
        JSON.stringify(signature));
  var binding =
      checks.filter(function (c) { return c.name === "Key binding (cnf)"; })[0];
  assert.ok(binding && binding.result === "OK",
    label + ": the credential should be bound to the holder key. Got: " +
        JSON.stringify(binding));
  log.debug("Leaving assertStepThreeIsHappy().");
}

// ---------------------------------------------------------------------------
// authorization_details (RFC 9396) — OID4VCI's other way of saying which
// credential is wanted.
//
// A scope says "authorize me for this kind of credential".
// authorization_details of type openid_credential says the same thing in a
// structure that can carry more, and it changes what happens afterwards: the
// token response grants credential_identifiers, and the Credential Request must
// then name one of THEM and must not send a credential_configuration_id
// (section 8.2). Getting that backwards is the mistake worth catching, so both
// wrong ways are checked too.
// ---------------------------------------------------------------------------
async function authorizationDetailsFlow(driver) {
  log.debug("Entering authorizationDetailsFlow().");
  log.info("=== authorization_details and credential_identifier ===");

  var asMeta = (await httpJson(issuerBase +
      "/.well-known/oauth-authorization-server")).body;
  assert.ok((asMeta.authorization_details_types_supported ||
            []).indexOf("openid_credential") !== -1,
    "the authorization server should advertise authorization_details of type " +
        "openid_credential. Got: " +
    JSON.stringify(asMeta.authorization_details_types_supported));

  await stepOneConfigured(driver, "authorization_details");
  var note = await waitForStatus(driver, "handoff_mechanism_note",
    function (s) { return s.trim() !== ""; },
    "step 1 never said what it was about to send");
  assert.ok(note.indexOf("openid_credential") !== -1,
    "step 1 should say what it is about to send. Got: " + note);
  log.info("[authz details] OK — step 1 offers both ways of asking, and " +
           "describes the one chosen.");

  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "the authorization request should still reach the IdP.");
  var authzUrl = await driver.getCurrentUrl();
  assert.ok(authzUrl.indexOf("authorization_details=") !== -1,
    "the authorization request should carry authorization_details. Got: " +
        authzUrl);
  var sent = JSON.parse(decodeURIComponent(/authorization_details=([^&]*)/.exec(
      authzUrl)[1]));
  assert.strictEqual(sent[0].type, "openid_credential",
    "of type openid_credential. Got: " + JSON.stringify(sent));
  assert.strictEqual(sent[0].credential_configuration_id, VCI_CONFIG_ID,
    "naming the credential configuration chosen in step 1. Got: " +
        JSON.stringify(sent));
  log.info("[authz details] OK — the authorization request carried " +
           JSON.stringify(sent) + ".");

  await driver.findElement(By.id("username")).sendKeys(MOCK_AS_USER);
  await driver.findElement(By.id("password")).sendKeys("any-password");
  await click(driver, By.id("kc-login"));
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
    "the workflow should come back to step 2 with tokens.");
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 should assemble the request.");

  var granted = await driver.executeScript(
    "return JSON.parse(window.localStorage.getItem('token_authorization_details') || 'null');");
  assert.ok(granted && granted.length && granted[0].credential_identifiers &&
            granted[0].credential_identifiers.length,
    "the token response should have granted credential_identifiers. Got: " +
        JSON.stringify(granted));
  var identifier = granted[0].credential_identifiers[0];

  var body = JSON.parse(await text(driver, "vc_request_body"));
  assert.strictEqual(body.credential_identifier, identifier,
    "the Credential Request must name the granted identifier. Got: " +
        JSON.stringify(body));
  assert.ok(!("credential_configuration_id" in body),
    "and MUST NOT also send credential_configuration_id (OID4VCI section " +
        "8.2). Got: " + JSON.stringify(body));
  var mode = await text(driver, "vc_identifier_mode");
  assert.ok(mode.indexOf(identifier) !== -1,
    "step 2 should say which identifier it is using and why. Got: " + mode);
  log.info("[authz details] OK — the request names credential_identifier " +
           identifier +
           " and omits credential_configuration_id.");

  var accessToken = await value(driver, "vc_access_token");
  var proof = await value(driver, "vc_proof_jwt");
  var both = await httpJson(issuerBase + "/oid4vci/credential", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " +
              accessToken },
    body: JSON.stringify({
      credential_identifier: identifier,
          credential_configuration_id: VCI_CONFIG_ID,
      proofs: { jwt: [proof] }
    })
  });
  assert.strictEqual(both.status, 400,
    "sending both identifiers should be refused. Got HTTP " + both.status);
  assert.strictEqual(both.body.error, "invalid_credential_request",
    "with invalid_credential_request. Got: " + JSON.stringify(both.body));

  var wrongOne = await httpJson(issuerBase + "/oid4vci/credential", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " +
              accessToken },
    body: JSON.stringify({ credential_configuration_id: VCI_CONFIG_ID,
                         proofs: { jwt: [proof] } })
  });
  assert.strictEqual(wrongOne.status, 400,
    "with identifiers granted, credential_configuration_id should be " +
        "refused. Got HTTP " + wrongOne.status);
  assert.ok(/MUST NOT be used/.test(wrongOne.raw),
    "and the refusal should say why. Got: " + wrongOne.raw.slice(0, 160));

  var invented = await httpJson(issuerBase + "/oid4vci/credential", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " +
              accessToken },
    body: JSON.stringify({ credential_identifier: identifier + "-invented",
                         proofs: { jwt: [proof] } })
  });
  assert.strictEqual(invented.status, 400,
    "an identifier that was not granted should be refused. Got HTTP " +
        invented.status);
  assert.ok(/was not granted/.test(invented.raw),
    "and say so. Got: " + invented.raw.slice(0, 160));
  log.info("[authz details] OK — both identifiers together, the wrong one, " +
           "and an invented one are all refused.");

  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "naming the credential by its granted identifier should issue it.");
  await driver.sleep(800);
  await assertStepThreeIsHappy(driver, "authorization_details");
  log.info("[authz details] OK — the credential was issued against a granted " +
           "credential_identifier.");
  log.debug("Leaving authorizationDetailsFlow().");
}

// ---------------------------------------------------------------------------
// Asking for a SUBSET of the claims (OID4VCI section 5.1.1).
//
// The optional `claims` member belongs to the authorization_details entry, not
// to the Credential Request — section 8.2 defines no such member — so this
// section follows the selection from the pane on step 1 through the
// authorization request, the token response and into the credential itself.
//
// What the issuer advertises is read OFF THE WIRE rather than assumed: which
// claims this mock carries is configuration (/admin/vc), it survives between
// tests, and a test that hard-coded the shipped ten would fail naming somebody
// else's setting. The rows unchecked are chosen the same way, from what is
// there.
// ---------------------------------------------------------------------------
async function claimsSelection(driver) {
  log.debug("Entering claimsSelection().");
  log.info("=== The claims member of authorization_details ===");

  var meta = (await httpJson(issuerMetadataUrl)).body;
  var configs = meta.credential_configurations_supported || {};
  var config = configs[VCI_CONFIG_ID] || {};
  var advertised = config.claims || [];
  assert.ok(advertised.length >= 3,
    "this section needs an issuer that advertises several claims for " +
    VCI_CONFIG_ID + "; its metadata lists " + advertised.length + ".");
  var advertisedLabels = advertised.map(function (c) {
    return c.path.join(".");
  });
  // Only top-level claims are dropped, so that what the credential must no
  // longer carry is a claim of its own rather than one member of a nested
  // object — the credential-side assertion at the end is then about the
  // presence of a disclosure rather than about its contents.
  var droppable = advertised.filter(function (c) {
    return c.path.length === 1;
  });
  assert.ok(droppable.length >= 2,
    "this section drops two top-level claims; the issuer advertises " +
    droppable.length + ".");
  var dropped = droppable.slice(-2).map(function (c) {
    return c.path.join(".");
  });
  var kept = advertisedLabels.filter(function (label) {
    return dropped.indexOf(label) === -1;
  });

  await stepOneConfigured(driver, "authorization_details");

  // ---- the pane -----------------------------------------------------------
  // Deliberately not `log`ged inside: this function is serialised into the
  // page, where bunyan does not exist.
  var readRows = "return Array.prototype.slice.call(" +
    "document.querySelectorAll('#vc_claims_table tbody tr')).map(" +
    "function (tr) {" +
    "  var td = tr.querySelectorAll('td');" +
    "  return { checked: td[0].querySelector('input').checked," +
    "           id: td[0].querySelector('input').id," +
    "           label: td[1].textContent.trim()," +
    "           name: td[2].textContent.trim() };" +
    "});";
  var rows = await driver.executeScript(readRows);
  assert.deepStrictEqual(rows.map(function (r) { return r.label; }),
                         advertisedLabels,
    "the pane should offer exactly the claims the metadata advertises, in " +
    "its order. Got: " +
    JSON.stringify(rows.map(function (r) { return r.label; })));
  assert.ok(rows.every(function (r) { return r.checked; }),
    "every claim should be checked by default. Unchecked: " +
    rows.filter(function (r) { return !r.checked; })
        .map(function (r) { return r.label; }).join(", "));
  assert.ok(rows.some(function (r) { return r.name; }),
    "the pane should show the display names the issuer publishes for its " +
    "claims. Got: " + JSON.stringify(rows));
  log.info("[claims] OK — " + rows.length +
           " advertised claims, all checked, built from the metadata.");

  // With everything checked the request restricts nothing, and the pane has to
  // say so: sending every claim is what omitting the member means, and a pane
  // reporting "10 of 10 requested" would imply a member that is not there.
  var note = await text(driver, "vc_claims_note");
  assert.ok(/no claims member|none will be sent/i.test(note),
    "with everything selected the pane should say no claims member is sent. " +
    "Got: " + note);
  var mechanism = await text(driver, "handoff_mechanism_note");
  assert.ok(mechanism.indexOf("\"claims\"") === -1,
    "and the authorization_details it is about to send should carry no " +
    "claims member. Got: " + mechanism);

  // ---- uncheck two --------------------------------------------------------
  for (var i = 0; i < rows.length; i++) {
    if (dropped.indexOf(rows[i].label) !== -1) {
      await click(driver, By.id(rows[i].id));
    }
  }
  var afterNote = await text(driver, "vc_claims_note");
  kept.forEach(function (label) {
    assert.ok(afterNote.indexOf(label) !== -1,
      "the pane should list " + label + " as still requested. Got: " +
          afterNote);
  });
  dropped.forEach(function (label) {
    assert.ok(afterNote.indexOf(label) === -1,
      "and should not list the unchecked " + label + ". Got: " + afterNote);
  });
  var sending = await text(driver, "handoff_mechanism_note");
  var described = JSON.parse(/(\[.*\])/.exec(sending)[1]);
  assert.ok(described[0] && described[0].claims,
    "unchecking a claim should put a claims member into the " +
    "authorization_details the pane says it will send. Got: " +
        JSON.stringify(described));
  assert.deepStrictEqual(described[0].claims.map(function (c) {
    return c.path.join(".");
  }), kept,
    "the authorization_details shown should carry exactly the claims left " +
    "checked. Got: " + JSON.stringify(described));
  log.info("[claims] OK — unchecking " + dropped.join(" and ") +
           " put a claims member of " + kept.length + " into " +
           "authorization_details.");

  // The selection is configuration like everything else on this page, so it
  // has to survive the hand-off it is about to make.
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_claims_table")), waitTime);
  var reloaded = await driver.executeScript(readRows);
  assert.deepStrictEqual(reloaded.filter(function (r) { return !r.checked; })
                                 .map(function (r) { return r.label; }),
                         dropped,
    "the selection should survive a reload. Got: " + JSON.stringify(reloaded));

  // ---- the authorization request ------------------------------------------
  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "the authorization request should reach the identity provider.");
  var authzUrl = await driver.getCurrentUrl();
  var sent = JSON.parse(decodeURIComponent(/authorization_details=([^&]*)/.exec(
      authzUrl)[1]));
  assert.ok(sent[0] && sent[0].claims,
    "the authorization request must carry the claims member, or the issuer " +
    "has been asked for everything. Got: " + JSON.stringify(sent));
  assert.deepStrictEqual(sent[0].claims.map(function (c) {
    return c.path.join(".");
  }), kept,
    "the authorization request should carry the selection. Got: " +
        JSON.stringify(sent));
  log.info("[claims] OK — the authorization request carried " +
           JSON.stringify(sent[0].claims) + ".");

  await driver.findElement(By.id("username")).sendKeys(MOCK_AS_USER);
  await driver.findElement(By.id("password")).sendKeys("any-password");
  await click(driver, By.id("kc-login"));
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
    "the workflow should come back to step 2 with tokens.");
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 should assemble the request.");

  // ---- what the token response granted, and what step 2 says --------------
  var granted = await driver.executeScript(
    "return JSON.parse(window.localStorage.getItem(" +
    "'token_authorization_details') || 'null');");
  assert.ok(granted && granted[0] && granted[0].claims,
    "the token response should echo the claims it authorized (RFC 9396 " +
    "section 7). Got: " + JSON.stringify(granted));
  assert.deepStrictEqual(granted[0].claims.map(function (c) {
    return c.path.join(".");
  }), kept, "and they should be the ones asked for. Got: " +
        JSON.stringify(granted[0].claims));

  var approval = await text(driver, "vc_approval_claims");
  kept.forEach(function (label) {
    assert.ok(approval.indexOf(label) !== -1,
      "the approval pane should name " + label + " as requested. Got: " +
          approval);
  });
  dropped.forEach(function (label) {
    assert.ok(approval.indexOf(label) === -1,
      "and must not name the claim that was dropped (" + label + "), which " +
      "is what the user is being asked to approve. Got: " + approval);
  });
  log.info("[claims] OK — step 2 asks approval for " + kept.length +
           " of " + rows.length + " claims.");

  // ---- the credential ------------------------------------------------------
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "approving should issue the credential.");
  await driver.sleep(800);
  await assertStepThreeIsHappy(driver, "claims selection");
  var credential = await waitForFilled(driver, "vc_credential_raw",
      "step 3 should show the credential");
  var carried = credential.split("~").slice(1).filter(Boolean)
    .map(function (d) { return jsonFromB64u(d); })
    .filter(function (a) { return a.length === 3; })
    .map(function (a) { return a[1]; });
  dropped.forEach(function (label) {
    assert.ok(carried.indexOf(label) === -1,
      "the issued credential must not carry " + label + ", which was not " +
      "asked for. It carries: " + carried.join(", "));
  });
  kept.filter(function (label) { return label.indexOf(".") === -1; })
      .forEach(function (label) {
    assert.ok(carried.indexOf(label) !== -1,
      "the issued credential should carry " + label + ", which was asked " +
      "for. It carries: " + carried.join(", "));
  });
  log.info("[claims] OK — the credential carries " + carried.join(", ") +
           " and neither of the two claims that were unchecked.");

  // ---- and back to everything ---------------------------------------------
  // Left as it was found, because the sections after this one issue credentials
  // of their own and a selection nobody made would quietly narrow them.
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vc_claims_all_button")),
                    waitTime);
  await click(driver, By.id("vc_claims_all_button"));
  var restored = await driver.executeScript(readRows);
  assert.ok(restored.length && restored.every(function (r) {
    return r.checked;
  }), "Select All should re-check every row. Got: " + JSON.stringify(restored));
  log.debug("Leaving claimsSelection().");
}

// ---------------------------------------------------------------------------
// A selection that CANNOT be sent, which is the state this pane shipped in for
// a day and the first thing a person hit.
//
// `scope` is the default way of asking for the credential, and a scope request
// has nowhere to put a claims member — it belongs to authorization_details
// (section 5.1.1). So a subset chosen on the default route travels nowhere, the
// issuer quite correctly returns everything, and the pane MUST say so rather
// than reporting "9 of 10 will be asked for". The bug was not in the issuer,
// and the report it produced was "the mock ignores my selection".
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// WHICH WAY OF ASKING THE PAGE OFFERS BEFORE ANYBODY CHOOSES ONE.
//
// authorization_details, whenever the chosen configuration advertises claims —
// because that is the only route the pane below the select can travel on. The
// section below this one covers what happens when somebody chooses scope
// anyway; this one covers the choice nobody makes, which is the one that
// produced two reports of "the issuer ignored my selection".
//
// Three things are asserted rather than one, because the cheap version of this
// check passes on a page that has simply had the default hard-coded the other
// way round: a STORED choice must still win, and a configuration advertising no
// claims must still default to scope — otherwise this "fix" would quietly
// change the plain flow for every issuer that publishes no claims member.
// ---------------------------------------------------------------------------
async function authorizationDetailsIsTheDefault(driver) {
  log.debug("Entering authorizationDetailsIsTheDefault().");
  log.info("=== the request mechanism nobody chose ===");
  // Deliberately NOT stepOneConfigured(): that helper sets the mechanism
  // explicitly, which is the one thing this section must not do.
  await signOutOfMockAs(driver);
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript("window.localStorage.clear();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  var atLoad = await driver.executeScript(
    "return document.getElementById('handoff_request_mechanism').value;");
  assert.strictEqual(atLoad, "scope",
    "with no metadata retrieved there is nothing to choose from, so the " +
    "select should still read scope. Got: " + atLoad);

  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];",
    issuerMetadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "the credential issuer metadata was not retrieved");
  await driver.wait(async function () {
    return (await driver.findElements(By.css("#vc_claims_table tbody tr")))
        .length > 0;
  }, fetchWait, "the claims pane never filled");

  var defaulted = await driver.executeScript(
    "return { mechanism: " +
    "document.getElementById('handoff_request_mechanism').value," +
    "         note: document.getElementById('handoff_mechanism_note')" +
    "                 .textContent.trim()," +
    "         status: document.getElementById('vc_claims_status')" +
    "                   .textContent.trim() };");
  assert.strictEqual(defaulted.mechanism, "authorization_details",
    "a credential advertising claims should default to the route those " +
    "claims can travel on. Got: " + defaulted.mechanism);
  assert.ok(/default/.test(defaulted.note),
    "and the note under the select should say the page chose it rather than " +
    "the user. Got: " + defaulted.note);
  assert.ok(!/will NOT be sent/.test(defaulted.status),
    "so unchecking a claim can no longer produce a selection nothing sends. " +
    "Got: " + defaulted.status);
  log.info("[claims] OK — the default is authorization_details, and the " +
           "note says why.");

  // A choice, once made, is the answer: this fills in a blank and must not
  // overrule anybody.
  await driver.executeScript(
    "document.getElementById('handoff_request_mechanism').value = 'scope';" +
    "vcissuance1.onRequestMechanismChange();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_claims_table")), waitTime);
  var chosen = await driver.executeScript(
    "return document.getElementById('handoff_request_mechanism').value;");
  assert.strictEqual(chosen, "scope",
    "a mechanism somebody chose must survive a reload — the default fills in " +
    "a blank, it does not overrule an answer. Got: " + chosen);
  log.info("[claims] OK — an explicit scope choice still wins.");

  // And an issuer publishing no claims member gets the flow it always had.
  // Its metadata is edited in storage rather than looked for on another
  // service: what is under test is this page's rule, and no mock here
  // advertises a configuration without claims.
  await driver.executeScript(
    "window.localStorage.removeItem('sdjwtvc_request_mechanism');" +
    "var doc = JSON.parse(window.localStorage.getItem('vci_info'));" +
    "var configs = doc.credential_configurations_supported;" +
    "Object.keys(configs).forEach(function (k) {" +
    "  delete configs[k].claims;" +
    "});" +
    "window.localStorage.setItem('vci_info', JSON.stringify(doc));");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_claims_table")), waitTime);
  var noClaims = await driver.executeScript(
    "return { mechanism: " +
    "document.getElementById('handoff_request_mechanism').value," +
    "         rows: document.querySelectorAll(" +
    "'#vc_claims_table tbody tr').length," +
    "         status: document.getElementById('vc_claims_status')" +
    "                   .textContent.trim() };");
  assert.strictEqual(noClaims.rows, 0,
    "this check needs a configuration advertising no claims; the pane still " +
    "drew " + noClaims.rows + " row(s).");
  assert.strictEqual(noClaims.mechanism, "scope",
    "an issuer that publishes no claims member has nothing to choose, so " +
    "the plain scope flow must be what it always was. Got: " +
        noClaims.mechanism);
  assert.ok(/publishes no claims member/.test(noClaims.status),
    "and the pane should say why it is empty. Got: " + noClaims.status);
  log.info("[claims] OK — no advertised claims, no change: still scope.");

  // ---- and the authorization server has to be able to REDEEM it -----------
  //
  // The fourth bound on the default, and the one it shipped without: RFC 9396
  // section 10 has the authorization server publish
  // authorization_details_types_supported, and Keycloak's RFC 8414 document
  // omits the member entirely. It accepts the authorization request and issues
  // a code, then refuses it at the TOKEN request with
  // invalid_authorization_details — which stopped this workflow on
  // oauth2_oidc_2.html and failed the Keycloak leg above as a timeout waiting
  // for step 2, naming neither the mechanism nor the parameter.
  //
  // So the flip is checked against BOTH servers in the same section, because a
  // rule that only ever sees one of them is not a rule: the mock issuer's own
  // AS advertises openid_credential and must still get the flip, and Keycloak
  // must not — and what separates them has to be the metadata rather than the
  // URL, which is why the positive control is here rather than implied by the
  // sections that set the mechanism themselves.
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript("window.localStorage.clear();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];",
    issuerMetadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "the credential issuer metadata was not retrieved");
  await driver.wait(async function () {
    return (await driver.findElements(By.css("#vc_claims_table tbody tr")))
        .length > 0;
  }, fetchWait, "the claims pane never filled");
  var beforeAs = await driver.executeScript(
    "return document.getElementById('handoff_request_mechanism').value;");
  assert.strictEqual(beforeAs, "authorization_details",
    "with no authorization server document in hand, whether it understands " +
    "authorization_details is unknown and the credential decides. Got: " +
        beforeAs);

  // Keycloak: the member is absent, so the request would not be redeemable.
  var keycloakMeta = (await httpJson(asMetadataUrl)).body;
  assert.ok(!(keycloakMeta.authorization_details_types_supported || [])
            .includes("openid_credential"),
    "this check needs an authorization server that does NOT advertise " +
    "openid_credential; " + asMetadataUrl + " now advertises " +
    JSON.stringify(keycloakMeta.authorization_details_types_supported) +
        ", so it can no longer show the rule.");
  await driver.executeScript(
    "document.getElementById('oidc_discovery_endpoint').value = arguments[0];",
    asMetadataUrl);
  await click(driver, By.id("as_retrieve_button"));
  await waitForStatus(driver, "as_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "the authorization server metadata was not retrieved");
  var againstKeycloak = await driver.executeScript(
    "return { mechanism: document.getElementById(" +
    "'handoff_request_mechanism').value," +
    "         note: document.getElementById('handoff_mechanism_note')" +
    "                 .textContent.trim() };");
  assert.strictEqual(againstKeycloak.mechanism, "scope",
    "an authorization server whose own metadata does not advertise " +
    "openid_credential cannot redeem the request, so the default must not " +
    "flip to it. Got: " + againstKeycloak.mechanism);
  assert.ok(/authorization_details would be the default/
            .test(againstKeycloak.note) &&
            /authorization_details_types_supported/
            .test(againstKeycloak.note),
    "and the note must say the page wanted authorization_details and what " +
    "stopped it, or the select sits on scope while the claims pane says to " +
    "switch. Got: " + againstKeycloak.note);
  log.info("[claims] OK — the default stays on scope at an authorization " +
           "server that does not advertise authorization_details, and the " +
           "note says why.");

  // The mock issuer's own AS: the member IS there, so the flip still happens.
  var mockAsUrl = issuerBase + "/.well-known/oauth-authorization-server";
  var mockAsMeta = (await httpJson(mockAsUrl)).body;
  assert.ok((mockAsMeta.authorization_details_types_supported || [])
            .includes("openid_credential"),
    "and this half needs one that DOES advertise it; " + mockAsUrl +
    " advertises " +
    JSON.stringify(mockAsMeta.authorization_details_types_supported) + ".");
  await driver.executeScript(
    "document.getElementById('oidc_discovery_endpoint').value = arguments[0];",
    mockAsUrl);
  await click(driver, By.id("as_retrieve_button"));
  await waitForStatus(driver, "as_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "the authorization server metadata was not retrieved");
  var againstMock = await driver.executeScript(
    "return document.getElementById('handoff_request_mechanism').value;");
  assert.strictEqual(againstMock, "authorization_details",
    "a server that advertises openid_credential must still get the default " +
    "the claims need — otherwise this rule has simply disabled it. Got: " +
        againstMock);
  log.info("[claims] OK — and it flips back at a server that advertises " +
           "openid_credential, so the metadata is what decides.");
  log.debug("Leaving authorizationDetailsIsTheDefault().");
}

async function claimsCannotTravelOnAScope(driver) {
  log.debug("Entering claimsCannotTravelOnAScope().");
  log.info("=== a claims selection the scope route cannot carry ===");
  await stepOneConfigured(driver, "scope");
  var rows = await driver.executeScript(
    "return Array.prototype.slice.call(" +
    "document.querySelectorAll('#vc_claims_table tbody tr')).map(" +
    "function (tr) {" +
    "  var input = tr.querySelector('input');" +
    "  return { id: input.id, label: tr.querySelectorAll('td')[1]" +
    "    .textContent.trim() };" +
    "});");
  assert.ok(rows.length >= 2, "the pane should have rows to unselect. Got " +
            rows.length + ".");
  var dropped = rows[rows.length - 1].label;
  await click(driver, By.id(rows[rows.length - 1].id));

  var state = await driver.executeScript(
    "return { status: " +
    "document.getElementById('vc_claims_status').textContent.trim()," +
    "         note: " +
    "document.getElementById('vc_claims_note').textContent.trim()," +
    "         fixShown: document.getElementById(" +
    "'vc_claims_use_details_button').style.display !== 'none' };");
  assert.ok(/will NOT be sent/.test(state.status),
    "the claims pane itself must say the selection is not being sent — a " +
    "sentence in the hand-off pane's note is not where anybody reads it. " +
    "Got: " + state.status);
  assert.ok(/scope/.test(state.status) &&
            /authorization_details/.test(state.status),
    "and name both halves of the reason. Got: " + state.status);
  assert.ok(!/will be asked for/.test(state.note),
    "and the note must not claim the claims will be asked for. Got: " +
        state.note);
  assert.ok(state.fixShown,
    "the pane should offer the one-click switch to authorization_details.");
  log.info("[claims] OK — a selection on the scope route is reported as not " +
           "sent, with the fix beside it.");

  // Nothing is sent, and the pane is right about that.
  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "the authorization request should still reach the identity provider.");
  var scopeUrl = await driver.getCurrentUrl();
  assert.ok(scopeUrl.indexOf("authorization_details=") === -1,
    "a scope request carries no authorization_details, which is exactly why " +
    "the pane has to say so. Got: " + scopeUrl);

  // And the fix works: same selection, one click, and it travels. Back to the
  // page by URL rather than by history — the hand-off is a redirect chain, and
  // going back through it re-issues the authorization request. Loading it
  // afresh also proves the warning is not a one-off from the click that caused
  // it: the selection and the mechanism both come out of storage.
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vc_claims_use_details_button")),
                    fetchWait);
  await driver.wait(async function () {
    return /will NOT be sent/.test(await text(driver, "vc_claims_status"));
  }, fetchWait, "the warning should still be there after a reload.");
  await click(driver, By.id("vc_claims_use_details_button"));
  var fixed = await driver.executeScript(
    "return { mechanism: " +
    "document.getElementById('handoff_request_mechanism').value," +
    "         fixShown: document.getElementById(" +
    "'vc_claims_use_details_button').style.display !== 'none' };");
  assert.strictEqual(fixed.mechanism, "authorization_details",
    "the button should switch how the credential is asked for. Got: " +
        fixed.mechanism);
  assert.ok(!fixed.fixShown,
    "and take itself out of the way once there is nothing to fix.");
  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "the authorization request should reach the identity provider again.");
  var fixedUrl = await driver.getCurrentUrl();
  var sent = JSON.parse(decodeURIComponent(/authorization_details=([^&]*)/
      .exec(fixedUrl)[1]));
  assert.ok(sent[0].claims && sent[0].claims.every(function (c) {
    return c.path.join(".") !== dropped;
  }), "and it should now carry the same selection. Got: " +
      JSON.stringify(sent));
  log.info("[claims] OK — one click on the pane's own button puts the " +
           "selection on the wire.");
  log.debug("Leaving claimsCannotTravelOnAScope().");
}

// The issuer's cross-device offer screen, read the way a second device would:
// the offer itself and the Transaction Code the issuer displays, which is
// deliberately not in the offer.
async function fetchCrossDeviceOffer() {
  log.debug("Entering fetchCrossDeviceOffer().");
  var page = await (await fetch(issuerBase +
      "/issuer/offer?mode=cross-device")).text();
  var offer = JSON.parse(decodeURIComponent(
      /credential_offer=([^"<\s]*)/.exec(page)[1]));
  var uri = /id="offer_uri"[^>]*>([^<]*)</.exec(page)[1].trim();
  var txCode = /id="tx_code"[^>]*>([^<]*)</.exec(page)[1].trim();
  log.debug("Leaving fetchCrossDeviceOffer(). tx_code=" + txCode);
  return { offer: offer, uri: uri, txCode: txCode,
           code: offer.grants[PRE_AUTHORIZED_GRANT]["pre-authorized_code"] };
}

// ---------------------------------------------------------------------------
// The selection on the PRE-AUTHORIZED code flow, through the pages.
//
// H.2 has no authorization request, so step 2's Token Request is the only place
// the wallet can ask — and it is the page rather than the wire that decides to
// put an authorization_details parameter there at all. That decision has a
// consequence worth seeing: a token response granting credential_identifiers
// forbids credential_configuration_id in the Credential Request (section 8.2),
// so asking for fewer claims also changes how the credential is then named.
// ---------------------------------------------------------------------------
async function preAuthorizedClaimsThroughThePages(driver) {
  log.debug("Entering preAuthorizedClaimsThroughThePages().");
  log.info("=== claims on a pre-authorized offer, through the pages ===");
  var offered = await fetchCrossDeviceOffer();

  await stepOneConfigured(driver, "scope");
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("scan_offer_input")), waitTime);
  await driver.executeScript(
    "document.getElementById('scan_offer_input').value = arguments[0];",
        offered.uri);
  await click(driver, By.id("scan_offer_button"));
  await driver.wait(async function () {
    return (await value(driver, "vci_credential_endpoint")) === issuerBase +
            "/oid4vci/credential";
  }, fetchWait, "taking the offer should discover the issuer it names.");
  await driver.sleep(400);

  // The pane is rebuilt from the metadata the offer led to, so it has rows
  // without anybody retrieving anything by hand.
  var rows = await driver.executeScript(
    "return Array.prototype.slice.call(" +
    "document.querySelectorAll('#vc_claims_table tbody tr')).map(" +
    "function (tr) {" +
    "  var td = tr.querySelectorAll('td');" +
    "  return { id: td[0].querySelector('input').id," +
    "           checked: td[0].querySelector('input').checked," +
    "           label: td[1].textContent.trim() };" +
    "});");
  assert.ok(rows.length >= 2,
    "taking an offer should leave the claims pane built from the offering " +
    "issuer's metadata. Got " + rows.length + " row(s).");
  assert.ok(rows.every(function (r) { return r.checked; }),
    "and every claim checked, since this wallet has chosen nothing yet.");
  var dropped = rows[rows.length - 1].label;
  await click(driver, By.id(rows[rows.length - 1].id));

  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
    "a pre-authorized offer goes straight to the Token Request.");
  await driver.wait(async function () {
    return !!(await value(driver, "vc_token_request"));
  }, fetchWait, "step 2 should assemble the Token Request.");
  var assembled = await value(driver, "vc_token_request");
  assert.ok(assembled.indexOf("authorization_details=") !== -1,
    "with a claim unchecked the Token Request must carry " +
    "authorization_details — section 6.1.1 is the only place this flow can " +
    "ask. Got: " + assembled.slice(0, 400));
  var carriedDetails = JSON.parse(decodeURIComponent(
      /authorization_details=([^&\s]*)/.exec(assembled)[1]));
  assert.ok(carriedDetails[0].claims,
    "and a claims member. Got: " + JSON.stringify(carriedDetails));
  assert.ok(carriedDetails[0].claims.every(function (c) {
    return c.path.join(".") !== dropped;
  }), "which must not name the claim that was unchecked (" + dropped +
      "). Got: " + JSON.stringify(carriedDetails[0].claims));
  log.info("[claims] OK — step 2's Token Request carries " +
           carriedDetails[0].claims.length + " claims and not " + dropped +
           ".");

  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = arguments[0]; " +
        "vcissuance2.onTxCodeChange();", offered.txCode);
  await click(driver, By.id("vc_token_request_button"));
  await driver.wait(async function () {
    return !!(await value(driver, "vc_access_token"));
  }, fetchWait, "the Transaction Code should redeem the pre-authorized code.");
  var granted = await driver.executeScript(
    "return JSON.parse(window.localStorage.getItem(" +
    "'token_authorization_details') || 'null');");
  assert.ok(granted && granted[0] && granted[0].credential_identifiers,
    "asking with authorization_details should be answered with " +
    "credential_identifiers. Got: " + JSON.stringify(granted));
  var body = JSON.parse(await text(driver, "vc_request_body"));
  assert.strictEqual(body.credential_identifier,
                     granted[0].credential_identifiers[0],
    "so the Credential Request must name the granted identifier rather than " +
    "the configuration id (section 8.2). Got: " + JSON.stringify(body));
  assert.ok(!("credential_configuration_id" in body),
    "and must not carry both. Got: " + JSON.stringify(body));

  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "approving should issue the offered credential.");
  await driver.sleep(800);
  await assertStepThreeIsHappy(driver, "H.2 with a claims selection");
  var credential = await waitForFilled(driver, "vc_credential_raw",
      "step 3 should show the credential");
  // Keyed by claim name AND kept with its value, because the claim dropped
  // here may be a NESTED one: an SD-JWT VC discloses `address` as a single
  // Disclosure whose value is an object, so "address.country is not in the
  // list of disclosed claim names" is true however much country is in there.
  // That check passed against a credential that still carried it.
  var carried = {};
  credential.split("~").slice(1).filter(Boolean)
    .map(function (d) { return jsonFromB64u(d); })
    .filter(function (a) { return a.length === 3; })
    .forEach(function (a) { carried[a[1]] = a[2]; });
  var parts = dropped.split(".");
  if (parts.length === 1) {
    assert.ok(!(parts[0] in carried),
      "the credential from a pre-authorized offer must not carry " + dropped +
      ", which was unchecked before it was requested. It carries: " +
          Object.keys(carried).join(", "));
  } else {
    var parent = carried[parts[0]];
    assert.ok(!parent || !(parts[1] in parent),
      "the credential must not carry " + dropped + ", which was unchecked " +
      "before it was requested. Its " + parts[0] + " is: " +
          JSON.stringify(parent));
  }
  log.info("[claims] OK — the offered credential carries " +
           Object.keys(carried).join(", ") + " and not " + dropped + ".");
  log.debug("Leaving preAuthorizedClaimsThroughThePages().");
}

// ---------------------------------------------------------------------------
// The same member on the PRE-AUTHORIZED code flow, which has no authorization
// request to carry it: section 6.1.1 puts authorization_details in the Token
// Request, and that is the only route H.2 / H.3 have.
//
// Driven over HTTP rather than through the browser because what is under test
// is the wire — the offer, the token request that names the claims, and the
// credential that comes back — and the issuer's refusals go through the same
// parser the authorization endpoint uses, so exercising them here covers both.
// ---------------------------------------------------------------------------
async function preAuthorizedClaimsRequest() {
  log.debug("Entering preAuthorizedClaimsRequest().");
  log.info("=== claims on the pre-authorized code flow ===");
  var meta = (await httpJson(issuerMetadataUrl)).body;
  var advertised = ((meta.credential_configurations_supported ||
      {})[VCI_CONFIG_ID] || {}).claims || [];
  var top = advertised.filter(function (c) { return c.path.length === 1; });
  assert.ok(top.length >= 2,
    "this section asks for one of several top-level claims; the issuer " +
    "advertises " + top.length + ".");
  var wanted = top[0].path;

  var offered = await fetchCrossDeviceOffer();
  assert.ok(offered.code,
    "the cross-device offer should carry a pre-authorized code. Got: " +
        JSON.stringify(offered.offer));

  var form = function (params) {
    return Object.keys(params).map(function (k) {
      return encodeURIComponent(k) + "=" + encodeURIComponent(params[k]);
    }).join("&");
  };
  var details = [{ type: "openid_credential",
                   credential_configuration_id: VCI_CONFIG_ID,
                   claims: [{ path: wanted }] }];
  var token = await httpJson(meta.authorization_servers
    ? meta.authorization_servers[0] + "/oauth2/token"
    : issuerBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: PRE_AUTHORIZED_GRANT,
                 "pre-authorized_code": offered.code,
                 tx_code: offered.txCode, client_id: clientId,
                 authorization_details: JSON.stringify(details) })
  });
  assert.ok(token.ok && token.body.access_token,
    "the token endpoint should accept authorization_details on the " +
    "pre-authorized grant (OID4VCI section 6.1.1). Got HTTP " + token.status +
    " " + token.raw.slice(0, 200));
  assert.ok(token.body.authorization_details &&
            token.body.authorization_details[0].credential_identifiers,
    "and grant credential_identifiers for what it authorized. Got: " +
        JSON.stringify(token.body.authorization_details));
  assert.deepStrictEqual(token.body.authorization_details[0].claims,
                         [{ path: wanted }],
    "echoing the claims it authorized. Got: " +
        JSON.stringify(token.body.authorization_details[0]));

  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = pair.publicKey.export({ format: "jwk" });
  var nonce = (await httpJson(meta.nonce_endpoint,
      { method: "POST" })).body.c_nonce;
  var head = b64u(JSON.stringify({ typ: "openid4vci-proof+jwt", alg: "ES256",
      jwk: jwk }));
  var body = b64u(JSON.stringify({ iss: clientId, aud: meta.credential_issuer,
      iat: Math.floor(Date.now() / 1000), nonce: nonce }));
  var proof = head + "." + body + "." +
    b64u(crypto.sign("sha256", Buffer.from(head + "." + body),
                     { key: pair.privateKey, dsaEncoding: "ieee-p1363" }));
  var credential = await httpJson(meta.credential_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json",
               "Authorization": "Bearer " + token.body.access_token },
    body: JSON.stringify({
      credential_identifier:
          token.body.authorization_details[0].credential_identifiers[0],
      proofs: { jwt: [proof] } })
  });
  assert.ok(credential.ok && credential.body.credentials,
    "the credential should be issued. Got HTTP " + credential.status + " " +
        credential.raw.slice(0, 200));
  var carried = credential.body.credentials[0].credential.split("~").slice(1)
    .filter(Boolean).map(function (d) { return jsonFromB64u(d); })
    .filter(function (a) { return a.length === 3; })
    .map(function (a) { return a[1]; });
  assert.deepStrictEqual(carried, [wanted[0]],
    "and it should carry only the claim the Token Request asked for. It " +
    "carries: " + carried.join(", "));
  log.info("[claims] OK — a pre-authorized Token Request asking for " +
           wanted.join(".") + " produced a credential carrying exactly it.");

  // The refusals. Same parser as the authorization endpoint's, which is why
  // they are checked here where no browser session is needed.
  var refuse = async function (claims, expected, why) {
    var another = await fetchCrossDeviceOffer();
    var refused = await httpJson(issuerBase + "/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form({ grant_type: PRE_AUTHORIZED_GRANT,
                   "pre-authorized_code": another.code,
                   tx_code: another.txCode,
                   client_id: clientId,
                   authorization_details: JSON.stringify([{
                     type: "openid_credential",
                     credential_configuration_id: VCI_CONFIG_ID,
                     claims: claims }]) })
    });
    assert.strictEqual(refused.status, 400, why + " should be refused. Got " +
                       "HTTP " + refused.status + " " + refused.raw.slice(0,
                       200));
    assert.strictEqual(refused.body.error, "invalid_authorization_details",
      "with invalid_authorization_details. Got: " + JSON.stringify(
          refused.body));
    assert.ok(expected.test(refused.body.error_description || ""),
      "and a description saying why. Got: " + refused.body.error_description);
  };
  await refuse([{ path: ["not_a_claim_this_issuer_has"] }],
               /does not advertise/,
               "a claim path the issuer does not advertise");
  await refuse([{ path: wanted }, { path: wanted }], /described twice/,
               "the same claim described twice (Appendix A.3)");
  await refuse([{ path: [] }], /non-empty claims path pointer/,
               "an empty claims path pointer");
  log.info("[claims] OK — an unadvertised path, a repeated claim and an " +
           "empty path are each refused with invalid_authorization_details.");
  log.debug("Leaving preAuthorizedClaimsRequest().");
}

// ---------------------------------------------------------------------------
// The Notification Endpoint (OID4VCI section 11).
//
// The issuer returns a notification_id and the wallet may report what became of
// the credential. "May" is the point: it is optional for the wallet, so this
// checks that the workflow offers it, sends what the spec defines, and that the
// issuer both validates it and records it — a 204 for anything at all would
// make the endpoint indistinguishable from a black hole.
// ---------------------------------------------------------------------------
async function notificationFlow(driver) {
  log.debug("Entering notificationFlow().");
  log.info("=== The Notification Endpoint ===");
  var record = await driver.executeScript(
    "return JSON.parse(window.localStorage.getItem('sdjwtvc_credential_meta') || '{}');");
  assert.ok(record.notificationId,
    "the Credential Response should have carried a notification_id. Got: " +
        JSON.stringify(record));
  assert.strictEqual(record.notificationEndpoint, issuerBase +
                     "/oid4vci/notification",
    "and step 2 should have recorded where to send it.");

  var shown = await driver.executeScript(
    "return { id: " +
        "document.getElementById('vc_notification_id').textContent.trim()," +
    "         endpoint: document.getElementById('vc_notification_endpoint').textContent.trim()," +
    "         request: " +
        "document.getElementById('vc_notification_request').value," +
    "         events: Array.prototype.slice.call(" +
    "           document.getElementById('vc_notification_event').options).map(function (o) { return o.value; }) };");
  assert.strictEqual(shown.id, record.notificationId,
                     "step 3 should show the notification_id.");
  assert.deepStrictEqual(shown.events,
    ["credential_accepted", "credential_failure", "credential_deleted"],
    "the three events OID4VCI section 11.1 defines, and no others. Got: " +
        JSON.stringify(shown.events));
  assert.ok(shown.request.indexOf("POST " + record.notificationEndpoint) === 0,
    "the assembled call should be shown before it is sent. Got: " +
        shown.request.slice(0, 90));
  assert.ok(shown.request.indexOf('"notification_id"') !== -1 &&
            shown.request.indexOf("Authorization: Bearer ") !== -1,
    "with the notification_id and the access token that authorizes it. Got: " +
        shown.request);
  log.info("[notification] OK — step 3 shows the notification it can send, " +
           "and the three events it may report.");

  var accessToken = await driver.executeScript(
    "return window.localStorage.getItem('token_access_token');");
  var invented = await httpJson(issuerBase + "/oid4vci/notification", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " +
              accessToken },
    body: JSON.stringify({ notification_id: "never-issued-this",
                         event: "credential_accepted" })
  });
  assert.strictEqual(invented.status, 400,
                     "an unknown notification_id should be refused.");
  assert.strictEqual(invented.body.error, "invalid_notification_id",
    "with the error section 11.3 names. Got: " + JSON.stringify(invented.body));

  var badEvent = await httpJson(issuerBase + "/oid4vci/notification", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " +
              accessToken },
    body: JSON.stringify({ notification_id: record.notificationId,
                         event: "credential_pondered" })
  });
  assert.strictEqual(badEvent.status, 400,
                     "an event outside the three should be refused.");
  assert.strictEqual(badEvent.body.error, "invalid_notification_request",
    "with invalid_notification_request. Got: " + JSON.stringify(badEvent.body));

  var noToken = await httpJson(issuerBase + "/oid4vci/notification", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notification_id: record.notificationId,
                         event: "credential_accepted" })
  });
  assert.strictEqual(noToken.status, 401,
    "and it should require the access token. Got HTTP " + noToken.status);
  log.info("[notification] OK — an invented id, an undefined event and a " +
           "missing token are all refused.");

  await driver.executeScript(
    "document.getElementById('vc_notification_event').value = " +
        "'credential_accepted';" +
    "document.getElementById('vc_notification_description').value = 'stored " +
        "in the wallet';" +
    "vcissuance3.renderNotification();");
  await click(driver, By.id("vc_notification_button"));
  await waitForStatus(driver, "vc_notification_status",
    function (s) { return /accepted|refused|failed/i.test(s); },
    "the notification should be answered");
  var verdict = await text(driver, "vc_notification_status");
  assert.ok(/accepted the notification/.test(verdict),
    "the issuer should have accepted it. Got: " + verdict);
  assert.ok(/204/.test(verdict),
    "section 11.2: success is 204 with no body. Got: " + verdict);

  var recorded = await httpJson(issuerBase + "/oid4vci/notification/" +
      record.notificationId);
  assert.strictEqual(recorded.status, 200,
      "the issuer should know about the notification it accepted.");
  assert.strictEqual(recorded.body.event, "credential_accepted",
    "and have recorded the event. Got: " + JSON.stringify(recorded.body));
  assert.strictEqual(recorded.body.event_description, "stored in the wallet",
    "including the description the wallet sent. Got: " +
        JSON.stringify(recorded.body));
  log.info("[notification] OK — the issuer recorded credential_accepted for " +
           record.notificationId + ".");
  log.debug("Leaving notificationFlow().");
}

// ---------------------------------------------------------------------------
// Batch issuance and response encryption — the two things the issuer's metadata
// advertises and nothing exercised until now.
//
//   batch_credential_issuance.batch_size   several proofs in one request, one
//                                          credential per proof (section 14.6)
//   credential_response_encryption         the response as a JWE the wallet
//                                          decrypts (section 10)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// An encrypted Credential REQUEST — OID4VCI section 10 in the other direction.
//
// batchAndEncryptedIssuance() below covers the response side, where the WALLET
// supplies the key. Here the ISSUER publishes keys in
// credential_request_encryption.jwks and the wallet encrypts to one of them,
// sending application/jwt instead of JSON. The two are not symmetric and the
// differences are what this section exists to pin:
//
//   * there is no alg_values_supported for requests — "The JWE alg algorithm
//     used MUST be equal to the alg value of the chosen JWK" — so a pane that
//     reads the response side's member list finds nothing;
//   * "Each JWK in the set MUST have a kid", and the JWE MUST echo it.
//
// The protocol itself is covered headlessly by
// tests/oid4vci_request_encryption.js against the wallet module. What is only
// observable HERE is that the pane is wired to that module at all: the checkbox
// reads the metadata step 1 stored, the assembled call shows what will really
// be sent, and Approve actually sends the ciphertext. Every one of those is a
// seam where the feature can be present in the module and unreachable from the
// page.
// ---------------------------------------------------------------------------
async function encryptedCredentialRequest(driver) {
  log.debug("Entering encryptedCredentialRequest().");
  log.info("=== An encrypted Credential Request (section 10, " +
           "issuer-published keys) ===");
  var meta = (await httpJson(issuerMetadataUrl)).body;
  var offered = meta.credential_request_encryption;
  assert.ok(offered, "this issuer should advertise " +
            "credential_request_encryption; without it the " +
    "checkbox is correctly disabled and this section would assert nothing.");
  assert.strictEqual(offered.alg_values_supported, undefined,
    "and must NOT carry alg_values_supported — that member belongs to the " +
        "response side.");
  var publishedKid = ((offered.jwks || {}).keys || [])[0].kid;
  assert.ok(publishedKid,
            "every published key needs a kid for the wallet to echo.");

  await stepOneConfigured(driver, "scope");
  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("username")), fetchWait);
  await driver.findElement(By.id("username")).sendKeys(MOCK_AS_USER);
  await driver.findElement(By.id("password")).sendKeys("any-password");
  await click(driver, By.id("kc-login"));
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 should assemble the request.");

  // The metadata step 1 retrieved has to have reached the key step 2 reads.
  // That seam is invisible when it breaks: the checkbox simply stays disabled,
  // with a note saying the issuer does not offer encryption — which is
  // indistinguishable from an issuer that genuinely does not.
  var stored = await driver.executeScript(
    "return window.localStorage.getItem('vci_credential_request_encryption') || '';");
  assert.ok(stored && stored.indexOf(publishedKid) !== -1,
    "step 1 must store credential_request_encryption where step 2 " +
        "looks for it " +
    "(vci_credential_request_encryption), including the published kid. Got: " +
    String(stored).slice(0, 160));

  var before = await driver.executeScript(
    "return { disabled: " +
        "document.getElementById('vc_encrypt_request').disabled," +
    "         checked: document.getElementById('vc_encrypt_request').checked," +
    "         note: document.getElementById('vc_encrypt_request_note').textContent.trim()," +
    "         call: document.getElementById('vc_approval_request').value };");
  assert.strictEqual(before.disabled, false,
    "the checkbox should be offered: this issuer advertises a usable " +
        "key. Note: " + before.note);
  assert.strictEqual(before.checked, false,
    "and left OFF, because encryption_required is false and section 10 makes " +
        "it the wallet's choice.");
  assert.ok(before.note.indexOf(publishedKid) !== -1,
    "the note should name the key it would encrypt to, so the choice is not " +
        "blind. Got: " + before.note);
  assert.ok(/application\/json/.test(before.call),
    "and while it is off the assembled call is plain JSON. Got: " +
        before.call.slice(0, 120));
  log.info("[request-enc] OK — offered, off by default, and naming " +
           publishedKid + ".");

  await driver.executeScript(
    "document.getElementById('vc_encrypt_request').checked = true;" +
    "vcissuance2.onRequestOptionsChange();");
  await driver.wait(async function () {
    return /application\/jwt/.test(await value(driver, "vc_approval_request"));
  }, fetchWait, "ticking the box should rebuild the call as application/jwt.");

  var call = await value(driver, "vc_approval_request");
  assert.ok(/Content-Type: application\/jwt/.test(call),
    "section 10: the media type MUST be application/jwt. Got: " + call.slice(0,
        160));
  // The pane must show what is SENT. The plaintext is exactly what encryption
  // hides, so showing it as the body would describe a call this page never
  // makes.
  var wireBody = call.split("--- the plaintext")[0];
  assert.ok(wireBody.indexOf("credential_configuration_id") === -1,
    "the displayed body must be the ciphertext, not the JSON it " +
        "encrypts. Got: " +
    wireBody.slice(-200));
  var compact = wireBody.trim().split("\n").pop().trim();
  assert.strictEqual(compact.split(".").length, 5,
    "and that body should be a JWE in compact serialization (five " +
        "parts). Got " +
    compact.split(".").length + " part(s).");
  var jweHeader = jsonFromB64u(compact.split(".")[0]);
  assert.strictEqual(jweHeader.kid, publishedKid,
    "the JWE MUST echo the kid of the key it was encrypted to. Got: " +
        JSON.stringify(jweHeader));
  assert.strictEqual(jweHeader.alg, ((offered.jwks || {}).keys || [])[0].alg,
    "and its alg MUST equal the chosen JWK's alg — there is no " +
        "alg_values_supported to read instead.");
  assert.ok((offered.enc_values_supported || []).indexOf(jweHeader.enc) !== -1,
    "and its enc must be one the issuer said it can decode. Got: " +
        jweHeader.enc);
  log.info("[request-enc] OK — the call is a five-part JWE echoing " +
           jweHeader.kid +
    " with alg " + jweHeader.alg + " / enc " + jweHeader.enc + ".");

  // And it has to actually reach the issuer as ciphertext. Everything asserted
  // above is client-side and is equally consistent with a pane that builds a
  // perfect JWE, displays it, and then posts the plaintext — while
  // encryption_required is false the issuer accepts that JSON and issues from
  // it, so even arriving at step 3 with a valid credential proves nothing. A
  // mutation that did exactly this went undetected until the check below
  // existed, which is why the issuer is asked what it actually received.
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "the issuer should decrypt the request and issue, reaching step 3.");
  await assertStepThreeIsHappy(driver, "encrypted request");

  var arrived = (await httpJson(issuerBase + "/oid4vci/last_request")).body ||
      {};
  assert.strictEqual(arrived.seen, true,
    "the issuer should have recorded the request it just served. Got: " +
        JSON.stringify(arrived));
  assert.strictEqual(arrived.encrypted, true,
    "the issuer must have received CIPHERTEXT. It received " +
    (arrived.contentType || "something unencrypted") +
     " — so the page displayed a JWE and sent the " +
    "plaintext, which is invisible from the browser and produces a working " +
        "credential either way. " +
    "Got: " + JSON.stringify(arrived));
  assert.strictEqual(arrived.kid, publishedKid,
    "and decrypted it with the key the wallet named. Got: " +
        JSON.stringify(arrived));
  assert.strictEqual(arrived.enc, jweHeader.enc,
    "with the enc the pane displayed — the bytes sent must be the bytes " +
        "shown, not a re-encryption.");
  log.info("[request-enc] OK — the ISSUER confirms it received ciphertext (" +
           arrived.alg + " / " +
    arrived.enc + ", kid " + arrived.kid + ") and issued from it.");

  // Unticking must go back to JSON. Without this the box could be write-once —
  // and the stale-ciphertext bug it guards against is real: the assembled call
  // is rendered inside buildRequestBody(), before the JWE is built, so clearing
  // the previous run's ciphertext at the wrong moment leaves the pane showing a
  // request that is no longer the one being sent.
  await driver.get(baseUrl + "/vc-issuance-2.html");
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 should reassemble on a fresh load.");
  await driver.executeScript(
    "document.getElementById('vc_encrypt_request').checked = true;" +
    "vcissuance2.onRequestOptionsChange();");
  await driver.wait(async function () {
    return /application\/jwt/.test(await value(driver, "vc_approval_request"));
  }, fetchWait, "it should encrypt when ticked.");
  await driver.executeScript(
    "document.getElementById('vc_encrypt_request').checked = false;" +
    "vcissuance2.onRequestOptionsChange();");
  await driver.wait(async function () {
    return /application\/json/.test(await value(driver, "vc_approval_request"));
  }, fetchWait, "and go back to JSON when unticked.");
  var reverted = await value(driver, "vc_approval_request");
  assert.ok(reverted.indexOf("--- the plaintext") === -1,
    "with encryption off there is no ciphertext to caption, so the plaintext " +
        "note must go too. Got: " +
    reverted.slice(0, 200));
  assert.ok(reverted.indexOf("credential_configuration_id") !== -1,
    "and the body is the JSON request again.");
  log.info("[request-enc] OK — unticking returns the call to plain JSON with " +
           "no stale ciphertext.");
  log.debug("Leaving encryptedCredentialRequest().");
}

async function batchAndEncryptedIssuance(driver) {
  log.debug("Entering batchAndEncryptedIssuance().");
  log.info("=== Batch issuance and an encrypted Credential Response ===");
  var meta = (await httpJson(issuerMetadataUrl)).body;
  var batchSize = (meta.batch_credential_issuance || {}).batch_size;
  assert.ok(batchSize >= 3,
      "this issuer should advertise a batch_size worth exercising. Got: " +
      batchSize);
  var encryption = meta.credential_response_encryption || {};
  assert.deepStrictEqual(encryption.alg_values_supported, ["RSA-OAEP-256"],
    "it should advertise only the algorithm it performs. Got: " +
        JSON.stringify(encryption));

  await stepOneConfigured(driver, "scope");
  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("username")), fetchWait);
  await driver.findElement(By.id("username")).sendKeys(MOCK_AS_USER);
  await driver.findElement(By.id("password")).sendKeys("any-password");
  await click(driver, By.id("kc-login"));
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 should assemble the request.");

  var options = await driver.executeScript(
    "return { batchNote: " +
        "document.getElementById('vc_batch_note').textContent.trim()," +
    "         encNote: " +
        "document.getElementById('vc_encrypt_note').textContent.trim()," +
    "         batchMax: document.getElementById('vc_batch_size').max," +
    "         encDisabled: " +
        "document.getElementById('vc_encrypt_response').disabled };");
  assert.strictEqual(options.batchMax, String(batchSize),
    "the pane should cap the number of keys at the issuer's batch_size. Got: " +
        options.batchMax);
  assert.strictEqual(options.encDisabled, false,
    "and offer encryption, since this issuer advertises it.");
  assert.ok(/RSA-OAEP-256/.test(options.encNote),
    "saying which algorithms are on offer. Got: " + options.encNote);
  log.info("[batch] OK — step 2 reads the issuer's batch_size (" + batchSize +
           ") and encryption support.");

  await driver.executeScript(
    "document.getElementById('vc_batch_size').value = '3';" +
    "document.getElementById('vc_encrypt_response').checked = true;" +
    "vcissuance2.onRequestOptionsChange();");
  await driver.wait(async function () {
    var shown = await text(driver, "vc_request_body");
    try {
      var parsed = JSON.parse(shown);
      return parsed.proofs.jwt.length === 3 &&
          !!parsed.credential_response_encryption;
    } catch (e) {
      return false;
    }
  }, fetchWait, "the request should be rebuilt with three proofs and " +
      "encryption parameters.");

  var body = JSON.parse(await text(driver, "vc_request_body"));
  assert.strictEqual(body.proofs.jwt.length, 3,
                     "three keys means three proofs.");
  var keys = body.proofs.jwt.map(function (p) {
    return jsonFromB64u(p.split(".")[0]).jwk.x;
  });
  assert.strictEqual(new Set(keys).size, 3,
    "each proof should name a DIFFERENT key — a batch of one key repeated " +
        "proves nothing. Got: " +
    JSON.stringify(keys));
  assert.ok((encryption.enc_values_supported ||
            []).indexOf(body.credential_response_encryption.enc) !== -1,
    "the wallet should pick an enc the issuer advertises (" +
    (encryption.enc_values_supported || []).join(", ") + "). Got: " +
    body.credential_response_encryption.enc);
  assert.strictEqual(body.credential_response_encryption.enc, "A256GCM",
    "and the strongest one on offer here, rather than whichever is listed " +
        "first. Got: " +
    body.credential_response_encryption.enc);
  assert.strictEqual(body.credential_response_encryption.jwk.kty, "RSA",
    "and supply an RSA key for RSA-OAEP-256. Got: " +
    JSON.stringify(body.credential_response_encryption.jwk));
  assert.ok(!body.credential_response_encryption.jwk.d,
    "only the PUBLIC half may be sent; the private key must never leave the " +
        "browser. Got: " +
    Object.keys(body.credential_response_encryption.jwk).join(", "));
  log.info("[batch] OK — the request carries three proofs over three " +
           "distinct keys, and an encryption key.");

  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "the issuer should accept the batch and the workflow should reach step 3.");
  await driver.sleep(900);

  var issued = await driver.executeScript(
    "return { all: " +
        "JSON.parse(window.localStorage.getItem('sdjwtvc_credentials') " +
        "|| '[]')," +
    "         meta: " +
        "JSON.parse(window.localStorage.getItem('sdjwtvc_credential_meta') " +
        "|| '{}')," +
    "         pickerShown: " +
        "document.getElementById('vc_batch_row').style.display !== 'none'," +
    "         options: Array.prototype.slice.call(" +
    "           document.getElementById('vc_credential_select').options).map(function (o) { return o.textContent; })," +
    "         provenance: " +
        "document.getElementById('vc_meta_request').textContent };");
  assert.strictEqual(issued.all.length, 3,
    "three proofs should have produced three credentials. Got: " +
        issued.all.length);
  assert.strictEqual(issued.meta.encrypted, true,
    "and the workflow should record that the response was encrypted.");
  assert.ok(issued.pickerShown,
            "step 3 should offer all three, not just the first.");
  assert.strictEqual(issued.options.length, 3,
                     "one entry per credential. Got: " + issued.options.length);
  assert.ok(/Credential Response was encrypted/.test(issued.provenance),
    "and the credential's provenance should record that the response arrived " +
        "encrypted. Got: " +
    issued.provenance);
  assert.ok(/3 credentials in one response/.test(issued.provenance),
    "and that three came back together. Got: " + issued.provenance);

  var bound = issued.all.map(function (c) {
    return jsonFromB64u(c.split("~")[0].split(".")[1]).cnf.jwk.x;
  });
  assert.deepStrictEqual(bound, keys,
    "each credential should be bound to the key from its own proof, in " +
        "order. Got: " +
    JSON.stringify(bound) + " for keys " + JSON.stringify(keys));
  log.info("[batch] OK — three credentials came back from an ENCRYPTED " +
           "response, each bound to its own key.");

  await driver.executeScript(
    "document.getElementById('vc_credential_select').value = '2'; " +
        "vcissuance3.onCredentialChange();");
  await waitForValue(driver, "vc_credential_raw",
    function (v) { return v === issued.all[2]; },
    "choosing another credential should show that one");
  await assertStepThreeIsHappy(driver, "batch credential 3");
  log.info("[batch] OK — each credential in the batch verifies on its own.");

  var accessToken = await driver.executeScript(
    "return window.localStorage.getItem('token_access_token');");
  var refused = await httpJson(issuerBase + "/oid4vci/credential", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " +
              accessToken },
    // The request that just succeeded, with ONLY the enc changed, so that the
    // encryption parameters are the single thing wrong with it.
    body: JSON.stringify(Object.assign({}, body, {
      proofs: { jwt: [body.proofs.jwt[0]] },
      credential_response_encryption: {
          jwk: body.credential_response_encryption.jwk, enc: "A192GCM" }
    }))
  });
  assert.strictEqual(refused.status, 400,
    "an unsupported enc should be refused, not answered in the clear. " +
        "Got HTTP " + refused.status);
  assert.strictEqual(refused.body.error, "invalid_encryption_parameters",
    "with invalid_encryption_parameters. Got: " + refused.raw.slice(0, 240));
  log.info("[batch] OK — an encryption algorithm this issuer does not " +
           "implement is refused.");
  log.debug("Leaving batchAndEncryptedIssuance().");
}

// Step 1, configured and ready to hand off. Shared by the sections above, which
// care about what happens after it rather than about discovery.
// Sign out of the mock authorization server.
//
// It sets a session cookie, so once one section has signed in the next
// authorization request is answered from that session and no login screen
// appears — a section that expects one would wait for a form that is not
// coming. deleteAllCookies() clears only the origin the browser is currently
// on, which is why this goes to the issuer's origin first.
async function signOutOfMockAs(driver) {
  log.debug("Entering signOutOfMockAs().");
  await driver.get(issuerBase + "/.well-known/oauth-authorization-server");
  await driver.manage().deleteAllCookies();
  log.debug("Leaving signOutOfMockAs(). No session remains at " + issuerBase +
            ".");
}

async function stepOneConfigured(driver, mechanism) {
  log.debug("Entering stepOneConfigured(). mechanism=" + (mechanism ||
            "scope"));
  await signOutOfMockAs(driver);
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript("window.localStorage.clear();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  // The ISSUER's own authorization server, not Keycloak: authorization_details
  // of type openid_credential is an OID4VCI mechanism, and the mock issuer is
  // the thing that implements it. Keycloak neither advertises it nor would
  // grant credential_identifiers, so pointing these sections at Keycloak would
  // be testing the wrong server.
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];" +
    "document.getElementById('oidc_discovery_endpoint').value = arguments[1];",
    issuerMetadataUrl, issuerBase + "/.well-known/oauth-authorization-server");
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
              "the credential issuer metadata was not retrieved");
  await click(driver, By.id("as_retrieve_button"));
  await waitForStatus(driver, "as_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
              "the authorization server metadata was not retrieved");
  await driver.executeScript(
    "document.getElementById('client_id').value = arguments[0];" +
    "document.getElementById('scope').value = 'openid identity_credential';" +
    // Set explicitly rather than inherited: the choice is remembered across
    // reloads, so a section that did not say which it wanted would silently run
    // whatever the previous one chose.
    "document.getElementById('handoff_request_mechanism').value = " +
        "arguments[1];" +
    "vcissuance1.onRequestMechanismChange();",
    clientId, mechanism === "authorization_details" ?
        "authorization_details" : "scope");
  await click(driver, By.id("config_save_button"));
  await driver.sleep(300);
  log.debug("Leaving stepOneConfigured().");
}

async function issuerNegatives() {
  log.debug("Entering issuerNegatives().");
  log.info("=== The credential endpoint's checks ===");
  var meta = (await httpJson(issuerMetadataUrl)).body;

  var noAuth = await httpJson(meta.credential_endpoint, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}"
  });
  assert.strictEqual(noAuth.status, 401,
      "a credential request with no access token must be refused.");
  assert.strictEqual(noAuth.body.error, "invalid_token",
                     "the refusal should be invalid_token.");

  var noProof = await httpJson(meta.credential_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json",
              "Authorization": "Bearer whatever" },
    body: JSON.stringify({ credential_configuration_id: "IdentityCredential" })
  });
  assert.strictEqual(noProof.status, 400,
                     "a credential request with no proof must be refused.");
  assert.strictEqual(noProof.body.error, "invalid_proof",
                     "the refusal should be invalid_proof.");

  // A well-formed proof, then the same proof again: the nonce is single use.
  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = pair.publicKey.export({ format: "jwk" });
  var nonce = (await httpJson(meta.nonce_endpoint,
      { method: "POST" })).body.c_nonce;
  var head = b64u(JSON.stringify({ typ: "openid4vci-proof+jwt", alg: "ES256",
      jwk: jwk }));
  var claims = b64u(JSON.stringify({
    iss: clientId, aud: meta.credential_issuer,
        iat: Math.floor(Date.now() / 1000), nonce: nonce
  }));
  var sig = b64u(crypto.sign("sha256", Buffer.from(head + "." + claims),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" }));
  var proof = head + "." + claims + "." + sig;
  var body = JSON.stringify({ credential_configuration_id: "IdentityCredential",
      proofs: { jwt: [proof] } });
  var headers = { "Content-Type": "application/json",
      "Authorization": "Bearer opaque-token" };

  var first = await httpJson(meta.credential_endpoint, { method: "POST",
      headers: headers, body: body });
  assert.ok(first.ok, "a well-formed request should be accepted, got HTTP " +
            first.status + " " + first.raw);
  var replay = await httpJson(meta.credential_endpoint, { method: "POST",
      headers: headers, body: body });
  assert.strictEqual(replay.status, 400,
                     "replaying a c_nonce must be refused.");
  assert.strictEqual(replay.body.error, "invalid_proof",
                     "a replayed nonce should be an invalid_proof.");

  // A proof whose signature does not match the key in its own header.
  var nonce2 = (await httpJson(meta.nonce_endpoint,
      { method: "POST" })).body.c_nonce;
  var claims2 = b64u(JSON.stringify({
    iss: clientId, aud: meta.credential_issuer,
        iat: Math.floor(Date.now() / 1000), nonce: nonce2
  }));
  var tampered = await httpJson(meta.credential_endpoint, {
    method: "POST", headers: headers,
    body: JSON.stringify({ credential_configuration_id: "IdentityCredential",
                           proofs: { jwt: [head + "." + claims2 + "." +
                                    sig] } })
  });
  assert.strictEqual(tampered.status, 400,
                     "a proof with a bad signature must be refused.");
  assert.ok(/signature does not verify/.test(tampered.body.error_description ||
            ""),
    "the refusal should name the signature. Got: " +
        tampered.body.error_description);

  // A proof for someone else's audience.
  var nonce3 = (await httpJson(meta.nonce_endpoint,
      { method: "POST" })).body.c_nonce;
  var claims3 = b64u(JSON.stringify({
    iss: clientId, aud: "https://another.example.com",
        iat: Math.floor(Date.now() / 1000), nonce: nonce3
  }));
  var sig3 = b64u(crypto.sign("sha256", Buffer.from(head + "." + claims3),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" }));
  var wrongAud = await httpJson(meta.credential_endpoint, {
    method: "POST", headers: headers,
    body: JSON.stringify({ credential_configuration_id: "IdentityCredential",
                           proofs: { jwt: [head + "." + claims3 + "." +
                                    sig3] } })
  });
  assert.strictEqual(wrongAud.status, 400,
                     "a proof addressed to another issuer must be refused.");
  log.info("[issuer] OK — no token, no proof, replayed nonce, bad signature " +
           "and wrong audience are all refused.");
  log.debug("Leaving issuerNegatives().");
}

// ---------------------------------------------------------------------------
// The query parameter is what puts oauth2_oidc_1.html into this workflow. With
// no configuration to run on it must SAY so rather than silently doing nothing
// — which is also the only way to observe the parameter's effect without racing
// the redirect it normally causes.
async function handoffParameterCheck(driver) {
  log.debug("Entering handoffParameterCheck().");
  log.info("=== The ?sdjwtvc=1 hand-off parameter ===");
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await driver.wait(until.elementLocated(By.id("oidc_discovery_endpoint")),
                    waitTime);
  // Empty the two values the hand-off needs, but leave the page "initialized"
  // so it does not helpfully put its dummy defaults back — an unconfigured
  // hand-off is what is under test here.
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('initialized', true);" +
    "localStorage.setItem('debugger_initialized', true);" +
    "localStorage.setItem('authorization_endpoint', '');" +
    "localStorage.setItem('client_id', '');");
  await driver.get(baseUrl + "/oauth2_oidc_1.html?sdjwtvc=1");
  await driver.wait(until.elementLocated(By.id("sdjwtvc_banner")), waitTime,
    "oauth2_oidc_1.html should say when it is being driven by the SD-JWT VC " +
        "workflow.");
  var banner = await waitForStatus(driver, "sdjwtvc_banner",
    function (s) { return /SD-JWT VC issuance/.test(s); },
    "the banner should name the workflow");
  assert.ok(/not configured|not started/.test(banner),
    "with nothing configured the banner should say the flow was not " +
        "started. Got: " + banner);
  assert.ok((await driver.getCurrentUrl()).indexOf("oauth2_oidc_1.html") !== -1,
    "an unconfigured hand-off must not redirect anywhere.");
  var flag = await driver.executeScript(
      "return localStorage.getItem('sdjwtvc_flow');");
  assert.strictEqual(flag, "active",
                     "the parameter should mark the workflow active.");

  // And with no parameter, none of it happens.
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await driver.sleep(700);
  var banners = await driver.executeScript(
      "return document.querySelectorAll('.vc-handoff-banner').length;");
  assert.strictEqual(banners, 0,
      "without the parameter oauth2_oidc_1.html must behave exactly as " +
          "before.");
  await driver.executeScript("window.localStorage.clear();");
  log.info("[handoff] OK — the parameter drives the page, and its absence " +
           "changes nothing.");
  log.debug("Leaving handoffParameterCheck().");
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. issuer=" + issuerMetadataUrl + ", as=" +
           asMetadataUrl);
  await issuerNegatives();

  var prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  var options = new chrome.Options().setLoggingPrefs(prefs)
    .addArguments("--window-size=1500,1400");
  if (headless) {
    options.addArguments("--headless=new", "--no-sandbox",
                         "--disable-dev-shm-usage");
  }
  // Two environment hazards this workflow is exposed to, both silent: it is all
  // Web Crypto (holder key pairs, proofs of possession, Key Binding JWTs,
  // signature verification), which needs a secure context; and its pages must
  // fetch this suite's services on loopback, which a deployed https page may
  // not do without the private-network flags. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await handoffParameterCheck(driver);
    await stepOne(driver);
    await oidcLeg(driver);
    var context = await stepTwo(driver);
    await stepThree(driver, context);
    var generations = await stepFour(driver, context);
    await credentialHistoryNavigation(driver, generations);
    await panesContainTheirContent(driver);
    await stepLinksOnEveryPage(driver);
    await chooserFitsOnOneScreen(driver);
    await stepOneFitsInOneRow(driver);
    await didConfigurationPane(driver);

    var errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0,
      "the workflow logged browser errors:\n" + errors.join("\n"));
    log.info("[browser] OK — no console errors across the workflow.");

    // Both of these belong AFTER the console-error assertion above, with the
    // other negative sections: each deliberately drives the pages into states
    // they are supposed to complain about. presentationHandoff() plants an
    // unparseable credential, and step 4 quite correctly logs that it cannot
    // parse what it was given — which failed the run when this sat above the
    // assertion. metadataSignatureValidation() clobbers and restores both
    // metadata documents.
    await presentationHandoff(driver, generations);
    await metadataSignatureValidation(driver);

    await refreshNegatives(driver);
    await staleProofRecovery(driver);
    await inspectLinksReturnHere(driver);
    await stepTwoWithoutTokens(driver);
    await credentialOfferSameDevice(driver);
    await crossDeviceOffer(driver);
    await deferredIssuance(driver);
    await authorizationDetailsFlow(driver);
    // Runs on the step 3 the previous section left behind: the notification is
    // about that credential.
    await notificationFlow(driver);
    // After the notification section, not before it: that one reads the step 3
    // the previous section left on screen, and this one navigates away.
    await authorizationDetailsIsTheDefault(driver);
    await claimsSelection(driver);
    await claimsCannotTravelOnAScope(driver);
    await preAuthorizedClaimsThroughThePages(driver);
    await preAuthorizedClaimsRequest();
    await batchAndEncryptedIssuance(driver);
    // The other direction of section 10. After the batch section because both
    // start from stepOneConfigured(), and this one leaves step 3 showing a
    // credential obtained through an encrypted request.
    await encryptedCredentialRequest(driver);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option('-u, --url <url>',
                  'base url of the debugger under test'));
program.addOption(new Option('-h, --headless <headless>',
                  'run headless (true/false)'));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) { baseUrl = opts.url; log.info("Setting url to " + baseUrl); }
if (opts.headless === "false") { headless = false; }

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
