// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_issuance_client_auth.js
//
// ---------------------------------------------------------------------------
// The VC issuance workflow's CLIENT AUTHENTICATION at the token endpoint,
// in Chrome, against a CONFIDENTIAL client on iya-sts that this job
// provisions itself through /admin-api (sts_applications.js) — it is never
// assumed to exist.
//
// For each method the client declares, a fresh pre-authorized offer is
// taken from iya-sts's portal wallet, step 1 is configured with the
// confidential client and the method, and step 2's Token Request is sent:
//
//   * client_secret_basic — the shown request carries `Authorization: Basic
//     base64(<client_id>:<client_secret>)` and never the secret; the token
//     is issued; the same with a WRONG secret is refused;
//   * client_secret_post — client_secret in the body (shown elided);
//   * private_key_jwt — a key made here in node, its JWKS registered on the
//     client; the shown request carries client_assertion;
//   * attest_jwt_client_auth — a Client Attestation signed HERE with node's
//     crypto by an attester iya-sts is told to trust for the length of the
//     job (oauth2.clientAttestationTrustedKeys, restored after); the shown
//     request carries both attestation headers.
//
// The secret is typed on step 2 and the test then checks that no storage
// holds it. Holds the sts-vc lock (run-report.js JOB_LOCKS): it configures
// iya-sts.
// ---------------------------------------------------------------------------

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const nodeCrypto = require("crypto");
const browserFlags = require("./browser_flags.js");
const registry = require("./sts_applications.js");
const common = require("./jwt_vc_json_common.js");
const consentScreen = require("./consent_screen.js");
const { usernameFor } = require("./random_username.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
const waitForContent = require("./wait_for.js");
const { waitForStatus } = require("./wait_for");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_issuance_client_auth",
    level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var fetchWait = Math.max(waitTime, 20000);
var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL ||
  stsUrl.replace(/\/sts\/?$/, "");
var VCI_CONFIG_ID = process.env.OID4VCI_CONFIG_ID || "IdentityCredential";
var OFFER_USER = usernameFor("vc-client-auth");
var CLIENT_ID = "vc-confidential-" + nodeCrypto.randomBytes(4)
  .toString("hex");
var SECRET = nodeCrypto.randomBytes(24).toString("base64url") + "-:&+";
var ATTESTATION_KEY = "oauth2.clientAttestationTrustedKeys";

function jwk(pair) {
  log.debug("Entering jwk().");
  log.debug("Leaving jwk().");
  return pair.privateKey.export({ format: "jwk" });
}

function pub(j) {
  log.debug("Entering pub().");
  var o = Object.assign({}, j);
  delete o.d;
  log.debug("Leaving pub().");
  return o;
}

function b64u(o) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(JSON.stringify(o)).toString("base64url");
}

// A Client Attestation signed with node's crypto (not the debugger's code).
function attestation(attester, instance) {
  log.debug("Entering attestation().");
  var now = Math.floor(Date.now() / 1000);
  var input = b64u({ typ: "oauth-client-attestation+jwt", alg: "ES256",
                     kid: "job-attester" }) + "." +
    b64u({ sub: CLIENT_ID, iat: now, exp: now + 3600,
           cnf: { jwk: pub(jwk(instance)) } });
  var sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: attester.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving attestation().");
  return input + "." + sig.toString("base64url");
}

async function value(driver, id) {
  log.debug("Entering value(). " + id);
  log.debug("Leaving value().");
  return driver.executeScript("var e=document.getElementById(arguments[0]);" +
    "return e ? (e.value || e.textContent || '') : '';", id);
}

async function setField(driver, id, v, event) {
  log.debug("Entering setField(). " + id);
  await driver.executeScript("var e=document.getElementById(arguments[0]);" +
    "e.value=arguments[1]; e.dispatchEvent(new Event(arguments[2]));",
    id, v, event || "input");
  log.debug("Leaving setField().");
}

async function provision(signingKey) {
  log.debug("Entering provision().");
  var base = registry.stsBaseFor(issuerBase);
  await registry.provision(base, {
    identifier: CLIENT_ID,
    name: "VC issuance confidential client (client authentication)",
    protocols: ["oauth2", "oid4vci"],
    fields: {
      oauthClientId: CLIENT_ID,
      oauthGrantType: ["urn:ietf:params:oauth:grant-type:pre-authorized_code",
                       "refresh_token"],
      oauthConfidential: "TRUE",
      oauthTokenEndpointAuthMethod: ["client_secret_basic",
        "client_secret_post", "private_key_jwt", "attest_jwt_client_auth"]
    },
    why: "the confidential wallet client the client-authentication job uses"
  });
  var set = async function (attribute, v) {
    var wrote = await registry.adminPost(base, "/applications/set",
      { application: CLIENT_ID, attribute: attribute, value: v });
    assert.ok(wrote && wrote.ok, "setting " + attribute + " on " + CLIENT_ID +
              " was refused: " + JSON.stringify(wrote).slice(0, 300));
  };
  await set("oauthClientSecret", SECRET);
  await set("oauthJwks", JSON.stringify({ keys: [Object.assign(
    pub(signingKey), { kid: "job-key", use: "sig" })] }));
  log.debug("Leaving provision().");
  return base;
}

// Step 1 with the issuer's own AS and the confidential client, then the
// offer taken; ends on step 2.
async function toStepTwo(driver, offerUri, methodName, fields) {
  log.debug("Entering toStepTwo(). " + methodName);
  await loadUrl(driver, baseUrl + "/vc-issuance-1.html");
  await waitForContent.waitForPageBundle(driver, "step 1");
  await driver.executeScript("window.localStorage.clear();");
  await driver.navigate().refresh();
  await waitForContent.waitForPageBundle(driver, "step 1 again");
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];" +
    "document.getElementById('oidc_discovery_endpoint').value = arguments[1];",
    issuerBase + "/.well-known/openid-credential-issuer",
    issuerBase + "/.well-known/oauth-authorization-server");
  await driver.findElement(By.id("vci_retrieve_button")).click();
  await waitForStatus(driver, "vci_signed_metadata_status", function (s) {
    return /^Retrieved/.test(s);
  }, "the credential issuer metadata was not retrieved", fetchWait);
  await driver.findElement(By.id("as_retrieve_button")).click();
  await waitForStatus(driver, "as_signed_metadata_status", function (s) {
    return /^Retrieved/.test(s);
  }, "the authorization server metadata was not retrieved", fetchWait);
  await driver.executeScript(
    "document.getElementById('client_id').value = arguments[0];", CLIENT_ID);
  await driver.findElement(By.id("config_save_button")).click();
  // The pane is rendered on load from what is stored; after the metadata
  // and the client, reload so it defaults from them, then choose.
  await driver.navigate().refresh();
  await waitForContent.waitForPageBundle(driver, "step 1, configured");
  await driver.wait(until.elementLocated(By.id("vc_client_auth_method")),
                    waitTime);
  await setField(driver, "vc_client_auth_method", methodName, "change");
  for (const id of Object.keys(fields || {})) {
    await setField(driver, id, fields[id]);
  }
  await driver.executeScript(
    "document.getElementById('scan_offer_input').value = arguments[0];",
    offerUri);
  await driver.findElement(By.id("scan_offer_button")).click();
  await driver.wait(async function () {
    return (await value(driver, "vci_credential_endpoint")) === issuerBase +
      "/oid4vci/credential";
  }, fetchWait, "taking the offer should discover its issuer");
  await driver.sleep(400);
  await driver.findElement(By.id("start_issuance_button")).click();
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
                    "a pre-authorized offer goes straight to step 2");
  await waitForContent.waitForPageBundle(driver, "step 2");
  log.debug("Leaving toStepTwo().");
}

async function redeem(driver, offered, methodName, fields, secret, shownRe,
                      expectOk) {
  log.debug("Entering redeem(). " + methodName);
  await toStepTwo(driver, offered.uri, methodName, fields);
  if (secret !== undefined) {
    await driver.wait(until.elementLocated(By.id("vc_client_secret")),
                      waitTime);
    await setField(driver, "vc_client_secret", secret);
  }
  if (offered.txCode) {
    await driver.executeScript("document.getElementById('vc_tx_code').value" +
      " = arguments[0]; vcissuance2.onTxCodeChange();", offered.txCode);
  }
  var shown = "";
  await driver.wait(async function () {
    shown = await value(driver, "vc_token_request");
    return shownRe.test(shown);
  }, fetchWait, methodName + ": the shown Token Request should match " +
    shownRe + "; it is: " + shown.slice(0, 300));
  assert.ok(secret === undefined || shown.indexOf(secret) === -1,
            methodName + ": the shown request must not carry the secret");
  await driver.findElement(By.id("vc_token_request_button")).click();
  if (expectOk) {
    await driver.wait(async function () {
      return !!(await value(driver, "vc_access_token"));
    }, fetchWait, methodName + ": the token endpoint should issue a token. " +
      "Status: " + (await value(driver, "vc_token_status")));
  } else {
    await waitForStatus(driver, "vc_token_status", function (s) {
      return /refused/.test(s);
    }, methodName + ": the token endpoint should refuse it", fetchWait);
  }
  var leaked = await driver.executeScript("var out=[];" +
    "[localStorage, sessionStorage].forEach(function (st) {" +
    " for (var i=0;i<st.length;i++){ var k=st.key(i);" +
    "  if (String(st.getItem(k)).indexOf(arguments[0])!==-1) out.push(k);}" +
    "}); return out;", SECRET);
  assert.deepStrictEqual(leaked, [], methodName + ": no storage holds the " +
                         "client secret");
  log.info("PASS " + methodName + (expectOk ? ": token issued" :
           ": refused as it must be") + "; nothing stored the secret.");
  log.debug("Leaving redeem().");
}

async function offer(driver) {
  log.debug("Entering offer().");
  var screen = await common.offerFromThePortalWallet(driver, { By: By,
    until: until, stsBase: issuerBase, username: OFFER_USER,
    mode: "cross-device", configuration: VCI_CONFIG_ID, wait: fetchWait,
    consentScreen: consentScreen });
  log.debug("Leaving offer().");
  return { uri: screen.offerUri, txCode: screen.txCode };
}

// A setting's current value anywhere in GET /admin-api/config's reply
// (an entry naming it as key or name, with a value), so it can be put back.
function settingIn(json, key) {
  log.debug("Entering settingIn(). " + key);
  var found;
  var walk = function (o) {
    if (found !== undefined || !o || typeof o !== "object") return;
    if ((o.key === key || o.name === key) && "value" in o) {
      found = o.value;
      return;
    }
    if (Object.prototype.hasOwnProperty.call(o, key) &&
        typeof o[key] !== "object") {
      found = o[key];
      return;
    }
    Object.keys(o).forEach(function (k) {
      walk(o[k]);
    });
  };
  walk(json);
  log.debug("Leaving settingIn(). " + (found === undefined ? "absent" :
            "found"));
  return found;
}

async function test() {
  log.debug("Entering test().");
  var signing = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var attester = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instance = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var base = await provision(jwk(signing));
  var previous = settingIn(await registry.adminGet(base, "/config"),
                           ATTESTATION_KEY);
  var trust = await registry.adminPost(base, "/config/set", {
    key: ATTESTATION_KEY, value: JSON.stringify({ keys: [Object.assign(
      pub(jwk(attester)), { kid: "job-attester", use: "sig" })] }) });
  assert.ok(trust && trust.ok, "iya-sts would not trust this job's " +
            "attester: " + JSON.stringify(trust).slice(0, 300));

  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await redeem(driver, await offer(driver), "client_secret_basic", {},
                 SECRET, /Authorization: Basic base64\(.*:<client_secret>\)/,
                 true);
    await redeem(driver, await offer(driver), "client_secret_basic", {},
                 "the-wrong-secret", /Authorization: Basic/, false);
    await redeem(driver, await offer(driver), "client_secret_post", {},
                 SECRET, /client_secret=%3Cclient_secret%3E/, true);
    await redeem(driver, await offer(driver), "private_key_jwt", {
      vc_client_private_jwk: JSON.stringify(jwk(signing)),
      vc_client_auth_kid: "job-key" }, undefined,
      /client_assertion=eyJ/, true);
    await redeem(driver, await offer(driver), "attest_jwt_client_auth", {
      vc_client_attestation: attestation(attester, instance),
      vc_client_instance_jwk: JSON.stringify(jwk(instance)) }, undefined,
      /OAuth-Client-Attestation-PoP: eyJ/, true);
    log.info("vc_issuance_client_auth: all checks passed.");
  } finally {
    await driver.quit();
    await registry.adminPost(base, "/config/set", { key: ATTESTATION_KEY,
      value: previous === undefined || previous === null ? "" :
        (typeof previous === "string" ? previous : JSON.stringify(previous))
    });
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
