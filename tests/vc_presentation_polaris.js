// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_presentation_polaris.js
//
// ---------------------------------------------------------------------------
// The VC Presentation workflow, under HAIP 1.0, against Polaris
// (polaris-oid4vp, https://github.com/EgorKhaklin/polaris-id, #423): an
// OpenID4VP 1.0 + HAIP 1.0 VERIFIER, independently written, run from its own
// published image and not modified. The debugger is the wallet.
//
// Polaris speaks HAIP and nothing else, which is the point: an x509_hash
// Client Identifier, a signed Request Object fetched by request_uri with
// request_uri_method=post (so the wallet posts wallet_metadata and a
// wallet_nonce the object must echo), and an encrypted direct_post.jwt
// answer. It checks an SD-JWT VC signed ES256 with holder key binding.
//
// The debugger is the wallet throughout, as the specifications intend:
//
//   * the credential is iya-sts's, issued in this run and COLLECTED BY THE
//     WALLET. iya-sts signs RS256 unless an offer chooses otherwise, so the
//     offer is made on iya-sts's portal with ES256 chosen, and the
//     debugger's own issuance pages redeem it, with the holder key they
//     generate. (The credential's x5c is switched off for that issuance;
//     see es256Credential() for why.)
//   * the presentation starts the way a wallet on another device starts one:
//     Polaris's haip-vp:// launch link pasted into step 1, with HAIP and
//     Polaris's trust anchor set on step 0.
//
// Polaris is told to trust iya-sts's issuer key (--issuer-jwks), to ask for
// that credential's vct and for given_name and family_name.
//
// Two cases:
//   accepted  everything asked for, through the pages; Polaris's --result
//             says `accepted` and names exactly the claims asked for;
//   refused   family_name withheld on step 2; Polaris refuses on `claims`,
//             and the wallet's step 3 says the Verifier refused it.
//
// Wiring: Polaris runs inside tests/polaris/serve-loop.sh, which restarts
// `serve --once` for each case on a signal file in a volume this job shares
// (POLARIS_DATA_DIR), and sits behind waltid/cors-proxy.js serving TLS
// (POLARIS_URL), because Polaris sends no CORS headers and HAIP's URLs are
// https. The job is not scheduled when POLARIS_DATA_DIR is unset.
// ---------------------------------------------------------------------------

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const browserFlags = require("./browser_flags.js");
const common = require("./jwt_vc_json_common.js");
const walletIssuance = require("./wallet_issuance.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
const { waitForStatus, waitForValue } = require("./wait_for");
const waitForContent = require("./wait_for.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_presentation_polaris",
                                level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 15000;
var stepWait = waitTime * 4;
var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL ||
    stsUrl.replace(/\/sts\/?$/, "");
const DATA = process.env.POLARIS_DATA_DIR || "";
const SD_JWT_CONFIG_ID = process.env.OID4VCI_CONFIG_ID || "IdentityCredential";
const ASKED = ["given_name", "family_name"];

async function pageBundleReady(driver) {
  log.debug("Entering pageBundleReady().");
  await waitForContent.waitForPageBundle(driver, stepWait);
  log.debug("Leaving pageBundleReady().");
}

async function clickId(driver, id) {
  log.debug("Entering clickId(). " + id);
  await driver.wait(until.elementLocated(By.id(id)), stepWait);
  await driver.executeScript("document.getElementById(arguments[0])" +
                             ".click();", id);
  log.debug("Leaving clickId().");
}

function readJson(file) {
  log.debug("Entering readJson(). " + file);
  try {
    log.debug("Leaving readJson().");
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    log.debug("Leaving readJson(). Not readable yet.");
    return null;
  }
}

async function until_(what, fn, ms) {
  log.debug("Entering until_(). " + what);
  const end = Date.now() + ms;
  for (;;) {
    const got = fn();
    if (got) {
      log.debug("Leaving until_().");
      return got;
    }
    if (Date.now() > end) {
      log.debug("Leaving until_(). Timed out.");
      throw new Error("timed out waiting for " + what);
    }
    await new Promise(function (r) {
      setTimeout(r, 300);
    });
  }
}

// One iya-sts setting, read and set through its management API.
async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  const before = await common.httpJson(issuerBase + "/admin-api/config");
  let old;
  ((before.body && before.body.groups) || []).forEach(function (g) {
    (g.settings || []).forEach(function (row) {
      if (row.key === key && old === undefined) {
        old = row.value !== undefined ? row.value : row.text;
      }
    });
  });
  if (value !== undefined) {
    const r = await common.httpJson(issuerBase + "/admin-api/config/set", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: key, value: String(value) }) });
    assert.ok(r.ok, "iya-sts refused " + key + "=" + value + ": " +
              String(r.raw).slice(0, 200));
  }
  log.debug("Leaving setting(). was " + old);
  return old;
}

// An ES256 SD-JWT VC from iya-sts: the offer made on its portal with ES256
// chosen, redeemed in node.
//
// WITHOUT x5c, which is the one iya-sts setting this job changes (under the
// `sts-vc` lock, and put back). iya-sts carries its signing key's chain in
// the credential by default, and that chain's certificates are RSA-signed
// even when the key that signs the credential is P-256. Polaris verifies an
// issuer chain's links with ECDSA only, so a credential with that x5c is
// refused as "does not chain to any configured trust anchor" whatever anchor
// is configured. Without x5c, Polaris takes the issuer key from
// --issuer-jwks: iya-sts's own ES256 key, from its issuer metadata.
async function es256Credential(driver) {
  log.debug("Entering es256Credential().");
  const header = "oid4vci.credentialCertificateHeader";
  const was = await setting(header, "none");
  try {
    log.debug("Leaving es256Credential().");
    return await mintEs256(driver);
  } finally {
    await setting(header, was === undefined || was === "" ? "x5c" : was);
  }
}

// The ES256 credential, collected BY THE WALLET: the debugger's own issuance
// pages take the portal's offer (vc-issuance-1's Receive pane), redeem the
// pre-authorized code with the Transaction Code (step 2), and send the
// Credential Request with a proof by the holder key the wallet generated.
// What reaches the presentation pages is what the wallet stored, not
// anything this job wrote.
async function mintEs256(driver) {
  log.debug("Entering mintEs256().");
  const held = await walletIssuance.collect(driver, {
    By: By, until: until, baseUrl: baseUrl, issuerBase: issuerBase,
    configuration: SD_JWT_CONFIG_ID, signingAlg: "ES256", label: "polaris",
    wait: stepWait });
  assert.strictEqual(held.header.alg, "ES256", "the offer chose ES256 and " +
    "the credential is signed " + held.header.alg + "; Polaris checks ES256");
  walletIssuance.assertBoundToTheWalletsKey(held);
  const carried = String(held.credential).split("~").slice(1)
    .filter(Boolean).map(function (d) {
      return JSON.parse(common.b64uDecode(d).toString("utf8"))[1];
    });
  ASKED.forEach(function (name) {
    assert.ok(carried.indexOf(name) !== -1, "the credential must carry " +
      name + " for Polaris to ask for it; it carries " + carried.join(", "));
  });
  assert.ok(!held.header.x5c, "the credential still carries x5c, so " +
            oid4vciHeaderNote());
  log.debug("Leaving mintEs256().");
  return held;
}

function oid4vciHeaderNote() {
  log.debug("Entering oid4vciHeaderNote().");
  log.debug("Leaving oid4vciHeaderNote().");
  return "oid4vci.credentialCertificateHeader=none did not take effect";
}

// The issuer key Polaris is to trust: iya-sts's, from the SD-JWT VC issuer
// metadata its credential's iss names.
async function issuerJwks(held) {
  log.debug("Entering issuerJwks().");
  const iss = String(held.payload.iss).replace(/\/+$/, "");
  const u = new URL(iss);
  const meta = await common.httpJson(u.origin + "/.well-known/jwt-vc-issuer" +
      (u.pathname === "/" ? "" : u.pathname));
  let jwks = meta.body && meta.body.jwks;
  if (!jwks && meta.body && meta.body.jwks_uri) {
    jwks = (await common.httpJson(meta.body.jwks_uri)).body;
  }
  const keys = ((jwks || {}).keys || []).filter(function (k) {
    return k.kty === "EC" && k.crv === "P-256" &&
           (!held.header.kid || k.kid === held.header.kid);
  });
  assert.ok(keys.length, "iya-sts publishes no P-256 key with kid " +
    held.header.kid + " at " + u.origin + "/.well-known/jwt-vc-issuer: " +
    String(meta.raw).slice(0, 300));
  log.debug("Leaving issuerJwks().");
  return { keys: keys };
}

// Start a fresh Polaris request and read its launch parameters.
async function freshRequest(serveArgs, issuers) {
  log.debug("Entering freshRequest().");
  fs.writeFileSync(path.join(DATA, "issuers.json"), JSON.stringify(issuers));
  fs.writeFileSync(path.join(DATA, "serve.args"), serveArgs.join("\n") + "\n");
  const before = readJson(path.join(DATA, "result.json"));
  fs.writeFileSync(path.join(DATA, "next"), String(Date.now()));
  const params = await until_("Polaris to start a request", function () {
    const result = readJson(path.join(DATA, "result.json"));
    if (!result || result.outcome !== "nothing_received" || !result.state ||
        (before && before.state === result.state)) {
      return null;
    }
    let text = "";
    try {
      text = fs.readFileSync(path.join(DATA, "serve.log"), "utf8");
    } catch (e) {
      return null;
    }
    const block = text.split("authorization request parameters:")[1] || "";
    const got = {};
    block.split("\n").forEach(function (line) {
      const m = /^\s+(client_id|request_uri|request_uri_method)\s+(\S+)/
          .exec(line);
      if (m) got[m[1]] = m[2];
    });
    // The link a wallet is launched with: HAIP 1.0's own scheme
    // (section 5.1), which Polaris prints beside openid4vp://.
    const link = /^\s+(haip-vp:\/\/\?\S+)/m.exec(text);
    got.launch = link ? link[1] : "";
    return got.client_id && got.request_uri && got.launch ? got : null;
  }, stepWait);
  log.info("Polaris asks as " + params.client_id + " at " +
           params.request_uri);
  log.debug("Leaving freshRequest().");
  return params;
}

async function outcome() {
  log.debug("Entering outcome().");
  const result = await until_("Polaris's verdict", function () {
    const r = readJson(path.join(DATA, "result.json"));
    return r && r.outcome && r.outcome !== "nothing_received" ? r : null;
  }, stepWait);
  log.debug("Leaving outcome(). " + result.outcome);
  return result;
}

// Step 0 as a person sets it up: HAIP chosen, and the Verifier's trust
// anchor (Polaris's keygen anchor) pasted into the configuration and saved.
async function chooseHaip(driver, anchor) {
  log.debug("Entering chooseHaip().");
  await loadUrl(driver, baseUrl + "/vc-presentation-0.html");
  await pageBundleReady(driver);
  await clickId(driver, "vp_protocol_haip");
  await driver.wait(until.elementLocated(By.id("vp_x509_trust_anchor")),
                    stepWait);
  await driver.executeScript(
    "document.getElementById('vp_x509_trust_anchor').value = arguments[0];",
    anchor);
  await clickId(driver, "config_save_button");
  const chosen = await driver.executeScript(
    "return [localStorage.getItem('sdjwtvp_protocol')," +
    "  localStorage.getItem('sdjwtvp_x509_trust_anchor')];");
  assert.strictEqual(chosen[0], "haip", "choosing HAIP on step 0 should " +
                     "stick");
  assert.ok(/BEGIN CERTIFICATE/.test(chosen[1] || ""), "saving step 0's " +
            "configuration should keep the trust anchor");
  log.debug("Leaving chooseHaip().");
}

// One presentation: the launch link Polaris printed pasted into step 1, the
// way a wallet on another device reads it from a QR code, then step 2 and
// Present.
async function presentTo(driver, launchLink, withhold) {
  log.debug("Entering presentTo(). withhold=" + (withhold || ""));
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vp_paste_request")),
                    stepWait);
  await driver.executeScript(
    "document.getElementById('vp_paste_request').value = arguments[0];",
    launchLink);
  await clickId(driver, "vp_use_pasted_button");
  const said = await waitForStatus(driver, "vp_request_status", function (s) {
    return /Request read|cannot be answered|Could not/.test(s);
  }, "step 1 should read Polaris's request", stepWait);
  assert.ok(/Request read/.test(said), "step 1 refused Polaris's request: " +
    said + "\n" + await driver.findElement(By.id("vp_protocol_rules"))
    .getText());
  const rules = await driver.findElement(By.id("vp_protocol_rules"))
    .getText();
  assert.ok(!/WARNING/.test(rules), "Polaris's request should meet every " +
    "HAIP rule, the trust anchor among them:\n" + rules);
  await clickId(driver, "vp_continue_button");
  await driver.wait(until.urlContains("vc-presentation-2.html"), stepWait);
  await pageBundleReady(driver);
  await waitForStatus(driver, "vp_present_status", function (s) {
    return /Ready/.test(s);
  }, "step 2 should build the answer", stepWait);
  if (withhold) {
    await driver.executeScript(
      "var name = arguments[0];" +
      "var rows = document.querySelectorAll(" +
      "  '#vp_disclosures_table tbody tr');" +
      "Array.prototype.forEach.call(rows, function (r) {" +
      "  if (r.textContent.indexOf(name) < 0) { return; }" +
      "  var c = r.querySelector('input[type=checkbox]');" +
      "  if (c && c.checked) { c.click(); }" +
      "});", withhold);
    await waitForStatus(driver, "vp_present_status", function (s) {
      return /missing a claim/.test(s);
    }, "withholding " + withhold + " should be reported", stepWait);
  }
  const call = await waitForValue(driver, "vp_assembled_call", function (v) {
    return /^POST /.test(v);
  }, "step 2 should assemble the encrypted answer", stepWait);
  assert.ok(/(^|\n)response=/.test(call),
    "under HAIP the answer must be ONE encrypted field:\n" + call);
  await clickId(driver, "vp_present_button");
  await driver.wait(until.urlContains("vc-presentation-3.html"), stepWait);
  await pageBundleReady(driver);
  const answer = await waitForStatus(driver, "vp_verifier_status",
    function (s) {
      return /accepted the response|refused the response/.test(s);
    }, "step 3 should report Polaris's answer", stepWait);
  log.debug("Leaving presentTo().");
  return answer;
}

async function test() {
  log.debug("Entering test().");
  if (!DATA) {
    throw new Error("POLARIS_DATA_DIR is not set; this job is scheduled " +
                    "only when it is.");
  }
  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    const held = await es256Credential(driver);
    const issuers = await issuerJwks(held);
    const anchor = await until_("Polaris's keys", function () {
      try {
        return fs.readFileSync(path.join(DATA, "pki", "anchor.pem"), "utf8");
      } catch (e) {
        return null;
      }
    }, stepWait);
    const args = ["--vct", held.payload.vct].concat([].concat.apply([],
        ASKED.map(function (c) {
          return ["--claim", c];
        })));

    log.info("=== Polaris accepts a complete HAIP presentation ===");
    await chooseHaip(driver, anchor);
    let params = await freshRequest(args, issuers);
    let answer = await presentTo(driver, params.launch, "");
    let result = await outcome();
    assert.strictEqual(result.outcome, "accepted", "Polaris should accept " +
      "the presentation: " + JSON.stringify(result));
    assert.ok(/accepted the response/.test(answer),
      "step 3 should say Polaris accepted it: " + answer);
    ASKED.forEach(function (c) {
      assert.ok((result.claims || []).indexOf(c) !== -1,
        "Polaris should have received " + c + ": " +
        JSON.stringify(result.claims));
    });
    log.info("[accepted] Polaris accepted, with " +
             JSON.stringify(result.claims));

    log.info("=== Polaris refuses a presentation that withholds a claim ===");
    params = await freshRequest(args, issuers);
    answer = await presentTo(driver, params.launch, "family_name");
    result = await outcome();
    assert.strictEqual(result.outcome, "refused", "withholding family_name " +
      "must be refused: " + JSON.stringify(result));
    assert.strictEqual(result.check, "claims", "and refused on claims: " +
      JSON.stringify(result));
    assert.ok(/refused the response/.test(answer),
      "step 3 should say Polaris refused it: " + answer);
    log.info("[refused] Polaris refused on " + result.check + ": " +
             result.reason);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                  "base url of the debugger under test"));
program.addOption(new Option("-h, --headless <headless>",
                  "run headless (true/false)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) {
  baseUrl = opts.url;
  log.info("Setting url to " + baseUrl);
}
if (opts.headless === "false") {
  headless = false;
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exitCode = 1;
});
