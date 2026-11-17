// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_presentation_protocols.js
//
// ---------------------------------------------------------------------------
// The VC Presentation workflow under its three PROTOCOLS — OpenID4VP 1.0,
// OpenID4VC HAIP 1.0 and SIOPv2 — with every credential format the wallet
// holds, through the pages, against iya-sts's Verifier.
//
// Every credential is issued by iya-sts in the same run, and every request
// is iya-sts's own, started through its management API with the parameters
// each protocol has a Verifier send. The wallet is implemented from the
// specifications and knows nothing of iya-sts; what this job asserts is that
// an independent Verifier ACCEPTS what the wallet sent, read back where an
// operator reads it (GET /admin-api/verifications?state=).
//
//   HAIP     x509_hash, a signed Request Object by request_uri, an encrypted
//            direct_post.jwt answer — dc+sd-jwt, jwt_vc_json and ldp_vc;
//   SIOPv2   "vp_token id_token", the ID Token signed by the credential's
//            own holder key and the Verifier checking it is the same holder —
//            all three formats; then an ID Token alone, three ways: a did:jwk
//            subject by direct_post, a PAIRWISE JWK Thumbprint subject
//            encrypted by direct_post.jwt, and form_post, where the BROWSER
//            carries the answer;
//   refusal  a request by value in the clear, which HAIP must refuse on
//            step 1 before a claim is shown.
// ---------------------------------------------------------------------------

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const path = require("path");
const browserFlags = require("./browser_flags.js");
const common = require("./jwt_vc_json_common.js");
const mdocIssuer = require("./mdoc_test_issuer.js");
const nodeCrypto = require("crypto");
const paths = require("./module_paths.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
const { waitForStatus, waitForValue } = require("./wait_for");
const waitForContent = require("./wait_for.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_presentation_protocols",
                                level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 15000;
// Four times the field budget for anything that crosses a page or derives a
// proof: see the note in ldp_vc_presentation.js.
var stepWait = waitTime * 4;
var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL ||
    stsUrl.replace(/\/sts\/?$/, "");
var verifierBase = process.env.OID4VP_VERIFIER_URL || issuerBase;

const SD_JWT_CONFIG_ID = process.env.OID4VCI_CONFIG_ID || "IdentityCredential";
const LDP_CONFIG_ID = process.env.OID4VCI_LDP_CONFIG_ID ||
    "IdentityCredentialLdpVc";

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

function severeErrors(driver) {
  log.debug("Entering severeErrors().");
  const logging = require("selenium-webdriver/lib/logging");
  log.debug("Leaving severeErrors().");
  return driver.manage().logs().get(logging.Type.BROWSER)
    .then(function (entries) {
      return entries.filter(function (e) {
        return e.level.name === "SEVERE";
      }).filter(function (e) {
        return !/favicon/.test(e.message) &&
               !browserFlags.isTransientLoadError(e.message) &&
               // A Verifier answering a refused presentation 400 is logged
               // by the browser as a failed resource load; the job asserts
               // the refusals it expects itself.
               !/oid4vp\/response.*400/.test(e.message);
      }).map(function (e) {
        return e.message;
      });
    });
}

// The issuer's JSON-LD contexts, added on step 2's pane the way a person
// would, once per browser (the page keeps them). As in
// ldp_vc_presentation.js.
var contextsAdded = false;
async function addTheIssuersContexts(driver, credential) {
  log.debug("Entering addTheIssuersContexts().");
  if (contextsAdded) {
    log.debug("Leaving addTheIssuersContexts(). Already added.");
    return;
  }
  const ROOT = path.join(__dirname, "..");
  const wallet = paths.requireSharedModule(
    [path.join(__dirname, "bbs2023.js"),
     path.join(ROOT, "client", "src", "bbs2023.js")],
    "the wallet's bbs-2023 cryptosuite");
  const names = [].concat((credential || {})["@context"] || [])
    .filter(function (one) {
      return typeof one === "string";
    });
  const lacking = (await Promise.all(names.map(function (url) {
    return wallet.documentLoader(url).then(function () {
      return null;
    }, function () {
      return url;
    });
  }))).filter(Boolean);
  contextsAdded = true;
  if (!lacking.length) {
    log.debug("Leaving addTheIssuersContexts(). None needed.");
    return;
  }
  const issuerSuite = paths.requireSharedModule(
    [paths.mockStsModule("bbs2023.js") || ""],
    "iya-sts's bbs-2023 cryptosuite, for the contexts it issues under");
  await waitForStatus(driver, "vp_present_status", function (s) {
    return /JSON-LD Contexts/.test(s);
  }, "step 2 should point at the JSON-LD Contexts pane", stepWait);
  for (const url of lacking) {
    const loaded = await issuerSuite.documentLoader(url);
    await driver.executeScript(
      "document.getElementById('vp_context_url').value = arguments[0];" +
      "document.getElementById('vp_context_json').value = arguments[1];",
      url, JSON.stringify(loaded.document));
    await clickId(driver, "vp_context_add_button");
    await driver.sleep(800);
    await pageBundleReady(driver);
  }
  log.debug("Leaving addTheIssuersContexts().");
}

// The wallet's state for one case: the credential and its holder key, the
// protocol, the Verifier's trust anchor. Everything else is cleared, except
// the JSON-LD contexts the page was given.
async function plant(driver, held, protocol, anchorPem) {
  log.debug("Entering plant(). protocol=" + protocol);
  await loadUrl(driver, baseUrl + "/vc-presentation-0.html");
  await pageBundleReady(driver);
  await driver.executeScript(
    "var keep = localStorage.getItem('vc_jsonld_contexts');" +
    "localStorage.clear();" +
    "if (keep) localStorage.setItem('vc_jsonld_contexts', keep);" +
    "if (arguments[0]) {" +
    "  localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "  localStorage.setItem('sdjwtvc_credentials'," +
    "    JSON.stringify([arguments[0]]));" +
    "  localStorage.setItem('sdjwtvc_holder_jwk', arguments[1]);" +
    "  localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[2]);" +
    "}" +
    "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[3]);" +
    "localStorage.setItem('sdjwtvp_protocol', arguments[4]);" +
    "localStorage.setItem('sdjwtvp_x509_trust_anchor', arguments[5]);",
    held ? (typeof held.credential === "string" ? held.credential :
            JSON.stringify(held.credential)) : "",
    held ? JSON.stringify(held.publicJwk) : "",
    held ? JSON.stringify(held.privateJwk) : "",
    verifierBase, protocol, anchorPem || "");
  log.debug("Leaving plant().");
}

async function startAt(asked) {
  log.debug("Entering startAt(). " + JSON.stringify(asked));
  const r = await common.httpJson(verifierBase +
      "/admin-api/verifications/start", {
    method: "POST",
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
    body: JSON.stringify(asked)
  });
  assert.ok(r.ok && r.body && r.body.ok, "the Verifier should start " +
    JSON.stringify(asked) + ": HTTP " + r.status + " " +
    String(r.raw).slice(0, 300));
  const uri = String(r.body.requestUri || "");
  assert.ok(uri.indexOf("?") > 0, "the start names no request URI: " +
            String(r.raw).slice(0, 300));
  log.debug("Leaving startAt(). state=" + r.body.state);
  return { state: r.body.state, query: uri.slice(uri.indexOf("?") + 1),
           scheme: uri.slice(0, uri.indexOf("?")), body: r.body };
}

// One case through the pages: the request read on step 1, the answer built
// and sent on step 2, and the Verifier's verdict read back.
async function present(driver, c) {
  log.debug("Entering present(). " + c.label);
  log.info("=== " + c.label + " ===");
  await plant(driver, c.held, c.protocol, c.anchor);
  const started = await startAt(c.asked);
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html?" + started.query);
  await pageBundleReady(driver);
  if (c.expectRefusal) {
    const said = await waitForStatus(driver, "vp_request_status",
      function (s) {
        return /cannot be answered/.test(s);
      }, c.label + ": step 1 should refuse this request", stepWait);
    const rules = await driver.findElement(By.id("vp_protocol_rules"))
      .getText();
    c.expectRefusal.forEach(function (id) {
      assert.ok(rules.indexOf(id) !== -1 && /REFUSED/.test(rules),
        c.label + ": the rules pane should refuse " + id + ":\n" + rules);
    });
    const disabled = await driver.findElement(By.id("vp_continue_button"))
      .getAttribute("disabled");
    assert.ok(disabled, c.label + ": Continue must be off. Status: " + said);
    log.info("[" + c.label + "] refused on step 1, as it must be.");
    log.debug("Leaving present(). Refused.");
    return null;
  }
  await waitForStatus(driver, "vp_request_status", function (s) {
    return /Request read/.test(s);
  }, c.label + ": step 1 should read the request", stepWait);
  await clickId(driver, "vp_continue_button");
  await driver.wait(until.urlContains("vc-presentation-2.html"), stepWait,
    c.label + ": Continue should open step 2");
  await pageBundleReady(driver);
  if (c.ldp) await addTheIssuersContexts(driver, c.held.credential);
  if (c.pairwise) {
    await driver.wait(until.elementLocated(By.id("vp_siop_pairwise")),
                      stepWait);
    await driver.executeScript(
      "var b = document.getElementById('vp_siop_pairwise');" +
      "b.checked = true; b.dispatchEvent(new Event('change'));");
  }
  if (c.syntax) {
    await driver.executeScript(
      "var s = document.getElementById('vp_subject_syntax');" +
      "s.value = arguments[0]; s.dispatchEvent(new Event('change'));",
      c.syntax);
  }
  const call = await waitForValue(driver, "vp_assembled_call", function (v) {
    return c.form ? /BROWSER submits/.test(v) : /^POST /.test(v);
  }, c.label + ": step 2 should assemble the answer", stepWait);
  if (c.encrypted) {
    assert.ok(/(^|\n)response=/.test(call) && !/vp_token=/.test(call),
      c.label + ": direct_post.jwt must post ONE field, response:\n" + call);
  }
  // An ldp_vc page says what it derived rather than "Ready".
  await waitForStatus(driver, "vp_present_status", function (s) {
    return /Ready|Derived a bbs-2023 proof/.test(s);
  }, c.label + ": step 2 should be ready to present", stepWait);
  await clickId(driver, "vp_present_button");
  if (c.form) {
    // The browser carries a form_post answer to the Verifier, which answers
    // the browser — this wallet never sees it.
    await driver.wait(async function () {
      return /\/oid4vp\/response/.test(await driver.getCurrentUrl());
    }, stepWait, c.label + ": the form should post to the Verifier");
  } else {
    await driver.wait(until.urlContains("vc-presentation-3.html"), stepWait,
      c.label + ": presenting should reach step 3");
    await pageBundleReady(driver);
    await waitForStatus(driver, "vp_verifier_status", function (s) {
      return /accepted the response|refused the response/.test(s);
    }, c.label + ": step 3 should report the Verifier's answer", stepWait);
    if (c.encrypted || c.idToken) {
      const own = await waitForStatus(driver, "vp_answer_status",
        function (s) {
          return /passes|FAIL/.test(s);
        }, c.label + ": step 3 should re-check the answer", stepWait);
      assert.ok(/passes/.test(own), c.label + ": the wallet's own checks " +
        "on its answer fail: " + own + "\n" + await driver.findElement(
          By.id("vp_answer_checks")).getText());
    }
  }
  const doc = await common.verdictFor(verifierBase, started.state);
  if (c.verifierGap) {
    // What iya-sts DOES with this answer, asserted exactly, because the
    // shortfall is the verifier's and not the wallet's (see the case).
    const failed = ((doc.verdict || {}).checks || []).filter(function (k) {
      return !k.ok;
    });
    assert.deepStrictEqual(failed.map(function (k) {
      return k.name;
    }), [c.verifierGap], c.label + ": iya-sts was expected to fail ONLY '" +
      c.verifierGap + "' (a known gap in its 1.0.0 verifier). It failed: " +
      JSON.stringify(failed) + ". If that list is now empty, iya-sts has " +
      "been fixed: drop verifierGap from this case.");
    log.info("[" + c.label + "] every iya-sts check passed but its known " +
             "gap, '" + c.verifierGap + "'.");
    log.debug("Leaving present(). Known verifier gap.");
    return doc.verdict;
  }
  assert.ok(doc.verdict && doc.verdict.ok, c.label + ": iya-sts should " +
    "accept the answer. The checks it failed: " + JSON.stringify(
      ((doc.verdict || {}).checks || []).filter(function (k) {
        return !k.ok;
      })) + " (verdict " + JSON.stringify(doc.verdict).slice(0, 300) + ")");
  (c.mustPass || []).forEach(function (name) {
    const found = (doc.verdict.checks || []).filter(function (k) {
      return k.name === name || k.check === name;
    })[0];
    assert.ok(found && (found.ok || found.pass || found.passed),
      c.label + ": the Verifier's check '" + name + "' should have run and " +
      "passed: " + JSON.stringify(doc.verdict.checks).slice(0, 1500));
  });
  log.info("[" + c.label + "] accepted by the Verifier.");
  log.debug("Leaving present().");
  return doc.verdict;
}

async function credentials() {
  log.debug("Entering credentials().");
  const found = await common.jwtVcJsonConfigurationId(issuerBase);
  assert.ok(found.meta, "no credential issuer metadata at " + issuerBase);
  assert.ok(found.id, "this issuer offers no jwt_vc_json configuration");
  await common.provisionWallet(issuerBase,
    { why: "the wallet whose credentials this job presents under HAIP and " +
           "SIOPv2" });
  const out = {
    "dc+sd-jwt": await common.mintJwtVcJson(issuerBase, SD_JWT_CONFIG_ID),
    jwt_vc_json: await common.mintJwtVcJson(issuerBase, found.id),
    ldp_vc: await common.mintJwtVcJson(issuerBase, LDP_CONFIG_ID)
  };
  assert.ok(typeof out["dc+sd-jwt"].credential === "string" &&
            out["dc+sd-jwt"].credential.indexOf("~") > 0,
            "the SD-JWT VC configuration minted no SD-JWT");
  assert.strictEqual(typeof out.ldp_vc.credential, "object",
                     "an ldp_vc credential is a JSON object");
  log.debug("Leaving credentials().");
  return out;
}

// One iya-sts setting, read and (when `value` is given) set through its
// management API. Answers the value it had.
async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  const before = await common.httpJson(verifierBase + "/admin-api/config");
  let old;
  ((before.body && before.body.groups) || []).forEach(function (g) {
    (g.settings || []).forEach(function (row) {
      if (row.key === key && old === undefined && !row.masked) {
        old = row.value !== undefined ? row.value : row.text;
      }
    });
  });
  if (value !== undefined) {
    const r = await common.httpJson(verifierBase + "/admin-api/config/set", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: key, value: String(value) }) });
    assert.ok(r.ok, "iya-sts refused " + key + ": " +
              String(r.raw).slice(0, 200));
  }
  log.debug("Leaving setting().");
  return old;
}

// An ISO mdoc. No issuer in this stack mints one (iya-sts VERIFIES mdocs
// from issuers it trusts and mints none), so it comes from
// tests/mdoc_test_issuer.js — written apart from the wallet — and iya-sts is
// told to trust that issuer's IACA for the length of this job.
async function mdocCredential() {
  log.debug("Entering mdocCredential().");
  const auth = await mdocIssuer.authority("vc_presentation_protocols");
  const p = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicJwk = p.publicKey.export({ format: "jwk" });
  const credential = mdocIssuer.issue(auth, publicJwk, {
    given_name: "Erika", family_name: "Mustermann",
    birth_date: new mdocIssuer.Tag(1004, "1971-09-01"),
    age_over_18: true, issuing_country: "US" });
  log.debug("Leaving mdocCredential().");
  return { credential: credential, iacaPem: auth.iacaPem,
           publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv,
                        x: publicJwk.x, y: publicJwk.y },
           privateJwk: p.privateKey.export({ format: "jwk" }) };
}

// The iya-sts settings an mdoc from a foreign issuer needs, set for the
// run and put back after it: the issuer's IACA as an mdoc trust anchor, and
// a status reference required only of iya-sts's own credentials (a test
// issuer publishes no status list).
const MDOC_SETTINGS = ["oid4vp.mdocTrustAnchors",
                       "oid4vp.requireStatusReference"];

async function test() {
  log.debug("Entering test().");
  log.info("Running the presentation protocols against " + verifierBase);
  const held = await credentials();
  held.mso_mdoc = await mdocCredential();
  const restore = {};
  restore[MDOC_SETTINGS[0]] = await setting(MDOC_SETTINGS[0],
                                            held.mso_mdoc.iacaPem);
  restore[MDOC_SETTINGS[1]] = await setting(MDOC_SETTINGS[1], "own-only");
  try {
    log.debug("Leaving test().");
    return await withFormats(held);
  } finally {
    for (const key of MDOC_SETTINGS) {
      await setting(key, restore[key] === undefined ? "" : restore[key]);
    }
  }
}

async function withFormats(held) {
  log.debug("Entering withFormats().");
  const cert = await common.httpJson(verifierBase +
      "/oid4vp/verifier-certificate");
  const anchor = cert.ok && cert.body && cert.body.x509_hash &&
      cert.body.x509_hash.trust_anchor_pem;
  assert.ok(anchor, "the Verifier publishes no trust anchor for its " +
    "x509_hash Client Identifier: " + String(cert.raw).slice(0, 300));

  const cases = [];
  cases.push({ label: "OpenID4VP / mso_mdoc", protocol: "oid4vp",
    held: held.mso_mdoc, anchor: anchor,
    asked: { format: "mso_mdoc", by: "reference",
             response_mode: "direct_post", mode: "same-device" } });
  ["dc+sd-jwt", "jwt_vc_json", "ldp_vc", "mso_mdoc"].forEach(
    function (format) {
    cases.push({ label: "HAIP / " + format, protocol: "haip",
      held: held[format], anchor: anchor, ldp: format === "ldp_vc",
      encrypted: true,
      asked: { format: format, by: "reference", client_id_prefix: "x509_hash",
               response_mode: "direct_post.jwt", mode: "same-device" } });
    cases.push({ label: "SIOPv2 vp_token id_token / " + format,
      protocol: "siopv2", held: held[format], anchor: anchor,
      ldp: format === "ldp_vc", idToken: true,
      mustPass: ["id_token subject is the holder"],
      // iya-sts 1.0.0 verifies an mdoc's device signature with the MSO's
      // device key but does not return that key as the presentation's
      // holder key (oid4vc/vc_mdoc.ts sets no holderJwk), so its SIOPv2
      // "same holder" check cannot pass for ANY mdoc. The wallet's own
      // step 3 re-check of the same thing ("Same holder") has passed by
      // this point; everything else iya-sts checks must pass too.
      verifierGap: format === "mso_mdoc" ?
          "id_token subject is the holder" : "",
      asked: { format: format, by: "reference", client_id_prefix: "x509_hash",
               response_type: "vp_token id_token",
               response_mode: "direct_post", mode: "same-device" } });
  });
  cases.push({ label: "SIOPv2 id_token / did:jwk / direct_post",
    protocol: "siopv2", held: held["dc+sd-jwt"], anchor: anchor,
    idToken: true, syntax: "did:jwk",
    asked: { by: "reference", client_id_prefix: "x509_hash",
             response_type: "id_token", response_mode: "direct_post" } });
  cases.push({ label: "SIOPv2 id_token / pairwise / direct_post.jwt",
    protocol: "siopv2", held: null, anchor: anchor, idToken: true,
    pairwise: true, encrypted: true,
    syntax: "urn:ietf:params:oauth:jwk-thumbprint",
    asked: { by: "reference", client_id_prefix: "x509_hash",
             response_type: "id_token",
             response_mode: "direct_post.jwt" } });
  cases.push({ label: "SIOPv2 id_token / form_post", protocol: "siopv2",
    held: held["dc+sd-jwt"], anchor: anchor, form: true,
    asked: { by: "value", response_type: "id_token",
             response_mode: "form_post" } });
  cases.push({ label: "HAIP refuses a request by value in the clear",
    protocol: "haip", held: held["dc+sd-jwt"], anchor: anchor,
    expectRefusal: ["HAIP: signed", "HAIP: x509_hash",
                    "HAIP: direct_post.jwt"],
    asked: { format: "dc+sd-jwt", by: "value",
             response_mode: "direct_post" } });

  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    for (const c of cases) {
      await present(driver, c);
    }
    const errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0, "the pages logged browser " +
                       "errors:\n" + errors.join("\n"));
    log.info("Test completed successfully: " + cases.length + " case(s).");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving withFormats().");
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
