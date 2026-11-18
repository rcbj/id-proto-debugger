// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc_browser.js
//
// ---------------------------------------------------------------------------
// acdc.html in Chrome (#480):
//
//   1. A presentation stream issued by signify-ts 0.4.1 (in node, as
//      tests/acdc_engine.js builds it) verifies in the page, every check
//      green.
//   2. The page issues a credential; its stream verifies in the page, and
//      again in node — read back with signify-ts, every SAID and signature
//      checked there.
//   3. The page revokes it: REVOKED.
//   4. A changed attribute: INVALID, naming the SAID.
//   5. Nothing is stored.
//
// Needs only the client.
// ---------------------------------------------------------------------------

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
// The user guide's pictures (docs/vc/). Inert unless DOC_SCREENSHOT_DIR is
// set, so an ordinary run takes none.
const docShots = require("./doc_screenshots.js");
const waitForContent = require("./wait_for.js");
const { waitForStatus } = require("./wait_for");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "acdc_browser",
    level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var stepWait = waitTime * 4;
const acdc = paths.requireSharedModule([path.join(__dirname, "..", "client",
  "src", "acdc.js")], "client/src/acdc.js");

async function loadSignify() {
  log.debug("Entering loadSignify().");
  var file = null;
  (require.resolve.paths("signify-ts") || []).some(function (dir) {
    var candidate = path.join(dir, "signify-ts", "dist", "index.js");
    if (fs.existsSync(candidate)) file = candidate;
    return !!file;
  });
  if (!file) {
    throw new Error("signify-ts is not installed (tests/package.json).");
  }
  var s = Object.assign({}, await import(file));
  await s.ready();
  var core = path.join(path.dirname(file), "keri", "core");
  s.vdr = (await import(path.join(core, "vdring.js"))).vdr;
  var utils = await import(path.join(core, "utils.js"));
  s.serializeIssExnAttachment = utils.serializeIssExnAttachment;
  s.serializeACDCAttachment = utils.serializeACDCAttachment;
  log.debug("Leaving loadSignify().");
  return s;
}

const text = function (b) {
  return Buffer.from(b).toString("utf8");
};

// signify-ts's issuance, as its Credentials.issue() and
// Registries.create() build it.
function signifyStream(s) {
  log.debug("Entering signifyStream().");
  var salter = new s.Salter({ raw: new TextEncoder()
    .encode("idprotodebugger2") });
  var signer = salter.signer(s.MtrDex.Ed25519_Seed, true, "0", s.Tier.low);
  var next = salter.signer(s.MtrDex.Ed25519_Seed, true, "1", s.Tier.low);
  var icp = s.incept({ keys: [signer.verfer.qb64],
    ndigs: [new s.Diger({}, next.verfer.qb64b).qb64],
    code: s.MtrDex.Blake3_256 });
  var vcp = s.vdr.incept({ pre: icp.pre, cnfg: ["NB"] });
  var ixn1 = s.interact({ pre: icp.pre, sn: 1, data: [{ i: vcp.pre, s: "0",
    d: vcp.sad.d }], dig: icp.sad.d, version: undefined, kind: undefined });
  var dt = new Date().toISOString().replace("Z", "000+00:00");
  var a = s.Saider.saidify({ d: "", holder: "signify", dt: dt })[1];
  var cred = s.Saider.saidify({ v: s.versify(s.Protocols.ACDC, undefined,
    s.Serials.JSON, 0), d: "", i: icp.pre, ri: vcp.pre,
    s: "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5", a: a })[1];
  var iss = s.Saider.saidify({ v: s.versify(s.Protocols.KERI, undefined,
    s.Serials.JSON, 0), t: s.Ilks.iss, d: "", i: cred.d, s: "0",
    ri: vcp.pre, dt: dt })[1];
  var ixn2 = s.interact({ pre: icp.pre, sn: 2, data: [{ i: iss.i,
    s: iss.s, d: iss.d }], dig: ixn1.sad.d, version: undefined,
    kind: undefined });
  var signed = function (serder) {
    return text(s.messagize(serder, [signer.sign(new TextEncoder()
      .encode(serder.raw), 0)]));
  };
  log.debug("Leaving signifyStream().");
  return signed(icp) + signed(ixn1) + signed(ixn2) + vcp.raw +
    text(s.serializeIssExnAttachment({ sn: 1, sad: ixn1.sad })) +
    new s.Serder(iss).raw +
    text(s.serializeIssExnAttachment({ sn: 2, sad: ixn2.sad })) +
    new s.Serder(cred).raw +
    text(s.serializeACDCAttachment({ pre: cred.d, sn: 0, sad: iss }));
}

async function setValue(driver, id, v) {
  log.debug("Entering setValue(). " + id);
  await driver.executeScript("document.getElementById(arguments[0]).value " +
                             "= arguments[1];", id, v);
  log.debug("Leaving setValue().");
}

async function click(driver, id) {
  log.debug("Entering click(). " + id);
  var e = await driver.wait(until.elementLocated(By.id(id)), stepWait);
  await driver.executeScript("arguments[0].scrollIntoView({block:" +
                             "'center'}); arguments[0].click();", e);
  log.debug("Leaving click().");
}

async function verdict(driver, label, pattern) {
  log.debug("Entering verdict(). " + label);
  await waitForStatus(driver, "acdc_verify_status", function (st) {
    return /^(VALID|INVALID|REVOKED)/.test(st);
  }, label, stepWait);
  var st = await driver.executeScript("return document.getElementById(" +
    "'acdc_verify_status').textContent;");
  assert.ok(pattern.test(st), label + ": " + st);
  log.debug("Leaving verdict().");
  return st;
}

async function test() {
  log.debug("Entering test().");
  var s = await loadSignify();
  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await loadUrl(driver, baseUrl + "/acdc.html");
    await waitForContent.waitForPageBundle(driver, "acdc.html");
    await driver.executeScript("localStorage.clear(); " +
                               "sessionStorage.clear();");

    // 1. signify-ts's stream.
    await setValue(driver, "acdc_stream", signifyStream(s));
    await setValue(driver, "acdc_schema", "");
    await click(driver, "acdc_verify_button");
    await verdict(driver, "signify-ts's presentation", /^VALID/);
    var crosses = await driver.executeScript("return document." +
      "querySelectorAll('#acdc_checks .vc-error').length;");
    assert.strictEqual(crosses, 0, "every check green");
    log.info("PASS a presentation stream issued by signify-ts 0.4.1 " +
             "verifies in the page.");

    // 2. Issue in the page; verify there and in node.
    docShots.setPrefix("acdc");
    await click(driver, "acdc_issue_button");
    await waitForStatus(driver, "acdc_issue_status", function (st) {
      return /^Issued/.test(st);
    }, "Issue should finish", stepWait);
    await docShots.snap(driver, "01-issue", { ids: ["pane_acdc_issue"] });
    var stream = await driver.executeScript("return document." +
      "getElementById('acdc_issue_output').value;");
    await click(driver, "acdc_verify_issued_button");
    await verdict(driver, "the page's own issuance", /^VALID/);
    await docShots.snap(driver, "02-verify", { ids: ["pane_acdc_verify"] });
    acdc.parseStream(stream).forEach(function (m, i) {
      var serder = new s.Serder(m.sad);
      assert.strictEqual(serder.raw, text(m.raw), "message " + i + ": " +
                         "signify-ts serializes it to the same bytes");
      var sad = m.sad.t === "icp" || m.sad.t === "vcp" ?
          Object.assign({}, m.sad, { i: new Array(45).join("#") }) : m.sad;
      assert.ok(new s.Saider({ qb64: m.sad.d }).verify(sad, true, true,
        undefined, "d"), "message " + i + ": signify-ts verifies its SAID");
    });
    log.info("PASS the page issued a credential; it verifies in the page, " +
             "and signify-ts reads every event and SAID of its stream.");

    // 3. Revoke.
    await click(driver, "acdc_revoke_button");
    await click(driver, "acdc_verify_issued_button");
    await verdict(driver, "the revoked credential", /^REVOKED/);
    await docShots.snap(driver, "03-revoked", { ids: ["pane_acdc_verify"] });
    log.info("PASS the page revoked it; REVOKED.");

    // 4. Tamper.
    await setValue(driver, "acdc_stream", stream.replace("Sunspot College",
                                                         "Sunspot Collegf"));
    await click(driver, "acdc_verify_button");
    await verdict(driver, "a changed attribute", /^INVALID .*SAID/);
    log.info("PASS a changed attribute is INVALID, naming the SAID.");

    var stored = await driver.executeScript("return localStorage.length + " +
                                            "sessionStorage.length;");
    assert.strictEqual(stored, 0, "the page stores nothing");
    log.info("PASS nothing is in localStorage or sessionStorage.");
    log.info("acdc_browser: all checks passed.");
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
