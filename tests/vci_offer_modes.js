// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vci_offer_modes.js
//
// ---------------------------------------------------------------------------
// THE TWO PRE-AUTHORIZED OFFERS THE ISSUANCE CHOOSER NAMES, COLLECTED THE
// WAY ANY ISSUER HANDS THEM OUT (#365).
//
// vc-issuance-0's cross-device (H.2) and deferred (H.3) cards send the
// person to the issuer's own website, because a pre-authorized offer is
// made wherever the issuer makes one — an account page somebody signs in
// to, an operator — and nothing in OpenID4VCI says where. The wallet's half
// is then issuer-independent: it takes the offer it is given and redeems
// it. iya-sts is the issuer here because its portal (/portal/wallet) is one
// such place; the wallet pages are given nothing iya-sts-specific.
//
// Two things nothing else in the suite drives:
//
//   1. DEFERRED. A `deferred` offer's Credential Response is a
//      transaction_id; step 2 opens its Deferred Issuance pane and polls the
//      Deferred Credential Endpoint on its own until the issuer is ready,
//      then opens step 3. The credential that arrives is checked like any
//      other — bound to the wallet's own key — and step 3 says it came by
//      the deferred route.
//   2. AN OFFER THAT IS ONLY A PICTURE. The cross-device offer is handed to
//      the wallet as the portal's QR CODE, an image file chosen on step 1,
//      and decoded in the page; it must decode to exactly the offer the
//      portal printed beside it, and the credential is collected from it.
//
// Needs the client and iya-sts.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vci_offer_modes",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());
const browserFlags = require("./browser_flags.js");
const wallet = require("./wallet_issuance.js");

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const STS = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
let BASE = "https://localhost:3000";
const CONFIGURATION = process.env.VCI_OFFER_CONFIGURATION ||
    "IdentityCredential";
const WAIT = Number(process.env.TEST_WAIT_TIME_MS) > 0
  ? Math.max(20000, Number(process.env.TEST_WAIT_TIME_MS) * 4) : 20000;

async function aDeferredOfferIsCollectedByPolling(driver) {
  log.debug("Entering aDeferredOfferIsCollectedByPolling().");
  log.info("=== H.3: a deferred pre-authorized offer ===");
  const held = await wallet.collect(driver, { By: By, until: until,
    baseUrl: BASE, issuerBase: STS, configuration: CONFIGURATION,
    label: "deferred", wait: WAIT, mode: "deferred" });
  wallet.assertBoundToTheWalletsKey(held);
  const step3 = await driver.executeScript(
    "return document.body.textContent;");
  assert.ok(/deferred/i.test(step3),
    "step 3 should say the credential was collected from the Deferred " +
    "Credential Endpoint; it says nothing about deferral.");
  log.info("[deferred] OK — " + (held.deferredTransactionId
    ? "the Deferred Issuance pane showed transaction_id " +
      held.deferredTransactionId + ", "
    : "") + "the wallet polled the Deferred Credential Endpoint and " +
    "collected a " + held.format + " bound to its own key.");
  log.debug("Leaving aDeferredOfferIsCollectedByPolling().");
}

async function anOfferIsReadFromItsQrCode(driver) {
  log.debug("Entering anOfferIsReadFromItsQrCode().");
  log.info("=== H.2: a cross-device offer read from its QR code ===");
  const held = await wallet.collect(driver, { By: By, until: until,
    baseUrl: BASE, issuerBase: STS, configuration: CONFIGURATION,
    label: "qr", wait: WAIT, mode: "cross-device", viaQrImage: true });
  assert.ok(held.readFromQr, "the offer was not read from the QR image");
  wallet.assertBoundToTheWalletsKey(held);
  log.info("[qr] OK — the portal's QR code decoded on step 1 to the offer " +
           "it printed, and the credential was collected from it.");
  log.debug("Leaving anOfferIsReadFromItsQrCode().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. client=" + BASE + ", issuer=" + STS);
  var options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
                       "--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, BASE);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await driver.manage().window().setRect({ width: 1500, height: 1200 });
    await aDeferredOfferIsCollectedByPolling(driver);
    await anOfferIsReadFromItsQrCode(driver);
  } finally {
    await driver.quit();
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("vci_offer_modes")
  .description("Collect a deferred pre-authorized offer by polling, and a " +
      "cross-device offer read from its QR code image, through the VC " +
      "Issuance pages.")
  .addOption(new Option("-u, --url <url>",
      "base url of the client under test"))
  .parse(process.argv);
const cliOptions = program.opts();
if (cliOptions.url) BASE = String(cliOptions.url).replace(/\/$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exitCode = 1;
});
