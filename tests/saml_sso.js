const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const path = require("path");
const { Command, Option } = require('commander');
// The SP key pair is generated per run and passed in through the environment;
// it is deliberately not stored in this repository. See common/sp_keypair.js.
const { readSpKeyPair } = require("../common/sp_keypair.js");
const browserFlags = require("./browser_flags.js");
const registry = require("./sts_applications.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'saml_sso',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// ---------------------------------------------------------------------------
// WHICH IDENTITY PROVIDER this run drives. Two of them answer this profile and
// the same combinations are run against both, which is the arrangement
// tests/wsfed_sso.js already has for WS-Federation and it is here for the same
// reason: a mock that is quietly more permissive than the real thing passes
// every test written against it alone.
//
//   keycloak  the Keycloak realm, with a SAML client provisioned by common.sh
//             carrying THIS RUN's SP certificate — so it validates the
//             AuthnRequest signature, and a request the debugger builds
//             sloppily fails there.
//   sts       the mock STS (sts/saml/saml2_sso.js). Deliberately strict where
//             Keycloak is permissive — it refuses a ProtocolBinding it does not
//             implement by name, and answers IsPassive with NoPassive rather
//             than a screen — and deliberately more permissive in exactly ONE
//             way that matters to this test: it ACCEPTS ANY entityID and
//             verifies no request signature, so nothing has to be provisioned
//             before a run.
//
// Everything below marked "IDP:" is a place the two genuinely differ. There are
// THREE, and none of them is a difference in the protocol: where the metadata
// document lives, whether the service provider has to be provisioned first, and
// which of them can be driven with no side-car at all. Anything else that
// diverges is a FINDING rather than a case to special-case, which is the whole
// point of running both.
// ---------------------------------------------------------------------------
var IDP = (process.env.SAML_IDP || "keycloak").toLowerCase();

// IDP: the sign-in screen. Both use #username / #password — THE MOCK STS COPIES
// KEYCLOAK'S FIELD IDS ON PURPOSE, so a test does not need to know which screen
// it is looking at in order to fill it in — and both use #kc-login for the
// submit button, because the mock reaches the same authentication service its
// OAuth flow does and that screen was written against Keycloak's ids too. It is
// written as a LIST anyway, and waiting for whichever arrives, for the reason
// wsfed_sso.js gives: if a third identity provider turns up with the same
// fields and a third button, the failure names the button rather than the
// environment.
//
// The password is the username on both: Keycloak's test user is provisioned
// that way (common.sh) and the mock checks no password at all, refusing only
// the literal "invalid" so a negative test has something to fail on.
var LOGIN_BUTTONS = ["kc-login", "saml2-login"];

async function elementExists(driver, id) {
  log.debug("Entering elementExists().");
  var found = await driver.findElements(By.id(id));
  log.debug("Leaving elementExists().");
  return found.length > 0;
}

async function loginAtIdp(driver, user, timeout) {
  log.debug("Entering loginAtIdp().");
  var username = By.id("username");
  await driver.wait(until.elementLocated(username), timeout,
    "the identity provider never showed its sign-in screen (no #username " +
        "field). idp=" + IDP);
  await driver.wait(until.elementIsVisible(driver.findElement(username)),
                    timeout);
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  await driver.findElement(By.id("password")).clear();
  await driver.findElement(By.id("password")).sendKeys(user);

  var clicked = null;
  for (var i = 0; i < LOGIN_BUTTONS.length; i++) {
    if (await elementExists(driver, LOGIN_BUTTONS[i])) {
      clicked = LOGIN_BUTTONS[i];
      await driver.findElement(By.id(clicked)).click();
      break;
    }
  }
  assert(clicked, "the sign-in screen carries none of the submit buttons this " +
      "test knows (" + LOGIN_BUTTONS.join(", ") + "). The username field was " +
      "there, so this is a new identity provider rather than a broken page.");
  log.info("Signed in at the " + IDP + " sign-in screen (" + clicked + ").");
  log.debug("Leaving loginAtIdp().");
}

// Poll a field's value until the predicate passes (or timeout).
async function waitForValue(driver, locator, predicate, message, timeout) {
  log.debug("Entering waitForValue().");
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(async function () {
    try {
      var v = await driver.findElement(locator).getAttribute("value");
      return predicate(v || "");
    } catch (e) {
      return false;
    }
  }, timeout || waitTime, message);
  log.debug("Leaving waitForValue().");
}

async function clickByValue(driver, value) {
  log.debug("Entering clickByValue().");
  var locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  var elArtifact = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(elArtifact), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", elArtifact);
  await elArtifact.click();
  log.debug("Leaving clickByValue().");
}

// Load the IdP metadata into the IdP Metadata pane, then wait for it to parse.
// Two modes:
//   - URL load (default): type the metadata URL and click "Load Metadata",
//     which fetches + parses the descriptor (directly, or via the API metadata
//     proxy).
//   - File upload (metadataFile set, i.e. SAML_METADATA_FILE): push a local
//     metadata file straight into the hidden file <input>, so the document is
//     parsed entirely in the browser with no cross-origin fetch.
//     remote-run-tests.sh uses this against the deployed HTTPS site, which
//     can't fetch the local http Keycloak descriptor (mixed content / CORS).
async function loadIdpMetadata(driver, metadataUrl, metadataFile) {
  log.debug("Entering loadIdpMetadata().");
  if (metadataFile) {
    log.info("Upload IdP metadata from local file: " + metadataFile);
    var fileInput = By.id("saml_metadata_file");
    await driver.wait(until.elementLocated(fileInput), waitTime);
    // The <input type=file> is display:none; Selenium sends the path to it
    // directly (file inputs don't require visibility), firing its onchange
    // handler → onMetadataFileChange() → parse.
    await driver.findElement(fileInput).sendKeys(path.resolve(metadataFile));
  } else {
    log.info("Enter metadata URL and load metadata.");
    var mdField = By.id("saml_metadata_url");
    await driver.wait(until.elementLocated(mdField), waitTime);
    await driver.findElement(mdField).clear();
    await driver.findElement(mdField).sendKeys(metadataUrl);
    await clickByValue(driver, "Load Metadata");
  }

  // Wait for the metadata to actually load + parse. The Configuration
  // Parameters fields carry sample/dummy defaults, so "endpoint is non-empty"
  // no longer proves the real IdP values were loaded — wait for the parsed
  // status instead.
  await waitForValue(driver, By.id("saml_metadata_status"),
    function (v) { return v.indexOf("Loaded and parsed") >= 0; },
    "Metadata was not loaded/parsed.");
  log.debug("Leaving loadIdpMetadata().");
}

async function samlActivities(driver, metadataUrl, spEntityId, user, binding,
                              metadataFile) {
  log.debug("Entering samlActivities().");
  // The Keycloak v2 login page (PatternFly + JS modules) can take several
  // seconds to render #username on a cold browser, and POST-binding processing
  // + request signature validation add latency — so give the login/response
  // round-trip a generous timeout regardless of the small generic waitTime.
  // The mock STS renders in milliseconds and needs none of it; one timeout for
  // both is better than a branch, because the generous one costs nothing when
  // nothing is slow.
  var loginWait = Math.max(waitTime, 15000);

  log.info("Load the SAML Test Tools page (binding=" + binding + ").");
  await driver.get(baseUrl + "/saml_request.html");

  // Load + parse the IdP metadata (URL fetch, or file upload when metadataFile
  // set).
  await loadIdpMetadata(driver, metadataUrl, metadataFile);

  // Ensure SP entityID matches the provisioned client.
  var spField = By.id("saml_sp_entity_id");
  await driver.findElement(spField).clear();
  await driver.findElement(spField).sendKeys(spEntityId);

  // Leave the NameID format at its default "(none)" — the AuthnRequest then
  // sends a <NameIDPolicy> without a Format, so the identity provider returns
  // its own default NameID rather than possibly rejecting a requested format.
  // This exercises the default "nothing chosen" behavior, and the two answer it
  // differently on purpose: Keycloak picks its client's configured format, and
  // the mock uses saml2.nameIdFormat. Neither is asserted, because what is
  // being tested is that the request without one WORKS.

  // The SP signing key pair generated for this run.
  //
  // IDP: what it is FOR differs, and the test does the same thing either way.
  // Keycloak has this run's certificate registered on its client and VALIDATES
  // the AuthnRequest signature, so the request must be signed with THIS key and
  // not one the page generates for itself. The mock STS records whether a
  // request was signed and verifies nothing — so signing there proves nothing
  // about the mock, and it still proves the DEBUGGER produced a signature it
  // was asked for, which is the half of this test that is about the client.
  log.info("Load this run's SP signing key pair (idp=" + IDP + ").");
  var spPair = readSpKeyPair();
  var spKey = spPair.privateKey;
  var spCert = spPair.certificate;
  await driver.executeScript(
    "document.getElementById('saml_sp_private_key').value = arguments[0];" +
    "document.getElementById('saml_sp_public_key').value = arguments[1];",
    spKey, spCert
  );

  // ---------------------------------------------------------------------
  // THE SERVICE PROVIDER, IN THE MOCK'S REGISTRY, BEFORE THE AUTHNREQUEST.
  //
  // Only against the mock — stsBaseFor() answers "" for the Keycloak half,
  // whose client common.sh provisions with this same entityID and this run's
  // certificate. Both identity providers therefore end up knowing about one
  // service provider, each in its own store, which is what a federation looks
  // like and is the arrangement the IDP note above describes.
  //
  // The ACS is read off the PAGE rather than composed here: it is the
  // deployment's own statement about where a response is posted (the static
  // deployments answer it from an edge function, which is a different URL from
  // the container stack's), and a registration naming a URL this run will not
  // use would be exactly the plausible-and-wrong entry pre-registration is
  // supposed to replace.
  //
  // THE MOCK STILL REQUIRES NONE OF IT, and the IDP note above says so. What
  // it buys is the difference between an entry that knows an entityID and one
  // that knows what the service provider IS: its ACS, its signing certificate,
  // and that it was declared for SAML 2.0 rather than inferred from a sighting.
  // ---------------------------------------------------------------------
  var acsUrl = await driver.findElement(By.id("saml_acs_url"))
      .getAttribute("value");
  log.info("Assertion consumer service (the page's own): " + acsUrl);
  await registry.provision(registry.stsBaseFor(metadataUrl), {
    identifier: spEntityId,
    name: "SAML 2.0 test service provider",
    protocols: ["saml2"],
    fields: Object.assign({
      samlEntityId: [spEntityId],
      // The certificate this run's AuthnRequests are signed with. The mock
      // VERIFIES no request signature — it records that one was there — so
      // this changes nothing about whether the flow works, and that is the
      // reason to register it rather than a reason not to: it is the one place
      // the two identity providers can be compared, since Keycloak's client
      // carries the same certificate and DOES verify against it.
      samlSigningCertificate: spCert
    }, acsUrl ? { samlAssertionConsumerService: [acsUrl] } : {}),
    why: "the service provider every AuthnRequest in this job comes from"
  });

  // Select the binding under test (redirect / post / artifact).
  log.info("Select binding: " + binding);
  await driver.executeScript(
    "var s=document.getElementById('saml_binding'); if(s){ s.value = " +
        "arguments[0]; s.dispatchEvent(new Event('change')); }",
    binding
  );
  var selected =
      await driver.findElement(By.id("saml_binding")).getAttribute("value");
  assert.strictEqual(selected, binding, "Binding '" + binding +
                     "' is not available in the selector.");

  // Send the (signed) AuthnRequest via the selected binding.
  log.info("Call IdP (" + binding + ").");
  await clickByValue(driver, "Call IdP");

  // The identity provider's sign-in screen. Both of them use the same field
  // ids; see loginAtIdp() and the IDP note above it.
  log.info("Log in at the identity provider (idp=" + IDP + ").");
  await loginAtIdp(driver, user, loginWait);

  // Land on the response page (ACS stashed the response and redirected here).
  log.info("Wait for the SAML response page.");
  await driver.wait(until.urlContains("saml_response.html"), loginWait);
  await waitForValue(driver, By.id("saml_resp_xml"),
    function (v) { return v.indexOf("Response") >= 0; },
    "SAMLResponse XML was not displayed.", loginWait);

  // Log the response for diagnosis (truncated). Invaluable when the IdP returns
  // a SAML error status instead of an assertion.
  var respXml =
      await driver.findElement(By.id("saml_resp_xml")).getAttribute("value");
  log.info("SAMLResponse (first 1500 chars):\n" + (respXml || "").substring(0,
           1500));

  // Assertion present. Reject the "(no <Assertion> …)" placeholder the page
  // shows for an error/encrypted response (the bare substring "Assertion" would
  // otherwise false-positive on that placeholder).
  await waitForValue(driver, By.id("saml_assertion_xml"),
    function (v) { return v.indexOf("Assertion") >= 0 &&
              v.indexOf("no <Assertion") < 0; },
    "No <Assertion> in the SAMLResponse (likely a SAML error status) — see " +
        "the logged response above.", loginWait);

  // Attributes tab includes a NameID row. Assert on the table's textContent
  // (readable even while the tab is the hidden one) rather than getText(),
  // which returns "" for a display:none element — otherwise this races the
  // tab-switch click taking effect / the bundle wiring its onclick handler
  // (that race made POST flake even though the row was rendered). The click
  // still exercises the tab UI, but the pass/fail no longer hinges on
  // visibility timing.
  log.info("Check the Attributes table for a NameID row.");
  try {
    await driver.wait(async function () {
      var txt = await driver.executeScript(
        "var e=document.getElementById('saml_attrs_table'); return e ? " +
            "(e.textContent || '') : '';");
      return txt.indexOf("NameID") >= 0;
    }, loginWait, "Attributes table did not include a NameID row.");
    try {
      await driver.findElement(By.id("tab_attrs_btn")).click();
    } catch (e) {
      /* best-effort UI exercise */
    }
  } catch (e) {
    // Dump what the page actually rendered so we can see why the NameID row is
    // missing (empty table => a render error; a table without NameID => the
    // assertion lacked one).
    var axml = await driver.findElement(By.id("saml_assertion_xml"))
        .getAttribute("value");
    var atbl = await driver.executeScript(
      "var e=document.getElementById('saml_attrs_table'); return e ? " +
          "(e.textContent || '') : '(missing)';");
    log.error("Assertion XML (first 3000 chars):\n" + (axml || "").substring(0,
              3000));
    log.error("Attributes table text:\n" + (atbl || "(empty)"));
    throw e;
  }

  log.info("SAML SSO round-trip succeeded.");
  log.debug("Leaving samlActivities().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages (e.g. jwt_tools) under coverage.
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");

  // The mock STS serves https on a certificate it generated at startup (see
  // STS_HTTPS in local-tests.yml). This trusts THAT KEY and no other, and adds
  // nothing when the run has no pin — browser_flags.js's addStsTrustFlags()
  // makes the whole argument. Without it the IdP half of this test meets a
  // certificate interstitial instead of a sign-in screen, and what the log
  // says is that the identity provider never showed its #username field.
  // This file builds its Chrome options by hand rather than through
  // addBrowserAccessFlags(), which is why the call is here instead of
  // arriving with the rest.
  browserFlags.addStsTrustFlags(options);

  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    const metadataUrl = process.env.SAML_METADATA_URL;
    // Optional: upload a local metadata file instead of fetching a URL (used by
    // remote-run-tests.sh against the deployed site — see loadIdpMetadata).
    const metadataFile = process.env.SAML_METADATA_FILE;
    const spEntityId = process.env.SAML_SP_ENTITY_ID;
    const user = process.env.SAML_USER || "saml";
    const binding = (process.env.SAML_BINDING || "redirect").toLowerCase();
    assert(metadataUrl || metadataFile, "Set SAML_METADATA_URL (URL load) or " +
           "SAML_METADATA_FILE (file upload).");
    // IDP: WHAT HAS TO BE PROVISIONED BEFORE THIS RUNS, which is the biggest
    // practical difference between the two and is worth stating where somebody
    // reading a failure will see it.
    //
    //   keycloak  a SAML client for this entityID, with this run's SP
    //             certificate on it and the test user created — common.sh does
    //             all of that, and a missing piece shows up as an error PAGE
    //             from Keycloak rather than as a sign-in screen.
    //   sts       nothing at all. The mock accepts any entityID, creates the
    //             application entry from the first valid AuthnRequest, and
    //             mints a metadata document for anything asked for — so
    //             SAML_METADATA_URL can name an entityID nobody has ever
    //             mentioned and it will answer.
    assert(spEntityId, "SAML_SP_ENTITY_ID environment variable is not set.");
    log.info("idp=" + IDP + " metadata=" + (metadataUrl || metadataFile) +
             " sp=" + spEntityId + " binding=" + binding);
    assert(["redirect", "post", "artifact"].indexOf(binding) >= 0,
           "SAML_BINDING must be redirect, post, or artifact.");

    await samlActivities(driver, metadataUrl, spEntityId, user, binding,
                         metadataFile);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    // Dump the current URL, page source, and browser console to diagnose
    // failures (an IdP error page vs the login form; a JS exception during page
    // render).
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
      var src = await driver.getPageSource();
      log.error("Page source (first 8000 chars):\n" + (src || "").substring(0,
                8000));
      var blogs = await driver.manage().logs().get("browser");
      if (blogs && blogs.length) {
        log.error("Browser console:\n" +
                  blogs.map(function (e) { return e.level.name + ": " +
                  e.message; }).join("\n"));
      }
    } catch (e2) {
      /* ignore */
    }
    testFailed = true;
  } finally {
    await driver.quit();
  }
  if (testFailed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('saml_sso')
  .description("Run SAML SSO test.")
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

test();
