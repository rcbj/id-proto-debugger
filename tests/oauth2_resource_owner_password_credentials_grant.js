const { Builder, By, until } = require("selenium-webdriver");
const browserFlags = require("./browser_flags.js");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
    name: 'oauth2_resource_owner_password_credentials_grant',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "https://localhost:3000"
var logout_post_redirect_uri_value = baseUrl + "/logout.html";
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata, getAccessTokenPassword, verifyAccessToken } =
       require("../common/tests.js")({ By, until, Select, waitTime, log, jwt,
       assert });


// Waits until the browser has come to REST on a page whose URL contains
// `fragment` and whose document has finished loading, and returns that URL.
//
// ANY command issued while a navigation is in flight can come back as "unknown
// error: cannot determine loading status ... Inspected target navigated or
// closed" — chromedriver questioning a target that has just been replaced
// underneath it. The message names neither the page being left nor the one
// being entered, so it reads as a browser fault rather than as a race.
//
// Both navigations in logout() are chains rather than single hops, which is
// what makes the race reachable here: the Logout button sets location to
// Keycloak's end_session endpoint, which 302s on to the post-logout redirect
// URI, and a WebDriver click returns once the FIRST of those has committed —
// so the very next command lands in the middle of the second. The Return to
// debugger link is the same shape: it points at oauth2_oidc_1.html, whose
// $(document).ready() reads authorization_grant_type back out of local storage
// and, still finding "resource_owner" (logout clears only the two client
// secrets), sends the browser straight on to oauth2_oidc_2.html.
//
// An executeScript click is NOT a way around this, which cost a run to learn:
// chromedriver runs the same wait-for-pending-navigation step after a script
// as after a click, so an in-page click on the Return link raised the error
// from inside executeScript itself. What works is clickAndSettle() below —
// tolerate the error on the way out, and let this function decide whether the
// click did what it was for.
//
// Retrying is the only answer, since there is no command that can be issued
// safely to ask whether it is safe to issue a command. The condition is simply
// re-checked once the dust settles, and a page that never arrives still fails
// on the deadline. The budget is a multiple of waitTime because this gates on
// a round trip to the identity provider rather than on a render.
async function settleOn(driver, fragment) {
  log.debug("Entering settleOn(). fragment=" + fragment);
  const deadline = Date.now() + waitTime * 4;
  let last = null;
  while (Date.now() < deadline) {
    try {
      const url = await driver.getCurrentUrl();
      const ready = await driver.executeScript("return document.readyState;");
      if (url.indexOf(fragment) !== -1 && ready === "complete") {
        log.info("Settled on " + url);
        log.debug("Leaving settleOn(). fragment=" + fragment);
        return url;
      }
      last = new Error("still at " + url + ", readyState " + ready);
    } catch (e) {
      // Mid-navigation: the target being asked has already been replaced.
      last = e;
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  log.debug("Leaving settleOn(). Timed out. fragment=" + fragment);
  throw new Error("The browser never came to rest on a page containing '" +
                  fragment + "'. Last: " +
                  (last ? last.message.split("\n")[0] : "(never checked)"));
}

// Clicks something that is EXPECTED to navigate, and returns once the browser
// has come to rest on a page whose URL contains `fragment`.
//
// The click is allowed to FAIL and the failure is deliberately swallowed. Both
// clicks here start a redirect chain, and chromedriver's wait for the page the
// click began is what the second hop tears down — so "cannot determine loading
// status" is reported for a click that did exactly what it was asked to do.
// The click is not the assertion; where the browser ends up is, and settleOn()
// makes it. Nothing is hidden by that: a click that did nothing, or one that
// landed on some other control, fails on settleOn()'s deadline — and the
// swallowed message is carried into that failure so an interception or a stale
// element still says so rather than being reported only as a page that never
// arrived.
async function clickAndSettle(driver, element, fragment, what) {
  log.debug("Entering clickAndSettle(). what=" + what);
  let clickError = null;
  try {
    await element.click();
  } catch (e) {
    clickError = e;
    log.info("Clicking " + what + " reported: " + e.message.split("\n")[0]);
  }
  try {
    const url = await settleOn(driver, fragment);
    log.debug("Leaving clickAndSettle(). what=" + what);
    return url;
  } catch (e) {
    log.debug("Leaving clickAndSettle(). Never settled. what=" + what);
    throw new Error("Clicking " + what + " did not land on '" + fragment +
                    "'. " + e.message +
                    (clickError ? " The click itself reported: " +
                     clickError.message.split("\n")[0] : ""));
  }
}

async function logout(driver) {
  log.debug("Entering logout().");
  log.info("Entering logout().");
  // Locate the logout controls, set the post-logout redirect URI and trigger
  // logout
  log.info("Find logout Button");
  logout_button = By.id("logout_btn");
  log.info("Find logout_post_redirect_uri.");
  logout_post_redirect_uri = By.id("logout_post_redirect_uri");
  log.info("Wait for logout_post_redirect_uri.");
  await driver.wait(until.elementLocated(logout_post_redirect_uri), waitTime);
  log.info("Wait for logout_post_redirect_uri to be visible.");
  await driver.findElement(logout_post_redirect_uri).clear();
  await driver.wait(until.elementIsVisible(driver.findElement(
                    logout_post_redirect_uri)), waitTime);
  log.info("Set post_redirect_uri for logout.");
  await driver.findElement(logout_post_redirect_uri)
                           .sendKeys(logout_post_redirect_uri_value);
  // Logout, then the link back to the debugger's front page. Both are chained
  // navigations and neither may be followed by a bare command — see
  // clickAndSettle() and settleOn() above.
  log.info("Click logout_btn.");
  await clickAndSettle(driver, await driver.findElement(logout_button),
                       "/logout.html", "the Logout button");

  log.info("Click link to return to the front page of the debugger.");
  returnToDebugLink = By.partialLinkText('Return to debugger');
  await driver.wait(until.elementLocated(returnToDebugLink), waitTime);
  const returnEl = await driver.findElement(returnToDebugLink);
  // Centre it first: the navbar in bottom.css is fixed to the foot of the
  // VIEWPORT and a WebDriver click scrolls its element to exactly that spot.
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", returnEl);
  await clickAndSettle(driver, returnEl, "oauth2_oidc_2.html",
                       "the Return to debugger link");
  log.info("Landed back on oauth2_oidc_2.html.");
  log.debug("Leaving logout().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if(headless) {
    // "=new", not bare --headless. This page fetches the discovery document
    // itself, from a Keycloak that is http://keycloak:8080 on the
    // containerized stack while the page is now https — and the OLD headless
    // implementation in the Chrome 121 this image pins IGNORES
    // --allow-running-insecure-content, so that XHR is blocked with
    // readyState 4 / status 0 and no console entry naming mixed content.
    // What the test then reports is a missing Populate button. See section 1
    // of browser_flags.js.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages (e.g. jwt_tools) under coverage.
  options.addArguments("--disable-dev-shm-usage");
  // Test-only: allow a deployed HTTPS debugger (e.g. https://test.idptools.com)
  // to make discovery/token XHRs to a plaintext http://localhost Keycloak,
  // which browsers otherwise block (mixed content / Private Network Access).
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  // THE STACK'S CERTIFICATE, AS AN EXACT KEY PIN. The client and the api serve
  // https (common/tls_listener.js), on a self-signed pair generated per run, so
  // without this Chrome stops on a certificate interstitial and every
  // assertion below reports a missing element on a page titled "Privacy
  // error". See browser_flags.js.
  browserFlags.addStsTrustFlags(options);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    log.info("Starting Test run.");
    // Read test configuration from environment variables
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    const username = process.env.USER;
    const password = client_id;
    const audience = process.env.AUDIENCE;
    log.info("Set environment variables.");

    // Verify all required environment variables are present
    assert(discovery_endpoint,
           "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(username, "USER environment variable is not set.");
    assert(audience, "AUDIENCE environment variable is not set.");
    log.info("Assertions completed successfully.");

    // Drive the full flow: load the app, populate IdP metadata, obtain and
    // verify a token, then log out
    log.info("Starting driver.get() run.");
    await driver.get(baseUrl + "/oauth2_oidc_1.html");
    log.info("Completed driver.get() run.");
    log.info("Starting populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Completed populateMetadata().");
    log.info("Retrieve access_token.");
    const access_token = await getAccessTokenPassword(driver, client_id,
        client_secret, scope, username, password);
    log.info("Found access_token=" + access_token);
    log.info("Calling verifyAccessToken().");
    await verifyAccessToken(access_token, client_id, scope, { user: username,
                            audience: "account", issuer: audience,
                            verifyTyp: true });
    log.info("Logging out.");
    await logout(driver);
    log.info("Test completed successfully.")
  } catch (error) {
    log.error(error.message);
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
  .name('oauth2_resource_owner_password_credentials_grant')
  .description("Run test.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
  )
  .action((options) => {
    // Apply CLI overrides for the base URL and headless/visible browser mode
    if(!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
      logout_post_redirect_uri_value = options.url + "/logout.html";
    }
    if(!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
