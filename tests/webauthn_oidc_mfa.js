// File: webauthn_oidc_mfa.js
//
// ---------------------------------------------------------------------------
// WebAuthn as the second factor of an OIDC Authorization Code sign-in, against
// the mock STS, driven by the WebDriver virtual authenticator.
//
// This is the join between the two protocols, and the reason the WebAuthn
// workflow was built against this service at all: a relying party asks for
// step-up with `acr_values`, the End-User completes a real WebAuthn ceremony,
// and the resulting ID token says so in `amr` and `acr`. Everything the
// debugger's existing OAuth2 / OIDC pages already decode then shows the whole
// chain — authorization request, hardware key, code, tokens — without a line of
// new OIDC code anywhere.
//
// **The negative is the point.** A service that stamped `amr: ["pwd","hwk"]` on
// every token would pass every positive check here, so the last section signs
// in WITHOUT the second factor and requires the tokens to say `["pwd"]` and
// `acr: "1"`. The claim has to be earned.
//
// No hardware: the virtual authenticator is a CTAP2 authenticator inside the
// browser. No Keycloak: the mock STS is the OP. It does need the STS, so the
// job is gated on WSTRUST_STS_URL the way every other STS-dependent job is.
//
// The redirect_uri deliberately points at a path the STS does not serve.
// Nothing needs to receive the code — this test reads it off the URL — and
// pointing at a port nothing is listening on behaves differently in a container
// than on a host, which is the sort of difference that costs a run to diagnose.
// ---------------------------------------------------------------------------

const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { VirtualAuthenticatorOptions, Transport, Protocol } =
  require("selenium-webdriver/lib/virtual_authenticator");
const assert = require("assert");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { usernameFor } = require("./random_username.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "webauthn_oidc_mfa",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl =
    "http://localhost:3000";   // unused by this test; accepted for uniformity
var headless = true;
var waitTime = appconfig.waitTime;

const STS = (process.env.OID4VCI_ISSUER_URL ||
             (process.env.WSTRUST_STS_URL ||
              "http://localhost:8081/sts").replace(/\/sts\/?$/, ""));
const CLIENT_ID = "webauthn-mfa-test";
// A username unique to this run. The STS remembers enrolled keys per username
// for the life of its process, while a virtual authenticator lives only as long
// as the browser session — so a second run against a still-running STS would be
// told to assert with a key this browser has never held, and the ceremony would
// fail with the browser's deliberately ambiguous NotAllowedError. CI starts the
// service fresh and would never show this, which is exactly why it is worth
// fixing rather than relying on: a test that passes only against a pristine
// service is one nobody can re-run while debugging it.
// Minted by tests/random_username.js rather than here, so that the reasoning
// above lives in one place and every test in the suite leaves the same kind of
// trail behind it. The prefixes still say which of the two identities a row in
// the STS's user table belongs to.
const MFA_USER = usernameFor("webauthn-mfa");
const PWD_USER = usernameFor("webauthn-pwdonly");
const REDIRECT = STS + "/oauth2/callback-sink";

function authorizeUrl(extra) {
  log.debug("Entering authorizeUrl().");
  log.debug("Leaving authorizeUrl().");
  return STS + "/oauth2/authorize?response_type=code&client_id=" +
      encodeURIComponent(CLIENT_ID) +
    "&redirect_uri=" + encodeURIComponent(REDIRECT) +
    "&scope=" + encodeURIComponent("openid profile email") +
    "&state=st4te&nonce=n0nce" + (extra || "");
}

// NB: the JS bindings' setters return undefined, unlike the Java ones, so these
// cannot be chained — and the failure is not "no authenticator" but a
// NotAllowedError blaming TLS certificates. Measured 2026-08-08.
function authenticatorOptions() {
  log.debug("Entering authenticatorOptions().");
  const vo = new VirtualAuthenticatorOptions();
  vo.setProtocol(Protocol.CTAP2);
  vo.setTransport(Transport.USB);
  vo.setHasResidentKey(true);
  vo.setIsUserConsenting(true);
  vo.setHasUserVerification(true);
  vo.setIsUserVerified(true);
  log.debug("Leaving authenticatorOptions().");
  return vo;
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const parts = String(jwt).split(".");
  assert.strictEqual(parts.length, 3, "expected a three-part JWS, got " +
                     parts.length + " part(s)");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

async function signIn(driver, username, url) {
  log.debug("Entering signIn().");
  await driver.get(url);
  await driver.wait(until.elementLocated(By.id("username")), waitTime * 4);
  await driver.findElement(By.id("username")).sendKeys(username);
  await driver.findElement(By.id("kc-login")).click();
  log.debug("Leaving signIn().");
}

// Wait for the code to appear in the address bar. The page it lands on is a 404
// from the STS, which is fine: this test is the relying party and reads the
// authorization response off the URL.
async function codeFromRedirect(driver) {
  log.debug("Entering codeFromRedirect().");
  await driver.wait(until.urlContains("/oauth2/callback-sink"), waitTime * 8);
  const url = new URL(await driver.getCurrentUrl());
  const code = url.searchParams.get("code");
  assert.ok(code, "the authorization response carried no code: " + url.search);
  log.debug("Leaving codeFromRedirect().");
  return code;
}

async function exchange(code) {
  log.debug("Entering exchange().");
  const res = await fetch(STS + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code: code,
      redirect_uri: REDIRECT, client_id: CLIENT_ID,
    }).toString(),
  });
  const body = await res.json();
  assert.ok(body.id_token, "the token response carried no id_token: " +
            JSON.stringify(body));
  log.debug("Leaving exchange().");
  return body;
}

let failures = 0;
async function section(name, fn) {
  log.debug("Entering section().");
  try {
    const detail = await fn();
    log.info("PASS  " + name + (detail ? " — " + detail : ""));
  } catch (e) {
    failures++;
    log.error("FAIL  " + name + " — " + (e && e.message ? e.message : e));
  }
  log.debug("Leaving section().");
}

async function test() {
  log.debug("Entering test().");
  // Gate rather than fail: this job needs the STS, and run-report skips it when
  // none is configured. Reaching here with nothing listening should say so in
  // those words rather than as a timeout on a login form.
  try {
    const probe = await fetch(STS + "/.well-known/openid-configuration");
    assert.ok(probe.ok, "the STS answered " + probe.status);
  } catch (e) {
    log.error("No mock STS at " + STS + " (" + e.message +
              "). This job needs one; " +
              "run-report gates it on WSTRUST_STS_URL.");
    process.exitCode = 1;
    log.debug("Leaving test().");
    return;
  }

  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage");
  // The ceremony happens on the STS's own origin, which in the containerized
  // stack is http://sts:8081 — not a secure context, where
  // navigator.credentials does not exist at all. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, STS);
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const driver = await new Builder().forBrowser("chrome")
    .setChromeOptions(options).setLoggingPrefs(prefs).build();

  try {
    await driver.addVirtualAuthenticator(authenticatorOptions());

    await section("acr_values=mfa forces the second factor and disables " +
                  "the opt-out", async () => {
      await driver.get(authorizeUrl("&acr_values=mfa"));
      await driver.wait(until.elementLocated(By.id("use_webauthn")),
                        waitTime * 4);
      const box = await driver.findElement(By.id("use_webauthn"));
      assert.ok(await box.isSelected(),
        "a relying party that asked for step-up should get the WebAuthn " +
            "step selected");
      assert.ok(!(await box.isEnabled()),
        "and it must not be possible to opt out of a step-up the relying " +
            "party demanded — " +
        "otherwise acr_values is advisory and the acr in the token " +
            "means nothing");
      return "checked and disabled";
    });

    await section("the first sign-in enrols a key and completes the flow",
                  async () => {
      await signIn(driver, MFA_USER, authorizeUrl("&acr_values=mfa"));
      await driver.wait(until.elementLocated(By.id("wa-go")), waitTime * 4);
      const heading = await driver.findElement(By.css("h1")).getText();
      assert.ok(/Enrol/i.test(heading),
        "with no key enrolled the step should register one; the " +
            "heading read: " + heading);
      await driver.findElement(By.id("wa-go")).click();
      const code = await codeFromRedirect(driver);
      return "code " + code.slice(0, 12) + "…";
    });

    await section("the ID token records BOTH factors", async () => {
      // Re-run the whole flow so this section owns its own code: an
      // authorization code is single-use, and sharing one between sections
      // would make the second failure a confusing invalid_grant.
      await driver.get(STS + "/oauth2/logout");
      await signIn(driver, MFA_USER, authorizeUrl("&acr_values=mfa"));
      await driver.wait(until.elementLocated(By.id("wa-go")), waitTime * 4);
      await driver.findElement(By.id("wa-go")).click();
      const tokens = await exchange(await codeFromRedirect(driver));
      const claims = claimsOf(tokens.id_token);
      assert.deepStrictEqual(claims.amr, ["pwd", "hwk"],
        "amr must name both factors; RFC 8176's hwk is proof of possession " +
            "of a hardware key, " +
        "which is what a WebAuthn assertion demonstrates. Got " +
            JSON.stringify(claims.amr));
      assert.strictEqual(claims.acr, "mfa",
                         "and the acr should be stepped up; got " + claims.acr);
      assert.ok(claims.auth_time, "auth_time should be present");
      return "amr=" + JSON.stringify(claims.amr) + " acr=" + claims.acr;
    });

    await section("a second sign-in asserts with the enrolled key rather " +
                  "than enrolling again",
      async () => {
        await driver.get(STS + "/oauth2/logout");
        await signIn(driver, MFA_USER, authorizeUrl("&acr_values=mfa"));
        await driver.wait(until.elementLocated(By.id("wa-go")), waitTime * 4);
        const heading = await driver.findElement(By.css("h1")).getText();
        assert.ok(/Use your security key/i.test(heading),
          "the key enrolled earlier should now be asserted with, not " +
              "replaced; heading: " + heading);
        await driver.findElement(By.id("wa-go")).click();
        const tokens = await exchange(await codeFromRedirect(driver));
        assert.deepStrictEqual(claimsOf(tokens.id_token).amr, ["pwd", "hwk"],
          "an assertion is as much a second factor as the enrolment was");
        return "asserted, amr unchanged";
      });

    await section("without the second factor the tokens say so", async () => {
      // The check that makes every one above mean something: a service that
      // stamped hwk on everything would have passed all of them.
      await driver.get(STS + "/oauth2/logout");
      await signIn(driver, PWD_USER, authorizeUrl(""));
      const tokens = await exchange(await codeFromRedirect(driver));
      const claims = claimsOf(tokens.id_token);
      assert.deepStrictEqual(claims.amr, ["pwd"],
        "a password-only sign-in must not claim a hardware key; got " +
            JSON.stringify(claims.amr));
      assert.strictEqual(claims.acr, "1",
        "and its acr must not be stepped up; got " + claims.acr);
      return "amr=[\"pwd\"] acr=1";
    });

    // Two 404s are this test's own doing, and they are filtered BY NAME rather
    // than by relaxing the check: the browser requests /favicon.ico unbidden on
    // every navigation, and the redirect sink is a path nothing serves ON
    // PURPOSE, because this test is the relying party and reads the code off
    // the URL. Anything else still fails — a filter broad enough to swallow a
    // real error would make this assertion decorative.
    const EXPECTED_404 = [/\/favicon\.ico\b/, /\/oauth2\/callback-sink\b/];
    const all = (await driver.manage().logs().get(logging.Type.BROWSER))
      .filter((e) => e.level.name === "SEVERE");
    const severe = all.filter((e) => !EXPECTED_404.some((p) =>
        p.test(e.message)));
    assert.strictEqual(severe.length, 0,
      "the ceremony pages logged browser errors:\n" + severe.map((e) =>
          e.message).join("\n"));
    log.info("PASS  no console errors across the ceremony pages (" +
             (all.length - severe.length) +
              " expected 404(s) filtered by name)");

    if (failures) {
      log.error(failures + " section(s) failed.");
      process.exitCode = 1;
      log.debug("Leaving test().");
      return;
    }
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    process.exitCode = 1;
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("webauthn_oidc_mfa")
  .description("WebAuthn as the second factor of an OIDC sign-in against the " +
      "mock STS.")
  .addOption(new Option("-u, --url <url>",
      "The debugger base URL; unused here."))
  .addOption(new Option("-b, --browser", "Display browser."))
  .action((options) => {
    if (options.url) {
      baseUrl = options.url;
    }
    if (options.browser) {
      headless = false;
    }
  });
program.parse(process.argv);

test();
