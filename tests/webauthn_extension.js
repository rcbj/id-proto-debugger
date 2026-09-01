// File: webauthn_extension.js
//
// ---------------------------------------------------------------------------
// The browser extension, loaded for real, observing a ceremony it does not own.
//
// This is the test the extension exists to make possible: a WebAuthn ceremony
// happens on the mock STS's login page — a third-party relying party as far as
// the debugger is concerned — and the artifacts arrive at the debugger's own
// origin without the debugger having been involved in the ceremony at all.
//
// It covers the two claims the extension makes:
//
//   CAPTURE       both halves reach the debugger, and the REQUEST half is the
//                 part no relying party ever shows anybody — challenge,
//                 userVerification, attestation, timeout, the algorithms asked
//                 for. Pasting a response can never produce it.
//
//   TRANSPARENCY  the same ceremony, run with the extension loaded and without
//                 it, produces the same result. This is what makes "read-only"
//                 a fact rather than an intention, and nobody at a store
//                 reviews an unpacked extension on our behalf, so it is the
//                 only thing standing behind that claim.
//
// It must NOT compare clientDataJSON byte for byte. Chrome inserts
// `other_keys_can_be_added_here` into some ceremonies and not others, at
// random, specifically to break implementations that compare it against a
// template — measured happening on 2026-08-08. The comparison is over the
// parsed fields.
//
// The extension loaded here is the CI build, which differs from the shipped one
// in exactly one way: a bundled autoarm.json naming the origin to observe,
// because a WebDriver session cannot click the browser's native permission
// dialog. That difference is asserted rather than trusted — a test-only bypass
// inside the arm path would mean exercising a code path users never run.
// ---------------------------------------------------------------------------

const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { VirtualAuthenticatorOptions, Transport, Protocol } =
  require("selenium-webdriver/lib/virtual_authenticator");
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const registry = require("./sts_applications.js");
const { waitForFocus } = require("./wait_for.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "webauthn_extension",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// The Analyzer's capture inbox is rebuilt from scratch on every refresh —
// window.onload starts one and the Refresh button starts another — so a button
// found in the old table is detached before it can be clicked. That is a
// StaleElementReferenceError the test can do nothing about except re-find, and
// it took out the run of 2026-08-25T20-23-22. clickStable() is the shared
// re-finding click; see common/tests.js.
const { clickStable } =
      require("../common/tests.js")({ By, until, waitTime, log, assert });

const STS = (process.env.OID4VCI_ISSUER_URL ||
             (process.env.WSTRUST_STS_URL ||
              "https://localhost:8081/sts").replace(/\/sts\/?$/, ""));
const CLIENT_ID = "webauthn-extension-test";
const REDIRECT = STS + "/oauth2/callback-sink";
const USER = "extuser-" + process.pid.toString(36) + "-" +
    Date.now().toString(36);

// The unpacked CI build. In a checkout it is extension/dist/ci; the tests image
// stages it beside the tests, because there is no extension/ tree in there.
const EXTENSION_DIR = [
  path.join(__dirname, "extension-ci"),
  path.join(__dirname, "..", "extension", "dist", "ci"),
].filter(function (p) { return fs.existsSync(path.join(p,
    "manifest.json")); })[0];

function authorizeUrl() {
  log.debug("Entering authorizeUrl().");
  log.debug("Leaving authorizeUrl().");
  return STS + "/oauth2/authorize?response_type=code&client_id=" +
      encodeURIComponent(CLIENT_ID) +
    "&redirect_uri=" + encodeURIComponent(REDIRECT) +
    "&scope=" + encodeURIComponent("openid profile email") +
    "&state=st4te&nonce=n0nce&acr_values=mfa";
}

function authenticatorOptions() {
  log.debug("Entering authenticatorOptions().");
  // NB: the JS bindings' setters return undefined and cannot be chained.
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

async function buildDriver(withExtension) {
  log.debug("Entering buildDriver().");
  const options = new chrome.Options();
  // **This test cannot run against branded Google Chrome.** That build refuses
  // the flags needed to side-load an unpacked extension — it says so on stderr,
  // "--disable-extensions-except is not allowed in Google Chrome, ignoring" —
  // and the extension is then simply absent, with no error anywhere and every
  // capture assertion timing out. Chrome for Testing (what the tests image
  // pins) and Chromium both allow it. CHROME_BIN/CHROMEDRIVER_BIN exist so a
  // developer on a branded Chrome can point at a Chrome-for-Testing download;
  // in the image they are unset and the pinned browser on PATH is already the
  // right one. Measured 2026-08-08.
  if (process.env.CHROME_BIN) {
    options.setChromeBinaryPath(process.env.CHROME_BIN);
  }
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, STS);
  if (withExtension) {
    // --load-extension, not addExtensions(): the latter wants a packed .crx,
    // and an unpacked directory is what this project ships and what a user
    // loads.
    options.addArguments("--load-extension=" + EXTENSION_DIR);
    // chromedriver passes --disable-extensions among its default switches,
    // which would silently cancel the line above.
    options.excludeSwitches("disable-extensions");
  }
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  let builder = new Builder().forBrowser("chrome")
    .setChromeOptions(options).setLoggingPrefs(prefs);
  if (process.env.CHROMEDRIVER_BIN) {
    builder = builder.setChromeService(new chrome.ServiceBuilder(
        process.env.CHROMEDRIVER_BIN));
  }
  log.debug("Leaving buildDriver().");
  return builder.build();
}

// Runs the STS's MFA sign-in to completion and returns what the ceremony
// produced, read from the authenticator data rather than from any page's report
// of it.
async function runCeremony(driver, username) {
  log.debug("Entering runCeremony().");
  await driver.get(authorizeUrl());
  await driver.wait(until.elementLocated(By.id("username")), waitTime * 4);
  await driver.findElement(By.id("username")).sendKeys(username);
  await driver.findElement(By.id("kc-login")).click();
  await driver.wait(until.elementLocated(By.id("wa-go")), waitTime * 4);
  // A headless window is neither focused nor visible for its first second or
  // so, and WebAuthn refuses on such a page with a bare NotAllowedError that
  // reads exactly like a declined prompt. See waitForFocus() in
  // tests/wait_for.js.
  await waitForFocus(driver, waitTime * 8);
  await driver.findElement(By.id("wa-go")).click();
  await driver.wait(until.urlContains("/oauth2/callback-sink"), waitTime * 8);
  const url = new URL(await driver.getCurrentUrl());
  log.debug("Leaving runCeremony().");
  return { code: url.searchParams.get("code") };
}

// Ask the extension, through the bridge, from the debugger's own origin. This
// is the contract: a namespaced postMessage handshake, because
// externally_connectable is Chrome-only and this has to work in Firefox too.
async function capturesFromBridge(driver) {
  log.debug("Entering capturesFromBridge().");
  log.debug("Leaving capturesFromBridge().");
  return driver.executeAsyncScript(
    "var done = arguments[arguments.length - 1];" +
    "var id = 'q' + Date.now();" +
    "var timer = setTimeout(function () { done({ timedOut: true }); }, 8000);" +
    "window.addEventListener('message', function handler(e) {" +
    "  if (!e.data || e.data.channel !== " +
        "'idptools-webauthn-response') return;" +
    "  if (e.data.id !== id) return;" +
    "  clearTimeout(timer); window.removeEventListener('message', handler);" +
    "  done(e.data.result || { empty: true });" +
    "});" +
    "window.postMessage({ channel: 'idptools-webauthn-request', id: id, " +
        "action: 'get' }," +
    "                   window.location.origin);");
}

// The sections after the first one all read the capture the first one waited
// for, and reading it off a bridge answer that carries none is a
// `Cannot read properties of undefined` naming a member of the capture — which
// is what three of the four failures in run 658 of the Selenium Tests workflow
// said, none of them naming the empty buffer they all shared. This says it
// once, in the one place that can.
function firstCapture(answer) {
  log.debug("Entering firstCapture().");
  assert.ok(answer, "the bridge did not answer at all.");
  assert.ok(!answer.timedOut,
      "the bridge did not answer within its own timeout, so the service " +
      "worker is asleep or gone rather than the buffer being empty.");
  assert.ok(answer.captures && answer.captures.length,
      "the bridge answered and holds NO captures" +
      (answer.armed ? ", though it is armed for " + answer.armed.origin +
        " — so the ceremony ran outside the observed origin, or before the " +
        "dynamic content scripts were registered."
        : ", and it is NOT ARMED — so nothing was observing anything."));
  log.debug("Leaving firstCapture().");
  return answer.captures[0];
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
  if (!EXTENSION_DIR) {
    log.error("No unpacked CI extension build found. Run `node " +
              "extension/build.js` (it writes " +
              "extension/dist/ci), or stage it beside the tests as " +
                  "extension-ci/. This job cannot " +
              "prove anything without the extension it is about.");
    process.exitCode = 1;
    log.debug("Leaving test().");
    return;
  }
  log.info("Loading the extension from " + EXTENSION_DIR);

  try {
    const probe = await fetch(STS + "/.well-known/openid-configuration");
    assert.ok(probe.ok, "the STS answered " + probe.status);
  } catch (e) {
    log.error("No mock STS at " + STS + " (" + e.message +
              "). This job needs one.");
    process.exitCode = 1;
    log.debug("Leaving test().");
    return;
  }

  // The relying party, in the mock's registry, before the extension is asked to
  // do anything with it. `acr_values=mfa` travels on the request rather than on
  // the entry, deliberately: what a client ASKS for at sign-in time is not a
  // property of its registration, and putting it on one here would suggest this
  // mock enforced an application-level authentication policy that it does not.
  await registry.provision(registry.baseOf(STS), {
    identifier: CLIENT_ID,
    name: "WebAuthn extension test",
    protocols: ["oauth2", "oidc"],
    fields: {
      oauthClientId: CLIENT_ID,
      oauthRedirectUri: [REDIRECT],
      oauthResponseType: ["code"],
      oauthGrantType: ["authorization_code"],
      oauthScope: ["openid", "profile", "email"],
      oauthTokenEndpointAuthMethod: "none",
      oauthConfidential: "FALSE"
    },
    why: "the client the extension performs the ceremony for"
  });

  await section("the CI build differs from the shipped build in " +
                "exactly one file", () => {
    // Two layouts: extension/dist/{ci,chrome} in a checkout, and extension-ci /
    // extension-chrome side by side in the tests image, which has no extension/
    // tree at all.
    const shipped = [
      path.join(EXTENSION_DIR, "..", "chrome"),
      path.join(__dirname, "extension-chrome"),
    ].filter(function (dir) { return fs.existsSync(path.join(dir,
        "manifest.json")); })[0];
    if (!shipped) {
      throw new Error("no shipped (chrome) build to compare the CI build " +
                      "against. It is staged " +
                      "beside the ci build precisely so this check can run — " +
                          "see tests/Dockerfile.");
    }
    const ciFiles = fs.readdirSync(EXTENSION_DIR).sort();
    const shippedFiles = fs.readdirSync(shipped).sort();
    const extra = ciFiles.filter((f) => shippedFiles.indexOf(f) < 0);
    assert.deepStrictEqual(extra, ["autoarm.json"],
      "the CI build should add autoarm.json and nothing else; it adds: " +
          extra.join(", "));
    // And every shared file must be byte-identical, or CI is exercising
    // different code from the one users load.
    shippedFiles.forEach(function (f) {
      if (f === "manifest.json") {
        return;
      }
      assert.ok(fs.readFileSync(path.join(EXTENSION_DIR, f)).equals(
                  fs.readFileSync(path.join(shipped, f))),
        f + " differs between the CI and shipped builds");
    });
    // The manifests may differ only by the auto-armed origin.
    const ciManifest = JSON.parse(fs.readFileSync(path.join(EXTENSION_DIR,
        "manifest.json"), "utf8"));
    const shippedManifest = JSON.parse(fs.readFileSync(path.join(shipped,
        "manifest.json"), "utf8"));
    const added = ciManifest.host_permissions.filter(
      (h) => shippedManifest.host_permissions.indexOf(h) < 0);
    assert.deepStrictEqual(ciManifest.permissions, shippedManifest.permissions,
      "the CI build must not hold extra API permissions");
    delete ciManifest.host_permissions;
    delete shippedManifest.host_permissions;
    assert.deepStrictEqual(ciManifest, shippedManifest,
      "the two manifests must be identical apart from host_permissions");
    return "adds autoarm.json and host permission for " + added.join(", ");
  });

  // --- capture ---------------------------------------------------------------
  let withExtension = null;
  const driver = await buildDriver(true);
  try {
    await driver.addVirtualAuthenticator(authenticatorOptions());

    await section("the extension is actually loaded and ARMED for the " +
                  "third-party origin", async () => {
      await driver.get(baseUrl + "/webauthn_analyzer.html");
      await driver.wait(until.elementLocated(By.id("wa_input")), waitTime * 4);
      const marker = await driver.executeScript(
        "return document.documentElement.getAttribute('data-idptools-webauthn-observer');");
      assert.ok(marker,
        "the bridge sets a presence attribute at document_start on the " +
            "debugger's origins, and it " +
        "is absent — so the extension did not load at all. Branded Google " +
            "Chrome refuses to " +
        "side-load an unpacked extension; use Chrome for Testing " +
            "(CHROME_BIN).");

      // AND THEN WAIT FOR THE ARM, WHICH IS A DIFFERENT FACT AND THE ONE THIS
      // TEST ACTUALLY DEPENDS ON.
      //
      // bridge.js is a STATIC content script declared in the manifest for the
      // debugger's own origins, so the attribute above appears the moment the
      // browser loads the extension. The scripts that observe somebody else's
      // ceremony — shim.js and relay.js — are DYNAMIC: background.js registers
      // them in arm(), which the CI build reaches from an async
      // chrome.runtime.onInstalled handler that reads autoarm.json. Those two
      // events are not ordered with respect to each other, and they are not
      // ordered with respect to this test either.
      //
      // So driving the ceremony straight after the marker is a race, and
      // losing it is unrecoverable: registerContentScripts() at runAt
      // document_start affects the NEXT navigation, so a ceremony that starts
      // first is simply never observed and there is nothing to retry. That is
      // what happened to run 658 of the Selenium Tests workflow — the ceremony
      // completed, the bridge answered, and it held an empty capture list, so
      // four sections failed and not one of them named the arm.
      //
      // The arm state is already published by the bridge's getCaptures reply
      // (background.js), so this waits on the extension's own answer rather
      // than on a sleep.
      let armed = null;
      await driver.wait(async function () {
        const answer = await capturesFromBridge(driver);
        armed = answer && answer.armed;
        return !!(armed && armed.origin &&
            STS.indexOf(String(armed.origin).replace(/\/+$/, "")) === 0);
      }, waitTime * 8,
          "the extension never armed for " + STS + ". The CI build arms " +
          "itself from autoarm.json in chrome.runtime.onInstalled; if that " +
          "file is absent, or names a different origin, nothing observes " +
          "the ceremony and every capture assertion below fails naming " +
          "something else.");
      return "version " + marker + ", armed for " + armed.origin;
    });

    await section("a ceremony on a third-party origin is captured", async () =>
                  {
      const result = await runCeremony(driver, USER);
      assert.ok(result.code, "the sign-in should have completed");

      // The captures live on the debugger's origin, reached through the bridge.
      await driver.get(baseUrl + "/webauthn_analyzer.html");
      await driver.wait(until.elementLocated(By.id("wa_input")), waitTime * 4);
      let answer = null;
      await driver.wait(async function () {
        answer = await capturesFromBridge(driver);
        return !!(answer && answer.captures && answer.captures.length);
      }, waitTime * 8,
          "no capture reached the debugger's origin through the bridge");

      const capture = answer.captures[0];
      assert.strictEqual(capture.v, 1, "the capture envelope version");
      assert.strictEqual(capture.ceremony, "create",
        "the first ceremony of a new user is an enrolment");
      assert.ok(capture.origin.indexOf(new URL(STS).host) >= 0,
        "the capture should name the origin it was taken on; got " +
            capture.origin);
      assert.ok(capture.response && capture.response.response.attestationObject,
        "the response half should carry the attestation object");
      assert.ok(answer.version,
          "the bridge should report the extension's version for drift checks");
      return "v" + capture.v + " " + capture.ceremony + " on " +
          capture.origin +
             ", extension " + answer.version;
    });

    await section("the REQUEST half is captured — the part no relying " +
                  "party shows", async () => {
      const answer = await capturesFromBridge(driver);
      const capture = firstCapture(answer);
      const pk = capture.request && capture.request.publicKey;
      assert.ok(pk,
          "the capture should carry the options the relying party passed in");
      assert.ok(pk.challenge && pk.challenge.__b64u,
        "including the challenge, as base64url: " +
            JSON.stringify(pk.challenge));
      assert.ok(Array.isArray(pk.pubKeyCredParams) &&
                pk.pubKeyCredParams.length,
        "and the algorithms it was willing to accept");
      assert.strictEqual(pk.attestation, "direct",
        "and the attestation conveyance it asked for; got " + pk.attestation);
      assert.ok(pk.authenticatorSelection,
        "and the authenticator it was willing to accept");
      return "challenge, " + pk.pubKeyCredParams.length +
          " algorithm(s), attestation=" +
             pk.attestation + ", timeout=" + pk.timeout;
    });

    await section("a decoded capture agrees with the ceremony it recorded",
                  async () => {
      const answer = await capturesFromBridge(driver);
      const capture = firstCapture(answer);
      // Feed it to the Analyzer the way a user would, and require the page to
      // decode it — the capture format and the paste format are the same shape
      // precisely so that this works.
      const field = await driver.findElement(By.id("wa_input"));
      await driver.executeScript("arguments[0].value = arguments[1];",
        field, JSON.stringify(capture.response, null, 2));
      await driver.findElement(By.id("wa_analyze_button")).click();
      await driver.wait(async function () {
        const t = await driver.findElement(By.id("wa_cose_body")).getText();
        return /jwk\.kty/.test(t);
      }, waitTime * 6, "the Analyzer did not decode the captured credential");
      const cose = await driver.findElement(By.id("wa_cose_body")).getText();
      assert.ok(/ES256|RS256/.test(cose),
                "the credential's algorithm should be named: " + cose.slice(0,
                80));
      return "the capture decodes on the Analyzer with no re-formatting";
    });

    await section("the Analyzer's capture inbox lists it and loads it with " +
                  "one click", async () => {
      await driver.get(baseUrl + "/webauthn_analyzer.html");
      await driver.wait(until.elementLocated(By.id("wa_ext_body")),
                        waitTime * 4);
      // The pane populates itself on load; Refresh is for after a new ceremony.
      await driver.findElement(By.id("wa_ext_refresh")).click();
      let listed = "";
      await driver.wait(async function () {
        listed = await driver.findElement(By.id("wa_ext_body")).getText();
        return /create/.test(listed);
      }, waitTime * 6, "the inbox never listed the capture; it holds: " +
          listed.slice(0, 200));

      const armedNote =
          await driver.findElement(By.id("wa_ext_status")).getText();
      assert.ok(/Observing/.test(armedNote),
        "the pane should say which origin is being observed and until when: " +
            armedNote);
      assert.ok(!/format v/.test(armedNote),
        "and it should not be reporting capture-format drift, since both " +
            "sides came from this " +
        "tree: " + armedNote);
      assert.ok(/Extension version /.test(armedNote),
        "the pane should state the extension's build, which is what somebody " +
            "reporting a problem " +
        "needs to quote: " + armedNote);

      // One click loads the WHOLE envelope, request half included, which is the
      // point of the inbox over pasting a response. Through clickStable(),
      // because the row carrying this button is re-created by every render of
      // the pane and one of those can land between finding it and clicking it.
      await clickStable(driver, By.css("input.wa-load-capture"),
                        "the inbox's Load button");
      let request = "";
      await driver.wait(async function () {
        request = await driver.findElement(By.id("wa_request_body")).getText();
        return /challenge/.test(request);
      }, waitTime * 6,
          "loading a capture did not populate the request pane; it holds: " +
                       request.slice(0, 200));
      const cose = await driver.findElement(By.id("wa_cose_body")).getText();
      assert.ok(/jwk\.kty/.test(cose),
                "and the credential should have decoded: " + cose.slice(0,
                120));
      return "listed, loaded, request and key both on screen";
    });

    await section("Done — stop observing disarms the extension from the page",
                  async () => {
      await driver.findElement(By.id("wa_ext_done")).click();
      let st = "";
      await driver.wait(async function () {
        st = await driver.findElement(By.id("wa_ext_status")).getText();
        return /stopped|observing nothing/i.test(st);
      }, waitTime * 6,
          "the page never confirmed the extension had stopped; status: " + st);
      // And the buffer really is gone, asked over the bridge rather than
      // believed.
      const after = await capturesFromBridge(driver);
      assert.ok(after && !after.armed,
        "the extension should no longer be armed after the page said " +
            "it stopped");
      assert.strictEqual((after.captures || []).length, 0,
        "and the capture buffer should have gone with it — a ceremony is " +
            "somebody's " +
        "authentication and keeping it past the window it was collected in " +
            "is not this " +
        "extension's business");
      return "disarmed, buffer empty";
    });

    withExtension = await ceremonyFingerprint(driver, USER + "-fp");
  } finally {
    await driver.quit();
  }

  // --- transparency
  // -----------------------------------------------------------
  const bare = await buildDriver(false);
  let withoutExtension = null;
  try {
    await bare.addVirtualAuthenticator(authenticatorOptions());
    withoutExtension = await ceremonyFingerprint(bare, USER + "-fp2");
  } finally {
    await bare.quit();
  }

  await section("the extension changes nothing about the ceremony", () => {
    assert.ok(withExtension && withoutExtension,
              "both fingerprints should have been taken");
    // NOT a byte comparison of clientDataJSON: Chrome adds a filler member to
    // some ceremonies at random, on purpose, to defeat exactly that.
    assert.deepStrictEqual(withExtension.flags, withoutExtension.flags,
      "the authenticator data flags must be identical");
    assert.strictEqual(withExtension.type, withoutExtension.type,
                       "clientData.type");
    assert.strictEqual(withExtension.origin, withoutExtension.origin,
                       "clientData.origin");
    assert.strictEqual(withExtension.crossOrigin, withoutExtension.crossOrigin,
                       "clientData.crossOrigin");
    assert.strictEqual(withExtension.alg, withoutExtension.alg,
                       "the credential algorithm");
    assert.strictEqual(withExtension.completed, true,
                       "the observed ceremony completed");
    assert.strictEqual(withoutExtension.completed, true,
                       "the unobserved ceremony completed");
    return "flags, type, origin, crossOrigin and algorithm all identical (bytes deliberately not compared)";
  });

  if (failures) {
    log.error(failures + " section(s) failed.");
    process.exitCode = 1;
    log.debug("Leaving test().");
    return;
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

// What the ceremony determined, read out of the artifacts themselves in the
// page that produced them, so the two runs are compared on the same terms.
async function ceremonyFingerprint(driver, username) {
  log.debug("Entering ceremonyFingerprint().");
  await driver.get(STS + "/oauth2/logout");
  await runCeremony(driver, username);
  // Re-run the enrolment's artifacts out of the STS is not possible (it keeps
  // only the key), so the fingerprint is taken from a fresh ceremony driven in
  // the page and read back with the browser's own APIs.
  await waitForFocus(driver, waitTime * 8);
  log.debug("Leaving ceremonyFingerprint().");
  return driver.executeAsyncScript(
    "var done = arguments[arguments.length - 1];" +
    "var b64u = function (b) { return btoa(String.fromCharCode.apply(null, " +
        "new Uint8Array(b)))" +
    "  .split('+').join('-').split('/').join('_').split('=').join(''); };" +
    "navigator.credentials.create({ publicKey: {" +
    "  rp: { name: 'fingerprint', id: location.hostname }," +
    "  user: { id: new TextEncoder().encode('fp'), name: 'fp', " +
        "displayName: 'fp' }," +
    "  challenge: new Uint8Array(32).fill(3)," +
    "  pubKeyCredParams: [{ type: 'public-key', alg: -7 }]," +
    "  authenticatorSelection: { userVerification: 'preferred' }," +
    "  attestation: 'direct', timeout: 20000 } })" +
    ".then(function (c) {" +
    "  var cd = JSON.parse(new " +
        "TextDecoder().decode(c.response.clientDataJSON));" +
    "  var ad = new Uint8Array(c.response.getAuthenticatorData());" +
    "  var f = ad[32];" +
    "  done({ completed: true, type: cd.type, origin: cd.origin, " +
        "crossOrigin: cd.crossOrigin," +
    "         alg: c.response.getPublicKeyAlgorithm ? " +
        "c.response.getPublicKeyAlgorithm() : null," +
    "         flags: { UP: !!(f & 1), UV: !!(f & 4), AT: !!(f & 64), ED: " +
        "!!(f & 128) } });" +
    "}).catch(function (e) { done({ completed: false, error: e.name + ': ' + " +
        "e.message }); });");
}

const program = new Command();
program
  .name("webauthn_extension")
  .description("The read-only extension observing a third party's ceremony, " +
      "and changing nothing.")
  .addOption(new Option("-u, --url <url>",
      "The debugger base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser."))
  .action((options) => {
    if (options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (options.browser) {
      headless = false;
    }
  });
program.parse(process.argv);

test();
