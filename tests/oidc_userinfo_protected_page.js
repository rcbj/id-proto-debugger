// File: oidc_userinfo_protected_page.js
//
// THE USERINFO PAGE READING A PROTECTED RESPONSE — OIDC Core section 5.3.2,
// in a real browser, against the mock.
//
// `sts_userinfo_protected.js` proves the SERVER produces every shape correctly
// and opens each one with the debugger's engines in node. This proves the
// PAGE does — which is a different claim and the one that was missing: a
// response the engines can open and the page cannot render is a page that
// shows an empty box, and nothing in node can see that.
//
// FOUR SHAPES, and they are the point of the file:
//
//   application/json     the claims as they are
//   a three-part JWT     a JWS — the signature must be verified against the
//                        OP's JWKS, or against the CLIENT SECRET for HS*
//   a five-part JWT      a JWE — decrypted with the client's private key
//   five parts with a    a Nested JWT: decrypt, then verify
//   JWS inside
//
// AND THE DISTINCTIONS THE REPORT HAS TO DRAW, which are what make the pane
// worth having rather than a boolean:
//
//   * an encrypted-only response says so — encryption is not authentication,
//     and "decrypted" must never be presented as "verified";
//   * a JWS nested inside a JWE whose outer header omits `cty` is reported as
//     a FINDING, because a recipient that trusted the header would hand a
//     dot-separated string to a claims parser;
//   * `iss`, `aud` and `sub` are checked by name — section 5.3.2 requires a
//     client to verify the sub against the ID Token's, and an unchecked one is
//     how a mixed-up token goes unnoticed.
//
// A REPRESENTATIVE ALGORITHM PER FAMILY rather than all twenty-five. The page
// does not implement any of them — `jws.js` and `jose_jwe.js` do, and every
// algorithm is driven against those in `sts_userinfo_protected.js` and
// `jose_jwe_encryption.js`. What is browser-specific is the wiring and the
// report, and that is the same code whichever algorithm produced the bytes.
// One family member each keeps this job seconds rather than minutes —
// SLH-DSA-SHAKE-128s alone costs twelve seconds to sign.

const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "oidc_userinfo_protected_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var stsUrl = process.env.WSTRUST_STS_URL || "";
var stsBase = process.env.OID4VCI_ISSUER_URL ||
    stsUrl.replace(/\/sts\/?$/, "");

// One RSA and one EC key pair standing in for the RELYING PARTY's: the public
// halves are registered so the mock encrypts to them, the private halves are
// pasted into the page's Decryption Key field.
var rpRsa = null;
var rpEc = null;

function rpKeys() {
  log.debug("Entering rpKeys().");
  if (!rpRsa) {
    rpRsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    rpEc = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  }
  log.debug("Leaving rpKeys().");
  return {
    jwks: { keys: [
      Object.assign(rpRsa.publicKey.export({ format: "jwk" }),
                    { kid: "rp-rsa", use: "enc" }),
      Object.assign(rpEc.publicKey.export({ format: "jwk" }),
                    { kid: "rp-ec", use: "enc" })
    ] },
    rsaPem: rpRsa.privateKey.export({ type: "pkcs8", format: "pem" }),
    ecPem: rpEc.privateKey.export({ type: "pkcs8", format: "pem" })
  };
}

async function registerClient(metadata) {
  log.debug("Entering registerClient().");
  var response = await fetch(stsBase + "/oauth2/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign(
      { redirect_uris: [baseUrl + "/callback"] }, metadata))
  });
  assert.strictEqual(response.status, 201,
    "the client registration should have been accepted.");
  log.debug("Leaving registerClient().");
  return response.json();
}

async function tokensFor(client) {
  log.debug("Entering tokensFor().");
  var response = await fetch(stsBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password", username: "alice", password: "any",
      scope: "openid profile email",
      client_id: client.client_id,
      client_secret: client.client_secret }).toString() });
  assert.strictEqual(response.status, 200, "a token should have been issued.");
  log.debug("Leaving tokensFor().");
  return response.json();
}

async function userinfoResponse(accessToken) {
  log.debug("Entering userinfoResponse().");
  var response = await fetch(stsBase + "/oauth2/userinfo",
    { headers: { Authorization: "Bearer " + accessToken } });
  var body = await response.text();
  assert.strictEqual(response.status, 200,
    "UserInfo should have answered 200; got " + response.status + ": " +
    body.slice(0, 200));
  log.debug("Leaving userinfoResponse().");
  return { body: body,
           contentType: response.headers.get("content-type") || "" };
}

// Hand the page a response and read back what it made of it. The reading path
// is driven directly because the page takes its endpoint and access token from
// localStorage at LOAD — the OAuth2/OIDC workflow's hand-off — so a click
// would be testing that hand-off rather than the reader.
async function readInPage(driver, raw, contentType, fields) {
  log.debug("Entering readInPage().");
  var result = await driver.executeAsyncScript(
    "var done = arguments[arguments.length - 1];" +
    "var f = arguments[2];" +
    "localStorage.setItem('token_id_token', f.idToken || '');" +
    "document.getElementById('userinfo_jwks_source').value = 'jwks_url';" +
    "document.getElementById('userinfo_jwks').value = f.jwks || '';" +
    "document.getElementById('userinfo_client_secret').value = f.secret || '';" +
    "document.getElementById('userinfo_decryption_key').value = f.key || '';" +
    "document.getElementById('userinfo_expected_issuer').value = f.iss || '';" +
    "document.getElementById('userinfo_expected_audience').value = " +
        "f.aud || '';" +
    "document.getElementById('userinfo_output').value = '';" +
    "document.getElementById('userinfo_protection_report').value = '';" +
    "Promise.resolve(userinfo.openUserinfoResponse(arguments[0], arguments[1]))" +
    "  .then(function () {" +
    "    done({ report: document.getElementById(" +
        "'userinfo_protection_report').value," +
    "           output: document.getElementById('userinfo_output').value });" +
    "  }, function (e) { done({ error: e.message }); });",
    raw, contentType, fields);
  assert.ok(!result.error,
    "the page threw while reading the response: " + result.error);
  log.debug("Leaving readInPage().");
  return result;
}

function claimsOf(result, what) {
  log.debug("Entering claimsOf().");
  assert.ok(result.output,
    what + ": the page produced no claims at all. The report said:\n" +
    result.report);
  var claims;
  try {
    claims = JSON.parse(result.output);
  } catch (e) {
    throw new Error(what + ": the claims pane does not hold JSON: " +
      result.output.slice(0, 200));
  }
  assert.ok(claims.sub, what + ": the claims should carry a sub.");
  log.debug("Leaving claimsOf().");
  return claims;
}

// A report line beginning "  ** " is a finding; the page marks nothing else
// that way, which is what lets this assert on the absence of one.
function assertNoFindings(result, what) {
  log.debug("Entering assertNoFindings().");
  assert.ok(result.report.indexOf("**") === -1,
    what + ": the page reported a finding it should not have:\n" +
    result.report);
  log.debug("Leaving assertNoFindings().");
}

async function eachShapeIsReadAndReported(driver) {
  log.debug("Entering eachShapeIsReadAndReported().");
  var keys = rpKeys();
  var jwksUrl = stsBase + "/oauth2/jwks";

  // --- 1. plain JSON -------------------------------------------------------
  var plainClient = await registerClient({});
  var plainTokens = await tokensFor(plainClient);
  var plain = await userinfoResponse(plainTokens.access_token);
  var plainResult = await readInPage(driver, plain.body, plain.contentType,
    { jwks: jwksUrl, iss: stsBase, aud: plainClient.client_id,
      idToken: plainTokens.id_token });
  claimsOf(plainResult, "plain JSON");
  assertNoFindings(plainResult, "plain JSON");
  assert.ok(/protection.*none/i.test(plainResult.report),
    "an unprotected response should SAY it is unprotected rather than " +
    "leaving the reader to infer it:\n" + plainResult.report);

  // --- 2. signed, one algorithm per family ---------------------------------
  var families = ["RS256", "PS384", "ES256", "ES256K", "EdDSA", "HS512",
                  "ML-DSA-44", "ML-DSA-44-Ed25519"];
  var metadata = await (await fetch(stsBase +
      "/.well-known/openid-configuration")).json();
  var advertised = metadata.userinfo_signing_alg_values_supported || [];
  for (var i = 0; i < families.length; i++) {
    var alg = families[i];
    assert.ok(advertised.indexOf(alg) !== -1,
      alg + " is no longer advertised by the OP, so this test is driving an " +
      "algorithm that has gone away. Update the family list.");
    var client = await registerClient({ userinfo_signed_response_alg: alg });
    var tokens = await tokensFor(client);
    var signed = await userinfoResponse(tokens.access_token);
    var result = await readInPage(driver, signed.body, signed.contentType,
      { jwks: jwksUrl, secret: client.client_secret, iss: stsBase,
        aud: client.client_id, idToken: tokens.id_token });
    claimsOf(result, alg);
    assertNoFindings(result, alg);
    assert.ok(/signature.*verified/i.test(result.report),
      alg + ": the report must say the signature verified:\n" + result.report);
    assert.ok(/OK iss/.test(result.report) && /OK aud/.test(result.report),
      alg + ": section 5.3.2's iss and aud checks must both pass and be " +
      "shown:\n" + result.report);
    assert.ok(/OK sub/.test(result.report),
      alg + ": the sub must be checked against the ID Token's.");
  }

  // --- 3. encrypted only ---------------------------------------------------
  var encClient = await registerClient({
    userinfo_encrypted_response_alg: "RSA-OAEP-256", jwks: keys.jwks });
  var encTokens = await tokensFor(encClient);
  var encrypted = await userinfoResponse(encTokens.access_token);
  var encResult = await readInPage(driver, encrypted.body,
    encrypted.contentType,
    { jwks: jwksUrl, key: keys.rsaPem, iss: stsBase,
      aud: encClient.client_id, idToken: encTokens.id_token });
  claimsOf(encResult, "encrypted");
  assert.ok(/decrypted/i.test(encResult.report),
    "the report must say it decrypted:\n" + encResult.report);
  // THE DISTINCTION THIS FILE EXISTS FOR. An encrypted-only response proves
  // who it was encrypted TO and nothing about who wrote it, and a report that
  // let a reader take "decrypted" for "verified" would be the worst thing
  // this pane could do.
  assert.ok(/not signed|nothing here proves who issued/i.test(encResult.report),
    "an encrypted-but-unsigned response must say that nothing proves who " +
    "issued it:\n" + encResult.report);
  assert.ok(!/signature.*verified/i.test(encResult.report),
    "an unsigned response must NEVER be reported as having a verified " +
    "signature:\n" + encResult.report);

  // --- 4. signed then encrypted (a Nested JWT) -----------------------------
  var nestedClient = await registerClient({
    userinfo_signed_response_alg: "ES256",
    userinfo_encrypted_response_alg: "ECDH-ES+A256KW",
    userinfo_encrypted_response_enc: "A192CBC-HS384",
    jwks: keys.jwks });
  var nestedTokens = await tokensFor(nestedClient);
  var nested = await userinfoResponse(nestedTokens.access_token);
  var nestedResult = await readInPage(driver, nested.body, nested.contentType,
    { jwks: jwksUrl, key: keys.ecPem, iss: stsBase,
      aud: nestedClient.client_id, idToken: nestedTokens.id_token });
  claimsOf(nestedResult, "nested");
  assertNoFindings(nestedResult, "nested");
  assert.ok(/decrypted/i.test(nestedResult.report) &&
            /signature.*verified/i.test(nestedResult.report),
    "a nested response must report BOTH the decryption and the signature:\n" +
    nestedResult.report);
  assert.ok(/cty=JWT/.test(nestedResult.report),
    "the outer header's cty must be shown, since it is what announces the " +
    "JWS inside:\n" + nestedResult.report);

  log.info("[shapes] OK — plain JSON, " + families.length +
           " signed algorithm(s), encrypted, and signed-then-encrypted all " +
           "read, with iss/aud/sub checked and 'decrypted' never presented " +
           "as 'verified'.");
  log.debug("Leaving eachShapeIsReadAndReported().");
}

// ---------------------------------------------------------------------------
// The negatives. A reader that cannot say WHY it failed is worth little, so
// each of these asserts the reason as well as the refusal.
// ---------------------------------------------------------------------------
async function badInputIsRefusedByName(driver) {
  log.debug("Entering badInputIsRefusedByName().");
  var keys = rpKeys();
  var jwksUrl = stsBase + "/oauth2/jwks";

  // An encrypted response with no key: the page must say so rather than
  // showing an empty claims box.
  var client = await registerClient({
    userinfo_encrypted_response_alg: "RSA-OAEP-256", jwks: keys.jwks });
  var tokens = await tokensFor(client);
  var encrypted = await userinfoResponse(tokens.access_token);
  var noKey = await readInPage(driver, encrypted.body, encrypted.contentType,
    { jwks: jwksUrl, iss: stsBase, aud: client.client_id });
  assert.ok(/no decryption key|decryption key was given/i.test(noKey.report),
    "an encrypted response with no key must say a key is needed:\n" +
    noKey.report);

  // A signed response checked against the WRONG audience — the member that
  // stops a signed profile issued for one client being believed by another.
  var signedClient = await registerClient({
    userinfo_signed_response_alg: "RS256" });
  var signedTokens = await tokensFor(signedClient);
  var signed = await userinfoResponse(signedTokens.access_token);
  var wrongAud = await readInPage(driver, signed.body, signed.contentType,
    { jwks: jwksUrl, iss: stsBase, aud: "some-other-client" });
  assert.ok(/\*\*/.test(wrongAud.report) && /aud/.test(wrongAud.report),
    "a response whose aud does not name this client must be reported as a " +
    "finding:\n" + wrongAud.report);

  // And a tampered signature must not verify.
  var parts = signed.body.trim().split(".");
  var tampered = parts[0] + "." +
    Buffer.from(JSON.stringify({ sub: "mallory" })).toString("base64url") +
    "." + parts[2];
  var mauled = await readInPage(driver, tampered, "application/jwt",
    { jwks: jwksUrl, iss: stsBase, aud: signedClient.client_id });
  assert.ok(/\*\*/.test(mauled.report),
    "an edited payload must be reported as a finding rather than shown as " +
    "claims:\n" + mauled.report);
  assert.ok(!/"sub": *"mallory"/.test(mauled.output || ""),
    "the page must NOT display the claims of a response whose signature does " +
    "not verify.");

  log.info("[negatives] OK — a missing decryption key, a wrong audience and " +
           "an edited payload are each reported by name.");
  log.debug("Leaving badInputIsRefusedByName().");
}

async function test() {
  log.debug("Entering test().");
  if (!stsBase) {
    log.info("No STS URL — skipping.");
    log.info("Test completed successfully.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("Starting Test run. url=" + baseUrl + ", sts=" + stsBase);
  var prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  var options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
                       "--disable-dev-shm-usage");
  // THE PAGE FETCHES THE OP'S JWKS ITSELF, so this driver needs the mock's
  // certificate — and that is the whole reason this call is here rather than
  // the `browserFlags.chromeOptions()` that used to be attempted above it.
  // There is no such export: the expression was always `undefined`, the
  // fallback always ran, and the browser therefore started with no SPKI pin
  // for a certificate the mock REGENERATES on every start. Step 1 of this test
  // reads a plain JSON body and needs no key, so it passed; the first signed
  // response sent the page to https://localhost:8081/oauth2/jwks and Chrome
  // refused it. What the page reports for that is `could not be read: Failed
  // to fetch` — a message that names neither TLS nor a certificate, on a test
  // whose subject is a signature.
  //
  // addBrowserAccessFlags() is what every other browser job here calls, and it
  // carries three more things this page needs for the same reason: loopback
  // access, the insecure origin the page itself is served from (no
  // `crypto.subtle` without it), and the api's origin.
  browserFlags.addBrowserAccessFlags(options, baseUrl, [stsBase]);
  // AND Ed25519 in Web Crypto, because one of the algorithms this page is
  // handed is EdDSA. The containerized Chrome refuses `Ed25519` to importKey
  // without the flag, and what the page reports for that is
  //
  //   ** signature: Failed to execute 'importKey' on 'SubtleCrypto':
  //          Algorithm: Unrecognized name
  //
  // followed by "the page produced no claims at all" — a message naming
  // importKey and claims, on a test whose subject is a signed UserInfo
  // response, with nothing anywhere naming the curve or the flag. It cost the
  // containerized run of 2026-08-29, and a HOST run passes without it because
  // a desktop Chrome ships the curve enabled. See addWebCryptoEd25519Flags().
  browserFlags.addWebCryptoEd25519Flags(options);
  options.setLoggingPrefs(prefs);
  var driver = await new Builder().forBrowser("chrome")
    .setChromeOptions(options).build();
  try {
    await driver.get(baseUrl + "/userinfo.html");
    await driver.wait(until.elementLocated(By.id("userinfo_output")), 20000);
    await eachShapeIsReadAndReported(driver);

    // THE CONSOLE IS JUDGED HERE AND NOT AT THE END, and the order is the
    // point: everything above is a response the page is EXPECTED to read, so
    // anything it logged as an error is a defect. The negatives below hand it
    // a missing key, a wrong audience and an edited payload on purpose, and
    // the page reports each of those through its own `log.error` — reading the
    // console after them would be asserting that a deliberate failure is
    // silent, which is the opposite of what this page should do.
    //
    // `isTransientLoadError` drops the two configuration-change codes Chrome
    // emits on its own; without it this job carries the flake that cost the
    // remote run of 2026-08-28, and jwk_pem_encoding.js fails any test here
    // that judges the console without the filter.
    var entries = await driver.manage().logs().get(logging.Type.BROWSER);
    var severe = entries.filter(function (entry) {
      return entry.level.name === "SEVERE" &&
        !browserFlags.isTransientLoadError(entry.message);
    });
    assert.strictEqual(severe.length, 0,
      "the browser console must be clean while reading responses the page is " +
      "expected to read; got " + severe.length + ": " +
      severe.map(function (e) { return e.message; }).join(" | ")
        .slice(0, 400));
    log.info("[console] OK — no SEVERE entries on the paths that should " +
             "succeed.");

    await badInputIsRefusedByName(driver);
  } finally {
    await driver.quit();
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("oidc_userinfo_protected_page")
  .description("The UserInfo page reads a signed, encrypted or nested " +
      "response and reports each step by name.")
  .addOption(new Option("-u, --url <url>", "base url of the client"))
  .parse(process.argv);
if (program.opts().url) {
  baseUrl = program.opts().url;
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
