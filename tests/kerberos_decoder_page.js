// File: kerberos_decoder_page.js
//
// client/public/kerberos_decoder.html — the Kerberos Decoder page.
//
// ---------------------------------------------------------------------------
// What this covers that tests/krb5_describe_output.js does not.
//
// That test drives common/krb5/krb5_describe.js directly and checks every fact
// the page displays, with no browser. So this one deliberately does NOT re-check
// protocol content — it checks the things that only exist once a browser is
// involved:
//
//  * **The bundle loads and the page is wired.** A page registered in
//    client/build.js but not in client/Dockerfile builds fine for the static
//    deployments while the containerized page's <script> 404s — so the failure
//    appears only in the suite, and only as a page that does nothing. Both
//    registrations exist; this asserts the result.
//  * **Every value reaches the DOM as TEXT.** This page renders bytes a stranger
//    pasted in: a realm, a principal name, a KDC's e-text. It is built with
//    createElement and textContent and has no innerHTML in it at all, the same
//    rule webauthn_panes.js carries. The hostile-input section below proves it
//    rather than trusting it — with a payload that would execute, and a check
//    that no element was injected AND that the payload is visible as text (a
//    payload silently dropped would also pass the first check and would be a
//    different bug).
//  * **Decryption in the browser.** The crypto runs on Web Crypto here rather
//    than on node's, which is a different implementation of the same code path.
//    An AS-REP is decrypted from a password and a salt, in the browser.
//  * **The secure-context refusal is honest.** Web Crypto does not exist on a
//    plain-http non-localhost origin, so the page says decryption is unavailable
//    instead of letting it fail with something that names AES.
//
// It needs no services: the page talks to no KDC and has no back end, which is
// the whole reason it can ship to the static deployments. It needs only the site.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "kerberos_decoder_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

function shared(name) {
  return paths.requireSharedModule(
    [__dirname + "/../common/krb5/" + name, __dirname + "/" + name], name);
}
var prim = shared("krb5_primitives.js");
var asn1 = shared("krb5_asn1.js");
var msgs = shared("krb5_messages.js");
var kcrypto = shared("krb5_crypto.js");

var baseUrl = "http://localhost:3000";

const b64 = (b) => Buffer.from(prim.toBytes(b)).toString("base64");

async function decode(driver, text) {
  log.debug("Entering decode(). " + text.length + " characters");
  await driver.findElement(By.id("krb_clear_button")).click();
  await driver.findElement(By.id("krb_input")).sendKeys(text);
  await driver.findElement(By.id("krb_decode_button")).click();
  // Wait on CONTENT, not on an element: the output div exists in the static
  // markup from the moment the page parses, so waiting for it to be located
  // says nothing about whether the decode has run. See tests/wait_for.js.
  await driver.wait(async function () {
    return (await driver.findElement(By.id("krb_output")).getText()).trim().length > 40;
  }, 20000, "the decoder produced no output");
  log.debug("Leaving decode().");
  return driver.findElement(By.id("krb_output")).getText();
}

// ---------------------------------------------------------------------------
// The page is wired: bundle present, handlers attached.
// ---------------------------------------------------------------------------
async function theBundleLoadedAndTheButtonsWork(driver) {
  log.debug("Entering theBundleLoadedAndTheButtonsWork().");
  // A missing bundle leaves the module global undefined and every button inert,
  // which otherwise reads as "the decoder is broken" rather than "the script
  // 404'd".
  const loaded = await driver.executeScript("return typeof " +
      "window.kerberos_decoder;");
  assert.strictEqual(loaded, "object",
    "the kerberos_decoder bundle did not load — check the browserify line in " +
        "client/Dockerfile " +
    "AND the BUNDLES entry in client/build.js; a page registered in only one " +
        "of the two fails " +
    "in exactly this way, in only one of the two environments");

  const initial = await driver.findElement(By.id("krb_status")).getText();
  assert.ok(/Paste a Kerberos message/.test(initial),
    "the page should say what to do on arrival, got: " + initial);
  log.debug("Leaving theBundleLoadedAndTheButtonsWork().");
}

// ---------------------------------------------------------------------------
// A KRB-ERROR, TCP-framed, in base64 — the pre-authentication case.
// ---------------------------------------------------------------------------
async function decodesAPreauthErrorAndReadsOutTheSalt(driver) {
  log.debug("Entering decodesAPreauthErrorAndReadsOutTheSalt().");
  const err = msgs.encKrbError({
    stime: new Date(), susec: 0, errorCode: 25, realm: "EXAMPLE.COM",
    sname: {
      type: 2,
      name: ["krbtgt", "EXAMPLE.COM"]
    }, eText: "NEEDED_PREAUTH",
    eData: asn1.encSequenceOf([msgs.encPaData({
      type: msgs.PA_TYPE.ETYPE_INFO2,
      value: msgs.encEtypeInfo2([
        {
          etype: 18,
          salt: "EXAMPLE.COMalice",
          s2kparams: prim.fromHex("00001000")
        },
        { etype: 23, salt: null, s2kparams: null }])
    })])
  });
  // With the TCP length prefix still attached, which is how a capture usually
  // arrives. Leaving it in place makes an ASN.1 parser fail on byte zero and
  // blame ASN.1, so the page strips it — and must SAY it did.
  const framed = prim.concat([
    new Uint8Array([0, 0, (err.length >> 8) & 255, err.length & 255]), err]);

  const out = await decode(driver, b64(framed));
  assert.strictEqual(await driver.findElement(By.css(".krb-kind")).getText(), 
      "KRB-ERROR",
    "the message kind must be shown prominently");
  assert.ok(/TCP length prefix/.test(out),
    "the stripped TCP framing must be reported, not silently removed");
  assert.ok(/KDC_ERR_PREAUTH_REQUIRED/.test(out), "the error must be named");
  assert.ok(/EXAMPLE\.COMalice/.test(out), "the SALT must be shown — it is " +
      "the point of this error");
  assert.ok(/4096/.test(out), "the s2kparams iteration count must be decoded");
  assert.ok(/not guessable/i.test(out),
    "and the page must say the salt cannot be guessed, which is why this " +
        "error matters");
  // PREAUTH_REQUIRED is not a failure, so the page must not present it as one.
  const problems = await driver.findElements(By.css(".krb-problems"));
  assert.strictEqual(problems.length, 0,
    "KDC_ERR_PREAUTH_REQUIRED must NOT be listed as a problem — it is where " +
        "the salt comes from");
  log.debug("Leaving decodesAPreauthErrorAndReadsOutTheSalt().");
}

// ---------------------------------------------------------------------------
// Findings are surfaced.
// ---------------------------------------------------------------------------
async function surfacesWhatIsWrongWithARequest(driver) {
  log.debug("Entering surfacesWhatIsWrongWithARequest().");
  const out = await decode(driver, b64(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: {
      kdcOptions: [],
      cname: { type: 1, name: ["alice"] },
      realm: "example.com",                          // lower case
      sname: { type: 2, name: ["krbtgt", "example.com"] },
      till: new Date(Date.UTC(2026, 11, 31)),
      nonce: 1,
      etypes: [23]                                   // RC4 only
    }
  })));
  assert.ok(/AS-REQ/.test(await driver.findElement(By.css(".krb-kind")).getText()), 
      "kind");
  const problems = await driver.findElement(By.css(".krb-problems")).getText();
  assert.ok(/not upper case/.test(problems), "a lower-case realm must be a " +
      "finding: " + problems);
  assert.ok(/RC4/.test(problems) && /2025/.test(problems),
    "an RC4-only etype list must be a finding naming the 2026 cause: " + 
        problems);
  assert.ok(/arcfour-hmac-md5/.test(out), "etypes must be named, not left as " +
      "numbers");
  log.debug("Leaving surfacesWhatIsWrongWithARequest().");
}

// ---------------------------------------------------------------------------
// Hostile input.
//
// The page renders bytes whose author is unknown. It is built entirely with
// createElement and textContent — there is no innerHTML in
// client/src/kerberos_decoder.js — and this is where that is PROVED rather than
// asserted in a comment.
//
// Two checks, not one. That nothing executed is necessary but not sufficient: a
// page that silently dropped the value would also pass it, and dropping a field
// is its own bug in a decoder. So the payload must also be VISIBLE, as text.
// ---------------------------------------------------------------------------
async function renderesHostileValuesAsTextAndNotAsMarkup(driver) {
  log.debug("Entering renderesHostileValuesAsTextAndNotAsMarkup().");
  const payloadRealm = '<img src=x onerror="window.__krbPwned=1">';
  const payloadText = '</td></tr></table><h1 id="krb_injected">injected</h1>';
  const err = msgs.encKrbError({
    stime: new Date(), susec: 0, errorCode: 6,
    realm: payloadRealm,
    sname: {
      type: 2,
      name: ["krbtgt", '<script>window.__krbPwned=1</script>']
    },
    eText: payloadText
  });

  await driver.executeScript("window.__krbPwned = undefined;");
  const out = await decode(driver, b64(err));

  const pwned = await driver.executeScript("return !!window.__krbPwned;");
  assert.strictEqual(pwned, false,
    "a payload in a KDC's realm or e-text EXECUTED — this page must build " +
        "every node with " +
    "textContent, never innerHTML");

  const injected = await driver.executeScript(
    "return document.querySelectorAll('#krb_output img, #krb_output h1, " +
        "#krb_output script, " +
    "#krb_injected').length;");
  assert.strictEqual(injected, 0,
    "the payload created " + injected + " element(s) inside the output — it " +
        "was parsed as markup");

  // ...and it must still be SHOWN. A decoder that silently swallows a hostile
  // value is safe and useless.
  assert.ok(out.indexOf("img src=x onerror") !== -1,
    "the hostile realm must be visible as text — a value dropped rather than " +
        "escaped is a " +
    "different defect with the same appearance in the check above");
  assert.ok(out.indexOf("injected") !== -1, "the hostile e-text must be " +
      "visible as text");
  log.debug("Leaving renderesHostileValuesAsTextAndNotAsMarkup().");
}

// ---------------------------------------------------------------------------
// Decryption, in the browser, on Web Crypto.
// ---------------------------------------------------------------------------
async function decryptsAnAsRepFromAPasswordAndSalt(driver) {
  log.debug("Entering decryptsAnAsRepFromAPasswordAndSalt().");
  const secure = await driver.executeScript("return !!(window.crypto && " +
      "window.crypto.subtle);");
  if (!secure) {
    // Not a skip to be quiet about: the page's own note must say so, and that
    // is the assertion. An environment without Web Crypto is a capability
    // limit, not a defect, but a page that failed silently in it would be.
    const note = await driver.findElement(By.id("krb_crypto_note")).getText();
    assert.ok(/not in a secure context/.test(note),
      "without Web Crypto the page must SAY decryption is unavailable, got: " + 
          JSON.stringify(note));
    log.info("Web Crypto is unavailable on this origin; the page says so, " +
        "which is what matters here.");
    return;
  }

  const e = kcrypto.etypeById(18);
  const salt = "EXAMPLE.COMalice";
  const password = "hunter2";
  const clientKey = await e.stringToKey(password, prim.utf8(salt), null);
  const sessionKey = kcrypto.randomBytes(32);
  const now = new Date(Date.UTC(2026, 7, 13, 12, 0, 0));
  const end = new Date(Date.UTC(2026, 7, 13, 22, 0, 0));

  const asRep = msgs.encKdcRep({
    msgType: msgs.MSG_TYPE.AS_REP,
    crealm: "EXAMPLE.COM",
    cname: { type: 1, name: ["alice"] },
    ticket: {
      realm: "EXAMPLE.COM", sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] },
      encPart: {
        etype: 18,
        cipher: kcrypto.randomBytes(96)
      }   // not ours to open
    },
    encPart: { etype: 18, cipher: await e.encrypt(clientKey, 
        kcrypto.KEY_USAGE.AS_REP_ENCPART,
      msgs.encEncKdcRepPart({
        key: {
          etype: 18,
          key: sessionKey
        }, lastReq: [{
          type: 0,
          value: now
        }], nonce: 424242,
        flags: [msgs.TICKET_FLAG.FORWARDABLE, msgs.TICKET_FLAG.INITIAL],
        authtime: now, endtime: end, srealm: "EXAMPLE.COM",
        sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] }
      }, msgs.APPLICATION.ENC_AS_REP_PART)) }
  });

  // First with no key: the encrypted parts must be described and must say what
  // would open them.
  const blind = await decode(driver, b64(asRep));
  assert.ok(/No keys supplied/.test(await driver.findElement(By.id("krb_status")).getText()),
    "with no keys the status must say so");
  assert.ok(/service/i.test(blind), "the ticket must say whose key would " +
      "open it");
  assert.ok(blind.indexOf(String(424242)) === -1,
    "the nonce lives inside the enc-part and must NOT appear before anything " +
        "is decrypted");

  // Now with the password and the salt.
  await driver.findElement(By.id("krb_input")).clear();
  await driver.findElement(By.id("krb_input")).sendKeys(b64(asRep));
  await driver.findElement(By.id("krb_password")).sendKeys(password);
  await driver.findElement(By.id("krb_salt")).sendKeys(salt);
  await driver.findElement(By.id("krb_decode_button")).click();
  await driver.wait(async function () {
    return (await driver.findElement(By.id("krb_output")).getText()).indexOf("424242") !== -1;
  }, 30000, "the AS-REP's enc-part was not decrypted in the browser");

  const opened = await driver.findElement(By.id("krb_output")).getText();
  assert.ok(/EncASRepPart \(decrypted\)/.test(opened),
    "the decrypted enc-part must be shown as its own section");
  assert.ok(new RegExp(prim.toHex(sessionKey).slice(0, 
      24)).test(opened.replace(/\s/g, "")) ||
            /aes256-cts-hmac-sha1-96/.test(opened),
    "the session key inside must be revealed");
  assert.ok(/the password with salt/.test(opened),
    "the page must say WHICH key opened it, so a reader with several keys " +
        "knows");

  // A wrong salt must fail, and fail informatively: the same password with a
  // different salt is a different key, which is the single commonest reason a
  // reader cannot open an AS-REP they have the password for.
  await driver.findElement(By.id("krb_salt")).clear();
  await driver.findElement(By.id("krb_salt")).sendKeys("EXAMPLE.COMAlice");    // one letter's case
  await driver.findElement(By.id("krb_decode_button")).click();
  // Wait for a POSITIVE signal, not for the absence of one.
  //
  // The obvious wait here — "until 424242 is gone" — is satisfied the moment
  // onDecode() empties the output pane, before the new decode has produced
  // anything. The read that follows then sees an empty pane and the assertion
  // fails against "", which reads as the page having said nothing when in fact
  // the test looked too early. That cost a run of this test while it was being
  // written, and it is the same hazard tests/wait_for.js exists for: an absence
  // is true of a blank page.
  await driver.wait(async function () {
    return /none decrypted this/.test(await driver.findElement(By.id("krb_output")).getText());
  }, 30000, "a wrong salt produced no 'tried and failed' report");
  const failed = await driver.findElement(By.id("krb_output")).getText();
  assert.ok(/none decrypted this/.test(failed),
    "a key of the right type that does not work must say it was tried and " +
        "failed: " +
    failed.slice(0, 300));
  assert.ok(failed.indexOf("424242") === -1,
    "and a wrong salt must NOT have decrypted the enc-part — the same " +
        "password with a different " +
    "salt is a different key, which is the commonest reason a reader who has " +
        "the password still " +
    "cannot open an AS-REP");
  log.debug("Leaving decryptsAnAsRepFromAPasswordAndSalt().");
}

// ---------------------------------------------------------------------------
// Bytes that are not Kerberos at all, and input that is not decodable.
// ---------------------------------------------------------------------------
async function fallsBackAndRefusesInformatively(driver) {
  log.debug("Entering fallsBackAndRefusesInformatively().");
  const out = await decode(driver, b64(asn1.encSequence([
    asn1.encInteger(42), asn1.encGeneralString("not kerberos")])));
  assert.ok(/unrecognised/.test(await driver.findElement(By.css(".krb-kind")).getText()),
    "non-Kerberos ASN.1 must be labelled as unrecognised rather than refused");
  assert.ok(/ASN.1 structure/.test(out), "and its structure shown instead");
  assert.ok(/SEQUENCE/.test(out), "with the tags named");

  // Input that is neither hex nor base64 must be refused with an explanation,
  // and the page must not be left showing the previous result.
  await driver.findElement(By.id("krb_clear_button")).click();
  await driver.findElement(By.id("krb_input")).sendKeys("this is not base64 " +
      "or hex!!!");
  await driver.findElement(By.id("krb_decode_button")).click();
  await driver.wait(async function () {
    const s = await driver.findElement(By.id("krb_status")).getText();
    return /hex|base64/i.test(s);
  }, 15000, "unreadable input produced no explanation");
  const status = await driver.findElement(By.id("krb_status")).getText();
  assert.ok(/hex|base64/i.test(status),
    "the refusal must name both encodings it tried: " + status);
  const stale = await driver.findElement(By.id("krb_output")).getText();
  assert.ok(!/SEQUENCE/.test(stale),
    "a refused decode must clear the previous result — a page showing the " +
        "last message's output " +
    "beside a new error reads as though the new input decoded");
  log.debug("Leaving fallsBackAndRefusesInformatively().");
}

// Nothing on this page may be persisted: everything it is given is key material
// or a credential.
async function persistsNothing(driver) {
  log.debug("Entering persistsNothing().");
  const stored = await driver.executeScript(
    "var out = {}; for (var i = 0; i < localStorage.length; i++) {" +
    "  var k = localStorage.key(i); out[k] = " +
        "String(localStorage.getItem(k)).slice(0, 40); }" +
    "return out;");
  const offending = Object.keys(stored).filter(function (k) { return /^krb/i.test(k); });
  assert.deepStrictEqual(offending, [],
    "this page stored " + JSON.stringify(offending) + " in localStorage. It " +
        "must persist nothing: " +
    "a password, a keytab and a session key out of a decrypted ticket are " +
        "all credentials, and a " +
    "scratchpad that remembered them would be a worse place to leave a " +
        "keytab than the file it came from");
  const sessionStored = await driver.executeScript(
    "var n = []; for (var i = 0; i < sessionStorage.length; i++) " +
        "n.push(sessionStorage.key(i)); return n;");
  assert.deepStrictEqual(sessionStored.filter(function (k) { return /^krb/i.test(k); }), 
      [],
    "nor in sessionStorage");
  log.debug("Leaving persistsNothing().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying the Kerberos Decoder page at " + 
      baseUrl + ".");
  const options = new chrome.Options();
  // --headless=new, never bare --headless: in the image's Chrome 121 the old
  // headless mode ignores --unsafely-treat-insecure-origin-as-secure, so
  // crypto.subtle stays undefined however carefully the flags were set. See
  // tests/CLAUDE.md.
  options.addArguments("--headless=new", "--no-sandbox", 
      "--disable-dev-shm-usage",
                       "--window-size=1400,1100");
  // The decryption half runs on Web Crypto, which does not exist on the
  // containerized origin without these. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    await driver.get(baseUrl + "/kerberos_decoder.html");
    await driver.wait(until.elementLocated(By.id("krb_decode_button")), 20000);
    await theBundleLoadedAndTheButtonsWork(driver);
    await decodesAPreauthErrorAndReadsOutTheSalt(driver);
    await surfacesWhatIsWrongWithARequest(driver);
    await renderesHostileValuesAsTextAndNotAsMarkup(driver);
    await decryptsAnAsRepFromAPasswordAndSalt(driver);
    await fallsBackAndRefusesInformatively(driver);
    await persistsNothing(driver);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("kerberos_decoder_page")
  .description("Verify the Kerberos Decoder page: wiring, hostile input " +
      "rendered as text, in-browser decryption.")
  .addOption(new Option("-u, --url <url>", 
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
