// File: pki_mutual_tls.js
//
// The PKI page, end to end, against a server that answers back: issue a client
// certificate from a Root and an Issuing CA in the browser, present it in a
// mutual-TLS handshake through the api, and read the MOCK STS's own account of
// the connection that resulted.
//
// ---------------------------------------------------------------------------
// WHAT THIS ADDS THAT tests/pki_page.js DOES NOT
//
// That test's TLS section is deliberately pointed at the client's own
// plain-HTTP port: a handshake that FAILS with a real alert proves the whole
// round trip — page to api, api to socket, report back to page — and needs no
// TLS service of its own. It proves the plumbing. What it cannot prove is
// anything about the certificate, because nothing ever accepted one.
//
// This is the other half, and every assertion in it is about something only the
// FAR END knows:
//
//   * that a certificate issued in this browser thirty seconds ago is
//     acceptable to somebody else's TLS stack at all;
//   * WHICH CHAIN the server built out of what was sent — a leaf presented
//     without its intermediates is the commonest mutual-TLS mistake there is
//     and it is invisible from the client;
//   * that the server verified it against the Root CA this page issued, and
//     said so, rather than merely completing a handshake. Under TLS 1.3 a
//     completed handshake means nothing about the client certificate: the
//     client sends its Certificate and Finished LAST, and the server's verdict
//     arrives afterwards as an alert or as a bare hang-up;
//   * and that the mutual-auth verdict this page reports is the one a real
//     server produces. `required` and `required-and-rejected` are the two an
//     operator confuses, and they are told apart here by trusting the CA
//     between two otherwise identical runs.
//
// The mock STS grew two HTTPS listeners for this (see docs/mock-sts.md): 8443
// asks for a client certificate and never refuses one, so it can report WHY
// something did not verify; 9443 requires one, so reaching it is itself the
// proof. Its client truststore starts EMPTY and is filled at runtime, because
// the CA in question does not exist anywhere until this test builds it in a
// browser — which is also why this test does that trusting itself, over the
// mock's plain HTTP port, in the middle of the run.
//
// It needs the client, the api and the mock STS. No identity provider, no KDC.
// ---------------------------------------------------------------------------
const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const assert = require("assert");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "pki_mutual_tls",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
// Headless by DEFAULT, and initialized true rather than false: a test that pops
// a window on every unattended run is a stolen desktop locally and a dead run
// in CI, which has no display. tests/browser_tests_headless.js asserts this
// over this directory's own sources.
var headless = true;
var waitTime = appconfig.waitTime;
var PAGE = "/pki.html";

// The mock STS's PLAIN HTTP base URL. Everything this test configures on the
// far end goes through it — the truststore, and the server certificate — and
// the TLS host is its hostname, with the ports read from the service itself
// rather than written down here.
//
// It is a variable of its own rather than derived from WSTRUST_STS_URL for the
// reason tests/CLAUDE.md gives about WSFED_STS_METADATA_URL: that one may
// legitimately point at a real Apache CXF STS, which has no TLS endpoint of
// this kind at all, and deriving would turn "not this service" into a failing
// job. Unset means SKIP.
var stsBaseUrl = process.env.STS_TLS_URL || "";

// The generation and issuing this page does is real cryptography in the
// browser, and an RSA key pair on a loaded CI runner is not instant. These
// waits are for CONTENT rather than for an element, per tests/wait_for.js.
var CRYPTO_WAIT = Math.max(waitTime, 20000);

async function waitVisible(driver, locator) {
  log.debug("Entering waitVisible().");
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(locator)),
                    waitTime);
  log.debug("Leaving waitVisible().");
  return driver.findElement(locator);
}

// ---------------------------------------------------------------------------
// Open the page the way a person does: from the landing page's PKI card, not
// by typing the URL. The card (client/public/index.html, added 2026-08-18) is
// this workflow's own front door — every other route to the page is somebody
// else's Tools pane — and a test that navigates straight to PAGE goes on
// passing after the card stops pointing anywhere, since nothing else in this
// file reads index.html. tests/navigation.js checks the card too, but only
// once and only on the containerized stack's own base URL; this runs wherever
// this test runs, the deployed static sites included.
//
// EVERY load here goes through it, the reloads included. localStorage is per
// ORIGIN rather than per page, so a trip via the landing page preserves
// exactly what a direct re-get would and the store assertions still mean what
// they say — while a reload that never leaves the page would be a weaker check
// than the one it replaces.
//
// Clicked rather than followed by href: a card that is present, correct and
// covered by something drawn over it is a card nobody can use, and only a real
// click says so. It is scrolled into view first because the grid's last row
// sits below the fold at the default window size.
// ---------------------------------------------------------------------------
var LANDING_CHOICES = By.css(".landing-choices");
var PKI_CARD = By.css('a.landing-card[href="' + PAGE + '"]');

async function openThePageFromTheLandingCard(driver) {
  log.debug("Entering openThePageFromTheLandingCard().");
  await driver.get(baseUrl);
  await waitVisible(driver, LANDING_CHOICES);
  const card = await waitVisible(driver, PKI_CARD);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", card);
  await card.click();
  await driver.wait(until.urlContains("pki.html"), waitTime,
    "the landing page's PKI card did not open " + PAGE);
  log.debug("Leaving openThePageFromTheLandingCard().");
}

// Set a field the way a person does — assign and dispatch — rather than
// assigning .value alone, which fires no event and so never reaches the page's
// change listener. Everything this page persists goes through that listener.
//
// NOTE: the bodies inside executeScript below run IN THE BROWSER. There is no
// bunyan there, so they carry no log lines — see tests/CLAUDE.md.
async function setField(driver, id, value) {
  log.debug("Entering setField(). id=" + id);
  const found = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (!e) { return false; }" +
    "e.value = arguments[1];" +
    "e.dispatchEvent(new Event('input', { bubbles: true }));" +
    "e.dispatchEvent(new Event('change', { bubbles: true }));" +
    "return true;", id, value);
  assert.ok(found, "there is no field " + id + " on this page");
  log.debug("Leaving setField().");
}

async function setCheckbox(driver, id, want) {
  log.debug("Entering setCheckbox(). id=" + id);
  const state = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (!e) { return null; }" +
    "if (e.checked !== arguments[1]) {" +
    "  e.checked = arguments[1];" +
    "  e.dispatchEvent(new Event('change', { bubbles: true }));" +
    "}" +
    "return e.checked;", id, want);
  assert.strictEqual(state, want,
    "the checkbox " + id + " did not take the value " + want +
    " (it reads " + JSON.stringify(state) + "; null means it is not there)");
  log.debug("Leaving setCheckbox().");
}

async function selectOption(driver, id, value) {
  log.debug("Entering selectOption(). id=" + id + " value=" + value);
  const applied = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (!e) { return 'no such element'; }" +
    "e.value = arguments[1];" +
    "if (e.value !== arguments[1]) { return 'no such option'; }" +
    "e.dispatchEvent(new Event('change', { bubbles: true }));" +
    "return 'ok';", id, value);
  assert.strictEqual(applied, "ok",
    "could not select " + value + " in " + id + ": " + applied);
  log.debug("Leaving selectOption().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). id=" + id);
  const text = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return e ? (e.textContent || '') : null;", id);
  log.debug("Leaving textOf().");
  return text;
}

async function valueOf(driver, id) {
  log.debug("Entering valueOf(). id=" + id);
  const value = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return e ? e.value : null;", id);
  log.debug("Leaving valueOf().");
  return value;
}

async function click(driver, id) {
  log.debug("Entering click(). id=" + id);
  const element = await waitVisible(driver, By.id(id));
  await element.click();
  log.debug("Leaving click().");
}

async function storeEntries(driver) {
  log.debug("Entering storeEntries().");
  const raw = await driver.executeScript(
    "return window.localStorage.getItem('pkitools_objects');");
  const entries = raw ? JSON.parse(raw) : [];
  log.debug("Leaving storeEntries(). " + entries.length + " entries.");
  return entries;
}

// ---------------------------------------------------------------------------
// The far end, over its plain HTTP port. Everything here is this test acting as
// the OPERATOR of the server being tested — trusting a CA is a configuration
// change, not part of the protocol exchange the page makes.
// ---------------------------------------------------------------------------
async function stsJson(path, options) {
  log.debug("Entering stsJson(). path=" + path);
  const response = await fetch(stsBaseUrl + path, options);
  const text = await response.text();
  if (!response.ok) {
    log.debug("Leaving stsJson(). HTTP " + response.status);
    throw new Error("the mock STS answered " + response.status + " to " +
      (options && options.method ? options.method : "GET") + " " + path +
      ": " + text.slice(0, 300));
  }
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    log.debug("Leaving stsJson(). Not JSON.");
    throw new Error("the mock STS answered " + path + " with something that " +
      "is not JSON (" + e.message + "): " + text.slice(0, 300));
  }
  log.debug("Leaving stsJson().");
  return parsed;
}

async function trustTheIssuer(pem) {
  log.debug("Entering trustTheIssuer().");
  const result = await stsJson("/tls/trust", {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: pem
  });
  assert.ok(result.anchors >= 1,
    "the mock STS did not record the CA as a trust anchor: " +
    JSON.stringify(result));
  log.info("The mock STS now trusts " + result.anchors +
           " client certificate issuer(s): " +
           (result.subjects || []).join("; "));
  log.debug("Leaving trustTheIssuer().");
  return result;
}

async function untrustEverything() {
  log.debug("Entering untrustEverything().");
  const result = await stsJson("/tls/trust/clear", { method: "POST" });
  assert.strictEqual(result.anchors, 0,
    "the mock STS's client truststore was not emptied: " +
    JSON.stringify(result));
  log.debug("Leaving untrustEverything(). removed=" + result.removed);
  return result;
}

async function serverCertificatePem() {
  log.debug("Entering serverCertificatePem().");
  const response = await fetch(stsBaseUrl + "/tls/server-certificate");
  const pem = await response.text();
  assert.ok(/-----BEGIN CERTIFICATE-----/.test(pem),
    "the mock STS did not hand out its TLS server certificate; without it " +
    "this test would have to disable verification, which is the habit this " +
    "whole workflow exists to break. It said: " + pem.slice(0, 200));
  log.debug("Leaving serverCertificatePem().");
  return pem;
}

// ---------------------------------------------------------------------------
// Building the hierarchy through the form, exactly as a person would.
// ---------------------------------------------------------------------------
// The page has ONE button: it generates the key pair and issues the
// certificate, because a pair that is never certified is kept nowhere. So the
// pair is checked after the issue rather than before it.
async function keyPairWasGenerated(driver, algId) {
  log.debug("Entering keyPairWasGenerated(). alg=" + algId);
  const priv = await valueOf(driver, "pki_private_key");
  assert.ok(priv && priv.indexOf("-----BEGIN") === 0,
    "the key pair fields never filled for " + algId);
  log.debug("Leaving keyPairWasGenerated().");
}

async function issueThrough(driver, spec) {
  log.debug("Entering issueThrough(). subject=" + spec.cn);
  await selectOption(driver, "pki_key_alg", spec.keyAlg);
  await selectOption(driver, "pki_profile", spec.profile);
  if (spec.issuerSubject) {
    // The issuer dropdown holds store ids, so it is chosen by the label the
    // page renders rather than by an id no human ever sees.
    const chosen = await driver.executeScript(
      "var e = document.getElementById('pki_issuer');" +
      "var want = arguments[0];" +
      "for (var i = 0; i < e.options.length; i++) {" +
      "  if (e.options[i].textContent.indexOf(want) >= 0) {" +
      "    e.value = e.options[i].value;" +
      "    e.dispatchEvent(new Event('change', { bubbles: true }));" +
      "    return e.options[i].textContent;" +
      "  }" +
      "}" +
      "return null;", spec.issuerSubject);
    assert.ok(chosen,
      "the issuer dropdown does not offer '" + spec.issuerSubject + "'");
  }
  await selectOption(driver, "pki_sig_alg", spec.sigAlg);
  await setField(driver, "pki_dn_cn", spec.cn);
  await setField(driver, "pki_dn_o", "idptools test");
  await setField(driver, "pki_dn_c", "US");
  if (spec.san) {
    await setCheckbox(driver, "pki_ext_san", true);
    await setField(driver, "pki_san", spec.san);
  }
  await click(driver, "pki_issue");
  // The button generates the key pair and then issues, so the status line
  // says two things about the key pair first. Waiting for "it changed" would
  // return one of those and the assertion below would fail on a message about
  // a key rather than about a certificate.
  let status = "";
  try {
    await driver.wait(async function () {
      status = await textOf(driver, "pki_status");
      return /Issued "|Could not issue|failed/.test(status || "");
    }, CRYPTO_WAIT);
  } catch (e) {
    throw new Error("timed out waiting for " + spec.cn + " to be issued (the " +
      "status line still reads " + JSON.stringify(status) + ")");
  }
  assert.ok(status.indexOf("Issued") >= 0,
    "issuing " + spec.cn + " failed: " + status);
  await keyPairWasGenerated(driver, spec.keyAlg);
  log.debug("Leaving issueThrough().");
  return status;
}

// ---------------------------------------------------------------------------
// One run of the TLS pane, and the report it produced.
// ---------------------------------------------------------------------------
async function runTlsTest(driver, options) {
  log.debug("Entering runTlsTest(). port=" + options.port);
  await setField(driver, "pki_tls_host", options.host);
  await setField(driver, "pki_tls_port", String(options.port));
  await setField(driver, "pki_tls_servername", options.servername);
  await setField(driver, "pki_tls_trust_pem", options.trustPem);
  await setCheckbox(driver, "pki_tls_system_roots", false);
  await setCheckbox(driver, "pki_tls_probe_mutual", !!options.mutualAuthProbe);
  await setCheckbox(driver, "pki_tls_http_probe", true);
  await setField(driver, "pki_tls_http_path", "/tls/whoami");
  // The client certificate is chosen by the label the page renders, for the
  // same reason the issuer is.
  const chosen = await driver.executeScript(
    "var e = document.getElementById('pki_tls_client_cert');" +
    "var want = arguments[0];" +
    "for (var i = 0; i < e.options.length; i++) {" +
    "  if (e.options[i].textContent.indexOf(want) >= 0) {" +
    "    e.value = e.options[i].value;" +
    "    e.dispatchEvent(new Event('change', { bubbles: true }));" +
    "    return e.options[i].textContent;" +
    "  }" +
    "}" +
    "return null;", options.clientSubject);
  assert.ok(chosen,
    "the client certificate dropdown does not offer '" + options.clientSubject +
    "'. Only objects whose PRIVATE KEY is in this browser can be presented, " +
    "so this is either a missing certificate or a purged key.");

  await click(driver, "pki_tls_run");
  // Wait for a SETTLED status rather than for any change: the pane writes
  // "Connecting to host:port…" the moment the button is pressed, so a
  // wait-for-anything-different is satisfied by the page's own progress message
  // and asserts on a call that has not happened yet.
  let status = "";
  try {
    await driver.wait(async function () {
      status = (await textOf(driver, "pki_tls_status")) || "";
      return status.trim().length > 0 && !/^Connecting/.test(status.trim());
    }, CRYPTO_WAIT);
  } catch (e) {
    throw new Error("the TLS test never came back from the api (the status " +
      "line still reads " + JSON.stringify(status) + ")");
  }
  assert.ok(!/could not be run/i.test(status),
    "the call to the api failed rather than the handshake: " + status);

  const report = await driver.executeScript(
    "function textOf(id) {" +
    "  var e = document.getElementById(id);" +
    "  return e ? (e.textContent || '') : null;" +
    "}" +
    "return { status: textOf('pki_tls_status')," +
    "         table: textOf('pki_tls_table')," +
    "         mutual: textOf('pki_tls_mutual_verdict')," +
    "         serverView: textOf('pki_tls_server_view')," +
    "         serverNote: textOf('pki_tls_server_view_note')," +
    "         serverChain: textOf('pki_tls_server_chain_table')," +
    "         serverBody: textOf('pki_tls_server_view_body') };");
  log.debug("Leaving runTlsTest(). status=" + report.status);
  return report;
}

// ---------------------------------------------------------------------------
// 1. A client certificate issued here, presented there, and read back from the
//    server's point of view — twice, so that "the server would not verify it"
//    and "the server verified it" are told apart by one configuration change
//    and nothing else.
// ---------------------------------------------------------------------------
async function theServerReportsWhatThisPageIssued(driver, ports, tlsHost) {
  log.debug("Entering theServerReportsWhatThisPageIssued().");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_key_alg"));
  await driver.executeScript("window.localStorage.clear();");
  await openThePageFromTheLandingCard(driver);
  await waitVisible(driver, By.id("pki_key_alg"));

  // The api's limits have to arrive first, since the page turns the
  // ask-the-server option off against an api that cannot do it — and a test
  // that set the box before that answer arrived would be racing it.
  await driver.wait(async function () {
    const text = await textOf(driver, "pki_tls_limits");
    return text && text.trim().length > 0;
  }, CRYPTO_WAIT, "the page never read GET /tls/limits");
  const asking = await driver.executeScript(
    "var e = document.getElementById('pki_tls_http_probe');" +
    "return e ? !e.disabled : null;");
  assert.strictEqual(asking, true,
    "the page has turned off asking the server what it saw, which it does " +
    "when GET /tls/limits reports httpRequestAvailable !== true. This api is " +
    "older than this page: " + (await textOf(driver, "pki_tls_http_note")));

  // A Root, an Issuing CA under it, and a client certificate under that. Three
  // levels rather than two on purpose: the leaf must then be SENT WITH ITS
  // CHAIN, and the server's own view of that chain is the only place the
  // difference shows.
  await issueThrough(driver, { profile: "root-ca", keyAlg: "rsa-2048",
    sigAlg: "sha256-rsa", cn: "Mutual TLS Root CA" });
  await issueThrough(driver, { profile: "issuing-ca", keyAlg: "ec-p256",
    sigAlg: "sha256-rsa", cn: "Mutual TLS Issuing CA",
    issuerSubject: "Mutual TLS Root CA" });
  await issueThrough(driver, { profile: "tls-client", keyAlg: "ec-p256",
    sigAlg: "sha256-ecdsa", cn: "Mutual TLS Client",
    issuerSubject: "Mutual TLS Issuing CA",
    san: "email:client@example.test\nupn:client@EXAMPLE.TEST" });

  const entries = await storeEntries(driver);
  const root = entries.filter(function (e) {
    return e.subject.indexOf("Mutual TLS Root CA") >= 0;
  })[0];
  const leaf = entries.filter(function (e) {
    return e.subject.indexOf("Mutual TLS Client") >= 0;
  })[0];
  assert.ok(root && root.certificatePem,
    "the Root CA is not in the store, so there is nothing to trust");
  assert.ok(leaf && leaf.privateKeyPem,
    "the client certificate has no private key here, so it cannot be " +
    "presented: the certificate is what is sent, the key is what proves it " +
    "is yours");
  assert.strictEqual(leaf.kind, "leaf",
    "a TLS client certificate is not a certificate authority");

  const trustPem = await serverCertificatePem();

  // --- Run one: the far end does NOT trust this CA yet. ---
  //
  // Against the PERMISSIVE listener, which answers anyway — that is what it is
  // for. The handshake completes, and the server's own account is the only
  // thing that says the certificate was not accepted. A test that read only
  // this end would call this a success.
  await untrustEverything();
  const before = await runTlsTest(driver, {
    host: tlsHost, port: ports.optional, servername: tlsHost,
    trustPem: trustPem, clientSubject: "Mutual TLS Client",
    mutualAuthProbe: false
  });
  assert.ok(/Connected\s*yes/.test(before.table.replace(/\s+/g, " ")),
    "the permissive listener must complete the handshake whatever it thinks " +
    "of the certificate — that is the whole reason it exists:\n" +
    before.table);
  assert.ok(before.serverView,
    "the server's own account of the connection is missing entirely. The " +
    "page asked for it (pki_tls_http_probe), so either the api did not make " +
    "the request or the pane did not render the answer.");
  assert.ok(/NOT verified/.test(before.serverView),
    "the mock STS's truststore was emptied a moment ago, so it cannot have " +
    "verified this certificate — and the page must report what the SERVER " +
    "said rather than what the handshake did:\n" + before.serverView);
  assert.ok(/Mutual TLS Client/.test(before.serverView),
    "the server did not name the certificate it was presented, so nothing " +
    "here is about the certificate this page issued:\n" + before.serverView);

  // --- Run two: trust the Root, and use the listener that REQUIRES a
  // certificate. Reaching it at all is the proof. ---
  await trustTheIssuer(root.certificatePem);
  const after = await runTlsTest(driver, {
    host: tlsHost, port: ports.required, servername: tlsHost,
    trustPem: trustPem, clientSubject: "Mutual TLS Client",
    mutualAuthProbe: true
  });
  const flat = after.table.replace(/\s+/g, " ");
  assert.ok(/Connected\s*yes/.test(flat),
    "the handshake did not complete against the listener that requires a " +
    "client certificate, now that the CA is trusted there:\n" + after.table +
    "\nstatus: " + after.status);
  assert.ok(/Certificate verified\s*yes/.test(flat),
    "this end did not verify the SERVER's certificate against the anchor " +
    "supplied, which is the other half of a mutual handshake:\n" + after.table);
  assert.ok(/Handshake completed/.test(after.status),
    "the status line should say the handshake completed: " + after.status);

  // The measured verdict, which is the thing a single connection cannot tell.
  assert.ok(after.mutual, "no mutual-authentication verdict was rendered");
  assert.ok(/Client authentication: required\b/.test(after.mutual),
    "the verdict must be `required`: this listener refuses a connection with " +
    "no client certificate and accepted one with it, which is precisely what " +
    "the two probe connections measure. `required-and-rejected` here would " +
    "mean the CA was not actually trusted; `not-required` would mean the " +
    "anonymous connection succeeded, and it cannot have:\n" + after.mutual);

  // And the server's own account of the same connection.
  assert.ok(after.serverView,
    "the server's account is missing on the run that mattered");
  const serverText = after.serverView.replace(/\s+/g, " ");
  assert.ok(/VERIFIED against \d+ anchor/.test(serverText),
    "the SERVER did not report verifying the certificate against the anchor " +
    "it was given. This is the assertion the whole test exists for: a " +
    "completed handshake is not an accepted client certificate, and under " +
    "TLS 1.3 the client is finished before the server has said anything:\n" +
    after.serverView);
  assert.ok(/Mutual TLS Client/.test(serverText),
    "the server named a different certificate than the one issued here:\n" +
    after.serverView);
  assert.ok(/required client certificate/.test(serverText),
    "the server did not report which of its two listeners answered, so the " +
    "report does not say whether a certificate was required:\n" +
    after.serverView);

  // The chain the server BUILT, which is the part no client can see. The page
  // sends the leaf and its intermediates and not the root — a server that does
  // not already hold the root will not trust it because we offered it — so the
  // server has to have bridged the Issuing CA itself.
  assert.ok(after.serverChain,
    "the server's own view of the chain was not rendered; a leaf presented " +
    "without its intermediates is the commonest mutual-TLS mistake there is " +
    "and this is the only place it shows");
  assert.ok(/Mutual TLS Issuing CA/.test(after.serverChain),
    "the Issuing CA is not in the chain the server built, which means the " +
    "page sent the leaf alone. Node's TLS server answers an unverifiable " +
    "client certificate by resetting the connection with no alert, so that " +
    "failure reads as 'the server refused my certificate' when what it could " +
    "not do was find the issuer:\n" + after.serverChain);
  log.debug("Leaving theServerReportsWhatThisPageIssued().");
}

// ---------------------------------------------------------------------------
// 2. The browser console must be clean. A page that throws on load looks
//    exactly like a page that is working until something on it is used.
// ---------------------------------------------------------------------------
async function theBrowserConsoleIsClean(driver) {
  log.debug("Entering theBrowserConsoleIsClean().");
  const entries = await driver.manage().logs().get(logging.Type.BROWSER);
  const severe = entries.filter(function (entry) {
    if (entry.level.name !== "SEVERE") return false;
    if (/favicon/.test(entry.message)) return false;
    return true;
  });
  assert.deepStrictEqual(severe.map(function (e) { return e.message; }), [],
    "the browser console carries severe errors, which on this page means a " +
    "bundle that did not load or a handler that threw");
  log.debug("Leaving theBrowserConsoleIsClean().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying " + baseUrl + PAGE +
           " against the mock STS at " + (stsBaseUrl || "(not set)"));

  if (!stsBaseUrl) {
    log.info("SKIPPING: STS_TLS_URL is not set, so there is no TLS endpoint " +
      "to present a certificate to. This test needs the mock STS's HTTPS " +
      "listeners (8443 and 9443) and its plain HTTP port to configure them.");
    log.debug("Leaving test(). Skipped.");
    return;
  }

  // What the far end will and will not do, read from the service rather than
  // written down here — the ports are configurable there, and a test carrying
  // its own copy of them is a test that breaks when somebody moves one.
  let ports = null;
  let tlsHost = "";
  try {
    const described = await stsJson("/tls?format=json");
    const optional = described.listeners.filter(function (listener) {
      return !listener.requiresClientCertificate;
    })[0];
    const required = described.listeners.filter(function (listener) {
      return listener.requiresClientCertificate;
    })[0];
    assert.ok(optional && required,
      "the mock STS does not publish both listeners: " +
      JSON.stringify(described.listeners));
    assert.ok(optional.listening && required.listening,
      "one of the mock STS's TLS listeners did not bind (" +
      (described.listenError || "no reason given") + "). Its HTTP port " +
      "answers either way, which is why it publishes this.");
    ports = { optional: optional.port, required: required.port };
    tlsHost = new URL(stsBaseUrl).hostname;
  } catch (e) {
    log.info("SKIPPING: the mock STS at " + stsBaseUrl + " has no TLS " +
      "endpoint (" + e.message + "). It is older than this test.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("The mock STS's TLS listeners are on " + tlsHost + ":" +
           ports.optional + " (client certificate optional) and " + tlsHost +
           ":" + ports.required + " (required).");

  const options = new chrome.Options();
  // --headless=new, NOT plain --headless. The tests image pins Chrome 121,
  // where plain --headless selects the OLD headless implementation — and in
  // that one --unsafely-treat-insecure-origin-as-secure has no effect, so on
  // the containerized suite's http://client:3000 origin window.crypto.subtle
  // stays undefined however carefully browser_flags.js was called. Every key
  // pair on this page needs it, and the symptom is a timeout waiting for a
  // field that never fills, naming neither crypto nor headless mode.
  if (headless) {
    options.addArguments("--headless=new");
  }
  // --no-sandbox and --disable-dev-shm-usage are what make Chrome start AT ALL
  // in the tests image, and this file and pki_page.js were the only two of the
  // fifty browser tests here without them. The failure is not a missing flag
  // and does not mention one: Chrome exits during startup and chromedriver
  // reports "session not created: Chrome failed to start: exited normally
  // (DevToolsActivePort file doesn't exist)", before the first driver.get().
  // The container has no user namespaces for the sandbox to use, and its
  // /dev/shm is the docker default 64MB, which the renderer outgrows. Neither
  // shows up on a host run, where both tests passed while the containerized
  // suite could not open a window.
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage");
  // The secure-context and private-network hazards. This page is ALL Web
  // Crypto, so it is exactly the kind that fails without these.
  browserFlags.addBrowserAccessFlags(options, baseUrl);

  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  // The in-page work here (an RSA key pair and three certificates) is bounded
  // by the WebDriver SCRIPT timeout, which is set separately from every
  // driver.wait in this suite and defaults to 30s. A CI runner is about twice
  // as slow as a dev host on identical code, so it is set explicitly rather
  // than inherited.
  await driver.manage().setTimeouts({ script: 60000 });

  try {
    const backendNoticeShown = await (async function () {
      await openThePageFromTheLandingCard(driver);
      await waitVisible(driver, By.id("pki_tls_host"));
      return driver.executeScript(
        "var e = document.getElementById('pki_backend_notice');" +
        "return !!e && e.style.display !== 'none';");
    })();
    if (backendNoticeShown) {
      log.info("SKIPPING: this build has no api behind it " +
        "(backendAvailable is false), and a browser cannot present a client " +
        "certificate, choose a truststore or read a handshake.");
      log.debug("Leaving test(). Skipped.");
      return;
    }
    await theServerReportsWhatThisPageIssued(driver, ports, tlsHost);
    await theBrowserConsoleIsClean(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    try {
      const url = await driver.getCurrentUrl();
      log.error("Current URL: " + url);
      const entries = await driver.manage().logs().get(logging.Type.BROWSER);
      entries.slice(-15).forEach(function (entry) {
        log.error("browser: " + entry.level.name + " " + entry.message);
      });
    } catch (e) {
      log.error("could not collect the browser log: " + e.message);
    }
    process.exit(1);
  } finally {
    // Leave the far end as it was found. The truststore is process state on a
    // service other tests share, and a CA left in it would make the next run's
    // "before trusting" case pass for the wrong reason — which is exactly the
    // kind of test that quietly stops asserting.
    try {
      await untrustEverything();
    } catch (e) {
      log.warn("could not empty the mock STS's truststore afterwards: " +
               e.message);
    }
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("pki_mutual_tls")
  .description("Issue a client certificate from a Root and an Issuing CA in " +
      "the browser, present it in a mutual-TLS handshake through the api, " +
      "and read the mock STS's own account of the connection.")
  .addOption(new Option("-u, --url <url>",
      "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser",
      "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
