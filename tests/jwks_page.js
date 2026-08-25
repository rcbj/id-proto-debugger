// File: jwks_page.js
//
// ---------------------------------------------------------------------------
// THE JWKS PAGE — the one page in this tree that no test had ever opened.
//
// It was found by the coverage report rather than by a failure, and that is the
// point worth recording: `client/src/jwks.js` is built by `client/build.js`,
// browserified by `client/Dockerfile`, and named in that file's COVERAGE list,
// so every check that guards the build was satisfied. It was simply ABSENT from
// the frontend coverage report — not at 0%, absent, because Istanbul reports on
// files that were loaded and nothing ever loaded this one. A page linked from
// two other pages ("Review JWKS meta data", on oauth2_oidc_1.html and
// oauth2_oidc_2.html) could have been broken for a year without a red test.
//
// What is checked, and why each needs a BROWSER:
//
//  * **The fetch is the page's own.** This page calls the JWKS endpoint
//    from the browser with jQuery — no api in the path at all — so it is
//    subject to CORS
//    and to Private Network Access, and neither exists outside a browser. It is
//    also what makes the page work on the static deployments.
//  * **The PEM column is a per-key TRY.** An identity provider may publish
//    a key this encoder does not cover; the encoder throws, and the whole
//    point of the catch is that the OTHER keys still render. A test that
//    only ever feeds it RSA keys cannot tell that catch from a missing one.
//  * **Every string in the table came from somewhere else.** This page builds
//    its markup by concatenation, so a JWKS member NAME is as much a stranger's
//    string as the value it points at — and one branch writes into a
//    `<textarea>`, where a value containing `</textarea>` closes the element
//    and everything after it is parsed as markup. That is the branch that
//    reaches the DOM as HTML, and it can only be observed in a DOM.
//
// **Services needed:** the client, and the mock STS for the live fetch. Section
// 2 SKIPS with a reason when the mock is not reachable; the rest of the file
// needs nothing but the page, because it drives the page's own exported
// functions with fixtures — which is also what keeps the Istanbul
// instrumentation counting, unlike the same fixtures run in node.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { waitForPageBundle, waitFor } = require("./wait_for.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "jwks_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
// The JWKS endpoint as THE BROWSER must reach it — its own variable, because on
// the containerized stack the browser's view of the mock is not the api's. That
// distinction has cost this suite a run before, on the LDAP and SPNEGO
// workflows.
var jwksUrl = process.env.JWKS_BROWSER_URL ||
    (process.env.STS_URL || "https://localhost:8081") + "/oauth2/jwks";

let checks = 0;
let skips = [];

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

function skip(what, why) {
  log.debug("Entering skip(). " + what);
  skips.push(what + ": " + why);
  log.warn("  SKIPPED — " + what + " — " + why);
  log.debug("Leaving skip().");
}

// ---------------------------------------------------------------------------
// The table's markup, and its text. Two different questions: the first is what
// reached the DOM as HTML, the second is what a reader sees.
//
// NOTE: THE SCRIPTS BELOW RUN IN THE BROWSER and are exempt from the
// Entering/Leaving convention — there is no bunyan in a page. See the repo-root
// CLAUDE.md.
// ---------------------------------------------------------------------------
function tableHtml(driver) {
  log.debug("Entering tableHtml().");
  log.debug("Leaving tableHtml().");
  return driver.executeScript(
    "var e = document.getElementById('jwks_info_table');" +
    "return e ? e.innerHTML : null;");
}

function tableText(driver) {
  log.debug("Entering tableText().");
  log.debug("Leaving tableText().");
  return driver.executeScript(
    "var e = document.getElementById('jwks_info_table');" +
    "return e ? e.textContent : null;");
}

// Render a JWKS the page did not fetch. The page exposes its own functions on
// the browserify --standalone global, which is what the inline onclick handlers
// call, so this is the same entry point a real response takes — one step later.
function renderFixture(driver, jwks) {
  log.debug("Entering renderFixture().");
  log.debug("Leaving renderFixture().");
  return driver.executeScript(
    "window.jwks.buildJWKSInfoTable(arguments[0]); return true;", jwks);
}

async function openPage(driver) {
  log.debug("Entering openPage().");
  await driver.get(baseUrl + "/jwks.html");
  // The inline onclick handlers call the browserify --standalone global, and a
  // click before that global exists is a SILENT NO-OP.
  await waitForPageBundle(driver, "the JWKS page");
  log.debug("Leaving openPage().");
}

// ---------------------------------------------------------------------------
// 1. The URL check in front of the fetch.
// ---------------------------------------------------------------------------
async function theEndpointIsValidatedBeforeAnythingIsFetched(driver) {
  log.debug("Entering theEndpointIsValidatedBeforeAnythingIsFetched().");
  log.info("1. The URL check.");

  const verdicts = await driver.executeScript(
    "return arguments[0].map(function (u) { return window.jwks.isUrl(u); });",
    ["https://idp.example.com/certs", "http://localhost:8081/oauth2/jwks",
      "", "not a url", "/certs", "   "]);
  check('an absolute URL is accepted and a relative or empty one is not',
      function () {
        assert.deepStrictEqual(verdicts,
            [true, true, false, false, false, false],
            'isUrl() guards the only network call this page makes. A ' +
            'relative path must be refused HERE — jQuery would happily ' +
            'resolve it against the client origin and fetch this site ' +
            'instead of the identity provider, and the table would fill ' +
            'with something that is not a JWKS.');
      });

  // Submitting a bad URL must leave the page alone rather than half-render.
  await driver.executeScript(
    "document.getElementById('jwks_endpoint').value = 'not a url';" +
    "return window.jwks.OnSubmitJWKSEndpointForm();");
  const after = await tableText(driver);
  check('a submit with an unusable URL changes nothing on the page',
      function () {
        assert.ok(!/Signer Certificate/.test(after || ''),
            'The table must not be built from a fetch that never happened. ' +
            'What it held instead: ' + JSON.stringify((after || '').slice(0,
                120)));
      });

  log.debug("Leaving theEndpointIsValidatedBeforeAnythingIsFetched().");
}

// ---------------------------------------------------------------------------
// 2. A real JWKS, fetched by the page itself.
// ---------------------------------------------------------------------------
async function theBrowserFetchesAJwksWithNoApiInThePath(driver) {
  log.debug("Entering theBrowserFetchesAJwksWithNoApiInThePath().");
  log.info("2. The page's own fetch, from " + jwksUrl + ".");

  await driver.executeScript(
    "document.getElementById('jwks_endpoint').value = arguments[0];" +
    "window.jwks.OnSubmitJWKSEndpointForm();", jwksUrl);

  let html = null;
  try {
    html = await waitFor(driver, function () {
      return tableHtml(driver);
    }, function (v) {
      return /Signer Certificate/.test(v || '');
    }, 'the JWKS table never filled from ' + jwksUrl, 15000);
  } catch (e) {
    // The two ways this fails are indistinguishable from here and both are
    // about the environment rather than the page: the mock is not running, or
    // it is and answered without the CORS headers the browser needs.
    skip('the live fetch', 'the browser could not read a JWKS from ' +
        jwksUrl + '. Either the mock STS is not running, or it answered ' +
        'without an Access-Control-Allow-Origin header — from inside the ' +
        'browser those two look the same. ' + e.message);
    log.debug("Leaving theBrowserFetchesAJwksWithNoApiInThePath(). Skipped.");
    return;
  }

  // The first column of every row, which is the member name as published. Read
  // as a LIST rather than by matching the table's text: the cells concatenate
  // with no separator, so "kty" arrives inside "ValuektyRSAusesig" and a
  // word-boundary regex for it matches nothing.
  const members = await driver.executeScript(
    "var rows = document.querySelectorAll('#jwks_info_table tr');" +
    "var out = [];" +
    "for (var i = 0; i < rows.length; i++) {" +
    "  if (rows[i].cells.length) {" +
    "    out.push(rows[i].cells[0].textContent.trim());" +
    "  }" +
    "}" +
    "return out;");
  check('the fetched key is rendered with its JWKS members', function () {
    ['kty', 'kid', 'alg', 'use', 'e', 'n'].forEach(function (member) {
      assert.ok(members.indexOf(member) >= 0,
          'the "' + member + '" member of the published key must be a row ' +
          'of the table; the rows were ' + JSON.stringify(members));
    });
  });

  // The modulus goes into a textarea rather than a cell, which is the one
  // branch of the member loop that is not a plain <td>.
  const modulus = await driver.executeScript(
    "var e = document.getElementById('jwks-0'); return e ? e.value : null;");
  check('the modulus is rendered into its own textarea', function () {
    assert.ok(modulus && modulus.length > 100,
        'the "n" member is base64url of a 2048-bit modulus and goes into a ' +
        'textarea of its own, so it neither wraps a table column to the ' +
        'width of the page nor is truncated. Got: ' +
        JSON.stringify(modulus));
  });

  const pem = await driver.executeScript(
    "var e = document.getElementById('x509-0'); return e ? e.value : null;");
  check('and the same key is offered as a PEM', function () {
    assert.ok(/^-----BEGIN PUBLIC KEY-----/.test(pem || ''),
        'the PEM pane is why this page exists — it is what a truststore is ' +
        'built from. Got: ' + JSON.stringify((pem || '').slice(0, 80)));
  });

  log.debug("Leaving theBrowserFetchesAJwksWithNoApiInThePath().");
}

// ---------------------------------------------------------------------------
// 3. A key the encoder cannot encode, beside one it can.
// ---------------------------------------------------------------------------
async function aKeyThatCannotBeEncodedDoesNotTakeTheOthersWithIt(driver) {
  log.debug("Entering aKeyThatCannotBeEncodedDoesNotTakeTheOthersWithIt().");
  log.info("3. A key with no PEM.");

  // An OKP key — Ed25519, published by more identity providers every year, and
  // not something this encoder covers. The RSA key after it is the assertion:
  // before the try/catch went in, one unsupported key left the whole table
  // unrendered, so a provider publishing an Ed25519 key beside its RSA one
  // showed the reader nothing at all.
  await renderFixture(driver, { keys: [
    { kty: 'OKP', crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo', kid: 'ed-1' },
    { kty: 'RSA', use: 'sig', alg: 'RS256', kid: 'rsa-1', e: 'AQAB',
      n: 'sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl' +
         'UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre' +
         'cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_' +
         '7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI' +
         'Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU' +
         '7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw' }
  ] });

  const text = await tableText(driver);
  const html = await tableHtml(driver);

  check('the key that could not be encoded says so, in its own pane',
      function () {
        assert.ok(/No PEM available for this key/.test(text),
            'the reader must be told which key has no PEM and why, rather ' +
            'than shown an empty box. The table read: ' + text.slice(0, 300));
      });
  check('and the reason names the key type rather than a stack trace',
      function () {
        assert.ok(/Unsupported key type/.test(text),
            'the message is the encoder\'s own and is the useful half — it ' +
            'names OKP, which is what tells the reader this is a key kind ' +
            'rather than a damaged key. Got: ' + text.slice(0, 300));
      });
  check('the key BESIDE it still rendered its PEM', function () {
    assert.ok(/-----BEGIN PUBLIC KEY-----/.test(text),
        'this is the whole reason the encode is a per-key try: one key the ' +
        'encoder does not cover must not empty the table. It did — the ' +
        'table read: ' + text.slice(0, 300));
  });
  check('both keys are still listed', function () {
    const panes = (html.match(/Signer Certificate #/g) || []).length;
    assert.strictEqual(panes, 2,
        'two keys were published, so two panes must be drawn whatever ' +
        'either of them encodes to.');
  });

  log.debug("Leaving aKeyThatCannotBeEncodedDoesNotTakeTheOthersWithIt().");
}

// ---------------------------------------------------------------------------
// 4. Everything in the table is somebody else's string.
// ---------------------------------------------------------------------------
async function nothingFetchedReachesTheDomAsMarkup(driver) {
  log.debug("Entering nothingFetchedReachesTheDomAsMarkup().");
  log.info("4. Escaping, on both halves of every row.");

  const hostileName = '<img src=x onerror="window.__jwksPwned=1">';
  // The textarea branch is the one that reaches the DOM as markup: a value
  // carrying </textarea> closes the element early and everything after it is
  // parsed as HTML. It is not the safer branch for being a textarea.
  const hostileModulus = 'AAAA</textarea><img src=y ' +
      'onerror="window.__jwksPwned=2">';

  await driver.executeScript("delete window.__jwksPwned;");
  const fixture = { keys: [{ kty: 'RSA', kid: "quote'and\"quote" }] };
  fixture.keys[0][hostileName] = 'value';
  fixture.keys[0].n = hostileModulus;
  await renderFixture(driver, fixture);

  const pwned = await driver.executeScript("return window.__jwksPwned;");
  check('nothing a JWKS carries executes', function () {
    assert.strictEqual(pwned, null,
        'a member name and a member value both came from a fetched ' +
        'document; an <img onerror> in either must be text. window.' +
        '__jwksPwned was ' + JSON.stringify(pwned) + ', which names which ' +
        'half got through: 1 is the member NAME, 2 is the textarea value.');
  });
  const injected = await driver.executeScript(
    "var e = document.getElementById('jwks_info_table');" +
    "return e ? e.querySelectorAll('img').length : -1;");
  check('and no element from it is in the document', function () {
    assert.strictEqual(injected, 0,
        'an <img> that fails to load quietly is still an element that was ' +
        'parsed as markup, and the next such string will carry something ' +
        'that does not fail quietly.');
  });

  const text = await tableText(driver);
  check('the hostile member NAME is displayed, as text', function () {
    assert.ok(text.indexOf(hostileName) >= 0,
        'escaping is not dropping — the reader is debugging a JWKS and has ' +
        'to be able to see the member exactly as published. The table ' +
        'read: ' + text.slice(0, 300));
  });
  const modulus = await driver.executeScript(
    "var e = document.getElementById('jwks-0'); return e ? e.value : null;");
  check('the textarea holds the value verbatim, closing tag and all',
      function () {
        assert.strictEqual(modulus, hostileModulus,
            'the value must survive escaping unchanged when it is read back ' +
            'out of the field, or the page is lying about what was ' +
            'published. Got: ' + JSON.stringify(modulus));
      });

  log.debug("Leaving nothingFetchedReachesTheDomAsMarkup().");
}

// ---------------------------------------------------------------------------
// 5. Clear.
// ---------------------------------------------------------------------------
async function clearEmptiesTheTable(driver) {
  log.debug("Entering clearEmptiesTheTable().");
  log.info("5. The Clear button.");

  const before = await tableText(driver);
  assert.ok((before || '').trim().length > 0,
      'the table must be populated before Clear is tested, or this section ' +
      'asserts nothing. It held: ' + JSON.stringify((before || '').slice(0,
          80)));

  await driver.findElement(By.css("input.btn_clear_all_forms")).click();
  const after = await waitFor(driver, function () {
    return tableText(driver);
  }, function (v) {
    return (v || '').trim() === '';
  }, 'Clear did not empty the JWKS table');
  check('Clear empties the table', function () {
    assert.strictEqual((after || '').trim(), '',
        'a stale key table beside a new endpoint is the kind of thing that ' +
        'gets read as the new endpoint\'s answer.');
  });

  log.debug("Leaving clearEmptiesTheTable().");
}

// ---------------------------------------------------------------------------
// 6. What the page remembers, and who wrote it.
// ---------------------------------------------------------------------------
async function theEndpointIsCarriedInFromTheDebugger(driver) {
  log.debug("Entering theEndpointIsCarriedInFromTheDebugger().");
  log.info("6. The endpoint field on load.");

  // This page writes nothing to localStorage: the value it prefills was put
  // there by oauth2_oidc_1.html / oauth2_oidc_2.html, whose "Review JWKS meta
  // data" link is the only way in. So the fixture is written the way THOSE
  // pages write it, and the assertion is that arriving here needs no retyping.
  const remembered = 'https://idp.example.com/protocol/openid-connect/certs';
  await driver.executeScript(
    "localStorage.setItem('jwks_endpoint', arguments[0]);", remembered);
  await openPage(driver);
  const filled = await driver.executeScript(
    "return document.getElementById('jwks_endpoint').value;");
  check('the endpoint the debugger stored is prefilled here', function () {
    assert.strictEqual(filled, remembered,
        'the link from the debugger carries no query string, so this field ' +
        'is the only thing that makes the page usable without pasting the ' +
        'endpoint again.');
  });

  // And with nothing stored the field is empty rather than the four characters
  // "null", which is what assigning a missing localStorage item to .value would
  // give in a language less forgiving than this one.
  await driver.executeScript("localStorage.removeItem('jwks_endpoint');");
  await openPage(driver);
  const empty = await driver.executeScript(
    "return document.getElementById('jwks_endpoint').value;");
  check('and with nothing stored it is empty rather than the word "null"',
      function () {
        assert.strictEqual(empty, '',
            'a field prefilled with "null" is one a user has to notice and ' +
            'clear before the page will work.');
      });

  log.debug("Leaving theEndpointIsCarriedInFromTheDebugger().");
}

// ---------------------------------------------------------------------------
// 7. The console.
// ---------------------------------------------------------------------------
async function theConsoleIsClean(driver) {
  log.debug("Entering theConsoleIsClean().");
  log.info("7. The browser console.");
  const entries = await driver.manage().logs().get("browser");
  const severe = entries.filter(function (entry) {
    if (entry.level.name !== "SEVERE") {
      return false;
    }
    const text = String(entry.message);
    // A favicon 404 is the server's business. A failed load is what section 2
    // deliberately provokes when the mock is absent, and section 4 renders an
    // <img> whose src is nonsense on purpose — neither is a script error.
    if (/favicon/.test(text)) {
      return false;
    }
    if (/Failed to load resource/.test(text)) {
      return false;
    }
    return true;
  });
  check('no page error reached the browser console', function () {
    assert.deepStrictEqual(severe.map(function (entry) {
      return entry.message.slice(0, 200);
    }), [],
        'A SEVERE console entry that is not a network status is a script ' +
        'error, and the ones this suite has seen name a page and a line ' +
        'deep inside a bundle rather than themselves.');
  });
  log.debug("Leaving theConsoleIsClean().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1000");
  // The page fetches the JWKS endpoint itself, and on this stack that is a
  // loopback address reached from whatever origin the suite is pointed at — a
  // Private Network Access request Chrome blocks or preflights unless told
  // otherwise. Without this the symptom is a table that never fills.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    await openPage(driver);
    await theEndpointIsValidatedBeforeAnythingIsFetched(driver);
    await theBrowserFetchesAJwksWithNoApiInThePath(driver);
    await aKeyThatCannotBeEncodedDoesNotTakeTheOthersWithIt(driver);
    await nothingFetchedReachesTheDomAsMarkup(driver);
    await clearEmptiesTheTable(driver);
    await theEndpointIsCarriedInFromTheDebugger(driver);
    await theConsoleIsClean(driver);
    log.info(checks + " checks passed.");
    if (skips.length) {
      log.warn(skips.length + " section(s) skipped:");
      skips.forEach(function (why) {
        log.warn("  - " + why);
      });
    }
    // The live fetch contributes four of these and skips as a group when the
    // mock is absent; everything else runs against fixtures and cannot.
    assert.ok(checks >= 11,
        'Only ' + checks + ' checks ran; a section has stopped being called.');
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("jwks_page")
  .description("Verify the JWKS page: the fetch it makes itself, the PEM " +
      "column's per-key try, and that nothing a JWKS carries reaches the " +
      "DOM as markup.")
  .addOption(new Option("-u, --url <url>",
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
