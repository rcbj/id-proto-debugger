// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_verifier_oid4vc_wallet.js
//
// ---------------------------------------------------------------------------
// THE DEBUGGER AS THE OPENID4VP VERIFIER, AGAINST A WALLET THAT IS NOT OURS
// (#364, PR 2).
//
// tests/vc_verifier_page.js answers the Verifier page from node with the
// debugger's own Wallet code, which is the debugger agreeing with itself.
// Here the wallet is rcbj/oid4vc-wallet: a native Rust wallet with its own
// OpenID4VP, SD-JWT and JOSE implementation, driven through its headless
// command line (`accept`, `present`, `credential`). Neither end of the
// presentation shares a line of code with the other.
//
// THE CREDENTIAL IS REAL TOO. A person signs in to iya-sts's own account
// page (/portal/wallet), makes a pre-authorized offer for an
// IdentityCredential (dc+sd-jwt), and the wallet redeems it with the
// Transaction Code: `accept` takes the offer BY VALUE, built from the
// document behind the portal's credential_offer_uri.
//
// THEN, PER ROUND, the Verifier page builds a request for that credential's
// vct and one of its disclosable claims, the wallet answers it
// (`present … --approve --json`), and every check the page draws must pass:
//
//   1. x509_hash, request_uri fetched with GET, direct_post;
//   2. x509_san_dns, request_uri_method=post, direct_post.jwt (the answer
//      encrypted to the key the Request Object carries);
//   3. the wallet REFUSES (`--refuse`): the page must report the wallet's
//      error answer as a failure rather than as a presentation.
//
// WHAT THE WALLET REQUIRES, which this exercises on the page and the api:
// a Request Object typed oauth-authz-req+jwt with the leaf alone in x5c, a
// root it can fetch from the leaf's Authority Information Access URL (the
// api's /oid4vp/verifier/<id>/ca), request_uri and response_uri on the same
// host, and aud https://self-issued.me/v2.
//
// The binary is OID4VC_WALLET_BIN, or `oid4vc-wallet` on PATH; the tests
// image builds it in its oid4vc-wallet stage, at a pinned commit, the way
// iya-sts's tests image does. Its TLS trust is SSL_CERT_FILE, pointed at the
// stack's CA bundle.
// A missing binary FAILS this job, naming it: a suite that skipped here
// would be green with the independent half switched off.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const childProcess = require("child_process");
const nodeCrypto = require("crypto");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { loadUrl } = require("./page_load.js");
const common = require("./jwt_vc_json_common.js");
const consentScreen = require("./consent_screen.js");
const { usernameFor } = require("./random_username.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_verifier_oid4vc_wallet",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
const issuerBase = (process.env.OID4VCI_ISSUER_URL ||
    String(process.env.WSTRUST_STS_URL || "https://localhost:8081")
      .replace(/\/sts$/, "")).replace(/\/+$/, "");
const WALLET_BIN = process.env.OID4VC_WALLET_BIN || "oid4vc-wallet";
const CA_FILE = process.env.STACK_TLS_CA_FILE ||
    process.env.NODE_EXTRA_CA_CERTS || "";
const WAIT = Number(process.env.TEST_WAIT_TIME_MS) ||
    Math.max(Number(appconfig.waitTime) || 2000, 20000);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE WALLET, a process with a home of its own.
// ---------------------------------------------------------------------------
function walletHome() {
  log.debug("Entering walletHome().");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "oid4vc-wallet-"));
  const data = path.join(home, "data");
  const config = path.join(home, "config");
  fs.mkdirSync(data, { mode: 0o700 });
  fs.mkdirSync(config, { mode: 0o700 });
  log.debug("Leaving walletHome(). " + home);
  return { home: home, data: data, config: config,
           keyFile: path.join(data, "storage.key") };
}

// Run the wallet. Answers { status, stdout, stderr, json }.
function wallet(where, args) {
  log.debug("Entering wallet(). " + args[0]);
  const env = Object.assign({}, process.env, {
    HOME: where.home,
    XDG_DATA_HOME: where.data,
    XDG_CONFIG_HOME: where.config,
    OID4VC_WALLET_KEY_FILE: where.keyFile
  });
  // No desktop: the command line needs none, and a stray DISPLAY or bus
  // would only send it looking for one.
  delete env.DISPLAY;
  delete env.WAYLAND_DISPLAY;
  delete env.DBUS_SESSION_BUS_ADDRESS;
  if (CA_FILE) {
    env.SSL_CERT_FILE = CA_FILE;
  }
  const run = childProcess.spawnSync(WALLET_BIN, args, {
    env: env, encoding: "utf8", timeout: 120000 });
  if (run.error) {
    log.debug("Leaving wallet(). Could not run.");
    throw new Error("could not run " + WALLET_BIN + ": " + run.error.message +
      ". The tests image builds it in its oid4vc-wallet stage; on a host, " +
      "set OID4VC_WALLET_BIN.");
  }
  let json = null;
  try {
    json = JSON.parse(String(run.stdout || "").trim().split("\n").pop());
  } catch (e) {
    log.debug("wallet(): stdout is not one JSON line.");
    json = null;
  }
  log.info("  $ oid4vc-wallet " + args.map(function (one) {
    return one.length > 60 ? one.slice(0, 57) + "..." : one;
  }).join(" ") + "  -> " + run.status);
  log.debug("Leaving wallet(). " + run.status);
  return { status: run.status, stdout: String(run.stdout || ""),
           stderr: String(run.stderr || ""), json: json };
}

// The vct and the disclosable claim names of an SD-JWT VC, read without
// verifying anything: this only chooses what the request asks for.
function describeSdJwt(document) {
  log.debug("Entering describeSdJwt().");
  const parts = String(document).split("~");
  const header = JSON.parse(Buffer.from(parts[0].split(".")[0],
                                        "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(parts[0].split(".")[1],
                                         "base64url").toString("utf8"));
  const names = parts.slice(1).filter(Boolean).map(function (one) {
    try {
      const d = JSON.parse(Buffer.from(one, "base64url").toString("utf8"));
      return d.length === 3 && typeof d[1] === "string" ? d[1] : null;
    } catch (e) {
      log.debug("describeSdJwt(): not a Disclosure.");
      return null;
    }
  }).filter(Boolean);
  log.debug("Leaving describeSdJwt(). " + names.length + " name(s).");
  return { vct: payload.vct, names: names,
           x5c: Array.isArray(header.x5c) ? header.x5c : [] };
}

// THE ISSUER'S ROOT, FETCHED OUT OF BAND, the way an operator configures
// trust: from the last x5c certificate, follow Authority Information Access
// caIssuers (RFC 5280 section 4.2.2.1) until a self-signed certificate. That
// is iya-sts's published CA (its /pki/ca/...). The Verifier is then given
// it as a trust anchor; nothing in the credential is trusted for being
// there. PEM, or "" when the chain names no AIA to follow.
async function issuerRootOutOfBand(x5c) {
  log.debug("Entering issuerRootOutOfBand(). " + x5c.length);
  if (!x5c.length) {
    log.debug("Leaving issuerRootOutOfBand(). No x5c.");
    return "";
  }
  let cert = new nodeCrypto.X509Certificate(
    Buffer.from(x5c[x5c.length - 1], "base64"));
  for (let hop = 0; hop < 5; hop++) {
    if (cert.issuer === cert.subject && cert.verify(cert.publicKey)) {
      log.info("  issuer root (out of band): " + cert.subject
        .replace(/\n/g, ", ") + ", sha256 " + cert.fingerprint256);
      log.debug("Leaving issuerRootOutOfBand(). Found.");
      return cert.toString();
    }
    const m = /CA Issuers - URI:(\S+)/.exec(cert.infoAccess || "");
    if (!m) {
      log.debug("Leaving issuerRootOutOfBand(). No AIA.");
      return "";
    }
    log.info("  following caIssuers of \"" + cert.subject
      .replace(/\n/g, ", ") + "\": " + m[1]);
    let got;
    try {
      got = await fetch(m[1]);
    } catch (e) {
      throw new Error("could not fetch the issuer's caIssuers URL " + m[1] +
          " (from the certificate \"" + cert.subject.replace(/\n/g, ", ") +
          "\"): " + (e.cause ? e.cause.code || e.cause.message : e.message) +
          ". iya-sts writes it from PKI_DISTRIBUTION_BASE_URL; is it set to " +
          "an address the tests container can reach?");
    }
    const body = Buffer.from(await got.arrayBuffer());
    assert.strictEqual(got.status, 200, m[1] + " answered " + got.status);
    const text = body.toString("utf8");
    const pem = (/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/
      .exec(text) || [])[0];
    cert = new nodeCrypto.X509Certificate(pem || body);
  }
  log.debug("Leaving issuerRootOutOfBand(). Too many hops.");
  return "";
}

// ---------------------------------------------------------------------------
// THE CREDENTIAL: an offer from iya-sts's portal, redeemed by the wallet.
// ---------------------------------------------------------------------------
async function walletHoldsACredential(driver, where) {
  log.debug("Entering walletHoldsACredential().");
  log.info("=== The wallet redeems iya-sts's pre-authorized offer ===");
  const screen = await common.offerFromThePortalWallet(driver, {
    By: By, until: until, stsBase: issuerBase,
    username: usernameFor("vcverifier"), mode: "cross-device",
    configuration: "IdentityCredential", wait: WAIT,
    consentScreen: consentScreen });
  // THE OFFER BY VALUE, built here from the one by reference the helper
  // read off the portal. The portal draws its "open in a wallet on this
  // device" link (the by-value offer) in the same card as the Transaction
  // Code, but the card belongs to the POST's answer and a later redraw of
  // the page drops it, so a second read of the DOM races it. The offer
  // document behind credential_offer_uri is the same offer. iya-sts 1.0.0
  // does not spend it when it is fetched; OpenID4VCI 1.0 does not say either
  // way, and this job fetches it exactly once. The wallet's `accept` takes
  // an offer by value.
  const params = new URL(screen.offerUri.replace(
      /^[a-z0-9+.-]+:\/\//i, "https://x/")).searchParams;
  const offerUri = params.get("credential_offer_uri") || "";
  let byValue = params.get("credential_offer") ?
      screen.offerUri : "";
  if (!byValue) {
    const fetched = await fetch(offerUri);
    const offerText = await fetched.text();
    let offer = null;
    // OpenID4VCI 1.0 section 4.1.1: credential_issuer and
    // credential_configuration_ids are REQUIRED; grants is OPTIONAL.
    check("the offer by reference resolves to a Credential Offer",
        function () {
          assert.strictEqual(fetched.status, 200, offerUri + " answered " +
              fetched.status + ": " + offerText.slice(0, 200));
          offer = JSON.parse(offerText);
          assert.ok(typeof offer.credential_issuer === "string" &&
              offer.credential_issuer.length > 0, offerText.slice(0, 200));
          assert.ok(Array.isArray(offer.credential_configuration_ids) &&
              offer.credential_configuration_ids.length > 0,
              offerText.slice(0, 200));
        });
    // What THIS job expects of the offer, which the spec leaves optional: a
    // pre-authorized code grant with a Transaction Code, because the portal
    // was asked for a cross-device offer and `accept --tx-code` redeems one.
    check("the offer carries a pre-authorized code grant with a " +
        "Transaction Code (the cross-device offer this job asked for)",
        function () {
          const grant = (offer.grants || {})[
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"];
          assert.ok(grant && grant["pre-authorized_code"],
              JSON.stringify(offer.grants || null).slice(0, 200));
          assert.ok(grant.tx_code, "the grant names no tx_code: " +
              JSON.stringify(grant).slice(0, 200));
        });
    byValue = "openid-credential-offer://?credential_offer=" +
        encodeURIComponent(JSON.stringify(JSON.parse(offerText)));
  }
  const shown = { href: byValue, txCode: screen.txCode };
  check("the portal made a pre-authorized offer with a Transaction Code",
      function () {
        assert.ok(/^openid-credential-offer:\/\/\?credential_offer=/.test(
            shown.href), "by value: " + shown.href.slice(0, 120));
        assert.ok(String(shown.txCode || "").length > 0,
            "no Transaction Code");
      });
  const accepted = wallet(where, ["accept", shown.href, "--tx-code",
                                  shown.txCode]);
  check("the wallet redeems the offer", function () {
    assert.strictEqual(accepted.status, 0, accepted.stdout + "\n" +
                       accepted.stderr);
  });
  const listed = wallet(where, ["credential", "list", "--json"]);
  const rows = Array.isArray(listed.json) ? listed.json
    : (listed.json && listed.json.credentials) || [];
  const held = rows.filter(function (row) {
    return /sd-jwt/.test(String(row.format || ""));
  });
  check("the wallet holds a dc+sd-jwt credential", function () {
    assert.ok(held.length > 0, "credential list says: " + listed.stdout);
  });
  const shownCredential = wallet(where, ["credential", "show",
                                         String(held[0].id), "--json"]);
  const doc = (shownCredential.json && (shownCredential.json.document ||
               shownCredential.json.credential)) || "";
  const described = describeSdJwt(doc);
  check("its vct is iya-sts's identity credential and it has disclosable " +
      "claims", function () {
        assert.strictEqual(described.vct, "urn:iya:sts:sd-jwt-vc:identity");
        assert.ok(described.names.length > 0, "no Disclosures");
      });
  log.debug("Leaving walletHoldsACredential(). " + described.names.join(","));
  return described;
}

// ---------------------------------------------------------------------------
// THE VERIFIER PAGE.
// ---------------------------------------------------------------------------
async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  await driver.executeScript(
      "var e = document.getElementById(arguments[0]);" +
      "if (e.type === 'checkbox') { e.checked = !!arguments[1]; }" +
      "else { e.value = arguments[1]; }", id, value);
  log.debug("Leaving setField().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). " + id);
  const text = await driver.executeScript(
      "var e = document.getElementById(arguments[0]);" +
      "return e ? String(e.textContent || '') : '';", id);
  log.debug("Leaving textOf().");
  return text;
}

async function createRequest(driver, credential, round) {
  log.debug("Entering createRequest(). " + round.label);
  await loadUrl(driver, baseUrl + "/vc-verifier.html");
  await driver.wait(async function () {
    return /will host|no api|did not|switched off/i.test(
        await textOf(driver, "vpv_api_status"));
  }, WAIT, "the Verifier page never said whether the api can host a " +
      "request");
  await setField(driver, "vpv_query_id", "identity");
  await setField(driver, "vpv_format", "dc+sd-jwt");
  await setField(driver, "vpv_type", credential.vct);
  await setField(driver, "vpv_claims", credential.names[0]);
  await setField(driver, "vpv_binding", true);
  await setField(driver, "vpv_dcql", "");
  await driver.executeScript("window.vcverifier.regenerateDcql();");
  await setField(driver, "vpv_client_prefix", round.prefix);
  await setField(driver, "vpv_response_mode", round.mode);
  await setField(driver, "vpv_delivery", round.delivery);
  await setField(driver, "vpv_scheme", "openid4vp://");
  await setField(driver, "vpv_redirect_uri", "");
  await driver.executeScript("window.vcverifier.settingsChanged();");
  await driver.findElement(By.id("btn_vpv_create")).click();
  await driver.wait(async function () {
    return /ready|failed|refused|no api|did not|not in a secure/i.test(
        await textOf(driver, "vpv_create_status"));
  }, WAIT, "Create the request never finished");
  const said = await textOf(driver, "vpv_create_status");
  assert.ok(/ready/i.test(said), "Creating the request said: " + said);
  const request = await driver.executeScript(
      "return window.vcverifier.currentRequest();");
  log.debug("Leaving createRequest().");
  return request;
}

async function waitForVerdict(driver) {
  log.debug("Entering waitForVerdict().");
  await driver.wait(async function () {
    return /passed|failed|could not/i.test(
        await textOf(driver, "vpv_verdict"));
  }, WAIT, "the page never drew a verdict; it says: " +
      await textOf(driver, "vpv_wait_status"));
  const rows = await driver.executeScript(
      "return Array.prototype.slice.call(" +
      "  document.querySelectorAll('#vpv_checks tr')).map(function (r) {" +
      "  return { id: r.id, cls: r.className, text: r.textContent }; });");
  const events = await driver.executeScript(
      "return Array.prototype.slice.call(" +
      "  document.querySelectorAll('#vpv_events li')).map(function (li) {" +
      "  return li.textContent; });");
  const verdict = await textOf(driver, "vpv_verdict");
  log.debug("Leaving waitForVerdict(). " + rows.length + " row(s).");
  return { verdict: verdict, rows: rows, events: events };
}

function failedRows(seen) {
  log.debug("Entering failedRows().");
  const failed = seen.rows.filter(function (r) {
    return /fail/.test(r.cls);
  }).map(function (r) {
    return r.text;
  });
  log.debug("Leaving failedRows(). " + failed.length);
  return failed;
}

// The first round has NO trust anchor for the issuer: its verdict must be
// "incomplete", with only the issuer's x5c trust not performed. The second
// is given iya-sts's root, fetched out of band, and must be a FULL pass:
// the anchored path against a third party's real chain.
const ROUNDS = [
  { label: "x509_hash, request_uri GET, direct_post, no issuer anchor",
    prefix: "x509_hash", delivery: "reference-get", mode: "direct_post",
    anchored: false },
  { label: "x509_san_dns, request_uri_method=post, direct_post.jwt, " +
      "issuer anchored",
    prefix: "x509_san_dns", delivery: "reference-post",
    mode: "direct_post.jwt", anchored: true }
];

async function walletPresents(driver, where, credential, round) {
  log.debug("Entering walletPresents(). " + round.label);
  log.info("=== " + round.label + " ===");
  await loadUrl(driver, baseUrl + "/vc-verifier.html");
  await setField(driver, "vpv_trust_anchors",
                 round.anchored ? credential.rootPem : "");
  await driver.executeScript("window.vcverifier.settingsChanged();");
  const request = await createRequest(driver, credential, round);
  const answered = wallet(where, ["present", request.invocation, "--approve",
                                  "--json"]);
  check("the wallet presents (" + round.label + ")", function () {
    assert.strictEqual(answered.status, 0, answered.stdout + "\n" +
                       answered.stderr);
    assert.ok(answered.json && answered.json.ok, answered.stdout);
  });
  const seen = await waitForVerdict(driver);
  // WHAT WAS ASKED AND WHAT CAME BACK, so a "not disclosed" says which side
  // is wrong: the DCQL claims the page sent, and the claims the page found
  // disclosed in the wallet's answer.
  const asked = await driver.executeScript(
      "try { return JSON.stringify(JSON.parse(document.getElementById(" +
      "  'vpv_dcql').value).credentials.map(function (c) {" +
      "  return { id: c.id, claims: c.claims || null }; })); }" +
      "catch (e) { return ''; }");
  const disclosed = await textOf(driver, "vpv_claims_out");
  log.info("  asked (DCQL claims): " + asked);
  log.info("  disclosed (as the page read the answer): " +
           String(disclosed).replace(/\s+/g, " ").slice(0, 600));
  // NOTHING FAILS. Unanchored, the issuer's x5c trust is the one essential
  // check not performed (a certificate is not trusted because it is in
  // x5c, SD-JWT VC -27 section 2.5). Anchored at iya-sts's root, it is a
  // full pass. Whether iss is bound to the certificate is reported on its
  // own row either way, and never fails.
  const unperformed = seen.rows.filter(function (r) {
    return /unperformed/.test(r.cls);
  }).map(function (r) {
    return r.id;
  });
  const rowEnding = function rowEnding(suffix) {
    return seen.rows.find(function (r) {
      return r.id.slice(-suffix.length) === suffix;
    });
  };
  const issRow = rowEnding(".issuer.iss");
  if (issRow) {
    log.info("  iss binding: " + issRow.text.replace(/\s+/g, " ")
      .slice(0, 300));
  }
  check("nothing on the wallet's answer fails (" + round.label + ")",
      function () {
        assert.deepStrictEqual(failedRows(seen), [], seen.verdict);
      });
  // iya-sts binds iss to its credential signer by a URI subjectAltName
  // equal to iss (rcbj/iya-sts#1880, on its develop branch and in 1.1.0).
  // This is the only test of that binding path against a third party's
  // real certificate, so it must PASS, not merely be reported. It needs
  // the stack on an iya-sts build with #1880: for now that is the local
  // iya-sts develop build (IYA_STS_IMAGE), not the 1.0.0 release.
  check("iss is bound to iya-sts's signing certificate by a URI " +
      "subjectAltName (" + round.label + ")", function () {
        assert.ok(issRow && /pass/.test(issRow.cls) &&
            /by a URI subjectAltName equal to it/.test(issRow.text),
            "issuer.iss: " + JSON.stringify(issRow) + ". An iya-sts build " +
            "without rcbj/iya-sts#1880 (the 1.0.0 release) does not bind " +
            "iss; run against its develop build (IYA_STS_IMAGE).");
      });
  if (round.anchored) {
    check("anchored at iya-sts's root, every check passes, issuer trust " +
        "included (" + round.label + ")", function () {
          assert.ok(/every check passed/i.test(seen.verdict),
              seen.verdict + "; not performed: " + unperformed.join(", "));
          const trust = rowEnding(".issuer.trust");
          assert.ok(trust && /pass/.test(trust.cls),
              "issuer.trust: " + JSON.stringify(trust));
          assert.ok(issRow, "the issuer.iss row is reported");
        });
  } else {
    check("without an issuer anchor the verdict is incomplete, and only " +
        "the issuer's x5c trust is unperformed (" + round.label + ")",
        function () {
          assert.ok(/could not be performed/i.test(seen.verdict),
              seen.verdict);
          assert.ok(unperformed.length > 0 && unperformed.every(
            function (id) {
              return /\.issuer\.trust$/.test(id);
            }), "essential checks not performed: " + unperformed.join(", "));
        });
  }
  check("the api saw the wallet fetch the Request Object and the root " +
      "(" + round.label + ")", function () {
        const all = seen.events.join("\n");
        assert.ok(/fetched the Request Object \((GET|POST)\)/.test(all), all);
        assert.ok(/root certificate/.test(all), all);
        if (round.delivery === "reference-post") {
          assert.ok(/\(POST\)/.test(all), all);
        }
      });
  if (round.mode === "direct_post.jwt") {
    check("the encrypted answer was decrypted", function () {
      const row = seen.rows.find(function (r) {
        return r.id === "vpv_check_response.decrypt";
      });
      assert.ok(row && /pass/.test(row.cls), JSON.stringify(row));
    });
  }
  log.debug("Leaving walletPresents().");
}

async function walletRefuses(driver, where, credential) {
  log.debug("Entering walletRefuses().");
  log.info("=== the wallet refuses ===");
  const request = await createRequest(driver, credential, ROUNDS[0]);
  const refused = wallet(where, ["present", request.invocation, "--refuse",
                                 "--json"]);
  check("the wallet tells the Verifier no", function () {
    assert.strictEqual(refused.status, 0, refused.stdout + "\n" +
                       refused.stderr);
  });
  const seen = await waitForVerdict(driver);
  check("the page reports the refusal as the wallet's error answer, not " +
      "as a presentation", function () {
        assert.ok(!/every check passed/i.test(seen.verdict), seen.verdict);
        const row = seen.rows.find(function (r) {
          return r.id === "vpv_check_response.error";
        });
        assert.ok(row && /fail/.test(row.cls) && /access_denied/.test(
            row.text), JSON.stringify(row));
      });
  log.debug("Leaving walletRefuses().");
}

async function test() {
  log.debug("Entering test().");
  const version = wallet(walletHome(), ["--version", "--json"]);
  check("the wallet binary runs (" + WALLET_BIN + ")", function () {
    assert.strictEqual(version.status, 0, version.stderr);
  });
  log.info("oid4vc-wallet " + version.stdout.trim());
  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,2400");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  const where = walletHome();
  try {
    const credential = await walletHoldsACredential(driver, where);
    credential.rootPem = await issuerRootOutOfBand(credential.x5c);
    check("iya-sts's issuer root is fetched out of band, through the " +
        "chain's Authority Information Access", function () {
          assert.ok(/BEGIN CERTIFICATE/.test(credential.rootPem),
              "no root reached from x5c (" + credential.x5c.length +
              " certificate(s))");
        });
    let round;
    for (round of ROUNDS) {
      await walletPresents(driver, where, credential, round);
    }
    await walletRefuses(driver, where, credential);
    log.info(checks + " checks passed.");
    assert.ok(checks >= 19, "Only " + checks + " checks ran.");
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
    fs.rmSync(where.home, { recursive: true, force: true });
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("vc_verifier_oid4vc_wallet")
  .description("The debugger as the OpenID4VP Verifier against " +
      "rcbj/oid4vc-wallet: the wallet redeems an iya-sts pre-authorized " +
      "offer, then answers the Verifier page over direct_post and " +
      "direct_post.jwt, and refuses once; every check the page draws is " +
      "read.")
  .addOption(new Option("-u, --url <url>", "base url of the client"))
  .parse(process.argv);

if (program.opts().url) {
  baseUrl = program.opts().url;
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
