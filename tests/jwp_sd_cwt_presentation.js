// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: jwp_sd_cwt_presentation.js
//
// ---------------------------------------------------------------------------
// The wallet's presentation pages, in Chrome, presenting a JSON Proof Token
// and an SD-CWT (#478, both drafts), with what they build checked by parties
// that share no code with the wallet. The credentials are handed to the
// wallet as issuance leaves one in storage, the request to step 1 by value;
// nothing is posted.
//
//   1. the SU-ES256 JPT of draft-ietf-jose-json-proof-algorithms-15
//      Appendix A.1, with its holder key, asked for given_name: step 2
//      discloses that slot, the Presentation Header carries the Verifier's
//      Client Identifier as aud and the request's nonce, and node's crypto
//      — over JPA's presentation internal representation rebuilt here —
//      verifies the issuer's, the ephemeral key's and the holder's
//      signatures;
//   2. a BBS JPT signed in the test by Digital Bazaar's released
//      bbs-signatures, its kid a did:jwk of the BLS12-381 key, asked for
//      two of four claims: Digital Bazaar's verifyProof accepts the
//      wallet's presentation proof for exactly those slots;
//   3. the issued SD-CWT of draft-ietf-spice-sd-cwt-09 (the working
//      group's encoding, Appendix C's holder key), asked for claims 501
//      and region: the Key Binding Token carries only those disclosures,
//      aud and the nonce as cnonce, and @auth0/cose verifies both the
//      issuer's COSE_Sign1 and the holder's.
//
// Needs only the client.
// ---------------------------------------------------------------------------

const { Builder, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
const waitForContent = require("./wait_for.js");
const { waitForStatus, waitForValue } = require("./wait_for");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "jwp_sd_cwt_presentation",
    level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var stepWait = waitTime * 4;

const VERIFIER = "https://verifier.example/response";
const CLIENT_ID = "redirect_uri:" + VERIFIER;
const JWP_FX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures",
  "jwp_jpa15_vectors.json"), "utf8"));
const CWT_FX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures",
  "sd_cwt_09_vectors.json"), "utf8"));

function b(s) {
  log.debug("Entering b().");
  log.debug("Leaving b().");
  return s === "_" ? Buffer.alloc(0) : Buffer.from(s, "base64url");
}

function pubOf(jwk) {
  log.debug("Entering pubOf().");
  var j = Object.assign({}, jwk);
  delete j.d;
  log.debug("Leaving pubOf().");
  return j;
}

function requestQuery(format, claims, nonce) {
  log.debug("Entering requestQuery(). " + format);
  var dcql = { credentials: [{ id: "cred", format: format,
    claims: claims.map(function (p) {
      return { path: p };
    }) }] };
  var q = new URLSearchParams({ client_id: CLIENT_ID,
    response_type: "vp_token", response_mode: "direct_post",
    response_uri: VERIFIER, nonce: nonce, state: "st-" + nonce,
    dcql_query: JSON.stringify(dcql),
    client_metadata: JSON.stringify({ vp_formats_supported: {} }) });
  log.debug("Leaving requestQuery().");
  return q.toString();
}

async function presentThroughThePages(driver, held, holderPub, holderPriv,
                                      query) {
  log.debug("Entering presentThroughThePages().");
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html");
  await waitForContent.waitForPageBundle(driver, "step 1");
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "if (arguments[1]) localStorage.setItem('sdjwtvc_holder_jwk', " +
    "arguments[1]);" +
    "if (arguments[2]) localStorage.setItem('sdjwtvc_holder_private_jwk', " +
    "arguments[2]);",
    held, holderPub ? JSON.stringify(holderPub) : "",
    holderPriv ? JSON.stringify(holderPriv) : "");
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html?" + query);
  await waitForContent.waitForPageBundle(driver, "step 1, with the request");
  await waitForStatus(driver, "vp_request_status", function (s) {
    return /Request read/.test(s);
  }, "step 1 should read the request", stepWait);
  await driver.executeScript(
    "var b=document.getElementById('vp_continue_button'); if (b) b.click();");
  await driver.wait(until.urlContains("vc-presentation-2.html"), stepWait,
                    "Continue should reach step 2");
  await waitForContent.waitForPageBundle(driver, "step 2");
  var text;
  try {
    text = await waitForValue(driver, "vp_presentation", function (v) {
      return v.trim().length > 40;
    }, "step 2 should build a presentation", stepWait);
  } catch (e) {
    var said = await driver.executeScript(
      "var e=document.getElementById('vp_present_status');" +
      "return e ? e.textContent : '(no status)';");
    log.debug("Leaving presentThroughThePages(). Step 2 said: " + said);
    throw new Error(e.message + " — step 2 says: " + said);
  }
  log.debug("Leaving presentThroughThePages().");
  return text.trim();
}

// --- the witness for SU: JPA section 7.2 rebuilt here, node's crypto -----
function u64(n) {
  log.debug("Entering u64().");
  var x = Buffer.alloc(8);
  x.writeBigUInt64BE(BigInt(n));
  log.debug("Leaving u64().");
  return x;
}

function internalRep(ph, ih, slots, proofs) {
  log.debug("Entering internalRep().");
  var p = [Buffer.from([0x84, 0x5b]), u64(ph.length), ph,
           Buffer.from([0x5b]), u64(ih.length), ih,
           Buffer.from([0x9b]), u64(slots.length)];
  slots.forEach(function (s) {
    if (s === null) {
      p.push(Buffer.from([0xf6]));
    } else {
      p.push(Buffer.from([0x5b]), u64(s.length), s);
    }
  });
  p.push(Buffer.from([0x9b]), u64(proofs.length));
  proofs.forEach(function (q) {
    p.push(Buffer.from([0x5b]), u64(q.length), q);
  });
  log.debug("Leaving internalRep().");
  return Buffer.concat(p);
}

function es256(jwk, data, sig) {
  log.debug("Entering es256().");
  log.debug("Leaving es256().");
  return nodeCrypto.verify("sha256", data, { key: nodeCrypto.createPublicKey(
    { key: pubOf(jwk), format: "jwk" }), dsaEncoding: "ieee-p1363" }, sig);
}

async function suJpt(driver) {
  log.debug("Entering suJpt().");
  var su = JWP_FX.su;
  var nonce = "n-" + nodeCrypto.randomBytes(8).toString("hex");
  var built = await presentThroughThePages(driver, su.issued,
    pubOf(su.holderKey), su.holderKey,
    requestQuery("jpt", [["given_name"]], nonce));
  var P = built.split(".");
  assert.strictEqual(P.length, 4, "SU: a presented JPT has four parts");
  var ph = JSON.parse(b(P[0]).toString());
  assert.deepStrictEqual([ph.alg, ph.aud, ph.nonce],
                         ["SU-ES256", CLIENT_ID, nonce],
                         "SU: the Presentation Header's alg, aud and nonce");
  var ih = b(P[1]);
  var h = JSON.parse(ih.toString());
  var slots = P[2].split("~").map(function (s) {
    return s === "" ? null : b(s);
  });
  var disclosed = [];
  slots.forEach(function (s, i) {
    if (s !== null) disclosed.push(h.claims[i]);
  });
  assert.deepStrictEqual(disclosed, ["given_name"],
                         "SU: only the asked-for slot is disclosed");
  var pr = P[3].split("~").map(b);
  assert.strictEqual(pr.length, 3, "SU: issuer, one payload, holder");
  assert.ok(es256(su.issuerKey, ih, pr[0]), "SU: the issuer's signature");
  assert.ok(es256(h.iek, slots[3], pr[1]), "SU: the payload's signature");
  assert.ok(es256(h.hpk, internalRep(b(P[0]), ih, slots, pr.slice(0, 2)),
                  pr[2]), "SU: the holder's signature over JPA 7.2");
  log.info("PASS SU-ES256 JPT (the draft's own): one slot, aud and nonce in " +
           "the Presentation Header; node's crypto verifies all three " +
           "signatures.");
  log.debug("Leaving suJpt().");
}

async function bbsJpt(driver) {
  log.debug("Entering bbsJpt().");
  var theirs = await import("@digitalbazaar/bbs-signatures");
  var suite = theirs.CIPHERSUITES.BLS12381_SHA256;
  var kp = await theirs.generateKeyPair({ ciphersuite: suite });
  var pub = { kty: "OKP", crv: "BLS12381G2",
              x: Buffer.from(kp.publicKey).toString("base64url") };
  var did = "did:jwk:" +
    Buffer.from(JSON.stringify(pub)).toString("base64url");
  var names = ["iss", "given_name", "family_name", "age_over_18"];
  var values = ["https://issuer.example", "Alice", "Liddell", true];
  var ih = Buffer.from(JSON.stringify({ alg: "BBS", claims: names,
                                        kid: did + "#0" }));
  var msgs = values.map(function (v) {
    return Buffer.from(JSON.stringify(v));
  });
  var sig = await theirs.sign({ secretKey: kp.secretKey,
    publicKey: kp.publicKey, header: ih, messages: msgs, ciphersuite: suite });
  var issued = [ih, msgs.map(function (m) {
    return m.toString("base64url");
  }).join("~"), Buffer.from(sig).toString("base64url")].map(function (x) {
    return typeof x === "string" ? x : x.toString("base64url");
  }).join(".");
  var nonce = "n-" + nodeCrypto.randomBytes(8).toString("hex");
  var built = await presentThroughThePages(driver, issued, null, null,
    requestQuery("jpt", [["given_name"], ["age_over_18"]], nonce));
  var P = built.split(".");
  var slots = P[2].split("~");
  var idx = [];
  var dm = [];
  slots.forEach(function (s, i) {
    if (s !== "") {
      idx.push(i);
      dm.push(b(s));
    }
  });
  assert.deepStrictEqual(idx, [1, 3], "BBS: given_name and age_over_18");
  assert.strictEqual(JSON.parse(b(P[0]).toString()).nonce, nonce,
                     "BBS: the request's nonce");
  assert.ok(await theirs.verifyProof({ publicKey: kp.publicKey,
    proof: b(P[3]), header: ih, presentationHeader: b(P[0]),
    disclosedMessages: dm, disclosedMessageIndexes: idx, ciphersuite: suite }),
    "BBS: Digital Bazaar verifies the wallet's presentation proof");
  log.info("PASS BBS JPT (signed by Digital Bazaar): two of four slots; its " +
           "verifyProof accepts the wallet's proof.");
  log.debug("Leaving bbsJpt().");
}

async function sdCwtKbt(driver) {
  log.debug("Entering sdCwtKbt().");
  var cose = require("@auth0/cose");
  var paths = require("./module_paths.js");
  var cbor = paths.requireSharedModule([path.join(__dirname, "..", "client",
    "src", "cbor.js")], "client/src/cbor.js");
  var mdoc = paths.requireSharedModule([path.join(__dirname, "..", "client",
    "src", "mdoc.js")], "client/src/mdoc.js");
  var held = Buffer.from(CWT_FX.cbor.issuer_cwt, "hex").toString("base64url");
  var hk = CWT_FX.holderKey;
  var nonce = "n-" + nodeCrypto.randomBytes(8).toString("hex");
  var built = await presentThroughThePages(driver, held, pubOf(hk), hk,
    requestQuery("sd-cwt", [["501"], ["503", "region"]], nonce));
  var raw = b(built);
  var kbt = cbor.decode(new Uint8Array(raw));
  var prot = cbor.decode(kbt.value[0]);
  assert.strictEqual(prot.get(16), 294, "SD-CWT: the KBT's typ is 294");
  var payload = cbor.decode(kbt.value[2]);
  assert.strictEqual(payload.get(3), CLIENT_ID, "SD-CWT: aud is the " +
                     "Verifier's Client Identifier");
  assert.strictEqual(Buffer.from(payload.get(39)).toString(), nonce,
                     "SD-CWT: cnonce is the request's nonce");
  var inner = prot.get(13);
  var disclosures = inner.value[1].get(17).map(function (d) {
    return cbor.decode(d);
  });
  assert.deepStrictEqual(disclosures.map(function (d) {
    return d[2];
  }).sort(), [501, "region"].sort(), "SD-CWT: exactly the asked-for " +
    "disclosures went");
  var ipk = nodeCrypto.createPublicKey({ key: pubOf(CWT_FX.issuerKey),
                                         format: "jwk" });
  var hpk = nodeCrypto.createPublicKey({ key: pubOf(hk), format: "jwk" });
  await cose.Sign1.decode(Buffer.from(mdoc.encode(inner))).verify(ipk);
  // The KBT is signed ESP256 (-9, RFC 9864's fully-specified ES256), which
  // @auth0/cose 1.0.2 predates; node verifies it over the Sig_structure
  // (RFC 9052 section 4.4) built here.
  assert.strictEqual(prot.get(1), -9, "SD-CWT: the KBT is signed ESP256");
  var toBeSigned = mdoc.encode(["Signature1", kbt.value[0],
                                new Uint8Array(0), kbt.value[2]]);
  assert.ok(nodeCrypto.verify("sha256", Buffer.from(toBeSigned),
    { key: hpk, dsaEncoding: "ieee-p1363" }, Buffer.from(kbt.value[3])),
    "SD-CWT: node verifies the KBT by Appendix C's holder key");
  log.info("PASS SD-CWT (the draft's own): a KBT with aud and cnonce and " +
           "only the two asked-for disclosures; @auth0/cose verifies the " +
           "issuer's COSE_Sign1, node the holder's ESP256 KBT.");
  log.debug("Leaving sdCwtKbt().");
}

async function test() {
  log.debug("Entering test().");
  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await suJpt(driver);
    await bbsJpt(driver);
    await sdCwtKbt(driver);
    log.info("jwp_sd_cwt_presentation: all checks passed.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                             "base url of the debugger's client"));
program.addOption(new Option("-h, --headless <headless>",
                             "run Chrome headless (default true)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) {
  baseUrl = opts.url;
  log.info("Setting url to " + baseUrl);
}
if (opts.headless === "false") headless = false;

test().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
