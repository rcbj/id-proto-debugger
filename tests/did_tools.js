// File: did_tools.js
//
// did-tools.html — the general-purpose DID verifier, driven through a browser.
//
// The DIDs it works on are MADE PER RUN, not hardcoded, and that matters for
// what this test is able to assert. A DID on its own proves nothing: the two
// checks worth making on that page are "does a key in this document verify
// something signed by it" and "does an origin vouch for this DID", and both
// need a real artifact. Each fixture is a DID together with a credential
// signed by the key that DID publishes, so the page's own verdict can be
// checked against a known-good answer rather than against "the document
// parsed". See generateDid() for where each comes from since iya-sts removed
// GET /did/generate.
//
// Two methods are exercised because they are genuinely different code paths in
// the wallet:
//
//   did:jwk   the identifier IS the key, so it resolves with NO network call. Its
//             credential is signed ES256 with a key this test generated, so a
//             pass cannot come from accidentally verifying against the
//             service's own key.
//   did:web   a real retrieval of /.well-known/did.json, plus the domain linkage at
//             /.well-known/did-configuration.json — the only non-circular proof
//             that an origin and a did:web are the same entity.
//
// What earns this test its keep is the pair of NEGATIVES: a document that
// resolves perfectly but whose key did NOT sign the held credential must be
// reported as not verifying, and an origin that vouches for a different DID
// must not read as linked. Both are cases where a page could look entirely
// healthy while telling the user something false.
//
// It also checks the page is INDEPENDENT of the VC workflows, which is the
// whole reason it exists separately: VC Issuance step 1 keeps its own DID pane,
// where a resolved document IS that workflow's configuration. This page must
// not write those keys — everything it stores is prefixed didtools_ — or
// resolving a DID here would silently rewrite an issuance run's configuration.
//
// Needs the STS mock and the client. No Keycloak, no walt.id.
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Builder, By, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");
const paths = require("./module_paths.js");
const browserFlags = require("./browser_flags.js");
const waitForContent = require("./wait_for.js");
const { loadPage } = require("./page_load.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "did_tools",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const ROOT = path.join(__dirname, "..");
// The wallet's own DID module, so this test resolves a DID with the same code
// the page does rather than a second reading of the same specifications.
const did = paths.requireSharedModule(
  [path.join(__dirname, "did.js"), path.join(ROOT, "client", "src", "did.js")],
  "the wallet's DID module");

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/,
    "");
var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 2000;

// --- the page, in the terms the test speaks ---------------------------------
async function setField(driver, id, value) {
  log.debug("Entering setField().");
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if (e) e.value = " +
        "arguments[1];", id, value);
  log.debug("Leaving setField().");
}
async function fieldValue(driver, id) {
  log.debug("Entering fieldValue().");
  log.debug("Leaving fieldValue().");
  return await driver.executeScript(
    "var e=document.getElementById(arguments[0]); return e ? e.value : null;",
        id);
}
async function statusText(driver, id) {
  log.debug("Entering statusText().");
  log.debug("Leaving statusText().");
  return await driver.executeScript(
    "var e=document.getElementById(arguments[0]); return e ? e.textContent : " +
        "'(no such element)';", id);
}
async function click(driver, id) {
  log.debug("Entering click().");
  await driver.findElement(By.id(id)).click();
  log.debug("Leaving click().");
}
// The status panes are filled asynchronously — a fetch, then Web Crypto. Poll
// for the content rather than sleeping on it: faster when the machine is idle
// and it does not fail when the machine is loaded. See tests/wait_for.js for
// the reasoning.
async function waitForStatus(driver, id, predicate, what) {
  log.debug("Entering waitForStatus().");
  var last = "";
  try {
    await driver.wait(async function () {
      last = String(await statusText(driver, id) || "");
      return predicate(last);
    }, waitTime * 6, what);
  } catch (e) {
    throw new Error(what + " (last status: " + JSON.stringify(last.slice(0,
                    240)) + ")");
  }
  log.debug("Leaving waitForStatus().");
  return last;
}

// THE FIXTURES: a DID, a credential signed by the key that DID publishes, and
// the document the DID resolves to.
//
// They came from iya-sts's GET /did/generate until iya-sts #594 deleted it
// ("test tooling makes its own keys"), and the job was skipped by declaration
// under rcbj/id-proto-debugger#366. Each half is now made the way that issue's
// options describe:
//
//   did:jwk   by THIS test: a P-256 key of its own, the DID made from it, and
//             an SD-JWT VC signed ES256 by it. Nothing about it needs a
//             service, which is the property the method exists to have.
//   did:web   by a REAL ISSUANCE (option 1): iya-sts advertises a did:web of
//             its own in its credential issuer metadata (`issuer_did`) and
//             offers `IdentityCredentialDid`, a configuration that signs under
//             it — the same route tests/vc_did.js drives. So the credential is
//             one a wallet would actually hold, and the document the page
//             retrieves, and the domain linkage it checks, are the service's
//             own rather than a fixture made for this job.
const RESOLVE = { allowHttp: true };
let ACCESS_TOKEN = "";

function b64u(bytes) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(bytes).toString("base64url");
}

function localDidJwk() {
  log.debug("Entering localDidJwk().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const full = pair.publicKey.export({ format: "jwk" });
  const jwk = { crv: full.crv, kty: full.kty, x: full.x, y: full.y };
  const didJwk = did.jwkToDidJwk(jwk);
  const now = Math.floor(Date.now() / 1000);
  // One real Disclosure, so this is an SD-JWT VC in the shape the wallet
  // stores rather than a bare JWT that happens to end in a tilde.
  const disclosure = b64u(JSON.stringify([b64u(crypto.randomBytes(16)),
                                          "given_name", "Dee"]));
  const digest = b64u(crypto.createHash("sha256").update(disclosure).digest());
  const header = { alg: "ES256", typ: "dc+sd-jwt", kid: didJwk + "#0" };
  const payload = {
    iss: didJwk,
    vct: "https://credentials.example.com/identity_credential",
    iat: now,
    exp: now + 3600,
    _sd_alg: "sha-256",
    _sd: [digest]
  };
  const signingInput = b64u(JSON.stringify(header)) + "." +
                       b64u(JSON.stringify(payload));
  const signature = crypto.sign("sha256", Buffer.from(signingInput),
                                { key: pair.privateKey,
                                  dsaEncoding: "ieee-p1363" });
  const local = did.resolveLocally(didJwk);
  log.debug("Leaving localDidJwk(). did=" + didJwk.slice(0, 48));
  return {
    did: didJwk,
    credential: signingInput + "." + b64u(signature) + "~" + disclosure + "~",
    document: local && local.document
  };
}

async function issuedDidWeb() {
  log.debug("Entering issuedDidWeb().");
  const meta = await common.issuerMetadata(issuerBase);
  assert.ok(meta && meta.issuer_did,
    "the issuer at " + issuerBase + " advertises no issuer_did in its " +
        "credential issuer metadata, so there is no did:web to issue under. " +
        "tests/vc_did.js asserts the same thing and will say more.");
  if (!ACCESS_TOKEN) {
    ACCESS_TOKEN = await common.holderAccessToken(issuerBase,
                                                  "did-tools-holder");
  }
  const held = await common.mintJwtVcJson(issuerBase, "IdentityCredentialDid",
                                          ACCESS_TOKEN);
  const resolved = await did.resolve(meta.issuer_did, RESOLVE);
  log.debug("Leaving issuedDidWeb(). did=" + meta.issuer_did);
  return {
    did: meta.issuer_did,
    credential: held.credential,
    document: resolved && resolved.document,
    documentUrl: (resolved && resolved.url) || did.didWebToUrl(meta.issuer_did),
    origin: new URL(issuerBase).origin
  };
}

async function generateDid(method) {
  log.debug("Entering generateDid(). method=" + method);
  const g = method === "jwk" ? localDidJwk() : await issuedDidWeb();
  assert.ok(did.isDid(g.did), "the fixture should be a DID; got " + g.did);
  assert.strictEqual(did.parse(g.did).method, method,
    "it should be a did:" + method + "; got " + g.did);
  assert.ok(g.credential && String(g.credential).indexOf("~") !== -1,
    "and a credential signed by that DID's key, or there is nothing to " +
        "verify against.");
  const issuerJwt = String(g.credential).split("~")[0];
  const iss = JSON.parse(Buffer.from(issuerJwt.split(".")[1], "base64url")
    .toString("utf8")).iss;
  assert.strictEqual(iss, g.did,
    "and that credential must name the DID as its issuer, or the page's " +
        "verdict is about somebody else. Got iss=" + iss);
  assert.ok(g.document && g.document.id === g.did,
    "and a document identifying itself as that DID.");
  log.debug("Leaving generateDid(). did=" + g.did.slice(0, 48));
  return g;
}

// A credential whose issuer is unchanged but whose SIGNATURE is not the one
// that key made. Needed because the mismatch case above never reaches the
// signature check — it stops at "this document describes a different subject",
// which is a different (and also correct) refusal. Without this case, a Verify
// Signing Key that always answered VERIFIED would pass every other assertion in
// this file: proven by mutating it and watching this test escape.
function tamperWithSignature(credential) {
  log.debug("Entering tamperWithSignature().");
  const parts = String(credential).split("~");
  const jws = parts[0].split(".");
  assert.strictEqual(jws.length, 3,
                     "the issuer-signed JWT should be a three-part JWS.");
  // Decoded to BYTES and one byte flipped, rather than one base64url CHARACTER
  // edited. The first version of this changed the last character ("A" -> "B"),
  // and that is intermittently a no-op: where a signature's length leaves
  // padding bits in the final character, several distinct characters decode to
  // the same bytes, so the "tampered" credential was byte-identical and still
  // verified. It passed on one machine and failed in the suite, which is the
  // worst way to learn it. Flipping a byte cannot be absorbed by padding.
  const sig = Buffer.from(jws[2], "base64url");
  assert.ok(sig.length > 0,
            "the signature should decode to at least one byte.");
  sig[0] = sig[0] ^ 0xff;
  jws[2] = sig.toString("base64url");
  parts[0] = jws.join(".");
  const tampered = parts.join("~");
  // A self-check, so this can never silently hand back the original again.
  assert.notStrictEqual(tampered, String(credential),
    "tampering produced an identical credential, so the negative below would " +
        "prove nothing.");
  log.debug("Leaving tamperWithSignature().");
  return tampered;
}

// The page reads the credential the VC workflows store. Planted directly,
// because what is under test is the DID verification, not issuance — which four
// other suites already cover end to end.
async function plantCredential(driver, credential) {
  log.debug("Entering plantCredential().");
  await driver.executeScript(
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_credentials', " +
        "JSON.stringify([arguments[0]]));", credential);
  log.debug("Leaving plantCredential().");
}

async function openPage(driver) {
  log.debug("Entering openPage().");
  // THROUGH loadPage() RATHER THAN driver.get(), BECAUSE THIS TEST NAVIGATES
  // TO A TARGET THE SUITE DID NOT START — the deployed site, under
  // ./remote-run-tests.sh — AND IT DOES SO TWELVE TIMES PER RUN, which is more
  // openings of a remote page than any other job here makes. A connection that
  // is established and then DROPPED (ERR_EMPTY_RESPONSE,
  // ERR_CONNECTION_RESET, ERR_HTTP2_PROTOCOL_ERROR — the shapes a CDN edge
  // produces once in a few hundred requests) is not reported by `driver.get()`
  // at all: it resolves, the tab holds Chromium's error page, and the wait for
  // #did_identifier then spends its whole budget on a document that was never
  // ours before failing with the name of one of OUR ids. That is this job on
  // 2026-09-10T18-36-09 against https://idptools.com — "did-tools.html did not
  // load its DID pane", 40s, the single red job of 301, with the three runs
  // before it green against the same pages and the page loading by hand in
  // 0.6s minutes later. loadPage() retries THAT and nothing else, and names
  // the error CODE when the target really is down. See tests/page_load.js and
  // tests/page_load_retry.js.
  await loadPage(driver, baseUrl + "/did-tools.html", "did_identifier",
                 { timeout: waitTime * 4 });
  // The pane above is static markup and is there as soon as the page parses.
  // Every control on it is wired INLINE — `onclick="didtools.resolveDid()"` —
  // so it is the bundle behind that name, not the element, that has to have
  // arrived before anything here presses a button. See waitForBundle().
  await waitForContent.waitForBundle(driver, "didtools",
    "did-tools.html's bundle", waitTime * 6);
  log.debug("Leaving openPage().");
}

// --- 1. the page itself -----------------------------------------------------
async function thePageIsLaidOutLikeTheOthers(driver) {
  log.debug("Entering thePageIsLaidOutLikeTheOthers().");
  log.info("=== The page ===");
  await openPage(driver);
  const title = await driver.getTitle();
  assert.ok(title.indexOf("DID Tools") !== -1,
            'the title should name the page; got "' + title + '"');

  const body = await driver.findElement(By.css("body")).getText();
  assert.strictEqual(body.indexOf("Issuer DID Document"), -1,
    'this is a general-purpose verifier, so the "Issuer DID Document" ' +
        'wording of the pane it came ' +
    "from must not appear on it.");

  // Every pane, including VC Tools, must answer the collapse-all toggle at the
  // top — a pane the toggle misses looks like a broken toggle rather than an
  // omission.
  const ids = ["did_fieldset", "did_members_fieldset", "did_linkage_fieldset",
      "vc_tools_fieldset"];
  for (const id of ids) {
    assert.strictEqual((await driver.findElements(By.id(id))).length, 1,
      "the page should have a " + id + " pane.");
  }
  const displays = async function () {
    log.debug("Entering displays().");
    log.debug("Leaving displays().");
    return await driver.executeScript(
      "return arguments[0].map(function (i) { var e = " +
          "document.getElementById(i); " +
      "return e ? e.style.display : '?'; }).join(',');", ids);
  };
  // Clicked in the page: the checkbox is opacity:0 behind a styled slider, so
  // Selenium refuses to click it directly, exactly as a user clicks the label.
  await driver.executeScript(
      "document.getElementById('dbg_toggle_all').click();");
  assert.strictEqual(await displays(), "none,none,none,none",
    "collapse all should hide every pane, VC Tools included.");
  await driver.executeScript(
      "document.getElementById('dbg_toggle_all').click();");
  assert.strictEqual(await displays(), "block,block,block,block",
    "and expand all should bring them all back.");

  const members = await driver.findElements(By.css("#did_members_table tr"));
  assert.ok(members.length >= 6,
    "the members table is built from DID_METADATA in did.js and should have " +
        "a row per member; got " +
    members.length);

  const href =
      await driver.findElement(By.id("vc_tools_did_link")).getAttribute("href");
  assert.ok(href.indexOf("/did-tools.html") !== -1,
    "the VC Tools pane should link to this page; got " + href);
  log.info("[page] OK — title, wording, four panes, collapse/expand all, " +
           "members table, VC Tools link.");
  log.debug("Leaving thePageIsLaidOutLikeTheOthers().");
}

// --- 2. did:jwk — resolves with no network at all ---------------------------
async function aGeneratedDidJwkResolvesAndVerifies(driver) {
  log.debug("Entering aGeneratedDidJwkResolvesAndVerifies().");
  log.info("=== A generated did:jwk ===");
  const g = await generateDid("jwk");
  await openPage(driver);
  await plantCredential(driver, g.credential);
  await openPage(driver);                       // reload so the page reads it

  await setField(driver, "did_identifier", g.did);
  await click(driver, "did_resolve_button");
  const resolved = await waitForStatus(driver, "did_status",
    function (s) { return /^Resolved|^Retrieved/.test(s); },
    "resolving the generated did:jwk produced no verdict");
  assert.ok(/no network call/.test(resolved),
    "a did:jwk IS its key, so the page must say it resolved with no network " +
        "call — implying a fetch " +
    "that never happened is the one misleading thing this pane could " +
        "say. Got: " + resolved);
  assert.strictEqual(await fieldValue(driver, "did_resolution_url"), "",
    "and there is no document URL for a did:jwk, so that field must " +
        "stay empty.");
  assert.strictEqual(await fieldValue(driver, "did_id"), g.did,
    "the members table should be populated from the resolved document.");

  // The check that means something: a key in this document really signed the
  // credential in the browser.
  await click(driver, "did_verify_button");
  const verdict = await waitForStatus(driver, "did_status",
    function (s) { return /VERIFIED|does NOT verify|could not be checked/.test(
              s); },
    "Verify Signing Key produced no verdict for the did:jwk");
  assert.ok(/^VERIFIED/.test(verdict),
    "the credential was signed with the key this did:jwk publishes, so it " +
        "must verify. Got: " + verdict);
  log.info("[did:jwk] OK — resolved locally, members populated, and its own " +
           "credential VERIFIES.");
  log.debug("Leaving aGeneratedDidJwkResolvesAndVerifies().");
  return g;
}

// --- 3. did:web — a real retrieval, and the domain linkage ------------------
async function aGeneratedDidWebResolvesVerifiesAndLinks(driver) {
  log.debug("Entering aGeneratedDidWebResolvesVerifiesAndLinks().");
  log.info("=== A generated did:web ===");
  const g = await generateDid("web");
  await openPage(driver);
  await plantCredential(driver, g.credential);
  await openPage(driver);

  await setField(driver, "did_identifier", g.did);
  await click(driver, "did_resolve_button");
  const resolved = await waitForStatus(driver, "did_status",
    function (s) { return /^Retrieved|^Resolved|^Could not/.test(s); },
    "resolving the generated did:web produced no verdict");
  assert.ok(/^Retrieved a DID Document for /.test(resolved),
    "a did:web has a document to FETCH, so the page should report a " +
        "retrieval. Got: " + resolved);
  assert.ok(/did\.json$/.test(await fieldValue(driver, "did_resolution_url")),
    "and should show the URL its method's rules derive; got " +
    (await fieldValue(driver, "did_resolution_url")));

  await click(driver, "did_verify_button");
  const verdict = await waitForStatus(driver, "did_status",
    function (s) { return /VERIFIED|does NOT verify|could not be checked/.test(
              s); },
    "Verify Signing Key produced no verdict for the did:web");
  assert.ok(/^VERIFIED/.test(verdict),
    "the credential was signed with the RS256 key this document publishes, " +
        "so it must verify. Got: " +
    verdict);

  // Retrieval by URL: the same document, fetched from a URL rather than
  // derived.
  await setField(driver, "did_resolution_url", g.documentUrl);
  await click(driver, "did_retrieve_button");
  const byUrl = await waitForStatus(driver, "did_status",
    function (s) { return /^Retrieved|^Could not/.test(s); },
              "retrieving by URL produced no verdict");
  assert.ok(/by URL rather than by resolving the DID/.test(byUrl),
    "a retrieval must say it is one: it applied the method's rules to " +
        "nothing, the caller chose the " +
    "URL. Got: " + byUrl);

  // And the linkage, which is the only non-circular proof for did:web.
  await setField(driver, "did_tools_origin", g.origin);
  await click(driver, "did_linkage_button");
  const linked = await waitForStatus(driver, "did_linkage_status",
    function (s) { return /^LINKED|^NOT LINKED|^Could not/.test(s); },
    "Verify Linkage produced no verdict");
  assert.ok(/^LINKED:/.test(linked),
    "the STS publishes a Domain Linkage Credential for its own DID at its " +
        "own origin, so this must " +
    "come back linked. Got: " + linked);
  const table = await driver.executeScript(
    "return document.getElementById('did_linkage_table').innerHTML;");
  assert.ok(/Linked DID/.test(table) && /Issuer signature/.test(table),
    "and the per-check table should be shown, so a reader can see WHICH " +
        "checks passed.");
  log.info("[did:web] OK — retrieved, VERIFIED, retrievable by URL, and " +
           "LINKED to its origin.");
  log.debug("Leaving aGeneratedDidWebResolvesVerifiesAndLinks().");
  return g;
}

// --- 4. the negatives, which is where the value is -------------------------
async function theNegatives(driver, jwkDid, webDid) {
  log.debug("Entering theNegatives().");
  log.info("=== The negatives ===");

  // (a) a document that resolves perfectly, against a credential its key did
  // not
  //     sign. The page must say so. If this passes as VERIFIED the check is
  //     decorative, and every other assertion above becomes meaningless.
  await openPage(driver);
  await plantCredential(driver,
                        webDid.credential);   // signed by the did:web key
  await openPage(driver);
  await setField(driver, "did_identifier",
                 jwkDid.did);   // resolve a DIFFERENT DID
  await click(driver, "did_resolve_button");
  await waitForStatus(driver, "did_status",
                      function (s) { return /^Resolved|^Retrieved/.test(s); },
    "the did:jwk did not resolve for the mismatch case");
  await click(driver, "did_verify_button");
  const mismatch = await waitForStatus(driver, "did_status",
    function (s) { return /VERIFIED|does NOT verify|different subjects|No key in this document/.test(s); },
    "Verify Signing Key produced no verdict for the mismatch case");
  assert.ok(!/^VERIFIED/.test(mismatch),
    "this document's key did NOT sign the held credential, so the page must " +
        "not report it verified. " +
    "Got: " + mismatch);
  log.info("[negative] OK — a document whose key did not sign the credential " +
           "is not reported verified: " +
           JSON.stringify(mismatch.slice(0, 90)));

  // (a2) the same DID, so no subject mismatch to stop at, but a signature that
  // key
  //      did not make. This is the case that reaches the signature check
  //      itself.
  await openPage(driver);
  await plantCredential(driver, tamperWithSignature(webDid.credential));
  await openPage(driver);
  await setField(driver, "did_identifier", webDid.did);
  await click(driver, "did_resolve_button");
  await waitForStatus(driver, "did_status",
                      function (s) { return /^Retrieved|^Resolved/.test(s); },
    "the did:web did not resolve for the tampered-signature case");
  await click(driver, "did_verify_button");
  const tampered = await waitForStatus(driver, "did_status",
    function (s) { return /VERIFIED|does NOT verify|could not be checked/.test(
              s); },
    "Verify Signing Key produced no verdict for the tampered credential");
  assert.ok(/does NOT verify/.test(tampered),
    "the issuer and the document agree, but the signature is not the one " +
        "that key made, so the page " +
    "must report that it does not verify. This is the assertion that catches " +
        "a check which always " +
    "answers VERIFIED. Got: " + tampered);
  log.info("[negative] OK — a tampered signature under the RIGHT issuer is " +
           "reported as not verifying.");

  // (b) an origin that vouches for a DIFFERENT DID must not read as linked.
  // Without
  //     this, "linked" would be a property of the file existing rather than of
  //     what it says.
  await setField(driver, "did_identifier", jwkDid.did);
  await setField(driver, "did_tools_origin", webDid.origin);
  await click(driver, "did_linkage_button");
  const other = await waitForStatus(driver, "did_linkage_status",
    function (s) { return /^LINKED|^NOT LINKED|^Could not/.test(s); },
    "Verify Linkage produced no verdict for the wrong-DID case");
  assert.ok(/^NOT LINKED/.test(other),
    "that origin links its own did:web, not this did:jwk, so it must not " +
        "read as linked. Got: " + other);
  log.info("[negative] OK — an origin that links another DID does not read " +
           "as linking this one.");

  // (c) something that is not a DID at all.
  await setField(driver, "did_identifier", "not-a-did");
  await click(driver, "did_resolve_button");
  const notADid = await waitForStatus(driver, "did_status",
    function (s) { return /not a DID|Could not/.test(s); },
              "a non-DID produced no complaint");
  assert.ok(/not a DID/.test(notADid), "it should say so plainly. Got: " +
            notADid);

  // (d) a URL that answers nothing.
  await setField(driver, "did_resolution_url", issuerBase + DELIBERATE_404);
  await click(driver, "did_retrieve_button");
  const missing = await waitForStatus(driver, "did_status",
    function (s) { return /Could not retrieve|answered HTTP/.test(s); },
    "a missing document produced no complaint");
  assert.ok(/answered HTTP 404/.test(missing),
    "and a missing document should name the status it got. Got: " + missing);
  log.info("[negative] OK — a non-DID and an unreachable URL are both " +
           "reported.");
  log.debug("Leaving theNegatives().");
}

// --- 5. independence from the VC workflows --------------------------------
async function itDoesNotDisturbTheWorkflow(driver, webDid) {
  log.debug("Entering itDoesNotDisturbTheWorkflow().");
  log.info("=== Independence from the VC workflows ===");
  // Seed the issuance workflow's own DID configuration, as its pane would.
  await openPage(driver);
  await driver.executeScript(
    "localStorage.setItem('did_identifier', arguments[0]);" +
    "localStorage.setItem('did_id', arguments[0]);" +
    "localStorage.setItem('did_verificationMethod', 'seeded-by-the-workflow');",
        webDid.did);
  const before = await driver.executeScript(
    "return ['did_identifier','did_id','did_verificationMethod']" +
    ".map(function (k) { return k + '=' + localStorage.getItem(k); " +
        "}).join('|');");

  await openPage(driver);
  await setField(driver, "did_identifier", webDid.did);
  await click(driver, "did_resolve_button");
  await waitForStatus(driver, "did_status",
                      function (s) { return /^Retrieved|^Resolved/.test(s); },
    "the did:web did not resolve for the independence check");
  await click(driver, "did_clear_button");
  await driver.sleep(300);

  const after = await driver.executeScript(
    "return ['did_identifier','did_id','did_verificationMethod']" +
    ".map(function (k) { return k + '=' + localStorage.getItem(k); " +
        "}).join('|');");
  assert.strictEqual(after, before,
    "resolving and clearing on this page must leave the ISSUANCE WORKFLOW's " +
        "DID configuration " +
    "untouched — step 1 keeps its own pane, where a resolved document IS " +
        "that workflow's " +
    "configuration. Before: " + before + "  After: " + after);

  const mine = await driver.executeScript(
    "var out = []; for (var i = 0; i < localStorage.length; i++) { var k = " +
        "localStorage.key(i);" +
    " if (k.indexOf('didtools_') === 0) out.push(k); } return out.sort();");
  assert.ok(mine.length >= 2,
    "and this page should keep its own state under didtools_* keys; found " +
        JSON.stringify(mine));
  log.info("[independence] OK — the workflow's did_* keys are untouched; " +
           "this page uses " +
           mine.length + " didtools_* keys.");
  log.debug("Leaving itDoesNotDisturbTheWorkflow().");
}

// --- 6. the layout rule these panes have to obey --------------------------
async function panesContainTheirContent(driver, webDid) {
  log.debug("Entering panesContainTheirContent().");
  log.info("=== The tables stay inside their panes ===");
  await openPage(driver);
  await setField(driver, "did_identifier", webDid.did);
  await click(driver, "did_resolve_button");
  await waitForStatus(driver, "did_status",
                      function (s) { return /^Retrieved|^Resolved/.test(s); },
    "the did:web did not resolve for the layout check");
  await setField(driver, "did_tools_origin", webDid.origin);
  await click(driver, "did_linkage_button");
  await waitForStatus(driver, "did_linkage_status",
                      function (s) { return /^LINKED|^NOT LINKED/.test(s); },
    "the linkage did not settle for the layout check");

  // A DID document is nothing but unbreakable base64url: an RSA modulus, a
  // multibase key, DID URLs. Everything it shows has to WRAP, or the table
  // walks out of its pane — which is what these tables are given a fixed layout
  // and a capped value column for.
  const geometry = await driver.executeScript(
    "return [['did_fieldset','did_document_table'],['did_linkage_fieldset'," +
        "'did_linkage_table']]" +
    ".map(function (pair) {" +
    "  var pane = document.getElementById(pair[0]);" +
    "  var host = document.getElementById(pair[1]);" +
    "  var table = host && host.querySelector('table');" +
    "  if (!pane || !table) return { id: pair[1], missing: true };" +
    "  return { id: pair[1], missing: false," +
    "           past: Math.round(table.getBoundingClientRect().right - " +
        "pane.getBoundingClientRect().right)," +
    "           scrolls: host.scrollWidth > host.clientWidth + 2 };" +
    "});");
  geometry.forEach(function (g) {
    assert.strictEqual(g.missing, false, g.id +
                       " rendered no table to measure.");
    assert.ok(g.past <= 2,
      g.id + " extends " + g.past +
          "px past the right edge of its pane. These tables are given " +
      "table-layout:fixed and a capped value column precisely so a long key " +
          "wraps instead of " +
      "widening them.");
    assert.strictEqual(g.scrolls, false, g.id +
                       " scrolls sideways inside its pane.");
  });
  log.info("[layout] OK — both tables stay inside their panes.");
  log.debug("Leaving panesContainTheirContent().");
}

// The one resource this test deliberately asks for and expects to fail: the "a
// URL that answers nothing" negative. Chrome logs a failed load as SEVERE, so
// it is filtered by its exact path — not by status, so an unexpected 404
// anywhere else still fails the run.
const DELIBERATE_404 = "/no-such-did-document.json";

async function severeErrors(driver) {
  log.debug("Entering severeErrors().");
  const entries = await driver.manage().logs().get(logging.Type.BROWSER);
  log.debug("Leaving severeErrors().");
  return entries.filter(function (e) {
    if (!e.level || e.level.name !== "SEVERE") return false;
    if (/favicon|manifest/i.test(e.message)) return false;
    // A load the browser abandoned because its own configuration changed
    // under it is not a page error either. See browser_flags.js.
    if (browserFlags.isTransientLoadError(e.message)) return false;
    if (e.message.indexOf(DELIBERATE_404) !== -1) return false;
    return true;
  }).map(function (e) { return e.message; });
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the DID Tools checks against " + baseUrl +
           " with the STS at " + issuerBase);

  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const options = new chrome.Options().setLoggingPrefs(prefs)
    .addArguments("--window-size=1500,1400");
  if (headless) {
    options.addArguments("--headless=new", "--no-sandbox",
                         "--disable-dev-shm-usage");
  }
  // This page is all Web Crypto (it verifies signatures), and it fetches this
  // suite's STS on loopback. Both need the flags: crypto.subtle does not exist
  // on a plain-HTTP DNS-name origin, and a private-network fetch from a
  // deployed https page is blocked or preflighted. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await thePageIsLaidOutLikeTheOthers(driver);
    const jwkDid = await aGeneratedDidJwkResolvesAndVerifies(driver);
    const webDid = await aGeneratedDidWebResolvesVerifiesAndLinks(driver);
    await theNegatives(driver, jwkDid, webDid);
    await itDoesNotDisturbTheWorkflow(driver, webDid);
    await panesContainTheirContent(driver, webDid);

    const errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0,
      "the page logged browser errors:\n" + errors.join("\n"));
    log.info("[browser] OK — no console errors across the page.");
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("did_tools")
  .description("Exercise did-tools.html against a did:jwk of its own and " +
      "iya-sts's did:web.")
  .addOption(new Option("-u, --url <url>",
      "base url of the debugger under test"))
  .addOption(new Option("--no-headless", "run with a visible browser"))
  .parse(process.argv);
const opts = program.opts();
if (opts.url) baseUrl = String(opts.url).replace(/\/+$/, "");
headless = opts.headless !== false;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
