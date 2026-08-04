// File: ldp_vc_refresh.js
//
// ---------------------------------------------------------------------------
// Refreshing an ldp_vc / bbs-2023 credential — OID4VCI section 14.5,
// "Refreshing Issued Credentials", and its section 14.3 alternative.
//
// A refresh is not one mechanism but two calls, and 14.5 is explicit that
// neither is OID4VCI's invention:
//
//   1. grant_type=refresh_token at the token endpoint — plain RFC 6749
//      section 6, nothing credential-specific about it;
//   2. the SAME Credential Request step 2 makes, with the new access token.
//
// That second point is why client/src/vci_wallet.js exists: on the wire a
// refresh is not a different request, so issuance step 2 and step 4 must not be
// two implementations of it. This test drives THAT module for both calls rather
// than rebuilding the request — a re-implementation here would pass while the
// pages were broken, which is exactly how this format's step 2 failed.
//
// Section 14.3 is the reason the refresh half is optional: the Credential
// Endpoint may simply be asked again with an access token that is still valid,
// and after the pre-authorized code grant that is the only route left, since
// that grant issues no refresh token. Both are covered below.
//
// What is FORMAT-specific here, and the reason this test exists beside the
// dc+sd-jwt and jwt_vc_json ones:
//
//   * holder binding is credentialSubject.id (a did:jwk), NOT cnf.jwk — a W3C
//     credential has no cnf claim, so "same key ⇒ same subject id" is the only
//     way to tell a replacement from a second credential;
//   * the refreshed credential is a JSON OBJECT, and the wallet has to store it
//     as a string. That read was broken: step 2 reported "the issuer answered,
//     but the response carries no credential" for a response this suite had
//     already asserted was correct. Step 4 calls the same two functions.
//
// tests/ldp_vc_issuance.js covers the first issuance; this covers what happens
// to a credential the wallet already holds. Needs only the STS mock.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "ldp_vc_refresh", level: appconfig.logLevel || "info" });

if (typeof globalThis.btoa !== "function") {
  globalThis.btoa = function (s) { return Buffer.from(s, "binary").toString("base64"); };
  globalThis.atob = function (s) { return Buffer.from(s, "base64").toString("binary"); };
}

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
const ROOT = path.join(__dirname, "..");
const paths = require("./module_paths.js");
const stsSuite = paths.requireSharedModule(
  [path.join(__dirname, "sts_bbs2023.js"), path.join(ROOT, "sts", "bbs2023.js")],
  "the STS's bbs-2023 cryptosuite");
// The wallet's own module — the one both issuance step 2 and step 4 use. Driving
// it is the point: it is the code under test, not a stand-in for it.
const wallet = paths.requireSharedModule(
  [path.join(__dirname, "vci_wallet.js"), path.join(ROOT, "client", "src", "vci_wallet.js")],
  "the wallet's Credential Request/Response module");
const sdJwtVc = paths.requireSharedModule(
  [path.join(__dirname, "sd_jwt_vc.js"), path.join(ROOT, "client", "src", "sd_jwt_vc.js")],
  "the wallet's credential parsing module");

const LDP_CONFIG_ID = process.env.OID4VCI_LDP_CONFIG_ID || "IdentityCredentialLdpVc";
const CLIENT_ID = common.WALLET_CLIENT_ID;

// --- the two calls a refresh is made of ------------------------------------

// OID4VCI 14.5 call 1. Plain RFC 6749 section 6.
async function refreshTokens(refreshToken) {
  log.debug("Entering refreshTokens().");
  const r = await common.httpJson(issuerBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token", refresh_token: refreshToken, client_id: CLIENT_ID
    }).toString()
  });
  log.debug("Leaving refreshTokens(). HTTP " + r.status);
  return r;
}

// OID4VCI 14.5 call 2 — and, with an unchanged access token, 14.3. Built with
// the WALLET's module at every step: its key pair, its c_nonce, its proof of
// possession, its request body, its reading of the response.
async function requestCredential(meta, accessToken, holderKey, configurationId) {
  log.debug("Entering requestCredential().");
  const nonce = await wallet.fetchNonce(meta.nonce_endpoint || "");
  const proof = await wallet.signProof(holderKey, {
    clientId: CLIENT_ID, credentialIssuer: meta.credential_issuer, nonce: nonce.nonce
  });
  const body = wallet.buildRequestBody({
    credentialConfigurationId: configurationId || LDP_CONFIG_ID, proofs: [proof]
  });
  const r = await fetch(meta.credential_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + accessToken },
    body: JSON.stringify(body)
  });
  const text = await r.text();
  const response = await wallet.readCredentialResponse(r, text, null);
  log.debug("Leaving requestCredential(). HTTP " + response.statusCode);
  return response;
}

// The credential as the wallet would store it, via the same two functions step 4
// calls (vc_issuance_4.js reads extractCredential at the reissue and deferred
// paths and allCredentials when it keeps the result).
function walletReads(response) {
  const stored = wallet.extractCredential(response.body);
  return { stored: stored, all: wallet.allCredentials(response.body),
           parsed: stored ? sdJwtVc.parseCredential(stored) : null };
}

function subjectIdOf(credential) {
  return ((credential || {}).credentialSubject || {}).id || "";
}

// Wait until the issuer's clock would stamp a different second.
//
// This is not a sleep-and-hope: it is load-bearing, and the reason is a genuine
// property of this format. BBS Sign is DETERMINISTIC — unlike ProofGen, it draws
// no randomness — and an ldp_vc carries no salts. So the credential is a pure
// function of (claims, holder key, timestamps), and the only part of that which
// varies between two requests is validFrom/validUntil/proof.created, stamped to
// the second. Two refreshes inside one second are therefore BYTE-IDENTICAL.
//
// dc+sd-jwt hides this: a fresh random salt per Disclosure makes every issuance
// differ whatever the clock says. That is why this wait belongs in this file and
// not in the SD-JWT one.
function waitPastSecondBoundary() {
  log.debug("Entering waitPastSecondBoundary().");
  var start = Math.floor(Date.now() / 1000);
  return new Promise(function (resolve) {
    (function poll() {
      if (Math.floor(Date.now() / 1000) > start) {
        log.debug("Leaving waitPastSecondBoundary().");
        return resolve();
      }
      setTimeout(poll, 50);
    })();
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("Running ldp_vc refresh against " + issuerBase);
  const meta = await common.issuerMetadata(issuerBase);
  assert.ok(meta && meta.credential_endpoint,
    "no credential issuer metadata at " + issuerBase + ". Start the STS mock.");
  assert.ok((meta.credential_configurations_supported || {})[LDP_CONFIG_ID],
    "this issuer offers no ldp_vc configuration \"" + LDP_CONFIG_ID + "\".");

  // --- the credential the wallet already holds ------------------------------
  log.info("=== The credential in hand ===");
  const initial = await common.httpJson(issuerBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password", username: "ldp-refresh-holder", password: "x",
      client_id: CLIENT_ID, scope: "openid"
    }).toString()
  });
  assert.strictEqual(initial.status, 200, "the mock should issue a token set: " + initial.raw);
  const firstRefreshToken = (initial.body || {}).refresh_token;
  assert.ok(firstRefreshToken,
    "a refresh needs a refresh token to start from, and section 14.5's first call is exactly the " +
    "RFC 6749 grant that consumes one. Without it only the 14.3 route below is possible.");

  // One holder key pair, kept, because reusing it is what distinguishes a
  // REPLACEMENT from a second credential for this format.
  const boundKey = await wallet.generateHolderKeyPair();
  const first = await requestCredential(meta, initial.body.access_token, boundKey);
  assert.ok(first.ok, "the first issuance should succeed: HTTP " + first.statusCode + " " +
    String(first.raw).slice(0, 200));
  const held = walletReads(first);
  assert.ok(held.stored, "the wallet should be able to store the first credential.");
  assert.strictEqual(held.parsed.format, "ldp_vc", "and read it as ldp_vc.");
  const heldCredential = JSON.parse(held.stored);
  const heldSubjectId = subjectIdOf(heldCredential);
  assert.ok(/^did:jwk:/.test(heldSubjectId),
    "for ldp_vc the holder is named by credentialSubject.id as a did:jwk. Got: " + heldSubjectId);
  assert.ok(!(held.parsed.payload || {}).cnf,
    "and NOT by cnf.jwk — a W3C credential has no cnf claim.");

  // Step 4 has to resolve that binding to an actual key, because everything it
  // offers depends on it: whether the credential is reported as bound, whether
  // "reuse the bound key" is available, and whether a refresh is a replacement
  // or a second credential. Reading payload.cnf — which is all it did — yields
  // null for this format, so an ldp_vc showed as unbound and every refresh was
  // silently forced onto a new key.
  const bound = sdJwtVc.boundHolderJwk(held.parsed);
  assert.ok(bound, "step 4 must resolve the holder key for an ldp_vc, not report it as unbound. It is " +
    "in credentialSubject.id as a did:jwk; there is no cnf claim to read.");
  assert.strictEqual(bound.kty, boundKey.publicJwk.kty, "and resolve it to a key of the right type.");
  assert.strictEqual(bound.crv, boundKey.publicJwk.crv, "on the right curve.");
  assert.strictEqual(bound.x, boundKey.publicJwk.x,
    "and it must be THE key the wallet proved possession of — the coordinates step 4 compares against " +
    "the private half to decide whether 'reuse the bound key' is honest.");
  assert.strictEqual(bound.y, boundKey.publicJwk.y, "both coordinates.");
  assert.strictEqual(sdJwtVc.bindingMemberName(held.parsed), "credentialSubject.id",
    "and the pane must NAME it correctly: saying cnf.jwk on a credential that has no cnf claim is how " +
    "a pane tells the user something false while looking right.");

  // The other two lines of the same pane, which failed the same way: reading
  // only the SD-JWT spelling turns DIFFERENCE into ABSENCE, and absence is the
  // reassuring answer. This credential has a type and expires in a month; the
  // pane said it had neither.
  assert.strictEqual(sdJwtVc.typeMemberName(held.parsed), "type",
    "a W3C credential is identified by a type array, not a vct.");
  assert.ok(sdJwtVc.credentialLabel(held.parsed),
    "and the pane must show that type rather than an em dash — reading payload.vct gives nothing here.");
  assert.notStrictEqual(sdJwtVc.credentialLabel(held.parsed), "credential",
    "and something more specific than the generic fallback: " +
    JSON.stringify(held.parsed.types));

  const window_ = sdJwtVc.validityWindowOf(held.parsed);
  assert.strictEqual(window_.notBeforeMember, "validFrom", "an ldp_vc's window is validFrom/validUntil.");
  assert.strictEqual(window_.expiresMember, "validUntil", "not nbf/exp, which it does not carry.");
  assert.ok(window_.expires,
    "and the pane must find an expiry. Reading payload.exp gives null and the pane then says \"no exp " +
    "claim, so it does not expire on its own\" about a credential that expires in a month — wrong, and " +
    "wrong in the direction that stops someone refreshing it.");
  assert.strictEqual(window_.expires, Math.floor(Date.parse(heldCredential.validUntil) / 1000),
    "resolved from the credential's own validUntil, as seconds since the epoch so the pane formats " +
    "every format's dates the same way.");
  assert.ok(window_.expires > window_.notBefore, "and a window that runs forwards.");
  log.info("[pane] OK — type \"" + sdJwtVc.credentialLabel(held.parsed) + "\" (" +
    sdJwtVc.typeMemberName(held.parsed) + "), expiring " + heldCredential.validUntil + " (" +
    window_.expiresMember + ").");
  log.info("[held] OK — an ldp_vc bound to " + heldSubjectId.slice(0, 28) +
    "… resolved from credentialSubject.id to the holder key.");

  // --- 14.5, call 1: the token refresh --------------------------------------
  log.info("=== Section 14.5, call 1: grant_type=refresh_token ===");
  const refreshed = await refreshTokens(firstRefreshToken);
  assert.strictEqual(refreshed.status, 200,
    "the refresh_token grant should succeed: " + String(refreshed.raw).slice(0, 200));
  const newAccessToken = (refreshed.body || {}).access_token;
  assert.ok(newAccessToken, "and return a new access token.");
  assert.notStrictEqual(newAccessToken, initial.body.access_token,
    "a refresh that hands back the SAME access token has refreshed nothing.");
  const before = JSON.parse(Buffer.from(initial.body.access_token.split(".")[1], "base64url"));
  const after = JSON.parse(Buffer.from(newAccessToken.split(".")[1], "base64url"));
  assert.strictEqual(after.sub, before.sub,
    "the refreshed token must describe the SAME End-User — a refresh re-authorizes, it does not " +
    "re-authenticate somebody else.");
  assert.ok(after.iat >= before.iat, "and be no older than the one it replaces.");

  // The control. Without it "the grant works" could mean the endpoint returns
  // 200 for anything at all, which would make every assertion above vacuous.
  const bogus = await refreshTokens("not-a-refresh-token");
  assert.strictEqual(bogus.status, 400,
    "an invalid refresh token must be refused — otherwise the success above says nothing. Got HTTP " +
    bogus.status);
  assert.strictEqual((bogus.body || {}).error, "invalid_grant", "and refused as invalid_grant.");
  log.info("[14.5/1] OK — new access token for the same subject; a bogus one is refused.");

  // --- 14.5, call 2: the Credential Request, reusing the bound key ----------
  log.info("=== Section 14.5, call 2: the same Credential Request, same key ===");
  // Past the second boundary first — see waitPastSecondBoundary(). Without it
  // this refresh returns the credential already in hand, byte for byte, and the
  // assertions below about a NEW validity window would fail for a reason that
  // has nothing to do with refreshing.
  await waitPastSecondBoundary();
  const reissue = await requestCredential(meta, newAccessToken, boundKey);
  assert.ok(reissue.ok, "the credential endpoint should accept the REFRESHED access token: HTTP " +
    reissue.statusCode + " " + String(reissue.raw).slice(0, 200));
  const got = walletReads(reissue);

  // This is the read that was broken for this format. It is asserted here as
  // well as in ldp_vc_issuance.js because step 4 is a different call site
  // (vc_issuance_4.js) reaching the same two functions.
  assert.strictEqual(typeof got.stored, "string",
    "step 4 stores the refreshed credential the same way step 2 does — as a string, because " +
    "localStorage takes one.");
  assert.ok(got.stored,
    "extractCredential() returned nothing for a refreshed ldp_vc. Step 4 would show \"the response " +
    "carries no credential\" for a credential the issuer did send. Response: " +
    JSON.stringify(reissue.body).slice(0, 240));
  assert.strictEqual(got.all.length, 1, "one proof was sent, so one credential comes back.");
  assert.strictEqual(got.all[0], got.stored,
    "and the two readers must agree: step 4 writes CREDENTIAL from one and CREDENTIALS from the other.");

  const refreshedCredential = JSON.parse(got.stored);
  assert.strictEqual((refreshedCredential.proof || {}).cryptosuite, "bbs-2023",
    "the refreshed credential is secured the same way.");
  // What a refresh actually owes the holder: a later validity window. That is
  // the benefit — the credential in hand expires and this one does not, or not
  // as soon. Asserted before the proof, because a differing proof is a
  // CONSEQUENCE of the new timestamps here rather than an independent fact.
  assert.ok(Date.parse(refreshedCredential.validFrom) > Date.parse(heldCredential.validFrom),
    "the refreshed credential should be valid FROM later than the one it replaces (" +
    refreshedCredential.validFrom + " vs " + heldCredential.validFrom + "). A refresh that does not " +
    "move the validity window has given the holder nothing.");
  assert.ok(Date.parse(refreshedCredential.validUntil) > Date.parse(heldCredential.validUntil),
    "and expire later — that is the point of refreshing it.");
  assert.notStrictEqual(refreshedCredential.proof.proofValue, heldCredential.proof.proofValue,
    "and so carry a different proof. Note this follows from the timestamps and NOT from any " +
    "randomness: BBS Sign is deterministic and an ldp_vc has no salts, so the same claims signed by " +
    "the same key at the same second give identical bytes. That is checked directly below.");
  assert.strictEqual(subjectIdOf(refreshedCredential), heldSubjectId,
    "reusing the holder key must give the SAME credentialSubject.id: that is what makes this a " +
    "replacement for the credential in hand rather than a second one beside it. For dc+sd-jwt the " +
    "same fact is cnf.jwk; this format has no cnf, so the subject id is the only signal.");
  log.info("[14.5/2] OK — a new proof, same subject id: this replaces the credential in hand.");

  // What the issuer actually changed. Step 4 reads this off the two credentials
  // rather than assuming, because the issuer decides whether to update the
  // signature only or the claim values too.
  const claimsBefore = Object.assign({}, heldCredential.credentialSubject);
  const claimsAfter = Object.assign({}, refreshedCredential.credentialSubject);
  assert.deepStrictEqual(claimsAfter, claimsBefore,
    "this issuer refreshes the SIGNATURE and not the claim values, so the comparison step 4 shows " +
    "should report no changed claims. If the mock is later made to vary a claim, this assertion is " +
    "the one to update — deliberately, rather than discovering it as a surprise in the pane.");
  log.info("[14.5/2] OK — claim values unchanged; only the proof is new.");

  // And it has to verify, or the refresh handed the wallet something unusable.
  const km = (await common.httpJson(refreshedCredential.proof.verificationMethod)).body;
  const pk = stsSuite.multibaseToBytes(km.publicKeyMultibase);
  const verdict = await stsSuite.verifyBase(refreshedCredential, pk);
  assert.strictEqual(verdict.ok, true,
    "the refreshed credential's base proof must verify against the issuer's published BBS key.");
  const tampered = JSON.parse(got.stored);
  tampered.credentialSubject.given_name = "Mallory";
  assert.strictEqual((await stsSuite.verifyBase(tampered, pk)).ok, false,
    "and an edited claim must break it — the control that shows the check above is not always-true.");
  log.info("[14.5/2] OK — the refreshed proof verifies over " + verdict.statements.length +
    " statements; an edit breaks it.");

  // --- the determinism the wait above exists for ----------------------------
  log.info("=== Two refreshes inside one second ===");
  // Pinned deliberately rather than left as folklore. It is what makes
  // waitPastSecondBoundary() necessary, and it is the assertion that would
  // change the day anything per-issuance (a credential id, a nonce,
  // millisecond timestamps) is added to buildLdpVc — at which point the wait can
  // go. It also documents a real difference between the formats for anyone
  // reading step 4's "what changed" pane and wondering why an ldp_vc refresh can
  // look like nothing happened.
  const twinA = await requestCredential(meta, newAccessToken, boundKey);
  const twinB = await requestCredential(meta, newAccessToken, boundKey);
  const aStr = wallet.extractCredential(twinA.body);
  const bStr = wallet.extractCredential(twinB.body);
  const sameSecond = JSON.parse(aStr).proof.created === JSON.parse(bStr).proof.created;
  if (sameSecond) {
    assert.strictEqual(aStr, bStr,
      "two ldp_vc issuances stamped with the same second must be byte-identical: BBS Sign draws no " +
      "randomness and this format carries no salts, so nothing else varies. If this ever fails, " +
      "something per-issuance has been added — good, but waitPastSecondBoundary() and the note in " +
      "step 4 about an unchanged refresh should go with it.");
    log.info("[determinism] OK — same second, identical bytes, as the format implies.");
  } else {
    // The two straddled a second boundary. Not a failure and not a pass either:
    // say so rather than logging OK for a check that did not run.
    assert.notStrictEqual(aStr, bStr,
      "these two straddled a second boundary, so they must differ.");
    log.info("[determinism] straddled a second boundary — the identity check did not run this time; " +
      "the differing-timestamp case was checked instead.");
  }

  // --- binding the refresh to a NEW key -------------------------------------
  log.info("=== The other key mode: bind the refresh to a new key ===");
  const newKey = await wallet.generateHolderKeyPair();
  const rebound = await requestCredential(meta, newAccessToken, newKey);
  assert.ok(rebound.ok, "the issuer should bind a refreshed credential to a new key too.");
  const reboundCredential = JSON.parse(wallet.extractCredential(rebound.body));
  assert.notStrictEqual(subjectIdOf(reboundCredential), heldSubjectId,
    "a new holder key must give a DIFFERENT credentialSubject.id — otherwise the wallet cannot tell " +
    "the two credentials apart, which is the confusion section 14.5 warns about.");
  assert.strictEqual(subjectIdOf(heldCredential), heldSubjectId,
    "and the credential in hand is untouched by that: it still needs its own key, which is why step 4 " +
    "must not overwrite HOLDER_PRIVATE_JWK before the new credential is kept.");

  // The verdict step 4 reaches about a rebinding, which is the consequential
  // one: a refreshed credential bound to a DIFFERENT key does not replace the
  // old one for a verifier holding the old key, and the pane says so. That
  // sentence is driven by comparing the two bound keys — so with the binding
  // unresolvable it compared null to null, and the warning never appeared.
  const reboundParsed = sdJwtVc.parseCredential(wallet.extractCredential(rebound.body));
  const heldBound = sdJwtVc.boundHolderJwk(held.parsed);
  const reboundBound = sdJwtVc.boundHolderJwk(reboundParsed);
  assert.ok(reboundBound, "the rebound credential's key must resolve too.");
  assert.notStrictEqual(JSON.stringify(reboundBound), JSON.stringify(heldBound),
    "and must compare as CHANGED against the credential in hand — this is what makes step 4 warn that " +
    "the refresh does not replace the old credential. Comparing an unresolvable binding gives null vs " +
    "null, which reads as 'same key' and suppresses the warning exactly when it matters.");
  const sameKeyParsed = sdJwtVc.parseCredential(got.stored);
  assert.strictEqual(JSON.stringify(sdJwtVc.boundHolderJwk(sameKeyParsed)), JSON.stringify(heldBound),
    "while the same-key refresh must compare as UNCHANGED — the control, without which the assertion " +
    "above would also pass for a comparison that always reports a change.");
  log.info("[key mode] OK — a new key gives a distinct subject id and compares as changed; the " +
    "same-key refresh compares as unchanged.");

  // The other format, through the same helper, in the same run. The binding fix
  // had to leave dc+sd-jwt alone, and "I did not touch it" is not evidence.
  const sdJwtConfig = process.env.OID4VCI_CONFIG_ID || "IdentityCredential";
  if ((meta.credential_configurations_supported || {})[sdJwtConfig]) {
    const sdResponse = await requestCredential(
      Object.assign({}, meta), newAccessToken, boundKey, sdJwtConfig);
    if (sdResponse.ok) {
      const sdParsed = sdJwtVc.parseCredential(wallet.extractCredential(sdResponse.body));
      assert.strictEqual(sdJwtVc.bindingMemberName(sdParsed), "cnf.jwk",
        "a dc+sd-jwt credential is still bound by cnf.jwk — the shared helper must not have renamed " +
        "the other family's binding.");
      const sdBound = sdJwtVc.boundHolderJwk(sdParsed);
      assert.ok(sdBound, "and must still resolve through the same helper.");
      assert.strictEqual(sdBound.x, boundKey.publicJwk.x,
        "to the same holder key, read out of cnf.jwk rather than credentialSubject.id.");
      assert.strictEqual(sdJwtVc.typeMemberName(sdParsed), "vct",
        "and an SD-JWT VC is still identified by its vct.");
      assert.strictEqual(sdJwtVc.credentialLabel(sdParsed), (sdParsed.payload || {}).vct,
        "shown from the vct claim, not from a type array it does not have.");
      const sdWindow = sdJwtVc.validityWindowOf(sdParsed);
      assert.strictEqual(sdWindow.expiresMember, "exp", "and its window is still nbf/exp.");
      assert.strictEqual(sdWindow.expires, (sdParsed.payload || {}).exp,
        "read straight off the NumericDate claim, with no date parsing in the way.");
      log.info("[cross-format] OK — dc+sd-jwt still reads vct, nbf/exp and cnf.jwk.");
    } else {
      log.info("[cross-format] the issuer refused a " + sdJwtConfig + " request (HTTP " +
        sdResponse.statusCode + "); the dc+sd-jwt side of the helper was not exercised.");
    }
  } else {
    log.info("[cross-format] this issuer offers no \"" + sdJwtConfig + "\" configuration; the " +
      "dc+sd-jwt side of the helper was not exercised.");
  }

  // --- the did:jwk decoder's own contract -----------------------------------
  log.info("=== did:jwk decoding ===");
  // jwkFromDid moved into sd_jwt_vc.js when step 4 started needing it, so it now
  // has TWO callers with different purposes: this format's HOLDER key, and step
  // 3's resolution of an ISSUER key (walt.id signs with a did:jwk). The cases
  // below are the ones this suite's own issuer cannot exercise — its identifiers
  // carry no fragment — and dropping the fragment strip is a silent corruption:
  // the base64url decode of "<jwk>#0" either throws or yields nonsense, so an
  // issuer key that used to resolve stops resolving and the credential is
  // reported unverifiable.
  const sampleJwk = { crv: "P-256", kty: "EC", x: boundKey.publicJwk.x, y: boundKey.publicJwk.y };
  const encoded = Buffer.from(JSON.stringify(sampleJwk)).toString("base64url");
  assert.deepStrictEqual(sdJwtVc.jwkFromDid("did:jwk:" + encoded), sampleJwk,
    "a bare did:jwk is the key itself.");
  assert.deepStrictEqual(sdJwtVc.jwkFromDid("did:jwk:" + encoded + "#0"), sampleJwk,
    "and a did:jwk URL with a fragment must decode to the same key — walt.id's issuer identifies its " +
    "signing key as did:jwk:<jwk>#0, so a decoder that keeps the fragment resolves nothing.");
  assert.strictEqual(sdJwtVc.jwkFromDid("did:key:z6Mk"), null, "another DID method is not this one.");
  assert.strictEqual(sdJwtVc.jwkFromDid("did:jwk:!!not-base64url"), null,
    "and an undecodable body is null rather than a throw — callers have other resolution paths.");
  assert.strictEqual(sdJwtVc.jwkFromDid(""), null, "as is nothing at all.");
  log.info("[did:jwk] OK — bare and fragment forms decode alike; junk is null, not a throw.");

  // --- validity spellings this issuer cannot produce ------------------------
  log.info("=== The other validity spellings ===");
  // W3C VCDM 1.1 called these issuanceDate/expirationDate, and a credential in
  // the wild may still use them. This suite's issuer emits 2.0's names only, so
  // without these the 1.1 branch is code nobody runs.
  const legacy = sdJwtVc.validityWindowOf({
    format: "ldp_vc",
    payload: { issuanceDate: "2026-01-01T00:00:00Z", expirationDate: "2027-01-01T00:00:00Z" }
  });
  assert.strictEqual(legacy.notBeforeMember, "issuanceDate",
    "a VCDM 1.1 credential names its window differently, and the pane should say which it read.");
  assert.strictEqual(legacy.expiresMember, "expirationDate", "both members.");
  assert.strictEqual(legacy.expires, Math.floor(Date.parse("2027-01-01T00:00:00Z") / 1000),
    "and the date must still resolve.");

  // 2.0 wins when both are present — otherwise a credential carrying both would
  // be reported by the older name.
  const both = sdJwtVc.validityWindowOf({
    format: "ldp_vc",
    payload: { validUntil: "2027-06-01T00:00:00Z", expirationDate: "2020-01-01T00:00:00Z" }
  });
  assert.strictEqual(both.expiresMember, "validUntil", "VCDM 2.0's spelling takes precedence.");
  assert.strictEqual(both.expires, Math.floor(Date.parse("2027-06-01T00:00:00Z") / 1000),
    "and its value is the one used — picking the 1.1 member here would report this credential as " +
    "having expired in 2020.");

  // An unparseable instant must read as absent, not as 1970 — which would show
  // as EXPIRED on a credential that is perfectly valid.
  const bad = sdJwtVc.validityWindowOf({ format: "ldp_vc", payload: { validUntil: "soon" } });
  assert.strictEqual(bad.expires, null,
    "a malformed date is absent, not the epoch. Date.parse returns NaN and Math.floor(NaN/1000) is " +
    "NaN, but a truthiness test on it would fall through to \"EXPIRED\" arithmetic.");
  log.info("[validity] OK — 1.1 and 2.0 spellings, 2.0 wins, junk reads as absent.");

  // --- 14.3: ask again with a still-valid access token ----------------------
  log.info("=== Section 14.3: re-request with the ORIGINAL access token ===");
  // The route that remains when there is no refresh token at all — which is the
  // case after the pre-authorized code grant (use cases H.2 and H.3).
  const again = await requestCredential(meta, initial.body.access_token, boundKey);
  assert.ok(again.ok,
    "the Credential Endpoint may be asked again with an access token that is still valid (section " +
    "14.3). This is the only refresh route after the pre-authorized code grant, which issues no " +
    "refresh token. HTTP " + again.statusCode + " " + String(again.raw).slice(0, 200));
  const againRead = walletReads(again);
  assert.ok(againRead.stored, "and the wallet reads that response the same way.");
  assert.strictEqual(againRead.parsed.format, "ldp_vc", "still an ldp_vc.");
  assert.strictEqual(subjectIdOf(JSON.parse(againRead.stored)), heldSubjectId,
    "bound to the same key, so it too is a replacement.");
  log.info("[14.3] OK — a still-valid access token gets a fresh credential with no token call.");

  // --- the control on the reader --------------------------------------------
  // Step 4 routes a deferred response to its polling pane by testing exactly
  // this emptiness (vc_issuance_4.js), so a reader that answers for everything
  // would break the deferred path while making every assertion above pass.
  assert.strictEqual(wallet.extractCredential({ transaction_id: "t-1" }), "",
    "a deferred response carries no credential, and step 4 routes on that emptiness.");
  assert.strictEqual(wallet.extractCredential(null), "", "nor does a missing body.");
  log.info("[reader] OK — and still reports nothing for a deferred/empty response.");

  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "unused"));
program.addOption(new Option("-h, --headless <headless>", "unused"));
program.parse(process.argv);

test().catch(function (e) { log.error(e.stack || e.message); process.exit(1); });
