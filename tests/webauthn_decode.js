// File: webauthn_decode.js
//
// ---------------------------------------------------------------------------
// The WebAuthn decoder — cbor.js, cose.js and webauthn.js — checked in node,
// with no browser and no network, so it is never skipped and never flakes.
//
// The artifacts in tests/webauthn_vectors.json are REAL: produced by Chrome
// 121's WebDriver virtual authenticator on 2026-08-08, both ES256 and RS256,
// registration and assertion, plus one assertion whose UV flag is deliberately
// clear. Nothing here is hand-written, which matters — a decoder tested only
// against material the same author invented agrees with itself and with nobody.
//
// TWO INDEPENDENT ORACLES, because "our decoder returns what our decoder
// returns" is worth nothing:
//
//   1. **The browser's own reading.** Chrome hands back both the raw
//      attestationObject and, separately, its own parse of it —
//      `getPublicKey()` (SPKI DER), `getPublicKeyAlgorithm()` and
//      `getTransports()`. Our COSE_Key -> JWK -> SPKI chain must reproduce
//      Chrome's SPKI byte for byte. It is the same key by two entirely
//      different routes.
//   2. **Node's crypto.** The assertion signatures are verified a second time
//      with `crypto.createPublicKey` / `crypto.verify`, an implementation this
//      project did not write, from the JWK our COSE decoder produced.
//
// Then the negatives, each flipping exactly one thing, because a verifier that
// always answers "invalid" would pass every positive test above if they were
// the only tests here.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "webauthn_decode",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The client modules resolve their own requires against client/, so they are
// loaded the way every other test that borrows one does it.
const paths = require("./module_paths.js");
const ROOT = path.join(__dirname, "..");
// Both layouts: copied flat beside the tests in the container image, under
// client/src in a checkout.
function shared(file, what) {
  log.debug("Entering shared().");
  log.debug("Leaving shared().");
  return paths.requireSharedModule(
    [path.join(__dirname, file), path.join(ROOT, "client", "src", file)], what);
}
const cbor = shared("cbor.js", "the CBOR reader");
const cose = shared("cose.js", "the COSE_Key decoder");
const webauthn = shared("webauthn.js", "the WebAuthn decoder");
// NB: the PEM comes through cose.describe() rather than by loading jwk_pem.js
// here. There is a TEST called tests/jwk_pem_encoding.js, so the container's
// flat layout would resolve that name to the test rather than the module — the
// collision the tests image's own comments warn about. cose.js requires it
// relative to itself and cannot be confused.

const VECTORS = JSON.parse(fs.readFileSync(path.join(__dirname,
    "webauthn_vectors.json"), "utf8"));

const b64u = webauthn.base64urlToBytes;
const toB64u = webauthn.bytesToBase64url;

let failures = 0;
function check(name, fn) {
  log.debug("Entering check().");
  try {
    const detail = fn();
    log.info("PASS  " + name + (detail ? " — " + detail : ""));
  } catch (e) {
    failures++;
    log.error("FAIL  " + name + " — " + (e && e.message ? e.message : e));
  }
  log.debug("Leaving check().");
}
async function checkAsync(name, fn) {
  log.debug("Entering checkAsync().");
  try {
    const detail = await fn();
    log.info("PASS  " + name + (detail ? " — " + detail : ""));
  } catch (e) {
    failures++;
    log.error("FAIL  " + name + " — " + (e && e.message ? e.message : e));
  }
  log.debug("Leaving checkAsync().");
}

// --- CBOR, against RFC 8949's own appendix A ---------------------------------
//
// Hand-checked values from the specification's table, which is an input and an
// expected output written down by the people who defined the encoding.
function cborVectors() {
  log.debug("Entering cborVectors().");
  const cases = [
    ["00", 0], ["01", 1], ["0a", 10], ["17", 23], ["1818", 24], ["1901f4", 500],
    ["20", -1], ["3903e7", -1000],
    ["40", ""], ["4401020304", "01020304"],
    ["60", ""], ["6161", "a"], ["6449455446", "IETF"],
    ["80", []], ["83010203", [1, 2, 3]],
    ["f4", false], ["f5", true], ["f6", null],
  ];
  cases.forEach(function ([hex, expected]) {
    const bytes = Uint8Array.from(Buffer.from(hex, "hex"));
    const got = cbor.decode(bytes);
    if (got instanceof Uint8Array) {
      assert.strictEqual(Buffer.from(got).toString("hex"), expected, "0x" +
                         hex);
    } else if (Array.isArray(expected)) {
      assert.deepStrictEqual(got, expected, "0x" + hex);
    } else {
      assert.strictEqual(got, expected, "0x" + hex);
    }
  });
  // A map keeps integer keys as integers, which is the whole reason maps are
  // decoded to a Map: COSE is keyed by 1, 3, -1, -2, -3.
  const m = cbor.decode(Uint8Array.from(Buffer.from("a201020304", "hex")));
  assert.ok(m instanceof Map, "a CBOR map should decode to a Map");
  assert.strictEqual(m.get(1), 2);
  assert.strictEqual(m.get(3), 4);
  log.debug("Leaving cborVectors().");
  return cases.length + 1 + " vectors";
}

function cborRefusals() {
  log.debug("Entering cborRefusals().");
  const mustThrow = [
    ["9f01ff", /indefinite/i, "an indefinite-length array"],
    ["a201020102", /duplicate/i, "a duplicate map key"],
    ["4405", /claims 4 byte/i, "a byte string longer than the input"],
    ["0001", /1 byte\(s\) follow/, "trailing data after a complete item"],
  ];
  mustThrow.forEach(function ([hex, pattern, what]) {
    const bytes = Uint8Array.from(Buffer.from(hex, "hex"));
    assert.throws(function () { cbor.decode(bytes); }, pattern, what +
                  " must be refused");
  });
  // Depth: 40 nested arrays, past the cap of 32.
  const deep = Buffer.concat([Buffer.alloc(40, 0x81), Buffer.from([0x00])]);
  assert.throws(function () { cbor.decode(Uint8Array.from(deep)); }, /nesting/i,
                "runaway nesting must be refused");
  log.debug("Leaving cborRefusals().");
  return mustThrow.length + 1 + " refusals";
}

// --- registration: our COSE key vs the browser's own getPublicKey() ----------

function registrationAgreesWithBrowser(name, vector) {
  log.debug("Entering registrationAgreesWithBrowser().");
  const att = webauthn.parseAttestationObject(b64u(vector.attestationObject));
  const ad = att.authData;

  assert.ok(ad.flags.AT, "the AT flag must be set on a registration");
  assert.ok(ad.credentialPublicKeyJwk,
            "the credential public key must decode: " +
            (ad.credentialPublicKeyError || ""));
  assert.strictEqual(toB64u(ad.credentialId), vector.rawId,
    "the credential ID inside the authenticator data must equal the " +
        "credential's rawId");

  // ORACLE 1: the browser's own SPKI for the same key.
  const described = cose.describe(ad.credentialPublicKey);
  assert.ok(described.pem, "the COSE key should render as a PEM: " +
            described.pemUnavailable);
  const derivedDer = Buffer.from(described.pem.replace(/-----[^-]+-----|\s+/g,
      ""), "base64");
  const browserDer = Buffer.from(b64u(vector.oracle.publicKeySpki));
  assert.strictEqual(derivedDer.toString("base64"),
                     browserDer.toString("base64"),
    "our COSE -> JWK -> SPKI must be byte-identical to the browser's " +
        "getPublicKey()");

  const algName = cose.algorithmName(ad.credentialPublicKey.get(3));
  const expectedAlg = cose.algorithm(vector.oracle.publicKeyAlgorithm);
  assert.strictEqual(algName, expectedAlg.name,
    "our algorithm reading must match the browser's getPublicKeyAlgorithm()");

  // The browser also hands back its own copy of the authenticator data.
  assert.strictEqual(toB64u(att.authDataBytes), vector.oracle.authenticatorData,
    "the authData we pulled out of the attestation object must equal " +
        "getAuthenticatorData()");

  const cd = webauthn.parseClientDataJSON(b64u(vector.clientDataJSON));
  assert.strictEqual(cd.type, "webauthn.create",
                     "clientData.type on a registration");
  assert.strictEqual(cd.origin, "http://localhost:3199", "clientData.origin");

  log.debug("Leaving registrationAgreesWithBrowser().");
  return att.fmt + ", " + algName + ", aaguid " + ad.aaguidHex +
         ", credId " + ad.credentialId.length + "B, SPKI matches the browser" +
         (cd.extraMembers.length ? ", clientData carries " +
          cd.extraMembers.join("/") : "");
}

// --- assertion: our verifier, then node's ------------------------------------

const EXPECTED_ASSERTION = {
  challenge: toB64u(Uint8Array.from([0xca, 0xfe, 0xba,
                    0xbe].concat(Array(28).fill(0x22)))),
  origin: "http://localhost:3199",
  rpId: "localhost",
};

async function assertionVerifies(regVector, assertVector, opts) {
  log.debug("Entering assertionVerifies().");
  opts = opts || {};
  const jwk = webauthn.parseAttestationObject(b64u(regVector.attestationObject))
                      .authData.credentialPublicKeyJwk;
  const result = await webauthn.verifyAssertion({
    authenticatorData: b64u(assertVector.authenticatorData),
    clientDataJSON: b64u(assertVector.clientDataJSON),
    signature: b64u(assertVector.signature),
    publicKeyJwk: jwk,
    expected: Object.assign({}, EXPECTED_ASSERTION, opts.expected || {}),
  });
  assert.ok(result.valid, "every check should pass; failing: " +
    result.checks.filter(c => !c.ok).map(c => c.name + " (" + c.detail +
                         ")").join("; "));

  // ORACLE 2: node's crypto, from the JWK our COSE decoder produced.
  const authData = Buffer.from(b64u(assertVector.authenticatorData));
  const clientHash = nodeCrypto.createHash("sha256")
    .update(Buffer.from(b64u(assertVector.clientDataJSON))).digest();
  const signed = Buffer.concat([authData, clientHash]);
  const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  const nodeOk = nodeCrypto.verify(
    jwk.kty === "RSA" ? "sha256" : "sha256", signed, key,
    Buffer.from(b64u(assertVector.signature)));
  assert.ok(nodeOk, "node's crypto must agree that the signature is valid");

  log.debug("Leaving assertionVerifies().");
  return result.checks.length + " checks, and node agrees";
}

// --- negatives ---------------------------------------------------------------

async function tamper(name, mutate, expectFailing) {
  log.debug("Entering tamper().");
  const reg = VECTORS.es256_registration, asr = VECTORS.es256_assertion;
  const jwk = webauthn.parseAttestationObject(b64u(reg.attestationObject))
                      .authData.credentialPublicKeyJwk;
  const input = {
    authenticatorData: b64u(asr.authenticatorData),
    clientDataJSON: b64u(asr.clientDataJSON),
    signature: b64u(asr.signature),
    publicKeyJwk: jwk,
    expected: Object.assign({}, EXPECTED_ASSERTION),
  };
  mutate(input);
  const result = await webauthn.verifyAssertion(input);
  assert.ok(!result.valid, "this must NOT verify");
  const failed = result.checks.filter(c => !c.ok).map(c => c.name);
  assert.ok(failed.some(n => n.indexOf(expectFailing) !== -1),
    "expected the failure to be \"" + expectFailing +
        "\"; the failing checks were: " +
    failed.join("; "));
  // The point of reporting per-check: exactly one thing should be wrong.
  assert.strictEqual(failed.length, 1,
    "exactly one check should fail, so the pane names the right cause; " +
        "failing: " + failed.join("; "));
  log.debug("Leaving tamper().");
  return "failed on \"" + failed[0] + "\"";
}

async function test() {
  log.debug("Entering test().");
  log.info("=== CBOR ===");
  check("RFC 8949 appendix A vectors decode correctly", cborVectors);
  check("malformed and non-canonical CBOR is refused", cborRefusals);

  log.info("=== Registration, against the browser's own parse ===");
  check("ES256 registration decodes and matches getPublicKey()",
        () => registrationAgreesWithBrowser("es256",
         VECTORS.es256_registration));
  check("RS256 registration decodes and matches getPublicKey()",
        () => registrationAgreesWithBrowser("rs256",
         VECTORS.rs256_registration));

  log.info("=== Assertion, verified by us and then by node ===");
  await checkAsync("ES256 assertion verifies",
    () => assertionVerifies(VECTORS.es256_registration, VECTORS.es256_assertion,
                            { expected: { requireUserVerification: true } }));
  await checkAsync("RS256 assertion verifies",
    () => assertionVerifies(VECTORS.rs256_registration, VECTORS.rs256_assertion,
                            { expected: { requireUserVerification: true } }));
  await checkAsync("a discoverable-credential assertion carries the " +
                   "user handle", async () => {
    const v = VECTORS.es256_assertion_discoverable;
    assert.ok(v.userHandle,
              "a discoverable credential's assertion should carry userHandle");
    await assertionVerifies(VECTORS.es256_registration, v,
                            { expected: { requireUserVerification: true } });
    return "userHandle " + v.userHandle;
  });

  log.info("=== Negatives ===");
  await checkAsync("tampered authenticatorData fails the signature", () =>
    tamper("authData", (i) => { i.authenticatorData[36] ^= 0xff; },
           "signature verifies"));
  await checkAsync("tampered clientDataJSON fails the signature (the SHA-256 " +
                   "binding is real)", () =>
    tamper("clientData", (i) => {
      // Change a byte inside the JSON that is not one of the fields checked
      // separately, so ONLY the signature check can catch it.
      const text = Buffer.from(i.clientDataJSON).toString("utf8")
          .replace('"crossOrigin":false', '"crossOrigin":true');
      i.clientDataJSON = new Uint8Array(Buffer.from(text, "utf8"));
    }, "signature verifies"));
  await checkAsync("a challenge mismatch is caught by name", () =>
    tamper("challenge", (i) => { i.expected.challenge =
           toB64u(new Uint8Array(32).fill(9)); },
           "challenge matches"));
  await checkAsync("an origin mismatch is caught by name", () =>
    tamper("origin", (i) => { i.expected.origin = "https://evil.example"; },
           "origin matches"));
  await checkAsync("an RP ID mismatch is caught by name", () =>
    tamper("rpId", (i) => { i.expected.rpId = "example.com"; },
           "rpIdHash is SHA-256"));
  await checkAsync("a sign-count regression is caught by name", () =>
    tamper("signCount", (i) => { i.expected.previousSignCount = 99999; },
           "signature counter advanced"));

  // UV: the browser will not produce a UV-clear assertion when UV is required,
  // so the material comes from a ceremony that asked for "discouraged" against
  // an authenticator with no user verification. Phase 0 established this.
  await checkAsync("a UV-clear assertion is rejected on the FLAG, not the " +
                   "signature", async () => {
    const reg = VECTORS.uv_clear_registration, asr = VECTORS.uv_clear_assertion;
    const jwk = webauthn.parseAttestationObject(b64u(reg.attestationObject))
                        .authData.credentialPublicKeyJwk;
    const result = await webauthn.verifyAssertion({
      authenticatorData: b64u(asr.authenticatorData),
      clientDataJSON: b64u(asr.clientDataJSON),
      signature: b64u(asr.signature),
      publicKeyJwk: jwk,
      expected: Object.assign({}, EXPECTED_ASSERTION,
                              { requireUserVerification: true }),
    });
    assert.ok(!result.valid,
              "UV was required and not performed, so this must not pass");
    assert.ok(result.signatureValid,
      "and the SIGNATURE must still be valid — reporting this as a bad " +
          "signature would send " +
      "the user hunting for the wrong problem");
    const failed = result.checks.filter(c => !c.ok).map(c => c.name);
    assert.deepStrictEqual(failed,
        ["user verification (UV) was performed, as required"],
      "exactly the UV check should fail; got: " + failed.join("; "));
    return "signature valid, UV flag clear, one check failed";
  });

  await checkAsync("the same UV-clear assertion PASSES when UV is not required",
                   async () => {
    const reg = VECTORS.uv_clear_registration, asr = VECTORS.uv_clear_assertion;
    const jwk = webauthn.parseAttestationObject(b64u(reg.attestationObject))
                        .authData.credentialPublicKeyJwk;
    const result = await webauthn.verifyAssertion({
      authenticatorData: b64u(asr.authenticatorData),
      clientDataJSON: b64u(asr.clientDataJSON),
      signature: b64u(asr.signature),
      publicKeyJwk: jwk,
      expected: EXPECTED_ASSERTION,
    });
    assert.ok(result.valid,
        "with UV not required this is a perfectly good assertion; failing: " +
      result.checks.filter(c => !c.ok).map(c => c.name).join("; "));
    return "the pair proves the UV check is the only difference";
  });

  // The DER conversion, in isolation. It is the single likeliest place for a
  // silent wrong answer, because a bad conversion returns FALSE rather than
  // throwing, and a false there reads as a bad authenticator.
  check("DER -> raw ECDSA conversion pads short components", () => {
    // r = 0x01 (one byte, must be left-padded to 32), s = 32 bytes of 0x02.
    const der = Buffer.concat([
      Buffer.from([0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00]),
      Buffer.alloc(32, 0x02)]);
    const raw = webauthn.derToRawSignature(new Uint8Array(der), 32);
    assert.strictEqual(raw.length, 64, "raw signature must be 2 * 32 bytes");
    assert.strictEqual(raw[31], 0x01,
                       "r must be right-aligned in the first half");
    assert.strictEqual(raw.slice(0, 31).every(b => b === 0), true,
                       "and zero-padded on the left");
    assert.strictEqual(raw[32], 0x02, "s must start the second half");
    return "64 bytes, r right-aligned";
  });

  if (failures) {
    // process.exitCode rather than process.exit(): stdout is a pipe under the
    // runner, so exiting immediately truncates bunyan's buffered writes — which
    // is how a failing run managed to print "Test completed successfully".
    log.error(failures + " check(s) failed.");
    process.exitCode = 1;
    log.debug("Leaving test().");
    return;
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("webauthn_decode")
  .description("Decode and verify real WebAuthn artifacts; no browser, " +
      "no network.")
  .addOption(new Option("-u, --url <url>",
      "Ignored; accepted so the runner can pass it uniformly."))
  .parse(process.argv);

test();
