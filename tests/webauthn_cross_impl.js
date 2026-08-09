// File: webauthn_cross_impl.js
//
// ---------------------------------------------------------------------------
// The wallet's WebAuthn decoder and the STS's, over the same real ceremonies,
// required to reach the same verdict on every one.
//
// This is the test the two implementations exist for. `client/src/webauthn.js`
// (with cbor.js and cose.js) and `sts/webauthn.js` share no code: different CBOR
// readers, different COSE mappings, and — the part that makes this worth doing —
// genuinely different signature paths. The browser side must convert an ECDSA
// signature from DER to raw `r‖s` because Web Crypto refuses DER; node takes DER
// natively and does no conversion at all. A mistake in one is therefore not
// mirrored in the other, which is the property `tests/bbs2023_cryptosuite.js`
// established for bbs-2023 and the reason the STS's verifier was written from
// the specification rather than by importing the client's.
//
// One implementation agreeing with itself is not a result. Two independent
// readings of section 7.2 agreeing on a real YubiKey-class ceremony is.
//
// Node only: no browser, no network, no services. Never skipped.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "webauthn_cross_impl",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const paths = require("./module_paths.js");
const ROOT = path.join(__dirname, "..");

function shared(file, what) {
  return paths.requireSharedModule(
    [path.join(__dirname, file), path.join(ROOT, "client", "src", file)], what);
}
const webauthn = shared("webauthn.js", "the wallet's WebAuthn decoder");

// The STS's copy. Three layouts: staged into the tests image under sts/ (a
// directory of its own, because unlike bbs2023.js it has a relative require); the
// sts/ submodule in a checkout; and the sibling development clone, for the
// window between writing the STS side and bumping the gitlink. The last one is
// why this test says WHERE it found the module in its log line — running against
// a stale submodule while editing the clone would otherwise look like a pass.
const STS_CANDIDATES = [
  path.join(__dirname, "sts", "webauthn.js"),
  path.join(ROOT, "sts", "webauthn.js"),
  path.join(ROOT, "..", "mock-sts", "webauthn.js"),
];
const stsWhich = STS_CANDIDATES.filter(function (p) { return fs.existsSync(p); })[0];
const sts = paths.requireSharedModule(STS_CANDIDATES, "the STS's WebAuthn verifier");

const VECTORS = JSON.parse(
  fs.readFileSync(path.join(__dirname, "webauthn_vectors.json"), "utf8"));

const ORIGIN = "http://localhost:3199";
const RP_ID = "localhost";
const REG_CHALLENGE = Buffer.from(
  Uint8Array.from([0xde, 0xad, 0xbe, 0xef].concat(Array(28).fill(0x11)))).toString("base64url");
const AUTH_CHALLENGE = Buffer.from(
  Uint8Array.from([0xca, 0xfe, 0xba, 0xbe].concat(Array(28).fill(0x22)))).toString("base64url");

let failures = 0;
async function check(name, fn) {
  try {
    const detail = await fn();
    log.info("PASS  " + name + (detail ? " — " + detail : ""));
  } catch (e) {
    failures++;
    log.error("FAIL  " + name + " — " + (e && e.message ? e.message : e));
  }
}

// The wallet's reading of a registration, in the STS's vocabulary.
function walletRegistration(vector) {
  const att = webauthn.parseAttestationObject(
    webauthn.base64urlToBytes(vector.attestationObject));
  return {
    fmt: att.fmt,
    aaguid: Buffer.from(att.authData.aaguid).toString("hex"),
    credentialId: webauthn.bytesToBase64url(att.authData.credentialId),
    publicKeyJwk: att.authData.credentialPublicKeyJwk,
    signCount: att.authData.signCount,
  };
}

async function walletAssertion(vector, jwk, opts) {
  return webauthn.verifyAssertion({
    authenticatorData: webauthn.base64urlToBytes(vector.authenticatorData),
    clientDataJSON: webauthn.base64urlToBytes(vector.clientDataJSON),
    signature: webauthn.base64urlToBytes(vector.signature),
    publicKeyJwk: jwk,
    expected: Object.assign({
      challenge: AUTH_CHALLENGE, origin: ORIGIN, rpId: RP_ID,
    }, opts || {}),
  });
}

function stsAssertion(vector, jwk, opts) {
  return sts.verifyAssertion(Object.assign({
    authenticatorData: vector.authenticatorData,
    clientDataJSON: vector.clientDataJSON,
    signature: vector.signature,
    publicKeyJwk: jwk,
    expectedChallenge: AUTH_CHALLENGE,
    expectedOrigin: ORIGIN,
    expectedRpId: RP_ID,
  }, opts || {}));
}

async function test() {
  log.info("The STS's verifier was loaded from " + stsWhich);

  await check("both implementations read the same registration identically", () => {
    ["es256_registration", "rs256_registration"].forEach(function (name) {
      const v = VECTORS[name];
      const mine = walletRegistration(v);
      const theirs = sts.verifyRegistration({
        attestationObject: v.attestationObject,
        clientDataJSON: v.clientDataJSON,
        expectedChallenge: REG_CHALLENGE,
        expectedOrigin: ORIGIN,
        expectedRpId: RP_ID,
        requireUserVerification: false,
      });
      assert.ok(theirs.ok, name + ": the STS should accept this registration; failing: " +
                theirs.failed.join("; "));
      assert.strictEqual(theirs.fmt, mine.fmt, name + ": attestation format");
      assert.strictEqual(theirs.aaguid, mine.aaguid, name + ": AAGUID");
      assert.strictEqual(theirs.credentialId, mine.credentialId, name + ": credential ID");
      assert.strictEqual(theirs.signCount, mine.signCount, name + ": sign count");
      // The public key by two independent COSE readings, compared member by
      // member. This is where an overloaded negative label (-1 is the curve for
      // EC2 and the modulus for RSA) would show up.
      assert.deepStrictEqual(theirs.publicKeyJwk, stripJwk(mine.publicKeyJwk),
        name + ": the credential public key must be identical, member for member");
    });
    return "ES256 and RS256, fmt/AAGUID/credId/signCount/JWK all identical";
  });

  await check("both accept the same valid assertions", async () => {
    const pairs = [
      ["es256", VECTORS.es256_registration, VECTORS.es256_assertion],
      ["rs256", VECTORS.rs256_registration, VECTORS.rs256_assertion],
    ];
    for (const [label, reg, asr] of pairs) {
      const jwk = walletRegistration(reg).publicKeyJwk;
      const mine = await walletAssertion(asr, jwk, { requireUserVerification: true });
      const theirs = stsAssertion(asr, stripJwk(jwk), { requireUserVerification: true });
      assert.ok(mine.valid, label + ": the wallet should accept it; failing: " +
        mine.checks.filter(c => !c.ok).map(c => c.name).join("; "));
      assert.ok(theirs.ok, label + ": the STS should accept it; failing: " + theirs.failed.join("; "));
      assert.strictEqual(mine.authenticatorData.signCount, theirs.signCount,
        label + ": both must read the same sign count");
    }
    return "ES256 and RS256 accepted by both, same sign counts";
  });

  await check("both reject the same tampered assertion, on the same check", async () => {
    const jwk = walletRegistration(VECTORS.es256_registration).publicKeyJwk;
    const asr = VECTORS.es256_assertion;
    // One byte of the signature, flipped.
    const sig = Buffer.from(asr.signature, "base64url");
    sig[10] ^= 0xff;
    const tampered = Object.assign({}, asr, { signature: sig.toString("base64url") });

    const mine = await walletAssertion(tampered, jwk);
    const theirs = stsAssertion(tampered, stripJwk(jwk));
    assert.ok(!mine.valid, "the wallet must reject a tampered signature");
    assert.ok(!theirs.ok, "the STS must reject a tampered signature");
    const mineFailed = mine.checks.filter(c => !c.ok).map(c => c.name);
    assert.deepStrictEqual(mineFailed.length, 1, "the wallet should fail exactly one check: " +
      mineFailed.join("; "));
    assert.deepStrictEqual(theirs.failed.length, 1, "the STS should fail exactly one check: " +
      theirs.failed.join("; "));
    assert.ok(/signature/.test(mineFailed[0]) && /signature/.test(theirs.failed[0]),
      "and both must name the SIGNATURE — wallet said \"" + mineFailed[0] +
      "\", STS said \"" + theirs.failed[0] + "\"");
    return "both failed on the signature, and on nothing else";
  });

  await check("both treat a UV-clear assertion the same way", async () => {
    const jwk = walletRegistration(VECTORS.uv_clear_registration).publicKeyJwk;
    const asr = VECTORS.uv_clear_assertion;

    const mineStrict = await walletAssertion(asr, jwk, { requireUserVerification: true });
    const theirsStrict = stsAssertion(asr, stripJwk(jwk), { requireUserVerification: true });
    assert.ok(!mineStrict.valid && !theirsStrict.ok,
      "with UV required, both must reject");
    assert.ok(mineStrict.signatureValid && theirsStrict.signatureValid,
      "and BOTH must still report the signature as valid — an implementation that called this a " +
      "bad signature would send its operator after the wrong problem");
    assert.ok(/user verification/i.test(mineStrict.checks.filter(c => !c.ok)[0].name) &&
              /user verification/i.test(theirsStrict.failed[0]),
      "both must name user verification as the failure");

    const mineLax = await walletAssertion(asr, jwk);
    const theirsLax = stsAssertion(asr, stripJwk(jwk));
    assert.ok(mineLax.valid && theirsLax.ok,
      "and with UV not required, both must accept the very same assertion");
    return "rejected on the flag by both, accepted by both when UV is not required";
  });

  await check("both reject a challenge, origin and RP ID mismatch", async () => {
    const jwk = walletRegistration(VECTORS.es256_registration).publicKeyJwk;
    const asr = VECTORS.es256_assertion;
    const cases = [
      ["challenge", { challenge: Buffer.alloc(32, 9).toString("base64url") },
                     { expectedChallenge: Buffer.alloc(32, 9).toString("base64url") }, /challenge/],
      ["origin", { origin: "https://evil.example" }, { expectedOrigin: "https://evil.example" }, /origin/],
      ["rpId", { rpId: "evil.example" }, { expectedRpId: "evil.example" }, /rpIdHash/],
    ];
    for (const [label, mineOpts, theirsOpts, pattern] of cases) {
      const mine = await walletAssertion(asr, jwk, mineOpts);
      const theirs = stsAssertion(asr, stripJwk(jwk), theirsOpts);
      assert.ok(!mine.valid, label + ": the wallet must reject");
      assert.ok(!theirs.ok, label + ": the STS must reject");
      const m = mine.checks.filter(c => !c.ok).map(c => c.name);
      assert.ok(m.some(n => pattern.test(n)) && theirs.failed.some(n => pattern.test(n)),
        label + ": both must name it — wallet " + m.join("/") + ", STS " + theirs.failed.join("/"));
    }
    return "three mismatches, both implementations naming the same cause each time";
  });

  if (failures) {
    log.error(failures + " check(s) failed.");
    process.exitCode = 1;
    return;
  }
  log.info("Test completed successfully.");
}

// The wallet's JWK carries `alg` (and sometimes `kid`); the STS's does not emit
// them. Compare the key material, which is the thing that must agree — a
// difference in whether a convenience member is present is not a disagreement
// about the key.
function stripJwk(jwk) {
  const out = {};
  Object.keys(jwk).forEach(function (k) {
    if (k !== "alg" && k !== "kid") {
      out[k] = jwk[k];
    }
  });
  return out;
}

const program = new Command();
program
  .name("webauthn_cross_impl")
  .description("The wallet's WebAuthn decoder and the STS's, over the same real ceremonies.")
  .addOption(new Option("-u, --url <url>", "Ignored; accepted so the runner can pass it uniformly."))
  .parse(process.argv);

test();
