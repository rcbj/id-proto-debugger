// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_jose_cose_engine.js
//
// ---------------------------------------------------------------------------
// W3C VC-JOSE-COSE (client/src/vc_jose_cose.js; #477) — vc+jwt, the W3C
// vc+sd-jwt, vc+cose and their envelopes — held to implementations that
// share no code with it:
//
//   * iya-sts's own vc_jose_cose.js (loaded from its image, as every job
//     that loads iya-sts code does): each form it secures verifies here and
//     each form secured here verifies there, for P-256, P-384 and (COSE)
//     Ed25519 issuer keys. iya-sts signs JOSE with Ed25519 only when its
//     keys.eddsaSigning setting is on, which this in-process copy does not
//     turn on, so that one direction is covered by jose below;
//   * jose (vc+jwt): a JWS it signs verifies here, ours verifies there;
//   * @sd-jwt/core (vc+sd-jwt, RFC 9901): its issuance and presentation
//     verify here, and ours decode and verify there with the same claims;
//   * @auth0/cose (vc+cose): its COSE_Sign1 verifies here, ours there.
//
// And the rules the specification adds: `vc`/`vp` claims refused, @context,
// type and issuer never selectively disclosable, a dc+sd-jwt (which has a
// `vct`) not mistaken for a W3C vc+sd-jwt, the EnvelopedVerifiableCredential
// data: URL round trip for text and bytes, and a Key Binding JWT checked for
// nonce, audience and sd_hash. No browser and no services.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vc_jose_cose_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

const SRC = path.join(repoRoot(), "client", "src");
const paths = require("./module_paths.js");
const jc = paths.requireSharedModule([path.join(SRC, "vc_jose_cose.js")],
                                     "client/src/vc_jose_cose.js");

function keyPair(crv) {
  log.debug("Entering keyPair(). " + crv);
  var pair = crv === "Ed25519" ? nodeCrypto.generateKeyPairSync("ed25519") :
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: crv });
  var pub = pair.publicKey.export({ format: "jwk" });
  var did = "did:jwk:" +
    Buffer.from(JSON.stringify(pub)).toString("base64url");
  log.debug("Leaving keyPair().");
  return { pair: pair, pub: pub,
           priv: pair.privateKey.export({ format: "jwk" }),
           did: did, kid: did + "#0" };
}

function credential(issuer) {
  log.debug("Entering credential().");
  log.debug("Leaving credential().");
  return { "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential"], issuer: issuer,
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: { id: "did:example:alice", given_name: "Alice",
      family_name: "Liddell", nationalities: ["GB", "FR"] } };
}

async function againstIyaSts() {
  log.debug("Entering againstIyaSts().");
  var found = paths.mockStsModule("vc_jose_cose.js", function (m) {
    log.warn(m);
  });
  if (!found) throw new Error("iya-sts's vc_jose_cose.js is not in its " +
                              "tree (" + paths.iyaStsImage() + ").");
  var sts = require(found);
  for (const crv of ["P-256", "P-384", "Ed25519"]) {
    var k = keyPair(crv);
    var vc = credential(k.did);
    var signer = { publicJwk: k.pub, privateKey: k.pair.privateKey,
                   kid: k.kid };
    for (const form of ["jwt", "sdjwt", "cose"]) {
      var label = crv + " " + form;
      var stsSigns = !(crv === "Ed25519" && form !== "cose");
      if (stsSigns) {
        var theirs = form === "jwt" ? await sts.secureJwt(vc, "vc", signer) :
          form === "cose" ? await sts.secureCose(vc, "vc", signer) :
          await sts.secureSdJwt(vc, "vc", signer,
            ["credentialSubject.given_name",
             "credentialSubject.nationalities[1]"]);
        if (Buffer.isBuffer(theirs)) theirs = new Uint8Array(theirs);
        var r = await jc.verify(theirs);
        assert.ok(r.valid, label + ": iya-sts's verifies here: " +
                  r.errors.join("; "));
        assert.deepStrictEqual(r.document.credentialSubject,
                               vc.credentialSubject,
                               label + ": the credential reads back whole");
      }
      var mine = form === "jwt" ? jc.secureJwt(vc, { privateJwk: k.priv,
          kid: k.kid }) :
        form === "cose" ? jc.secureCose(vc, { privateJwk: k.priv,
          kid: k.kid }) :
        jc.secureSdJwt(vc, { privateJwk: k.priv, kid: k.kid },
          ["/credentialSubject/given_name",
           "/credentialSubject/nationalities/1"]);
      var v = await sts.verify(form, form === "cose" ? Buffer.from(mine) :
                               mine, "vc", {});
      assert.ok(v && (v.ok || v.valid || v.verified), label + ": ours " +
                "verifies in iya-sts: " + JSON.stringify(v && v.errors));
      log.info("PASS " + label + ": " + (stsSigns ? "both directions" :
               "ours verifies in iya-sts (it signs JOSE EdDSA only with " +
               "keys.eddsaSigning on)") + ".");
    }
  }
  log.debug("Leaving againstIyaSts().");
}

async function againstJose() {
  log.debug("Entering againstJose().");
  var jose = await import("jose");
  for (const crv of ["P-256", "Ed25519"]) {
    var k = keyPair(crv);
    var vc = credential(k.did);
    var alg = crv === "Ed25519" ? "EdDSA" : "ES256";
    var theirs = await new jose.CompactSign(Buffer.from(JSON.stringify(vc)))
      .setProtectedHeader({ alg: alg, typ: "vc+jwt", cty: "vc", kid: k.kid })
      .sign(k.pair.privateKey);
    var r = await jc.verify(theirs);
    assert.ok(r.valid, crv + ": jose's vc+jwt verifies here: " +
              r.errors.join("; "));
    var mine = jc.secureJwt(vc, { privateJwk: k.priv, kid: k.kid });
    var v = await jose.compactVerify(mine, k.pair.publicKey);
    assert.strictEqual(v.protectedHeader.typ, "vc+jwt", crv + ": typ");
    assert.deepStrictEqual(JSON.parse(Buffer.from(v.payload).toString()), vc,
                           crv + ": jose reads our payload as the VC itself");
  }
  log.info("PASS vc+jwt against jose, P-256 and Ed25519, both directions.");
  log.debug("Leaving againstJose().");
}

async function againstSdJwtCore() {
  log.debug("Entering againstSdJwtCore().");
  var core = await import("@sd-jwt/core");
  var k = keyPair("P-256");
  var vc = credential(k.did);
  var instance = new core.SdJwtInstance({
    signer: async function (data) {
      return Buffer.from(nodeCrypto.sign("sha256", Buffer.from(data),
        { key: k.pair.privateKey, dsaEncoding: "ieee-p1363" }))
        .toString("base64url");
    },
    verifier: async function (data, sig) {
      return nodeCrypto.verify("sha256", Buffer.from(data),
        { key: k.pair.publicKey, dsaEncoding: "ieee-p1363" },
        Buffer.from(sig, "base64url"));
    },
    signAlg: "ES256",
    hasher: async function (data, alg) {
      return new Uint8Array(nodeCrypto.createHash(alg.replace("-", ""))
        .update(data).digest());
    },
    hashAlg: "sha-256",
    saltGenerator: async function () {
      return nodeCrypto.randomBytes(16).toString("base64url");
    }
  });
  var theirs = await instance.issue(vc, {
    credentialSubject: { _sd: ["given_name", "family_name"],
                         nationalities: { _sd: [1] } } },
    { header: { typ: "vc+sd-jwt", kid: k.kid } });
  var r = await jc.verify(theirs);
  assert.ok(r.valid, "@sd-jwt/core's vc+sd-jwt verifies here: " +
            r.errors.join("; "));
  assert.deepStrictEqual(r.document.credentialSubject, vc.credentialSubject,
    "every disclosure reconstructs, the array element in place");
  var shown = await instance.present(theirs,
    { credentialSubject: { given_name: true } });
  r = await jc.verify(shown);
  assert.ok(r.valid && r.document.credentialSubject.given_name === "Alice" &&
            r.document.credentialSubject.family_name === undefined,
            "its presentation of one claim verifies here with that claim " +
            "alone: " + r.errors.join("; "));
  var mine = jc.secureSdJwt(vc, { privateJwk: k.priv, kid: k.kid },
    ["/credentialSubject/given_name", "/credentialSubject/family_name",
     "/credentialSubject/nationalities/1"]);
  var decoded = await instance.verify(mine);
  assert.deepStrictEqual(decoded.payload.credentialSubject,
                         vc.credentialSubject,
                         "@sd-jwt/core verifies ours to the same claims");
  log.info("PASS vc+sd-jwt against @sd-jwt/core: issuance and a one-claim " +
           "presentation verify here, ours verifies there.");
  log.debug("Leaving againstSdJwtCore().");
}

async function againstAuth0Cose() {
  log.debug("Entering againstAuth0Cose().");
  var cose = require("@auth0/cose");
  var k = keyPair("P-256");
  var vc = credential(k.did);
  var signed = await cose.Sign1.sign(
    new cose.ProtectedHeaders([[cose.Headers.Algorithm,
      cose.Algorithms.ES256], [16, "application/vc+cose"],
      [cose.Headers.KeyID, Buffer.from(k.kid)]]),
    undefined, Buffer.from(JSON.stringify(vc)), k.pair.privateKey);
  var r = await jc.verify(new Uint8Array(signed.encode()));
  assert.ok(r.valid, "@auth0/cose's COSE_Sign1 verifies here: " +
            r.errors.join("; "));
  var mine = jc.secureCose(vc, { privateJwk: k.priv, kid: k.kid });
  await cose.Sign1.decode(Buffer.from(mine)).verify(k.pair.publicKey);
  log.info("PASS vc+cose against @auth0/cose, both directions.");
  log.debug("Leaving againstAuth0Cose().");
}

async function rules() {
  log.debug("Entering rules().");
  var k = keyPair("P-256");
  var vc = credential(k.did);
  var withVc = jc.secureJwt(Object.assign({ vc: {} }, vc),
                            { privateJwk: k.priv, kid: k.kid });
  assert.ok(!(await jc.verify(withVc)).valid,
            "a `vc` claim is refused (section 1.1.2.1)");
  assert.throws(function () {
    jc.secureSdJwt(vc, { privateJwk: k.priv }, ["/issuer"]);
  }, /always disclosed/, "issuer cannot be made selectively disclosable");
  var dc = jc.secureSdJwt(vc, { privateJwk: k.priv, kid: k.kid }, []);
  var parts = dc.split("~");
  var p = JSON.parse(Buffer.from(parts[0].split(".")[1], "base64url"));
  p.vct = "urn:example";
  var forged = parts[0].split(".")[0] + "." +
    Buffer.from(JSON.stringify(p)).toString("base64url") + ".x~";
  assert.strictEqual(jc.detect(forged), null, "a payload with a vct is a " +
                     "dc+sd-jwt, not a W3C vc+sd-jwt");
  var jwt = jc.secureJwt(vc, { privateJwk: k.priv, kid: k.kid });
  var env = jc.envelope("jwt", "vc", jwt);
  assert.strictEqual(jc.unenvelope(env).secured, jwt, "jwt envelope");
  var cbor = jc.secureCose(vc, { privateJwk: k.priv, kid: k.kid });
  var envC = jc.envelope("cose", "vc", cbor);
  assert.ok(/^data:application\/vc\+cose;base64,/.test(envC.id),
            "COSE travels base64 in its data: URL");
  assert.deepStrictEqual(jc.unenvelope(envC).secured, cbor, "cose envelope");
  var holder = keyPair("P-256");
  var bound = jc.secureSdJwt(vc, { privateJwk: k.priv, kid: k.kid },
    ["/credentialSubject/given_name"], { cnf: { jwk: holder.pub } });
  var discl = bound.split("~").filter(Boolean).slice(1);
  var shown = jc.presentSdJwt(bound, discl, { privateJwk: holder.priv,
    aud: "x509_hash:v", nonce: "n-1" });
  var r = await jc.verify(shown, { kbNonce: "n-1", kbAudience: "x509_hash:v" });
  assert.ok(r.valid && r.keyBinding.valid, "a Key Binding JWT verifies: " +
            r.errors.join("; "));
  r = await jc.verify(shown, { kbNonce: "other" });
  assert.ok(!r.valid, "under another nonce it does not");
  log.info("PASS the specification's rules: vc claim refused, issuer always " +
           "disclosed, dc+sd-jwt not mistaken, envelopes, key binding.");
  log.debug("Leaving rules().");
}

async function main() {
  log.debug("Entering main().");
  await rules();
  await againstJose();
  await againstSdJwtCore();
  await againstAuth0Cose();
  await againstIyaSts();
  log.info("vc_jose_cose_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
