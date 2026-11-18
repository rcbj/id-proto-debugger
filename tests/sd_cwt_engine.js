// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: sd_cwt_engine.js
//
// ---------------------------------------------------------------------------
// SD-CWT (client/src/sd_cwt.js; #478), held to draft-ietf-spice-sd-cwt-09's
// own examples and to implementations that share no code with it. No
// browser, no services.
//
// tests/fixtures/sd_cwt_09_vectors.json is the working group's encoded
// examples at the -09 tag (generated there with pycose), with Appendix C's
// keys:
//
//   * the first disclosure's Redacted Claim Hash is Figure 8's;
//   * the issued SD-CWT, the nested one and the decoy one each confirm in
//     holder mode with every Redacted Claim restored, and the redacted
//     payload with no disclosures does NOT (a holder needs them all);
//   * the KBT and the nested KBT verify under the example's aud and
//     cnonce, restoring exactly the disclosures Alice chose (section 3.3,
//     Appendix D);
//   * presenting the issued example again, choosing those same
//     disclosures, verifies.
//
// Our own issuance and presentation, P-256, P-384 and Ed25519, checked by
// @auth0/cose (both COSE_Sign1 signatures) and by node's own hash over
// each disclosure; nested and array redaction; and what must fail: a
// changed disclosure, a disclosure with no hash, a KBT by another key,
// another aud or cnonce, a KBT made after the SD-CWT expired, an empty
// sd_claims, and redacting a claim Table 2 never redacts.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "sd_cwt_engine",
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
function load(name) {
  log.debug("Entering load(). " + name);
  log.debug("Leaving load().");
  return paths.requireSharedModule([path.join(SRC, name)],
                                   "client/src/" + name);
}
const sd = load("sd_cwt.js");
const cbor = load("cbor.js");
const mdoc = load("mdoc.js");
const FX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures",
  "sd_cwt_09_vectors.json"), "utf8"));

function hexBytes(h) {
  log.debug("Entering hexBytes().");
  log.debug("Leaving hexBytes().");
  return new Uint8Array(Buffer.from(h, "hex"));
}

function pubOf(jwk) {
  log.debug("Entering pubOf().");
  var j = Object.assign({}, jwk);
  delete j.d;
  log.debug("Leaving pubOf().");
  return j;
}

function specificationVectors() {
  log.debug("Entering specificationVectors().");
  var ik = pubOf(FX.issuerKey);
  var issued = sd.confirm(hexBytes(FX.cbor.issuer_cwt),
                          { issuerKey: ik, holderKey: FX.holderKey });
  assert.ok(issued.valid, "the issued example confirms: " +
            issued.errors.join("; "));
  assert.strictEqual(issued.disclosures[0].hash, FX.firstHash,
                     "the first disclosure's hash is Figure 8's");
  var plain = sd.toPlainClaims(issued.claims);
  assert.deepStrictEqual(plain["503"], { country: "us", region: "ca",
    postal_code: "94188" }, "every redacted claim of 503 is restored");
  assert.deepStrictEqual(plain["502"], [1549560720, 1612560720, 1674004740],
                         "and both redacted array elements");
  ["nested_issuer_cwt", "decoy"].forEach(function (f) {
    var c = sd.confirm(hexBytes(FX.cbor[f]), { issuerKey: ik });
    assert.ok(c.valid, f + " confirms: " + c.errors.join("; "));
  });
  var bare = sd.confirm(hexBytes(FX.cbor.nested_cwt), { issuerKey: ik });
  assert.ok(!bare.valid && /no disclosure/.test(bare.errors.join(" ")),
            "a redacted payload without its disclosures does not confirm");

  var v = sd.verify(hexBytes(FX.cbor.kbt), { issuerKey: ik, aud: FX.aud,
                                             cnonce: hexBytes(FX.cnonce) });
  assert.ok(v.valid, "the KBT example verifies: " + v.errors.join("; "));
  plain = sd.toPlainClaims(v.claims);
  assert.strictEqual(plain["501"], "ABCD-123456", "license disclosed");
  assert.deepStrictEqual(plain["503"], { country: "us", region: "ca" },
                         "region disclosed, postal_code withheld");
  assert.deepStrictEqual(plain["502"], [1549560720, 1674004740],
                         "the earliest date disclosed, the other dropped");
  v = sd.verify(hexBytes(FX.cbor.nested_kbt), { issuerKey: ik, aud: FX.aud });
  assert.ok(v.valid, "the nested KBT verifies: " + v.errors.join("; "));
  assert.strictEqual(sd.toPlainClaims(v.claims)["504"].length, 2,
                     "two of three nested inspections disclosed");

  var chosen = v.disclosed.map(function (r) {
    return r.hash;
  });
  var again = sd.present(hexBytes(FX.cbor.issuer_cwt), { disclose:
    sd.verify(hexBytes(FX.cbor.kbt), { issuerKey: ik }).disclosed.map(
      function (r) {
        return r.hash;
      }), holderKey: FX.holderKey, aud: FX.aud, cnonce: hexBytes(FX.cnonce),
    iat: 1725244237 });
  v = sd.verify(again, { issuerKey: ik, aud: FX.aud,
                         cnonce: hexBytes(FX.cnonce) });
  assert.ok(v.valid, "our presentation of the issued example verifies: " +
            v.errors.join("; "));
  assert.ok(chosen.length > 0, "the nested KBT disclosed something");
  log.info("PASS the draft's examples: Figure 8's hash; the issued, nested " +
           "and decoy SD-CWTs confirm, a bare one does not; both KBTs " +
           "verify with exactly Alice's disclosures; ours of the same " +
           "verifies.");
  log.debug("Leaving specificationVectors().");
}

function keyPair(crv) {
  log.debug("Entering keyPair(). " + crv);
  var pair = crv === "Ed25519" ? nodeCrypto.generateKeyPairSync("ed25519") :
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: crv });
  log.debug("Leaving keyPair().");
  return { jwk: pair.privateKey.export({ format: "jwk" }),
           pub: pair.publicKey };
}

const CLAIMS = { 1: "https://issuer.example", 2: "https://holder.example",
                 6: 1725244200, 4: 4102444800,
                 500: true, 501: "ABCD-123456",
                 502: [1549560720, 1612560720, 1674004740],
                 503: { country: "us", region: "ca", postal_code: "94188" } };
const REDACT = [[501], [502, 0], [502, 1], [503, "region"],
                [503, "postal_code"], [503]];

// The witness for a KBT: @auth0/cose verifies the issuer's COSE_Sign1 inside
// it and the holder's around it (the disclosure hashes are checked by node
// in roundTrips()).
async function witness(cose, token, issuerPub, holderPub) {
  log.debug("Entering witness().");
  var kbt = cbor.decode(token);
  var inner = cbor.decode(kbt.value[0]).get(13);
  var innerBytes = Buffer.from(mdoc.encode(inner));
  await cose.Sign1.decode(innerBytes).verify(issuerPub);
  await cose.Sign1.decode(Buffer.from(token)).verify(holderPub);
  log.debug("Leaving witness().");
}

async function roundTrips() {
  log.debug("Entering roundTrips().");
  var cose = require("@auth0/cose");
  for (const crv of ["P-256", "P-384", "Ed25519"]) {
    var issuer = keyPair(crv);
    var holder = keyPair(crv === "Ed25519" ? "P-256" : crv);
    var algs = { "P-256": -7, "P-384": -35, "Ed25519": -8 };
    var token = sd.issue({ claims: CLAIMS, redact: REDACT, decoys: 2,
      issuerKey: issuer.jwk, alg: algs[crv], kid: "issuer-key-1",
      holderKey: pubOf(holder.jwk) });
    var c = sd.confirm(token, { issuerKey: pubOf(issuer.jwk),
                                holderKey: pubOf(holder.jwk) });
    assert.ok(c.valid, crv + ": ours confirms: " + c.errors.join("; "));
    assert.deepStrictEqual(sd.toPlainClaims(c.claims)["503"],
      CLAIMS["503"], crv + ": a nested redaction restores whole");
    // The decoded payload's hashes, by node, are the disclosures' hashes.
    var sign1 = cbor.decode(token).value;
    var payloadHex = Buffer.from(sign1[2]).toString("hex");
    sign1[1].get(17).forEach(function (d) {
      var h = nodeCrypto.createHash("sha256")
        .update(Buffer.from(mdoc.encode(d))).digest("hex");
      var nestedOk = payloadHex.indexOf(h) !== -1 ||
        sign1[1].get(17).some(function (o) {
          return Buffer.from(o).toString("hex").indexOf(h) !== -1;
        });
      assert.ok(nestedOk, crv + ": node's SHA-256 of every disclosure is " +
                "a hash in the payload or in another disclosure");
    });
    await cose.Sign1.decode(Buffer.from(token))
      .verify(issuer.pub);
    var disclose = c.disclosures.filter(function (r) {
      return r.kind === "claim" && r.key === "region" ||
        r.kind === "claim" && r.key === 503 ||
        r.kind === "element" && r.value === 1549560720;
    }).map(function (r) {
      return r.hash;
    });
    var kbt = sd.present(token, { disclose: disclose, holderKey: holder.jwk,
      alg: crv === "Ed25519" ? -7 : algs[crv], aud: FX.aud, cnonce: "n-1" });
    await witness(cose, kbt, issuer.pub, holder.pub);
    var v = sd.verify(kbt, { issuerKey: pubOf(issuer.jwk), aud: FX.aud,
                             cnonce: "n-1", now: 1800000000 });
    assert.ok(v.valid, crv + ": ours verifies: " + v.errors.join("; "));
    var plain = sd.toPlainClaims(v.claims);
    assert.deepStrictEqual(plain["503"], { country: "us", region: "ca" },
                           crv + ": region shown, postal_code withheld");
    assert.deepStrictEqual(plain["502"], [1549560720, 1674004740],
                           crv + ": one redacted element shown");
    assert.strictEqual(plain["501"], undefined, crv + ": 501 withheld");
    negatives(crv, token, kbt, issuer, holder);
  }
  log.info("PASS ours, P-256, P-384 and Ed25519 issuers: nested and array " +
           "redaction with decoys; @auth0/cose verifies both signatures, " +
           "node's SHA-256 finds every disclosure's hash.");
  log.debug("Leaving roundTrips().");
}

function negatives(crv, token, kbt, issuer, holder) {
  log.debug("Entering negatives(). " + crv);
  var o = { issuerKey: pubOf(issuer.jwk), aud: FX.aud, cnonce: "n-1" };
  assert.ok(!sd.verify(kbt, Object.assign({}, o, { aud: "https://x" }))
    .valid, crv + ": another aud fails");
  assert.ok(!sd.verify(kbt, Object.assign({}, o, { cnonce: "n-2" })).valid,
            crv + ": another cnonce fails");
  assert.ok(!sd.verify(token, o).valid, crv + ": an SD-CWT with no KBT is " +
            "not a presentation");
  var other = keyPair("P-256");
  var forged = sd.present(token, { disclose: [], holderKey: other.jwk,
                                   aud: FX.aud, cnonce: "n-1" });
  assert.ok(/cnf key does not verify/.test(sd.verify(forged, o).errors
    .join(" ")), crv + ": a KBT by a key other than cnf fails");
  var late = sd.present(token, { disclose: [], holderKey: holder.jwk,
    aud: FX.aud, cnonce: "n-1", iat: 4102444801 });
  assert.ok(/after the SD-CWT expired/.test(sd.verify(late, o).errors
    .join(" ")), crv + ": a KBT made after the SD-CWT expired fails");
  // A disclosure swapped for one with a different value.
  var k = cbor.decode(kbt);
  var prot = cbor.decode(k.value[0]);
  var inner = prot.get(13);
  var list = inner.value[1].get(17);
  var arr = cbor.decode(list[0]);
  arr[1] = "tampered";
  list[0] = mdoc.encode(arr);
  inner.value[1].set(17, list);
  assert.ok(/matches no Redacted Claim Hash/.test(sd.verify(rewrap(prot,
    k, holder.jwk), o).errors.join(" ")), crv + ": a changed disclosure " +
    "matches no hash and fails");
  inner.value[1].set(17, []);
  assert.ok(/empty array/.test(sd.verify(rewrap(prot, k, holder.jwk), o)
    .errors.join(" ")), crv + ": an empty sd_claims fails");
  assert.throws(function () {
    sd.issue({ claims: CLAIMS, redact: [[1]], issuerKey: issuer.jwk,
               holderKey: pubOf(holder.jwk) });
  }, /never redacted/, crv + ": iss cannot be redacted");
  log.debug("Leaving negatives().");
}

// A KBT re-signed by the holder around an edited kcwt, so that only the
// SD-CWT's own checks can catch the edit.
function rewrap(prot, k, holderJwk) {
  log.debug("Entering rewrap().");
  var p = new Map(prot);
  var kbtPayload = cbor.decode(k.value[2]);
  var key = nodeCrypto.createPrivateKey({ key: holderJwk, format: "jwk" });
  var protBytes = mdoc.encode(encodableMap(p));
  var toSign = mdoc.encode(["Signature1", protBytes, new Uint8Array(0),
                            k.value[2]]);
  var sig = /^Ed/.test(holderJwk.crv) ? nodeCrypto.sign(null,
    Buffer.from(toSign), key) : nodeCrypto.sign(holderJwk.crv === "P-384" ?
    "sha384" : "sha256", Buffer.from(toSign), { key: key,
    dsaEncoding: "ieee-p1363" });
  assert.ok(kbtPayload.get(3), "the KBT has an aud");
  log.debug("Leaving rewrap().");
  return mdoc.encode(new cbor.Tagged(18, [protBytes, new Map(), k.value[2],
                                          new Uint8Array(sig)]));
}

function encodableMap(v) {
  log.debug("Entering encodableMap().");
  if (v instanceof Map) {
    var m = new Map();
    v.forEach(function (val, key) {
      m.set(key && typeof key === "object" && typeof key.simple === "number" &&
            !(key instanceof Uint8Array) ? new mdoc.Simple(key.simple) : key,
            encodableMap(val));
    });
    log.debug("Leaving encodableMap(). Map.");
    return m;
  }
  if (Array.isArray(v)) {
    log.debug("Leaving encodableMap(). Array.");
    return v.map(encodableMap);
  }
  if (v instanceof cbor.Tagged) {
    log.debug("Leaving encodableMap(). Tagged.");
    return new cbor.Tagged(v.tag, encodableMap(v.value));
  }
  log.debug("Leaving encodableMap().");
  return v;
}

async function main() {
  log.debug("Entering main().");
  specificationVectors();
  await roundTrips();
  log.info("sd_cwt_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
