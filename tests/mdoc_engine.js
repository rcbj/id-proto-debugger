// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: mdoc_engine.js
//
// ---------------------------------------------------------------------------
// The wallet's ISO mdoc (client/src/mdoc.js and its place in sd_jwt_vc.js and
// sd_jwt_vp.js), in node, against an issuer written elsewhere
// (tests/mdoc_test_issuer.js: its own CBOR encoder, node's ECDSA).
//
// Called mdoc_engine.js and not mdoc.js because the tests image is one flat
// directory and a test named after a module would replace it.
//
//   * reading: an issued IssuerSigned is recognized as mso_mdoc, its elements
//     become the wallet's rows and claims, and its device key is the
//     credential's cnf.jwk — which is where every other part of the wallet
//     looks for the key a credential is bound to;
//   * the wallet's own checks: every element's digest, and issuerAuth
//     against the document signer certificate it carries; a tampered element
//     fails by name;
//   * presenting: the DeviceResponse carries exactly the chosen elements,
//     BYTE FOR BYTE as issued, the issuerAuth unchanged, and a device
//     signature that verifies — with the ISSUER's encoder and node's crypto —
//     over the transcript OpenID4VP 1.0 Appendix B.2.6.1 defines, and not
//     over one for another nonce, Verifier, response URI or encryption key.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");
const issuer = require("./mdoc_test_issuer.js");
const paths = require("./module_paths.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "mdoc_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

function srcDir() {
  log.debug("Entering srcDir().");
  for (const c of [path.resolve(__dirname, ".."),
                   path.resolve(__dirname, "..", "source-tree")]) {
    if (fs.existsSync(path.join(c, "client", "package.json"))) {
      log.debug("Leaving srcDir().");
      return path.join(c, "client", "src");
    }
  }
  log.debug("Leaving srcDir(). Default.");
  return path.resolve(__dirname, "..", "client", "src");
}
function load(name) {
  log.debug("Entering load(). " + name);
  log.debug("Leaving load().");
  return paths.requireSharedModule([path.join(srcDir(), name)],
                                   "client/src/" + name);
}
// sd_jwt_vc.js reads localStorage; a node run has none, so a Map stands in.
if (typeof globalThis.localStorage === "undefined") {
  const store = new Map();
  globalThis.localStorage = {
    getItem: function (k) {
      return store.has(k) ? store.get(k) : null;
    },
    setItem: function (k, v) {
      store.set(k, String(v));
    },
    removeItem: function (k) {
      store.delete(k);
    }
  };
}
const mdoc = load("mdoc.js");
const cbor = load("cbor.js");
const sdJwtVc = load("sd_jwt_vc.js");
const sdJwtVp = load("sd_jwt_vp.js");

function ecPair() {
  log.debug("Entering ecPair().");
  const p = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  log.debug("Leaving ecPair().");
  return { publicJwk: p.publicKey.export({ format: "jwk" }),
           privateJwk: p.privateKey.export({ format: "jwk" }),
           publicKey: p.publicKey };
}

const ELEMENTS = {
  given_name: "Erika", family_name: "Mustermann",
  birth_date: new issuer.Tag(1004, "1971-09-01"), age_over_18: true
};

async function main() {
  log.debug("Entering main().");
  const auth = await issuer.authority("mdoc engine");
  const device = ecPair();
  const credential = issuer.issue(auth, device.publicJwk, ELEMENTS);

  // --- reading -------------------------------------------------------------
  assert.strictEqual(sdJwtVc.credentialFormat(credential), "mso_mdoc",
    "an IssuerSigned must be recognized as mso_mdoc");
  const parsed = sdJwtVc.parseCredential(credential);
  assert.strictEqual(parsed.docType, issuer.DOCTYPE);
  assert.deepStrictEqual(Object.keys(parsed.claims).sort(),
    Object.keys(ELEMENTS).sort(), "every element is a claim");
  assert.strictEqual(parsed.claims.birth_date, "1971-09-01",
    "a full-date (tag 1004) reads as its text");
  assert.strictEqual(parsed.disclosures.length, 4,
    "every element is a row the holder can select");
  assert.ok(parsed.disclosures.every(function (d) {
    return d.encoded === issuer.NS + "/" + d.name;
  }), "rows are keyed namespace/element");
  assert.ok(parsed.payload.cnf && parsed.payload.cnf.jwk.x ===
    device.publicJwk.x && parsed.payload.cnf.jwk.y === device.publicJwk.y,
    "the MSO's device key is the credential's cnf.jwk");
  assert.strictEqual(sdJwtVp.claimNameForPath(issuer.NS + ".given_name",
    "mso_mdoc"), "given_name", "a [namespace, element] path names the " +
    "element");
  // The two W3C formats address claims under credentialSubject, and the
  // wallet's claim map is flat in both.
  ["jwt_vc_json", "ldp_vc"].forEach(function (format) {
    assert.strictEqual(sdJwtVp.claimNameForPath(
      "credentialSubject.given_name", format), "given_name",
      format + ": a credentialSubject path names the claim");
  });
  log.info("PASS reading an mdoc an independent issuer made.");

  // --- the wallet's own checks ----------------------------------------------
  let checks = await mdoc.checkIssuerSigned(parsed.mdoc);
  assert.ok(checks.every(function (c) {
    return c.ok;
  }), "a correct mdoc fails its own checks: " + JSON.stringify(checks));
  const tampered = mdoc.parseIssuerSigned(credential);
  tampered.items[1].tagged = Uint8Array.from(tampered.items[1].tagged);
  tampered.items[1].tagged[tampered.items[1].tagged.length - 1] ^= 1;
  checks = await mdoc.checkIssuerSigned(tampered);
  assert.strictEqual(checks.filter(function (c) {
    return c.name === "Element digests";
  })[0].ok, false, "a tampered element must fail its digest");
  log.info("PASS element digests and the issuer signature.");

  // --- presenting -----------------------------------------------------------
  const verifierKey = ecPair().publicJwk;
  const ctx = { clientId: "x509_hash:abc", nonce: "n-1",
                responseUri: "https://verifier.example/response",
                encryptionJwk: verifierKey };
  const built = await sdJwtVp.buildPresentationFor({
    credential: credential, parsed: parsed,
    selected: [issuer.NS + "/given_name", issuer.NS + "/family_name"],
    holderPrivateJwk: device.privateJwk, aud: ctx.clientId,
    nonce: ctx.nonce, responseUri: ctx.responseUri,
    encryptionJwk: ctx.encryptionJwk, keyBinding: true });
  assert.strictEqual(built.format, "mso_mdoc");
  const top = cbor.decode(Buffer.from(built.presentation, "base64url"));
  assert.strictEqual(top.get("version"), "1.0");
  assert.strictEqual(top.get("status"), 0);
  const doc = top.get("documents")[0];
  const sentItems = doc.get("issuerSigned").get("nameSpaces")
    .get(issuer.NS);
  assert.strictEqual(sentItems.length, 2, "exactly the chosen elements go");
  const issued = cbor.decode(Buffer.from(credential, "base64url"));
  const issuedItems = issued.get("nameSpaces").get(issuer.NS);
  sentItems.forEach(function (t) {
    assert.ok(issuedItems.some(function (i) {
      return Buffer.from(i.value).equals(Buffer.from(t.value));
    }), "a presented element must be the issued bytes, unchanged");
  });
  assert.ok(Buffer.from(issuer.cbor(doc.get("issuerSigned").get(
    "issuerAuth")[2])).equals(Buffer.from(issuer.cbor(
    issued.get("issuerAuth")[2]))), "issuerAuth goes unchanged");
  const deviceSigned = doc.get("deviceSigned");
  const forIssuer = {
    docType: doc.get("docType"),
    deviceSigned: {
      nameSpacesBytes: deviceSigned.get("nameSpaces").value,
      deviceAuth: { deviceSignature: deviceSigned.get("deviceAuth")
        .get("deviceSignature") }
    }
  };
  assert.ok(issuer.verifyDeviceSignature(forIssuer, device.publicKey,
    issuer.transcript(ctx.clientId, ctx.nonce, verifierKey,
                      ctx.responseUri)),
    "the device signature must verify, with an encoder the wallet does not " +
    "share, over OpenID4VP's session transcript");
  [["another nonce", issuer.transcript(ctx.clientId, "n-2", verifierKey,
                                       ctx.responseUri)],
   ["another Verifier", issuer.transcript("x509_hash:xyz", ctx.nonce,
                                          verifierKey, ctx.responseUri)],
   ["another response URI", issuer.transcript(ctx.clientId, ctx.nonce,
     verifierKey, "https://elsewhere.example/response")],
   ["no encryption key", issuer.transcript(ctx.clientId, ctx.nonce, null,
                                           ctx.responseUri)]
  ].forEach(function (c) {
    assert.ok(!issuer.verifyDeviceSignature(forIssuer, device.publicKey,
      c[1]), "the device signature must NOT verify for " + c[0]);
  });
  const read = mdoc.readDeviceResponse(built.presentation);
  assert.ok(await mdoc.checkDeviceSignature(read, ctx),
    "the wallet's own re-check of its device signature must pass");
  const presented = sdJwtVp.presentedClaims(built.presentation);
  assert.deepStrictEqual(Object.keys(presented.claims).sort(),
    ["family_name", "given_name"], "what the Verifier ends up with");
  log.info("PASS the DeviceResponse and its device signature.");
  log.info("mdoc_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
