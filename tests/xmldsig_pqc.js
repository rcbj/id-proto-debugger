// File: xmldsig_pqc.js
//
// ===========================================================================
// POST-QUANTUM XML SIGNATURE — THE SIXTEEN IDENTIFIERS, DRIVEN.
//
// `common/xmldsig.js` gained the signature methods of
// draft-eastlake-rfc9231bis-xmlsec-uris-09 (21 August 2026): ML-DSA at three
// parameter sets (section 3.3.15, FIPS 204), SLH-DSA at twelve (section
// 3.3.16, FIPS 205) and HSS/LMS (section 3.3.14, RFC 8554). The cryptography
// is NOT in that file — it arrives through `opts.signer` / `opts.verifier`,
// which is the arrangement it already had for ECDSA and HMAC — and
// `client/src/xmldsig_pqc.js` is the one bridge from a `SignatureMethod` to
// the engine that performs it.
//
// WHAT THIS FILE IS FOR, and it is not the lattice. ML-DSA, SLH-DSA and
// HSS/LMS are each already held to their own standards' vectors:
// `tests/pqc_engines.js` drives FIPS 204 and 205 and `tests/hbs_signatures.js`
// drives RFC 8554's and RFC 9858's own test cases, one verification vector per
// XMSS parameter set, and eight signatures that must NOT verify. Repeating
// that here would be a second copy of somebody else's answer.
//
// What is NEW here is the XML layer, and it has four ways to be wrong that no
// primitive test can see:
//
//   A. THE WRONG BYTES ARE SIGNED. XMLDSIG hands a signer the canonicalized
//      SignedInfo as a forge BINARY STRING — one character per byte, already
//      UTF-8 encoded — and every engine here speaks Uint8Array. A
//      `new TextEncoder().encode()` on that re-encodes every byte from 0x80 up
//      as a two-byte sequence, so the signature is over a DIFFERENT MESSAGE:
//      it verifies against itself perfectly and against no other
//      implementation on earth.
//
//      **A SignedInfo IS ALWAYS ASCII, AND THAT IS WHY THIS FAULT WOULD SHIP
//      RATHER THAN FAIL.** It holds URIs, element names and base64 — the
//      document's own text never reaches it, because a Reference carries a
//      DIGEST of the content and not the content. So the two encodings agree
//      on every real SignedInfo this engine produces, a wrong conversion
//      passes every round-trip check in this file, and the first thing to
//      notice would be another implementation refusing a signature. Section A
//      therefore does two things: it asserts the SignatureValue equals a
//      signature computed directly over those octets, and it demonstrates on
//      octets that DO carry a high byte that the two conversions diverge —
//      which is what makes the first assertion an assertion rather than a
//      coincidence.
//
//   B. THE URI MEANS THE WRONG ALGORITHM. Twelve of the sixteen differ only in
//      a suffix (`-128s` against `-128f`, `sha2` against `shake`), and picking
//      the neighbouring parameter set produces a signature of a different
//      length that fails for a reason naming nothing. Section B asserts each
//      URI's SignatureValue is the length FIPS 204/205 specifies for the set
//      the URI names, which is the one property that distinguishes them.
//
//   C. THE DOCUMENT DOES NOT ROUND-TRIP. Signing and verifying through the
//      same engine can agree while producing a document a verifier cannot
//      read. Section C verifies the produced XML back through `verifyXml()` —
//      digests and signature — and then breaks the document and requires the
//      refusal.
//
//   D. THE REGISTRY DISAGREES WITH THE DRAFT. Section D holds the sixteen URIs
//      and their sizes against the draft's own text, written out, because a
//      table copied by hand from a specification is a table with a transposed
//      digit in it.
//
// **THE URIs ARE FROM A DRAFT AND THIS FILE SAYS SO.** There is no W3C
// Recommendation for any of this — the W3C's own strategy issue #484 asks for
// a workshop — and Apache Santuario's in-flight PR for the same draft ships
// `http://www.w3.org/tbd#ml-dsa-44` rather than commit to the namespace. So
// section D is a check against a document that can still change, and when it
// does, this file is where the change is noticed.
//
// Needs no browser, no IdP and no network. It takes a `--url` it ignores, for
// the reason every node-only job here does: run-report.js passes one to every
// script and commander exits on an option it was not told about.
// ===========================================================================

const path = require("path");
const bunyan = require("bunyan");
const { program } = require("commander");

program.option("--url <url>", "ignored; this test needs no server").parse();

const log = bunyan.createLogger({
  name: "xmldsig_pqc",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

// The browser globals common/xmldsig.js expects, exactly as
// tests/xmlsec_interop.js supplies them.
const xmldom = require("@xmldom/xmldom");
global.DOMParser = xmldom.DOMParser;
global.XMLSerializer = xmldom.XMLSerializer;
const { webcrypto } = require("crypto");
if (!global.window) global.window = {};
if (!global.window.crypto) global.window.crypto = webcrypto;

const { requireSharedModule } = require("./module_paths.js");
const xd = requireSharedModule([
  path.join(__dirname, "xmldsig.js"),
  path.join(__dirname, "..", "common", "xmldsig.js"),
], "common/xmldsig.js");
const bridge = requireSharedModule([
  path.join(__dirname, "xmldsig_pqc_bridge.js"),
  path.join(__dirname, "..", "client", "src", "xmldsig_pqc.js"),
], "client/src/xmldsig_pqc.js");
const pqc = requireSharedModule([
  path.join(__dirname, "pqc.js"),
  path.join(__dirname, "..", "client", "src", "pqc.js"),
], "client/src/pqc.js");
const pk = requireSharedModule([
  path.join(__dirname, "pk_encryption.js"),
  path.join(__dirname, "..", "client", "src", "pk_encryption.js"),
], "client/src/pk_encryption.js");
const frodo = requireSharedModule([
  path.join(__dirname, "frodokem.js"),
  path.join(__dirname, "..", "client", "src", "frodokem.js"),
], "client/src/frodokem.js");
const hbs = requireSharedModule([
  path.join(__dirname, "hbs.js"),
  path.join(__dirname, "..", "client", "src", "hbs.js"),
], "client/src/hbs.js");

let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) {
    pass++;
    log.info("  PASS  " + name + (detail ? "  -> " + detail : ""));
  } else {
    fail++;
    log.error("  FAIL  " + name + (detail ? "  -> " + detail : ""));
  }
  return !!ok;
}

// ---------------------------------------------------------------------------
// SECTION D's TABLE, written out from the draft rather than read from the code
// under test. Every number is section 3.3.15's or 3.3.16's own: public key
// bytes and signature bytes per parameter set. A table derived from
// SIG_METHODS would assert that the code agrees with itself.
// ---------------------------------------------------------------------------
const NS = "http://www.w3.org/2026/08/xmldsig-more#";
const DRAFT = [
  ["ml-dsa-44", "ML-DSA-44", 1312, 2420],
  ["ml-dsa-65", "ML-DSA-65", 1952, 3309],
  ["ml-dsa-87", "ML-DSA-87", 2592, 4627],
  ["slh-dsa-sha2-128s", "SLH-DSA-SHA2-128s", 32, 7856],
  ["slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f", 32, 17088],
  ["slh-dsa-sha2-192s", "SLH-DSA-SHA2-192s", 48, 16224],
  ["slh-dsa-sha2-192f", "SLH-DSA-SHA2-192f", 48, 35664],
  ["slh-dsa-sha2-256s", "SLH-DSA-SHA2-256s", 64, 29792],
  ["slh-dsa-sha2-256f", "SLH-DSA-SHA2-256f", 64, 49856],
  ["slh-dsa-shake-128s", "SLH-DSA-SHAKE-128s", 32, 7856],
  ["slh-dsa-shake-128f", "SLH-DSA-SHAKE-128f", 32, 17088],
  ["slh-dsa-shake-192s", "SLH-DSA-SHAKE-192s", 48, 16224],
  ["slh-dsa-shake-192f", "SLH-DSA-SHAKE-192f", 48, 35664],
  ["slh-dsa-shake-256s", "SLH-DSA-SHAKE-256s", 64, 29792],
  ["slh-dsa-shake-256f", "SLH-DSA-SHAKE-256f", 64, 49856]
];

// A document with NON-ASCII in it, deliberately: section A cannot detect the
// TextEncoder fault with an all-ASCII SignedInfo, because for bytes under 0x80
// the two encodings agree. The Id and the element names stay ASCII so the
// canonicalizer and the Reference are ordinary.
const XML = '<Assertion xmlns="urn:x" ID="_pq1">' +
  '<Issuer>https://sts.example.com/éü中</Issuer>' +
  '<Subject>alice—smith</Subject></Assertion>';

// The five parameter sets driven through the full XML round trip. Twelve
// SLH-DSA sets at up to 50KB a signature would take minutes and would assert
// nothing the registry check does not: one "s" and one "f", one SHA-2 and one
// SHAKE, is the coverage that distinguishes the axes. The other seven are
// held to their sizes by section D and to their cryptography by
// tests/pqc_engines.js.
const DRIVEN = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128f"];

function uriFor(algName) {
  const row = DRAFT.filter(function (r) { return r[1] === algName; })[0];
  return NS + row[0];
}

// ---------------------------------------------------------------------------
function registryMatchesTheDraft() {
  log.info("D. the registry says what the draft says");
  check("the registry holds sixteen post-quantum SignatureMethods",
        xd.PQ_SIG_URIS.length === 16, xd.PQ_SIG_URIS.length + " found");
  DRAFT.forEach(function (row) {
    const uri = NS + row[0];
    const spec = xd.SIG_METHODS[uri];
    if (!check(row[0] + ": the URI is in the registry", !!spec)) {
      return;
    }
    check(row[0] + ": it names " + row[1], spec.alg === row[1], spec.alg);
    check(row[0] + ": public key is " + row[2] + " bytes",
          spec.pubBytes === row[2], String(spec.pubBytes));
    check(row[0] + ": signature is " + row[3] + " bytes",
          spec.sigBytes === row[3], String(spec.sigBytes));
    check(row[0] + ": it is marked post-quantum AND draft",
          spec.postQuantum === true && spec.draft === true);
    check(row[0] + ": its label says draft, so a menu cannot imply a REC",
          /draft/i.test(spec.label || ""), spec.label);
  });
  // HSS/LMS is the sixteenth and is the one with no fixed sizes: one URI
  // covers every LMS tree height and Winternitz width, so the draft gives it
  // no numbers and neither does the registry.
  const hss = xd.SIG_METHODS[xd.HSS_LMS_URI];
  check("hss-lms is in the registry", !!hss);
  check("hss-lms carries no fixed signature size, because the URI does not " +
        "name a parameter set", !!hss && hss.sigBytes === undefined);
  check("hss-lms is marked STATEFUL, which nothing else here is",
        !!hss && hss.stateful === true);
  check("and its label says so in capitals, because a menu is where " +
        "somebody chooses it",
        !!hss && /STATEFUL/.test(hss.label || ""), hss && hss.label);
}

// ---------------------------------------------------------------------------
function theBytesSignedAreTheCanonicalizedSignedInfo() {
  log.info("A. the signature is over the canonicalized SignedInfo, byte for " +
           "byte");
  const alg = "ML-DSA-65";
  const kp = pqc.generateAkpKeyPair(alg);
  // Capture what the engine hands the signer, then sign it a SECOND time
  // directly through pqc.js and require the two signatures to be identical.
  // ML-DSA signing is deterministic, so equality here is exact — and it is
  // what proves no re-encoding happened between the canonicalizer and the
  // lattice.
  let captured = null;
  const signed = xd.signXml(XML, {
    mode: "enveloped", sigAlg: uriFor(alg), refUri: "#_pq1", keyInfo: "none",
    signer: function (octets, spec) {
      captured = octets;
      return bridge.signerFor(kp.priv)(octets, spec);
    }
  });
  // Stated rather than assumed: this is WHY a wrong conversion would ship.
  check("the SignedInfo this engine produces is pure ASCII — the document's " +
        "own text never reaches it, only a digest of it",
        !/[^\x00-\x7f]/.test(captured || ""),
        (captured || "").length + " characters");
  const direct = pqc.signWithPriv(alg, bridge.binaryStringToBytes(captured),
                                  kp.priv);
  const fromXml = Buffer.from(signed.signatureValue, "base64");
  check("the SignatureValue is exactly the signature over those octets",
        Buffer.compare(fromXml, Buffer.from(direct)) === 0,
        fromXml.length + " bytes");
  // The demonstration, on octets that DO carry a high byte — which a
  // SignedInfo does not, and which is exactly why the assertion above needs
  // this one beside it to mean anything.
  const highBytes = "SignedInfo\u00e9\u00fc";
  const viaBridge = pqc.signWithPriv(alg,
      bridge.binaryStringToBytes(highBytes), kp.priv);
  const viaTextEncoder = pqc.signWithPriv(alg,
      new TextEncoder().encode(highBytes), kp.priv);
  check("on octets with a high byte the two conversions DIVERGE, which is " +
        "the fault the one shared conversion exists to prevent",
        Buffer.compare(Buffer.from(viaBridge),
                       Buffer.from(viaTextEncoder)) !== 0);
  check("and the bridge's conversion is the byte-for-byte one",
        bridge.binaryStringToBytes(highBytes).length === highBytes.length,
        bridge.binaryStringToBytes(highBytes).length + " bytes from " +
        highBytes.length + " characters");
}

// ---------------------------------------------------------------------------
function everyDrivenAlgorithmRoundTrips() {
  log.info("B and C. each driven algorithm signs, is the right length, " +
           "verifies, and refuses");
  DRIVEN.forEach(function (alg) {
    const uri = uriFor(alg);
    const spec = xd.SIG_METHODS[uri];
    const kp = pqc.generateAkpKeyPair(alg);
    const signed = xd.signXml(XML, {
      mode: "enveloped", sigAlg: uri, digestUri: spec.digestUri,
      refUri: "#_pq1", keyInfo: "none",
      signer: bridge.signerFor(kp.priv)
    });
    check(alg + ": SignedInfo names the draft URI",
          signed.signatureMethod === uri);
    const sigLen = Buffer.from(signed.signatureValue, "base64").length;
    check(alg + ": the SignatureValue is the FIPS length for this set",
          sigLen === spec.sigBytes, sigLen + " bytes");
    const v = xd.verifyXml(signed.xml,
        { verifier: bridge.verifierFor(kp.pub) });
    check(alg + ": the document verifies — signature AND references",
          v.valid === true && v.signatureValid === true &&
          v.referencesValid === true,
          JSON.stringify({ valid: v.valid, sig: v.signatureValid,
                           refs: v.referencesValid }));
    // A different key must be refused — the ordinary negative, and the one
    // that shows the verification is looking at the signature at all.
    const other = pqc.generateAkpKeyPair(alg);
    const wrongKey = xd.verifyXml(signed.xml,
        { verifier: bridge.verifierFor(other.pub) });
    check(alg + ": a key the document was not signed with is refused",
          wrongKey.signatureValid === false);
    // A tampered document, and WHICH CHECK CATCHES IT IS THE POINT. Changing
    // the signed content leaves SignedInfo untouched, so the SIGNATURE is
    // still perfectly valid — it is the Reference DIGEST that no longer
    // matches. A test asserting only `signatureValid === false` here would
    // fail against a correct engine, and one asserting only `valid` would not
    // say which half did the work.
    const tampered = signed.xml.replace("alice", "mallo");
    const broken = xd.verifyXml(tampered,
        { verifier: bridge.verifierFor(kp.pub) });
    check(alg + ": changing the signed content is REFUSED",
          broken.valid === false, JSON.stringify({ valid: broken.valid }));
    check(alg + ": and it is the Reference digest that catches it, not the " +
          "signature — SignedInfo did not change",
          broken.referencesValid === false && broken.signatureValid === true,
          JSON.stringify({ sig: broken.signatureValid,
                           refs: broken.referencesValid }));
    // A SignatureValue of the wrong length is refused BY LENGTH, naming the
    // parameter set, rather than reaching the engine as bytes it cannot use.
    let lengthMessage = "";
    try {
      bridge.verifierFor(kp.pub)("x", new Uint8Array(7), spec);
    } catch (e) {
      lengthMessage = e.message;
    }
    check(alg + ": a truncated SignatureValue is refused by length, with " +
          "the expected size in the sentence",
          lengthMessage.indexOf(String(spec.sigBytes)) >= 0, lengthMessage);
  });
}

// ---------------------------------------------------------------------------
function hssLmsSignsAndSaysItSpentAKey() {
  log.info("E. HSS/LMS — the one that changes its own private key");
  // The smallest parameter set RFC 8554 defines, because key generation walks
  // the whole tree and this test is not about how long that takes.
  const kp = hbs.hssKeygen({ levels: [{ lms: "LMS_SHA256_M32_H5",
                                        lmots: "LMOTS_SHA256_N32_W8" }] });
  let advanced = null;
  const signed = xd.signXml(XML, {
    mode: "enveloped", sigAlg: xd.HSS_LMS_URI, refUri: "#_pq1",
    keyInfo: "none",
    signer: bridge.signerFor(kp.privateKey, {
      onKeyAdvanced: function (next) { advanced = next; }
    })
  });
  check("hss-lms: the document is signed",
        !!signed.signatureValue && signed.signatureValue.length > 0);
  check("hss-lms: SignedInfo names the draft URI",
        signed.signatureMethod === xd.HSS_LMS_URI);
  check("hss-lms: it verifies",
        xd.verifyXml(signed.xml,
            { verifier: bridge.verifierFor(kp.publicKey) }).valid === true);
  // THE PART THAT MATTERS. A one-time key was spent, so the private key that
  // comes back is not the one that went in — and a caller that ignores it
  // signs twice from one index, which is what hands an attacker the material
  // to forge a third message. Nothing in the document records this.
  check("hss-lms: signing HANDED BACK AN ADVANCED PRIVATE KEY",
        advanced !== null);
  check("hss-lms: and it is not the key that went in — a one-time key was " +
        "spent", advanced !== null && Buffer.compare(
            Buffer.from(advanced), Buffer.from(kp.privateKey)) !== 0);
  // A signer given no way to report that is REFUSED rather than allowed to
  // leave the caller reusing an index.
  let refusal = "";
  try {
    xd.signXml(XML, {
      mode: "enveloped", sigAlg: xd.HSS_LMS_URI, refUri: "#_pq1",
      keyInfo: "none", signer: bridge.signerFor(kp.privateKey)
    });
  } catch (e) {
    refusal = e.message;
  }
  check("hss-lms: signing with no onKeyAdvanced is REFUSED, and the refusal " +
        "says why", /STATEFUL/.test(refusal) && /forge/.test(refusal),
        refusal);
}

// ---------------------------------------------------------------------------
function theEngineRefusesWhatItCannotDo() {
  log.info("F. the refusals a caller has to be able to act on");
  // xmldsig.js implements RSA and nothing else; a post-quantum method with no
  // signer must say which module to reach for rather than "unsupported".
  let noSigner = "";
  try {
    xd.signXml(XML, { mode: "enveloped", sigAlg: uriFor("ML-DSA-44"),
                      refUri: "#_pq1", keyInfo: "none",
                      privateKeyPem: "not a key" });
  } catch (e) {
    noSigner = e.message;
  }
  check("a post-quantum method with no signer names opts.signer AND the " +
        "engine that performs it",
        /opts\.signer/.test(noSigner) && /pqc\.js/.test(noSigner), noSigner);
  // And the bridge refuses a method that is not one of its own, by name.
  let notPq = "";
  try {
    bridge.engineFor(xd.SIG_METHODS[
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"]);
  } catch (e) {
    notPq = e.message;
  }
  check("the bridge refuses a classical SignatureMethod by name",
        /not one of the post-quantum/.test(notPq), notPq);
}

// ---------------------------------------------------------------------------
// RFC 5869's OWN TEST VECTORS. HKDF is the step a recipient has to reproduce
// exactly, and it is the one part of the key-encapsulation path this project
// implements rather than injects — so it is held to the RFC's published
// vectors and not to a round trip against itself. Appendix A, cases 1, 2 and 3:
// with salt and info, with LONG inputs, and with neither (the default-salt
// path, which is the one a wrong implementation gets wrong).
// ---------------------------------------------------------------------------
const RFC5869 = [
  ["A.1 basic, SHA-256",
   "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
   "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
   "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
   "34007208d5b887185865"],
  ["A.2 longer inputs, SHA-256",
   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
   "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
   "404142434445464748494a4b4c4d4e4f",
   "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
   "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
   "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
   "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
   "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
   "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 82,
   "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
   "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
   "cc30c58179ec3e87c14c01d5c1f3434f1d87"],
  ["A.3 zero-length salt and info, SHA-256",
   "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 42,
   "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d" +
   "9d201395faa4b61a96c8"]
];

function hkdfMatchesTheRfcsOwnVectors() {
  log.info("G. HKDF against RFC 5869 appendix A");
  const hex = function (h) { return Buffer.from(h, "hex").toString("binary"); };
  RFC5869.forEach(function (row) {
    const got = Buffer.from(
        xd.hkdf(xd.HMAC_SHA256_URI, hex(row[1]), hex(row[2]), hex(row[3]),
                row[4]),
        "binary").toString("hex");
    check("RFC 5869 " + row[0], got === row[5], got);
  });
  // And a PRF this file does not implement is refused by name rather than
  // quietly falling back to SHA-1, which would derive a key that decrypts
  // nothing and say nothing about why.
  let refused = "";
  try {
    xd.hkdf("urn:not-a-prf", "ikm", "", "", 16);
  } catch (e) {
    refused = e.message;
  }
  check("an unknown PRF is refused by name", /not a PRF/.test(refused),
        refused);
}

// ---------------------------------------------------------------------------
function mlKemEncryptsAndDecrypts() {
  log.info("H. ML-KEM key encapsulation in XML Encryption (section 3.6.9)");
  const mlKemUris = xd.KEM_URIS.filter(function (uri) {
    return xd.KEM_METHODS[uri].family === "mlkem";
  });
  check("the registry holds three ML-KEM methods", mlKemUris.length === 3,
        String(mlKemUris.length));
  check("and fifteen key-encapsulation methods in all — three from section " +
        "3.6.9 and twelve from 3.6.10", xd.KEM_URIS.length === 15,
        String(xd.KEM_URIS.length));
  const sizes = { "ML-KEM-512": [800, 768], "ML-KEM-768": [1184, 1088],
                  "ML-KEM-1024": [1568, 1568] };
  mlKemUris.forEach(function (uri) {
    const spec = xd.KEM_METHODS[uri];
    check(spec.alg + ": the registry has FIPS 203's sizes",
          spec.pubBytes === sizes[spec.alg][0] &&
          spec.ctBytes === sizes[spec.alg][1],
          spec.pubBytes + "/" + spec.ctBytes);
    check(spec.alg + ": its label says draft", /draft/i.test(spec.label || ""),
          spec.label);
    const kem = bridge.kemFor(spec);
    const kp = pk.mlkemSet(spec.alg).kem.keygen();
    const doc = xd.encryptXml(XML,
        { keyAlg: uri, kem: kem, kemPublicKey: kp.publicKey });
    check(spec.alg + ": the EncryptionMethod names the draft URI",
          doc.indexOf(uri) > 0);
    // THE DERIVATION IS IN THE DOCUMENT. The draft says the shared secret is
    // "typically" fed to a KDF and pins nothing, so a document that did not
    // state its own parameters would be readable only by an implementation
    // that happened to guess the same ones.
    check(spec.alg + ": the document states its own key derivation",
          doc.indexOf("HKDFParams") > 0 && doc.indexOf(xd.HKDF_URI) > 0 &&
          doc.indexOf("KeyLength") > 0);
    // And the CipherValue is an ENCAPSULATION, not a wrapped key — which is
    // the one structural difference from every other EncryptedKey here, and
    // the length is how you can tell.
    const ct = doc.match(
        /<xenc:EncryptedKey>[\s\S]*?<xenc:CipherValue>([^<]+)/)[1];
    check(spec.alg + ": the CipherValue is the encapsulation, not a wrapped " +
          "key", Buffer.from(ct, "base64").length === spec.ctBytes,
          Buffer.from(ct, "base64").length + " bytes");
    const back = xd.decryptXml(doc,
        { kem: kem, kemPrivateKey: kp.secretKey });
    check(spec.alg + ": it round-trips", back.indexOf("alice") > 0);
    // A wrong decapsulation key. ML-KEM is IMPLICITLY REJECTING (FIPS 203),
    // so this does not fail at the KEM — it produces a different, perfectly
    // well-formed secret and fails at the AEAD tag. The message has to say so
    // or it reads as a corrupted document.
    const other = pk.mlkemSet(spec.alg).kem.keygen();
    let wrongKey = "";
    try {
      xd.decryptXml(doc, { kem: kem, kemPrivateKey: other.secretKey });
    } catch (e) {
      wrongKey = e.message;
    }
    check(spec.alg + ": a wrong decapsulation key is refused, and the " +
          "message explains that a KEM fails at the tag",
          /implicitly rejecting/.test(wrongKey), wrongKey.slice(0, 70));
  });
  // FrodoKEM's twelve, section 3.6.10. The MECHANISM is held to the reference
  // implementation's own Known Answer Tests in tests/frodokem_vectors.js —
  // this is the XML layer over it, and the encapsulation LENGTH is what says
  // the right parameter set was used: the ephemeral variants' ciphertexts are
  // shorter than their salted twins by exactly the salt.
  const frodoUris = xd.KEM_URIS.filter(function (uri) {
    return xd.KEM_METHODS[uri].family === "frodokem";
  });
  check("the registry holds twelve FrodoKEM methods", frodoUris.length === 12,
        String(frodoUris.length));
  frodoUris.forEach(function (uri) {
    const spec = xd.KEM_METHODS[uri];
    const kem = bridge.kemFor(spec);
    const kp = frodo.keygen(spec.alg, function (n) {
      return new Uint8Array(require("crypto").randomBytes(n));
    });
    const doc = xd.encryptXml(XML,
        { keyAlg: uri, kem: kem, kemPublicKey: kp.publicKey });
    const ct = doc.match(
        /<xenc:EncryptedKey>[\s\S]*?<xenc:CipherValue>([^<]+)/)[1];
    check(spec.alg + ": the encapsulation is the published length",
          Buffer.from(ct, "base64").length === spec.ctBytes,
          Buffer.from(ct, "base64").length + " bytes");
    const back = xd.decryptXml(doc,
        { kem: kem, kemPrivateKey: kp.secretKey });
    check(spec.alg + ": it round-trips through XML Encryption",
          back.indexOf("alice") > 0);
  });
  // The ephemeral ciphertext is SHORTER, which is the one difference visible
  // from outside — and a reminder that it is not the only one. See
  // client/src/frodokem.js.
  const salted = xd.KEM_METHODS[
      xd.XMLDSIG_MORE_2026 + "frodokem-640-aes"];
  const ephemeral = xd.KEM_METHODS[
      xd.XMLDSIG_MORE_2026 + "e-frodokem-640-aes"];
  check("the ephemeral variant's ciphertext is shorter by exactly the salt",
        salted.ctBytes - ephemeral.ctBytes === 32,
        salted.ctBytes + " against " + ephemeral.ctBytes);
  check("and its label says EPHEMERAL, because that is what a reader has to " +
        "weigh", /EPHEMERAL/.test(ephemeral.label || ""), ephemeral.label);

  // A KEM with no derivation stated is refused rather than defaulted.
  const spec = xd.KEM_METHODS[xd.KEM_URIS[0]];
  const kem = bridge.kemFor(spec);
  const kp = pk.mlkemSet(spec.alg).kem.keygen();
  const doc = xd.encryptXml(XML,
      { keyAlg: xd.KEM_URIS[0], kem: kem, kemPublicKey: kp.publicKey });
  const stripped = doc.replace(
      /<xenc11:KeyDerivationMethod[\s\S]*?<\/xenc11:KeyDerivationMethod>/,
      "");
  let noKdf = "";
  try {
    xd.decryptXml(stripped, { kem: kem, kemPrivateKey: kp.secretKey });
  } catch (e) {
    noKdf = e.message;
  }
  check("an EncryptedKey with no KeyDerivationMethod is refused — a KEM's " +
        "derivation is not guessable", /not guessable/.test(noKdf), noKdf);
}

// ---------------------------------------------------------------------------
function theMenuIsBuiltFromTheRegistry() {
  log.info("I. the menu the five signing pages draw");
  // A <select> the way a page has one, through @xmldom — the builder takes a
  // DOM element and the registry, so it is the same code the browser runs.
  const doc = new xmldom.DOMParser().parseFromString(
      "<select id='sig'><option value='a'>classical</option></select>",
      "text/html");
  const select = doc.documentElement;
  const added = bridge.appendSignatureOptions(select, xd.SIG_METHODS,
                                              xd.PQ_SIG_URIS);
  check("all sixteen post-quantum methods reach the menu", added === 16,
        String(added));
  const groups = select.getElementsByTagName("optgroup");
  check("they go in one optgroup, not loose among the classical ones",
        groups.length === 1);
  check("whose label names the draft, because what separates them from the " +
        "options above is how settled the identifier is",
        groups.length === 1 &&
        /rfc9231bis/.test(groups[0].getAttribute("label") || ""),
        groups.length === 1 ? groups[0].getAttribute("label") : "");
  const options = select.getElementsByTagName("option");
  check("the classical option that was already there is untouched",
        options.length === 17 && options[0].getAttribute("value") === "a",
        options.length + " options");
  // Every generated option carries the URI in its title: the label names the
  // algorithm, and the thing that goes into SignedInfo is the identifier.
  let titled = 0;
  for (let i = 0; i < options.length; i++) {
    const value = options[i].getAttribute("value");
    if (xd.SIG_METHODS[value] && xd.SIG_METHODS[value].postQuantum &&
        options[i].getAttribute("title") === value) {
      titled++;
    }
  }
  check("each one carries its URI as the tooltip", titled === 16,
        String(titled));
  // IDEMPOTENT. A page that initialises twice must not offer thirty-two.
  const again = bridge.appendSignatureOptions(select, xd.SIG_METHODS,
                                              xd.PQ_SIG_URIS);
  check("calling it twice adds nothing the second time", again === 0);
  check("and the menu still holds seventeen",
        select.getElementsByTagName("option").length === 17);
  // No element, no crash: a page that does not have the menu is not an error.
  check("a page with no such menu is not an error",
        bridge.appendSignatureOptions(null, xd.SIG_METHODS,
                                      xd.PQ_SIG_URIS) === 0);
}

// ---------------------------------------------------------------------------
// THE THREE FIXED-SHAPE SIGNERS the four protocol pages go through, as
// distinct from the general engine sections above.
//
// `signEnveloped()` and `signWsSecurity()` each sign ONE SHAPE of document
// with almost every XMLDSIG choice fixed, and client/CLAUDE.md records that
// they were deliberately left untouched when the general engine was added
// beside them — a SAML assertion that quietly stops verifying is a defect
// nobody sees until an identity provider refuses it. So the post-quantum
// support in them is ADDITIVE and this section asserts both halves of that:
// the new path works, AND the RSA path is what it was.
//
// The trap they carry is worth stating: `sigAlgSpec()`, the older three-entry
// table those two consult, returns SHA-256 for any URI it does not recognise.
// That is right for the RSA family it was written for. Handed an ML-DSA
// identifier it would have produced a SHA-256-digested Reference and then died
// on the PEM parse, naming a key — so the registry is looked up FIRST.
// ---------------------------------------------------------------------------
const SAML = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
  'assertion" ID="_a1" Version="2.0">' +
  '<saml:Issuer>https://sts.example.com</saml:Issuer>' +
  '<saml:Subject>alice</saml:Subject></saml:Assertion>';

function theFixedShapeSignersTakePostQuantum() {
  log.info("J. signEnveloped() and signWsSecurity() — the protocol pages\' " +
           "path");
  // THE RSA PATH FIRST, because "additive" is a claim about it.
  const forge = xd.forge;
  const rsa = forge.pki.rsa.generateKeyPair({ bits: 1024 });
  const pem = forge.pki.privateKeyToPem(rsa.privateKey);
  const rsaSigned = xd.signEnveloped(SAML, { privateKeyPem: pem });
  check("the RSA path still defaults to rsa-sha256 and needs no signer",
        rsaSigned.indexOf("xmldsig-more#rsa-sha256") > 0 &&
        rsaSigned.indexOf("<ds:SignatureValue>") > 0);
  let noPem = "";
  try {
    xd.signEnveloped(SAML, {});
  } catch (e) {
    noPem = e.message;
  }
  check("and it still refuses a missing privateKeyPem the way it did",
        /privateKeyPem is required/.test(noPem), noPem);

  ["ML-DSA-44", "ML-DSA-65"].forEach(function (alg) {
    const uri = uriFor(alg);
    const spec = xd.SIG_METHODS[uri];
    const kp = pqc.generateAkpKeyPair(alg);
    const signed = xd.signEnveloped(SAML, {
      sigAlg: uri, signer: bridge.signerFor(kp.priv),
      keyInfoXml: xd.derEncodedKeyValueXml(kp.pub)
    });
    check(alg + ": signEnveloped names the draft URI in SignedInfo",
          signed.indexOf(uri) > 0);
    // The Reference digest must be the registry's pairing and NOT
    // sigAlgSpec()'s SHA-256 fallback — this is the trap in the header.
    check(alg + ": the Reference digest is the registry's pairing, not " +
          "sigAlgSpec()'s fallback", signed.indexOf(spec.digestUri) > 0,
          spec.digestUri);
    check(alg + ": the public key travels as a DEREncodedKeyValue, since " +
          "there is no X.509 profile for one",
          signed.indexOf("DEREncodedKeyValue") > 0);
    const sv = signed.match(/<ds:SignatureValue>([^<]+)/)[1];
    check(alg + ": the SignatureValue is the FIPS length",
          Buffer.from(sv, "base64").length === spec.sigBytes,
          Buffer.from(sv, "base64").length + " bytes");
    const v = xd.verifyXmlSignature(signed,
        { verifier: bridge.verifierFor(kp.pub) });
    check(alg + ": verifyXmlSignature accepts it — signature and references",
          v.valid === true, JSON.stringify({ valid: v.valid,
              sig: v.signatureValid, refs: v.referencesValid }));
    const other = pqc.generateAkpKeyPair(alg);
    const wrong = xd.verifyXmlSignature(signed,
        { verifier: bridge.verifierFor(other.pub) });
    check(alg + ": and refuses a key the document was not signed with",
          wrong.valid === false);
  });

  // The two refusals a caller has to be able to act on.
  let noSigner = "";
  try {
    xd.signEnveloped(SAML, { sigAlg: uriFor("ML-DSA-44"),
                             privateKeyPem: pem });
  } catch (e) {
    noSigner = e.message;
  }
  check("signEnveloped with a post-quantum alg and no signer names the bridge",
        /opts\.signer/.test(noSigner) && /xmldsig_pqc/.test(noSigner),
        noSigner);
  const noVerifier = xd.verifyXmlSignature(
      xd.signEnveloped(SAML, {
        sigAlg: uriFor("ML-DSA-44"),
        signer: bridge.signerFor(pqc.generateAkpKeyPair("ML-DSA-44").priv)
      }), {});
  check("verifying one with no verifier says so instead of demanding a " +
        "certificate that cannot exist",
        noVerifier.valid === false &&
        /opts\.verifier/.test(noVerifier.error || ""), noVerifier.error);
}

function main() {
  log.info("Starting Test run. Post-quantum XML Signature and Encryption " +
           "(draft-eastlake-rfc9231bis-xmlsec-uris-09).");
  registryMatchesTheDraft();
  theBytesSignedAreTheCanonicalizedSignedInfo();
  everyDrivenAlgorithmRoundTrips();
  hssLmsSignsAndSaysItSpentAKey();
  theEngineRefusesWhatItCannotDo();
  hkdfMatchesTheRfcsOwnVectors();
  mlKemEncryptsAndDecrypts();
  theMenuIsBuiltFromTheRegistry();
  theFixedShapeSignersTakePostQuantum();
  log.info("---------------------------------------------------------------");
  log.info(pass + " passed, " + fail + " failed.");
  process.exit(fail ? 1 : 0);
}

main();
