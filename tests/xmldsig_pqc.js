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

function main() {
  log.info("Starting Test run. Post-quantum XML Signature " +
           "(draft-eastlake-rfc9231bis-xmlsec-uris-09).");
  registryMatchesTheDraft();
  theBytesSignedAreTheCanonicalizedSignedInfo();
  everyDrivenAlgorithmRoundTrips();
  hssLmsSignsAndSaysItSpentAKey();
  theEngineRefusesWhatItCannotDo();
  log.info("---------------------------------------------------------------");
  log.info(pass + " passed, " + fail + " failed.");
  process.exit(fail ? 1 : 0);
}

main();
