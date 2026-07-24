// File: xmlsec_interop.js
//
// XML Signature & XML Encryption interoperability test for the WS-Trust
// workflow's in-browser crypto (client/src/xmldsig.js). Unlike the other tests
// in this directory it drives NO browser — it exercises the frontend crypto
// module directly in Node and validates its output against independent, official
// libraries:
//   * xml-crypto      — verifies the WS-Security XML digital signature.
//   * xml-encryption  — decrypts the W3C XML-Encryption output and checks the
//                       plaintext round-trips.
// It also round-trips the reusable encrypt AND decrypt logic
// (encryptXml -> decryptXml) that the response pages use to decrypt an
// EncryptedAssertion / message-level EncryptedData.
//
// This proves the exclusive-C14N + RSA-SHA* signing and the xmlenc data/key
// encryption produce standards-compliant output a third party accepts. It is
// wired into tests/run-report.js like any other job (run-report spawns it with a
// --url argument, which this script ignores).
//
// The module under test (client/src/xmldsig.js) uses the browser globals
// DOMParser/XMLSerializer, provided here by @xmldom/xmldom, and window.crypto,
// provided by Node's webcrypto.

const fs = require("fs");
const path = require("path");

// Browser globals the module expects.
const xmldom = require("@xmldom/xmldom");
global.DOMParser = xmldom.DOMParser;
global.XMLSerializer = xmldom.XMLSerializer;
const { webcrypto } = require("crypto");
if (!global.window) global.window = {};
if (!global.window.crypto) global.window.crypto = webcrypto;

// Locate the frontend crypto module. In the tests container it is copied next to
// this script (tests/Dockerfile); from a repo checkout it lives in client/src.
function loadXmldsig() {
  const candidates = [
    path.join(__dirname, "xmldsig.js"),
    path.join(__dirname, "..", "client", "src", "xmldsig.js"),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return require(p);
  }
  throw new Error("could not locate client/src/xmldsig.js (looked in: " + candidates.join(", ") + ")");
}
const xd = loadXmldsig();

const { SignedXml } = require("xml-crypto");
const xmlenc = require("xml-encryption");

let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) { pass++; console.log("  PASS  " + name); }
  else { fail++; console.log("  FAIL  " + name + (detail ? "  -> " + detail : "")); }
}

// Namespaces / algorithm URIs.
const DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";
const SHA1 = DSIG_NS + "sha1";

// One signing key pair reused across the checks.
const kp = xd.generateKeyPair(2048, "xmlsec-interop-client");

// --- 1) WS-Security signature -> verified by xml-crypto ---------------------
function buildSoap() {
  return '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"' +
    ' xmlns:wsa="http://www.w3.org/2005/08/addressing"' +
    ' xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    '<soap:Header>' +
    '<wsa:Action>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action>' +
    '<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"' +
    ' xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    '<wsu:Timestamp wsu:Id="_timestamp"><wsu:Created>2026-01-01T00:00:00Z</wsu:Created><wsu:Expires>2026-01-01T00:05:00Z</wsu:Expires></wsu:Timestamp>' +
    '<wsse:UsernameToken wsu:Id="_ut"><wsse:Username>wstrust</wsse:Username>' +
    '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">wstrust</wsse:Password></wsse:UsernameToken>' +
    '</wsse:Security>' +
    '</soap:Header>' +
    '<soap:Body wsu:Id="_body">' +
    '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"' +
    ' xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
    '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '<wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>' +
    '<wsp:AppliesTo><wsa:EndpointReference><wsa:Address>urn:rp</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken>' +
    '</soap:Body></soap:Envelope>';
}

function verifyWithXmlCrypto(signedXml, certPem) {
  const doc = new DOMParser().parseFromString(signedXml, "text/xml");
  const sigNodes = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
  if (!sigNodes.length) return { ok: false, detail: "no <Signature> found" };
  const sig = new SignedXml();
  sig.publicCert = certPem;
  sig.loadSignature(sigNodes[0]);
  let ok = false, detail = "";
  try { ok = sig.checkSignature(signedXml); }
  catch (e) { detail = e.message; ok = false; }
  if (!ok && !detail && sig.validationErrors) detail = JSON.stringify(sig.validationErrors);
  return { ok, detail };
}

function signatureTests() {
  console.log("== WS-Security signature (verified by xml-crypto) ==");
  // RSA-SHA384 is offered in the UI but omitted here: xml-crypto's default hash
  // registry has no SHA-384 digest, so it cannot verify that (correct, standard)
  // URI — an xml-crypto coverage gap, not an output defect.
  const algs = [
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  ];
  for (const alg of algs) {
    const short = alg.split("#").pop();
    const signed = xd.signWsSecurity(buildSoap(), {
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem, sigAlg: alg, signTimestamp: true,
    });
    const r = verifyWithXmlCrypto(signed, kp.certPem);
    check("sign Body+Timestamp (" + short + ") verifies", r.ok, r.detail);

    // Negative control: tampering with the signed Body must fail verification.
    const tampered = signed.replace("urn:rp", "urn:rp-EVIL");
    const rt = verifyWithXmlCrypto(tampered, kp.certPem);
    check("tampered Body (" + short + ") is REJECTED", rt.ok === false, "unexpectedly verified");
  }
  // Body-only (no timestamp) also verifies.
  const bodyOnly = xd.signWsSecurity(buildSoap(), {
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem,
    sigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signTimestamp: false,
  });
  const rb = verifyWithXmlCrypto(bodyOnly, kp.certPem);
  check("sign Body-only (rsa-sha256) verifies", rb.ok, rb.detail);
}

// --- 2) XML-Encryption -> decrypted by xml-encryption -----------------------
const PLAINTEXT = '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
  '<wst:RequestType>Issue</wst:RequestType><secret>hunter2 &amp; friends &lt;x&gt;</secret></wst:RequestSecurityToken>';

function decryptWithXmlEnc(encXml, privPem) {
  return new Promise(function (resolve) {
    // disallowDecryptionWithInsecureAlgorithm:false lets the reference lib
    // decrypt the CBC/3DES combinations it would otherwise refuse on policy
    // grounds — we validate correctness of our output, not endorse the algorithm.
    xmlenc.decrypt(encXml, { key: privPem, disallowDecryptionWithInsecureAlgorithm: false }, function (err, res) {
      resolve({ err, res });
    });
  });
}

async function encryptionTests() {
  console.log("== XML-Encryption (decrypted by xml-encryption) ==");
  // GCM data-encryption is defined in xmlenc11; CBC/3DES in xmlenc 1.0. RSA key
  // transport uses RSA-OAEP-MGF1P (SHA-1) — the interoperable modern default.
  // (RSA-1_5 is intentionally not exercised here: Node/OpenSSL 3 no longer
  // permits RSA_PKCS1_PADDING private decryption, so the reference lib cannot
  // decrypt it; it remains a labeled legacy option in the UI.)
  const cases = [
    { name: "AES-256-GCM + RSA-OAEP-MGF1P", dataAlg: XENC11 + "aes256-gcm", keyAlg: XENC + "rsa-oaep-mgf1p" },
    { name: "AES-128-GCM + RSA-OAEP-MGF1P", dataAlg: XENC11 + "aes128-gcm", keyAlg: XENC + "rsa-oaep-mgf1p" },
    { name: "AES-256-CBC + RSA-OAEP-MGF1P", dataAlg: XENC + "aes256-cbc", keyAlg: XENC + "rsa-oaep-mgf1p" },
    { name: "AES-128-CBC + RSA-OAEP-MGF1P", dataAlg: XENC + "aes128-cbc", keyAlg: XENC + "rsa-oaep-mgf1p" },
    { name: "Triple-DES-CBC + RSA-OAEP-MGF1P", dataAlg: XENC + "tripledes-cbc", keyAlg: XENC + "rsa-oaep-mgf1p" },
  ];
  for (const c of cases) {
    let encXml;
    try {
      encXml = xd.encryptXml(PLAINTEXT, {
        certPem: kp.certPem, dataAlg: c.dataAlg, keyAlg: c.keyAlg,
        type: XENC + "Element", c14nMode: "none", digest: SHA1, mgf: XENC11 + "mgf1sha1",
      });
    } catch (e) { check(c.name + " (encrypt)", false, e.message); continue; }
    const { err, res } = await decryptWithXmlEnc(encXml, kp.privateKeyPem);
    if (err) { check(c.name, false, "decrypt error: " + err.message); continue; }
    check(c.name + " round-trips", res === PLAINTEXT, 'decrypted="' + String(res).slice(0, 80) + '"');
  }
}

// --- 3) XML-Encryption round-trip: encryptXml -> decryptXml -----------------
// Exercises the reusable encrypt AND decrypt logic (client/src/xmldsig.js) that
// the response pages use to decrypt an EncryptedAssertion / message-level
// EncryptedData. Unlike section 2 this uses our own decryptor (node-forge), so
// it also covers RSA-1_5 (which Node/OpenSSL 3 refuses to privately decrypt) and
// the <saml:EncryptedAssertion> wrapper, plus a wrong-key negative control.
function decryptRoundTripTests() {
  console.log("== XML-Encryption round-trip (encryptXml -> decryptXml) ==");
  const other = xd.generateKeyPair(2048, "xmlsec-interop-other");
  const cases = [
    { name: "AES-256-GCM + RSA-OAEP (SHA-256/MGF1-SHA-256)", dataAlg: XENC11 + "aes256-gcm", keyAlg: XENC11 + "rsa-oaep", digest: XENC + "sha256", mgf: XENC11 + "mgf1sha256" },
    { name: "AES-128-GCM + RSA-OAEP-MGF1P (SHA-1)", dataAlg: XENC11 + "aes128-gcm", keyAlg: XENC + "rsa-oaep-mgf1p", digest: SHA1, mgf: XENC11 + "mgf1sha1" },
    { name: "AES-256-CBC + RSA-OAEP-MGF1P (SHA-1)", dataAlg: XENC + "aes256-cbc", keyAlg: XENC + "rsa-oaep-mgf1p", digest: SHA1, mgf: XENC11 + "mgf1sha1" },
    { name: "Triple-DES-CBC + RSA-1_5", dataAlg: XENC + "tripledes-cbc", keyAlg: XENC + "rsa-1_5", digest: SHA1, mgf: XENC11 + "mgf1sha1" },
  ];
  for (const c of cases) {
    let enc, dec;
    try {
      enc = xd.encryptXml(PLAINTEXT, {
        certPem: kp.certPem, dataAlg: c.dataAlg, keyAlg: c.keyAlg,
        type: XENC + "Element", c14nMode: "none", digest: c.digest, mgf: c.mgf,
      });
    } catch (e) { check(c.name + " (encrypt)", false, e.message); continue; }
    try { dec = xd.decryptXml(enc, { privateKeyPem: kp.privateKeyPem }); }
    catch (e) { check(c.name, false, "decrypt error: " + e.message); continue; }
    check(c.name + " round-trips", dec === PLAINTEXT, 'decrypted="' + String(dec).slice(0, 80) + '"');
  }

  // <saml:EncryptedAssertion> wrapper (the shape SAML / WS-Trust responses use).
  const encA = xd.encryptXml(PLAINTEXT, {
    certPem: kp.certPem, dataAlg: XENC11 + "aes256-gcm", keyAlg: XENC + "rsa-oaep-mgf1p",
    type: XENC + "Element", c14nMode: "none", digest: SHA1, mgf: XENC11 + "mgf1sha1",
  });
  const wrapped = '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' + encA + '</saml:EncryptedAssertion>';
  let decW; try { decW = xd.decryptXml(wrapped, { privateKeyPem: kp.privateKeyPem }); } catch (e) { decW = "ERR:" + e.message; }
  check("EncryptedAssertion wrapper decrypts", decW === PLAINTEXT, String(decW).slice(0, 80));

  // Negative control: the wrong private key MUST fail to decrypt.
  let threw = false;
  try { xd.decryptXml(encA, { privateKeyPem: other.privateKeyPem }); } catch (e) { threw = true; }
  check("negative control: wrong private key is REJECTED", threw, "decrypted with the wrong key");
}

async function main() {
  try {
    signatureTests();
    await encryptionTests();
    decryptRoundTripTests();
  } catch (e) {
    console.error("Unexpected error: " + (e && e.stack ? e.stack : e));
    process.exit(1);
  }
  console.log("\n== SUMMARY: " + pass + " passed, " + fail + " failed ==");
  process.exit(fail ? 1 : 0);
}

main();
