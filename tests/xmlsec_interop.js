// File: xmlsec_interop.js
//
// XML Signature & XML Encryption interoperability test for the WS-Trust
// workflow's in-browser crypto (common/xmldsig.js). Unlike the other tests
// in this directory it drives NO browser — it exercises the frontend crypto
// module directly in Node and validates its output against independent,
// official libraries:
//   * xml-crypto      — verifies the WS-Security XML digital signature.
//   * xml-encryption  — decrypts the W3C XML-Encryption output and checks the
//                       plaintext round-trips.
// It also round-trips the reusable encrypt AND decrypt logic
// (encryptXml -> decryptXml) that the response pages use to decrypt an
// EncryptedAssertion / message-level EncryptedData, and covers the enveloped
// assertion signatures the SAML Assertion Tool page produces for all three SAML
// versions (each of which places the <ds:Signature> differently).
//
// This proves the exclusive-C14N + RSA-SHA* signing and the xmlenc data/key
// encryption produce standards-compliant output a third party accepts. It is
// wired into tests/run-report.js like any other job (run-report spawns it with
// a --url argument, which this script ignores).
//
// The module under test (common/xmldsig.js) uses the browser globals
// DOMParser/XMLSerializer, provided here by @xmldom/xmldom, and window.crypto,
// provided by Node's webcrypto.

const fs = require("fs");
const path = require("path");

const bunyan = require("bunyan");
// The level is read through a guard because this script is run BOTH ways: by
// run-report.js, which sets CONFIG_FILE, and directly from a checkout, where it
// is unset. A bare require(process.env.CONFIG_FILE) throws in the second case,
// and a test that cannot start is worse than one that logs at the default
// level.
const log = bunyan.createLogger({
  name: "xmlsec_interop",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to info
      // loses only the configured verbosity.
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

// Browser globals the module expects.
const xmldom = require("@xmldom/xmldom");
global.DOMParser = xmldom.DOMParser;
global.XMLSerializer = xmldom.XMLSerializer;
const { webcrypto } = require("crypto");
if (!global.window) global.window = {};
if (!global.window.crypto) global.window.crypto = webcrypto;

// Locate the frontend crypto module. In the tests container it is copied next
// to this script (tests/Dockerfile); from a repo checkout it lives in
// client/src. requireSharedModule also makes the tests' own dependencies
// resolvable for it — see module_paths.js.
const { requireSharedModule } = require("./module_paths.js");
const xd = requireSharedModule([
  path.join(__dirname, "xmldsig.js"),
  path.join(__dirname, "..", "common", "xmldsig.js"),
], "common/xmldsig.js");

const { SignedXml } = require("xml-crypto");
const xmlenc = require("xml-encryption");

let pass = 0, fail = 0;
function check(name, ok, detail) {
  log.debug("Entering check().");
  if (ok) { pass++; log.info("  PASS  " + name); }
  else { fail++; log.info("  FAIL  " + name + (detail ? "  -> " +
        detail : "")); }
  log.debug("Leaving check().");
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
  log.debug("Entering buildSoap().");
  log.debug("Leaving buildSoap().");
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
    '<wst:RequestSecurityToken ' +
        'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"' +
    ' xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" ' +
        'xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
    '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '<wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>' +
    '<wsp:AppliesTo><wsa:EndpointReference><wsa:Address>urn:rp</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken>' +
    '</soap:Body></soap:Envelope>';
}

function verifyWithXmlCrypto(signedXml, certPem, idAttributes) {
  log.debug("Entering verifyWithXmlCrypto().");
  const doc = new DOMParser().parseFromString(signedXml, "text/xml");
  const sigNodes = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
  if (!sigNodes.length) {
    log.debug("Leaving verifyWithXmlCrypto().");
    return { ok: false, detail: "no <Signature> found" };
  }
  const sig = new SignedXml();
  sig.publicCert = certPem;
  // xml-crypto resolves Reference URIs through a fixed list of ID attribute
  // names; a caller can extend it (SAML 1.1 names its xs:ID "AssertionID").
  if (idAttributes) sig.idAttributes = sig.idAttributes.concat(idAttributes);
  sig.loadSignature(sigNodes[0]);
  let ok = false, detail = "";
  try {
    ok = sig.checkSignature(signedXml);
  } catch (e) {
    detail = e.message;
    ok = false;
  }
  if (!ok && !detail && sig.validationErrors) detail =
      JSON.stringify(sig.validationErrors);
  log.debug("Leaving verifyWithXmlCrypto().");
  return { ok, detail };
}

function signatureTests() {
  log.debug("Entering signatureTests().");
  log.info("== WS-Security signature (verified by xml-crypto) ==");
  // RSA-SHA384 is offered in the UI but omitted here: xml-crypto's default hash
  // registry has no SHA-384 digest, so it cannot verify that (correct,
  // standard) URI — an xml-crypto coverage gap, not an output defect.
  const algs = [
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  ];
  for (const alg of algs) {
    const short = alg.split("#").pop();
    const signed = xd.signWsSecurity(buildSoap(), {
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem, sigAlg: alg,
          signTimestamp: true,
    });
    const r = verifyWithXmlCrypto(signed, kp.certPem);
    check("sign Body+Timestamp (" + short + ") verifies", r.ok, r.detail);

    // Negative control: tampering with the signed Body must fail verification.
    const tampered = signed.replace("urn:rp", "urn:rp-EVIL");
    const rt = verifyWithXmlCrypto(tampered, kp.certPem);
    check("tampered Body (" + short + ") is REJECTED", rt.ok === false,
          "unexpectedly verified");
  }
  // Body-only (no timestamp) also verifies.
  const bodyOnly = xd.signWsSecurity(buildSoap(), {
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem,
    sigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        signTimestamp: false,
  });
  const rb = verifyWithXmlCrypto(bodyOnly, kp.certPem);
  check("sign Body-only (rsa-sha256) verifies", rb.ok, rb.detail);
  log.debug("Leaving signatureTests().");
}

// --- 2) XML-Encryption -> decrypted by xml-encryption -----------------------
const PLAINTEXT = '<wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
  '<wst:RequestType>Issue</wst:RequestType><secret>hunter2 &amp; friends &lt;x&gt;</secret></wst:RequestSecurityToken>';

function decryptWithXmlEnc(encXml, privPem) {
  log.debug("Entering decryptWithXmlEnc().");
  log.debug("Leaving decryptWithXmlEnc().");
  return new Promise(function (resolve) {
    // disallowDecryptionWithInsecureAlgorithm:false lets the reference lib
    // decrypt the CBC/3DES combinations it would otherwise refuse on policy
    // grounds — we validate correctness of our output, not endorse the
    // algorithm.
    xmlenc.decrypt(encXml, { key: privPem,
                   disallowDecryptionWithInsecureAlgorithm: false },
                   function (err, res) {
      resolve({ err, res });
    });
  });
}

async function encryptionTests() {
  log.debug("Entering encryptionTests().");
  log.info("== XML-Encryption (decrypted by xml-encryption) ==");
  // GCM data-encryption is defined in xmlenc11; CBC/3DES in xmlenc 1.0. RSA key
  // transport uses RSA-OAEP-MGF1P (SHA-1) — the interoperable modern default.
  // (RSA-1_5 is intentionally not exercised here: Node/OpenSSL 3 no longer
  // permits RSA_PKCS1_PADDING private decryption, so the reference lib cannot
  // decrypt it; it remains a labeled legacy option in the UI.)
  const cases = [
    { name: "AES-256-GCM + RSA-OAEP-MGF1P", dataAlg: XENC11 + "aes256-gcm",
     keyAlg: XENC + "rsa-oaep-mgf1p" },
    { name: "AES-128-GCM + RSA-OAEP-MGF1P", dataAlg: XENC11 + "aes128-gcm",
     keyAlg: XENC + "rsa-oaep-mgf1p" },
    { name: "AES-256-CBC + RSA-OAEP-MGF1P", dataAlg: XENC + "aes256-cbc",
     keyAlg: XENC + "rsa-oaep-mgf1p" },
    { name: "AES-128-CBC + RSA-OAEP-MGF1P", dataAlg: XENC + "aes128-cbc",
     keyAlg: XENC + "rsa-oaep-mgf1p" },
    { name: "Triple-DES-CBC + RSA-OAEP-MGF1P", dataAlg: XENC + "tripledes-cbc",
     keyAlg: XENC + "rsa-oaep-mgf1p" },
  ];
  for (const c of cases) {
    let encXml;
    try {
      encXml = xd.encryptXml(PLAINTEXT, {
        certPem: kp.certPem, dataAlg: c.dataAlg, keyAlg: c.keyAlg,
        type: XENC + "Element", c14nMode: "none", digest: SHA1, mgf: XENC11 +
            "mgf1sha1",
      });
    } catch (e) {
      check(c.name + " (encrypt)", false, e.message);
      continue;
    }
    const { err, res } = await decryptWithXmlEnc(encXml, kp.privateKeyPem);
    if (err) { check(c.name, false, "decrypt error: " +
        err.message); continue; }
    check(c.name + " round-trips", res === PLAINTEXT, 'decrypted="' +
          String(res).slice(0, 80) + '"');
  }
  log.debug("Leaving encryptionTests().");
}

// --- 3) XML-Encryption round-trip: encryptXml -> decryptXml -----------------
// Exercises the reusable encrypt AND decrypt logic (common/xmldsig.js) that
// the response pages use to decrypt an EncryptedAssertion / message-level
// EncryptedData. Unlike section 2 this uses our own decryptor (node-forge), so
// it also covers RSA-1_5 (which Node/OpenSSL 3 refuses to privately decrypt)
// and the <saml:EncryptedAssertion> wrapper, plus a wrong-key negative control.
function decryptRoundTripTests() {
  log.debug("Entering decryptRoundTripTests().");
  log.info("== XML-Encryption round-trip (encryptXml -> decryptXml) ==");
  const other = xd.generateKeyPair(2048, "xmlsec-interop-other");
  const cases = [
    { name: "AES-256-GCM + RSA-OAEP (SHA-256/MGF1-SHA-256)", dataAlg: XENC11 +
     "aes256-gcm", keyAlg: XENC11 + "rsa-oaep", digest: XENC + "sha256",
     mgf: XENC11 + "mgf1sha256" },
    { name: "AES-128-GCM + RSA-OAEP-MGF1P (SHA-1)", dataAlg: XENC11 +
     "aes128-gcm", keyAlg: XENC + "rsa-oaep-mgf1p", digest: SHA1, mgf: XENC11 +
     "mgf1sha1" },
    { name: "AES-256-CBC + RSA-OAEP-MGF1P (SHA-1)", dataAlg: XENC +
     "aes256-cbc", keyAlg: XENC + "rsa-oaep-mgf1p", digest: SHA1, mgf: XENC11 +
     "mgf1sha1" },
    { name: "Triple-DES-CBC + RSA-1_5", dataAlg: XENC + "tripledes-cbc",
     keyAlg: XENC + "rsa-1_5", digest: SHA1, mgf: XENC11 + "mgf1sha1" },
  ];
  for (const c of cases) {
    let enc, dec;
    try {
      enc = xd.encryptXml(PLAINTEXT, {
        certPem: kp.certPem, dataAlg: c.dataAlg, keyAlg: c.keyAlg,
        type: XENC + "Element", c14nMode: "none", digest: c.digest, mgf: c.mgf,
      });
    } catch (e) {
      check(c.name + " (encrypt)", false, e.message);
      continue;
    }
    try {
      dec = xd.decryptXml(enc, { privateKeyPem: kp.privateKeyPem });
    } catch (e) {
      check(c.name, false, "decrypt error: " + e.message);
      continue;
    }
    check(c.name + " round-trips", dec === PLAINTEXT, 'decrypted="' +
          String(dec).slice(0, 80) + '"');
  }

  // <saml:EncryptedAssertion> wrapper (the shape SAML / WS-Trust responses
  // use).
  const encA = xd.encryptXml(PLAINTEXT, {
    certPem: kp.certPem, dataAlg: XENC11 + "aes256-gcm", keyAlg: XENC +
        "rsa-oaep-mgf1p",
    type: XENC + "Element", c14nMode: "none", digest: SHA1, mgf: XENC11 +
        "mgf1sha1",
  });
  const wrapped = '<saml:EncryptedAssertion ' +
      'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' + encA +
      '</saml:EncryptedAssertion>';
  let decW;
  try {
    decW = xd.decryptXml(wrapped, { privateKeyPem: kp.privateKeyPem });
  } catch (e) {
    decW = "ERR:" + e.message;
  }
  check("EncryptedAssertion wrapper decrypts", decW === PLAINTEXT,
        String(decW).slice(0, 80));

  // Negative control: the wrong private key MUST fail to decrypt.
  let threw = false;
  try {
    xd.decryptXml(encA, { privateKeyPem: other.privateKeyPem });
  } catch (e) {
    threw = true;
  }
  check("negative control: wrong private key is REJECTED", threw,
        "decrypted with the wrong key");
  log.debug("Leaving decryptRoundTripTests().");
}

// --- 4) Enveloped assertion signatures (SAML Assertion Tool) ----------------
// xd.signEnveloped() is the shared primitive behind saml_tools.html. The three
// SAML versions disagree about where the <ds:Signature> goes and what the
// Reference points at, so each variant is signed and then verified twice: by
// xml-crypto (independent) and by our own verifyXmlSignature (used by the
// page's "Validate a Signature" box). The assertions below mirror what the page
// emits, including xsi:type-ed attribute values — the classic exclusive-C14N
// trap, since the "xs" prefix is declared on the root but never visibly
// utilized.
const SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAML1_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
const XS_NS = "http://www.w3.org/2001/XMLSchema";
const XSI_NS = "http://www.w3.org/2001/XMLSchema-instance";

function assertion20(id) {
  log.debug("Entering assertion20().");
  log.debug("Leaving assertion20().");
  return '<saml:Assertion xmlns:saml="' + SAML2_NS + '" xmlns:xs="' + XS_NS +
      '" xmlns:xsi="' + XSI_NS + '"' +
    ' ID="' + id + '" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">\n' +
    '  <saml:Issuer>http://localhost:3000</saml:Issuer>\n' +
    '  <saml:Subject>\n' +
    '    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameID>\n' +
    '    <saml:SubjectConfirmation ' +
        'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">\n' +
    '      <saml:SubjectConfirmationData NotOnOrAfter="2026-01-01T00:05:00Z" ' +
        'Recipient="http://localhost:4000/samlacs"/>\n' +
    '    </saml:SubjectConfirmation>\n' +
    '  </saml:Subject>\n' +
    '  <saml:Conditions NotBefore="2025-12-31T23:59:00Z" ' +
        'NotOnOrAfter="2026-01-01T00:05:00Z">\n' +
    '    <saml:AudienceRestriction>\n' +
    '      <saml:Audience>http://localhost:3000/saml/sp</saml:Audience>\n' +
    '    </saml:AudienceRestriction>\n' +
    '  </saml:Conditions>\n' +
    '  <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z" ' +
        'SessionIndex="_sess1">\n' +
    '    <saml:AuthnContext>\n' +
    '      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n' +
    '    </saml:AuthnContext>\n' +
    '  </saml:AuthnStatement>\n' +
    '  <saml:AttributeStatement>\n' +
    '    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"' +
    ' NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" ' +
        'FriendlyName="emailaddress">\n' +
    '      <saml:AttributeValue ' +
        'xsi:type="xs:string">testuser@example.com</saml:AttributeValue>\n' +
    '    </saml:Attribute>\n' +
    '  </saml:AttributeStatement>\n' +
    '</saml:Assertion>';
}

function assertion1x(id, minor) {
  log.debug("Entering assertion1x().");
  log.debug("Leaving assertion1x().");
  return '<saml:Assertion xmlns:saml="' + SAML1_NS + '" xmlns:xs="' + XS_NS +
      '" xmlns:xsi="' + XSI_NS + '"' +
    ' MajorVersion="1" MinorVersion="' + minor + '" AssertionID="' + id + '"' +
    ' Issuer="http://localhost:3000" IssueInstant="2026-01-01T00:00:00Z">\n' +
    '  <saml:Conditions NotBefore="2025-12-31T23:59:00Z" ' +
        'NotOnOrAfter="2026-01-01T00:05:00Z">\n' +
    '    <saml:AudienceRestrictionCondition>\n' +
    '      <saml:Audience>http://localhost:3000/saml/sp</saml:Audience>\n' +
    '    </saml:AudienceRestrictionCondition>\n' +
    '  </saml:Conditions>\n' +
    '  <saml:AuthenticationStatement ' +
        'AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password"' +
    ' AuthenticationInstant="2026-01-01T00:00:00Z">\n' +
    '    <saml:Subject>\n' +
    '      <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameIdentifier>\n' +
    '      <saml:SubjectConfirmation>\n' +
    '        <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>\n' +
    '      </saml:SubjectConfirmation>\n' +
    '    </saml:Subject>\n' +
    '  </saml:AuthenticationStatement>\n' +
    '  <saml:AttributeStatement>\n' +
    '    <saml:Subject>\n' +
    '      <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameIdentifier>\n' +
    '    </saml:Subject>\n' +
    '    <saml:Attribute AttributeName="emailaddress" ' +
        'AttributeNamespace="http://schemas.xmlsoap.org/claims/">\n' +
    '      <saml:AttributeValue ' +
        'xsi:type="xs:string">testuser@example.com</saml:AttributeValue>\n' +
    '    </saml:Attribute>\n' +
    '  </saml:AttributeStatement>\n' +
    '</saml:Assertion>';
}

// Direct-element children of the signed assertion, by local name — used to
// assert the <ds:Signature> landed where each version's schema requires.
function childElementNames(xml) {
  log.debug("Entering childElementNames().");
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const out = [];
  let c = doc.documentElement.firstChild;
  while (c) { if (c.nodeType === 1) out.push(c.localName); c = c.nextSibling; }
  log.debug("Leaving childElementNames().");
  return out;
}

function envelopedSignatureTests() {
  log.debug("Entering envelopedSignatureTests().");
  log.info("== Enveloped assertion signature (SAML Assertion Tool) ==");
  const id = "_a1b2c3d4e5f6";
  // SAML 1.1 references its assertion through AssertionID (an xs:ID as of 1.1),
  // which a generic verifier only resolves once told that attribute name.
  const cases = [
    { name: "SAML 2.0", xml: assertion20(id), refUri: "#" + id,
     placement: "after-issuer", lastChild: false },
    { name: "SAML 1.1", xml: assertion1x(id, "1"), refUri: "#" + id,
     placement: "last", lastChild: true, idAttrs: ["AssertionID"] },
    // SAML 1.0's AssertionID is not an xs:ID, so the whole-document reference
    // is the interoperable form.
    { name: "SAML 1.0", xml: assertion1x(id, "0"), refUri: "",
     placement: "last", lastChild: true },
  ];
  for (const c of cases) {
    let signed;
    try {
      signed = xd.signEnveloped(c.xml, {
        privateKeyPem: kp.privateKeyPem, certPem: kp.certPem,
        sigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        refUri: c.refUri, placement: c.placement,
      });
    } catch (e) {
      check(c.name + " (sign)", false, e.message);
      continue;
    }

    const r = verifyWithXmlCrypto(signed, kp.certPem, c.idAttrs);
    check(c.name + " assertion verifies (xml-crypto)", r.ok, r.detail);

    const own = xd.verifyXmlSignature(signed);
    check(c.name + " assertion verifies (verifyXmlSignature)", own.valid,
      own.error || JSON.stringify(own.references));

    const kids = childElementNames(signed);
    if (c.lastChild) {
      check(c.name + " Signature is the last child", kids[kids.length -
            1] === "Signature", kids.join(","));
    } else {
      check(c.name + " Signature directly follows Issuer",
        kids[0] === "Issuer" && kids[1] === "Signature", kids.join(","));
    }

    // Negative control: tampering with a signed attribute value must fail.
    const tampered = signed.replace("testuser@example.com",
        "attacker@example.com");
    const rt = verifyWithXmlCrypto(tampered, kp.certPem, c.idAttrs);
    check(c.name + " tampered assertion is REJECTED (xml-crypto)",
          rt.ok === false, "unexpectedly verified");
    const ot = xd.verifyXmlSignature(tampered);
    check(c.name + " tampered assertion is REJECTED (verifyXmlSignature)",
          ot.valid === false, "unexpectedly verified");
  }

  // Inclusive C14N is offered in the page's Canonicalization select.
  const inclusive = xd.signEnveloped(assertion20("_inclusive1"), {
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem,
    refUri: "#_inclusive1", placement: "after-issuer",
    c14nAlg: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  });
  const ri = verifyWithXmlCrypto(inclusive, kp.certPem);
  check("SAML 2.0 assertion with inclusive C14N verifies (xml-crypto)", ri.ok,
        ri.detail);

  // Sign-then-encrypt: the signed assertion survives an EncryptedAssertion
  // round-trip and still verifies afterwards.
  const signed20 = xd.signEnveloped(assertion20(id), {
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem, refUri: "#" + id,
        placement: "after-issuer",
  });
  const enc = xd.encryptXml(signed20, {
    certPem: kp.certPem, dataAlg: XENC11 + "aes256-gcm", keyAlg: XENC11 +
        "rsa-oaep",
    type: XENC + "Element", c14nMode: "none", digest: XENC + "sha256",
        mgf: XENC11 + "mgf1sha256",
  });
  const wrapped = '<saml:EncryptedAssertion xmlns:saml="' + SAML2_NS + '">' +
      enc + '</saml:EncryptedAssertion>';
  let dec;
  try {
    dec = xd.decryptXml(wrapped, { privateKeyPem: kp.privateKeyPem });
  } catch (e) {
    dec = "ERR:" + e.message;
  }
  check("sign-then-encrypt round-trips", dec === signed20, String(dec).slice(0,
        80));
  const rd = verifyWithXmlCrypto(String(dec), kp.certPem);
  check("decrypted assertion still verifies", rd.ok, rd.detail);
  log.debug("Leaving envelopedSignatureTests().");
}

// ===========================================================================
// THE GENERAL XML SIGNATURE ENGINE — the Digital Signature page's XML pane.
//
// Everything above this line exercises the two SHAPED signers (a WS-Security
// header, an enveloped SAML assertion), each of which fixes almost every
// choice XMLDSIG offers. The pane on the Digital Signature page leaves them
// open, so this section is about the choices themselves, and about the ones
// that produce a signature which is cryptographically perfect and verifies
// nowhere:
//
//   * A canonicalization that differs from the verifier's by ONE property —
//     comments. A document with a single comment in it is the only thing that
//     tells "#WithComments" from its twin, and every document without one
//     passes under either.
//   * A transform chain in the wrong order, or missing the enveloped-signature
//     transform, so the digest covers the DigestValue that is about to hold it.
//   * An ECDSA SignatureValue left in DER, where RFC 4051 wants R || S.
//   * A Reference that resolves to the wrong element, or to nothing.
//
// The ECDSA and HMAC signers here are built on NODE'S OWN CRYPTO — that is the
// point of xmldsig.js taking an injected signer rather than importing a curve
// library: the half of the engine the browser bundle drives with @noble is
// driven here by OpenSSL, so a byte disagreement between them is a failure
// rather than a shared opinion.
// ===========================================================================

const crypto = require("crypto");

const GENERAL_DOC = '<Order xmlns="urn:example:order" ' +
  'xmlns:meta="urn:example:meta" ID="order-1">' +
  '<!-- the comment that tells the two canonicalizations apart -->' +
  '<Item sku="A1" meta:origin="warehouse-3">Widget</Item>' +
  '<Total currency="USD">42.00</Total></Order>';

// R || S <-> DER, in the TEST rather than in the module — xmldsig.js must
// never produce DER, and having the conversion here is what lets OpenSSL sign
// something the engine then verifies.
function rsToDer(sig) {
  log.debug("Entering rsToDer().");
  const n = sig.length / 2;
  function trim(b) {
    log.debug("Entering trim().");
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.slice(i);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    log.debug("Leaving trim().");
    return b;
  }
  const r = trim(sig.slice(0, n)), s = trim(sig.slice(n));
  const body = Buffer.concat([Buffer.from([0x02, r.length]), r,
                              Buffer.from([0x02, s.length]), s]);
  const header = body.length < 128 ? Buffer.from([0x30, body.length])
    : Buffer.from([0x30, 0x81, body.length]);
  log.debug("Leaving rsToDer().");
  return Buffer.concat([header, body]);
}

function derToRs(der, n) {
  log.debug("Entering derToRs().");
  let i = 2;
  if (der[1] & 0x80) i += der[1] & 0x7f;
  function read() {
    log.debug("Entering read().");
    const len = der[i + 1];
    let b = der.slice(i + 2, i + 2 + len);
    i += 2 + len;
    while (b.length > n) b = b.slice(1);
    log.debug("Leaving read().");
    return Buffer.concat([Buffer.alloc(n - b.length), b]);
  }
  const r = read(), s = read();
  log.debug("Leaving derToRs().");
  return Buffer.concat([r, s]);
}

const EC_KEY = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const HMAC_SECRET = Buffer.from("a shared secret, which is not a signature");

function ecSigner(octets) {
  log.debug("Entering ecSigner().");
  const s = crypto.createSign("sha256");
  s.update(Buffer.from(octets, "binary"));
  log.debug("Leaving ecSigner().");
  return derToRs(s.sign(EC_KEY.privateKey), 32).toString("binary");
}

function ecVerifier(octets, signature) {
  log.debug("Entering ecVerifier().");
  const v = crypto.createVerify("sha256");
  v.update(Buffer.from(octets, "binary"));
  log.debug("Leaving ecVerifier().");
  return v.verify(EC_KEY.publicKey,
                  rsToDer(Buffer.from(signature, "binary")));
}

function hmacSigner(octets) {
  log.debug("Entering hmacSigner().");
  log.debug("Leaving hmacSigner().");
  return crypto.createHmac("sha256", HMAC_SECRET)
    .update(Buffer.from(octets, "binary")).digest("binary");
}

function hmacVerifier(octets, signature) {
  log.debug("Entering hmacVerifier().");
  const tag = crypto.createHmac("sha256", HMAC_SECRET)
    .update(Buffer.from(octets, "binary")).digest("binary");
  log.debug("Leaving hmacVerifier().");
  return tag === signature;
}

function generalSignatureTests() {
  log.debug("Entering generalSignatureTests().");
  log.info("== General XML Signature engine (Digital Signature page) ==");

  // --- Every RSA SignatureMethod, self-verified and (where xml-crypto can
  //     read it) verified by xml-crypto. Its algorithm table has no SHA-384
  //     digest and no RSASSA-PSS, which is a limit of that library and is why
  //     those two are checked against this engine only.
  Object.keys(xd.SIG_METHODS).forEach(function (alg) {
    const spec = xd.SIG_METHODS[alg];
    if (spec.family !== "rsa") return;
    const signed = xd.signXml(GENERAL_DOC, { mode: "enveloped", sigAlg: alg,
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
    check("enveloped " + spec.label + " verifies",
      xd.verifyXml(signed.xml, {}).valid);
    if (spec.pad !== "pss" && spec.hash !== "sha384") {
      const r = verifyWithXmlCrypto(signed.xml, kp.certPem);
      check("enveloped " + spec.label + " verified by xml-crypto", r.ok,
            r.detail);
    }
  });

  // --- All three signature types.
  ["enveloped", "enveloping", "detached"].forEach(function (mode) {
    const signed = xd.signXml(GENERAL_DOC, { mode: mode,
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
    const result = xd.verifyXml(signed.xml,
      { referencedXml: signed.referencedXml });
    check(mode + " signature verifies", result.valid, JSON.stringify(result));
    if (mode === "enveloping") {
      check("enveloping wraps the document in a ds:Object",
        /<ds:Object[ >]/.test(signed.xml) && signed.referenceUri.charAt(0) ===
        "#");
    }
    if (mode === "detached") {
      // This sample already carries ID="order-1", so nothing had to be added
      // and there is nothing to report — which is the case that would hide a
      // note fired on every document.
      check("detached signing of a document that HAS an ID says nothing",
        signed.notes.length === 0 &&
        signed.referenceUri === "#order-1",
        JSON.stringify(signed.notes) + " " + signed.referenceUri);
      check("detached signature refuses a modified referenced document",
        !xd.verifyXml(signed.xml, { referencedXml:
          signed.referencedXml.replace("Widget", "Gadget") }).valid);

      // Without one, the Reference has nothing to name — an empty URI in a
      // standalone <ds:Signature> means the signature document itself. So an
      // ID is added and the engine SAYS SO, because the document that
      // verifies is then the one it returned rather than the one it was
      // handed.
      const anonymous = xd.signXml('<Note>hello</Note>', { mode: "detached",
        privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
      check("detached signing of a document with NO ID adds one and reports it",
        anonymous.notes.length === 1 && /ID=/.test(anonymous.notes[0]) &&
        /ID="/.test(anonymous.referencedXml),
        JSON.stringify(anonymous.notes));
      check("the returned referenced document is the one that verifies",
        xd.verifyXml(anonymous.xml,
          { referencedXml: anonymous.referencedXml }).valid &&
        !xd.verifyXml(anonymous.xml,
          { referencedXml: '<Note>hello</Note>' }).valid);
    }
  });

  // --- Tampering.
  const enveloped = xd.signXml(GENERAL_DOC, { mode: "enveloped",
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
  check("a modified element is refused",
    !xd.verifyXml(enveloped.xml.replace("Widget", "Gadget"), {}).valid);
  check("a modified ATTRIBUTE is refused",
    !xd.verifyXml(enveloped.xml.replace('sku="A1"', 'sku="A2"'), {}).valid);

  // --- The four canonicalization methods, and the one property that
  //     separates each pair. A document with no comment in it passes under
  //     either method, which is exactly why the sample carries one.
  const digests = {};
  Object.keys(xd.C14N_METHODS).forEach(function (c14n) {
    const signed = xd.signXml(GENERAL_DOC, { mode: "enveloped",
      c14nAlg: c14n,
      transforms: [{ algorithm: xd.TRANSFORM_ENVELOPED },
                   { algorithm: c14n }],
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
    check("c14n " + xd.C14N_METHODS[c14n].label + " verifies",
      xd.verifyXml(signed.xml, {}).valid);
    digests[c14n] = signed.digestValue;
  });
  check("WithComments really changes the reference digest (exclusive)",
    digests[xd.C14N_EXCLUSIVE] !== digests[xd.C14N_EXCLUSIVE_WC],
    digests[xd.C14N_EXCLUSIVE] + " vs " + digests[xd.C14N_EXCLUSIVE_WC]);
  check("WithComments really changes the reference digest (inclusive)",
    digests[xd.C14N_INCLUSIVE] !== digests[xd.C14N_INCLUSIVE_WC],
    digests[xd.C14N_INCLUSIVE] + " vs " + digests[xd.C14N_INCLUSIVE_WC]);
  const noComment = GENERAL_DOC.replace(/<!--[\s\S]*?-->/, "");
  const withoutComment = xd.signXml(noComment, { mode: "enveloped",
    transforms: [{ algorithm: xd.TRANSFORM_ENVELOPED },
                 { algorithm: xd.C14N_EXCLUSIVE }],
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
  check("omit-comments digests a commented document as an uncommented one",
    withoutComment.digestValue === digests[xd.C14N_EXCLUSIVE],
    withoutComment.digestValue + " vs " + digests[xd.C14N_EXCLUSIVE]);

  // --- Every DigestMethod.
  Object.keys(xd.DIGEST_METHODS).forEach(function (uri) {
    const signed = xd.signXml(GENERAL_DOC, { mode: "enveloped",
      digestUri: uri, privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
    check("DigestMethod " + xd.DIGEST_METHODS[uri].label + " verifies",
      xd.verifyXml(signed.xml, {}).valid);
  });

  // --- ECDSA and HMAC, through OpenSSL. The engine implements neither, on
  //     purpose; what is under test is the SignedInfo it hands over and the
  //     SignatureValue it writes back.
  const ecSigned = xd.signXml(GENERAL_DOC, { mode: "enveloped",
    sigAlg: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    keyInfo: "keyvalue",
    ecNamedCurve: "urn:oid:1.2.840.10045.3.1.7",
    ecPublicPoint: EC_KEY.publicKey.export({ format: "der", type: "spki" })
      .slice(-65),
    signer: ecSigner });
  check("ECDSA-SHA256 signed by OpenSSL verifies",
    xd.verifyXml(ecSigned.xml, { verifier: ecVerifier }).valid);
  check("the ECDSA SignatureValue is R || S, not DER",
    Buffer.from(ecSigned.signatureValue, "base64").length === 64,
    "length " + Buffer.from(ecSigned.signatureValue, "base64").length +
    " — RFC 4051 wants the 64-byte concatenation, and a DER SEQUENCE is the " +
    "usual reason this is wrong");
  check("a dsig11:ECKeyValue is what carries an EC public key",
    /dsig11:ECKeyValue/.test(ecSigned.xml) &&
    /urn:oid:1\.2\.840\.10045\.3\.1\.7/.test(ecSigned.xml));
  check("a modified ECDSA-signed document is refused",
    !xd.verifyXml(ecSigned.xml.replace("Widget", "Gadget"),
      { verifier: ecVerifier }).valid);

  const hmacSigned = xd.signXml(GENERAL_DOC, { mode: "enveloped",
    sigAlg: "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    keyInfo: "keyname", keyName: "shared-key-1", signer: hmacSigner });
  check("HMAC-SHA256 computed by OpenSSL verifies",
    xd.verifyXml(hmacSigned.xml, { verifier: hmacVerifier }).valid);
  check("a KeyName is what a MAC key can be identified by",
    /<ds:KeyName>shared-key-1<\/ds:KeyName>/.test(hmacSigned.xml));

  // --- The refusals. Each of these is a chain that cannot mean anything, and
  //     each is named rather than producing a signature that verifies nowhere.
  let message = "";
  try {
    xd.signXml(GENERAL_DOC, { mode: "enveloped",
      transforms: [{ algorithm: xd.C14N_EXCLUSIVE },
                   { algorithm: xd.TRANSFORM_ENVELOPED }],
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
  } catch (e) {
    message = e.message;
  }
  check("a transform after a canonicalization is refused by name",
    /already produced octets/.test(message), message);

  message = "";
  try {
    xd.signXml("<a><b></a>", { privateKeyPem: kp.privateKeyPem,
      certPem: kp.certPem });
  } catch (e) {
    message = e.message;
  }
  check("malformed XML is refused before anything is signed",
    /not well-formed/.test(message), message);

  message = "";
  try {
    xd.signXml(GENERAL_DOC, { mode: "enveloped", sigAlg: "urn:made:up",
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
  } catch (e) {
    message = e.message;
  }
  check("an unknown SignatureMethod is refused rather than defaulted",
    /Unsupported SignatureMethod/.test(message), message);

  message = "";
  try {
    xd.signXml(GENERAL_DOC, { mode: "enveloped", digestUri: "urn:made:up",
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
  } catch (e) {
    message = e.message;
  }
  check("an unknown DigestMethod is refused rather than defaulted",
    /Unsupported DigestMethod/.test(message), message);

  // An enveloped signature whose Reference does not remove itself can never
  // verify — the digest would cover a DigestValue that is still empty. The
  // engine adds the transform and says it did.
  const repaired = xd.signXml(GENERAL_DOC, { mode: "enveloped",
    transforms: [{ algorithm: xd.C14N_EXCLUSIVE }],
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
  check("a missing enveloped-signature transform is added, and reported",
    repaired.notes.length === 1 &&
    /enveloped-signature/.test(repaired.notes[0]) &&
    xd.verifyXml(repaired.xml, {}).valid, JSON.stringify(repaired.notes));

  // --- The base64 transform digests the DECODED octets, which is the whole
  //     of what it is for.
  const payload = Buffer.from("hello world");
  const b64doc = '<Data ID="d1">' + payload.toString("base64") + '</Data>';
  const b64signed = xd.signXml(b64doc, { mode: "enveloping",
    transforms: [{ algorithm: xd.TRANSFORM_BASE64 }],
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
  check("the base64 transform verifies",
    xd.verifyXml(b64signed.xml, {}).valid);
  check("the base64 transform digests the DECODED octets",
    b64signed.digestValue ===
    crypto.createHash("sha256").update(payload).digest("base64"),
    b64signed.digestValue);

  // --- KeyInfo. An RSAKeyValue is a public key with no identity attached,
  //     which is a poor thing to trust and a useful thing to read.
  const publicPem = require("node-forge").pki.publicKeyToPem(
    require("node-forge").pki.certificateFromPem(kp.certPem).publicKey);
  const kvSigned = xd.signXml(GENERAL_DOC, { mode: "enveloped",
    keyInfo: "keyvalue", privateKeyPem: kp.privateKeyPem,
    publicKeyPem: publicPem });
  check("an RSAKeyValue KeyInfo verifies with no certificate anywhere",
    xd.verifyXml(kvSigned.xml, {}).valid && !/X509Certificate/
      .test(kvSigned.xml));
  const noKeyInfo = xd.signXml(GENERAL_DOC, { mode: "enveloped",
    keyInfo: "none", privateKeyPem: kp.privateKeyPem });
  check("KeyInfo can be omitted, and the caller's key then verifies it",
    !/KeyInfo/.test(noKeyInfo.xml) &&
    xd.verifyXml(noKeyInfo.xml, { publicKeyPem: publicPem }).valid);

  // --- InclusiveNamespaces. The sample's meta: prefix is used only in an
  //     ATTRIBUTE NAME, so exclusive C14N renders it either way; what this
  //     asserts is that the PrefixList reaches the document and the signature
  //     still verifies with it in place.
  const prefixed = xd.signXml(GENERAL_DOC, { mode: "enveloped",
    c14nPrefixList: "meta #default",
    transforms: [{ algorithm: xd.TRANSFORM_ENVELOPED },
                 { algorithm: xd.C14N_EXCLUSIVE, prefixList: "meta" }],
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
  check("an InclusiveNamespaces PrefixList is written into the signature",
    /PrefixList="meta #default"/.test(prefixed.xml) &&
    /PrefixList="meta"/.test(prefixed.xml));
  check("a signature carrying a PrefixList verifies",
    xd.verifyXml(prefixed.xml, {}).valid);

  // --- A Reference that names nothing is a failure with a reason, not a
  //     crash and not a quiet pass.
  const broken = enveloped.xml.replace(/URI="#[^"]*"/, 'URI="#nowhere"');
  const brokenResult = xd.verifyXml(broken, {});
  check("a Reference that resolves to nothing fails with a reason",
    !brokenResult.valid && /not found/.test(
      brokenResult.references[0].reason || ""),
    JSON.stringify(brokenResult.references));

  // --- The XPath transforms need the DOM's own engine, which @xmldom does
  //     not provide. That has to be a NAMED refusal rather than a bad
  //     signature: tests/digital_signature.js drives them in a browser, and
  //     this is what says why they are not driven here.
  message = "";
  try {
    xd.signXml(GENERAL_DOC, { mode: "enveloped",
      transforms: [{ algorithm: xd.TRANSFORM_XPATH, xpath: "true()" },
                   { algorithm: xd.C14N_EXCLUSIVE }],
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem });
  } catch (e) {
    message = e.message;
  }
  check("the XPath transform names the engine it needs",
    /document\.evaluate/.test(message), message);
  log.debug("Leaving generalSignatureTests().");
}

// ===========================================================================
// WHAT THE API SIGNS.
//
// api/server.js's POST /samlsign used to reach for the `xml-crypto` package,
// which made three implementations of XML Signature in this application: that
// one, and two copies of a hand-written one in the browser. It now uses this
// module, so what the api produces and what the SSO page produces are the same
// bytes from the same code — and this section holds them to that.
//
// It also pins the defect the consolidation fixed. The redirect binding's
// signature was `crypto.createSign('RSA-SHA256')` whatever SigAlg the caller
// asked for, so a request declaring rsa-sha512 was signed with SHA-256 and
// said otherwise in its own query string. Nothing catches that locally: the
// only symptom is an identity provider answering "invalid signature".
// ===========================================================================
const AUTHN_REQUEST = '<samlp:AuthnRequest ' +
  'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
  'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
  'ID="_req-1" Version="2.0" IssueInstant="2026-08-24T00:00:00Z" ' +
  'Destination="https://idp.example.com/sso">' +
  '<saml:Issuer>https://sp.example.com</saml:Issuer>' +
  '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:' +
  'persistent"/></samlp:AuthnRequest>';

const REDIRECT_SIG_ALGS = {
  "http://www.w3.org/2000/09/xmldsig#rsa-sha1": "RSA-SHA1",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "RSA-SHA256",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": "RSA-SHA384",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "RSA-SHA512"
};

function apiSignatureTests() {
  log.debug("Entering apiSignatureTests().");
  log.info("== What api/server.js signs (POST /samlsign) ==");

  // The POST binding, exactly as the api now calls it: signEnveloped() with
  // the SAML defaults. xml-crypto has to accept it, because a real identity
  // provider's verifier is the same kind of thing.
  Object.keys(REDIRECT_SIG_ALGS).forEach(function (uri) {
    const label = REDIRECT_SIG_ALGS[uri];
    const signed = xd.signEnveloped(AUTHN_REQUEST, {
      privateKeyPem: kp.privateKeyPem, certPem: kp.certPem,
      sigAlg: uri, placement: "after-issuer", includeKeyInfo: true });
    check("AuthnRequest signed with " + label + " self-verifies",
      xd.verifyXmlSignature(signed, {}).valid);
    if (label !== "RSA-SHA384") {
      // xml-crypto's algorithm table has no SHA-384 DIGEST, which is a limit
      // of that library rather than of this one — the self-check above still
      // covers it.
      const r = verifyWithXmlCrypto(signed, kp.certPem);
      check("AuthnRequest signed with " + label + " verified by xml-crypto",
            r.ok, r.detail);
    }
    // The SAML schema requires the Signature to follow <Issuer>, and an
    // identity provider that validates the schema rejects it anywhere else.
    const names = childElementNames(signed);
    check(label + ": the Signature sits directly after <Issuer>",
      names[0] === "Issuer" && names[1] === "Signature",
      JSON.stringify(names));
  });

  // The REDIRECT binding. The signature is over the query string as sent, and
  // the digest must be the one SigAlg names — this is the check that would
  // have failed before the api stopped hard-coding SHA-256.
  Object.keys(REDIRECT_SIG_ALGS).forEach(function (uri) {
    const label = REDIRECT_SIG_ALGS[uri];
    const qs = "SAMLRequest=" + encodeURIComponent("deflated-bytes") +
      "&SigAlg=" + encodeURIComponent(uri);
    const signature = xd.signQueryString(qs, {
      privateKeyPem: kp.privateKeyPem, sigAlg: uri });
    // node's OpenSSL is the independent opinion here: it is told which digest
    // to use, so a signature made with any OTHER digest fails.
    const v = crypto.createVerify(label);
    v.update(qs);
    check("redirect binding: SigAlg=" + label + " is signed with " + label,
      v.verify(kp.certPem, Buffer.from(signature, "base64")),
      "the digest does not match the SigAlg the query string declares");
    // ...and the mutation check that makes the assertion above non-vacuous:
    // verifying the same bytes under a DIFFERENT digest must fail.
    const other = label === "RSA-SHA256" ? "RSA-SHA512" : "RSA-SHA256";
    const v2 = crypto.createVerify(other);
    v2.update(qs);
    check("redirect binding: SigAlg=" + label + " is NOT " + other,
      !v2.verify(kp.certPem, Buffer.from(signature, "base64")));
  });

  // KeyInfo is omitted when there is no certificate to put in it, rather than
  // emitting an empty X509Data — the api passes '' when the caller sent none.
  const noCert = xd.signEnveloped(AUTHN_REQUEST, {
    privateKeyPem: kp.privateKeyPem, certPem: "", includeKeyInfo: false,
    placement: "after-issuer" });
  check("no certificate means no KeyInfo, not an empty one",
    noCert.indexOf("KeyInfo") < 0 &&
    xd.verifyXmlSignature(noCert, { certPem: kp.certPem }).valid);
  log.debug("Leaving apiSignatureTests().");
}

async function main() {
  log.debug("Entering main().");
  try {
    signatureTests();
    await encryptionTests();
    decryptRoundTripTests();
    envelopedSignatureTests();
    generalSignatureTests();
    apiSignatureTests();
  } catch (e) {
    log.error("Unexpected error: " + (e && e.stack ? e.stack : e));
    process.exit(1);
  }
  log.info("== SUMMARY: " + pass + " passed, " + fail + " failed ==");
  process.exit(fail ? 1 : 0);
  log.debug("Leaving main().");
}

main();
