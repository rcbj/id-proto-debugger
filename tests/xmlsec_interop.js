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
// EncryptedAssertion / message-level EncryptedData, and covers the enveloped
// assertion signatures the SAML Assertion Tool page produces for all three SAML
// versions (each of which places the <ds:Signature> differently).
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

const bunyan = require("bunyan");
// The level is read through a guard because this script is run BOTH ways: by
// run-report.js, which sets CONFIG_FILE, and directly from a checkout, where it is
// unset. A bare require(process.env.CONFIG_FILE) throws in the second case, and a
// test that cannot start is worse than one that logs at the default level.
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

// Locate the frontend crypto module. In the tests container it is copied next to
// this script (tests/Dockerfile); from a repo checkout it lives in client/src.
// requireSharedModule also makes the tests' own dependencies resolvable for it —
// see module_paths.js.
const { requireSharedModule } = require("./module_paths.js");
const xd = requireSharedModule([
  path.join(__dirname, "xmldsig.js"),
  path.join(__dirname, "..", "client", "src", "xmldsig.js"),
], "client/src/xmldsig.js");

const { SignedXml } = require("xml-crypto");
const xmlenc = require("xml-encryption");

let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) { pass++; log.info("  PASS  " + name); }
  else { fail++; log.info("  FAIL  " + name + (detail ? "  -> " + detail : "")); }
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

function verifyWithXmlCrypto(signedXml, certPem, idAttributes) {
  const doc = new DOMParser().parseFromString(signedXml, "text/xml");
  const sigNodes = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
  if (!sigNodes.length) return { ok: false, detail: "no <Signature> found" };
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
  if (!ok && !detail && sig.validationErrors) detail = JSON.stringify(sig.validationErrors);
  return { ok, detail };
}

function signatureTests() {
  log.info("== WS-Security signature (verified by xml-crypto) ==");
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
  log.info("== XML-Encryption (decrypted by xml-encryption) ==");
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
    } catch (e) {
      check(c.name + " (encrypt)", false, e.message);
      continue;
    }
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
  log.info("== XML-Encryption round-trip (encryptXml -> decryptXml) ==");
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
    check(c.name + " round-trips", dec === PLAINTEXT, 'decrypted="' + String(dec).slice(0, 80) + '"');
  }

  // <saml:EncryptedAssertion> wrapper (the shape SAML / WS-Trust responses use).
  const encA = xd.encryptXml(PLAINTEXT, {
    certPem: kp.certPem, dataAlg: XENC11 + "aes256-gcm", keyAlg: XENC + "rsa-oaep-mgf1p",
    type: XENC + "Element", c14nMode: "none", digest: SHA1, mgf: XENC11 + "mgf1sha1",
  });
  const wrapped = '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' + encA + '</saml:EncryptedAssertion>';
  let decW;
  try {
    decW = xd.decryptXml(wrapped, { privateKeyPem: kp.privateKeyPem });
  } catch (e) {
    decW = "ERR:" + e.message;
  }
  check("EncryptedAssertion wrapper decrypts", decW === PLAINTEXT, String(decW).slice(0, 80));

  // Negative control: the wrong private key MUST fail to decrypt.
  let threw = false;
  try {
    xd.decryptXml(encA, { privateKeyPem: other.privateKeyPem });
  } catch (e) {
    threw = true;
  }
  check("negative control: wrong private key is REJECTED", threw, "decrypted with the wrong key");
}

// --- 4) Enveloped assertion signatures (SAML Assertion Tool) ----------------
// xd.signEnveloped() is the shared primitive behind saml_tools.html. The
// three SAML versions disagree about where the <ds:Signature> goes and what the
// Reference points at, so each variant is signed and then verified twice: by
// xml-crypto (independent) and by our own verifyXmlSignature (used by the page's
// "Validate a Signature" box). The assertions below mirror what the page emits,
// including xsi:type-ed attribute values — the classic exclusive-C14N trap,
// since the "xs" prefix is declared on the root but never visibly utilized.
const SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAML1_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
const XS_NS = "http://www.w3.org/2001/XMLSchema";
const XSI_NS = "http://www.w3.org/2001/XMLSchema-instance";

function assertion20(id) {
  return '<saml:Assertion xmlns:saml="' + SAML2_NS + '" xmlns:xs="' + XS_NS + '" xmlns:xsi="' + XSI_NS + '"' +
    ' ID="' + id + '" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">\n' +
    '  <saml:Issuer>http://localhost:3000</saml:Issuer>\n' +
    '  <saml:Subject>\n' +
    '    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameID>\n' +
    '    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">\n' +
    '      <saml:SubjectConfirmationData NotOnOrAfter="2026-01-01T00:05:00Z" Recipient="http://localhost:4000/samlacs"/>\n' +
    '    </saml:SubjectConfirmation>\n' +
    '  </saml:Subject>\n' +
    '  <saml:Conditions NotBefore="2025-12-31T23:59:00Z" NotOnOrAfter="2026-01-01T00:05:00Z">\n' +
    '    <saml:AudienceRestriction>\n' +
    '      <saml:Audience>http://localhost:3000/saml/sp</saml:Audience>\n' +
    '    </saml:AudienceRestriction>\n' +
    '  </saml:Conditions>\n' +
    '  <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z" SessionIndex="_sess1">\n' +
    '    <saml:AuthnContext>\n' +
    '      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n' +
    '    </saml:AuthnContext>\n' +
    '  </saml:AuthnStatement>\n' +
    '  <saml:AttributeStatement>\n' +
    '    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"' +
    ' NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="emailaddress">\n' +
    '      <saml:AttributeValue xsi:type="xs:string">testuser@example.com</saml:AttributeValue>\n' +
    '    </saml:Attribute>\n' +
    '  </saml:AttributeStatement>\n' +
    '</saml:Assertion>';
}

function assertion1x(id, minor) {
  return '<saml:Assertion xmlns:saml="' + SAML1_NS + '" xmlns:xs="' + XS_NS + '" xmlns:xsi="' + XSI_NS + '"' +
    ' MajorVersion="1" MinorVersion="' + minor + '" AssertionID="' + id + '"' +
    ' Issuer="http://localhost:3000" IssueInstant="2026-01-01T00:00:00Z">\n' +
    '  <saml:Conditions NotBefore="2025-12-31T23:59:00Z" NotOnOrAfter="2026-01-01T00:05:00Z">\n' +
    '    <saml:AudienceRestrictionCondition>\n' +
    '      <saml:Audience>http://localhost:3000/saml/sp</saml:Audience>\n' +
    '    </saml:AudienceRestrictionCondition>\n' +
    '  </saml:Conditions>\n' +
    '  <saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password"' +
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
    '    <saml:Attribute AttributeName="emailaddress" AttributeNamespace="http://schemas.xmlsoap.org/claims/">\n' +
    '      <saml:AttributeValue xsi:type="xs:string">testuser@example.com</saml:AttributeValue>\n' +
    '    </saml:Attribute>\n' +
    '  </saml:AttributeStatement>\n' +
    '</saml:Assertion>';
}

// Direct-element children of the signed assertion, by local name — used to
// assert the <ds:Signature> landed where each version's schema requires.
function childElementNames(xml) {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const out = [];
  let c = doc.documentElement.firstChild;
  while (c) { if (c.nodeType === 1) out.push(c.localName); c = c.nextSibling; }
  return out;
}

function envelopedSignatureTests() {
  log.info("== Enveloped assertion signature (SAML Assertion Tool) ==");
  const id = "_a1b2c3d4e5f6";
  // SAML 1.1 references its assertion through AssertionID (an xs:ID as of 1.1),
  // which a generic verifier only resolves once told that attribute name.
  const cases = [
    { name: "SAML 2.0", xml: assertion20(id), refUri: "#" + id, placement: "after-issuer", lastChild: false },
    { name: "SAML 1.1", xml: assertion1x(id, "1"), refUri: "#" + id, placement: "last", lastChild: true, idAttrs: ["AssertionID"] },
    // SAML 1.0's AssertionID is not an xs:ID, so the whole-document reference is
    // the interoperable form.
    { name: "SAML 1.0", xml: assertion1x(id, "0"), refUri: "", placement: "last", lastChild: true },
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
      check(c.name + " Signature is the last child", kids[kids.length - 1] === "Signature", kids.join(","));
    } else {
      check(c.name + " Signature directly follows Issuer",
        kids[0] === "Issuer" && kids[1] === "Signature", kids.join(","));
    }

    // Negative control: tampering with a signed attribute value must fail.
    const tampered = signed.replace("testuser@example.com", "attacker@example.com");
    const rt = verifyWithXmlCrypto(tampered, kp.certPem, c.idAttrs);
    check(c.name + " tampered assertion is REJECTED (xml-crypto)", rt.ok === false, "unexpectedly verified");
    const ot = xd.verifyXmlSignature(tampered);
    check(c.name + " tampered assertion is REJECTED (verifyXmlSignature)", ot.valid === false, "unexpectedly verified");
  }

  // Inclusive C14N is offered in the page's Canonicalization select.
  const inclusive = xd.signEnveloped(assertion20("_inclusive1"), {
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem,
    refUri: "#_inclusive1", placement: "after-issuer",
    c14nAlg: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  });
  const ri = verifyWithXmlCrypto(inclusive, kp.certPem);
  check("SAML 2.0 assertion with inclusive C14N verifies (xml-crypto)", ri.ok, ri.detail);

  // Sign-then-encrypt: the signed assertion survives an EncryptedAssertion
  // round-trip and still verifies afterwards.
  const signed20 = xd.signEnveloped(assertion20(id), {
    privateKeyPem: kp.privateKeyPem, certPem: kp.certPem, refUri: "#" + id, placement: "after-issuer",
  });
  const enc = xd.encryptXml(signed20, {
    certPem: kp.certPem, dataAlg: XENC11 + "aes256-gcm", keyAlg: XENC11 + "rsa-oaep",
    type: XENC + "Element", c14nMode: "none", digest: XENC + "sha256", mgf: XENC11 + "mgf1sha256",
  });
  const wrapped = '<saml:EncryptedAssertion xmlns:saml="' + SAML2_NS + '">' + enc + '</saml:EncryptedAssertion>';
  let dec;
  try {
    dec = xd.decryptXml(wrapped, { privateKeyPem: kp.privateKeyPem });
  } catch (e) {
    dec = "ERR:" + e.message;
  }
  check("sign-then-encrypt round-trips", dec === signed20, String(dec).slice(0, 80));
  const rd = verifyWithXmlCrypto(String(dec), kp.certPem);
  check("decrypted assertion still verifies", rd.ok, rd.detail);
}

async function main() {
  try {
    signatureTests();
    await encryptionTests();
    decryptRoundTripTests();
    envelopedSignatureTests();
  } catch (e) {
    log.error("Unexpected error: " + (e && e.stack ? e.stack : e));
    process.exit(1);
  }
  log.info("== SUMMARY: " + pass + " passed, " + fail + " failed ==");
  process.exit(fail ? 1 : 0);
}

main();
