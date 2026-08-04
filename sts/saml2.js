'use strict';
//
// File: saml2.js
//
// ---------------------------------------------------------------------------
// SAML 2.0 assertions: building one, signing it, and encrypting it.
//
// Separate from wstrust.js because a SAML assertion is not a WS-Trust concept —
// WS-Trust merely carries one. These three functions are what a SAML 2.0
// implementation owes anyone who asks for a token in that format, and the
// debugger's SAML pages verify their output against an independent reading of the
// specification.
//
// The signature is an enveloped XML Signature over the Assertion with an
// exclusive canonicalization, and the encryption is XML Encryption with an
// AES-256-CBC content key wrapped with RSA-OAEP. Both are what Keycloak and
// ADFS produce, which is the point: the debugger's response pages have to cope
// with what real identity providers send.
// ---------------------------------------------------------------------------

const forge = require('node-forge');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');
const { log, logArtifact, ISSUER, STS, xmlEscape, genId, iso } = require('./helpers');
// Sign a SAML assertion enveloped (signature after Issuer), like api/server.js.
function signAssertion(xml) {
  log.debug("Entering signAssertion().");
  logArtifact('SAML assertion', 'before signing', xml);
  const m = xml.match(/\bID="([^"]+)"/);
  const id = m ? m[1] : '';
  const sig = new SignedXml({ privateKey: STS.privateKeyPem, publicCert: STS.certPem });
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  sig.addReference({
    xpath: "/*[local-name(.)='Assertion']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    uri: id ? ('#' + id) : ''
  });
  sig.computeSignature(xml, {
    location: { reference: "/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' }
  });
  const signed = sig.getSignedXml();
  logArtifact('SAML assertion', 'after signing', signed);
  log.debug("Leaving signAssertion().");
  return signed;
}

function buildSamlAssertion(subject, audience, lifetimeMin) {
  log.debug("Entering buildSamlAssertion().");
  const id = genId();
  const now = iso(0);
  const exp = iso(lifetimeMin > 0 ? lifetimeMin : 60);
  const audienceEl = audience
    ? '<saml:AudienceRestriction><saml:Audience>' + xmlEscape(audience) + '</saml:Audience></saml:AudienceRestriction>'
    : '';
  const xml =
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
      ' ID="' + id + '" Version="2.0" IssueInstant="' + now + '">' +
      '<saml:Issuer>' + xmlEscape(ISSUER) + '</saml:Issuer>' +
      '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">' +
        xmlEscape(subject) + '</saml:NameID>' +
      '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/></saml:Subject>' +
      '<saml:Conditions NotBefore="' + now + '" NotOnOrAfter="' + exp + '">' + audienceEl + '</saml:Conditions>' +
      '<saml:AuthnStatement AuthnInstant="' + now + '" SessionIndex="' + id + '">' +
      '<saml:AuthnContext><saml:AuthnContextClassRef>' +
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' +
      '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>' +
      '<saml:AttributeStatement>' +
        '<saml:Attribute Name="name"><saml:AttributeValue>' + xmlEscape(subject) + '</saml:AttributeValue></saml:Attribute>' +
      '<saml:Attribute Name="issuedBy"><saml:AttributeValue>' + xmlEscape(ISSUER) + '</saml:AttributeValue></saml:Attribute>' +
      '</saml:AttributeStatement>' +
    '</saml:Assertion>';
  try { 
    log.debug("Leaving buildSamlAssertion().");
    return signAssertion(xml); 
  } catch (e) { 
    log.error('sign failed, returning unsigned: ' + e.message); 
    return xml; 
  }
}

// Encrypt an assertion to a recipient certificate (AES-256-GCM data key wrapped
// with RSA-OAEP-MGF1P/SHA-1), wrapped in <saml:EncryptedAssertion> — the shape
// the debugger's decryptXml consumes. Used when a request asks for encryption
// (?encrypt=1) and carries the recipient cert in its WS-Security signature.
function encryptAssertion(assertionXml, certPem) {
  log.debug("Entering encryptAssertion().");
  logArtifact('SAML assertion', 'before encryption', assertionXml);
  var XENC = 'http://www.w3.org/2001/04/xmlenc#';
  var X11 = 'http://www.w3.org/2009/xmlenc11#';
  var DS = 'http://www.w3.org/2000/09/xmldsig#';
  var cert = forge.pki.certificateFromPem(certPem);
  var pub = cert.publicKey;
  var key = forge.random.getBytesSync(32);
  var iv = forge.random.getBytesSync(12);
  var cipher = forge.cipher.createCipher('AES-GCM', key);
  cipher.start({ iv: iv, tagLength: 128 });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(assertionXml)));
  if (!cipher.finish()) throw new Error('assertion encryption failed');
  var cipherB64 = forge.util.encode64(iv + cipher.output.getBytes() + cipher.mode.tag.getBytes());
  var wrapped = pub.encrypt(key, 'RSA-OAEP', { md: forge.md.sha1.create(), mgf1: { md: forge.md.sha1.create() } });
  var wrappedB64 = forge.util.encode64(wrapped);
  var certB64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  var encrypted = '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
    '<xenc:EncryptedData xmlns:xenc="' + XENC + '" Type="' + XENC + 'Element">' +
      '<xenc:EncryptionMethod Algorithm="' + X11 + 'aes256-gcm"/>' +
      '<ds:KeyInfo xmlns:ds="' + DS + '">' +
        '<xenc:EncryptedKey>' +
          '<xenc:EncryptionMethod Algorithm="' + XENC + 'rsa-oaep-mgf1p">' +
            '<ds:DigestMethod xmlns:ds="' + DS + '" Algorithm="' + DS + 'sha1"/></xenc:EncryptionMethod>' +
          '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
          '<xenc:CipherData><xenc:CipherValue>' + wrappedB64 + '</xenc:CipherValue></xenc:CipherData>' +
        '</xenc:EncryptedKey>' +
      '</ds:KeyInfo>' +
      '<xenc:CipherData><xenc:CipherValue>' + cipherB64 + '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData></saml:EncryptedAssertion>';
  logArtifact('SAML assertion', 'after encryption (AES-256-GCM, key wrapped with RSA-OAEP-MGF1P)', encrypted);
  log.debug("Leaving encryptAssertion().");
  return encrypted;
}

module.exports = {
  signAssertion: signAssertion,
  buildSamlAssertion: buildSamlAssertion,
  encryptAssertion: encryptAssertion
};
