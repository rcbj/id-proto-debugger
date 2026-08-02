'use strict';
//
// WS-Trust 1.4 STS mock.
//
// A deliberately small, dependency-light Security Token Service that speaks
// enough WS-Trust to exercise the OAuth2/OIDC Debugger's WS-Trust workflow end
// to end in the test suite. It accepts a SOAP RequestSecurityToken (RST) and
// dispatches on wst:RequestType:
//
//   Issue    -> RSTR Collection with a freshly minted, STS-signed SAML 2.0
//               assertion (or a JWT / plain UsernameToken echo, per TokenType),
//               a Lifetime, and an attached reference.
//   Renew    -> RSTR with a fresh token for the supplied RenewTarget.
//   Validate -> RSTR with wst:Status/wst:Code valid|invalid.
//   Cancel   -> RSTR with wst:RequestedTokenCancelled.
//
// Authentication: a WS-Security UsernameToken is accepted when username and
// password are both present (and the password is not the literal "invalid",
// which lets a negative test force an auth failure). A request carrying an
// OnBehalfOf/ActAs token (delegation) is also accepted. This is a TEST STS —
// it does not verify request signatures or enforce real policy.
//
// The project's real intent is to run against Apache CXF's WS-Trust STS; this
// mock is the CI fallback (see the plan / README) and the app can target either.
//
// Config via env:
//   CONFIG_FILE  the configuration module to load, chosen the same way as for the
//                api and client services (e.g. ./env/local.js). It supplies the
//                log level; env/docker-tests.js is what the containerized test
//                stack uses.
//   STS_PORT     listening port (default 8081)
//   STS_ISSUER   the WS-Trust issuer name (default the mock's own)
//
// Logging: everything this mock does is written to the log at DEBUG level — every
// endpoint call (path, request headers and body, response headers and body,
// status code and elapsed time), and every SAML assertion, JWT and SD-JWT VC both
// BEFORE and AFTER it was signed or encrypted. Drop the level to info (see
// env/test.js) for a quiet run.

const appconfig = require(process.env.CONFIG_FILE);
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');
const bunyan = require("bunyan"); 
const log = bunyan.createLogger({ name: 'sts', 
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// Logging helpers.
//
// This is a mock whose whole purpose is to show what it did, so everything it
// produces is written down at debug level: the artifact BEFORE it was signed or
// encrypted, the artifact AFTER, and — for every endpoint — the request that
// came in, the response that went back, the status code and how long it took.
// ---------------------------------------------------------------------------

// A security artifact, recorded before and after it was protected.
//
//   what   'SAML assertion' / 'JWT' / 'SD-JWT VC' ...
//   stage  'before signing' / 'after signing' / 'before encryption' / ...
//   value  the object or string itself, recorded in full
function logArtifact(what, stage, value) {
  log.debug({ artifact: what,
              stage: stage,
              value: (typeof value === 'string') ? value : JSON.stringify(value) },
            what + ' ' + stage + '.');
}

// Headers with nothing removed: this mock issues test credentials only, and the
// point of the log is to be able to see exactly what was exchanged.
function headersOf(source) {
  const out = {};
  Object.keys(source || {}).forEach(function (k) { out[k] = source[k]; });
  return out;
}

// Bodies arrive (and leave) as strings or objects; either way they go in whole.
function bodyOf(value) {
  if (value === undefined || value === null) return '';
  return (typeof value === 'string') ? value : JSON.stringify(value);
}

const PORT = parseInt(process.env.STS_PORT, 10) || 8081;
const ISSUER = process.env.STS_ISSUER || 'urn:wstrust:mock:sts';

const WST_NS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const SOAP12_NS = 'http://www.w3.org/2003/05/soap-envelope';
const SOAP11_NS = 'http://schemas.xmlsoap.org/soap/envelope/';
const SAML2_TOKEN_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';
const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
const STATUS_TOKEN_TYPE = WST_NS + '/RSTR/Status';
const STATUS_VALID = WST_NS + '/status/valid';
const STATUS_INVALID = WST_NS + '/status/invalid';

// --- STS signing key/cert (generated once at startup) ----------------------
function makeStsKeys() {
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = kp.publicKey;
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
  const attrs = [{ name: 'commonName', value: 'ws-trust-mock-sts' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(kp.privateKey, forge.md.sha256.create());
  const certB64 = forge.pki.certificateToPem(cert)
    .replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return {
    privateKeyPem: forge.pki.privateKeyToPem(kp.privateKey),
    certPem: forge.pki.certificateToPem(cert),
    certB64: certB64,
    // A `kid` names a KEY, so it is derived from the key material rather than
    // hard-coded. This key is regenerated on every start, and the kid was
    // previously a constant — so two instances of this mock (a stale container
    // beside a fresh one, or two ports during development) published the SAME kid
    // over DIFFERENT keys. A verifier matches the kid exactly, tries that one key,
    // fails, and reports "the signature does not verify", which reads like a
    // corrupt document instead of what it is: keys fetched from the wrong
    // instance. A per-key kid cannot collide, so the mismatch names itself.
    kid: 'sts-mock-' + forge.md.sha256.create().update(certB64).digest().toHex().slice(0, 12)
  };
}

const STS = makeStsKeys();

// Every document that carries or describes this key is served `Cache-Control:
// no-store` (the RFC 8414 metadata, the OID4VCI credential issuer metadata, the
// jwt-vc-issuer document and the JWKS). The key is regenerated on every start, so
// a cached copy of any of them outlives the key it describes — and the resulting
// failure is a signature that does not verify, which looks like a broken document
// rather than a stale one. Nothing about a mock is worth caching.

// --- helpers ---------------------------------------------------------------
function xmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function genId() {
  return '_' + forge.util.bytesToHex(forge.random.getBytesSync(16));
}

function iso(offsetMin) {
  return new Date(Date.now() + (offsetMin || 0) * 60000).toISOString();
}

function firstByLocal(root, name) {
  const els = root.getElementsByTagNameNS('*', name);
  return els && els.length ? els[0] : null;
}

function textByLocal(root, name) {
  const e = firstByLocal(root, name);
  return e ? (e.textContent || '').trim() : '';
}

function soapNsFor(version) { return version === '1.1' ? SOAP11_NS : SOAP12_NS; }

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

function buildJwt(subject, audience, lifetimeMin) {
  // jsonwebtoken rejects an empty-string audience — only set it when present.
  log.debug("Entering buildJwt().");
  const opts = { 
    algorithm: 'RS256', 
    issuer: ISSUER, 
    expiresIn: (lifetimeMin > 0 ? lifetimeMin : 60) * 60 
  };
  if (audience) opts.audience = audience;
  const claims = { sub: subject, name: subject };
  logArtifact('WS-Trust JWT', 'before signing', { header: { alg: opts.algorithm }, payload: claims, options: opts });
  const signed = jwt.sign(claims, STS.privateKeyPem, opts);
  logArtifact('WS-Trust JWT', 'after signing', signed);
  log.debug("Leaving buildJwt().");
  return signed;
}

// Build the token element (what goes inside wst:RequestedSecurityToken).
function buildToken(tokenType, subject, audience, lifetimeMin) {
  log.debug("Entering buildToken(). tokenType=" + tokenType + ", subject=" + subject);
  if (tokenType === JWT_TOKEN_TYPE) {
    const raw = buildJwt(subject, audience, lifetimeMin);
    const token = { xml: '<wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"' +
      ' ValueType="urn:ietf:params:oauth:token-type:jwt">' + raw + '</wsse:BinarySecurityToken>', ref: '', tokenType: JWT_TOKEN_TYPE };
    log.debug("Leaving buildToken(). Issued a JWT.");
    return token;
  }
  const assertion = buildSamlAssertion(subject, audience, lifetimeMin);
  const idm = assertion.match(/\bID="([^"]+)"/);
  const id = idm ? idm[1] : '';
  const ref = '<wst:RequestedAttachedReference><wsse:SecurityTokenReference' +
    ' xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">' +
    xmlEscape(id) + '</wsse:KeyIdentifier></wsse:SecurityTokenReference></wst:RequestedAttachedReference>';
  log.debug("Leaving buildToken(). Issued a SAML 2.0 assertion with ID " + id + ".");
  return { xml: assertion, ref: ref, tokenType: SAML2_TOKEN_TYPE };
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

function envelope(version, action, bodyInner) {
  log.debug("Entering envelope(). version=" + version + ", action=" + action);
  const soapNs = soapNsFor(version);
  const header = action
    ? '<soap:Header><wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">' + action + '</wsa:Action></soap:Header>'
    : '';
  log.debug("Leaving envelope().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="' + soapNs + '">' + header +
    '<soap:Body>' + bodyInner + '</soap:Body></soap:Envelope>';
}

function soapFault(version, reason) {
  log.debug("Entering soapFault(). version=" + version + ", reason=" + reason);
  const soapNs = soapNsFor(version);
  const body = version === '1.1'
    ? '<soap:Fault><faultcode>soap:Client</faultcode><faultstring>' + xmlEscape(reason) + '</faultstring></soap:Fault>'
    : '<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code>' +
      '<soap:Reason><soap:Text xml:lang="en">' + xmlEscape(reason) + '</soap:Text></soap:Reason></soap:Fault>';
  log.debug("Leaving soapFault().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="' + soapNs + '">' + '<soap:Body>' + body + '</soap:Body></soap:Envelope>';
}

// --- request handling ------------------------------------------------------
function detectSoapVersion(doc, contentType) {
  log.debug("Entering detectSoapVersion().");
  const root = doc && doc.documentElement;
  log.debug("Leaving detectSoapVersion().");
  if (root && root.namespaceURI === SOAP11_NS) return '1.1';
  if (root && root.namespaceURI === SOAP12_NS) return '1.2';
  return /text\/xml/i.test(contentType || '') ? '1.1' : '1.2';
}

function authenticate(doc) {
  log.debug("Entering authenticate().");
  // OnBehalfOf / ActAs => delegated, accept and use the delegated subject if any.
  const obo = firstByLocal(doc, 'OnBehalfOf') || firstByLocal(doc, 'ActAs');
  if (obo) {
    const nameId = firstByLocal(obo, 'NameID') || firstByLocal(obo, 'NameIdentifier');
    log.debug("Leaving authenticate(). Delegated request (OnBehalfOf/ActAs).");
    return { ok: true, subject: (nameId && (nameId.textContent || '').trim()) || 'delegated-subject' };
  }
  const ut = firstByLocal(doc, 'UsernameToken');
  if (ut) {
    const user = textByLocal(ut, 'Username');
    const pass = textByLocal(ut, 'Password');
    if (!user || !pass) {
      log.debug("Leaving authenticate(). Incomplete UsernameToken.");
      return { ok: false, reason: 'UsernameToken requires a username and password.' };
    }
    if (pass === 'invalid') {
      log.debug("Leaving authenticate(). The reserved password was used, so this is a failure.");
      return { ok: false, reason: 'Authentication failed for user ' + user + '.' };
    }
    log.debug("Leaving authenticate(). UsernameToken accepted for " + user + ".");
    return { ok: true, subject: user };
  }
  // A SAML assertion presented directly as the credential.
  const assertion = firstByLocal(doc, 'Assertion');
  if (assertion) {
    const nameId = firstByLocal(assertion, 'NameID') || firstByLocal(assertion, 'NameIdentifier');
    log.debug("Leaving authenticate(). A SAML assertion was presented as the credential.");
    return { ok: true, subject: (nameId && (nameId.textContent || '').trim()) || 'saml-subject' };
  }
  // No credential — lenient (anonymous), so a "None" credential still issues.
  log.debug("Leaving authenticate(). No credential was presented; treating as anonymous.");
  return { ok: true, subject: 'anonymous' };
}

function handleRst(rawBody, contentType, options) {
  log.debug("Entering handleRst().");
  options = options || {};
  const doc = new DOMParser().parseFromString(rawBody || '', 'text/xml');
  const version = detectSoapVersion(doc, contentType);
  const requestType = textByLocal(doc, 'RequestType');
  // Operation from the LAST path segment of RequestType, so any WS-Trust
  // version's namespace works (2004/04, 2005/02, or ws-sx 200512).
  const op = requestType.split('/').pop().toLowerCase();
  // Echo the request's trust namespace in the response (whatever version the
  // client used); fall back to 200512.
  const rstEl = firstByLocal(doc, 'RequestSecurityToken');
  const trustNs = (rstEl && rstEl.namespaceURI) || WST_NS;
  const statusTokenType = trustNs + '/RSTR/Status';
  const statusValid = trustNs + '/status/valid';
  const statusInvalid = trustNs + '/status/invalid';
  const keyTypeReq = textByLocal(doc, 'KeyType') || (trustNs + '/Bearer');

  const tokenTypeReq = textByLocal(doc, 'TokenType');
  const appliesToEl = firstByLocal(doc, 'AppliesTo');
  const audience = appliesToEl ? (textByLocal(appliesToEl, 'Address') || (appliesToEl.textContent || '').trim()) : '';
  const lifetimeEl = firstByLocal(doc, 'Lifetime');
  let lifetimeMin = 60;
  if (lifetimeEl) {
    const created = textByLocal(lifetimeEl, 'Created');
    const expires = textByLocal(lifetimeEl, 'Expires');
    if (created && expires) {
      const diff = (Date.parse(expires) - Date.parse(created)) / 60000;
      if (diff > 0) lifetimeMin = Math.round(diff);
    }
  }

  if (op === 'validate') {
    const target = firstByLocal(doc, 'ValidateTarget');
    const hasToken = target && (firstByLocal(target, 'Assertion') || firstByLocal(target, 'BinarySecurityToken') || (target.textContent || '').trim());
    const code = hasToken ? statusValid : statusInvalid;
    const reason = hasToken ? 'The token is valid.' : 'No token to validate.';
    const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs + '">' +
      '<wst:TokenType>' + statusTokenType + '</wst:TokenType>' +
      '<wst:Status><wst:Code>' + code + '</wst:Code><wst:Reason>' + xmlEscape(reason) + '</wst:Reason></wst:Status>' +
      '</wst:RequestSecurityTokenResponse>';
    log.debug("Leaving handleRst(). Validate answered with wst:Status.");
    return { status: 200, version: version, body: envelope(version, trustNs + '/RSTR/ValidateFinal', rstr) };
  }

  if (op === 'cancel') {
    const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs + '">' +
      '<wst:RequestedTokenCancelled/></wst:RequestSecurityTokenResponse>';
    log.debug("Leaving handleRst(). Cancel answered with wst:RequestedTokenCancelled.");
    return { status: 200, version: version, body: envelope(version, trustNs + '/RSTR/CancelFinal', rstr) };
  }

  // Issue / Renew both mint (or re-mint) a token.
  const auth = authenticate(doc);
  if (!auth.ok) {
    log.debug("Leaving handleRst(). Authentication failed, answering with a SOAP Fault.");
    return { status: 500, version: version, body: soapFault(version, auth.reason || 'Authentication failed.') };
  }

  const tokenType = (tokenTypeReq === JWT_TOKEN_TYPE) ? JWT_TOKEN_TYPE : SAML2_TOKEN_TYPE;
  const tok = buildToken(tokenType, auth.subject, audience, lifetimeMin);

  // Optional encryption (?encrypt=1): encrypt the SAML assertion to the recipient
  // certificate carried in the request's WS-Security signature (X509Data).
  if (options.encrypt && tok.tokenType === SAML2_TOKEN_TYPE) {
    const x509 = firstByLocal(doc, 'X509Certificate');
    const recipB64 = x509 ? (x509.textContent || '').replace(/\s+/g, '') : '';
    if (recipB64) {
      const recipPem = '-----BEGIN CERTIFICATE-----\n' + (recipB64.match(/.{1,64}/g) || []).join('\n') + '\n-----END CERTIFICATE-----\n';
      try { tok.xml = encryptAssertion(tok.xml, recipPem); tok.ref = ''; }
      catch (e) {
        log.error('encrypt failed, returning plaintext: ' + e.message);
      }
    } else {
      log.error('?encrypt=1 requested but no recipient certificate in the request signature; returning plaintext.');
    }
  }
  const appliesToOut = audience
    ? '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"' +
      ' xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:EndpointReference><wsa:Address>' +
      xmlEscape(audience) + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'
    : '';
  const rstrInner =
    '<wst:TokenType>' + tok.tokenType + '</wst:TokenType>' +
    '<wst:RequestedSecurityToken>' + tok.xml + '</wst:RequestedSecurityToken>' +
    appliesToOut +
    '<wst:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    '<wsu:Created>' + iso(0) + '</wsu:Created><wsu:Expires>' + iso(lifetimeMin) + '</wsu:Expires></wst:Lifetime>' +
    '<wst:KeyType>' + keyTypeReq + '</wst:KeyType>' +
    tok.ref;

  if (op === 'renew') {
    const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs + '">' + rstrInner + '</wst:RequestSecurityTokenResponse>';
    log.debug("Leaving handleRst(). Renew answered with a fresh token.");
    return { status: 200, version: version, body: envelope(version, trustNs + '/RSTR/RenewFinal', rstr) };
  }

  // Issue -> RSTR Collection (WS-Trust 1.3+; pre-OASIS clients tolerate it too).
  const rstrc = '<wst:RequestSecurityTokenResponseCollection xmlns:wst="' + trustNs + '">' +
    '<wst:RequestSecurityTokenResponse>' + rstrInner + '</wst:RequestSecurityTokenResponse>' +
    '</wst:RequestSecurityTokenResponseCollection>';
  log.debug("Leaving handleRst(). Issue answered with an RSTR Collection.");
  return { status: 200, version: version, body: envelope(version, trustNs + '/RSTRC/IssueFinal', rstrc) };
}

// --- express app -----------------------------------------------------------
const app = express();
// Chrome Private Network Access: when a PUBLIC page calls a LOCAL (loopback)
// server — which is exactly the live-site test setup, an HTTPS page on
// idptools.com calling this mock at http://localhost:8081 — Chrome may send a
// CORS preflight carrying Access-Control-Request-Private-Network and require
// this header on the response. Answer it so the call isn't blocked. Registered
// BEFORE cors() so the header is set before the preflight response is sent;
// a no-op for the containerized suite (both sides on the same bridge network).
app.use(function (req, res, next) {
  if (req.headers['access-control-request-private-network']) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }
  next();
});

// The response hardening that actually applies to this service.
//
// Almost everything here answers `application/json`, and the values in those
// responses are echoed from what a caller sent — an error_description quoting a
// bad grant_type, a client name from a registration request. Escaping that
// content is NOT the control: JSON.stringify already encodes it unambiguously,
// and running an HTML sanitizer over it would corrupt legitimate values while
// protecting nothing (a JSON string is not markup). The way such a body turns
// into script is a browser deciding to treat it as HTML anyway, so the control
// is to forbid that decision:
//
//   X-Content-Type-Options: nosniff   honour the declared Content-Type, never
//                                     sniff a JSON body as text/html
//   Content-Security-Policy           no script runs even if some response were
//                                     rendered as a document after all
//   X-Frame-Options: DENY             no framing of the login screen the
//                                     authorization endpoint serves
//
// The HTML this service does emit (the login screen, the credential-offer and
// verifier pages) builds its markup from server-side values, and where a
// caller-supplied value appears in it, it is escaped at that point with
// xmlEscape().
//
// The policy is as tight as these pages allow, and it is worth saying what each
// clause is for, because a stricter-looking one would break them:
//   script-src 'none'   they contain no <script> at all, inline or external —
//                       so this is the clause that makes the whole family of
//                       js/reflected-xss reports moot rather than merely
//                       unlikely: a JSON body rendered as a document still runs
//                       nothing.
//   style-src           six pages carry an inline <style> block, so
//                       'unsafe-inline' is required; extracting them to files
//                       would buy nothing here since no untrusted value reaches
//                       a style.
//   img-src data:       the two QR pages embed the code as a data: URI produced
//                       by the qrcode library server-side.
//
// NOT present, and it must not be added back: **form-action**. It looks obviously
// right here — the only form posts to /oauth2/login, which is same-origin — but
// Chrome enforces form-action against the whole REDIRECT CHAIN that follows a
// submission, not just its immediate target. This is an authorization server:
// signing in POSTs the login form and the response is a 302 to the client's
// redirect_uri, which is by definition another origin. `form-action 'self'`
// therefore blocks the browser from ever reaching the client, and the symptom is
// remote from the cause — the sign-in appears to succeed and the wallet simply
// never comes back. It cost a full SD-JWT VC issuance run to find, and
// tests/sd_jwt_vc_issuance.js is what catches it (H.1 signs in here).
// Enumerating allowed redirect origins is not a fix either: this mock accepts
// arbitrary redirect_uris on purpose.
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'unsafe-inline'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "frame-ancestors 'none'"
].join('; ');

app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(cors({ origin: '*' }));
app.options('*', cors({ origin: '*' }));

// Accept any content-type as raw text (SOAP arrives as text/xml or
// application/soap+xml).
app.use(bodyParser.text({ type: function () { return true; }, limit: '5mb' }));

// ---------------------------------------------------------------------------
// Record every call into every endpoint: the path, the request (headers and
// body), the response (headers, body and status), and how long it took.
//
// Registered AFTER the body parser on purpose: before that runs req.body is
// undefined, and every request would be recorded as empty.
//
// res.send / res.json / res.end are wrapped rather than hooked on 'finish',
// because by the time the response has been flushed the body is gone. Two
// entries are written per call — one when the request arrives, one when the
// answer goes out — so a request that never gets answered is still visible.
// ---------------------------------------------------------------------------
app.use(function (req, res, next) {
  const started = Date.now();
  const request = {
    path: req.originalUrl,
    method: req.method,
    query: req.query,
    headers: headersOf(req.headers),
    body: bodyOf(req.body)
  };
  log.debug({ request: request }, 'Request: ' + req.method + ' ' + req.originalUrl);

  let responseBody = '';
  const send = res.send;
  const json = res.json;
  const end = res.end;
  res.send = function (body) {
    responseBody = bodyOf(body);
    return send.apply(res, arguments);
  };
  res.json = function (body) {
    responseBody = bodyOf(body);
    return json.apply(res, arguments);
  };
  res.end = function (chunk) {
    if (!responseBody && chunk) responseBody = bodyOf(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : chunk);
    return end.apply(res, arguments);
  };

  res.on('finish', function () {
    log.debug({ response: { path: req.originalUrl,
                            method: req.method,
                            status: res.statusCode,
                            durationMs: Date.now() - started,
                            headers: headersOf(res.getHeaders()),
                            body: responseBody } },
              'Response: ' + res.statusCode + ' ' + req.method + ' ' + req.originalUrl +
              ' in ' + (Date.now() - started) + 'ms');
  });
  next();
});


app.get('/healthcheck', function (req, res) {
  log.debug("Entering the healthcheck endpoint.");
  res.status(200).json({ message: 'Success' });
  log.debug("Leaving the healthcheck endpoint.");
});

app.get('/sts/cert', function (req, res) {
  log.debug("Entering the STS certificate endpoint.");
  res.type('text/plain').send(STS.certPem);
  log.debug("Leaving the STS certificate endpoint.");
});

app.get('/sts', function (req, res) {
  log.debug("Entering the STS description endpoint.");
  res.type('text/plain').send('WS-Trust STS mock. POST a SOAP RequestSecurityToken here.\nIssuer: ' + ISSUER + '\n');
  log.debug("Leaving the STS description endpoint.");
});

app.post('/sts', function (req, res) {
  log.debug("Entering the WS-Trust STS endpoint.");
  const contentType = req.headers['content-type'] || '';
  try {
    const encrypt = req.query.encrypt === '1' || req.query.encrypt === 'true';
    const result = handleRst(req.body || '', contentType, { encrypt: encrypt });
    const ct = result.version === '1.1' ? 'text/xml; charset=utf-8' : 'application/soap+xml; charset=utf-8';
    res.status(result.status).type(ct).send(result.body);
    log.debug("Leaving the WS-Trust STS endpoint. HTTP " + result.status + ".");
  } catch (e) {
    log.error('STS error: ' + (e && e.stack ? e.stack : e));
    res.status(500).type('application/soap+xml; charset=utf-8')
       .send(soapFault('1.2', 'STS error: ' + (e && e.message ? e.message : String(e))));
    log.debug("Leaving the WS-Trust STS endpoint. It failed.");
  }
});

// ---------------------------------------------------------------------------
// RFC 8414 — OAuth 2.0 Authorization Server Metadata
//
// A dummy metadata document with EVERY member RFC 8414 section 2 defines
// populated, so the debugger's Configuration Parameters pane can be filled from
// a real endpoint. Served at the well-known path from section 3, and also with
// an issuer path component appended (section 3.1) so both shapes resolve.
//
// The issuer and every endpoint are derived from the URL the request arrived
// on, so the document is self-consistent whether it is reached as
// http://localhost:8081 (host) or http://sts:8081 (compose network).
// ---------------------------------------------------------------------------
function baseUrlOf(req) {
  log.debug("Entering baseUrlOf().");
  const base = (req.protocol || 'http') + '://' + (req.get('host') || ('localhost:' + PORT));
  log.debug("Leaving baseUrlOf(). base=" + base);
  return base;
}

function asMetadata(req) {
  log.debug("Entering asMetadata().");
  const base = baseUrlOf(req);
  const metadata = {
    // --- REQUIRED ---
    issuer: base,
    authorization_endpoint: base + '/oauth2/authorize',
    token_endpoint: base + '/oauth2/token',
    response_types_supported: ['code', 'token', 'id_token', 'code token', 'code id_token', 'code id_token token'],
    // --- RECOMMENDED / OPTIONAL ---
    jwks_uri: base + '/oauth2/jwks',
    registration_endpoint: base + '/oauth2/register',
    scopes_supported: ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'],
    response_modes_supported: ['query', 'fragment', 'form_post'],
    // Only what the token endpoint below actually implements — the metadata
    // should not promise a grant this server would refuse. (No device_code:
    // there is no device authorization endpoint to start that flow.)
    grant_types_supported: ['authorization_code', 'implicit', 'refresh_token', 'client_credentials',
                            'password', 'urn:ietf:params:oauth:grant-type:token-exchange',
                            // OID4VCI's pre-authorized code grant, which the
                            // cross-device Credential Offers use.
                            'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    // RFC 9396. OID4VCI's other way of saying which credential is wanted:
    // authorization_details of type openid_credential, instead of a scope.
    authorization_details_types_supported: ['openid_credential'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post',
                                            'client_secret_jwt', 'private_key_jwt', 'none'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'RS384', 'RS512', 'ES256', 'PS256', 'HS256'],
    service_documentation: base + '/docs',
    ui_locales_supported: ['en-US', 'en-GB', 'fr-CA', 'de-DE'],
    op_policy_uri: base + '/policy',
    op_tos_uri: base + '/tos',
    revocation_endpoint: base + '/oauth2/revoke',
    revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    revocation_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    introspection_endpoint: base + '/oauth2/introspect',
    introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    introspection_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    code_challenge_methods_supported: ['S256', 'plain']
    // signed_metadata is added below — it is a JWT OF this object, so it cannot
    // be one of the claims it signs.
  };
  log.debug("Leaving asMetadata().");
  return metadata;
}

// RFC 8414 section 2.1: signed_metadata is a JWT whose claims are the metadata
// members, signed by the issuer, and carrying iss and sub. Genuinely signed
// with the STS key so it can be verified (public key at /sts/cert, JWKS below).
function signedMetadata(meta) {
  log.debug("Entering signedMetadata().");
  const claims = Object.assign({}, meta, { sub: meta.issuer });
  logArtifact('RFC 8414 signed_metadata', 'before signing', claims);
  try {
    const signed = jwt.sign(claims, STS.privateKeyPem,
      { algorithm: 'RS256', issuer: meta.issuer, expiresIn: 3600, keyid: STS.kid });
    logArtifact('RFC 8414 signed_metadata', 'after signing', signed);
    log.debug("Leaving signedMetadata().");
    return signed;
  } catch (e) {
    log.error('signed_metadata: ' + e.message);
    log.debug("Leaving signedMetadata(). Nothing was signed.");
    return undefined;
  }
}

function sendAsMetadata(req, res) {
  log.debug("Entering sendAsMetadata().");
  const meta = asMetadata(req);
  const signed = signedMetadata(meta);
  if (signed) meta.signed_metadata = signed;
  res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify(meta, null, 2));
  log.debug("Leaving sendAsMetadata().");
}

app.get('/.well-known/oauth-authorization-server', sendAsMetadata);
// Issuer-with-path form, e.g. /.well-known/oauth-authorization-server/tenant1.
app.get('/.well-known/oauth-authorization-server/*', sendAsMetadata);

// The JWKS the metadata advertises, so jwks_uri actually resolves: the STS
// signing key as a single RS256 JWK.
app.get('/oauth2/jwks', function (req, res) {
  log.debug("Entering the JWKS endpoint.");
  try {
    const pub = forge.pki.certificateFromPem(STS.certPem).publicKey;
    const b64u = function (hex) {
      return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify({
      keys: [{
        kty: 'RSA', use: 'sig', alg: 'RS256', kid: STS.kid,
        n: b64u(pub.n.toString(16)), e: b64u(pub.e.toString(16)),
        x5c: [STS.certB64]
      }]
    }, null, 2));
    log.debug("Leaving the JWKS endpoint.");
  } catch (e) {
    log.error('could not publish the JWKS: ' + e.message);
    res.status(500).type('application/json').send(JSON.stringify({ error: e.message }));
    log.debug("Leaving the JWKS endpoint. It failed.");
  }
});

// ===========================================================================
// OpenID for Verifiable Credential Issuance (OID4VCI) — mock Credential Issuer
//
// The bare minimum needed to drive the debugger's SD-JWT VC issuance workflow
// end to end:
//
//   GET  /.well-known/openid-credential-issuer   Credential Issuer Metadata
//   GET  /.well-known/jwt-vc-issuer              JWT VC Issuer Metadata (the
//                                                SD-JWT VC key-resolution
//                                                document: issuer + jwks_uri)
//   POST /oid4vci/nonce                          a fresh c_nonce
//   POST /oid4vci/credential                     the Credential Request; returns
//                                                an SD-JWT VC built per RFC 9901
//
// This is a TEST issuer. It checks that a request carries SOME bearer token but
// cannot validate one issued by the separate authorization server (Keycloak in
// the test suite), so it does not try; what it DOES check properly is the
// wallet's proof of possession, because that is the part the debugger produces
// and therefore the part worth verifying.
//
// The authorization server the metadata advertises is configurable
// (OID4VCI_AUTHORIZATION_SERVER), so the document can point the wallet at the
// real IdP while the credential endpoint stays here.
// ===========================================================================
const crypto = require('crypto');
const qrcode = require('qrcode');

const VCI_AS = process.env.OID4VCI_AUTHORIZATION_SERVER || '';
const VCI_CONFIG_ID = 'IdentityCredential';
// The most proofs this issuer will take in one Credential Request, and so the
// most credentials it will return (OID4VCI section 14.6).
const VCI_BATCH_SIZE = Number(process.env.OID4VCI_BATCH_SIZE || 4);
const VCI_VCT = 'urn:idptools:sd-jwt-vc:identity';
const VCI_SCOPE = 'identity_credential';

// ---------------------------------------------------------------------------
// A second credential format: jwt_vc_json (OID4VCI Appendix A.1.1).
//
// The same End-User facts, issued as a W3C Verifiable Credential secured as a
// JWT instead of as an SD-JWT VC. It is here because the two formats differ in
// the one way this workflow is about: jwt_vc_json has NO selective disclosure.
// The whole credentialSubject is in the JWT, so a holder presenting it hands
// over everything in it — there are no Disclosures to choose between, and the
// holder binding that an SD-JWT does with a Key Binding JWT is done instead by
// signing a Verifiable Presentation JWT around the credential.
//
// Everything else is deliberately identical: the same proof of possession, the
// same batch and deferred paths, the same response encryption, the same
// notification ids. Only the artefact at the end is a different shape.
// ---------------------------------------------------------------------------
const VCI_JWT_CONFIG_ID = 'IdentityCredentialJwtVcJson';
const VCI_JWT_SCOPE = 'identity_credential_jwt';
const VCI_JWT_TYPES = ['VerifiableCredential', 'IdentityCredential'];
const VCI_LDP_CONFIG_ID = 'IdentityCredentialLdpVc';
const VCI_LDP_SCOPE = 'identity_credential_ldp';
const bbs2023 = require('./bbs2023.js');
// One BBS key pair per start, like the RSA one. Generated lazily because key
// generation is async and the module loads synchronously.
let bbsKeys = null;
async function bbsKeyPair() {
  if (!bbsKeys) bbsKeys = await bbs2023.generateKeyPair();
  return bbsKeys;
}
const VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1';

// Every credential this issuer offers, by credential_configuration_id. One
// place, because "is this a configuration I offer" is asked from four of them
// (the credential endpoint, authorization_details, the offer builder and the
// metadata) and a list that disagrees with itself between those is an issuer
// that advertises what it will then refuse.
const VCI_CONFIGS = {};
VCI_CONFIGS[VCI_CONFIG_ID] = { format: 'dc+sd-jwt', scope: VCI_SCOPE };
VCI_CONFIGS[VCI_JWT_CONFIG_ID] = { format: 'jwt_vc_json', scope: VCI_JWT_SCOPE };
// The third format: a W3C credential secured by an EMBEDDED Data Integrity
// proof (bbs-2023) rather than by a JWS. This is the only one of the three that
// can carry BBS at all — the other two are JOSE-secured and BBS is not a JOSE
// alg — and it is the only one offering unlinkable selective disclosure: the
// holder derives a fresh proof per presentation instead of replaying the
// issuer's signature.
VCI_CONFIGS[VCI_LDP_CONFIG_ID] = { format: 'ldp_vc', scope: VCI_LDP_SCOPE };

function vciConfigIds() { return Object.keys(VCI_CONFIGS); }
function vciFormatOf(configId) {
  const c = VCI_CONFIGS[configId];
  return c ? c.format : '';
}
// A credential_identifier is minted as "<configId>:<hash>", so the
// configuration it belongs to is the part before the colon. Used to route a
// section 8.2 identifier request to the right format.
function configIdOfIdentifier(identifier) {
  const prefix = String(identifier || '').split(':')[0];
  return VCI_CONFIGS[prefix] ? prefix : '';
}
// c_nonce values this issuer has handed out and not yet seen used. A nonce is
// single-use (RFC-conformant behaviour, and it makes replay visible in a test).
const vciNonces = new Map();
const VCI_NONCE_TTL_MS = 5 * 60 * 1000;

// base64url, in both directions. Deliberately without entering/leaving logs:
// these are called several times per token and would drown the log.
function b64u(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function jsonFromB64u(s) { return JSON.parse(b64uDecode(s).toString('utf8')); }

function vciMetadata(req) {
  log.debug("Entering vciMetadata().");
  const base = baseUrlOf(req);
  const authServer = VCI_AS || base;
  const meta = {
    // --- REQUIRED ---
    credential_issuer: base,
    credential_endpoint: base + '/oid4vci/credential',
    credential_configurations_supported: {},
    // --- OPTIONAL ---
    authorization_servers: [authServer],
    nonce_endpoint: base + '/oid4vci/nonce',
    // OPTIONAL, and a wallet must not assume it: an issuer that cannot defer
    // omits it entirely (walt.id's does). Ours can, so it says so.
    deferred_credential_endpoint: base + '/oid4vci/deferred_credential',
    notification_endpoint: base + '/oid4vci/notification',
    batch_credential_issuance: { batch_size: VCI_BATCH_SIZE },
    // Only what this issuer actually performs. It used to advertise ECDH-ES as
    // well, which nothing implemented — metadata that overstates is worse than
    // metadata that says little.
    credential_response_encryption: {
      alg_values_supported: [VCI_ENC_ALG],
      enc_values_supported: VCI_ENC_VALUES,
      encryption_required: false
    },
    display: [{
      name: 'IdP Tools Mock Credential Issuer',
      locale: 'en-US',
      logo: { uri: base + '/images/logo.png', alt_text: 'IdP Tools' }
    }]
  };
  meta.credential_configurations_supported[VCI_CONFIG_ID] = {
    format: 'dc+sd-jwt',
    scope: VCI_SCOPE,
    vct: VCI_VCT,
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: ['RS256'],
    proof_types_supported: {
      jwt: { proof_signing_alg_values_supported: ['ES256', 'RS256'] }
    },
    display: [{
      name: 'Identity Credential',
      locale: 'en-US',
      background_color: '#12107c',
      text_color: '#FFFFFF'
    }],
    claims: [
      { path: ['given_name'], display: [{ locale: 'en-US', name: 'Given name' }] },
      { path: ['family_name'], display: [{ locale: 'en-US', name: 'Family name' }] },
      { path: ['email'], display: [{ locale: 'en-US', name: 'Email address' }] },
      { path: ['birthdate'], display: [{ locale: 'en-US', name: 'Date of birth' }] },
      { path: ['address', 'country'], display: [{ locale: 'en-US', name: 'Country' }] }
    ]
  };
  // The same facts as a W3C VC secured as a JWT. `credential_definition.type`
  // is what identifies the credential in this format — jwt_vc_json has no vct —
  // and the claim paths are rooted at credentialSubject because that is where a
  // W3C VC keeps them.
  meta.credential_configurations_supported[VCI_JWT_CONFIG_ID] = {
    format: 'jwt_vc_json',
    scope: VCI_JWT_SCOPE,
    credential_definition: { type: VCI_JWT_TYPES },
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: ['RS256'],
    proof_types_supported: {
      jwt: { proof_signing_alg_values_supported: ['ES256', 'RS256'] }
    },
    display: [{
      name: 'Identity Credential (JWT VC, no selective disclosure)',
      locale: 'en-US',
      background_color: '#0b6b4f',
      text_color: '#FFFFFF'
    }],
    claims: [
      { path: ['credentialSubject', 'given_name'], display: [{ locale: 'en-US', name: 'Given name' }] },
      { path: ['credentialSubject', 'family_name'], display: [{ locale: 'en-US', name: 'Family name' }] },
      { path: ['credentialSubject', 'email'], display: [{ locale: 'en-US', name: 'Email address' }] },
      { path: ['credentialSubject', 'birthdate'], display: [{ locale: 'en-US', name: 'Date of birth' }] },
      { path: ['credentialSubject', 'address', 'country'], display: [{ locale: 'en-US', name: 'Country' }] }
    ]
  };
  // ldp_vc: the signing "alg" slot holds a CRYPTOSUITE name, not a JOSE alg —
  // which is the visible sign that this format is secured differently.
  meta.credential_configurations_supported[VCI_LDP_CONFIG_ID] = {
    format: 'ldp_vc',
    scope: VCI_LDP_SCOPE,
    credential_definition: {
      '@context': ['https://www.w3.org/ns/credentials/v2', bbs2023.IDENTITY_CONTEXT_URL],
      type: VCI_JWT_TYPES
    },
    cryptographic_binding_methods_supported: ['did:key'],
    credential_signing_alg_values_supported: ['bbs-2023'],
    proof_types_supported: {
      jwt: { proof_signing_alg_values_supported: ['ES256'] }
    },
    display: [{
      name: 'Identity Credential (ldp_vc, BBS selective disclosure)',
      locale: 'en-US', background_color: '#4a148c', text_color: '#FFFFFF'
    }],
    claims: [
      { path: ['credentialSubject', 'given_name'], display: [{ locale: 'en-US', name: 'Given name' }] },
      { path: ['credentialSubject', 'family_name'], display: [{ locale: 'en-US', name: 'Family name' }] },
      { path: ['credentialSubject', 'email'], display: [{ locale: 'en-US', name: 'Email address' }] },
      { path: ['credentialSubject', 'birthDate'], display: [{ locale: 'en-US', name: 'Date of birth' }] }
    ]
  };
  log.debug("Leaving vciMetadata(). " + Object.keys(meta.credential_configurations_supported).length +
            " credential configuration(s).");
  return meta;
}

// OID4VCI adopts RFC 8414's signed_metadata: a JWT of the metadata signed by
// the issuer. Signed with the same STS key, so the debugger can verify it
// against /oauth2/jwks exactly as it verifies an RFC 8414 document.
function sendVciMetadata(req, res) {
  log.debug("Entering sendVciMetadata().");
  const meta = vciMetadata(req);
  const claims = Object.assign({}, meta, { sub: meta.credential_issuer });
  logArtifact('OID4VCI signed_metadata', 'before signing', claims);
  try {
    meta.signed_metadata = jwt.sign(claims, STS.privateKeyPem,
      { algorithm: 'RS256', issuer: meta.credential_issuer, expiresIn: 3600, keyid: STS.kid });
    logArtifact('OID4VCI signed_metadata', 'after signing', meta.signed_metadata);
  } catch (e) {
    log.error('OID4VCI signed_metadata: ' + e.message);
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify(meta, null, 2));
  log.debug("Leaving sendVciMetadata().");
}

app.get('/.well-known/openid-credential-issuer', sendVciMetadata);
app.get('/.well-known/openid-credential-issuer/*', sendVciMetadata);

// SD-JWT VC key resolution: how a verifier finds the issuer's public keys.
function sendJwtVcIssuerMetadata(req, res) {
  log.debug("Entering sendJwtVcIssuerMetadata().");
  const base = baseUrlOf(req);
  res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify({
    issuer: base,
    jwks_uri: base + '/oauth2/jwks'
  }, null, 2));
  log.debug("Leaving sendJwtVcIssuerMetadata().");
}

app.get('/.well-known/jwt-vc-issuer', sendJwtVcIssuerMetadata);
app.get('/.well-known/jwt-vc-issuer/*', sendJwtVcIssuerMetadata);

// ---------------------------------------------------------------------------
// Credential Offer (OID4VCI section 4) — the issuer-initiated half of issuance.
//
// Appendix H.1 "Credential Offer - Same-Device": the End-User is browsing the
// issuer's site, follows a "request your digital diploma" link, and is taken to
// their Wallet with a Credential Offer in hand. That is what these three
// endpoints are:
//
//   GET /issuer                     the issuer's web page, with the link
//   GET /issuer/offer               builds an offer and redirects to the wallet,
//                                   by value (credential_offer) or by reference
//                                   (credential_offer_uri)
//   GET /oid4vci/credential-offer/:id  serves an offer fetched by reference
//
// The offer names this issuer, the credential configuration(s) on offer, and the
// grant. For H.1 that grant is authorization_code carrying an issuer_state,
// which the Wallet must hand back on the authorization request so the issuer can
// tie the two together.
//
// The Wallet a browser page can be sent to is a URL, not the openid-credential-offer://
// scheme a native wallet would register — OID4VCI_WALLET_URL says where it lives.
// ---------------------------------------------------------------------------
const WALLET_BASE_URL = process.env.OID4VCI_WALLET_URL || 'http://localhost:3000';
const credentialOffers = new Map();     // id -> { offer, issuerState, expires }
const issuerStates = new Map();         // issuer_state -> { configurationIds, expires }
// Pre-authorized codes (OID4VCI Appendix H.2 / H.3): the End-User authorized the
// issuance out of band, so there is no authorization request at all — the code
// in the offer IS the authorization. `txCode` is the Transaction Code the issuer
// shows on its own screen and the End-User types into the wallet; `deferred`
// marks an issuance the credential endpoint will not complete immediately.
const preAuthorizedCodes = new Map();   // code -> { configurationIds, txCode, user, deferred, expires }
// Deferred issuance transactions (OID4VCI section 9): the credential endpoint
// answered 202 with one of these instead of a credential.
const deferredTransactions = new Map(); // transaction_id -> { claims, holderJwk, readyAt, expires }
// Access tokens minted from a deferred offer: the credential endpoint answers
// 202 for these instead of issuing straight away.
const deferredAccessTokens = new Set();
// How long a deferred issuance "takes". Short enough for a test to wait for it,
// long enough that the first poll genuinely comes back still-pending.
const DEFERRED_READY_MS = Number(process.env.OID4VCI_DEFERRED_READY_MS || 4000);
const DEFERRED_INTERVAL_S = Number(process.env.OID4VCI_DEFERRED_INTERVAL_S || 2);
const OFFER_TTL_MS = 10 * 60 * 1000;
// A pre-authorized offer is made to an End-User the issuer has ALREADY
// identified (H.2: they uploaded documents to an employee portal days before),
// so the issuer knows the subject without anyone signing in.
const VCI_OFFER_USERNAME = process.env.OID4VCI_OFFER_USERNAME || 'diploma.student';

// Build a Credential Offer for one of the Appendix H use cases.
//
//   same-device  (H.1) authorization_code + issuer_state: the wallet still has
//                      to take the End-User through the authorization server.
//   cross-device (H.2) pre-authorized_code + tx_code: the End-User already
//                      identified themselves to the issuer by some other route,
//                      so the code IS the authorization and the Transaction
//                      Code shown on the issuer's screen is what ties the
//                      wallet on the other device to this End-User.
//   deferred     (H.3) the same pre-authorized offer, but flagged so the
//                      credential endpoint answers 202 with a transaction_id
//                      instead of a credential.
function buildCredentialOffer(req, configurationIds, mode) {
  log.debug("Entering buildCredentialOffer(). mode=" + mode);
  const base = baseUrlOf(req);
  const expires = Date.now() + OFFER_TTL_MS;
  const offer = {
    credential_issuer: base,
    credential_configuration_ids: configurationIds
  };
  let issuerState = "";
  let preAuthorizedCode = "";
  let txCodeValue = "";

  if (mode === 'cross-device' || mode === 'deferred') {
    preAuthorizedCode = randomId(24);
    // Five numeric digits, which is what the issuer's page displays. The value
    // never travels in the offer — only its shape does — because the whole
    // point is that it reaches the End-User by a different channel.
    txCodeValue = String(Math.floor(Math.random() * 90000) + 10000);
    preAuthorizedCodes.set(preAuthorizedCode, {
      configurationIds: configurationIds,
      txCode: txCodeValue,
      user: userFor(VCI_OFFER_USERNAME),
      deferred: mode === 'deferred',
      expires: expires
    });
    offer.grants = {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': preAuthorizedCode,
        tx_code: {
          input_mode: 'numeric',
          length: txCodeValue.length,
          // No apostrophe: this string is URL-encoded into the offer, and an
          // apostrophe survives encodeURIComponent only to be XML-escaped into
          // "&apos;" when the offer URI is displayed — which turns one query
          // parameter into two for anything reading it off the page.
          description: 'Type the ' + txCodeValue.length + '-digit code shown by the issuer.'
        },
        interval: 5
      }
    };
  } else {
    issuerState = randomId(18);
    issuerStates.set(issuerState, { configurationIds: configurationIds, expires: expires });
    offer.grants = { authorization_code: { issuer_state: issuerState } };
  }

  logArtifact('OID4VCI Credential Offer', 'as built', offer);
  log.debug("Leaving buildCredentialOffer(). mode=" + mode + ", issuer_state=" + issuerState +
            ", pre-authorized=" + (preAuthorizedCode ? "yes" : "no"));
  return { offer: offer, issuerState: issuerState,
           preAuthorizedCode: preAuthorizedCode, txCode: txCodeValue, mode: mode || 'same-device' };
}

// The issuer's own web page — where H.1 starts.
app.get('/issuer', function (req, res) {
  log.debug("Entering the issuer web page.");
  const base = baseUrlOf(req);
  const configId = VCI_CONFIG_ID;
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Mock University — digital diploma</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:520px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
    'p{line-height:1.5;color:#333}a.cta{display:inline-block;margin-top:14px;margin-right:10px;padding:10px 16px;' +
    'border-radius:6px;background:#12107c;color:#fff;text-decoration:none;font-weight:600}' +
    'a.cta.secondary{background:#fff;color:#12107c;border:1px solid #12107c}' +
    'p.alt{margin-top:20px;font-size:.92em;color:#555}' +
    '.meta{margin-top:22px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>Mock University</h1>' +
    '<p>Congratulations on your graduation. Your diploma is available as a digital credential ' +
    '(<code>' + xmlEscape(configId) + '</code>) that you can keep in your wallet.</p>' +
    '<p><a class="cta" href="/issuer/offer">Request your digital diploma</a>' +
    '<a class="cta secondary" href="/issuer/offer?by=reference">Request it (offer by reference)</a></p>' +
    '<p class="alt">On a different device? These show a QR code to scan with your wallet instead:<br>' +
    '<a class="cta secondary" href="/issuer/offer?mode=cross-device">Show a QR code (cross-device)</a>' +
    '<a class="cta secondary" href="/issuer/offer?mode=deferred">Show a QR code (issuance takes a while)</a></p>' +
    '<div class="meta">This is the Credential Issuer\'s web page in OID4VCI Appendix H. The first two links ' +
    'build a Credential Offer and send you to your wallet at <code>' + xmlEscape(WALLET_BASE_URL) + '</code> ' +
    '(H.1, same device). The other two hand the offer over by QR code and a Transaction Code instead — H.2, ' +
    'and H.3 where the issuer needs time to produce the credential. The issuer is ' +
    '<code>' + xmlEscape(base) + '</code>.</div>' +
    '</div></body></html>\n';
  res.status(200).type('text/html').send(page);
  log.debug("Leaving the issuer web page.");
});

// The link on that page: build the offer and send the End-User to their wallet.
app.get('/issuer/offer', function (req, res) {
  log.debug("Entering the credential offer endpoint.");
  const base = baseUrlOf(req);
  const configurationIds = req.query.credential_configuration_ids
    ? String(req.query.credential_configuration_ids).split(',').filter(Boolean)
    : [VCI_CONFIG_ID];
  const mode = String(req.query.mode || 'same-device');
  const built = buildCredentialOffer(req, configurationIds, mode);
  const wallet = String(req.query.wallet || WALLET_BASE_URL).replace(/\/+$/, '') +
                 '/vc-issuance-1.html';

  // Sweep expired offers/states/codes while we are here.
  const now = Date.now();
  credentialOffers.forEach(function (v, k) { if (v.expires < now) credentialOffers.delete(k); });
  issuerStates.forEach(function (v, k) { if (v.expires < now) issuerStates.delete(k); });
  preAuthorizedCodes.forEach(function (v, k) { if (v.expires < now) preAuthorizedCodes.delete(k); });
  deferredTransactions.forEach(function (v, k) { if (v.expires < now) deferredTransactions.delete(k); });

  // How the offer reaches the wallet: in the URL, or behind a URI it fetches.
  let offerQuery;
  if (String(req.query.by || '') === 'reference') {
    const id = randomId(12);
    credentialOffers.set(id, { offer: built.offer, expires: now + OFFER_TTL_MS });
    const offerUri = base + '/oid4vci/credential-offer/' + id;
    offerQuery = 'credential_offer_uri=' + encodeURIComponent(offerUri);
    log.debug("The offer is passed by reference: " + offerUri);
  } else {
    offerQuery = 'credential_offer=' + encodeURIComponent(JSON.stringify(built.offer));
    log.debug("The offer is passed by value.");
  }

  // Same device (H.1): the wallet is right here, so send the browser to it.
  if (built.mode !== 'cross-device' && built.mode !== 'deferred') {
    res.redirect(302, wallet + '?' + offerQuery);
    log.debug("Leaving the credential offer endpoint. Sent the End-User to " + wallet + ".");
    return;
  }

  // Cross device (H.2 / H.3): the wallet is on the End-User's OTHER device, so
  // the offer is displayed for it to scan — as the openid-credential-offer URI
  // a wallet registers for — and the Transaction Code is shown here, on the
  // issuer's screen, never in the offer.
  const offerUri = 'openid-credential-offer://?' + offerQuery;
  renderOfferQrPage(res, {
    base: base,
    mode: built.mode,
    offerUri: offerUri,
    walletUrl: wallet + '?' + offerQuery,
    txCode: built.txCode,
    offer: built.offer
  });
  log.debug("Leaving the credential offer endpoint. Displayed a QR code for the wallet to scan.");
});

// The issuer's screen in a cross-device flow: a QR code carrying the Credential
// Offer, and — separately, which is the whole point — the Transaction Code.
function renderOfferQrPage(res, opts) {
  log.debug("Entering renderOfferQrPage(). mode=" + opts.mode);
  qrcode.toDataURL(opts.offerUri, { errorCorrectionLevel: 'M', margin: 2, width: 320 })
    .then(function (dataUrl) {
      const deferred = opts.mode === 'deferred';
      const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
        '<title>Mock University — scan to receive your credential</title><style>' +
        'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
        'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
        '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
        'box-shadow:0 6px 24px rgba(0,0,0,.08);text-align:center}h1{font-size:1.25em;margin:0 0 6px}' +
        'p{line-height:1.5;color:#333}img.qr{margin:14px auto;display:block;border:1px solid #eee;border-radius:8px}' +
        '.txcode{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:2.1em;letter-spacing:.28em;' +
        'font-weight:700;color:#12107c;background:#f0f0fa;border-radius:8px;padding:12px 6px;margin:6px 0 2px}' +
        '.uri{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.72em;' +
        'color:#555;background:#fafafa;border:1px solid #eee;border-radius:6px;padding:8px;text-align:left}' +
        '.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777;text-align:left}' +
        'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
        '</style></head><body><div class="card">' +
        '<h1>Scan this with your wallet</h1>' +
        '<p>Your digital diploma is ready to be claimed' +
        (deferred ? ', though issuing it will take us a little time once you ask.' : '.') + '</p>' +
        '<img class="qr" id="offer_qr" alt="Credential Offer QR code" src="' + dataUrl + '">' +
        '<p>Then type this Transaction Code into your wallet:</p>' +
        '<div class="txcode" id="tx_code">' + xmlEscape(opts.txCode) + '</div>' +
        '<p style="font-size:.8em;color:#777">It is shown here, and only here — it does not travel in the QR code.</p>' +
        '<div class="uri" id="offer_uri">' + xmlEscape(opts.offerUri) + '</div>' +
        '<div class="meta">OID4VCI Appendix ' + (deferred ? 'H.3' : 'H.2') + '. The offer uses the ' +
        '<code>pre-authorized_code</code> grant: you already identified yourself to this issuer, so your wallet ' +
        'goes straight to the token endpoint — there is no authorization request. ' +
        (deferred ? 'The credential endpoint will answer with a <code>transaction_id</code> and your wallet will ' +
                    'have to come back for the credential. ' : '') +
        'If your wallet is on this device, <a id="open_in_wallet" href="' + xmlEscape(opts.walletUrl) + '">open it here</a>.' +
        '</div></div></body></html>\n';
      res.status(200).type('text/html').send(page);
      log.debug("Leaving renderOfferQrPage(). Rendered a QR code.");
    })
    .catch(function (e) {
      log.error("could not render the offer QR code: " + e.message);
      res.status(500).type('text/plain').send('Could not render the Credential Offer QR code: ' + e.message);
    });
}

app.get('/oid4vci/credential-offer/:id', function (req, res) {
  log.debug("Entering the credential offer retrieval endpoint. id=" + req.params.id);
  const record = credentialOffers.get(req.params.id);
  if (!record || record.expires < Date.now()) {
    credentialOffers.delete(req.params.id);
    log.debug("Leaving the credential offer retrieval endpoint. No such offer.");
    return vciError(res, 404, 'invalid_request', 'No such Credential Offer, or it has expired.');
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(record.offer, null, 2));
  log.debug("Leaving the credential offer retrieval endpoint.");
});

// --- Nonce Endpoint ---------------------------------------------------------
app.post('/oid4vci/nonce', function (req, res) {
  log.debug("Entering the OID4VCI nonce endpoint.");
  const nonce = b64u(crypto.randomBytes(24));
  const now = Date.now();
  vciNonces.set(nonce, now + VCI_NONCE_TTL_MS);
  // Opportunistic sweep, so a long-running mock does not grow without bound.
  vciNonces.forEach(function (expires, key) { if (expires < now) vciNonces.delete(key); });
  res.set('Cache-Control', 'no-store');
  res.status(200).type('application/json').send(JSON.stringify({
    c_nonce: nonce,
    c_nonce_expires_in: VCI_NONCE_TTL_MS / 1000
  }));
  log.debug("Leaving the OID4VCI nonce endpoint. Handed out one c_nonce; " +
            vciNonces.size + " now outstanding.");
});

// --- the wallet's proof of possession --------------------------------------
// A JWT proof (OID4VCI): typ openid4vci-proof+jwt, the holder's public key in
// the header as a JWK, and claims binding it to this issuer and to a c_nonce
// this issuer handed out. Returns the holder JWK on success.
function verifyProofJwt(proofJwt, credentialIssuer) {
  log.debug("Entering verifyProofJwt().");
  logArtifact('OID4VCI proof of possession', 'as received', proofJwt);
  const parts = String(proofJwt || '').split('.');
  if (parts.length !== 3) throw new Error('the proof is not a three-part JWS.');
  let header, claims;
  try {
    header = jsonFromB64u(parts[0]);
    claims = jsonFromB64u(parts[1]);
  } catch (e) {
    throw new Error('the proof is not a readable JWT: ' + e.message);
  }

  if (header.typ !== 'openid4vci-proof+jwt') {
    throw new Error('the proof typ must be openid4vci-proof+jwt, got "' + header.typ + '".');
  }
  if (!header.jwk) throw new Error('the proof header carries no jwk (this issuer binds to a JWK).');
  if (['ES256', 'RS256'].indexOf(header.alg) < 0) {
    throw new Error('unsupported proof alg "' + header.alg + '".');
  }
  if (claims.aud !== credentialIssuer) {
    throw new Error('the proof aud ("' + claims.aud + '") is not this credential issuer ("' +
                    credentialIssuer + '").');
  }
  if (!claims.iat || Math.abs(Date.now() / 1000 - claims.iat) > 600) {
    throw new Error('the proof iat is missing or too far from now.');
  }
  const expires = vciNonces.get(claims.nonce);
  if (!expires) throw new Error('the proof nonce is not one this issuer handed out (or was already used).');
  // The c_nonce belongs to the REQUEST, not to a single proof: a batch request
  // carries several proofs and they all quote the same one (section 8.2). So it
  // is not spent here — the caller spends it once, after every proof in the
  // request has been verified. Consuming it per proof made the second proof of
  // any batch fail, which is exactly the bug batch issuance uncovered.
  if (expires < Date.now()) {
    vciNonces.delete(claims.nonce);
    throw new Error('the proof nonce has expired.');
  }

  let key;
  try {
    key = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
  } catch (e) {
    throw new Error('the proof header jwk is not a usable public key: ' + e.message);
  }
  const data = Buffer.from(parts[0] + '.' + parts[1], 'ascii');
  const sig = b64uDecode(parts[2]);
  const opts = (header.alg === 'ES256')
    ? { key: key, dsaEncoding: 'ieee-p1363' }
    : { key: key };
  if (!crypto.verify('sha256', data, opts, sig)) {
    throw new Error('the proof signature does not verify with the key in its own header.');
  }
  logArtifact('OID4VCI proof of possession', 'verified', { header: header, payload: claims });
  log.debug("Leaving verifyProofJwt(). The proof is good.");
  return header.jwk;
}

// --- SD-JWT VC construction (RFC 9901) --------------------------------------
// A Disclosure is base64url(JSON [salt, claim name, claim value]); the digest
// that goes in _sd is base64url(SHA-256(the ASCII of that base64url string)).
function makeDisclosure(name, value) {
  log.debug("Entering makeDisclosure(). name=" + name);
  const salt = b64u(crypto.randomBytes(16));
  const encoded = b64u(Buffer.from(JSON.stringify([salt, name, value]), 'utf8'));
  const digest = b64u(crypto.createHash('sha256').update(encoded, 'ascii').digest());
  log.debug("Leaving makeDisclosure(). digest=" + digest);
  return { salt: salt, name: name, value: value, encoded: encoded, digest: digest };
}

function buildSdJwtVc(subjectClaims, holderJwk, credentialIssuer) {
  log.debug("Entering buildSdJwtVc().");
  logArtifact('SD-JWT VC', 'the claims it will assert, before any of them are hidden',
              { subjectClaims: subjectClaims, holderJwk: holderJwk, credentialIssuer: credentialIssuer });
  const now = Math.floor(Date.now() / 1000);
  // Everything the holder can choose to disclose, one Disclosure each. sub is
  // not among them: it stays a plain claim, so the credential always says who
  // it is about.
  const disclosures = Object.keys(subjectClaims)
    .filter(function (name) { return name !== 'sub'; })
    .map(function (name) { return makeDisclosure(name, subjectClaims[name]); });
  // A decoy digest: RFC 9901 section 4.2.5 — hash a random value so the count
  // of _sd entries does not reveal how many claims there really are.
  const decoy = b64u(crypto.createHash('sha256').update(b64u(crypto.randomBytes(16)), 'ascii').digest());
  const digests = disclosures.map(function (d) { return d.digest; }).concat([decoy]).sort();

  const payload = {
    iss: credentialIssuer,
    nbf: now,
    exp: now + 30 * 24 * 3600,
    vct: VCI_VCT,
    sub: subjectClaims.sub || 'urn:uuid:' + crypto.randomUUID(),
    cnf: { jwk: holderJwk },
    _sd_alg: 'sha-256',
    _sd: digests
  };
  logArtifact('SD-JWT VC', 'before signing',
              { header: { alg: 'RS256', typ: 'dc+sd-jwt', kid: STS.kid },
                payload: payload,
                disclosures: disclosures.map(function (d) {
                  return { name: d.name, value: d.value, salt: d.salt, digest: d.digest, encoded: d.encoded };
                }),
                decoyDigest: decoy });

  // iat is added by the signer (jsonwebtoken drops a payload iat when it is
  // told not to timestamp, so it is left to do it).
  const issuerJwt = jwt.sign(payload, STS.privateKeyPem, {
    algorithm: 'RS256',
    header: { alg: 'RS256', typ: 'dc+sd-jwt', kid: STS.kid }
  });
  logArtifact('SD-JWT VC issuer-signed JWT', 'after signing', issuerJwt);

  // Combined Serialization: <JWT>~<D1>~...~<Dn>~ (the trailing ~ is required
  // when no Key Binding JWT is present).
  const serialized = [issuerJwt].concat(disclosures.map(function (d) { return d.encoded; })).join('~') + '~';
  logArtifact('SD-JWT VC', 'after signing, as it will be sent (Combined Serialization)', serialized);
  log.debug("Leaving buildSdJwtVc(). " + disclosures.length + " disclosure(s) plus 1 decoy digest.");
  return { credential: serialized, disclosures: disclosures, payload: payload, decoy: decoy };
}

// A W3C Verifiable Credential secured as a JWT (OID4VCI format jwt_vc_json).
//
// The VC-JWT encoding of VCDM 1.1: the credential object goes in the `vc`
// claim, and the JWT's own registered claims carry the parts that would
// otherwise be duplicated inside it — iss is the issuer, sub the credential
// subject, nbf/exp the validity window, jti the credential id.
//
// Two things to notice, because they are what the workflow is meant to show:
// there are NO Disclosures and no _sd digests — every claim is in the clear in
// the payload, so a holder presenting this discloses all of it; and holder
// binding is the same cnf.jwk this issuer puts in an SD-JWT VC, but what proves
// possession at presentation time is a Verifiable Presentation JWT signed with
// that key rather than a Key Binding JWT.
function buildJwtVcJson(subjectClaims, holderJwk, credentialIssuer) {
  log.debug("Entering buildJwtVcJson().");
  logArtifact('jwt_vc_json credential', 'the claims it will assert',
              { subjectClaims: subjectClaims, holderJwk: holderJwk, credentialIssuer: credentialIssuer });
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 30 * 24 * 3600;
  const subjectId = subjectClaims.sub || ('urn:uuid:' + crypto.randomUUID());

  // credentialSubject.id is the subject identifier; the rest of the claims sit
  // beside it. `sub` is not repeated inside as a claim of its own — it IS the id.
  const credentialSubject = { id: subjectId };
  Object.keys(subjectClaims).forEach(function (name) {
    if (name !== 'sub') credentialSubject[name] = subjectClaims[name];
  });

  const vc = {
    '@context': [VC_CONTEXT],
    type: VCI_JWT_TYPES,
    issuer: credentialIssuer,
    issuanceDate: new Date(now * 1000).toISOString(),
    expirationDate: new Date(exp * 1000).toISOString(),
    credentialSubject: credentialSubject
  };
  const payload = {
    iss: credentialIssuer,
    sub: subjectId,
    nbf: now,
    exp: exp,
    jti: 'urn:uuid:' + crypto.randomUUID(),
    cnf: { jwk: holderJwk },
    vc: vc
  };
  logArtifact('jwt_vc_json credential', 'before signing',
              { header: { alg: 'RS256', typ: 'JWT', kid: STS.kid }, payload: payload });

  const token = jwt.sign(payload, STS.privateKeyPem, {
    algorithm: 'RS256',
    header: { alg: 'RS256', typ: 'JWT', kid: STS.kid }
  });
  logArtifact('jwt_vc_json credential', 'after signing, as it will be sent', token);
  log.debug("Leaving buildJwtVcJson(). " + (Object.keys(credentialSubject).length - 1) +
            " claim(s), none of them selectively disclosable.");
  // `disclosures` is deliberately an empty array rather than absent: the callers
  // count them for logging, and "this format has none" is the honest answer.
  return { credential: token, disclosures: [], payload: payload, vc: vc };
}

// A W3C credential with an EMBEDDED bbs-2023 proof (OID4VCI format ldp_vc).
//
// Async, unlike the other two, because canonicalization is — which is why
// buildCredentialFor and the credential endpoint are async as well.
//
// Holder binding differs from the other formats by necessity: there is no
// cnf.jwk here. The holder is named by credentialSubject.id, a did:key built
// from the key it proved possession of, and what proves possession at
// presentation time is the BBS derived proof itself rather than a separate
// signature by the holder.
async function buildLdpVc(subjectClaims, holderJwk, credentialIssuer) {
  log.debug("Entering buildLdpVc().");
  const keys = await bbsKeyPair();
  const now = Math.floor(Date.now() / 1000);
  const subjectId = 'did:jwk:' + b64u(Buffer.from(JSON.stringify({
    crv: holderJwk.crv, kty: holderJwk.kty, x: holderJwk.x, y: holderJwk.y
  })));
  const unsecured = {
    '@context': ['https://www.w3.org/ns/credentials/v2', bbs2023.IDENTITY_CONTEXT_URL],
    type: VCI_JWT_TYPES,
    issuer: credentialIssuer,
    validFrom: new Date(now * 1000).toISOString(),
    validUntil: new Date((now + 30 * 24 * 3600) * 1000).toISOString(),
    credentialSubject: {
      id: subjectId,
      given_name: subjectClaims.given_name,
      family_name: subjectClaims.family_name,
      email: subjectClaims.email,
      birthDate: subjectClaims.birthdate
    }
  };
  logArtifact('ldp_vc credential', 'before signing', unsecured);
  const issued = await bbs2023.issue(unsecured, {
    verificationMethod: credentialIssuer + '/bbs/keys/1',
    created: new Date(now * 1000).toISOString()
  }, keys.secretKey, keys.publicKey);

  // Verified immediately, by this service, before it is handed out: the
  // requirement is that the STS validate every crypto operation, and an issuer
  // that cannot verify its own output has no business emitting it.
  const check = await bbs2023.verifyBase(issued.credential, keys.publicKey);
  if (!check.ok) throw new Error('the ldp_vc credential this issuer just built does not verify');

  logArtifact('ldp_vc credential', 'after signing (' + issued.statements.length + ' statements)',
              issued.credential);
  log.debug("Leaving buildLdpVc(). " + issued.statements.length + " canonical statement(s).");
  return { credential: issued.credential, disclosures: [], payload: issued.credential,
           statements: issued.statements };
}

// Mint whichever format the requested configuration names.
async function buildCredentialFor(configId, subjectClaims, holderJwk, credentialIssuer) {
  const format = vciFormatOf(configId);
  if (format === 'ldp_vc') return buildLdpVc(subjectClaims, holderJwk, credentialIssuer);
  if (format === 'jwt_vc_json') return buildJwtVcJson(subjectClaims, holderJwk, credentialIssuer);
  return buildSdJwtVc(subjectClaims, holderJwk, credentialIssuer);
}

// The claims the credential asserts. Lifted from the access token when it is a
// JWT (so the credential describes whoever actually authenticated), with
// mock-issuer defaults for anything the token does not carry.
function subjectClaimsFrom(accessToken) {
  log.debug("Entering subjectClaimsFrom().");
  let t = {};
  try {
    const parts = String(accessToken || '').split('.');
    if (parts.length === 3) t = jsonFromB64u(parts[1]) || {};
  } catch (e) {
    // An opaque token — the mock defaults it is.
    log.debug("The access token is not a readable JWT; using the default claims.");
  }
  const user = t.preferred_username || t.sub || 'mock-holder';
  log.debug("Leaving subjectClaimsFrom(). The credential will describe " + user + ".");
  return {
    sub: t.sub || ('urn:uuid:' + crypto.randomUUID()),
    given_name: t.given_name || user,
    family_name: t.family_name || 'Holder',
    email: t.email || (user + '@example.com'),
    birthdate: '1979-04-01',
    nationality: 'US',
    address: { street_address: '100 Main St', locality: 'Springfield', region: 'IL', country: 'US' }
  };
}

function vciError(res, status, error, description) {
  log.debug("Entering vciError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').send(JSON.stringify({
    error: error, error_description: description
  }));
  log.debug("Leaving vciError().");
}

// ---------------------------------------------------------------------------
// Which Credential Dataset identifiers an access token was granted.
//
// They were put into the token when it was issued, and the token is signed by
// this service, so reading them back is a verification — a wallet cannot award
// itself an identifier by editing anything.
// ---------------------------------------------------------------------------
// The nonces a set of proofs quoted, spent together: one Credential Request, one
// c_nonce, however many proofs.
function spendProofNonces(proofJwts) {
  log.debug("Entering spendProofNonces(). " + proofJwts.length + " proof(s).");
  const spent = [];
  proofJwts.forEach(function (proof) {
    let nonce;
    try {
      nonce = (jsonFromB64u(String(proof).split('.')[1]) || {}).nonce;
    } catch (e) {
      // Unreadable proofs never got this far; ignore it rather than throwing
      // after the credential has already been decided on.
      log.debug("spendProofNonces(): a proof payload could not be read: " + e.message);
      return;
    }
    if (nonce && vciNonces.delete(nonce) && spent.indexOf(nonce) === -1) spent.push(nonce);
  });
  log.debug("Leaving spendProofNonces(). Spent " + spent.length + " distinct nonce(s).");
}

function grantedIdentifiers(accessToken) {
  log.debug("Entering grantedIdentifiers().");
  let claims;
  try {
    claims = jwt.verify(accessToken, STS.certPem, { algorithms: ['RS256'] });
  } catch (e) {
    // Not our token (or not valid): nothing was granted by us. The caller still
    // checks the token elsewhere; this only answers "what did we grant".
    log.debug("Leaving grantedIdentifiers(). The token is not one of ours: " + e.message);
    return [];
  }
  const details = claims.authorization_details || [];
  const out = [];
  details.forEach(function (d) {
    (d.credential_identifiers || []).forEach(function (id) { out.push(id); });
  });
  log.debug("Leaving grantedIdentifiers(). " + out.length + " identifier(s).");
  return out;
}

// ---------------------------------------------------------------------------
// Notification ids (OID4VCI section 11).
//
// The issuer returns one per Credential Response so the wallet can report what
// it did with the credential. Remembering them is what lets the notification
// endpoint tell a real id from an invented one — and section 11.3 defines
// invalid_notification_id precisely so that distinction is made.
// ---------------------------------------------------------------------------
const notificationIds = new Map();   // id -> { accessToken, expires, event }

function newNotificationId(accessToken) {
  log.debug("Entering newNotificationId().");
  const id = b64u(crypto.randomBytes(12));
  notificationIds.set(id, { accessToken: accessToken, expires: Date.now() + OFFER_TTL_MS, event: null });
  const now = Date.now();
  notificationIds.forEach(function (v, k) { if (v.expires < now) notificationIds.delete(k); });
  log.debug("Leaving newNotificationId(). " + id);
  return id;
}

// ---------------------------------------------------------------------------
// Credential Response encryption (OID4VCI section 10).
//
// The wallet supplies the key and the content encryption algorithm, and gets a
// JWE back instead of JSON. Only what the metadata advertises is accepted —
// advertising an algorithm this then refuses would make the metadata a lie.
// ---------------------------------------------------------------------------
const VCI_ENC_ALG = 'RSA-OAEP-256';
const VCI_ENC_VALUES = ['A128GCM', 'A256GCM'];

function encryptionProblem(encryption) {
  log.debug("Entering encryptionProblem().");
  const jwk = encryption.jwk;
  if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
    log.debug("Leaving encryptionProblem(). The key is unusable.");
    return 'credential_response_encryption.jwk must be an RSA public key; this issuer encrypts with ' +
           VCI_ENC_ALG + '.';
  }
  const alg = jwk.alg || encryption.alg || VCI_ENC_ALG;
  if (alg !== VCI_ENC_ALG) {
    log.debug("Leaving encryptionProblem(). Unsupported alg " + alg);
    return 'This issuer supports alg ' + VCI_ENC_ALG + ' only; "' + alg + '" was requested.';
  }
  if (!encryption.enc) {
    log.debug("Leaving encryptionProblem(). No enc.");
    return 'credential_response_encryption.enc is required (' + VCI_ENC_VALUES.join(' or ') + ').';
  }
  if (VCI_ENC_VALUES.indexOf(encryption.enc) === -1) {
    log.debug("Leaving encryptionProblem(). Unsupported enc " + encryption.enc);
    return 'This issuer supports enc ' + VCI_ENC_VALUES.join(' or ') + '; "' + encryption.enc +
           '" was requested.';
  }
  if (encryption.zip) {
    log.debug("Leaving encryptionProblem(). zip requested.");
    return 'This issuer does not compress responses, so zip cannot be used.';
  }
  log.debug("Leaving encryptionProblem(). The parameters are usable.");
  return "";
}

// A JWE in compact serialization: RSA-OAEP-256 for the content key, AES-GCM for
// the content. Written out by hand rather than with a JOSE library, because
// having the steps visible is the point of a mock.
function encryptToJwe(plaintext, encryption) {
  log.debug("Entering encryptToJwe(). enc=" + encryption.enc);
  const bits = encryption.enc === 'A128GCM' ? 128 : 256;
  const cek = crypto.randomBytes(bits / 8);
  const iv = crypto.randomBytes(12);
  const header = { alg: VCI_ENC_ALG, enc: encryption.enc, typ: 'JWT' };
  if (encryption.jwk.kid) header.kid = encryption.jwk.kid;
  const headerB64 = b64u(Buffer.from(JSON.stringify(header), 'utf8'));

  const publicKey = crypto.createPublicKey({ key: encryption.jwk, format: 'jwk' });
  const encryptedKey = crypto.publicEncrypt({
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, cek);

  const cipher = crypto.createCipheriv('aes-' + bits + '-gcm', cek, iv);
  // The protected header is the additional authenticated data, per RFC 7516.
  cipher.setAAD(Buffer.from(headerB64, 'ascii'));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();

  const compact = [headerB64, b64u(encryptedKey), b64u(iv), b64u(ciphertext), b64u(tag)].join('.');
  log.debug("Leaving encryptToJwe(). " + compact.length + " characters.");
  return compact;
}

// Every Credential Response goes out through here, so the encrypted and plain
// paths cannot drift apart.
function sendCredentialResponse(res, status, payload, encryption) {
  log.debug("Entering sendCredentialResponse(). status=" + status + ", encrypted=" + !!encryption);
  res.set('Cache-Control', 'no-store');
  if (!encryption) {
    res.status(status).type('application/json').send(JSON.stringify(payload));
    log.debug("Leaving sendCredentialResponse(). Sent as JSON.");
    return;
  }
  logArtifact('OID4VCI Credential Response', 'before encryption', payload);
  const jwe = encryptToJwe(JSON.stringify(payload), encryption);
  logArtifact('OID4VCI Credential Response', 'after encryption (JWE compact serialization)', jwe);
  // Section 10: an encrypted response is a JWT, and says so.
  res.status(status).type('application/jwt').send(jwe);
  log.debug("Leaving sendCredentialResponse(). Sent as a JWE.");
}

// The BBS public key the ldp_vc proofs are made with. A BBS key is not a JWK —
// there is no registered kty for BLS12-381 G2 in the JOSE registry — so it is
// published as its raw compressed bytes in multibase base64url, which is what
// the Data Integrity multikey encoding uses and what verificationMethod above
// points at. Served no-store because the key is regenerated on every start.
app.get('/bbs/keys/1', async function (req, res) {
  log.debug("Entering the BBS key endpoint.");
  const keys = await bbsKeyPair();
  res.set('Cache-Control', 'no-store');
  res.set('Access-Control-Allow-Origin', '*');
  res.status(200).type('application/json').send(JSON.stringify({
    id: baseUrlOf(req) + '/bbs/keys/1',
    type: 'Multikey',
    controller: baseUrlOf(req),
    cryptosuite: bbs2023.CRYPTOSUITE,
    publicKeyMultibase: 'u' + bbs2023.bytesToB64u(keys.publicKey)
  }));
  log.debug("Leaving the BBS key endpoint.");
});

app.post('/oid4vci/credential', async function (req, res) {
  log.debug("Entering the OID4VCI credential endpoint.");
  const auth = req.headers['authorization'] || '';
  if (!/^Bearer\s+\S+/i.test(auth)) {
    res.set('WWW-Authenticate', 'Bearer');
    return vciError(res, 401, 'invalid_token', 'A Bearer access token is required.');
  }
  const accessToken = auth.replace(/^Bearer\s+/i, '').trim();

  let body = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  } catch (e) {
    log.error('the credential request body is not JSON: ' + e.message);
    return vciError(res, 400, 'invalid_request', 'The request body is not JSON: ' + e.message);
  }

  // Which credential (OID4VCI section 8.2). Exactly one of the two identifies
  // it, and which one is not the wallet's choice: it depends on whether the
  // token response granted credential_identifiers.
  const granted = grantedIdentifiers(accessToken);
  const identifier = body.credential_identifier;
  const configId = body.credential_configuration_id;
  if (identifier && configId) {
    return vciError(res, 400, 'invalid_credential_request',
      'credential_identifier and credential_configuration_id are mutually exclusive; send one.');
  }
  if (identifier) {
    if (!granted.length) {
      return vciError(res, 400, 'invalid_credential_request',
        'credential_identifier may only be used when the token response granted credential_identifiers ' +
        '(this authorization used a scope, so send credential_configuration_id instead).');
    }
    if (granted.indexOf(identifier) === -1) {
      return vciError(res, 400, 'invalid_credential_request',
        'credential_identifier "' + identifier + '" was not granted by the token response. Granted: ' +
        granted.join(', '));
    }
  } else if (configId) {
    if (granted.length) {
      return vciError(res, 400, 'invalid_credential_request',
        'the token response granted credential_identifiers, so credential_configuration_id MUST NOT be used ' +
        '(OID4VCI section 8.2).');
    }
    if (!VCI_CONFIGS[configId]) {
      return vciError(res, 400, 'unsupported_credential_type',
        'This issuer offers credential_configuration_id ' +
        vciConfigIds().map(function (id) { return '"' + id + '"'; }).join(' and ') + '.');
    }
  } else {
    return vciError(res, 400, 'invalid_credential_request',
      'Name the credential: credential_identifier (when one was granted) or credential_configuration_id.');
  }

  // Which format, decided once. An identifier names its configuration in its own
  // prefix; a configuration id names it directly. Anything else falls back to
  // the SD-JWT configuration, which is what this issuer has always offered.
  const requestedConfigId = identifier
    ? (configIdOfIdentifier(identifier) || VCI_CONFIG_ID)
    : (configId || VCI_CONFIG_ID);
  log.debug("The credential endpoint will issue " + vciFormatOf(requestedConfigId) +
            " (configuration " + requestedConfigId + ").");

  // Encryption of the response is the wallet's call (section 8.2). Checked before
  // any signature work: a request this issuer is going to refuse should not cost
  // the wallet its single-use c_nonce, and "your enc is unsupported" is a more
  // useful answer than "your proof is stale".
  const encryption = body.credential_response_encryption;
  if (encryption) {
    const problem = encryptionProblem(encryption);
    if (problem) {
      log.debug("Leaving the OID4VCI credential endpoint. The encryption parameters were refused.");
      return vciError(res, 400, 'invalid_encryption_parameters', problem);
    }
  }

  // OID4VCI 1.0 sends proofs.jwt[], one entry per key the credential should be
  // bound to; the earlier single-proof form is accepted too, since wallets in
  // the wild still send it. One credential comes back per proof (section 8.3).
  let proofJwts = [];
  if (body.proofs && Array.isArray(body.proofs.jwt) && body.proofs.jwt.length) proofJwts = body.proofs.jwt;
  else if (body.proof && body.proof.jwt) proofJwts = [body.proof.jwt];
  if (!proofJwts.length) {
    return vciError(res, 400, 'invalid_proof', 'A JWT proof of possession is required (proofs.jwt).');
  }
  if (proofJwts.length > VCI_BATCH_SIZE) {
    return vciError(res, 400, 'invalid_credential_request',
      'This issuer accepts at most ' + VCI_BATCH_SIZE + ' proofs in one request ' +
      '(batch_credential_issuance.batch_size); ' + proofJwts.length + ' were sent.');
  }

  let holderJwks = [];
  try {
    holderJwks = proofJwts.map(function (jwt) {
      return verifyProofJwt(jwt, vciMetadata(req).credential_issuer);
    });
  } catch (e) {
    log.error('the proof of possession was refused: ' + e.message);
    return vciError(res, 400, 'invalid_proof', e.message);
  }
  // Every proof in this request quoted the same c_nonce, and it is single use:
  // spend it now that they have all been accepted, so replaying the request is
  // refused while a batch inside one request is not.
  spendProofNonces(proofJwts);
  const holderJwk = holderJwks[0];


  // A deferred issuance (OID4VCI section 8.3 / Appendix H.3): the issuer cannot
  // produce the credential yet, so it answers 202 with a transaction_id and the
  // wallet comes back to the Deferred Credential Endpoint for it. Everything
  // needed to mint the credential is kept here; only the answer is postponed.
  if (deferredAccessTokens.has(accessToken)) {
    deferredAccessTokens.delete(accessToken);
    const transactionId = randomId(16);
    deferredTransactions.set(transactionId, {
      claims: subjectClaimsFrom(accessToken),
      holderJwk: holderJwk,
      holderJwks: holderJwks,
      // The format was chosen in the request that was deferred, not in the one
      // that collects it — the wallet asked for a credential, and postponing
      // the answer must not change which credential it gets.
      configId: requestedConfigId,
      // A deferred response is encrypted with the parameters given in the
      // DEFERRED request, not these — but keeping them means an issuer that
      // decides otherwise still has them. Section 9.2 is explicit that the newly
      // provided ones win.
      encryption: encryption,
      accessToken: accessToken,
      readyAt: Date.now() + DEFERRED_READY_MS,
      expires: Date.now() + OFFER_TTL_MS
    });
    const deferredResponse = { transaction_id: transactionId, interval: DEFERRED_INTERVAL_S };
    logArtifact('OID4VCI Credential Response', 'deferred', deferredResponse);
    res.set('Cache-Control', 'no-store');
    res.status(202).type('application/json').send(JSON.stringify(deferredResponse));
    log.debug("Leaving the OID4VCI credential endpoint. Deferred as " + transactionId +
              ", ready in " + DEFERRED_READY_MS + "ms.");
    return;
  }

  // One credential per key the wallet proved possession of.
  const claims = subjectClaimsFrom(accessToken);
  const issuerId = vciMetadata(req).credential_issuer;
  const issued = await Promise.all(holderJwks.map(function (jwk) {
    return buildCredentialFor(requestedConfigId, claims, jwk, issuerId);
  }));
  const response = {
    credentials: issued.map(function (b) { return { credential: b.credential }; }),
    notification_id: newNotificationId(accessToken)
  };
  logArtifact('OID4VCI Credential Response', 'as returned', response);
  sendCredentialResponse(res, 200, response, encryption);
  log.debug("Leaving the OID4VCI credential endpoint. Issued " + issued.length + " " +
            vciFormatOf(requestedConfigId) + " credential(s), " + issued[0].disclosures.length +
            " disclosure(s) each" + (encryption ? ", encrypted to the wallet's key" : "") + ".");
});

// The Deferred Credential Endpoint (OID4VCI section 9). 202 with the same
// transaction_id while the issuance is still "in progress", 200 with the
// credential once it is ready, and invalid_transaction_id for a transaction
// this issuer never made or has already handed over.
app.post('/oid4vci/deferred_credential', async function (req, res) {
  log.debug("Entering the OID4VCI deferred credential endpoint.");
  const auth = req.headers['authorization'] || '';
  if (!/^Bearer\s+\S+/i.test(auth)) {
    res.set('WWW-Authenticate', 'Bearer');
    log.debug("Leaving the OID4VCI deferred credential endpoint. No access token.");
    return vciError(res, 401, 'invalid_token', 'A Bearer access token is required.');
  }

  let body = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  } catch (e) {
    log.error('the deferred credential request body is not JSON: ' + e.message);
    log.debug("Leaving the OID4VCI deferred credential endpoint. Unreadable body.");
    return vciError(res, 400, 'invalid_request', 'The request body is not JSON: ' + e.message);
  }

  const transactionId = String(body.transaction_id || '');
  const record = deferredTransactions.get(transactionId);
  if (!record || record.expires < Date.now()) {
    deferredTransactions.delete(transactionId);
    log.debug("Leaving the OID4VCI deferred credential endpoint. No such transaction.");
    return vciError(res, 400, 'invalid_transaction_id',
      'That transaction_id was not issued by this Credential Issuer, or it has already been used.');
  }

  if (Date.now() < record.readyAt) {
    const pending = { transaction_id: transactionId, interval: DEFERRED_INTERVAL_S };
    logArtifact('OID4VCI Deferred Credential Response', 'still pending', pending);
    res.set('Cache-Control', 'no-store');
    res.status(202).type('application/json').send(JSON.stringify(pending));
    log.debug("Leaving the OID4VCI deferred credential endpoint. Still " +
              (record.readyAt - Date.now()) + "ms to go.");
    return;
  }

  // Ready. The transaction_id MUST be invalidated once the credential has been
  // obtained, so a second poll with it is an error rather than a second copy.
  deferredTransactions.delete(transactionId);
  const holderKeys = record.holderJwks || [record.holderJwk];
  const issuerId = vciMetadata(req).credential_issuer;
  // The format the DEFERRED request asked for, not a fresh choice: see the note
  // where it was recorded.
  const deferredConfigId = record.configId || VCI_CONFIG_ID;
  const issued = await Promise.all(holderKeys.map(function (jwk) {
    return buildCredentialFor(deferredConfigId, record.claims, jwk, issuerId);
  }));
  const response = {
    credentials: issued.map(function (b) { return { credential: b.credential }; }),
    notification_id: newNotificationId(record.accessToken)
  };
  logArtifact('OID4VCI Deferred Credential Response', 'as returned', response);
  sendCredentialResponse(res, 200, response, record.encryption);
  log.debug("Leaving the OID4VCI deferred credential endpoint. Issued " + issued.length + " " +
            vciFormatOf(deferredConfigId) + " credential(s).");
});

// The Notification Endpoint (OID4VCI section 11): the wallet reports what it did
// with a credential this issuer issued.
//
// It used to answer 204 to anything at all, which made it useless — a wallet
// could not tell a notification that was understood from one that was ignored,
// and the suite could not tell whether it had sent a valid one. Now the id has
// to be one this issuer handed out and the event one of the three the spec
// defines.
const NOTIFICATION_EVENTS = ['credential_accepted', 'credential_failure', 'credential_deleted'];

app.post('/oid4vci/notification', function (req, res) {
  log.debug("Entering the OID4VCI notification endpoint.");
  const auth = req.headers['authorization'] || '';
  if (!/^Bearer\s+\S+/i.test(auth)) {
    res.set('WWW-Authenticate', 'Bearer');
    log.debug("Leaving the OID4VCI notification endpoint. No access token.");
    return vciError(res, 401, 'invalid_token', 'A Bearer access token is required.');
  }

  let body = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  } catch (e) {
    log.error('the notification body is not JSON: ' + e.message);
    log.debug("Leaving the OID4VCI notification endpoint. Unreadable body.");
    return vciError(res, 400, 'invalid_notification_request',
      'The request body is not JSON: ' + e.message);
  }

  const id = String(body.notification_id || '');
  const event = String(body.event || '');
  const record = notificationIds.get(id);
  if (!record || record.expires < Date.now()) {
    notificationIds.delete(id);
    log.debug("Leaving the OID4VCI notification endpoint. No such notification_id.");
    return vciError(res, 400, 'invalid_notification_id',
      'That notification_id was not issued by this Credential Issuer, or it has expired.');
  }
  if (NOTIFICATION_EVENTS.indexOf(event) === -1) {
    log.debug("Leaving the OID4VCI notification endpoint. Unknown event: " + event);
    return vciError(res, 400, 'invalid_notification_request',
      'event must be one of ' + NOTIFICATION_EVENTS.join(', ') + '; got "' + event + '".');
  }

  record.event = event;
  record.description = body.event_description || '';
  record.notifiedAt = new Date().toISOString();
  logArtifact('OID4VCI Notification', 'as received', {
    notification_id: id, event: event, event_description: record.description
  });
  // Section 11.2: 204, no body.
  res.status(204).end();
  log.debug("Leaving the OID4VCI notification endpoint. Recorded " + event + " for " + id + ".");
});

// What this issuer was told about a credential. Not part of OID4VCI — it exists
// so a test can check that a notification actually arrived and was understood,
// rather than trusting a 204.
app.get('/oid4vci/notification/:id', function (req, res) {
  log.debug("Entering the notification inspection endpoint. id=" + req.params.id);
  const record = notificationIds.get(String(req.params.id));
  if (!record) {
    log.debug("Leaving the notification inspection endpoint. Unknown id.");
    return vciError(res, 404, 'invalid_notification_id', 'No such notification_id.');
  }
  res.status(200).type('application/json').send(JSON.stringify({
    notification_id: req.params.id,
    event: record.event,
    event_description: record.description || '',
    notified_at: record.notifiedAt || null
  }));
  log.debug("Leaving the notification inspection endpoint.");
});

// ===========================================================================
// OpenID for Verifiable Presentations (OID4VP 1.0) — mock Verifier
//
// The other half of the SD-JWT VC story: the issuance flow above puts a
// credential in a wallet, and this is the Verifier that asks for part of it.
//
//   GET  /oid4vp/verifier          the Verifier's web page (where a
//                                  presentation starts, same device)
//   GET  /oid4vp/start             builds an Authorization Request and either
//                                  sends the browser to the wallet with it or
//                                  displays it as a QR code (cross device)
//   GET  /oid4vp/request/:id       the signed Request Object, fetched by
//                                  reference (RFC 9101 / OID4VP request_uri)
//   POST /oid4vp/response          the Response URI: response_mode direct_post,
//                                  where the vp_token arrives and is VERIFIED
//   GET  /oid4vp/result/:state     non-spec: the verdict, so the wallet page and
//                                  the tests can read what the Verifier decided
//   GET  /oid4vp/done              the Verifier's "thank you" page
//
// What it checks is the whole point, so it checks properly (RFC 9901 section 7.3
// plus OID4VP's rules for the Key Binding JWT):
//
//   * the presentation is an SD-JWT+KB: <Issuer-signed JWT>~<Disclosure>*~<KB-JWT>
//   * the Issuer-signed JWT verifies against the issuer's key, and its typ is an
//     SD-JWT VC media type
//   * every Disclosure presented hashes to a digest in _sd — a Disclosure the
//     issuer never signed is the forgery this catches
//   * the KB-JWT has typ kb+jwt, an alg that is not none, and verifies against
//     the cnf key IN THE CREDENTIAL — key binding means nothing if the presenter
//     may nominate the key
//   * its sd_hash equals the hash of exactly the bytes presented, so disclosures
//     cannot be added or removed after it was signed
//   * its nonce is the nonce from THIS request (replay) and its aud is this
//     Verifier's Client Identifier (an honest presentation to someone else is
//     not a presentation to us)
//   * the credential is inside its validity window, and every claim the DCQL
//     query asked for is actually there
// ===========================================================================
const VP_CLIENT_ID = process.env.OID4VP_CLIENT_ID || 'sts-mock-verifier';
const VP_WALLET_URL = process.env.OID4VP_WALLET_URL || WALLET_BASE_URL;
const VP_TTL_MS = 10 * 60 * 1000;
// How old a Key Binding JWT may be. It is signed for one presentation, so this is
// short on purpose.
const VP_KB_MAX_AGE_S = Number(process.env.OID4VP_KB_MAX_AGE_S || 600);
// The claims this Verifier asks for: enough to show selective disclosure doing
// its job — it wants two of the six claims the credential can carry.
const VP_REQUESTED_CLAIMS = (process.env.OID4VP_CLAIMS || 'given_name,family_name').split(',');
const VP_DCQL_ID = 'identity_credential';

// state -> { id, nonce, state, responseMode, clientId, requestObject, dcql,
//            expires, verdict }
const vpTransactions = new Map();
// id -> state, so a Request Object fetched by reference can find its transaction.
const vpRequests = new Map();

function sweepVpTransactions() {
  const now = Date.now();
  vpTransactions.forEach(function (v, k) {
    if (v.expires < now) {
      vpRequests.delete(v.id);
      vpTransactions.delete(k);
    }
  });
}

// The DCQL query (OID4VP section 6): which credential, of which format, with
// which claims. `claims` is what makes this a selective-disclosure request — the
// Verifier names the paths it needs and has no way to ask for "everything".
// The DCQL credential query, which differs by format in two ways that matter.
//
// How the credential is IDENTIFIED: an SD-JWT VC by its vct, a W3C VC by its
// type array — hence `vct_values` against `type_values`, and note type_values
// is an array OF ARRAYS (each entry is a complete type set that would satisfy
// the query).
//
// Where the CLAIMS live: an SD-JWT VC keeps them at the top level of the
// payload, a W3C VC under credentialSubject — so the same claim is asked for as
// ["given_name"] in one format and ["credentialSubject","given_name"] in the
// other. Getting that path wrong does not fail loudly; it asks for a claim that
// is not there and the presentation looks like it withheld something.
function vpDcqlQuery(format) {
  log.debug("Entering vpDcqlQuery(). format=" + (format || 'dc+sd-jwt'));
  if (format === 'ldp_vc') {
    // A W3C credential identified by its type array, like jwt_vc_json — what
    // differs is how it is SECURED, not how it is named.
    const ldp = {
      id: VP_DCQL_ID,
      format: 'ldp_vc',
      meta: { type_values: [VCI_JWT_TYPES] },
      claims: VP_REQUESTED_CLAIMS.map(function (name) {
        return { path: ['credentialSubject', name] };
      })
    };
    const ldpQuery = { credentials: [ldp] };
    logArtifact('OID4VP DCQL query', 'as built (ldp_vc)', ldpQuery);
    log.debug("Leaving vpDcqlQuery(). ldp_vc, " + VP_REQUESTED_CLAIMS.length + " claim(s).");
    return ldpQuery;
  }
  const jwtVcJson = format === 'jwt_vc_json';
  const credential = jwtVcJson
    ? {
        id: VP_DCQL_ID,
        format: 'jwt_vc_json',
        meta: { type_values: [VCI_JWT_TYPES] },
        claims: VP_REQUESTED_CLAIMS.map(function (name) {
          return { path: ['credentialSubject', name] };
        })
      }
    : {
        id: VP_DCQL_ID,
        format: 'dc+sd-jwt',
        meta: { vct_values: [VCI_VCT] },
        claims: VP_REQUESTED_CLAIMS.map(function (name) { return { path: [name] }; })
      };
  const query = { credentials: [credential] };
  logArtifact('OID4VP DCQL query', 'as built', query);
  log.debug("Leaving vpDcqlQuery(). " + VP_REQUESTED_CLAIMS.length + " claim(s) requested as " +
            credential.format + ".");
  return query;
}

// One Authorization Request, in the two shapes this mock offers:
//
//   by value      client_id uses the redirect_uri prefix, so the request needs no
//                 signature — and cannot have one, because the Wallet has no way
//                 to obtain a key for a client identified only by a URL
//                 (OID4VP section 5.10).
//   by reference  a pre-registered client_id and a SIGNED Request Object at
//                 request_uri, verifiable against this service's published JWKS.
function buildVpRequest(req, opts) {
  log.debug("Entering buildVpRequest(). byReference=" + !!opts.byReference +
            ", format=" + (opts.format || 'dc+sd-jwt'));
  const base = baseUrlOf(req);
  const responseUri = base + '/oid4vp/response';
  const id = randomId(16);
  const nonce = randomId(18);
  const state = randomId(18);
  const clientId = opts.byReference ? VP_CLIENT_ID : ('redirect_uri:' + responseUri);
  const request = {
    client_id: clientId,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: responseUri,
    nonce: nonce,
    state: state,
    dcql_query: vpDcqlQuery(opts.format),
    client_metadata: {
      client_name: 'Mock Verifier (bar door)',
      // Both formats are advertised whichever one this request asks for: this is
      // what the Verifier CAN accept, not what it wants this time — the DCQL
      // query is what says that.
      vp_formats_supported: {
        'dc+sd-jwt': { 'sd-jwt_alg_values': ['RS256', 'ES256'], 'kb-jwt_alg_values': ['ES256'] },
        'jwt_vc_json': { alg_values: ['RS256', 'ES256'] },
        'ldp_vc': { cryptosuites: ['bbs-2023'] }
      }
    }
  };
  const record = {
    id: id, nonce: nonce, state: state, clientId: clientId,
    responseMode: 'direct_post', request: request, byReference: !!opts.byReference,
    // Which format this Verifier asked for. The response is verified against
    // THIS, not against whatever shape happens to turn up, so a wallet that
    // answers a jwt_vc_json query with an SD-JWT is refused rather than quietly
    // accepted by the other code path.
    format: opts.format === 'jwt_vc_json' ? 'jwt_vc_json'
          : opts.format === 'ldp_vc' ? 'ldp_vc'
          : 'dc+sd-jwt',
    expires: Date.now() + VP_TTL_MS, verdict: null
  };
  logArtifact('OID4VP Authorization Request', 'as built', request);
  if (opts.byReference) {
    // RFC 9101: the Request Object is a signed JWT. iss/aud are the client and
    // the wallet; the wallet checks the signature against the client's key,
    // which for a pre-registered client it has out of band — here, this
    // service's JWKS.
    const payload = Object.assign({
      iss: clientId,
      aud: 'https://self-issued.me/v2',
      iat: nowSec(),
      exp: nowSec() + Math.floor(VP_TTL_MS / 1000)
    }, request);
    record.requestObject = signJwt(Object.assign({ typ: 'oauth-authz-req+jwt' }, payload));
    logArtifact('OID4VP Request Object', 'after signing', record.requestObject);
    vpRequests.set(id, state);
  }
  vpTransactions.set(state, record);
  sweepVpTransactions();
  log.debug("Leaving buildVpRequest(). state=" + state + ", nonce=" + nonce);
  return record;
}

// The query the wallet is handed: by value it carries the whole request, by
// reference only client_id and request_uri (OID4VP section 5.2).
function vpRequestQuery(req, record) {
  log.debug("Entering vpRequestQuery().");
  const base = baseUrlOf(req);
  const params = record.byReference
    ? { client_id: record.clientId, request_uri: base + '/oid4vp/request/' + record.id,
        request_uri_method: 'get' }
    : {
        client_id: record.clientId,
        response_type: record.request.response_type,
        response_mode: record.request.response_mode,
        response_uri: record.request.response_uri,
        nonce: record.nonce,
        state: record.state,
        dcql_query: JSON.stringify(record.request.dcql_query),
        client_metadata: JSON.stringify(record.request.client_metadata)
      };
  const query = Object.keys(params)
    .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); })
    .join('&');
  log.debug("Leaving vpRequestQuery(). " + Object.keys(params).length + " parameter(s).");
  return query;
}

// The Verifier's own web page — where a same-device presentation starts.
app.get('/oid4vp/verifier', function (req, res) {
  log.debug("Entering the verifier web page.");
  const base = baseUrlOf(req);
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>The Bar Door — are you over 21?</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
    'p{line-height:1.5;color:#333}a.cta{display:inline-block;margin-top:14px;margin-right:10px;padding:10px 16px;' +
    'border-radius:6px;background:#12107c;color:#fff;text-decoration:none;font-weight:600}' +
    'a.cta.secondary{background:#fff;color:#12107c;border:1px solid #12107c}' +
    'p.alt{margin-top:20px;font-size:.92em;color:#555}' +
    '.meta{margin-top:22px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>The Bar Door</h1>' +
    '<p>We need to see that you are who you say you are — but only that. Present the ' +
    '<code>' + xmlEscape(VP_REQUESTED_CLAIMS.join(', ')) + '</code> claim(s) from a credential of type ' +
    '<code>' + xmlEscape(VCI_VCT) + '</code>, and nothing else.</p>' +
    '<p><a class="cta" id="present_by_value" href="/oid4vp/start">Present your credential</a>' +
    '<a class="cta secondary" id="present_by_reference" href="/oid4vp/start?by=reference">' +
    'Present it (signed request by reference)</a></p>' +
    '<p class="alt">Wallet on another device?<br>' +
    '<a class="cta secondary" id="present_cross_device" href="/oid4vp/start?mode=cross-device">' +
    'Show a QR code (cross-device)</a></p>' +
    '<p class="alt">Holding a <code>jwt_vc_json</code> credential instead? That format has no selective ' +
    'disclosure, so presenting it hands over every claim it carries.<br>' +
    '<a class="cta secondary" id="present_jwt_vc_json" href="/oid4vp/start?format=jwt_vc_json">' +
    'Present a JWT VC</a></p>' +
    '<div class="meta">This is the Verifier in OID4VP. It builds an Authorization Request with ' +
    '<code>response_type=vp_token</code>, a <code>dcql_query</code> naming the claims above, a fresh ' +
    '<code>nonce</code>, and <code>response_mode=direct_post</code> — so your wallet POSTs the presentation ' +
    'to <code>' + xmlEscape(base) + '/oid4vp/response</code> rather than putting it in a URL. The wallet is at ' +
    '<code>' + xmlEscape(VP_WALLET_URL) + '</code>.</div>' +
    '</div></body></html>\n';
  res.status(200).type('text/html').send(page);
  log.debug("Leaving the verifier web page.");
});

// The link on that page: build the request and hand it to the wallet.
app.get('/oid4vp/start', function (req, res) {
  log.debug("Entering the presentation start endpoint. mode=" + (req.query.mode || 'same-device') +
            ", format=" + (req.query.format || 'dc+sd-jwt'));
  const byReference = String(req.query.by || '') === 'reference';
  const mode = String(req.query.mode || 'same-device');
  // Which credential format to ask for. Anything unrecognised falls back to
  // dc+sd-jwt, which is what this Verifier has always asked for.
  const requested = String(req.query.format || '');
  const format = requested === 'jwt_vc_json' ? 'jwt_vc_json'
               : requested === 'ldp_vc' ? 'ldp_vc'
               : 'dc+sd-jwt';
  const record = buildVpRequest(req, { byReference: byReference, format: format });
  const query = vpRequestQuery(req, record);
  const wallet = String(req.query.wallet || VP_WALLET_URL).replace(/\/+$/, '') +
                 '/vc-presentation-1.html';

  if (mode !== 'cross-device') {
    // Same device: the browser IS the wallet's user agent, so send it there.
    res.redirect(302, wallet + '?' + query);
    log.debug("Leaving the presentation start endpoint. Redirected to the wallet.");
    return;
  }
  // Cross device: display the request for the wallet on the other device to
  // scan, as the openid4vp URI a wallet registers for.
  renderVpQrPage(res, {
    base: baseUrlOf(req),
    requestUri: 'openid4vp://?' + query,
    walletUrl: wallet + '?' + query,
    record: record
  });
  log.debug("Leaving the presentation start endpoint. Displayed a QR code.");
});

// The Verifier's screen in a cross-device presentation.
function renderVpQrPage(res, opts) {
  log.debug("Entering renderVpQrPage().");
  qrcode.toDataURL(opts.requestUri, { errorCorrectionLevel: 'M', margin: 2, width: 320 })
    .then(function (dataUrl) {
      const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
        '<title>The Bar Door — scan to present</title><style>' +
        'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
        'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
        '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
        'box-shadow:0 6px 24px rgba(0,0,0,.08);text-align:center}h1{font-size:1.25em;margin:0 0 6px}' +
        'p{line-height:1.5;color:#333}img.qr{margin:14px auto;display:block;border:1px solid #eee;border-radius:8px}' +
        '.uri{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.72em;' +
        'color:#555;background:#fafafa;border:1px solid #eee;border-radius:6px;padding:8px;text-align:left}' +
        '.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777;text-align:left}' +
        'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
        '</style></head><body><div class="card">' +
        '<h1>Scan this with your wallet</h1>' +
        '<p>Your wallet will show you exactly which claims we are asking for before anything is sent.</p>' +
        '<img class="qr" id="request_qr" alt="OID4VP Authorization Request QR code" src="' + dataUrl + '">' +
        '<div class="uri" id="request_uri">' + xmlEscape(opts.requestUri) + '</div>' +
        '<div class="meta">OID4VP cross-device flow. The wallet is on your other device, so it cannot be ' +
        'redirected — it reads the request from this code and POSTs the presentation straight back to us ' +
        '(<code>response_mode=direct_post</code>). The <code>nonce</code> in the request is what stops a ' +
        'presentation from being replayed. If your wallet is on this device, ' +
        '<a id="open_in_wallet" href="' + xmlEscape(opts.walletUrl) + '">open it here</a>.' +
        '</div></div></body></html>\n';
      res.status(200).type('text/html').send(page);
      log.debug("Leaving renderVpQrPage().");
    })
    .catch(function (e) {
      log.error("could not render the presentation QR code: " + e.message);
      res.status(500).type('text/plain').send('Could not render the Authorization Request QR code: ' + e.message);
    });
}

// The Request Object, fetched by reference (request_uri). Signed, and served with
// the media type RFC 9101 defines for it.
app.get('/oid4vp/request/:id', function (req, res) {
  log.debug("Entering the request object endpoint. id=" + req.params.id);
  const state = vpRequests.get(String(req.params.id));
  const record = state ? vpTransactions.get(state) : null;
  if (!record || !record.requestObject) {
    log.debug("Leaving the request object endpoint. No such request.");
    return oauthError(res, 404, 'invalid_request', 'No such Request Object.');
  }
  res.status(200).type('application/oauth-authz-req+jwt').send(record.requestObject);
  log.debug("Leaving the request object endpoint. Served a signed Request Object.");
});
// ---------------------------------------------------------------------------
// Verifying a presentation (RFC 9901 section 7.3, plus OID4VP's rules for the
// Key Binding JWT).
//
// Every check is recorded with its own verdict rather than collapsed into one
// boolean: "the presentation was refused" is not a useful answer to a wallet
// developer, and a debugger's job is to say WHICH rule was broken.
// ---------------------------------------------------------------------------
function vpCheck(checks, name, ok, detail) {
  checks.push({ name: name, ok: !!ok, detail: detail });
  log.debug("vpCheck(): " + name + " -> " + (ok ? "OK" : "FAILED") + " (" + detail + ")");
  return !!ok;
}

// base64url(hash) of the US-ASCII of everything before the KB-JWT, which is what
// sd_hash has to be (RFC 9901 section 4.3.1).
function sdHashOf(presentedWithoutKb, sdAlg) {
  const alg = String(sdAlg || 'sha-256').toLowerCase();
  const nodeAlg = { 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512' }[alg];
  if (!nodeAlg) return null;
  return b64u(crypto.createHash(nodeAlg).update(presentedWithoutKb, 'ascii').digest());
}

// A W3C Verifiable Presentation secured as a JWT, carrying a jwt_vc_json
// credential (OID4VP with format jwt_vc_json).
//
// The checks are the same QUESTIONS the SD-JWT path asks, answered against a
// different artefact — which is the point of running both formats through this
// workflow:
//
//   who signed the credential          the issuer's key, as before
//   is it still valid                  nbf/exp, as before
//   is the holder the one it was bound to
//                                      here the VP JWT's signature against the
//                                      credential's cnf.jwk, where an SD-JWT
//                                      uses a Key Binding JWT
//   is this presentation fresh and for us
//                                      nonce and aud, as before — but they are
//                                      claims of the VP JWT, not of a KB-JWT
//   what was disclosed                 everything in credentialSubject, because
//                                      this format cannot withhold anything
//
// There is deliberately no sd_hash equivalent: an SD-JWT's KB-JWT commits to the
// exact bytes presented because a presentation can be a SUBSET. A VP JWT signs
// over the whole credential it embeds, so the commitment is the signature.
// A bbs-2023 derived proof (OID4VP format ldp_vc).
//
// The same questions as the other two formats, asked of a very different
// artefact. There is no issuer signature to check on what arrives — a derived
// proof IS the signature, re-randomised — so "did the issuer sign this" and "is
// this the holder presenting it" collapse into one check.
//
// SHAPE NOTE, a stated simplification: a full bbs-2023 presentation
// reconstructs a JSON-LD document from the disclosed statements. This mock is
// handed the statements and their indexes directly, beside the proof and the
// issuer's proof options. Everything cryptographic is real — the proof is
// verified against this service's BBS key over exactly those statements, with
// this request's nonce as the presentation header — but another verifier would
// expect a document.
async function verifyLdpVc(presentation, record) {
  log.debug("Entering verifyLdpVc().");
  const checks = [];
  const result = { ok: false, checks, claims: {}, disclosed: [], vct: '', sub: '', extraDisclosed: [] };

  let payload;
  try {
    payload = typeof presentation === 'string' ? JSON.parse(presentation) : presentation;
  } catch (e) {
    vpCheck(checks, 'Format', false, 'an ldp_vc presentation here is a JSON object carrying the ' +
      'derived proof and the statements it discloses; this is not JSON: ' + e.message);
    return result;
  }
  const proofBytes = payload.proof ? bbs2023.b64uToBytes(payload.proof) : null;
  const statements = [].concat(payload.disclosedStatements || []);
  const indexes = [].concat(payload.disclosedIndexes || []);
  if (!proofBytes || !statements.length || statements.length !== indexes.length) {
    vpCheck(checks, 'Format', false,
      'expected proof, disclosedStatements and disclosedIndexes of equal length; got ' +
      statements.length + ' statement(s) and ' + indexes.length + ' index(es).');
    return result;
  }
  vpCheck(checks, 'Format', true,
    'a bbs-2023 derived proof disclosing ' + statements.length + ' canonical statement(s).');

  const keys = await bbsKeyPair();
  let header;
  try {
    header = await bbs2023.headerFor(payload.proofOptions || {});
  } catch (e) {
    vpCheck(checks, 'Proof options', false, 'could not be canonicalized: ' + e.message);
    return result;
  }
  vpCheck(checks, 'Proof options', true, 'canonicalized to the header the base proof was bound to.');

  const ok = await bbs2023.verifyDerived(keys.publicKey, proofBytes, header,
    Buffer.from(String(record.nonce), 'utf8'), statements, indexes);
  vpCheck(checks, 'Derived proof', ok, ok
    ? "verifies against this issuer's BBS key over exactly the statements disclosed, and against this " +
      "request's nonce — so it was derived for THIS request and cannot be replayed."
    : 'does not verify. Either it was not derived from a credential this issuer signed, the statements ' +
      'do not match what was proved, or it was derived against a different nonce.');

  statements.forEach(function (line, i) {
    result.claims['statement ' + (indexes[i] + 1)] = String(line).trim();
  });
  result.disclosed = indexes.map(function (i) { return 'statement ' + (i + 1); });
  result.ok = checks.every(function (c) { return c.ok; });
  log.debug("Leaving verifyLdpVc(). " + (result.ok ? 'accepted' : 'REFUSED'));
  return result;
}

function verifyVpJwt(presentation, record) {
  log.debug("Entering verifyVpJwt().");
  logArtifact('OID4VP Verifiable Presentation (jwt_vc_json)', 'as received', presentation);
  const checks = [];
  const result = { ok: false, checks: checks, claims: {}, disclosed: [], vct: '', sub: '',
                   extraDisclosed: [] };

  // The tilde test comes FIRST, and it has to. An SD-JWT Combined Serialization
  // is <JWT>~<Disclosure>*~ — splitting THAT on "." also yields three parts,
  // because the tildes hang off the end of the signature segment. So a
  // part-count check alone lets an SD-JWT through to be reported as an
  // undecodable JWT, which names the wrong problem: the wallet answered in the
  // wrong FORMAT, and that is what it needs to be told.
  const raw = String(presentation || '');
  if (raw.indexOf('~') >= 0) {
    vpCheck(checks, 'Format', false,
      'this is an SD-JWT Combined Serialization (it contains "~"), but this request asked for ' +
      'jwt_vc_json, whose presentation is a Verifiable Presentation JWT.');
    log.debug("Leaving verifyVpJwt(). An SD-JWT answered a jwt_vc_json query.");
    return result;
  }
  const vpParts = raw.split('.');
  if (vpParts.length !== 3) {
    vpCheck(checks, 'Format', false,
      'a jwt_vc_json presentation is a Verifiable Presentation JWT (three parts); this has ' +
      vpParts.length + ' part(s).');
    log.debug("Leaving verifyVpJwt(). Not a JWS.");
    return result;
  }
  let vpHeader = {}, vpPayload = {};
  try {
    vpHeader = jsonFromB64u(vpParts[0]);
    vpPayload = jsonFromB64u(vpParts[1]);
  } catch (e) {
    vpCheck(checks, 'Format', false, 'the presentation JWT cannot be decoded: ' + e.message);
    return result;
  }
  const vp = vpPayload.vp || {};
  const embedded = [].concat(vp.verifiableCredential || []);
  if (!embedded.length || typeof embedded[0] !== 'string') {
    vpCheck(checks, 'Format', false,
      'the vp claim carries no verifiableCredential; a jwt_vc_json presentation embeds the credential JWT there.');
    log.debug("Leaving verifyVpJwt(). No credential inside.");
    return result;
  }
  vpCheck(checks, 'Format', true,
    'Verifiable Presentation JWT carrying ' + embedded.length + ' credential(s); no Disclosures, because ' +
    'jwt_vc_json has no selective disclosure.');

  // --- the credential inside -----------------------------------------------
  const vcJwt = embedded[0];
  let vcHeader = {}, vcPayload = {};
  try {
    vcHeader = jsonFromB64u(vcJwt.split('.')[0]);
    vcPayload = jsonFromB64u(vcJwt.split('.')[1]);
  } catch (e) {
    vpCheck(checks, 'Credential', false, 'the embedded credential cannot be decoded: ' + e.message);
    return result;
  }
  const vc = vcPayload.vc || {};
  const subject = vc.credentialSubject || {};
  result.sub = vcPayload.sub || subject.id || '';

  let issuerSignatureOk = false;
  try {
    jwt.verify(vcJwt, STS.certPem, { algorithms: ['RS256'] });
    issuerSignatureOk = true;
  } catch (e) {
    vpCheck(checks, 'Issuer signature', false, 'does not verify: ' + e.message);
  }
  if (issuerSignatureOk) {
    vpCheck(checks, 'Issuer signature', true, "verifies against the issuer's key (alg " + vcHeader.alg + ').');
  }
  const now = nowSec();
  vpCheck(checks, 'Validity window',
    (!vcPayload.exp || vcPayload.exp > now) && (!vcPayload.nbf || vcPayload.nbf <= now),
    'nbf ' + (vcPayload.nbf || '—') + ', exp ' + (vcPayload.exp || '—') + ', now ' + now + '.');

  const types = [].concat(vc.type || []);
  const wantedTypes = VCI_JWT_TYPES;
  const typesOk = wantedTypes.every(function (t) { return types.indexOf(t) >= 0; });
  vpCheck(checks, 'Credential type', typesOk,
    'type is [' + types.join(', ') + ']; this Verifier asked for [' + wantedTypes.join(', ') + '].');

  // --- holder binding: the VP JWT is signed by the key the credential names --
  const cnfJwk = (vcPayload.cnf || {}).jwk;
  if (!cnfJwk) {
    vpCheck(checks, 'Holder binding', false,
      'the credential carries no cnf.jwk, so nothing says which key may present it.');
  } else {
    let holderOk = false;
    try {
      const holderKey = crypto.createPublicKey({ key: cnfJwk, format: 'jwk' });
      holderOk = crypto.verify(
        vpHeader.alg === 'RS256' ? 'sha256' : null,
        Buffer.from(vpParts[0] + '.' + vpParts[1]),
        vpHeader.alg === 'RS256'
          ? holderKey
          : { key: holderKey, dsaEncoding: 'ieee-p1363' },
        Buffer.from(vpParts[2], 'base64url'));
    } catch (e) {
      vpCheck(checks, 'Holder binding', false, 'the presentation signature could not be checked: ' + e.message);
    }
    if (holderOk) {
      vpCheck(checks, 'Holder binding', true,
        'the presentation JWT is signed by the key the credential is bound to (cnf.jwk, alg ' +
        vpHeader.alg + ').');
    } else {
      vpCheck(checks, 'Holder binding', false,
        'the presentation JWT is NOT signed by the key the credential is bound to (cnf.jwk).');
    }
  }

  // --- freshness and audience ----------------------------------------------
  vpCheck(checks, 'Nonce', vpPayload.nonce === record.nonce,
    'nonce is "' + (vpPayload.nonce || '—') + '"; this request used "' + record.nonce + '".');
  vpCheck(checks, 'Audience', String(vpPayload.aud) === String(record.clientId),
    'aud is "' + vpPayload.aud + '"; this Verifier is "' + record.clientId + '".');

  // --- what arrived ---------------------------------------------------------
  // Everything in credentialSubject came, because this format cannot send less.
  // `id` is the subject identifier rather than a claim, so it is not counted.
  const present = Object.keys(subject).filter(function (k) { return k !== 'id'; });
  present.forEach(function (name) { result.claims[name] = subject[name]; });
  result.disclosed = present;
  const missing = VP_REQUESTED_CLAIMS.filter(function (name) { return present.indexOf(name) < 0; });
  result.extraDisclosed = present.filter(function (name) { return VP_REQUESTED_CLAIMS.indexOf(name) < 0; });
  vpCheck(checks, 'Requested claims', missing.length === 0,
    missing.length
      ? 'missing: ' + missing.join(', ') + '.'
      : 'all ' + VP_REQUESTED_CLAIMS.length + ' requested claim(s) arrived' +
        (result.extraDisclosed.length
          ? ', along with ' + result.extraDisclosed.length + ' this Verifier did not ask for (' +
            result.extraDisclosed.join(', ') + ') — jwt_vc_json cannot withhold them.'
          : '.'));

  result.ok = checks.every(function (c) { return c.ok; });
  log.debug("Leaving verifyVpJwt(). " + (result.ok ? "accepted" : "REFUSED") + ", " +
            checks.filter(function (c) { return !c.ok; }).length + " failed check(s).");
  return result;
}

function verifyPresentation(presentation, record) {
  log.debug("Entering verifyPresentation().");
  logArtifact('OID4VP Verifiable Presentation', 'as received', presentation);
  const checks = [];
  const result = { ok: false, checks: checks, claims: {}, disclosed: [], vct: '', sub: '' };
  const parts = String(presentation || '').split('~');
  if (parts.length < 2) {
    vpCheck(checks, 'Format', false,
      'a presentation is <Issuer-signed JWT>~<Disclosure>*~<KB-JWT>; this has ' + parts.length + ' part(s).');
    log.debug("Leaving verifyPresentation(). Not a Combined Serialization.");
    return result;
  }
  const issuerJwt = parts[0];
  const kbJwt = parts[parts.length - 1];
  const disclosures = parts.slice(1, parts.length - 1).filter(function (d) { return d !== ''; });
  vpCheck(checks, 'Format', true,
    'SD-JWT+KB with ' + disclosures.length + ' Disclosure(s) and a Key Binding JWT.');

  // --- the issuer-signed JWT ------------------------------------------------
  let header = {};
  let payload = {};
  try {
    header = jsonFromB64u(issuerJwt.split('.')[0]);
    payload = jsonFromB64u(issuerJwt.split('.')[1]);
  } catch (e) {
    vpCheck(checks, 'Issuer-signed JWT', false, 'cannot be decoded: ' + e.message);
    log.debug("Leaving verifyPresentation(). Undecodable credential.");
    return result;
  }
  result.vct = payload.vct || '';
  result.sub = payload.sub || '';
  vpCheck(checks, 'Media type (typ)', ['dc+sd-jwt', 'vc+sd-jwt'].indexOf(String(header.typ)) >= 0,
    'typ is "' + header.typ + '".');
  let issuerSignatureOk = false;
  try {
    jwt.verify(issuerJwt, STS.certPem, { algorithms: ['RS256'] });
    issuerSignatureOk = true;
  } catch (e) {
    // Not signed by us — or expired, which jsonwebtoken reports here too. Both
    // are reasons to refuse, and the message says which.
    vpCheck(checks, 'Issuer signature', false, 'does not verify: ' + e.message);
  }
  if (issuerSignatureOk) {
    vpCheck(checks, 'Issuer signature', true, 'verifies against the issuer\'s key (alg RS256).');
  }
  const now = nowSec();
  vpCheck(checks, 'Validity window',
    (!payload.exp || payload.exp > now) && (!payload.nbf || payload.nbf <= now),
    'nbf ' + (payload.nbf || '—') + ', exp ' + (payload.exp || '—') + ', now ' + now + '.');
  vpCheck(checks, 'Credential type (vct)', payload.vct === VCI_VCT,
    'vct is "' + payload.vct + '"; this Verifier asked for "' + VCI_VCT + '".');

  // --- the Disclosures presented -------------------------------------------
  // Every one must hash to a digest the issuer signed. This is the check that
  // catches a Disclosure invented by whoever is presenting.
  const sdAlg = payload._sd_alg || 'sha-256';
  const nodeAlg = { 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512' }[String(sdAlg).toLowerCase()];
  const signedDigests = [];
  (function collect(node) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      node.forEach(function (item) {
        if (item && typeof item === 'object' && typeof item['...'] === 'string') signedDigests.push(item['...']);
        else collect(item);
      });
      return;
    }
    Object.keys(node).forEach(function (k) {
      if (k === '_sd' && Array.isArray(node[k])) node[k].forEach(function (d) { signedDigests.push(d); });
      else if (typeof node[k] === 'object') collect(node[k]);
    });
  })(payload);

  let unmatched = 0;
  disclosures.forEach(function (encoded) {
    let arr = null;
    try {
      arr = JSON.parse(b64uDecode(encoded).toString('utf8'));
    } catch (e) {
      unmatched++;
      log.error('a presented Disclosure is not base64url JSON: ' + e.message);
      return;
    }
    const digest = nodeAlg ? b64u(crypto.createHash(nodeAlg).update(encoded, 'ascii').digest()) : '';
    if (signedDigests.indexOf(digest) === -1) {
      unmatched++;
      log.error('a presented Disclosure hashes to a digest the issuer never signed: ' + digest);
      return;
    }
    if (Array.isArray(arr) && arr.length === 3) {
      result.claims[arr[1]] = arr[2];
      result.disclosed.push(arr[1]);
    }
  });
  vpCheck(checks, 'Disclosure digests', unmatched === 0,
    unmatched === 0
      ? 'all ' + disclosures.length + ' presented Disclosure(s) hash to a digest in _sd.'
      : unmatched + ' presented Disclosure(s) were not signed by the issuer.');

  // The always-visible claims are part of what was presented too.
  Object.keys(payload).forEach(function (k) {
    if (['_sd', '_sd_alg', 'cnf'].indexOf(k) >= 0) return;
    if (!(k in result.claims)) result.claims[k] = payload[k];
  });

  // --- the Key Binding JWT --------------------------------------------------
  let kbHeader = {};
  let kbPayload = {};
  let kbReadable = false;
  try {
    kbHeader = jsonFromB64u(kbJwt.split('.')[0]);
    kbPayload = jsonFromB64u(kbJwt.split('.')[1]);
    kbReadable = kbJwt.split('.').length === 3;
  } catch (e) {
    kbReadable = false;
  }
  if (!kbReadable) {
    vpCheck(checks, 'Key Binding JWT', false,
      'the last element is not a readable three-part JWS, so the presentation has no holder proof at all.');
    result.ok = checks.every(function (c) { return c.ok; });
    log.debug("Leaving verifyPresentation(). No usable KB-JWT.");
    return result;
  }
  logArtifact('OID4VP Key Binding JWT', 'as received', { header: kbHeader, payload: kbPayload });
  vpCheck(checks, 'KB-JWT media type', String(kbHeader.typ) === 'kb+jwt',
    'typ is "' + kbHeader.typ + '"; RFC 9901 section 4.3 requires kb+jwt.');
  vpCheck(checks, 'KB-JWT algorithm', !!kbHeader.alg && kbHeader.alg !== 'none',
    'alg is ' + kbHeader.alg + '.');
  vpCheck(checks, 'KB-JWT nonce', kbPayload.nonce === record.nonce,
    kbPayload.nonce === record.nonce
      ? 'matches the nonce in this Authorization Request.'
      : 'is "' + kbPayload.nonce + '", but this request\'s nonce is "' + record.nonce +
        '" — a presentation made for another request, or replayed.');
  vpCheck(checks, 'KB-JWT audience', kbPayload.aud === record.clientId,
    kbPayload.aud === record.clientId
      ? 'is this Verifier\'s Client Identifier.'
      : 'is "' + kbPayload.aud + '", not "' + record.clientId + '" — this presentation was made for someone else.');
  vpCheck(checks, 'KB-JWT freshness',
    !!kbPayload.iat && Math.abs(now - Number(kbPayload.iat)) <= VP_KB_MAX_AGE_S,
    'iat is ' + kbPayload.iat + ' (' + (kbPayload.iat ? (now - Number(kbPayload.iat)) + 's ago' : 'absent') +
    '); at most ' + VP_KB_MAX_AGE_S + 's is accepted.');

  // sd_hash ties the KB-JWT to exactly these bytes: the issuer-signed JWT and the
  // Disclosures presented, each followed by a tilde.
  const withoutKb = parts.slice(0, parts.length - 1).join('~') + '~';
  const expectedSdHash = sdHashOf(withoutKb, sdAlg);
  vpCheck(checks, 'KB-JWT sd_hash', !!expectedSdHash && kbPayload.sd_hash === expectedSdHash,
    kbPayload.sd_hash === expectedSdHash
      ? 'is the hash of exactly the bytes presented, so no Disclosure was added or removed after it was signed.'
      : 'is "' + kbPayload.sd_hash + '" but these bytes hash to "' + expectedSdHash +
        '" — the presentation was altered after the holder signed it.');

  // The signature must verify against the key the CREDENTIAL names, not one the
  // presenter chose: that is what key binding means.
  const cnfJwk = (payload.cnf && payload.cnf.jwk) || null;
  if (!cnfJwk) {
    vpCheck(checks, 'KB-JWT signature', false,
      'the credential carries no cnf.jwk, so there is no key this presentation could be bound to.');
  } else {
    try {
      const holderKey = crypto.createPublicKey({ key: cnfJwk, format: 'jwk' });
      jwt.verify(kbJwt, holderKey, { algorithms: ['ES256', 'ES384', 'RS256', 'PS256'] });
      vpCheck(checks, 'KB-JWT signature', true,
        'verifies against the cnf key in the credential (' + cnfJwk.kty + ' ' + (cnfJwk.crv || '') + ').');
    } catch (e) {
      vpCheck(checks, 'KB-JWT signature', false,
        'does NOT verify against the cnf key in the credential: ' + e.message);
    }
  }

  // --- did we get what we asked for? ---------------------------------------
  const missing = VP_REQUESTED_CLAIMS.filter(function (name) { return !(name in result.claims); });
  vpCheck(checks, 'Requested claims', missing.length === 0,
    missing.length === 0
      ? 'every claim the DCQL query asked for is present (' + VP_REQUESTED_CLAIMS.join(', ') + ').'
      : 'missing: ' + missing.join(', ') + '.');
  // Not a failure — the holder may disclose more than was asked — but worth
  // saying, because over-disclosure is the thing SD-JWT VC exists to prevent.
  const extra = result.disclosed.filter(function (name) { return VP_REQUESTED_CLAIMS.indexOf(name) === -1; });
  result.extraDisclosed = extra;

  result.ok = checks.every(function (c) { return c.ok; });
  log.debug("Leaving verifyPresentation(). ok=" + result.ok + ", " + checks.length + " check(s), " +
            result.disclosed.length + " disclosed claim(s), " + extra.length + " more than asked for.");
  return result;
}

// The Response URI (OID4VP section 8.2): response_mode direct_post, so the
// Authorization Response arrives as a form POST rather than in a URL.
app.post('/oid4vp/response', async function (req, res) {
  log.debug("Entering the OID4VP response endpoint.");
  const body = parseBody(req);
  const state = String(body.state || '');
  const record = vpTransactions.get(state);
  if (!record) {
    log.debug("Leaving the OID4VP response endpoint. Unknown state.");
    return oauthError(res, 400, 'invalid_request',
      'Unknown or expired state: this Verifier has no such Authorization Request outstanding.');
  }
  if (body.error) {
    // The wallet refused, which is a legitimate answer (section 8.4).
    record.verdict = { ok: false, refused: true, error: String(body.error),
                       errorDescription: String(body.error_description || ''), checks: [], at: new Date().toISOString() };
    res.status(200).type('application/json').send(JSON.stringify({
      redirect_uri: baseUrlOf(req) + '/oid4vp/done?state=' + encodeURIComponent(state)
    }));
    log.debug("Leaving the OID4VP response endpoint. The wallet refused: " + body.error);
    return;
  }

  // vp_token is a JSON object keyed by the DCQL credential query id, each value
  // an array of presentations (section 8.1).
  let presentations = [];
  let tokenShapeOk = true;
  try {
    const parsed = typeof body.vp_token === 'string' ? JSON.parse(body.vp_token) : body.vp_token;
    const forQuery = parsed && parsed[VP_DCQL_ID];
    if (Array.isArray(forQuery)) presentations = forQuery;
    else if (typeof forQuery === 'string') presentations = [forQuery];
    else tokenShapeOk = false;
  } catch (e) {
    log.error('the vp_token is not the JSON object OID4VP defines: ' + e.message);
    tokenShapeOk = false;
  }
  if (!tokenShapeOk || !presentations.length) {
    record.verdict = {
      ok: false, at: new Date().toISOString(),
      checks: [{ name: 'vp_token', ok: false,
                 detail: 'vp_token must be a JSON object keyed by the DCQL credential query id ("' +
                         VP_DCQL_ID + '"), each value an array of presentations.' }]
    };
    res.status(400).type('application/json').send(JSON.stringify({
      error: 'invalid_request',
      error_description: 'vp_token is not the JSON object OID4VP section 8.1 defines.'
    }));
    log.debug("Leaving the OID4VP response endpoint. Malformed vp_token.");
    return;
  }

  // Verified against the format THIS request asked for, so answering a
  // jwt_vc_json query with an SD-JWT (or the reverse) is refused rather than
  // silently handled by the other code path.
  const verified = record.format === 'ldp_vc'
    ? await verifyLdpVc(presentations[0], record)
    : record.format === 'jwt_vc_json'
      ? verifyVpJwt(presentations[0], record)
      : verifyPresentation(presentations[0], record);
  record.verdict = {
    ok: verified.ok,
    at: new Date().toISOString(),
    checks: verified.checks,
    claims: verified.claims,
    disclosed: verified.disclosed,
    extraDisclosed: verified.extraDisclosed || [],
    requested: VP_REQUESTED_CLAIMS,
    vct: verified.vct,
    sub: verified.sub,
    presentation: presentations[0]
  };
  logArtifact('OID4VP verification result', verified.ok ? 'accepted' : 'REFUSED', record.verdict);

  if (!verified.ok) {
    // Section 8.4: an invalid presentation is invalid_request. The failing checks
    // go in the description, because a wallet developer cannot fix "no".
    const failed = verified.checks.filter(function (c) { return !c.ok; });
    res.status(400).type('application/json').send(JSON.stringify({
      error: 'invalid_request',
      error_description: 'The presentation was refused: ' +
        failed.map(function (c) { return c.name + ' — ' + c.detail; }).join(' | ')
    }));
    log.debug("Leaving the OID4VP response endpoint. Refused " + failed.length + " check(s).");
    return;
  }
  res.status(200).type('application/json').send(JSON.stringify({
    redirect_uri: baseUrlOf(req) + '/oid4vp/done?state=' + encodeURIComponent(state)
  }));
  log.debug("Leaving the OID4VP response endpoint. Accepted.");
});

// Not in the spec: the verdict, so the wallet's own page (and the test suite) can
// show what this Verifier decided and why. A real Verifier tells the End-User in
// its own UI; this makes the same information machine-readable.
app.get('/oid4vp/result/:state', function (req, res) {
  log.debug("Entering the presentation result endpoint. state=" + req.params.state);
  const record = vpTransactions.get(String(req.params.state));
  if (!record) {
    log.debug("Leaving the presentation result endpoint. Unknown state.");
    return oauthError(res, 404, 'invalid_request', 'No such presentation.');
  }
  res.set('Access-Control-Allow-Origin', '*');
  res.status(200).type('application/json').send(JSON.stringify({
    state: record.state,
    nonce: record.nonce,
    client_id: record.clientId,
    requested: VP_REQUESTED_CLAIMS,
    dcql_query: record.request.dcql_query,
    received: !!record.verdict,
    verdict: record.verdict
  }));
  log.debug("Leaving the presentation result endpoint. received=" + !!record.verdict);
});

// Where the wallet sends the End-User once the Verifier has answered.
app.get('/oid4vp/done', function (req, res) {
  log.debug("Entering the verifier done page.");
  const record = vpTransactions.get(String(req.query.state || ''));
  const verdict = record && record.verdict;
  const ok = !!(verdict && verdict.ok);
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>The Bar Door — ' + (ok ? 'come on in' : 'not today') + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
    'p{line-height:1.5;color:#333}ul{line-height:1.5}.ok{color:#2e7d32;font-weight:700}' +
    '.bad{color:#b00020;font-weight:700}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>The Bar Door</h1>' +
    (verdict
      ? '<p class="' + (ok ? 'ok' : 'bad') + '" id="verdict">' +
        (ok ? 'Presentation accepted.' : 'Presentation refused.') + '</p>' +
        '<ul id="claims">' + Object.keys(verdict.claims || {}).map(function (k) {
          return '<li><code>' + xmlEscape(k) + '</code>: <code>' +
                 xmlEscape(typeof verdict.claims[k] === 'object'
                   ? JSON.stringify(verdict.claims[k]) : String(verdict.claims[k])) + '</code></li>';
        }).join('') + '</ul>' +
        '<p style="font-size:.85em;color:#666">We asked for <code>' +
        xmlEscape((verdict.requested || []).join(', ')) + '</code> and that is all we know about you.</p>'
      : '<p id="verdict">Nothing has been presented for this request yet.</p>') +
    '</div></body></html>\n';
  res.status(200).type('text/html').send(page);
  log.debug("Leaving the verifier done page. ok=" + ok);
});



// ===========================================================================
// The endpoints the RFC 8414 metadata advertises.
//
// A dummy authorization server: every endpoint in the metadata document answers,
// and every token it issues is a real RS256 JWT signed with the STS key, so it
// verifies against the JWKS the same document points at (/oauth2/jwks).
//
//   GET  /oauth2/authorize   authorization endpoint (code / implicit / hybrid)
//   POST /oauth2/token       authorization_code, refresh_token, password,
//                            client_credentials, token-exchange
//   POST /oauth2/introspect  RFC 7662
//   POST /oauth2/revoke      RFC 7009
//   *    /oauth2/register    RFC 7591 registration + RFC 7592 management
//   GET  /oauth2/jwks        the signing key (above, with the metadata)
//   GET  /docs /policy /tos  the documents the metadata links to
//
// It authenticates NOBODY: the authorization endpoint issues a code for whoever
// asks (the "user" is the login_hint, or a fixed mock subject), and any client
// secret is accepted. That is the point — it exists so the debugger's panes have
// something complete to talk to, not to enforce anything. What it does do
// properly is the mechanics a client can check: PKCE verification, single-use
// authorization codes, real signatures, honest introspection, and revocation
// that actually takes effect.
// ===========================================================================
// Whoever signs in at the login screen. No password is ever checked; the
// username they type is the identity every token then describes.
function userFor(username) {
  log.debug("Entering userFor(). username=" + username);
  const name = String(username || 'mock-user');
  const user = {
    sub: 'urn:sts-mock:user:' + name,
    username: name,
    preferred_username: name,
    name: name + ' (mock)',
    given_name: name,
    family_name: 'Mock',
    email: name + '@sts-mock.example',
    email_verified: true
  };
  log.debug("Leaving userFor(). sub=" + user.sub);
  return user;
}

const SESSION_COOKIE = 'sts_mock_session';
const SESSION_TTL_MS = 60 * 60 * 1000;
const LOGIN_TTL_MS = 10 * 60 * 1000;
const ACCESS_TOKEN_TTL = 3600;
const REFRESH_TOKEN_TTL = 30 * 24 * 3600;
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

const authzCodes = new Map();       // code -> the authorization request it came from
const sessions = new Map();         // session id -> the signed-in user
const pendingLogins = new Map();    // login id -> the authorization request being interrupted
const revokedJtis = new Set();      // tokens revoked via /oauth2/revoke
const registeredClients = new Map();// client_id -> { metadata, registrationAccessToken }

// Small and called constantly: no entering/leaving logs, they would drown the log.
function nowSec() { return Math.floor(Date.now() / 1000); }
function randomId(bytes) { return b64u(crypto.randomBytes(bytes || 24)); }

// Request bodies arrive as raw text (the SOAP parser takes every content type),
// so form-encoded and JSON are both decoded here.
function parseBody(req) {
  log.debug("Entering parseBody(). content-type=" + (req.headers['content-type'] || '(none)'));
  const raw = typeof req.body === 'string' ? req.body : '';
  const type = String(req.headers['content-type'] || '');
  if (/json/i.test(type)) {
    try {
      const parsed = JSON.parse(raw || '{}');
      log.debug("Leaving parseBody(). Parsed a JSON body.");
      return parsed;
    } catch (e) {
      log.error('the request body is not JSON: ' + e.message);
      log.debug("Leaving parseBody(). Nothing could be parsed.");
      return {};
    }
  }
  const out = {};
  new URLSearchParams(raw).forEach(function (v, k) { out[k] = v; });
  log.debug("Leaving parseBody(). Parsed a form-encoded body with " +
            Object.keys(out).length + " parameter(s).");
  return out;
}

// Client credentials from either client_secret_basic or client_secret_post. No
// secret is ever checked; what matters is which client is being claimed.
function clientFrom(req, body) {
  log.debug("Entering clientFrom().");
  const auth = req.headers['authorization'] || '';
  if (/^Basic\s+/i.test(auth)) {
    try {
      const decoded = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      const client = { client_id: decodeURIComponent(i < 0 ? decoded : decoded.slice(0, i)) };
      log.debug("Leaving clientFrom(). client_secret_basic named " + client.client_id + ".");
      return client;
    } catch (e) {
      log.error('could not read the Basic credential: ' + e.message);
      // Fall through to the form parameter.
    }
  }
  log.debug("Leaving clientFrom(). client_id from the body: " + (body.client_id || '(none)'));
  return { client_id: body.client_id || '' };
}

function oauthError(res, status, error, description) {
  log.debug("Entering oauthError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ error: error, error_description: description }));
  log.debug("Leaving oauthError().");
}

// --- token minting ----------------------------------------------------------
// Every OAuth token this server issues goes through here, so this is where each
// one is recorded: the claim set before it is signed, and the JWT after.
function signJwt(payload) {
  log.debug("Entering signJwt(). typ=" + (payload.typ || '(none)'));
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'before signing',
              { header: { alg: 'RS256', kid: STS.kid }, payload: payload });
  const signed = jwt.sign(payload, STS.privateKeyPem, { algorithm: 'RS256', keyid: STS.kid });
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'after signing', signed);
  log.debug("Leaving signJwt().");
  return signed;
}

function accessToken(base, opts) {
  log.debug("Entering accessToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const payload = {
    iss: base, sub: opts.sub || user.sub, aud: opts.audience || base + '/resource',
    client_id: opts.client_id, scope: opts.scope || '', typ: 'Bearer',
    jti: randomId(16), iat: iat, nbf: iat, exp: iat + ACCESS_TOKEN_TTL,
    username: user.username
  };
  if (opts.act) payload.act = opts.act;
  // OID4VCI section 6.2: when the authorization was expressed as
  // authorization_details, the token response grants credential_identifiers and
  // the Credential Request must use one of them. They ride in the access token
  // so the credential endpoint can verify one without consulting any state — the
  // token is signed, so the wallet cannot award itself an identifier.
  if (opts.authorization_details) payload.authorization_details = opts.authorization_details;
  const token = signJwt(payload);
  log.debug("Leaving accessToken().");
  return token;
}

function refreshToken(base, opts) {
  log.debug("Entering refreshToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const token = signJwt({
    // username travels with the refresh token, so refreshing keeps describing
    // the person who actually signed in.
    iss: base, sub: opts.sub || user.sub, aud: base, client_id: opts.client_id,
    scope: opts.scope || '', typ: 'Refresh', jti: randomId(16), username: user.username,
    iat: iat, nbf: iat, exp: iat + REFRESH_TOKEN_TTL
  });
  log.debug("Leaving refreshToken().");
  return token;
}

// OIDC section 3.1.3.6: at_hash / c_hash are the base64url of the left half of
// the SHA-256 of the ASCII of the token.
function halfHash(value) {
  log.debug("Entering halfHash().");
  const h = crypto.createHash('sha256').update(String(value), 'ascii').digest();
  log.debug("Leaving halfHash().");
  return b64u(h.subarray(0, h.length / 2));
}

function idToken(base, opts) {
  log.debug("Entering idToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const payload = {
    iss: base, sub: opts.sub || user.sub, aud: opts.client_id, typ: 'ID',
    iat: iat, nbf: iat, exp: iat + ACCESS_TOKEN_TTL, auth_time: opts.auth_time || iat,
    azp: opts.client_id, jti: randomId(16),
    name: user.name, given_name: user.given_name, family_name: user.family_name,
    preferred_username: user.preferred_username, email: user.email,
    email_verified: user.email_verified
  };
  if (opts.nonce) payload.nonce = opts.nonce;
  if (opts.access_token) payload.at_hash = halfHash(opts.access_token);
  if (opts.code) payload.c_hash = halfHash(opts.code);
  const token = signJwt(payload);
  log.debug("Leaving idToken().");
  return token;
}

function hasScope(scope, name) {
  return String(scope || '').split(/\s+/).indexOf(name) >= 0;
}

function tokenSet(base, opts) {
  log.debug("Entering tokenSet(). scope=" + (opts.scope || '(none)'));
  const access = accessToken(base, opts);
  const body = {
    access_token: access,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    scope: opts.scope || ''
  };
  if (opts.authorization_details) body.authorization_details = opts.authorization_details;
  if (opts.withRefresh !== false) body.refresh_token = refreshToken(base, opts);
  if (hasScope(opts.scope, 'openid')) {
    body.id_token = idToken(base, Object.assign({}, opts, { access_token: access }));
  }
  log.debug("Leaving tokenSet(). Issued: " + Object.keys(body).join(', '));
  return body;
}

// --- authorization endpoint + login screen ----------------------------------
// A browser flow, so it behaves like one: an unauthenticated request is shown a
// login screen, and only once the user has signed in does the endpoint issue
// the authorization code (or the implicit/hybrid tokens) and redirect back to
// the client.
//
//   GET  /oauth2/authorize   no session  -> the login screen
//                            session     -> issue and redirect to redirect_uri
//   POST /oauth2/login       signs the user in, then redirects BACK to
//                            /oauth2/authorize with the original request, which
//                            then proceeds as normal
//
// No password is checked — the username typed in is simply who the tokens then
// describe. A session cookie means the next authorization request does not
// prompt again; prompt=login forces it to.
function cookiesOf(req) {
  log.debug("Entering cookiesOf().");
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(function (part) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  log.debug("Leaving cookiesOf(). " + Object.keys(out).length + " cookie(s).");
  return out;
}

function sessionOf(req) {
  log.debug("Entering sessionOf().");
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (!id) {
    log.debug("Leaving sessionOf(). No session cookie.");
    return null;
  }
  const session = sessions.get(id);
  if (!session) {
    log.debug("Leaving sessionOf(). The cookie names no session this server knows.");
    return null;
  }
  if (session.expires < Date.now()) {
    sessions.delete(id);
    log.debug("Leaving sessionOf(). The session had expired and was discarded.");
    return null;
  }
  log.debug("Leaving sessionOf(). Signed in as " + session.user.username + ".");
  return session;
}

// The authorization request, as the query string it arrived as. Kept whole so
// the redirect back after login is the same request over again.
function queryString(query, omit) {
  log.debug("Entering queryString().");
  const usp = new URLSearchParams();
  Object.keys(query).forEach(function (k) {
    if (omit && omit.indexOf(k) >= 0) return;
    usp.set(k, query[k]);
  });
  log.debug("Leaving queryString().");
  return usp.toString();
}

function loginPage(base, login, error) {
  log.debug("Entering loginPage(). client_id=" + (login.query.client_id || '(none)') +
            (error ? ", showing an error" : ""));
  const q = login.query;
  const scope = q.scope || '(none requested)';
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Sign in — mock authorization server</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:28px 32px;width:380px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 4px}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}label{display:block;font-size:.85em;font-weight:600;' +
    'margin:12px 0 4px}input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:8px 10px;' +
    'border:1px solid #bbb;border-radius:5px;font-size:1em}.row{display:flex;gap:10px;margin-top:20px}' +
    'button{flex:1;padding:9px 12px;border-radius:5px;border:1px solid #12107c;background:#12107c;color:#fff;' +
    'font-size:.95em;cursor:pointer}button.secondary{background:#fff;color:#12107c}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
    'font-size:.85em;margin-bottom:12px}.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;' +
    'font-size:.75em;color:#777;word-break:break-all}.meta div{margin:2px 0}code{font-family:ui-monospace,' +
    'SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>Sign in</h1>' +
    '<p class="sub">Mock authorization server at <code>' + xmlEscape(base) + '</code></p>' +
    (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
    '<form method="post" action="/oauth2/login">' +
    '<input type="hidden" name="login_id" value="' + xmlEscape(login.id) + '">' +
    '<label for="username">Username</label>' +
    '<input type="text" id="username" name="username" autocomplete="username" autofocus' +
    ' value="' + xmlEscape(q.login_hint || '') + '">' +
    '<label for="password">Password</label>' +
    '<input type="password" id="password" name="password" autocomplete="current-password">' +
    '<div class="row"><button type="submit" id="kc-login" name="action" value="login">Sign In</button>' +
    '<button type="submit" id="kc-cancel" name="action" value="cancel" class="secondary">Cancel</button></div>' +
    '</form><div class="meta">' +
    '<div>No password is checked. The username you enter is the identity the issued tokens describe.</div>' +
    '<div>client_id: <code>' + xmlEscape(q.client_id || '') + '</code></div>' +
    '<div>scope: <code>' + xmlEscape(scope) + '</code></div>' +
    '<div>redirect_uri: <code>' + xmlEscape(q.redirect_uri || '') + '</code></div>' +
    (q.issuer_state
      ? '<div>issuer_state: <code>' + xmlEscape(q.issuer_state) + '</code>' +
        (issuerStates.has(String(q.issuer_state)) ? ' (from a Credential Offer this issuer made)' : '') +
        '</div>'
      : '') +
    '</div></div></body></html>\n';
  log.debug("Leaving loginPage().");
  return page;
}

// Build the authorization response for a signed-in user and redirect back to
// the client. Everything after authentication — which is "as normal".
// authorization_details (RFC 9396) as OID4VCI uses it: an array of objects of
// type openid_credential, each naming a credential_configuration_id. Unreadable
// JSON is not silently dropped — a wallet that sent nonsense should be told.
function parseAuthorizationDetails(raw) {
  log.debug("Entering parseAuthorizationDetails().");
  if (!raw) {
    log.debug("Leaving parseAuthorizationDetails(). None were sent.");
    return { details: null };
  }
  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch (e) {
    log.debug("Leaving parseAuthorizationDetails(). Not JSON: " + e.message);
    return { error: 'authorization_details is not readable JSON: ' + e.message };
  }
  if (!Array.isArray(parsed)) {
    log.debug("Leaving parseAuthorizationDetails(). Not an array.");
    return { error: 'authorization_details must be a JSON array.' };
  }
  const wanted = [];
  for (let i = 0; i < parsed.length; i++) {
    const d = parsed[i] || {};
    if (d.type !== 'openid_credential') {
      log.debug("Leaving parseAuthorizationDetails(). Unsupported type: " + d.type);
      return { error: 'authorization_details type "' + d.type + '" is not supported; ' +
                      'this issuer understands openid_credential.' };
    }
    const configId = d.credential_configuration_id;
    if (configId && !VCI_CONFIGS[configId]) {
      log.debug("Leaving parseAuthorizationDetails(). Unknown configuration: " + configId);
      return { error: 'credential_configuration_id "' + configId + '" is not one this issuer offers.' };
    }
    wanted.push({ type: 'openid_credential', credential_configuration_id: configId || VCI_CONFIG_ID });
  }
  log.debug("Leaving parseAuthorizationDetails(). " + wanted.length + " detail(s).");
  return { details: wanted.length ? wanted : null };
}

function issueAuthorizationResponse(req, res, query, user, authTime) {
  log.debug("Entering issueAuthorizationResponse(). response_type=" + (query.response_type || '(none)') +
            ", user=" + user.username);
  const base = baseUrlOf(req);
  const redirectUri = String(query.redirect_uri);
  const types = String(query.response_type || '').split(/\s+/).filter(Boolean);
  const scope = String(query.scope || 'openid');
  const out = {};
  const parsedDetails = parseAuthorizationDetails(query.authorization_details);
  if (parsedDetails.error) {
    log.debug("Leaving issueAuthorizationResponse(). " + parsedDetails.error);
    return redirectBack(res, base, redirectUri, query.state,
      { error: 'invalid_authorization_details', error_description: parsedDetails.error },
      types.length > 1 || types.indexOf('code') < 0);
  }
  const authorizationDetails = parsedDetails.details;
  if (authorizationDetails) {
    logArtifact('authorization_details', 'as requested', authorizationDetails);
  }

  if (types.indexOf('code') >= 0) {
    const code = randomId(24);
    authzCodes.set(code, {
      client_id: String(query.client_id), redirect_uri: redirectUri, scope: scope,
      nonce: query.nonce, user: user, auth_time: authTime,
      code_challenge: query.code_challenge, code_challenge_method: query.code_challenge_method || 'plain',
      // What the wallet asked to be authorized for, if it used
      // authorization_details rather than a scope. The token response has to
      // echo it back with the credential_identifiers it grants.
      authorization_details: authorizationDetails,
      expires: Date.now() + AUTH_CODE_TTL_MS
    });
    out.code = code;
  }
  if (types.indexOf('token') >= 0) {
    out.access_token = accessToken(base, { user: user, client_id: String(query.client_id), scope: scope });
    out.token_type = 'Bearer';
    out.expires_in = ACCESS_TOKEN_TTL;
    out.scope = scope;
  }
  if (types.indexOf('id_token') >= 0) {
    out.id_token = idToken(base, {
      user: user, client_id: String(query.client_id), nonce: query.nonce, auth_time: authTime,
      access_token: out.access_token, code: out.code
    });
  }
  // Only a bare code goes in the query; anything carrying a token uses the
  // fragment, per OAuth 2.0 / OIDC.
  logArtifact('Authorization response', 'as returned to the client', out);
  redirectBack(res, base, redirectUri, query.state, out,
    types.length > 1 || types.indexOf('code') < 0);
  log.debug("Leaving issueAuthorizationResponse().");
}

function redirectBack(res, base, redirectUri, state, params, fragment) {
  log.debug("Entering redirectBack(). fragment=" + !!fragment);
  const usp = new URLSearchParams();
  Object.keys(params).forEach(function (k) { if (params[k] !== undefined) usp.set(k, params[k]); });
  if (state !== undefined) usp.set('state', state);
  usp.set('iss', base);
  const sep = fragment ? '#' : (redirectUri.indexOf('?') >= 0 ? '&' : '?');
  res.redirect(302, redirectUri + sep + usp.toString());
  log.debug("Leaving redirectBack().");
}

app.get('/oauth2/authorize', function (req, res) {
  log.debug("Entering the authorization endpoint.");
  const base = baseUrlOf(req);
  const q = req.query || {};
  const redirectUri = String(q.redirect_uri || '');

  // Without a usable redirect_uri there is nowhere to report an error TO, so it
  // is reported here instead (OAuth 2.0 section 4.1.2.1).
  if (!redirectUri || !/^https?:\/\//i.test(redirectUri)) {
    log.debug("Leaving the authorization endpoint. There is no usable redirect_uri to report to.");
    return oauthError(res, 400, 'invalid_request', 'A valid absolute redirect_uri is required.');
  }
  const fail = function (error, description) {
    log.debug("Leaving the authorization endpoint. Reporting " + error + " to the client.");
    redirectBack(res, base, redirectUri, q.state, { error: error, error_description: description }, false);
  };
  if (!q.client_id) return fail('invalid_request', 'client_id is required.');
  const types = String(q.response_type || '').split(/\s+/).filter(Boolean);
  const known = ['code', 'token', 'id_token'];
  if (!types.length || types.some(function (t) { return known.indexOf(t) < 0; })) {
    return fail('unsupported_response_type', 'response_type "' + (q.response_type || '') + '" is not supported.');
  }

  // issuer_state (OID4VCI section 4.1.1): if this request came from a Credential
  // Offer this server issued, say so — it is what ties the authorization request
  // back to the offer, and seeing it arrive is most of its debugging value.
  if (q.issuer_state) {
    const known = issuerStates.get(String(q.issuer_state));
    if (known && known.expires >= Date.now()) {
      log.debug("The authorization request carries an issuer_state from a Credential Offer this issuer made" +
                " (credential_configuration_ids=" + (known.configurationIds || []).join(', ') + ").");
    } else {
      log.debug("The authorization request carries an issuer_state this issuer does not recognise: " +
                q.issuer_state);
    }
  }

  // Already signed in? Then this is the second pass — after the login screen,
  // or a later request on the same session — and the response goes out now.
  const session = sessionOf(req);
  const forcePrompt = String(q.prompt || '').split(/\s+/).indexOf('login') >= 0;
  if (session && !forcePrompt) {
    log.debug("Leaving the authorization endpoint. The session stands, so the response goes out now.");
    return issueAuthorizationResponse(req, res, q, session.user, session.authTime);
  }
  if (String(q.prompt || '').split(/\s+/).indexOf('none') >= 0) {
    // OIDC: prompt=none must not show any UI.
    return fail('login_required', 'No session, and prompt=none forbids showing the login screen.');
  }

  // Otherwise: authenticate the user first. The request is stashed so the login
  // POST can send the browser back to it unchanged.
  const login = {
    id: randomId(18),
    query: JSON.parse(JSON.stringify(q)),
    expires: Date.now() + LOGIN_TTL_MS
  };
  pendingLogins.set(login.id, login);
  pendingLogins.forEach(function (v, k) { if (v.expires < Date.now()) pendingLogins.delete(k); });
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(loginPage(base, login, ''));
  log.debug("Leaving the authorization endpoint. Showing the login screen first.");
});

app.post('/oauth2/login', function (req, res) {
  log.debug("Entering the login endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const login = pendingLogins.get(String(body.login_id || ''));
  if (!login || login.expires < Date.now()) {
    pendingLogins.delete(String(body.login_id || ''));
    log.debug("Leaving the login endpoint. The form had expired.");
    return oauthError(res, 400, 'invalid_request',
      'This login form has expired. Start the authorization request again.');
  }
  const redirectUri = String(login.query.redirect_uri);

  if (String(body.action || '') === 'cancel') {
    pendingLogins.delete(login.id);
    log.debug("Leaving the login endpoint. The user cancelled.");
    return redirectBack(res, base, redirectUri, login.query.state,
      { error: 'access_denied', error_description: 'The user cancelled at the login screen.' }, false);
  }

  const username = String(body.username || '').trim();
  // The only two ways to fail: no username to put in the tokens, and the
  // reserved password the rest of this mock also refuses.
  if (!username) {
    log.debug("Leaving the login endpoint. No username was entered, so the form is shown again.");
    return res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(loginPage(base, login, 'Enter a username. It does not have to exist — it is the identity the ' +
                                  'issued tokens will describe.'));
  }
  if (String(body.password || '') === 'invalid') {
    log.debug("Leaving the login endpoint. The reserved password was used, so the form is shown again.");
    return res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(loginPage(base, login, 'Authentication failed for ' + username + '.'));
  }

  pendingLogins.delete(login.id);
  const sessionId = randomId(24);
  sessions.set(sessionId, {
    user: userFor(username), authTime: nowSec(), expires: Date.now() + SESSION_TTL_MS
  });
  res.set('Set-Cookie', SESSION_COOKIE + '=' + sessionId + '; Path=/; HttpOnly; SameSite=Lax');

  // Back to the authorization endpoint with the original request — minus
  // prompt, which has now been honoured and would otherwise prompt forever.
  res.redirect(302, base + '/oauth2/authorize?' + queryString(login.query, ['prompt']));
  log.debug("Leaving the login endpoint. " + username + " is signed in; back to the authorization endpoint.");
});

// Ends the session, so the next authorization request prompts again.
app.get('/oauth2/logout', function (req, res) {
  log.debug("Entering the logout endpoint.");
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (id) sessions.delete(id);
  res.set('Set-Cookie', SESSION_COOKIE + '=; Path=/; Max-Age=0');
  const target = req.query.post_logout_redirect_uri;
  if (target && /^https?:\/\//i.test(String(target))) {
    log.debug("Leaving the logout endpoint. Redirecting to " + target + ".");
    return res.redirect(302, String(target));
  }
  res.status(200).type('text/plain').send('Signed out of the mock authorization server.\n');
  log.debug("Leaving the logout endpoint.");
});

// --- token endpoint ---------------------------------------------------------
app.post('/oauth2/token', function (req, res) {
  log.debug("Entering the token endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const client = clientFrom(req, body);
  const grant = String(body.grant_type || '');
  res.set('Cache-Control', 'no-store');

  const respond = function (payload) {
    res.status(200).type('application/json').send(JSON.stringify(payload));
    log.debug("Leaving the token endpoint. Issued: " + Object.keys(payload).join(', '));
  };

  // Turn what was authorized into what may be requested: OID4VCI calls these
  // Credential Dataset identifiers, and they are the issuer's own names for
  // "this credential, for this End-User".
  const grantIdentifiers = function (details, user) {
    if (!details) return null;
    return details.map(function (d) {
      return {
        type: 'openid_credential',
        credential_configuration_id: d.credential_configuration_id,
        credential_identifiers: [
          d.credential_configuration_id + ':' +
          b64u(crypto.createHash('sha256')
            .update(String((user && user.sub) || 'anonymous') + ':' + d.credential_configuration_id)
            .digest()).slice(0, 16)
        ]
      };
    });
  };

  if (grant === 'authorization_code') {
    const record = authzCodes.get(String(body.code || ''));
    if (!record) return oauthError(res, 400, 'invalid_grant', 'Unknown or already-used authorization code.');
    authzCodes.delete(String(body.code));  // single use
    if (record.expires < Date.now()) return oauthError(res, 400, 'invalid_grant', 'The authorization code has expired.');
    if (body.redirect_uri && body.redirect_uri !== record.redirect_uri) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'redirect_uri does not match the authorization request.');
    }
    if (record.code_challenge) {
      const verifier = String(body.code_verifier || '');
      if (!verifier) return oauthError(res, 400, 'invalid_grant', 'PKCE was used, so code_verifier is required.');
      const computed = record.code_challenge_method === 'S256'
        ? b64u(crypto.createHash('sha256').update(verifier, 'ascii').digest())
        : verifier;
      if (computed !== record.code_challenge) {
        log.debug("Leaving the token endpoint. The grant was refused.");
        return oauthError(res, 400, 'invalid_grant', 'The code_verifier does not match the code_challenge.');
      }
    }
    return respond(tokenSet(base, {
      user: record.user, client_id: record.client_id, scope: record.scope,
      nonce: record.nonce, auth_time: record.auth_time,
      authorization_details: grantIdentifiers(record.authorization_details, record.user)
    }));
  }

  // OID4VCI's pre-authorized code grant (Appendix H.2 / H.3, RFC-registered as
  // urn:ietf:params:oauth:grant-type:pre-authorized_code). No authorization
  // request happened: the End-User was identified out of band and the code in
  // the Credential Offer is the authorization. When the offer said a
  // Transaction Code is required, the wallet must present the one the End-User
  // read off the issuer's screen.
  if (grant === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    const code = String(body['pre-authorized_code'] || '');
    const record = preAuthorizedCodes.get(code);
    if (!record) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'Unknown or already-used pre-authorized code.');
    }
    if (record.expires < Date.now()) {
      preAuthorizedCodes.delete(code);
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'The pre-authorized code has expired.');
    }
    const presented = String(body.tx_code || '');
    if (record.txCode) {
      if (!presented) {
        log.debug("Leaving the token endpoint. The grant was refused: no tx_code.");
        return oauthError(res, 400, 'invalid_grant',
          'This pre-authorized code requires the Transaction Code shown by the issuer (tx_code).');
      }
      if (presented !== record.txCode) {
        log.debug("Leaving the token endpoint. The grant was refused: the tx_code is wrong.");
        return oauthError(res, 400, 'invalid_grant', 'The Transaction Code is not correct.');
      }
    }
    // Single use, like an authorization code.
    preAuthorizedCodes.delete(code);
    const issued = tokenSet(base, {
      user: record.user, client_id: client.client_id, scope: VCI_SCOPE, withRefresh: false
    });
    // Remember which access token belongs to a deferred issuance, so the
    // credential endpoint knows to answer 202 rather than a credential.
    if (record.deferred) {
      deferredAccessTokens.add(issued.access_token);
      log.debug("This access token belongs to a DEFERRED issuance.");
    }
    return respond(issued);
  }

  if (grant === 'refresh_token') {
    let claims;
    try {
      claims = jwt.verify(String(body.refresh_token || ''), STS.certPem, { algorithms: ['RS256'] });
    } catch (e) {
      log.error('the refresh token is not valid: ' + e.message);
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'The refresh token is not valid: ' + e.message);
    }
    if (revokedJtis.has(claims.jti)) return oauthError(res, 400, 'invalid_grant', 'The refresh token was revoked.');
    return respond(tokenSet(base, {
      user: userFor(claims.username), client_id: claims.client_id,
      scope: body.scope ? String(body.scope) : claims.scope
    }));
  }

  if (grant === 'client_credentials') {
    // No user is involved, so no refresh token and no ID token.
    return respond(tokenSet(base, {
      sub: client.client_id || 'unknown-client', username: client.client_id,
      client_id: client.client_id, scope: String(body.scope || ''), withRefresh: false,
      user: Object.assign(userFor(client.client_id), { sub: client.client_id || 'unknown-client' })
    }));
  }

  if (grant === 'password') {
    const username = String(body.username || '');
    if (!username || !body.password) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_request', 'username and password are required.');
    }
    // The one credential this mock rejects, so a negative test has something to
    // fail on (the WS-Trust side of this service does the same).
    if (body.password === 'invalid') {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'Authentication failed for user ' + username + '.');
    }
    return respond(tokenSet(base, {
      user: userFor(username), client_id: client.client_id, scope: String(body.scope || 'openid')
    }));
  }

  if (grant === 'urn:ietf:params:oauth:grant-type:token-exchange') {
    const subjectToken = String(body.subject_token || '');
    if (!subjectToken) return oauthError(res, 400, 'invalid_request', 'subject_token is required.');
    let subject = {};
    try {
      subject = jwt.verify(subjectToken, STS.certPem, { algorithms: ['RS256'] });
    } catch (e) {
      // A token from somewhere else: exchange it anyway, but say who it was for
      // as best it can be read.
      log.debug("The subject_token was not signed by this server; reading it without verifying.");
      try {
        subject = jsonFromB64u(subjectToken.split('.')[1]) || {};
      } catch (e2) {
        log.error('the subject_token could not be read at all: ' + e2.message);
        subject = {};
      }
    }
    let act;
    if (body.actor_token) {
      try {
        act = { sub: (jsonFromB64u(String(body.actor_token).split('.')[1]) || {}).sub };
      } catch (e) {
        log.error('the actor_token could not be read: ' + e.message);
        act = undefined;
      }
    }
    const exchanged = tokenSet(base, {
      sub: subject.sub || 'urn:sts-mock:exchanged',
      user: Object.assign(userFor(subject.username), subject.sub ? { sub: subject.sub } : {}),
      client_id: client.client_id, scope: String(body.scope || subject.scope || ''),
      audience: body.audience || body.resource, act: act, withRefresh: false
    });
    exchanged.issued_token_type = 'urn:ietf:params:oauth:token-type:access_token';
    return respond(exchanged);
  }

  log.debug("Leaving the token endpoint.");
  log.debug("Leaving the token endpoint. The grant type is not supported.");
  return oauthError(res, 400, 'unsupported_grant_type', 'grant_type "' + grant + '" is not supported.');
});

// --- introspection (RFC 7662) ------------------------------------------------
app.post('/oauth2/introspect', function (req, res) {
  log.debug("Entering the introspection endpoint.");
  const body = parseBody(req);
  res.set('Cache-Control', 'no-store');
  const inactive = function () {
    res.status(200).type('application/json').send(JSON.stringify({ active: false }));
    log.debug("Leaving the introspection endpoint. The token is not active.");
  };
  const token = String(body.token || '');
  if (!token) return inactive();
  let claims;
  try {
    claims = jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
  } catch (e) {
    // Expired, forged, or simply not one of ours.
    log.debug("Introspection: the token does not verify (" + e.message + "), so it is inactive.");
    return inactive();
  }
  if (revokedJtis.has(claims.jti)) return inactive();
  res.status(200).type('application/json').send(JSON.stringify({
    active: true,
    scope: claims.scope || '',
    client_id: claims.client_id,
    username: claims.username,
    token_type: claims.typ === 'Refresh' ? 'refresh_token' : 'Bearer',
    exp: claims.exp, iat: claims.iat, nbf: claims.nbf,
    sub: claims.sub, aud: claims.aud, iss: claims.iss, jti: claims.jti
  }));
  log.debug("Leaving the introspection endpoint. The token is active.");
});

// --- revocation (RFC 7009) ---------------------------------------------------
// "The authorization server responds with HTTP 200 for both a successful
// revocation and an invalid token" — so this always succeeds. A revoked jti
// stops introspecting as active and stops refreshing.
app.post('/oauth2/revoke', function (req, res) {
  log.debug("Entering the revocation endpoint.");
  const body = parseBody(req);
  const token = String(body.token || '');
  if (token) {
    try {
      const claims = jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
      if (claims.jti) revokedJtis.add(claims.jti);
    } catch (e) {
      // RFC 7009: an invalid token is still a successful revocation.
      log.debug("Revocation: the token does not verify (" + e.message + "), so there is nothing to revoke.");
    }
  }
  res.status(200).set('Cache-Control', 'no-store').end();
  log.debug("Leaving the revocation endpoint. " + revokedJtis.size + " token(s) revoked so far.");
});

// --- dynamic client registration (RFC 7591) + management (RFC 7592) ----------
function clientRecord(base, metadata, clientId, secret, token) {
  log.debug("Entering clientRecord(). client_id=" + clientId);
  const record = Object.assign({}, metadata, {
    client_id: clientId,
    client_id_issued_at: nowSec(),
    client_secret: secret,
    client_secret_expires_at: 0,               // 0 = never
    registration_access_token: token,
    registration_client_uri: base + '/oauth2/register/' + clientId
  });
  log.debug("Leaving clientRecord().");
  return record;
}

app.post('/oauth2/register', function (req, res) {
  log.debug("Entering the client registration endpoint.");
  const base = baseUrlOf(req);
  const metadata = parseBody(req);
  if (metadata.redirect_uris && !Array.isArray(metadata.redirect_uris)) {
    return oauthError(res, 400, 'invalid_redirect_uri', 'redirect_uris must be an array.');
  }
  const clientId = 'sts-mock-client-' + randomId(8);
  const record = clientRecord(base, metadata, clientId, randomId(24), randomId(24));
  registeredClients.set(clientId, record);
  res.status(201).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(record, null, 2));
  log.debug("Leaving the client registration endpoint. Registered " + clientId + ".");
});

// The management calls all authenticate with the registration access token the
// registration handed out.
function withRegisteredClient(req, res, handler) {
  log.debug("Entering withRegisteredClient(). client_id=" + req.params.client_id);
  const record = registeredClients.get(req.params.client_id);
  if (!record) {
    log.debug("Leaving withRegisteredClient(). No such client.");
    return oauthError(res, 404, 'invalid_client', 'No such registered client.');
  }
  const auth = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  if (auth !== record.registration_access_token) {
    res.set('WWW-Authenticate', 'Bearer');
    log.debug("Leaving withRegisteredClient(). The registration access token did not match.");
    return oauthError(res, 401, 'invalid_token', 'The registration access token does not match.');
  }
  const result = handler(record);
  log.debug("Leaving withRegisteredClient().");
  return result;
}

app.get('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client read endpoint.");
  withRegisteredClient(req, res, function (record) {
    res.status(200).type('application/json').send(JSON.stringify(record, null, 2));
  });
  log.debug("Leaving the client read endpoint.");
});

app.put('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client update endpoint.");
  withRegisteredClient(req, res, function (record) {
    const updated = Object.assign({}, parseBody(req), {
      client_id: record.client_id,
      client_id_issued_at: record.client_id_issued_at,
      client_secret: record.client_secret,
      client_secret_expires_at: record.client_secret_expires_at,
      registration_access_token: record.registration_access_token,
      registration_client_uri: record.registration_client_uri
    });
    registeredClients.set(record.client_id, updated);
    res.status(200).type('application/json').send(JSON.stringify(updated, null, 2));
  });
  log.debug("Leaving the client update endpoint.");
});

app.delete('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client delete endpoint.");
  withRegisteredClient(req, res, function (record) {
    registeredClients.delete(record.client_id);
    res.status(204).end();
  });
  log.debug("Leaving the client delete endpoint.");
});

// --- the documents the metadata links to ------------------------------------
app.get('/docs', function (req, res) {
  log.debug("Entering the service documentation endpoint.");
  res.type('text/plain').send(
    'Mock authorization server (service_documentation).\n\n' +
    'Every endpoint in ' + baseUrlOf(req) + '/.well-known/oauth-authorization-server answers.\n' +
    'Tokens are RS256 JWTs signed with the key at ' + baseUrlOf(req) + '/oauth2/jwks.\n' +
    'No credential is ever verified: this server exists to exercise a client.\n');
  log.debug("Leaving the service documentation endpoint.");
});

app.get('/policy', function (req, res) {
  log.debug("Entering the policy document endpoint.");
  res.type('text/plain').send('Mock authorization server policy (op_policy_uri). Test data only.\n');
  log.debug("Leaving the policy document endpoint.");
});

app.get('/tos', function (req, res) {
  log.debug("Entering the terms of service endpoint.");
  res.type('text/plain').send('Mock authorization server terms of service (op_tos_uri). Test data only.\n');
  log.debug("Leaving the terms of service endpoint.");
});

app.listen(PORT, '0.0.0.0', function () {
  log.info('WS-Trust STS mock listening on :' + PORT + ' (issuer ' + ISSUER + '); POST SOAP RST to /sts');
  log.info('RFC 8414 metadata at /.well-known/oauth-authorization-server; JWKS at /oauth2/jwks');
  log.info('OID4VCI issuer metadata at /.well-known/openid-credential-issuer; ' +
           'credential endpoint at /oid4vci/credential');
  log.info('Issuer-initiated (OID4VCI H.1): the issuer web page is at /issuer; ' +
           'it builds a Credential Offer and sends the browser to the wallet.');
  log.info('Mock authorization server endpoints: /oauth2/authorize (login screen), /oauth2/login, ' +
           '/oauth2/token, /oauth2/introspect, /oauth2/revoke, /oauth2/register, /oauth2/logout');
  log.info('Every endpoint call, and every token or assertion before and after it was signed, ' +
           'is written to this log at debug level.');
});
