'use strict';
//
// File: wstrust.js
//
// ---------------------------------------------------------------------------
// WS-Trust 1.4 (and 1.0-1.3, which differ only in the namespace and action URIs):
// the SOAP RequestSecurityToken endpoint and everything that reads or writes one.
//
// It accepts an RST and dispatches on wst:RequestType:
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
// OnBehalfOf/ActAs token (delegation) is also accepted. This is a TEST STS — it
// does not verify request signatures or enforce real policy.
//
// The SAML assertion itself is built and protected by saml2.js: WS-Trust carries
// tokens, it does not define them.
// ---------------------------------------------------------------------------

const jwt = require('jsonwebtoken');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const app = require('./app');
const { log, logArtifact, ISSUER, STS, xmlEscape, iso } = require('./helpers');
const { buildSamlAssertion, encryptAssertion } = require('./saml2');
const WST_NS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';

const SOAP12_NS = 'http://www.w3.org/2003/05/soap-envelope';

const SOAP11_NS = 'http://schemas.xmlsoap.org/soap/envelope/';

const SAML2_TOKEN_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';

const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';

const STATUS_TOKEN_TYPE = WST_NS + '/RSTR/Status';

const STATUS_VALID = WST_NS + '/status/valid';

const STATUS_INVALID = WST_NS + '/status/invalid';

function firstByLocal(root, name) {
  const els = root.getElementsByTagNameNS('*', name);
  return els && els.length ? els[0] : null;
}

function textByLocal(root, name) {
  const e = firstByLocal(root, name);
  return e ? (e.textContent || '').trim() : '';
}

function soapNsFor(version) { return version === '1.1' ? SOAP11_NS : SOAP12_NS; }

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

module.exports = {
  handleRst: handleRst,
  buildToken: buildToken,
  soapFault: soapFault
};
