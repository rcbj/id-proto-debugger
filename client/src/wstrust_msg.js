// File: wstrust_msg.js
//
// Pure WS-Trust RequestSecurityToken (RST) construction, factored out of
// wstrust_tools.js so it can be unit-tested / schema-validated without a DOM.
// Given an options object (the values the page reads from its form) it produces
// exactly the RST body the page sends. The version model + the namespace-relative
// URI helpers (RequestType / Action / KeyType / Status) live here too, since
// they drive construction. No DOM, no crypto — safe to require from Node.

// WS-Trust protocol versions. The RequestType / Action / KeyType / Status URIs
// are namespace-relative, so the selected version's trust namespace (ns) drives
// construction. Feature gates: `bearer` — the Bearer KeyType is WS-Trust 1.3+;
// `actas` — wst14:ActAs (composite delegation) is WS-Trust 1.4 only.
var TRUST_VERSIONS = {
  "1.0": { ns: "http://schemas.xmlsoap.org/ws/2004/04/trust", bearer: false, actas: false },
  "1.1": { ns: "http://schemas.xmlsoap.org/ws/2005/02/trust", bearer: false, actas: false },
  "1.2": { ns: "http://schemas.xmlsoap.org/ws/2005/02/trust", bearer: false, actas: false },
  "1.3": { ns: "http://docs.oasis-open.org/ws-sx/ws-trust/200512", bearer: true, actas: false },
  "1.4": { ns: "http://docs.oasis-open.org/ws-sx/ws-trust/200512", bearer: true, actas: true }
};
var OP_SEGMENT = { issue: "Issue", renew: "Renew", validate: "Validate", cancel: "Cancel" };
var KEY_TYPE_SEGMENT = { bearer: "Bearer", symmetric: "SymmetricKey", public: "PublicKey" };

var WST14_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200802"; // ActAs
var WSP_NS = "http://schemas.xmlsoap.org/ws/2004/09/policy";
var WSA_NS = "http://www.w3.org/2005/08/addressing";
var WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
var CLAIMS_DIALECT = "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims";

function xmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}
function nowPlusMinutes(mins) {
  return new Date(Date.now() + (mins || 0) * 60000).toISOString();
}

function versionCfg(version) { return TRUST_VERSIONS[version] || TRUST_VERSIONS["1.4"]; }
function versionNs(version) { return versionCfg(version).ns; }
function requestTypeUri(version, op) { return versionNs(version) + "/" + (OP_SEGMENT[op] || "Issue"); }
function wsaActionUri(version, op) { return versionNs(version) + "/RST/" + (OP_SEGMENT[op] || "Issue"); }
function keyTypeUri(version, kt) { return versionNs(version) + "/" + (KEY_TYPE_SEGMENT[kt] || "Bearer"); }
function statusTokenTypeUri(version) { return versionNs(version) + "/RSTR/Status"; }

function tokenTypeUri(tokenType, version) {
  switch (tokenType) {
    case 'saml2': return "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
    case 'saml11': return "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
    case 'jwt': return "urn:ietf:params:oauth:token-type:jwt";
    case 'usernametoken': return "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#UsernameToken";
    case 'status': return statusTokenTypeUri(version);
    default: return "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
  }
}

// Build the <wst:RequestSecurityToken> element (the RST body). `o` mirrors the
// page's form fields:
//   version, operation, tokenType, keyType, keySize, appliesTo,
//   lifetimeMinutes, claims, useOnBehalfOf, onBehalfOf, useActAs, actAs,
//   targetToken
function buildRst(o) {
  o = o || {};
  var version = o.version;
  var op = o.operation;
  var parts = [];
  parts.push('<wst:RequestType>' + requestTypeUri(version, op) + '</wst:RequestType>');

  if (op === 'validate') {
    parts.push('<wst:TokenType>' + statusTokenTypeUri(version) + '</wst:TokenType>');
  } else if (op !== 'cancel') {
    parts.push('<wst:TokenType>' + tokenTypeUri(o.tokenType, version) + '</wst:TokenType>');
  }

  var appliesTo = (o.appliesTo || '').trim();
  if ((op === 'issue' || op === 'renew') && appliesTo) {
    parts.push('<wsp:AppliesTo><wsa:EndpointReference><wsa:Address>' + xmlEscape(appliesTo) + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>');
  }

  if (op === 'issue') {
    parts.push('<wst:KeyType>' + keyTypeUri(version, o.keyType) + '</wst:KeyType>');
    if (o.keyType === 'symmetric') {
      var ks = parseInt(o.keySize, 10) || 256;
      parts.push('<wst:KeySize>' + ks + '</wst:KeySize>');
    }
    var lifeMin = parseInt(o.lifetimeMinutes, 10) || 0;
    if (lifeMin > 0) {
      parts.push('<wst:Lifetime><wsu:Created>' + nowPlusMinutes(0) + '</wsu:Created><wsu:Expires>' + nowPlusMinutes(lifeMin) + '</wsu:Expires></wst:Lifetime>');
    }
    var claims = (o.claims || '').trim();
    if (claims) {
      var claimEls = claims.split(/[\s,]+/).filter(Boolean).map(function (uri) {
        return '<auth:ClaimType xmlns:auth="' + CLAIMS_DIALECT + '" Uri="' + xmlEscape(uri) + '"/>';
      }).join('');
      parts.push('<wst:Claims Dialect="' + CLAIMS_DIALECT + '">' + claimEls + '</wst:Claims>');
    }
    if (o.useOnBehalfOf && (o.onBehalfOf || '').trim()) {
      parts.push('<wst:OnBehalfOf>' + o.onBehalfOf.trim() + '</wst:OnBehalfOf>');
    }
    if (o.useActAs && (o.actAs || '').trim()) {
      parts.push('<wst14:ActAs xmlns:wst14="' + WST14_NS + '">' + o.actAs.trim() + '</wst14:ActAs>');
    }
  } else {
    // Renew / Validate / Cancel operate on an existing token in Target Token.
    var target = (o.targetToken || '').trim();
    var wrap = { renew: 'RenewTarget', validate: 'ValidateTarget', cancel: 'CancelTarget' }[op];
    parts.push('<wst:' + wrap + '>' + (target || '<!-- paste the target token above -->') + '</wst:' + wrap + '>');
  }

  return '<wst:RequestSecurityToken xmlns:wst="' + versionNs(version) + '"' +
    ' xmlns:wsp="' + WSP_NS + '" xmlns:wsa="' + WSA_NS + '" xmlns:wsu="' + WSU_NS + '">' +
    parts.join('') +
    '</wst:RequestSecurityToken>';
}

module.exports = {
  TRUST_VERSIONS: TRUST_VERSIONS,
  versionCfg: versionCfg,
  versionNs: versionNs,
  requestTypeUri: requestTypeUri,
  wsaActionUri: wsaActionUri,
  keyTypeUri: keyTypeUri,
  statusTokenTypeUri: statusTokenTypeUri,
  tokenTypeUri: tokenTypeUri,
  buildRst: buildRst
};
