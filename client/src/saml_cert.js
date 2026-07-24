// File: saml_cert.js
// Author: Robert C. Broeckelmann Jr.
//
// SAML signer-certificate details page. Reads the signer certificate saved by
// the SAML config page (localStorage key samltools_saml_signer_cert, a bare
// base64 DER string from the metadata) or any PEM/base64 the user pastes, parses
// it with node-forge, and renders the details in a table.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var forge = require("node-forge");
var log = bunyan.createLogger({ name: 'saml_cert', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ''; }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Accept PEM or bare base64 DER; return normalized PEM.
function toPem(input) {
  var s = (input || '').trim();
  if (!s) return '';
  if (s.indexOf('-----BEGIN') >= 0) return s;
  var b64 = s.replace(/\s+/g, '');
  var lines = b64.match(/.{1,64}/g) || [b64];
  return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----\n';
}

function dnString(attrs) {
  return (attrs || []).map(function (a) {
    return (a.shortName || a.name || a.type) + '=' + a.value;
  }).join(', ');
}

function fingerprint(cert, mdCreate) {
  var der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  var md = mdCreate();
  md.update(der);
  var hex = md.digest().toHex().toUpperCase();
  return (hex.match(/.{2}/g) || [hex]).join(':');
}

function pubKeyInfo(cert) {
  var pk = cert.publicKey;
  if (pk && pk.n && pk.n.bitLength) {
    return 'RSA ' + pk.n.bitLength() + '-bit (e=' + (pk.e ? pk.e.toString(10) : '?') + ')';
  }
  return 'unknown';
}

function extSummary(ext) {
  if (ext.name === 'subjectAltName' && ext.altNames) {
    return ext.altNames.map(function (n) { return (n.value || n.ip || ''); }).filter(Boolean).join(', ');
  }
  if (ext.name === 'keyUsage') {
    var flags = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
                 'keyAgreement', 'keyCertSign', 'cRLSign'];
    return flags.filter(function (f) { return ext[f]; }).join(', ');
  }
  if (ext.name === 'basicConstraints') {
    return 'cA=' + (!!ext.cA);
  }
  if (typeof ext.value === 'string') return ext.value;
  return '(present)';
}

function row(k, v) {
  return '<tr><td class="saml-key">' + esc(k) + '</td><td>' + esc(v) + '</td></tr>';
}

function parseCert() {
  var pem = toPem(val('saml_cert_input'));
  if (!pem) { setVal('saml_cert_status', 'Paste a certificate first.'); el('saml_cert_details').innerHTML = '&nbsp;'; return false; }
  var cert;
  try {
    cert = forge.pki.certificateFromPem(pem);
  } catch (e) {
    log.error('parseCert: ' + e.message);
    setVal('saml_cert_status', 'Parse error: ' + e.message);
    el('saml_cert_details').innerHTML = '&nbsp;';
    return false;
  }

  var sigAlg = forge.pki.oids[cert.signatureOid] || cert.signatureOid;
  var html = '<table class="saml-table">';
  html += row('Subject', dnString(cert.subject.attributes));
  html += row('Issuer', dnString(cert.issuer.attributes));
  html += row('Serial Number', cert.serialNumber);
  html += row('Version', 'v' + ((cert.version || 2) + 1));
  html += row('Not Before', cert.validity.notBefore);
  html += row('Not After', cert.validity.notAfter);
  html += row('Signature Algorithm', sigAlg);
  html += row('Public Key', pubKeyInfo(cert));
  html += row('SHA-1 Fingerprint', fingerprint(cert, forge.md.sha1.create));
  html += row('SHA-256 Fingerprint', fingerprint(cert, forge.md.sha256.create));
  (cert.extensions || []).forEach(function (ext) {
    html += row('Extension: ' + (ext.name || ext.id) + (ext.critical ? ' (critical)' : ''), extSummary(ext));
  });
  html += '</table>';
  html += '<div class="saml-field" style="margin-top:10px;"><label>PEM</label><textarea rows="8" readonly>' + esc(pem.trim()) + '</textarea></div>';

  el('saml_cert_details').innerHTML = html;
  setVal('saml_cert_status', 'Parsed.');
  return false;
}

function copyField(id) {
  var e = el(id);
  if (!e) return false;
  var text = e.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error('copyField: ' + err); });
  } else {
    try { e.focus(); e.select(); document.execCommand('copy'); } catch (err) { log.error('copyField fallback: ' + err.message); }
  }
  return false;
}

function setReturnLink() {
  var from = new URLSearchParams(window.location.search).get('from');
  var allowed = {
    'saml_tools.html': '/saml_tools.html',
    'saml_response.html': '/saml_response.html',
    'wstrust_tools.html': '/wstrust_tools.html',
    'wstrust_response.html': '/wstrust_response.html',
    'digital_signature.html': '/digital_signature.html',
    'jwt_tools.html': '/jwt_tools.html'
  };
  var link = el('return_link');
  if (link && allowed[from]) {
    link.setAttribute('href', allowed[from]);
    link.textContent = '← Return to ' + from;
  }
}

window.onload = function () {
  setReturnLink();
  // Pre-fill the certificate to view, then auto-parse. Any key-pair page stores
  // the cert to inspect in 'saml_cert_view'; fall back to the SAML signer cert.
  if (window.localStorage) {
    var saved = localStorage.getItem('saml_cert_view') || localStorage.getItem('samltools_saml_signer_cert');
    if (saved && !val('saml_cert_input')) setVal('saml_cert_input', saved);
  }
  if (val('saml_cert_input')) parseCert();
};

module.exports = {
  parseCert,
  copyField
};
