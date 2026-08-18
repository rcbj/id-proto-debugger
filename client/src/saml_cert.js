// File: saml_cert.js
// Author: Robert C. Broeckelmann Jr.
//
// Certificate details page, shared by nine others. Reads the certificate saved
// by whichever page sent you here (localStorage key saml_cert_view), or the
// SAML signer certificate (samltools_saml_signer_cert, a bare base64 DER
// string out of an IdP's metadata), or any PEM/base64 pasted into the box, and
// renders what is in it.
//
// IT PARSES WITH x509.js, NOT node-forge, and that is the whole of the
// 2026-08-18 change to this file. node-forge's certificateFromPem() reads the
// SubjectPublicKeyInfo eagerly and supports exactly one algorithm in it, so
// every EC and every Ed25519 certificate died here on
//
//     Parse error: Cannot read public key. OID is not RSA.
//
// — a message about a public key, from a page that had not got as far as
// showing the subject. That was every certificate the PKI page issues except
// the RSA ones, and its own "View certificate details" button lands here.
//
// x509.js is the module that page issues with, so this is now one description
// of a certificate rather than two: every extension it can build it can also
// read back, and describeCertificate() names the key algorithm from the
// SubjectPublicKeyInfo whether or not this browser can import the key.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var x509 = require("./x509.js");
var log = bunyan.createLogger({ name: 'saml_cert', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}
function val(id) {
  log.debug("Entering val().");
  var e = el(id);
  log.debug("Leaving val().");
  return e ? e.value : '';
}
function setVal(id, v) {
  log.debug("Entering setVal().");
  var e = el(id);
  if (e) e.value = (v == null ? '' : v);
  log.debug("Leaving setVal().");
}
function esc(s) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Accept PEM or bare base64 DER; return normalized PEM.
//
// A pasted bundle is normal — an IdP's metadata carries a chain, and so does
// half of what anybody has in a file — so the FIRST certificate is taken
// rather than the concatenation of all of them. x509.js's pemToDer() strips
// every armour line before it decodes, which turns two certificates into one
// unparseable blob and an error about ASN.1 rather than about a chain.
function toPem(input) {
  log.debug("Entering toPem().");
  var s = (input || '').trim();
  if (!s) {
    log.debug("Leaving toPem().");
    return '';
  }
  if (s.indexOf('-----BEGIN') >= 0) {
    var first = s.match(
        /-----BEGIN [^-]*-----[\s\S]*?-----END [^-]*-----/);
    log.debug("Leaving toPem(). PEM.");
    return first ? first[0] + '\n' : s;
  }
  var b64 = s.replace(/\s+/g, '');
  var lines = b64.match(/.{1,64}/g) || [b64];
  log.debug("Leaving toPem().");
  return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') +
      '\n-----END CERTIFICATE-----\n';
}

function row(k, v) {
  log.debug("Entering row().");
  log.debug("Leaving row().");
  return '<tr><td class="saml-key">' + esc(k) + '</td><td>' + esc(v) +
      '</td></tr>';
}

// The button's handler. describeCertificate() is async — it imports the public
// key and digests the DER — so the work is done by renderCert() and this
// returns false straight away, which is what an onclick has to give back.
function parseCert() {
  log.debug("Entering parseCert().");
  renderCert().catch(function (e) {
    log.error('parseCert: ' + (e && e.message));
    fail('Parse error: ' + (e && e.message ? e.message : e));
  });
  log.debug("Leaving parseCert().");
  return false;
}

function fail(message) {
  log.debug("Entering fail().");
  setVal('saml_cert_status', message);
  el('saml_cert_details').innerHTML = '&nbsp;';
  log.debug("Leaving fail().");
}

async function renderCert() {
  log.debug("Entering renderCert().");
  var pem = toPem(val('saml_cert_input'));
  if (!pem) {
    fail('Paste a certificate first.');
    log.debug("Leaving renderCert(). Nothing to parse.");
    return;
  }
  var described;
  try {
    described = await x509.describeCertificate(pem);
  } catch (e) {
    log.error('renderCert: ' + e.message);
    fail('Parse error: ' + e.message);
    log.debug("Leaving renderCert(). Not a certificate.");
    return;
  }

  var html = '<table class="saml-table" id="saml_cert_table">';
  html += row('Subject', described.subject);
  html += row('Issuer', described.issuer);
  html += row('Serial Number', described.serialHex);
  html += row('Version', 'v' + described.version);
  html += row('Not Before', described.notBefore);
  html += row('Not After', described.notAfter);
  html += row('Signature Algorithm', described.signatureAlgorithm + ' (' +
      described.signatureAlgorithmOid + ')');
  html += row('Public Key', described.publicKey);
  html += row('Public Key Algorithm', described.publicKeyAlgorithm);
  html += row('Self-signed', described.selfSigned ? 'yes' : 'no');
  // Null rather than absent when this browser has no Web Crypto — see
  // fingerprintsOf() in x509.js. The rows stay so that the table does not
  // quietly change shape.
  html += row('SHA-1 Fingerprint', described.fingerprints.sha1 ||
      '(needs Web Crypto, which this page does not have here)');
  html += row('SHA-256 Fingerprint', described.fingerprints.sha256 ||
      '(needs Web Crypto, which this page does not have here)');
  described.extensions.forEach(function (ext) {
    html += row('Extension: ' + ext.name + (ext.critical ? ' (critical)' : ''),
        x509.extensionValueText(ext));
  });
  html += '</table>';
  html += '<div class="saml-field" ' +
      'style="margin-top:10px;"><label>PEM</label><textarea rows="8" ' +
      'readonly>' + esc(pem.trim()) + '</textarea></div>';

  el('saml_cert_details').innerHTML = html;
  setVal('saml_cert_status', 'Parsed. ' + described.publicKey + ', signed ' +
      'with ' + described.signatureAlgorithm + '.');
  log.debug("Leaving renderCert(). " + described.extensions.length +
      " extension(s).");
}

function copyField(id) {
  log.debug("Entering copyField().");
  var e = el(id);
  if (!e) {
    log.debug("Leaving copyField().");
    return false;
  }
  var text = e.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error(
                                  'copyField: ' + err); });
  } else {
    try {
      e.focus();
      e.select();
      document.execCommand('copy');
    } catch (err) {
      log.error('copyField fallback: ' + err.message);
    }
  }
  log.debug("Leaving copyField().");
  return false;
}

function setReturnLink() {
  log.debug("Entering setReturnLink().");
  var from = new URLSearchParams(window.location.search).get('from');
  // Map each caller to its href AND a human label — the return link must read
  // "← Return to SAML Test Tools", not the raw "...to saml_request.html".
  var allowed = {
    'saml_request.html':      { href: '/saml_request.html',
                               label: 'SAML Test Tools' },
    'saml_tools.html':        { href: '/saml_tools.html',
                               label: 'SAML Assertion Tool' },
    'saml_response.html':     { href: '/saml_response.html',
                               label: 'SAML Response' },
    'wstrust_tools.html':     { href: '/wstrust_tools.html',
                               label: 'WS-Trust Test Tools' },
    'wstrust_response.html':  { href: '/wstrust_response.html',
                               label: 'WS-Trust Response' },
    'wsfed_request.html':       { href: '/wsfed_request.html',
                                 label: 'WS-Federation Test Tools' },
    'wsfed_response.html':    { href: '/wsfed_response.html',
                               label: 'WS-Federation Response' },
    'digital_signature.html': { href: '/digital_signature.html',
                               label: 'Digital Signature (SLH-DSA)' },
    'jwt_tools.html':         { href: '/jwt_tools.html',
                               label: 'JWT Tools' },
    'pki.html':               { href: '/pki.html',
                               label: 'Certificate Authority & X.509 Tools' }
  };
  var link = el('return_link');
  if (link && allowed[from]) {
    link.setAttribute('href', allowed[from].href);
    link.textContent = '← Return to ' + allowed[from].label;
  }
  log.debug("Leaving setReturnLink().");
}

window.onload = function () {
  log.debug("Entering onload().");
  setReturnLink();
  // Pre-fill the certificate to view, then auto-parse. Any key-pair page stores
  // the cert to inspect in 'saml_cert_view'; fall back to the SAML signer cert.
  if (window.localStorage) {
    var saved = localStorage.getItem('saml_cert_view') ||
        localStorage.getItem('samltools_saml_signer_cert');
    if (saved && !val('saml_cert_input')) setVal('saml_cert_input', saved);
  }
  if (val('saml_cert_input')) parseCert();
  log.debug("Leaving onload().");
};

module.exports = {
  parseCert,
  copyField
};
