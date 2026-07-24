// File: saml_response.js
// Author: Robert C. Broeckelmann Jr.
//
// SAML Response debugger page. The API ACS endpoint stashes the IdP's
// SAMLResponse and redirects here with ?id=<stash id>; this page fetches the
// stashed XML (GET /samlresponse?id=), shows the full response and the extracted
// assertion, and lists the assertion attributes (incl. NameID) in a table.
//
// As a fallback it also accepts the base64 SAMLResponse directly in the query
// (?SAMLResponse=) for manual testing.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var xd = require("./xmldsig");
var log = bunyan.createLogger({ name: 'saml_response', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// Signer certificate extracted from the response-level <Signature>; handed to
// the certificate-details page via localStorage when "View" is clicked.
var responseSignerCertPem = '';

// The last successfully-rendered SAMLResponse/LogoutResponse XML, cached in
// localStorage so returning to this page (e.g. from the certificate-details
// page, which drops the ?id= query param) can repopulate the fields.
var SAML_RESP_KEY = 'saml_last_response';

// The extracted <Assertion> as originally serialized (NOT the pretty-printed
// textarea value, whose added whitespace would break canonicalization) — used
// by the signature-validation option.
var lastAssertionXml = '';

// The first <xenc:EncryptedData> in the response (an EncryptedAssertion, or a
// message/wrapper-level EncryptedData), serialized — used by the decrypt option.
var lastEncryptedXml = '';

function el(id) { return document.getElementById(id); }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function setStatus(msg) { setVal('saml_resp_status', msg); }
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function qp(name) { return new URLSearchParams(window.location.search).get(name); }
function tags(root, localName) { return root.getElementsByTagNameNS('*', localName); }

// Minimal, dependency-free XML pretty-printer.
function formatXml(xml) {
  if (!xml) return '';
  var reg = /(>)(<)(\/*)/g;
  xml = xml.replace(reg, '$1\n$2$3');
  var pad = 0, out = '';
  xml.split('\n').forEach(function (node) {
    var indent = 0;
    if (/^<\/\w/.test(node)) { pad = Math.max(pad - 1, 0); }
    else if (/^<\w[^>]*[^\/]>.*$/.test(node) && !/<\/\w/.test(node)) { indent = 1; }
    out += new Array(pad + 1).join('  ') + node + '\n';
    pad += indent;
  });
  return out.trim();
}

function serialize(node) {
  try { return new XMLSerializer().serializeToString(node); } catch (e) { return ''; }
}

// --- decoding a SAMLResponse handed in via the URL query --------------------
// Backendless (static) deployments have no ACS server: the IdP is asked to
// return its response over the HTTP-Redirect binding, so it arrives here as a
// GET ?SAMLResponse= parameter that we decode in the browser. Redirect-binding
// messages are DEFLATE-compressed then base64-encoded; POST-binding messages
// (or a value pasted in for manual testing) are just base64. decodeSamlParam()
// tries inflate first and falls back to a plain base64 decode.
function base64ToBytes(b64) {
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bytesToUtf8(bytes) {
  try { return new TextDecoder('utf-8').decode(bytes); }
  catch (e) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    try { return decodeURIComponent(escape(s)); } catch (e2) { return s; }
  }
}
// RAW DEFLATE inflate (no zlib header) via the native DecompressionStream —
// the mirror of the deflate-raw saml_tools.js uses to build a Redirect request.
function inflateRaw(bytes) {
  if (typeof DecompressionStream === 'undefined') {
    return Promise.reject(new Error('This browser lacks DecompressionStream; cannot inflate a Redirect-binding response.'));
  }
  var ds = new DecompressionStream('deflate-raw');
  var writer = ds.writable.getWriter();
  writer.write(bytes);
  writer.close();
  return new Response(ds.readable).arrayBuffer().then(function (buf) {
    return bytesToUtf8(new Uint8Array(buf));
  });
}
function decodeSamlParam(b64) {
  var bytes;
  try { bytes = base64ToBytes(b64); }
  catch (e) { return Promise.reject(new Error('not valid base64: ' + e.message)); }
  return inflateRaw(bytes)
    // A successful inflate that yields XML is a Redirect-binding message; if the
    // bytes weren't actually deflated, treat the base64 as a raw (POST) message.
    .then(function (xml) { return (xml && xml.indexOf('<') >= 0) ? xml : bytesToUtf8(bytes); })
    .catch(function () { return bytesToUtf8(bytes); });
}

function render(responseXml) {
  setVal('saml_resp_xml', formatXml(responseXml));

  var doc = new DOMParser().parseFromString(responseXml, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    setStatus('Response received, but XML is malformed.');
    return;
  }

  // Cache so a return trip to this page (which may lack the ?id=) repopulates.
  try { if (window.localStorage) localStorage.setItem(SAML_RESP_KEY, responseXml); } catch (e) { /* ignore */ }

  // The root element is the protocol message: <Response> (login) or
  // <LogoutResponse> (SLO) — both carry Version/IssueInstant/InResponseTo/ID/
  // Issuer/Signature/Status; only a login Response carries an <Assertion>.
  var msgType = doc.documentElement ? doc.documentElement.localName : '';
  var isLogout = msgType === 'LogoutResponse';

  buildResponseDetailsTable(doc);

  var assertion = tags(doc, 'Assertion')[0];
  var assertionXml = assertion ? serialize(assertion) : '';
  lastAssertionXml = assertionXml;

  // Detect an encrypted assertion / message-level EncryptedData for the decrypt
  // option (the response may carry <saml:EncryptedAssertion> instead of a
  // plaintext <Assertion>).
  // Prefer the <saml:EncryptedAssertion> wrapper (it also contains any sibling
  // <xenc:EncryptedKey> referenced by RetrievalMethod), else the bare EncryptedData.
  var encEl = tags(doc, 'EncryptedAssertion')[0] || tags(doc, 'EncryptedData')[0];
  lastEncryptedXml = encEl ? serialize(encEl) : '';
  if (encEl && !assertion) {
    setVal('saml_dec_status', 'Response contains encrypted content — paste/confirm the recipient key and click Decrypt.');
  }
  var noAssertionNote = isLogout
    ? '(LogoutResponse carries no assertion — see the Details tab for the logout status.)'
    : '(no <Assertion> — the response may be an error or encrypted)';
  setVal('saml_assertion_xml', assertionXml ? formatXml(assertionXml) : noAssertionNote);

  buildAttributesTable(assertion);
  saveSubjectForLogout(assertion);
  setStatus((msgType || 'Response') + ' loaded.');
}

// Persist the NameID + SessionIndex so the config page's Single Logout can build
// a LogoutRequest for this session.
function saveSubjectForLogout(assertion) {
  if (!assertion || !window.localStorage) return;
  var subj = tags(assertion, 'Subject')[0];
  var nameId = subj ? tags(subj, 'NameID')[0] : null;
  if (nameId) {
    localStorage.setItem('saml_last_nameid', (nameId.textContent || '').trim());
    localStorage.setItem('saml_last_nameid_format', nameId.getAttribute('Format') || '');
  }
  var authn = tags(assertion, 'AuthnStatement')[0];
  if (authn) localStorage.setItem('saml_last_session_index', authn.getAttribute('SessionIndex') || '');
}

function row(cells) {
  return '<tr>' + cells.map(function (c) { return '<td>' + c + '</td>'; }).join('') + '</tr>';
}

function buildAttributesTable(assertion) {
  var container = el('saml_attrs_table');
  if (!assertion) { container.innerHTML = '<em>No assertion available.</em>'; return; }

  var html = '<table class="saml-table"><tr><th>Name</th><th>Value(s)</th><th>Format</th><th>FriendlyName</th></tr>';

  // Assertion metadata.
  html += row(['<span class="saml-key">Assertion ID</span>', esc(assertion.getAttribute('ID') || ''), '', '']);
  html += row(['<span class="saml-key">IssueInstant</span>', esc(assertion.getAttribute('IssueInstant') || ''), '', '']);

  // Conditions: validity window plus every restriction (Audience, etc.). Wrapped
  // so an unexpected condition shape can never blank the whole table (which would
  // drop the NameID/attribute rows built below).
  try {
    var cond = tags(assertion, 'Conditions')[0];
    if (cond) {
      if (cond.getAttribute('NotBefore')) {
        html += row(['<span class="saml-key">Conditions NotBefore</span>', esc(cond.getAttribute('NotBefore')), '', '']);
      }
      if (cond.getAttribute('NotOnOrAfter')) {
        html += row(['<span class="saml-key">Conditions NotOnOrAfter</span>', esc(cond.getAttribute('NotOnOrAfter')), '', '']);
      }
      var cc = cond.firstChild;
      while (cc) {
        if (cc.nodeType === 1) {
          if (cc.localName === 'AudienceRestriction') {
            var auds = tags(cc, 'Audience'), list = [];
            for (var ci = 0; ci < auds.length; ci++) { list.push(esc((auds[ci].textContent || '').trim())); }
            html += row(['<span class="saml-key">Condition: AudienceRestriction</span>', list.join('<br>'), '', '']);
          } else {
            html += row(['<span class="saml-key">Condition: ' + esc(cc.localName) + '</span>', esc((cc.textContent || '').trim()) || '(present)', '', '']);
          }
        }
        cc = cc.nextSibling;
      }
    }
  } catch (e) {
    log.error('buildAttributesTable conditions: ' + e.message);
  }

  // NameID (from Subject) shown first.
  var subj = tags(assertion, 'Subject')[0];
  if (subj) {
    var nameId = tags(subj, 'NameID')[0];
    if (nameId) {
      html += row([
        '<span class="saml-key">NameID</span>',
        esc((nameId.textContent || '').trim()),
        esc(nameId.getAttribute('Format') || ''),
        ''
      ]);
    }
  }

  // Attributes from every AttributeStatement.
  var attrs = tags(assertion, 'Attribute');
  for (var i = 0; i < attrs.length; i++) {
    var a = attrs[i];
    var vals = tags(a, 'AttributeValue');
    var valStrs = [];
    for (var j = 0; j < vals.length; j++) { valStrs.push(esc((vals[j].textContent || '').trim())); }
    html += row([
      esc(a.getAttribute('Name') || ''),
      valStrs.join('<br>'),
      esc(a.getAttribute('NameFormat') || ''),
      esc(a.getAttribute('FriendlyName') || '')
    ]);
  }
  html += '</table>';
  container.innerHTML = html;
}

// Two-column key/value row (value may already contain HTML).
function kv(k, v) { return '<tr><td class="saml-key">' + esc(k) + '</td><td>' + v + '</td></tr>'; }

// Text of a direct-child element by local name (avoids grabbing a nested
// element of the same name, e.g. the assertion's Issuer vs the response's).
function directChildText(parent, localName) {
  var kids = parent.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === localName) return (kids[i].textContent || '').trim();
  }
  return '';
}

// The X509Certificate from the response-level <Signature> (a direct child of
// <Response>), not the assertion's signature.
function responseSignerCert(responseEl) {
  var kids = responseEl.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === 'Signature') {
      var c = tags(kids[i], 'X509Certificate')[0];
      return c ? (c.textContent || '').replace(/\s+/g, '') : '';
    }
  }
  return '';
}

function buildResponseDetailsTable(doc) {
  var container = el('saml_resp_details');
  // The document root is the protocol message (Response / LogoutResponse / …).
  var msg = doc.documentElement;
  if (!msg) { container.innerHTML = '<em>No SAML message element found.</em>'; return; }

  var certB64 = responseSignerCert(msg);
  responseSignerCertPem = certB64; // saml_cert.js accepts bare base64 DER

  var certCell;
  if (certB64) {
    certCell = '<a href="/saml_cert.html?from=saml_response.html" onclick="return saml_response.viewSignerCert();">View certificate details &rarr;</a>' +
      '<div style="word-break:break-all; font-size:0.85em; margin-top:4px;">' +
      esc(certB64.substring(0, 96)) + (certB64.length > 96 ? '…' : '') + '</div>';
  } else {
    certCell = '<em>(not signed / no certificate)</em>';
  }

  var html = '<table class="saml-table">';
  html += kv('Message Type', esc(msg.localName || ''));
  html += kv('SAML Version', esc(msg.getAttribute('Version') || ''));
  html += kv('Issue Date (IssueInstant)', esc(msg.getAttribute('IssueInstant') || ''));
  html += kv('In Response To', esc(msg.getAttribute('InResponseTo') || ''));
  html += kv('ID', esc(msg.getAttribute('ID') || ''));
  var dest = msg.getAttribute('Destination') || '';
  if (dest) html += kv('Destination', esc(dest));
  html += kv('Issuer', esc(directChildText(msg, 'Issuer')));
  html += kv('Signer Certificate', certCell);
  html += kv('SAML Status', statusHtml(msg));
  html += '</table>';
  container.innerHTML = html;
}

// Render <samlp:Status>: a colored friendly label for the top-level StatusCode,
// the full code URI, an optional nested (second-level) StatusCode, and any
// StatusMessage — this is the key result for a LogoutResponse and error responses.
function statusHtml(msg) {
  var statusEl = tags(msg, 'Status')[0];
  if (!statusEl) return '<em>(no Status)</em>';
  var codes = tags(statusEl, 'StatusCode');
  var top = codes[0] ? (codes[0].getAttribute('Value') || '') : '';
  var sub = codes[1] ? (codes[1].getAttribute('Value') || '') : '';
  var smEl = tags(statusEl, 'StatusMessage')[0];
  var sm = smEl ? (smEl.textContent || '').trim() : '';

  var isSuccess = top.indexOf(':status:Success') >= 0;
  var out = '<strong style="color:' + (isSuccess ? '#2e7d32' : '#b00') + ';">' + esc(shortStatus(top)) + '</strong>';
  if (top) out += ' <span style="color:#888; word-break:break-all;">' + esc(top) + '</span>';
  if (sub) out += '<br>Sub-status: ' + esc(sub);
  if (sm) out += '<br>Message: ' + esc(sm);
  return out;
}

// Last segment of a SAML status URI (…:status:Success -> "Success").
function shortStatus(uri) {
  if (!uri) return '(none)';
  var i = uri.lastIndexOf(':');
  return i >= 0 ? uri.substring(i + 1) : uri;
}

function viewSignerCert() {
  if (!responseSignerCertPem) return false;
  try { if (window.localStorage) localStorage.setItem('saml_cert_view', responseSignerCertPem); } catch (e) { /* ignore */ }
  window.open('/saml_cert.html?from=saml_response.html', '_blank');
  return false;
}

// Tab switching scoped to the pane containing the clicked tab, so the two tab
// groups (SAMLResponse pane, Assertion pane) toggle independently.
function showTab(evt, tabId) {
  var target = el(tabId);
  var scope = (target && target.closest && target.closest('.saml-pane')) || document;
  var contents = scope.getElementsByClassName('saml-tabcontent');
  for (var i = 0; i < contents.length; i++) { contents[i].style.display = 'none'; }
  var links = scope.getElementsByClassName('tablinks');
  for (var k = 0; k < links.length; k++) { links[k].className = links[k].className.replace(' active', ''); }
  if (target) target.style.display = 'block';
  if (evt && evt.currentTarget) evt.currentTarget.className += ' active';
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

// Repopulate from the last response saved in localStorage. Returns true if a
// cached response was found and rendered.
function renderFromStorage(msgIfMissing) {
  var saved = null;
  try { saved = window.localStorage && localStorage.getItem(SAML_RESP_KEY); } catch (e) { saved = null; }
  if (saved) { render(saved); return true; }
  if (msgIfMissing) setStatus(msgIfMissing);
  return false;
}

// Render a signature-verification result (from xd.verifyXmlSignature) as a table.
function formatSigResult(res) {
  if (res.error) return '<span style="color:#b00;">Cannot validate: ' + esc(res.error) + '</span>';
  var color = res.valid ? '#2e7d32' : '#b00';
  var refs = (res.references || []).length;
  var html = '<table class="saml-table">';
  html += '<tr><td class="saml-key">Signature</td><td><strong style="color:' + color + ';">' + (res.valid ? 'VALID' : 'INVALID') + '</strong></td></tr>';
  html += '<tr><td class="saml-key">SignatureValue</td><td>' + (res.signatureValid ? 'verified' : 'FAILED') + '</td></tr>';
  html += '<tr><td class="saml-key">Reference digests</td><td>' + (res.referencesValid ? 'match' : 'MISMATCH') + ' (' + refs + ')</td></tr>';
  html += '<tr><td class="saml-key">Signature Method</td><td>' + esc(res.signatureMethod || '') + '</td></tr>';
  html += '<tr><td class="saml-key">Canonicalization</td><td>' + esc(res.canonicalization || '') + '</td></tr>';
  html += '<tr><td class="saml-key">Signer (cert CN)</td><td>' + esc(res.signerSubject || '(from KeyInfo)') + '</td></tr>';
  html += '</table>';
  return html;
}

// Validate the enveloped XML digital signature on the extracted assertion, using
// the certificate embedded in the signature's KeyInfo. Reuses xmldsig.js.
function validateAssertionSignature() {
  var details = el('saml_sig_details');
  if (!lastAssertionXml || lastAssertionXml.indexOf('<') < 0) {
    setVal('saml_sig_status', 'No assertion available to validate.');
    if (details) details.innerHTML = '';
    return false;
  }
  var res;
  try { res = xd.verifyXmlSignature(lastAssertionXml); }
  catch (e) { setVal('saml_sig_status', 'Validation error: ' + e.message); return false; }
  setVal('saml_sig_status', res.error ? ('Cannot validate: ' + res.error) : (res.valid ? 'Assertion signature VALID.' : 'Assertion signature INVALID.'));
  if (details) details.innerHTML = formatSigResult(res);
  return false;
}

// Decrypt an <xenc:EncryptedData> / <saml:EncryptedAssertion> in the response
// with the recipient (SP) private key, then show + re-render the plaintext
// assertion. Reuses xmldsig.js decryptXml.
function decryptAssertion() {
  if (!lastEncryptedXml) { setVal('saml_dec_status', 'No <xenc:EncryptedData> / <saml:EncryptedAssertion> found in this response.'); return false; }
  var keyEl = el('saml_dec_key');
  var key = keyEl ? keyEl.value : '';
  if (!key.trim()) { setVal('saml_dec_status', 'Paste the recipient (SP) private key to decrypt.'); return false; }
  var plaintext;
  try { plaintext = xd.decryptXml(lastEncryptedXml, { privateKeyPem: key }); }
  catch (e) { setVal('saml_dec_status', 'Decryption failed: ' + e.message); return false; }
  lastAssertionXml = plaintext;
  setVal('saml_assertion_xml', formatXml(plaintext));
  try {
    var adoc = new DOMParser().parseFromString(plaintext, 'application/xml');
    var a = tags(adoc, 'Assertion')[0] || null;
    buildAttributesTable(a);
    saveSubjectForLogout(a);
  } catch (e) { log.error('decrypt render: ' + e.message); }
  setVal('saml_dec_status', 'Decrypted. The assertion is shown in the XML tab; use Validate Signature to verify it.');
  return false;
}

window.onload = function () {
  // Prefill the decryption key from the SP private key stored by the SAML Test
  // Tools page (the IdP encrypts to the SP's certificate).
  try {
    var dk = el('saml_dec_key');
    var sk = window.localStorage && localStorage.getItem('samltools_saml_sp_private_key');
    if (dk && !dk.value && sk) dk.value = sk;
  } catch (e) { /* ignore */ }

  var id = qp('id');
  var direct = qp('SAMLResponse');
  if (id) {
    setStatus('Loading response…');
    fetch(appconfig.apiUrl + '/samlresponse?id=' + encodeURIComponent(id))
      .then(function (r) { if (!r.ok) { throw new Error('HTTP ' + r.status); } return r.json(); })
      .then(function (j) {
        // Stash expired/unknown — fall back to the last response we cached.
        if (!j || !j.responseXml) {
          if (!renderFromStorage()) setStatus('No response found for that id (it may have expired).');
          return;
        }
        render(j.responseXml);
      })
      .catch(function (e) {
        log.error('fetch response: ' + e.message);
        if (!renderFromStorage()) setStatus('Failed to load response: ' + e.message);
      });
  } else if (direct) {
    setStatus('Decoding SAMLResponse…');
    decodeSamlParam(direct)
      .then(function (xml) { render(xml); })
      .catch(function (e) {
        log.error('decode SAMLResponse: ' + e.message);
        setStatus('Could not decode SAMLResponse parameter: ' + e.message);
      });
  } else {
    // No id/param (e.g. returned from the certificate-details page, which drops
    // the ?id=) — repopulate the fields from the last cached response.
    renderFromStorage('No response id in the URL. Start from the SAML Test Tools page and click "Call IdP".');
  }
};

module.exports = {
  showTab,
  viewSignerCert,
  copyField,
  validateAssertionSignature,
  decryptAssertion
};
