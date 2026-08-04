// File: wstrust_response.js
//
// WS-Trust response debugger. The config page (wstrust_tools.js) sends the SOAP
// RequestSecurityToken to the STS, stashes the request + the STS reply (RSTR)
// in localStorage under 'wstrust_last_exchange', and navigates here. This page
// renders:
//   * Request (RST)  — the SOAP request that was sent, pretty-printed.
//   * Response (RSTR) — the full SOAP reply, pretty-printed.
//   * Fields          — the important WS-Trust fields (operation, RSTR action,
//                       token type, lifetime, key type, AppliesTo, and — for
//                       Validate/Cancel — the status / cancelled marker).
//   * Token           — the security token extracted from
//                       <wst:RequestedSecurityToken>, as XML and (for SAML/JWT)
//                       decoded details.

var appconfig = require(process.env.CONFIG_FILE);
var history = require("./wstrust_history");
var bunyan = require("bunyan");
var xd = require("./xmldsig");
var log = bunyan.createLogger({ name: 'wstrust_response', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var EXCHANGE_KEY = "wstrust_last_exchange";

// Signer certificate (bare base64 DER) extracted from the issued token's
// <ds:Signature>; handed to the certificate-details page via localStorage when
// "View certificate details" is clicked.
var tokenSignerCertB64 = '';

// The issued token as originally serialized (NOT the pretty-printed textarea
// value) — used by the signature-validation option.
var lastTokenXml = '';

// The first <xenc:EncryptedData> in the response (an encrypted token /
// EncryptedAssertion, or a message/wrapper-level EncryptedData), serialized —
// used by the decrypt option.
var lastEncryptedXml = '';

function el(id) { return document.getElementById(id); }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function setStatus(msg) { setVal('wst_resp_status', msg); }
function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function tags(root, localName) { return root.getElementsByTagNameNS('*', localName); }

function formatXml(xml) {
  log.debug("Entering formatXml().");
  if (!xml) return '';
  xml = xml.replace(/(>)(<)(\/*)/g, '$1\n$2$3');
  var pad = 0, out = '';
  xml.split('\n').forEach(function (node) {
    var indent = 0;
    if (/^<\/\w/.test(node)) { pad = Math.max(pad - 1, 0); }
    else if (/^<\w[^>]*[^\/]>.*$/.test(node) && !/<\/\w/.test(node)) { indent = 1; }
    out += new Array(pad + 1).join('  ') + node + '\n';
    pad += indent;
  });
  log.debug("Leaving formatXml().");
  return out.trim();
}
function serialize(node) {
try {
  return new XMLSerializer().serializeToString(node);
} catch (e) {
  return '';
} }
function row(k, v) { return '<tr><td class="saml-key">' + esc(k) + '</td><td>' + v + '</td></tr>'; }
function firstText(root, localName) { var e = tags(root, localName)[0]; return e ? (e.textContent || '').trim() : ''; }

// The security token carried in the response: the first element child of
// <wst:RequestedSecurityToken> (a SAML Assertion, a wsse:BinarySecurityToken,
// an EncryptedAssertion, etc.).
function extractToken(doc) {
  var holder = tags(doc, 'RequestedSecurityToken')[0];
  if (!holder) return null;
  var c = holder.firstChild;
  while (c) { if (c.nodeType === 1) return c; c = c.nextSibling; }
  return null;
}

// base64url / base64 JWT segment decode.
function b64urlDecode(s) {
  log.debug("Entering b64urlDecode().");
  s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    return decodeURIComponent(escape(atob(s)));
  } catch (e) {
    try {
      return atob(s);
    } catch (e2) {
      // Not base64 either: there is nothing to show.
      return '';
    }
  }
  log.debug("Leaving b64urlDecode().");
}
function looksLikeJwt(s) { return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(String(s || '').trim()); }

function buildFieldsTable(doc, meta) {
  log.debug("Entering buildFieldsTable().");
  var container = el('wst_fields_table');
  var root = doc.documentElement;
  if (!root) { container.innerHTML = '<em>No SOAP response to parse.</em>'; return; }

  var html = '<table class="saml-table">';
  html += row('Operation', esc(meta.operation || ''));
  html += row('SOAP Version', esc(meta.soapVersion || ''));
  html += row('HTTP Status', esc(String(meta.httpStatus == null ? '' : meta.httpStatus)));
  html += row('STS URL', esc(meta.stsUrl || ''));
  html += row('Sent At', esc(meta.sentAt || ''));

  var action = firstText(root, 'Action');
  if (action) html += row('Response wsa:Action', esc(action));

  // SOAP Fault?
  var fault = tags(root, 'Fault')[0];
  if (fault) {
    var reason = firstText(fault, 'Reason') || firstText(fault, 'faultstring') || firstText(fault, 'Text');
    var code = firstText(fault, 'Value') || firstText(fault, 'faultcode');
    html += row('SOAP Fault', '<strong style="color:#b00;">' + esc(code || 'Fault') + '</strong>' + (reason ? '<br>' + esc(reason) : ''));
  }

  var tokenType = firstText(root, 'TokenType');
  if (tokenType) html += row('TokenType', esc(tokenType));

  var keyType = firstText(root, 'KeyType');
  if (keyType) html += row('KeyType', esc(keyType));

  var applies = tags(root, 'AppliesTo')[0];
  if (applies) html += row('AppliesTo', esc((firstText(applies, 'Address') || (applies.textContent || '')).trim()));

  var lifetime = tags(root, 'Lifetime')[0];
  if (lifetime) {
    html += row('Lifetime Created', esc(firstText(lifetime, 'Created')));
    html += row('Lifetime Expires', esc(firstText(lifetime, 'Expires')));
  }

  // Validate → <wst:Status><wst:Code>.
  var statusEl = tags(root, 'Status')[0];
  if (statusEl) {
    var codeUri = firstText(statusEl, 'Code');
    var reasonTxt = firstText(statusEl, 'Reason');
    var valid = /\/status\/valid$/.test(codeUri);
    html += row('Validation Status',
      '<strong style="color:' + (valid ? '#2e7d32' : '#b00') + ';">' + esc(valid ? 'valid' : 'invalid') + '</strong>' +
      (codeUri ? ' <span style="color:#888;word-break:break-all;">' + esc(codeUri) + '</span>' : '') +
      (reasonTxt ? '<br>' + esc(reasonTxt) : ''));
  }

  // Cancel → <wst:RequestedTokenCancelled/>.
  if (tags(root, 'RequestedTokenCancelled')[0]) {
    html += row('Cancel Result', '<strong style="color:#2e7d32;">RequestedTokenCancelled</strong>');
  }

  html += '</table>';
  container.innerHTML = html;
  log.debug("Leaving buildFieldsTable().");
}

function buildTokenDetails(tokenEl) {
  log.debug("Entering buildTokenDetails().");
  var container = el('wst_token_details');
  if (!tokenEl) { container.innerHTML = '<em>No token in the response.</em>'; return; }

  var local = tokenEl.localName || '';

  // SAML assertion → subject / conditions / attributes.
  if (local === 'Assertion') {
    var html = '<table class="saml-table"><tr><th>Field</th><th>Value</th></tr>';
    html += row('Assertion ID', esc(tokenEl.getAttribute('ID') || tokenEl.getAttribute('AssertionID') || ''));
    html += row('IssueInstant', esc(tokenEl.getAttribute('IssueInstant') || ''));
    html += row('Issuer', esc(firstText(tokenEl, 'Issuer')));

    // Signer certificate from the assertion's <ds:Signature> (KeyInfo/X509Data).
    tokenSignerCertB64 = '';
    var tokenSig = tags(tokenEl, 'Signature')[0];
    if (tokenSig) {
      var x509 = tags(tokenSig, 'X509Certificate')[0];
      if (x509) tokenSignerCertB64 = (x509.textContent || '').replace(/\s+/g, '');
    }
    var certCell;
    if (tokenSignerCertB64) {
      certCell = '<a href="/saml_cert.html?from=wstrust_response.html" onclick="return wstrust_response.viewSignerCert();">View certificate details &rarr;</a>' +
        '<div style="word-break:break-all; font-size:0.85em; margin-top:4px;">' +
        esc(tokenSignerCertB64.substring(0, 96)) + (tokenSignerCertB64.length > 96 ? '…' : '') + '</div>';
    } else {
      certCell = '<em>(not signed / no certificate)</em>';
    }
    html += row('Signer Certificate', certCell);

    var subj = tags(tokenEl, 'Subject')[0];
    if (subj) {
      var nameId = tags(subj, 'NameID')[0] || tags(subj, 'NameIdentifier')[0];
      if (nameId) html += row('Subject NameID', esc((nameId.textContent || '').trim()));
      // SubjectConfirmation (Method + any SubjectConfirmationData attributes).
      var sc = tags(subj, 'SubjectConfirmation')[0];
      if (sc) {
        html += row('SubjectConfirmation Method', esc(sc.getAttribute('Method') || ''));
        var scd = tags(sc, 'SubjectConfirmationData')[0];
        if (scd) {
          if (scd.getAttribute('Recipient')) html += row('SubjectConfirmation Recipient', esc(scd.getAttribute('Recipient')));
          if (scd.getAttribute('NotOnOrAfter')) html += row('SubjectConfirmation NotOnOrAfter', esc(scd.getAttribute('NotOnOrAfter')));
          if (scd.getAttribute('InResponseTo')) html += row('SubjectConfirmation InResponseTo', esc(scd.getAttribute('InResponseTo')));
        }
      }
    }
    var cond = tags(tokenEl, 'Conditions')[0];
    if (cond) {
      if (cond.getAttribute('NotBefore')) html += row('Conditions NotBefore', esc(cond.getAttribute('NotBefore')));
      if (cond.getAttribute('NotOnOrAfter')) html += row('Conditions NotOnOrAfter', esc(cond.getAttribute('NotOnOrAfter')));
      // AudienceRestriction → one row per Audience.
      var auds = tags(cond, 'Audience');
      for (var ai = 0; ai < auds.length; ai++) html += row('AudienceRestriction Audience', esc((auds[ai].textContent || '').trim()));
    }
    // AuthnStatement → AuthnContextClassRef (how the subject authenticated).
    var accr = tags(tokenEl, 'AuthnContextClassRef')[0];
    if (accr) html += row('AuthnContextClassRef', esc((accr.textContent || '').trim()));

    var attrs = tags(tokenEl, 'Attribute');
    for (var i = 0; i < attrs.length; i++) {
      var a = attrs[i];
      var vals = tags(a, 'AttributeValue'), vs = [];
      for (var j = 0; j < vals.length; j++) vs.push(esc((vals[j].textContent || '').trim()));
      html += row('Attribute: ' + esc(a.getAttribute('Name') || a.getAttribute('AttributeName') || ''), vs.join('<br>'));
    }
    html += '</table>';
    container.innerHTML = html;
    return;
  }

  // JWT (often carried in a wsse:BinarySecurityToken text node, or a raw string).
  var raw = (tokenEl.textContent || '').trim();
  if (looksLikeJwt(raw)) {
    var parts = raw.split('.');
    var hdr = b64urlDecode(parts[0]);
    var pl = b64urlDecode(parts[1]);
    var html2 = '<table class="saml-table"><tr><th>Segment</th><th>Decoded</th></tr>';
    html2 += row('Header', '<pre style="white-space:pre-wrap;margin:0;">' + esc(prettyJson(hdr)) + '</pre>');
    html2 += row('Payload', '<pre style="white-space:pre-wrap;margin:0;">' + esc(prettyJson(pl)) + '</pre>');
    html2 += '</table>';
    container.innerHTML = html2;
    return;
  }

  container.innerHTML = '<em>Token type &lt;' + esc(local || '?') + '&gt; — see the Token XML tab.</em>';
  log.debug("Leaving buildTokenDetails().");
}

function prettyJson(s) {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch (e) {
    return s;
  }
}

function render(requestXml, responseXml, meta) {
  log.debug("Entering render().");
  meta = meta || {};
  setVal('wst_request_xml', formatXml(requestXml));
  setVal('wst_response_xml', formatXml(responseXml));

  var doc = new DOMParser().parseFromString(responseXml || '', 'application/xml');
  if (!responseXml || doc.getElementsByTagName('parsererror').length) {
    el('wst_fields_table').innerHTML = '<em>Response is empty or not well-formed XML — see the Response tab.</em>';
    el('wst_token_details').innerHTML = '<em>No token.</em>';
    setVal('wst_token_xml', responseXml ? '(response is not well-formed XML)' : '(no response)');
    setStatus('Response received (' + (meta.httpStatus == null ? '?' : meta.httpStatus) + ') — could not parse as XML.');
    return;
  }

  buildFieldsTable(doc, meta);

  // Detect an encrypted token for the decrypt option. Prefer the
  // <saml:EncryptedAssertion> wrapper (it also carries any sibling EncryptedKey),
  // else the bare EncryptedData.
  var encEl = tags(doc, 'EncryptedAssertion')[0] || tags(doc, 'EncryptedData')[0];
  lastEncryptedXml = encEl ? serialize(encEl) : '';
  if (encEl) setVal('wst_dec_status', 'Response contains encrypted content — paste/confirm the requestor key and click Decrypt.');

  var tokenEl = extractToken(doc);
  if (tokenEl) {
    // Keep the ORIGINAL serialized token (not the pretty-printed textarea value,
    // whose added whitespace would break canonicalization) for signature checks.
    lastTokenXml = serialize(tokenEl);
    setVal('wst_token_xml', formatXml(lastTokenXml));
    buildTokenDetails(tokenEl);
  } else {
    lastTokenXml = '';
    // Validate/Cancel responses carry no token — say so plainly.
    var op = meta.operation || '';
    var note = (op === 'validate' || op === 'cancel')
      ? '(' + op + ' responses carry no security token — see the Fields tab for the result.)'
      : '(no <wst:RequestedSecurityToken> in the response — see the Response tab.)';
    setVal('wst_token_xml', note);
    el('wst_token_details').innerHTML = '<em>' + esc(note) + '</em>';
  }

  setStatus((meta.operation || 'WS-Trust') + ' response loaded (HTTP ' + (meta.httpStatus == null ? '?' : meta.httpStatus) + ').');
  log.debug("Leaving render().");
}

function copyField(id) {
  log.debug("Entering copyField().");
  var e = el(id);
  if (!e) return false;
  var text = e.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error('copyField: ' + err); });
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

// Open the certificate-details page for the issued token's signer certificate.
// The cert (bare base64 DER) is handed over via localStorage ('saml_cert_view')
// and shown in a new tab — same mechanism the SAML pages use.
function viewSignerCert() {
  if (!tokenSignerCertB64) return false;
  try {
    if (window.localStorage) localStorage.setItem('saml_cert_view', tokenSignerCertB64);
  } catch (e) {
    // No storage available in this context.
  }
  window.open('/saml_cert.html?from=wstrust_response.html', '_blank');
  return false;
}

function showTab(evt, tabId) {
  log.debug("Entering showTab().");
  var target = el(tabId);
  var scope = (target && target.closest && target.closest('.saml-pane')) || document;
  var contents = scope.getElementsByClassName('saml-tabcontent');
  for (var i = 0; i < contents.length; i++) { contents[i].style.display = 'none'; }
  var links = scope.getElementsByClassName('tablinks');
  for (var k = 0; k < links.length; k++) { links[k].className = links[k].className.replace(' active', ''); }
  if (target) target.style.display = 'block';
  if (evt && evt.currentTarget) evt.currentTarget.className += ' active';
  log.debug("Leaving showTab().");
  return false;
}

// Render a signature-verification result (from xd.verifyXmlSignature) as a table.
function formatSigResult(res) {
  log.debug("Entering formatSigResult().");
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
  log.debug("Leaving formatSigResult().");
  return html;
}

// Validate the enveloped XML digital signature on the issued token (a SAML
// assertion), using the certificate embedded in the signature's KeyInfo.
function validateTokenSignature() {
  log.debug("Entering validateTokenSignature().");
  var details = el('wst_sig_details');
  if (!lastTokenXml || lastTokenXml.indexOf('<') < 0) {
    setVal('wst_sig_status', 'No XML token available to validate.');
    if (details) details.innerHTML = '';
    return false;
  }
  var res;
  try {
    res = xd.verifyXmlSignature(lastTokenXml);
  } catch (e) {
    setVal('wst_sig_status', 'Validation error: ' + e.message);
    return false;
  }
  setVal('wst_sig_status', res.error ? ('Cannot validate: ' + res.error) : (res.valid ? 'Token signature VALID.' : 'Token signature INVALID.'));
  if (details) details.innerHTML = formatSigResult(res);
  log.debug("Leaving validateTokenSignature().");
  return false;
}

// Decrypt an <xenc:EncryptedData> (an encrypted issued token / EncryptedAssertion,
// or a message-level EncryptedData) with the requestor private key, then show +
// re-render the plaintext token. Reuses xmldsig.js decryptXml.
function decryptToken() {
  log.debug("Entering decryptToken().");
  if (!lastEncryptedXml) { setVal('wst_dec_status', 'No <xenc:EncryptedData> found in this response.'); return false; }
  var keyEl = el('wst_dec_key');
  var key = keyEl ? keyEl.value : '';
  if (!key.trim()) { setVal('wst_dec_status', 'Paste the requestor private key to decrypt.'); return false; }
  var plaintext;
  try {
    plaintext = xd.decryptXml(lastEncryptedXml, { privateKeyPem: key });
  } catch (e) {
    setVal('wst_dec_status', 'Decryption failed: ' + e.message);
    return false;
  }
  lastTokenXml = plaintext;
  setVal('wst_token_xml', formatXml(plaintext));
  try {
    var d = new DOMParser().parseFromString(plaintext, 'application/xml');
    if (!d.getElementsByTagName('parsererror').length && d.documentElement) buildTokenDetails(d.documentElement);
  } catch (e) {
    log.error('decrypt render: ' + e.message);
  }
  setVal('wst_dec_status', 'Decrypted. Token shown in the Token XML tab; use Validate Signature to verify it.');
  log.debug("Leaving decryptToken().");
  return false;
}


// ---------------------------------------------------------------------------
// Operations History (shared with wstrust_tools.html): the tools page can only
// record that a request was dispatched — whether the STS issued a token or
// refused is known here. Close out the pending entry from the response.
//
// meta.historyId names the exact entry this exchange answers; it is cleared
// from the stored exchange once resolved, so redisplaying this page later
// cannot pin an old answer on a newer pending call.
// ---------------------------------------------------------------------------
function resolveHistory(doc, meta, parseError) {
  log.debug("Entering resolveHistory().");
  if (!meta || !meta.historyId) return;
  var result = history.SUCCESS;
  var detail = '';
  var status = (meta.httpStatus == null) ? '?' : meta.httpStatus;

  if (parseError || !doc) {
    result = history.FAILURE;
    detail = 'HTTP ' + status + ' — the response could not be parsed as XML';
  } else {
    var fault = tags(doc, 'Fault')[0];
    if (fault) {
      var code = firstText(fault, 'Value') || firstText(fault, 'faultcode');
      var reason = firstText(fault, 'Reason') || firstText(fault, 'faultstring') || firstText(fault, 'Text');
      result = history.FAILURE;
      detail = 'SOAP Fault' + (code ? ' ' + code : '') + (reason ? ' — ' + reason : '');
    } else if (typeof status === 'number' && status >= 400) {
      result = history.FAILURE;
      detail = 'HTTP ' + status;
    } else {
      // Issue/Renew must carry a token; Validate/Cancel answer with a status.
      var token = tags(doc, 'RequestedSecurityToken')[0];
      var statusEl = tags(doc, 'Status')[0];
      if (token) detail = 'HTTP ' + status + ' — token issued';
      else if (statusEl) detail = 'HTTP ' + status + ' — ' + (firstText(statusEl, 'Code') || 'status returned').split('/').pop();
      else {
        result = history.FAILURE;
        detail = 'HTTP ' + status + ' — no RequestedSecurityToken and no Status in the RSTR';
      }
    }
  }
  history.update(meta.historyId, result, detail);
  renderOperationHistory();

  // One answer resolves one call: forget the id so a later visit to this page
  // (which redisplays the same stored exchange) cannot resolve anything else.
  try {
    if (window.localStorage) {
      var raw = localStorage.getItem(EXCHANGE_KEY);
      if (raw) {
        var ex = JSON.parse(raw);
        if (ex && ex.meta) { ex.meta.historyId = null; localStorage.setItem(EXCHANGE_KEY, JSON.stringify(ex)); }
      }
    }
  } catch (e) {
    // leave it; update() is idempotent for an already-resolved id
  }
  log.debug("Leaving resolveHistory().");
}

function renderOperationHistory() { history.render(el('wst_operation_history')); }

function clearOperationHistory() {
  history.clear();
  renderOperationHistory();
  return false;
}

window.onload = function () {
  log.debug("Entering onload().");
  renderOperationHistory();
  // Prefill the decryption key from the requestor private key stored by the
  // WS-Trust Test Tools page (the STS encrypts to the requestor's certificate).
  try {
    var dk = el('wst_dec_key');
    var sk = window.localStorage && localStorage.getItem('wstrust_wst_sp_private_key');
    if (dk && !dk.value && sk) dk.value = sk;
    // The Test Tools page can be told not to keep the key pair in localStorage,
    // in which case there is nothing to prefill from and the standing "Prefilled
    // from…" wording would be a promise this page did not keep. Say what is
    // actually true, so an empty field reads as expected rather than broken.
    // This page never WRITES the key: whatever is pasted here stays in the field.
    var note = el('wst_dec_key_note');
    if (note && dk && !dk.value) {
      note.textContent = 'If the STS returns an encrypted token, decrypt it in the browser with the ' +
        'requestor private key. Nothing was prefilled — either no key pair has been generated yet, ' +
        'or "Save this key pair in browser localStorage" is turned off on the WS-Trust Test Tools ' +
        'page. Paste the private key below.';
    }
  } catch (e) {
    // No storage, or nothing stashed by the WS-Trust Test Tools page: the field
    // is simply left for the user to paste into.
  }

  var saved = null;
  try {
    saved = window.localStorage && localStorage.getItem(EXCHANGE_KEY);
  } catch (e) {
    saved = null;
  }
  if (!saved) {
    setStatus('No WS-Trust exchange found. Start from the WS-Trust Test Tools page and click "Send Request".');
    return;
  }
  try {
    var ex = JSON.parse(saved);
    var meta = ex.meta || {};
    render(ex.requestXml || '', ex.responseXml || '', meta);
    // Close out the Operations History entry for this exchange.
    var doc = null, parseError = false;
    try {
      doc = new DOMParser().parseFromString(ex.responseXml || '', 'application/xml');
      if (!ex.responseXml || doc.getElementsByTagName('parsererror').length) { doc = null; parseError = true; }
    } catch (pe) {
      parseError = true;
    }
    resolveHistory(doc, meta, parseError);
  } catch (e) {
    log.error('parse exchange: ' + e.message);
    setStatus('Could not read the stored exchange: ' + e.message);
  }
  log.debug("Leaving onload().");
};

module.exports = {
  showTab,
  copyField,
  clearOperationHistory,
  viewSignerCert,
  validateTokenSignature,
  decryptToken
};
