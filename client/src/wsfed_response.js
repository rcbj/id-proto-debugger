// File: wsfed_response.js
//
// WS-Federation Passive Requestor Profile response debugger. In the passive
// profile the IdP authenticates the user and auto-POSTs a form (wa=wsignin1.0,
// wresult, wctx) to the RP's wreply URL. There are three ways that POST reaches
// this page, and it handles all three:
//
//   ?id=<stash>   the API /wsfed landing captured the POST server-side and
//                 stashed the wresult; this page fetches it by id.
//   ?posted=1     the STATIC deployments' Lambda@Edge landing
//                 (infra/edge/wsfed_landing.js) captured it at the edge and,
//                 having nowhere to stash it, handed it to the browser in
//                 sessionStorage under the edge_landing.js WSFED keys. This
//                 page reads them and DELETES them — a token left in storage
//                 would be replayed onto the next sign-in that failed.
//   neither       nothing captured it (a deployment with no landing at all):
//                 paste the wresult XML into the box.
//
// wresult is a WS-Trust RequestSecurityTokenResponse[Collection] carrying the
// issued SAML (1.1 or 2.0) assertion. This page renders:
//   * Response (wresult) — the full RSTR, pretty-printed.
//   * Fields             — the important WS-Trust/WS-Fed fields (context, RSTR
//                          action, token type, key type, AppliesTo, lifetime).
//   * Token XML          — the security token from <wst:RequestedSecurityToken>.
//   * Token Details      — decoded assertion (subject, conditions, attributes),
//                          Validate Signature, and Decrypt (EncryptedAssertion).
//
// Token extraction / rendering / signature-validation / decryption are lifted
// from wstrust_response.js (which already handles SAML 1.1 vs 2.0), reusing the
// shared xmldsig.js crypto (algorithms are auto-detected from the XML).

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var xd = require("./xmldsig");
var edge = require("./edge_landing"); // the static landings' hand-off contract
var log = bunyan.createLogger({ name: 'wsfed_response', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// Signer certificate (bare base64 DER) extracted from the token's <ds:Signature>;
// handed to the certificate-details page via localStorage when "View certificate
// details" is clicked.
var tokenSignerCertB64 = '';
// The issued token as originally serialized (NOT the pretty-printed textarea
// value) — used by signature validation.
var lastTokenXml = '';
// The first EncryptedAssertion/EncryptedData in the response, serialized — used
// by the decrypt option.
var lastEncryptedXml = '';

function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ''; }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function setStatus(msg) { setVal('wsfed_resp_status', msg); }
function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function tags(root, localName) { return root.getElementsByTagNameNS('*', localName); }
function firstText(root, localName) { var e = tags(root, localName)[0]; return e ? (e.textContent || '').trim() : ''; }
function serialize(node) { try { return new XMLSerializer().serializeToString(node); } catch (e) { return ''; } }
function row(k, v) { return '<tr><td class="saml-key">' + esc(k) + '</td><td>' + v + '</td></tr>'; }

function formatXml(xml) {
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
  return out.trim();
}

// The security token: the first element child of <wst:RequestedSecurityToken>
// (a SAML Assertion, an EncryptedAssertion, etc.). Namespace-agnostic, so it
// handles both WS-Trust namespaces (2005/02 RSTR, 200512 RSTRCollection) and both
// SAML versions.
function extractToken(doc) {
  var holder = tags(doc, 'RequestedSecurityToken')[0];
  if (!holder) return null;
  var c = holder.firstChild;
  while (c) { if (c.nodeType === 1) return c; c = c.nextSibling; }
  return null;
}

function b64urlDecode(s) {
  s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try { return decodeURIComponent(escape(atob(s))); } catch (e) { try { return atob(s); } catch (e2) { return ''; } }
}
function looksLikeJwt(s) { return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(String(s || '').trim()); }
function prettyJson(s) { try { return JSON.stringify(JSON.parse(s), null, 2); } catch (e) { return s; } }

function buildFieldsTable(doc, meta) {
  var container = el('wsfed_fields_table');
  var root = doc.documentElement;
  if (!root) { container.innerHTML = '<em>No response to parse.</em>'; return; }

  var html = '<table class="saml-table">';
  html += row('Profile', 'WS-Federation Passive Requestor (wa=wsignin1.0)');
  if (meta.context) html += row('Context (wctx)', esc(meta.context));

  var action = firstText(root, 'Action');
  if (action) html += row('RSTR wsa:Action', esc(action));

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

  html += '</table>';
  container.innerHTML = html;
}

function buildTokenDetails(tokenEl) {
  var container = el('wsfed_token_details');
  if (!tokenEl) { container.innerHTML = '<em>No token in the response.</em>'; return; }

  var local = tokenEl.localName || '';

  if (local === 'Assertion') {
    var html = '<table class="saml-table"><tr><th>Field</th><th>Value</th></tr>';
    // SAML 2.0 uses ID; SAML 1.1 uses AssertionID.
    html += row('Assertion ID', esc(tokenEl.getAttribute('ID') || tokenEl.getAttribute('AssertionID') || ''));
    html += row('IssueInstant', esc(tokenEl.getAttribute('IssueInstant') || ''));
    // SAML 2.0 <Issuer> element; SAML 1.1 Issuer is an attribute on <Assertion>.
    html += row('Issuer', esc(firstText(tokenEl, 'Issuer') || tokenEl.getAttribute('Issuer') || ''));

    tokenSignerCertB64 = '';
    var tokenSig = tags(tokenEl, 'Signature')[0];
    if (tokenSig) {
      var x509 = tags(tokenSig, 'X509Certificate')[0];
      if (x509) tokenSignerCertB64 = (x509.textContent || '').replace(/\s+/g, '');
    }
    var certCell;
    if (tokenSignerCertB64) {
      certCell = '<a href="/saml_cert.html?from=wsfed_response.html" onclick="return wsfed_response.viewSignerCert();">View certificate details &rarr;</a>' +
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
      var sc = tags(subj, 'SubjectConfirmation')[0];
      if (sc) {
        if (sc.getAttribute('Method')) html += row('SubjectConfirmation Method', esc(sc.getAttribute('Method')));
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
      var auds = tags(cond, 'Audience');
      for (var ai = 0; ai < auds.length; ai++) html += row('AudienceRestriction Audience', esc((auds[ai].textContent || '').trim()));
    }
    var accr = tags(tokenEl, 'AuthnContextClassRef')[0] || tags(tokenEl, 'AuthenticationMethod')[0];
    if (accr) html += row('AuthnContext / Method', esc((accr.textContent || accr.value || '').trim()));
    // SAML 1.1 carries AuthenticationMethod as an attribute on AuthenticationStatement.
    var authnStmt = tags(tokenEl, 'AuthenticationStatement')[0];
    if (authnStmt && authnStmt.getAttribute('AuthenticationMethod')) {
      html += row('AuthenticationMethod', esc(authnStmt.getAttribute('AuthenticationMethod')));
    }

    var attrs = tags(tokenEl, 'Attribute');
    for (var i = 0; i < attrs.length; i++) {
      var a = attrs[i];
      var vals = tags(a, 'AttributeValue'), vs = [];
      for (var j = 0; j < vals.length; j++) vs.push(esc((vals[j].textContent || '').trim()));
      // SAML 2.0: Name; SAML 1.1: AttributeName (+ AttributeNamespace).
      var an = a.getAttribute('Name') || a.getAttribute('AttributeName') || '';
      html += row('Attribute: ' + esc(an), vs.join('<br>'));
    }
    html += '</table>';
    container.innerHTML = html;
    return;
  }

  // JWT (rare in WS-Fed, but possible as a BinarySecurityToken / raw string).
  var raw = (tokenEl.textContent || '').trim();
  if (looksLikeJwt(raw)) {
    var parts = raw.split('.');
    var html2 = '<table class="saml-table"><tr><th>Segment</th><th>Decoded</th></tr>';
    html2 += row('Header', '<pre style="white-space:pre-wrap;margin:0;">' + esc(prettyJson(b64urlDecode(parts[0]))) + '</pre>');
    html2 += row('Payload', '<pre style="white-space:pre-wrap;margin:0;">' + esc(prettyJson(b64urlDecode(parts[1]))) + '</pre>');
    html2 += '</table>';
    container.innerHTML = html2;
    return;
  }

  container.innerHTML = '<em>Token type &lt;' + esc(local || '?') + '&gt; — see the Token XML tab.</em>';
}

function render(wresultXml, context) {
  setVal('wsfed_response_xml', formatXml(wresultXml));

  var doc = new DOMParser().parseFromString(wresultXml || '', 'application/xml');
  if (!wresultXml || doc.getElementsByTagName('parsererror').length) {
    el('wsfed_fields_table').innerHTML = '<em>wresult is empty or not well-formed XML — see the Response tab.</em>';
    el('wsfed_token_details').innerHTML = '<em>No token.</em>';
    setVal('wsfed_token_xml', wresultXml ? '(wresult is not well-formed XML)' : '(no wresult)');
    setStatus('Could not parse wresult as XML.');
    return;
  }

  buildFieldsTable(doc, { context: context || '' });

  var encEl = tags(doc, 'EncryptedAssertion')[0] || tags(doc, 'EncryptedData')[0];
  lastEncryptedXml = encEl ? serialize(encEl) : '';
  if (encEl) setVal('wsfed_dec_status', 'Response contains encrypted content — confirm the RP private key and click Decrypt.');

  var tokenEl = extractToken(doc);
  if (tokenEl) {
    lastTokenXml = serialize(tokenEl);
    setVal('wsfed_token_xml', formatXml(lastTokenXml));
    buildTokenDetails(tokenEl);
  } else {
    lastTokenXml = '';
    var note = '(no <wst:RequestedSecurityToken> in wresult — see the Response tab.)';
    setVal('wsfed_token_xml', note);
    el('wsfed_token_details').innerHTML = '<em>' + esc(note) + '</em>';
  }

  setStatus('wresult loaded.');
}

// Load a manually-pasted wresult (raw XML — no decoding).
function loadPasted() {
  var xml = val('wsfed_wresult_input').trim();
  if (!xml) { setStatus('Paste a wresult (RSTR XML) first.'); return false; }
  render(xml, val('wsfed_context_input'));
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

function viewSignerCert() {
  if (!tokenSignerCertB64) return false;
  try { if (window.localStorage) localStorage.setItem('saml_cert_view', tokenSignerCertB64); } catch (e) { /* ignore */ }
  window.open('/saml_cert.html?from=wsfed_response.html', '_blank');
  return false;
}

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

// Validate the enveloped XML digital signature on the issued assertion, using
// the certificate embedded in the signature's KeyInfo.
function validateTokenSignature() {
  var details = el('wsfed_sig_details');
  if (!lastTokenXml || lastTokenXml.indexOf('<') < 0) {
    setVal('wsfed_sig_status', 'No XML token available to validate.');
    if (details) details.innerHTML = '';
    return false;
  }
  var res;
  try { res = xd.verifyXmlSignature(lastTokenXml); }
  catch (e) { setVal('wsfed_sig_status', 'Validation error: ' + e.message); return false; }
  setVal('wsfed_sig_status', res.error ? ('Cannot validate: ' + res.error) : (res.valid ? 'Token signature VALID.' : 'Token signature INVALID.'));
  if (details) details.innerHTML = formatSigResult(res);
  return false;
}

// Decrypt an EncryptedAssertion/EncryptedData with the RP private key, then show
// and re-render the plaintext token. Reuses xmldsig.js decryptXml.
function decryptToken() {
  if (!lastEncryptedXml) { setVal('wsfed_dec_status', 'No <xenc:EncryptedData> / <EncryptedAssertion> found in this response.'); return false; }
  var key = val('wsfed_dec_key');
  if (!key.trim()) { setVal('wsfed_dec_status', 'Paste the RP private key to decrypt.'); return false; }
  var plaintext;
  try { plaintext = xd.decryptXml(lastEncryptedXml, { privateKeyPem: key }); }
  catch (e) { setVal('wsfed_dec_status', 'Decryption failed: ' + e.message); return false; }
  lastTokenXml = plaintext;
  setVal('wsfed_token_xml', formatXml(plaintext));
  try {
    var d = new DOMParser().parseFromString(plaintext, 'application/xml');
    if (!d.getElementsByTagName('parsererror').length && d.documentElement) buildTokenDetails(d.documentElement);
  } catch (e) { log.error('decrypt render: ' + e.message); }
  setVal('wsfed_dec_status', 'Decrypted. Token shown in the Token XML tab; use Validate Signature to verify it.');
  return false;
}

function qp(name) { try { return new URLSearchParams(window.location.search).get(name); } catch (e) { return null; } }

// ---------------------------------------------------------------------------
// The edge landing's hand-off (static deployments — see the header comment and
// infra/edge/wsfed_landing.js).
//
// Read once and remove: the wresult is a bearer token, and leaving it in
// sessionStorage would make the NEXT visit to this page render a stale sign-in
// as though it had just happened — which is exactly the kind of thing a debugger
// must not do, because it hides a sign-in that actually failed.
// ---------------------------------------------------------------------------
function takeEdgeHandoff() {
  log.debug('Entering takeEdgeHandoff().');
  var out = edge.takeHandoff({
    wresult: edge.WSFED.wresultKey,
    wctx: edge.WSFED.wctxKey,
    wa: edge.WSFED.waKey
  });
  if (!out.ok) { log.error('takeEdgeHandoff: sessionStorage could not be read.'); }
  log.debug('Leaving takeEdgeHandoff(). wresult ' + (out.wresult ? 'present' : 'absent') + '.');
  return out;
}

// Handle ?posted=… . Returns true when this page has dealt with the parameter,
// so onload stops. `posted` is "1" from a successful hand-off and "blocked" when
// the edge page itself could not write sessionStorage.
function handleEdgeHandoff(posted) {
  log.debug('Entering handleEdgeHandoff(). posted=' + posted);
  if (posted === 'blocked') {
    setStatus('The IdP\'s POST was captured at the edge, but this browser would not let that page ' +
              'store the token (sessionStorage is blocked), so it could not be handed over. ' +
              'Capture the POST with the developer tools and paste the wresult below.');
    return true;
  }
  var handoff = takeEdgeHandoff();
  if (!handoff.wresult) {
    setStatus('The edge landing redirected here but no wresult was waiting in sessionStorage. ' +
              'A reload will do this — the token is deliberately read once and removed. ' +
              'Sign in again, or paste the wresult below.');
    return true;
  }
  render(handoff.wresult, handoff.wctx);
  log.debug('Leaving handleEdgeHandoff(). Rendered the edge hand-off.');
  return true;
}

window.onload = function () {
  // Prefill the decryption key from the RP private key stored by the tools page
  // (the IdP encrypts the token to the RP certificate).
  try {
    var dk = el('wsfed_dec_key');
    var sk = window.localStorage && localStorage.getItem('wsfedtools_wsfed_rp_private_key');
    if (dk && !dk.value && sk) dk.value = sk;
  } catch (e) { /* ignore */ }

  var signout = qp('signout');
  if (signout) {
    setStatus('Signed out at the IdP (wa=' + esc(signout) + '). No token is returned for sign-out.');
    return;
  }

  // The static deployments' edge landing hands the token over in sessionStorage
  // rather than by id — it has nowhere on a server to stash it.
  var posted = qp(edge.WSFED.handoffParam);
  if (posted) {
    handleEdgeHandoff(posted);
    return;
  }

  var id = qp('id');
  if (id) {
    setStatus('Loading wresult…');
    fetch(appconfig.apiUrl + '/wsfedresponse?id=' + encodeURIComponent(id))
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (j) { render(j.responseXml || '', j.relayState || ''); })
      .catch(function (e) {
        log.error('fetch wresult: ' + e.message);
        setStatus('Could not load the stashed wresult: ' + e.message + ' — it may have expired. Paste it manually below.');
      });
    return;
  }

  setStatus('No wresult loaded. Complete a sign-in from the WS-Federation Test Tools page, or paste a wresult below.');
};

module.exports = {
  loadPasted,
  showTab,
  copyField,
  viewSignerCert,
  validateTokenSignature,
  decryptToken
};
