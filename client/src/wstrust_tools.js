// File: wstrust_tools.js
//
// WS-Trust Test Tools — configuration page. Builds a SOAP
// RequestSecurityToken (RST) for the four WS-Trust operations (Issue, Renew,
// Validate, Cancel), optionally signs it (WS-Security XML-DSIG) and/or encrypts
// its body (XML-Encryption), adds WS-Addressing headers, and sends it to a
// Security Token Service (STS). The RST/RSTR round-trip is synchronous: the STS
// reply is stashed in localStorage and the browser navigates to
// wstrust_response.html to render it.
//
// Modeled on the SAML Test Tools workflow (saml_tools.js): the same pane /
// tab / .stored-localStorage conventions, and the shared in-browser XML
// security primitives in ./xmldsig.js. The STS call can be made either directly
// from the browser (frontend) or through the API proxy (backend, POST /wstrust)
// to dodge CORS — a radio, exactly like the OAuth2 token call. On the static
// (backend-less) build the backend option is disabled.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var xd = require("./xmldsig");
var wm = require("./wstrust_msg");
var log = bunyan.createLogger({ name: 'wstrust_tools', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var forge = xd.forge;
var STORE_PREFIX = "wstrust_";

// WS-Trust 1.3/1.4 (the 200512 namespace is shared; 1.4 adds ActAs in a 200802
// namespace and wraps Issue/Renew responses in an RSTR Collection).
var WST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
var WST14_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200802"; // ActAs
var WSP_NS = "http://schemas.xmlsoap.org/ws/2004/09/policy";
var WSA_NS = "http://www.w3.org/2005/08/addressing";
var WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
var WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
var SOAP12_NS = "http://www.w3.org/2003/05/soap-envelope";
var SOAP11_NS = "http://schemas.xmlsoap.org/soap/envelope/";
var CLAIMS_DIALECT = "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims";
var WSA_ANON = "http://www.w3.org/2005/08/addressing/anonymous";
var PW_TEXT = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
var PW_DIGEST = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";

// WS-Trust protocol version model + RST construction live in the shared,
// DOM-free ./wstrust_msg module (so they can be schema-validated in Node). These
// thin wrappers read the selected version from the form and delegate, keeping
// every call site below unchanged.
function trustVersion() { return wm.versionCfg(val("wst_trust_version")); }
function trustNs() { return wm.versionNs(val("wst_trust_version")); }
function requestTypeUri(op) { return wm.requestTypeUri(val("wst_trust_version"), op); }
function wsaActionUri(op) { return wm.wsaActionUri(val("wst_trust_version"), op); }
function keyTypeUri(kt) { return wm.keyTypeUri(val("wst_trust_version"), kt); }
function statusTokenTypeUri() { return wm.statusTokenTypeUri(val("wst_trust_version")); }

var EXCHANGE_KEY = "wstrust_last_exchange";

// ---------------------------------------------------------------------------
// Small DOM helpers (mirror saml_tools.js).
// ---------------------------------------------------------------------------
function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ''; }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function setStatus(id, msg) { setVal(id, msg); }
function show(id, on) { var e = el(id); if (e) { if (on) e.classList.remove('saml-hidden'); else e.classList.add('saml-hidden'); } }
function checked(id) { var e = el(id); return !!(e && e.checked); }
function xmlEscape(s) { return xd.xmlEscape(s); }

// ---------------------------------------------------------------------------
// localStorage persistence — every .stored element is saved by its id.
// ---------------------------------------------------------------------------
function persistedEls() { return document.querySelectorAll('.stored'); }
function saveState() {
  if (!window.localStorage) return;
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (!els[i].id) continue;
    var v = els[i].type === 'checkbox' ? (els[i].checked ? '1' : '0') : els[i].value;
    localStorage.setItem(STORE_PREFIX + els[i].id, v);
  }
}
function restoreState() {
  if (!window.localStorage) return;
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (!els[i].id) continue;
    var v = localStorage.getItem(STORE_PREFIX + els[i].id);
    if (v === null) continue;
    if (els[i].type === 'checkbox') els[i].checked = (v === '1' || v === 'true' || v === 'on');
    else els[i].value = v;
  }
}

// ---------------------------------------------------------------------------
// Section-visibility toggles.
// ---------------------------------------------------------------------------
function onCredModeChange() {
  var mode = val('wst_cred_mode');
  show('wst_ut_section', mode === 'usernametoken');
  show('wst_samltoken_section', mode === 'saml');
  saveState();
  autoBuildRequest();
  return false;
}
function onSignChange() { show('wst_signing_section', checked('wst_sign_request')); saveState(); autoBuildRequest(); return false; }
function onEncryptChange() { show('wst_encryption_section', checked('wst_encrypt_request')); saveState(); autoBuildRequest(); return false; }
function onWsaChange() { show('wst_wsa_section', checked('wst_wsa_support')); saveState(); autoBuildRequest(); return false; }
function onOnBehalfOfChange() { show('wst_onbehalfof_row', checked('wst_use_onbehalfof')); saveState(); autoBuildRequest(); return false; }
function onActAsChange() { show('wst_actas_row', checked('wst_use_actas')); saveState(); autoBuildRequest(); return false; }

// Apply the selected WS-Trust version: gate the version-specific options
// (Bearer key type is 1.3+, ActAs is 1.4) and refresh the namespace-derived
// wsa:Action. Hidden options are also reset so they aren't sent.
function onVersionChange() {
  var v = trustVersion();
  var kt = el('wst_key_type');
  if (kt) {
    var bearerOpt = kt.querySelector('option[value="bearer"]');
    if (bearerOpt) { bearerOpt.hidden = !v.bearer; bearerOpt.disabled = !v.bearer; }
    if (!v.bearer && kt.value === 'bearer') kt.value = 'symmetric';
  }
  show('wst_actas_check_row', v.actas);
  if (!v.actas) { var a = el('wst_use_actas'); if (a) a.checked = false; }
  onActAsChange();      // adjust the ActAs textarea row to the (possibly reset) checkbox
  onOperationChange();  // refresh wsa:Action for the new namespace + rebuild
  saveState();
  return false;
}

// Show the Target Token field only for the operations that need one
// (Renew/Validate/Cancel act on an existing token; Issue mints a new one).
function onOperationChange() {
  var op = val('wst_operation');
  show('wst_target_section', op !== 'issue');
  // Auto-fill wsa:Action to match the operation + version, unless the user has
  // customized it (any /RST/<Op> value, in any trust namespace, is auto-managed).
  var wsaAction = el('wst_wsa_action');
  if (wsaAction && (!wsaAction.value || /\/RST\/(Issue|Renew|Validate|Cancel)$/.test(wsaAction.value))) {
    wsaAction.value = wsaActionUri(op);
  }
  saveState();
  autoBuildRequest();
  return false;
}

// ---------------------------------------------------------------------------
// Signing key-pair generation (RSA via node-forge) + self-signed certificate.
// ---------------------------------------------------------------------------
function generateKeys() {
  var bits = parseInt(val('wst_key_bits'), 10) || 2048;
  setStatus('wst_call_status', 'Generating ' + bits + '-bit RSA key pair…');
  setTimeout(function () {
    try {
      var kp = xd.generateKeyPair(bits, 'ws-trust-debugger-client');
      setVal('wst_sp_private_key', kp.privateKeyPem);
      setVal('wst_sp_cert', kp.certPem);
      setStatus('wst_call_status', 'Key pair generated.');
      saveState();
      autoBuildRequest();
    } catch (e) {
      log.error('generateKeys: ' + e.message);
      setStatus('wst_call_status', 'Key generation error: ' + e.message);
    }
  }, 20);
  return false;
}

function triggerDownload(filename, data, mime) {
  var blob = new Blob([data], { type: mime || 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
}
function downloadKeys() {
  var priv = val('wst_sp_private_key');
  if (!priv) { setStatus('wst_call_status', 'Generate a key pair first.'); return false; }
  triggerDownload('wstrust-client-key.pem', priv, 'application/x-pem-file');
  triggerDownload('wstrust-client-cert.pem', val('wst_sp_cert'), 'application/x-pem-file');
  return false;
}

// Import a SAML assertion from the SAML workflow's last response (saved by
// saml_response.js under 'saml_last_response'); extract the <Assertion>.
function importSamlAssertion() {
  var saved = '';
  try { saved = (window.localStorage && localStorage.getItem('saml_last_response')) || ''; } catch (e) { saved = ''; }
  if (!saved) {
    setStatus('wst_config_status', 'No SAML response found — run a SAML SSO first (SAML Debugger), or paste an assertion manually.');
    return false;
  }
  try {
    var doc = new DOMParser().parseFromString(saved, 'application/xml');
    var assertion = doc.getElementsByTagNameNS('*', 'Assertion')[0];
    if (!assertion) { setStatus('wst_config_status', 'No <Assertion> in the last SAML response.'); return false; }
    setVal('wst_saml_token', new XMLSerializer().serializeToString(assertion));
    el('wst_cred_mode').value = 'saml';
    onCredModeChange();
    setStatus('wst_config_status', 'Imported SAML assertion from the SAML workflow.');
  } catch (e) {
    log.error('importSamlAssertion: ' + e.message);
    setStatus('wst_config_status', 'Import failed: ' + e.message);
  }
  return false;
}

// ---------------------------------------------------------------------------
// SOAP RequestSecurityToken construction.
// ---------------------------------------------------------------------------
function nowPlusMinutes(mins) {
  var d = new Date(Date.now() + (mins || 0) * 60000);
  return d.toISOString();
}

function tokenTypeUri() { return wm.tokenTypeUri(val('wst_token_type'), val('wst_trust_version')); }

// The credential element that goes inside <wsse:Security> (UsernameToken, an
// embedded SAML assertion, or nothing).
function buildSecurityCredential() {
  var mode = val('wst_cred_mode');
  if (mode === 'usernametoken') {
    var user = val('wst_username');
    var pass = val('wst_password');
    var pwType = val('wst_password_type') || PW_TEXT;
    if (pwType === PW_DIGEST) {
      var nonce = forge.random.getBytesSync(16);
      var created = new Date().toISOString();
      var md = forge.md.sha1.create();
      md.update(nonce + created + forge.util.encodeUtf8(pass));
      var digest = forge.util.encode64(md.digest().getBytes());
      return '<wsse:UsernameToken wsu:Id="_ut">' +
        '<wsse:Username>' + xmlEscape(user) + '</wsse:Username>' +
        '<wsse:Password Type="' + PW_DIGEST + '">' + digest + '</wsse:Password>' +
        '<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">' + forge.util.encode64(nonce) + '</wsse:Nonce>' +
        '<wsu:Created>' + created + '</wsu:Created>' +
        '</wsse:UsernameToken>';
    }
    return '<wsse:UsernameToken wsu:Id="_ut">' +
      '<wsse:Username>' + xmlEscape(user) + '</wsse:Username>' +
      '<wsse:Password Type="' + PW_TEXT + '">' + xmlEscape(pass) + '</wsse:Password>' +
      '</wsse:UsernameToken>';
  }
  if (mode === 'saml') {
    // Embed the assertion XML as-is (already an element).
    return val('wst_saml_token').trim();
  }
  return '';
}

function buildRstBody() {
  return wm.buildRst({
    version: val('wst_trust_version'),
    operation: val('wst_operation'),
    tokenType: val('wst_token_type'),
    keyType: val('wst_key_type'),
    keySize: val('wst_key_size'),
    appliesTo: val('wst_applies_to'),
    lifetimeMinutes: val('wst_lifetime_minutes'),
    claims: val('wst_claims'),
    useOnBehalfOf: checked('wst_use_onbehalfof'),
    onBehalfOf: val('wst_onbehalfof'),
    useActAs: checked('wst_use_actas'),
    actAs: val('wst_actas'),
    targetToken: val('wst_target_token')
  });
}

function soapEnvelopeNs() {
  return val('wst_soap_version') === '1.1' ? SOAP11_NS : SOAP12_NS;
}

// Build the full SOAP envelope (unsigned/unencrypted). Body and Timestamp carry
// wsu:Id attributes so signing can reference them without mutating the tree.
function buildSoapEnvelope() {
  var soapNs = soapEnvelopeNs();
  var op = val('wst_operation');
  var headerParts = [];

  if (checked('wst_wsa_support')) {
    var action = val('wst_wsa_action') || wsaActionUri(op);
    var to = val('wst_wsa_to') || val('wst_sts_url');
    var msgId = val('wst_wsa_messageid') || ('urn:uuid:' + xd.genId().slice(1));
    var replyTo = val('wst_wsa_replyto') || WSA_ANON;
    headerParts.push('<wsa:Action>' + xmlEscape(action) + '</wsa:Action>');
    headerParts.push('<wsa:MessageID>' + xmlEscape(msgId) + '</wsa:MessageID>');
    if (to) headerParts.push('<wsa:To wsu:Id="_to">' + xmlEscape(to) + '</wsa:To>');
    headerParts.push('<wsa:ReplyTo><wsa:Address>' + xmlEscape(replyTo) + '</wsa:Address></wsa:ReplyTo>');
    var from = val('wst_wsa_from').trim();
    if (from) headerParts.push('<wsa:From><wsa:Address>' + xmlEscape(from) + '</wsa:Address></wsa:From>');
  }

  var secParts = [];
  if (checked('wst_add_timestamp')) {
    secParts.push('<wsu:Timestamp wsu:Id="_timestamp"><wsu:Created>' + nowPlusMinutes(0) + '</wsu:Created><wsu:Expires>' + nowPlusMinutes(5) + '</wsu:Expires></wsu:Timestamp>');
  }
  var cred = buildSecurityCredential();
  if (cred) secParts.push(cred);
  var securityHeader = secParts.length
    ? '<wsse:Security xmlns:wsse="' + WSSE_NS + '" xmlns:wsu="' + WSU_NS + '" soap:mustUnderstand="' + (soapNs === SOAP11_NS ? '1' : 'true') + '">' + secParts.join('') + '</wsse:Security>'
    : '';

  var header = (headerParts.length || securityHeader)
    ? '<soap:Header>' + headerParts.join('') + securityHeader + '</soap:Header>'
    : '';

  return '<soap:Envelope xmlns:soap="' + soapNs + '" xmlns:wsa="' + WSA_NS + '" xmlns:wsu="' + WSU_NS + '">' +
    header +
    '<soap:Body wsu:Id="_body">' + buildRstBody() + '</soap:Body>' +
    '</soap:Envelope>';
}

// ---------------------------------------------------------------------------
// WS-Security message signing (XML-DSIG, detached signature in the Security
// header referencing the Body and — optionally — the Timestamp by wsu:Id).
// Uses the shared exclusive-C14N + RSA-SHA* primitives in xmldsig.js.
// ---------------------------------------------------------------------------
function firstByLocal(root, name) {
  var els = root.getElementsByTagNameNS('*', name);
  return els.length ? els[0] : null;
}

function signWsSecurity(soapXml) {
  var priv = val('wst_sp_private_key');
  if (!priv) throw new Error('Signing is enabled but there is no client private key — generate a key pair.');
  return xd.signWsSecurity(soapXml, {
    privateKeyPem: priv,
    certPem: val('wst_sp_cert'),
    sigAlg: val('wst_sig_alg') || xd.SIG_ALG_RSA_SHA256,
    signTimestamp: checked('wst_sign_timestamp')
  });
}

// Encrypt the SOAP Body content with XML-Encryption (educational — most STSes
// won't process an encrypted request body). Replaces the RST inside <soap:Body>
// with an <xenc:EncryptedData>.
function encryptSoapBody(soapXml) {
  var doc = new DOMParser().parseFromString(soapXml, 'application/xml');
  var body = firstByLocal(doc, 'Body');
  if (!body) throw new Error('No <soap:Body> to encrypt.');
  var rst = null, c = body.firstChild;
  while (c) { if (c.nodeType === 1) { rst = c; break; } c = c.nextSibling; }
  if (!rst) throw new Error('No RST element in the body to encrypt.');
  var rstXml = new XMLSerializer().serializeToString(rst);
  var encXml = xd.encryptXml(rstXml, {
    certPem: val('wst_enc_cert'),
    dataAlg: val('wst_enc_data_alg'),
    keyAlg: val('wst_enc_key_alg'),
    type: val('wst_enc_type'),
    c14nMode: val('wst_enc_c14n'),
    digest: val('wst_enc_digest'),
    mgf: val('wst_enc_mgf')
  });
  var encNode = doc.importNode(new DOMParser().parseFromString(encXml, 'application/xml').documentElement, true);
  body.replaceChild(encNode, rst);
  return new XMLSerializer().serializeToString(doc);
}

// Apply the selected signing/encryption to a freshly-built envelope.
function buildFinalRequest() {
  var xml = buildSoapEnvelope();
  if (checked('wst_sign_request')) xml = signWsSecurity(xml);
  if (checked('wst_encrypt_request')) xml = encryptSoapBody(xml);
  return xml;
}

// ---------------------------------------------------------------------------
// Auto-rebuild the Generated Request field on any change.
// ---------------------------------------------------------------------------
function autoBuildRequest() {
  try { buildRequestUi(); } catch (e) { log.error('autoBuildRequest: ' + e.message); }
  return false;
}
function buildRequestUi() {
  try {
    var xml = buildFinalRequest();
    setVal('wst_generated_request', formatXml(xml));
    var op = val('wst_operation');
    var bits = (checked('wst_sign_request') ? 'signed' : 'unsigned') + (checked('wst_encrypt_request') ? ' + encrypted body' : '');
    var msg = 'Built ' + op + ' RequestSecurityToken (' + bits + ').';
    if (checked('wst_encrypt_request')) msg += ' Note: most STSes will not accept an encrypted request body.';
    setStatus('wst_call_status', msg);
  } catch (e) {
    log.error('buildRequestUi: ' + e.message);
    setStatus('wst_call_status', 'Build failed: ' + e.message);
  }
  return false;
}

// Minimal, dependency-free XML pretty-printer (shared shape with saml_response.js).
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

// ---------------------------------------------------------------------------
// Send the request to the STS (frontend fetch or backend proxy), stash the
// exchange, and navigate to the response page.
// ---------------------------------------------------------------------------
function useBackend() {
  return appconfig.backendAvailable !== false && checked('wst_initiateFromBackEnd');
}

function contentTypeFor(soapVersion, action) {
  if (soapVersion === '1.1') return 'text/xml; charset=utf-8';
  return 'application/soap+xml; charset=utf-8' + (action ? ('; action="' + action + '"') : '');
}

function stashAndGo(requestXml, responseXml, httpStatus) {
  var meta = {
    operation: val('wst_operation'),
    trustVersion: val('wst_trust_version'),
    trustNs: trustNs(),
    tokenType: tokenTypeUri(),
    keyType: keyTypeUri(val('wst_key_type')),
    appliesTo: val('wst_applies_to'),
    soapVersion: val('wst_soap_version'),
    stsUrl: val('wst_sts_url'),
    httpStatus: httpStatus,
    sentAt: new Date().toISOString()
  };
  try {
    if (window.localStorage) {
      localStorage.setItem(EXCHANGE_KEY, JSON.stringify({ requestXml: requestXml, responseXml: responseXml, meta: meta }));
    }
  } catch (e) { log.error('stash: ' + e.message); }
  window.location.assign('/wstrust_response.html');
}

function callSts() {
  var url = val('wst_sts_url').trim();
  if (!url) { setStatus('wst_call_status', 'Enter the STS endpoint URL first.'); return false; }
  var op = val('wst_operation');
  if (op !== 'issue' && !val('wst_target_token').trim()) {
    setStatus('wst_call_status', 'The ' + op + ' operation needs a Target Token — paste the token from a prior Issue.');
    return false;
  }
  var soapVersion = val('wst_soap_version') || '1.2';
  var action = val('wst_wsa_action') || wsaActionUri(op);

  var soap;
  try { soap = buildFinalRequest(); }
  catch (e) { setStatus('wst_call_status', 'Build failed: ' + e.message); return false; }

  setStatus('wst_call_status', 'Sending ' + op + ' request to the STS…');

  if (useBackend()) {
    fetch(appconfig.apiUrl + '/wstrust', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url, soap: soap, soapVersion: soapVersion, action: action,
        sslValidate: checked('wst_ssl_validate')
      })
    })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) { throw new Error(j && j.error ? j.error : ('HTTP ' + r.status)); } return j; }); })
      .then(function (j) { stashAndGo(soap, j.body || '', j.status); })
      .catch(function (e) { log.error('callSts backend: ' + e.message); setStatus('wst_call_status', 'STS call failed: ' + e.message); });
    return false;
  }

  // Frontend (direct browser) — subject to the STS's CORS policy.
  var headers = { 'Content-Type': contentTypeFor(soapVersion, action) };
  if (soapVersion === '1.1') headers['SOAPAction'] = '"' + action + '"';
  fetch(url, { method: 'POST', headers: headers, body: soap })
    .then(function (r) { return r.text().then(function (t) { return { status: r.status, body: t }; }); })
    .then(function (res) { stashAndGo(soap, res.body || '', res.status); })
    .catch(function (e) {
      log.error('callSts frontend: ' + e.message);
      setStatus('wst_call_status', 'STS call failed: ' + e.message + ' — a cross-origin SOAP endpoint often blocks direct browser calls (CORS); switch to backend routing.');
    });
  return false;
}

// ---------------------------------------------------------------------------
// Misc UI (shared shapes with saml_tools.js).
// ---------------------------------------------------------------------------
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
function togglePane(bodyId) {
  var b = el(bodyId);
  if (b) b.style.display = (b.style.display === 'none') ? 'block' : 'none';
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
function viewCertificate(fieldId) {
  var pem = val(fieldId);
  if (!pem) { setStatus('wst_call_status', 'No certificate to view yet.'); return false; }
  try { if (window.localStorage) localStorage.setItem('saml_cert_view', pem); } catch (e) { /* ignore */ }
  window.open('/saml_cert.html?from=wstrust_tools.html', '_blank');
  return false;
}

// Static (backend-less) build: no API proxy, so the STS call must be made from
// the browser. Force the Front radio on and disable the Back radio, mirroring
// the OAuth2 debugger's enforceBackendAvailability().
function enforceBackendAvailability() {
  if (appconfig.backendAvailable === false) {
    var front = el('wst_initiateFromFrontEnd');
    var back = el('wst_initiateFromBackEnd');
    if (front) front.checked = true;
    if (back) { back.checked = false; back.disabled = true; }
  }
}

function setReturnLink() {
  var link = el('return_link');
  if (link) link.setAttribute('href', '/index.html');
}

window.onload = function () {
  log.debug('Entering onload().');
  restoreState();
  setReturnLink();

  // Seed the STS URL default if nothing stored yet.
  if (!val('wst_sts_url') && appconfig.wstrustStsUrlDefault) setVal('wst_sts_url', appconfig.wstrustStsUrlDefault);
  // Fall back to HTML defaults for blank fields (fresh page).
  ['wst_applies_to', 'wst_username', 'wst_password'].forEach(function (id) {
    var e = el(id);
    if (e && !e.value && e.defaultValue) e.value = e.defaultValue;
  });

  show('wst_backend_notice', appconfig.backendAvailable === false);
  enforceBackendAvailability();
  onCredModeChange();
  onSignChange();
  onEncryptChange();
  onWsaChange();
  onOnBehalfOfChange();
  onActAsChange();
  // onVersionChange() gates the version-specific options and calls
  // onOperationChange() (which refreshes wsa:Action and rebuilds the request).
  onVersionChange();

  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    els[i].addEventListener('change', saveState);
    els[i].addEventListener('input', saveState);
    els[i].addEventListener('change', autoBuildRequest);
  }

  autoBuildRequest();
};

module.exports = {
  onVersionChange,
  onOperationChange,
  onCredModeChange,
  onSignChange,
  onEncryptChange,
  onWsaChange,
  onOnBehalfOfChange,
  onActAsChange,
  generateKeys,
  downloadKeys,
  importSamlAssertion,
  buildRequestUi,
  callSts,
  viewCertificate,
  copyField,
  showTab,
  togglePane
};
