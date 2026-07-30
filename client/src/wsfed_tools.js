// File: wsfed_tools.js
//
// WS-Federation Test Tools — configuration page for the WS-Federation Passive
// Requestor Profile. Loads/parses IdP federation metadata, builds the passive
// sign-in request (wa=wsignin1.0 + wtrealm/wreply/wctx/wct/wfresh/whr/wauth/wreq)
// and the sign-out request (wa=wsignout1.0), and drives the browser to the IdP.
//
// Modeled on saml_tools.js / wstrust_tools.js: the same pane / .stored-localStorage
// conventions and the shared xmldsig.js key-pair generation. Because the passive
// sign-in is a top-level browser NAVIGATION (not an XHR), CORS never applies to
// the sign-in leg and there is nothing to proxy — the backend option only
// changes (a) how metadata is fetched and (b) the wreply target (the API /wsfed
// landing endpoint vs the static response page). The passive-profile sign-in
// request is NOT signed; all signature/encryption handling is on the returned
// token (wresult) side, in wsfed_response.js. On the static (backend-less) build
// the backend routing option is disabled.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var xd = require("./xmldsig");
var wm = require("./wsfed_msg");
var log = bunyan.createLogger({ name: 'wsfed_tools', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var STORE_PREFIX = "wsfedtools_";

// ---------------------------------------------------------------------------
// Small DOM helpers (mirror saml_tools.js / wstrust_tools.js).
// ---------------------------------------------------------------------------
function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ''; }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function setStatus(id, msg) { setVal(id, msg); }
function show(id, on) { var e = el(id); if (e) { if (on) e.classList.remove('saml-hidden'); else e.classList.add('saml-hidden'); } }
function checked(id) { var e = el(id); return !!(e && e.checked); }
function tags(root, localName) { return root.getElementsByTagNameNS('*', localName); }
function firstText(root, localName) { var e = tags(root, localName)[0]; return e ? (e.textContent || '').trim() : ''; }

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
function onIncludeWreqChange() { show('wsfed_wreq_section', checked('wsfed_include_wreq')); saveState(); autoBuildRequest(); return false; }

// ---------------------------------------------------------------------------
// IdP federation metadata: load (via the backend proxy or a direct browser
// fetch), parse the WS-Federation RoleDescriptor, and populate the config pane.
// ---------------------------------------------------------------------------
function loadMetadata() {
  var url = val('wsfed_metadata_url').trim();
  if (!url) { setStatus('wsfed_metadata_status', 'Enter a federation metadata URL first.'); return false; }
  setStatus('wsfed_metadata_status', 'Loading metadata…');
  // With a backend, proxy the fetch to dodge CORS (the metadata endpoint rarely
  // sends CORS headers); on the static build, fetch it directly from the browser.
  var fetchUrl = appconfig.backendAvailable
    ? (appconfig.apiUrl + '/samlmetadata?url=' + encodeURIComponent(btoa(url)))
    : url;
  fetch(fetchUrl)
    .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
    .then(function (xml) {
      setVal('wsfed_metadata_doc', xml);
      parseWsFedMetadata(xml);
      saveState();
      autoBuildRequest();
    })
    .catch(function (e) {
      log.error('loadMetadata: ' + e.message);
      setStatus('wsfed_metadata_status', 'Metadata load failed: ' + e.message +
        (appconfig.backendAvailable ? '' : ' — the metadata endpoint likely blocks direct browser calls (CORS); paste the XML into the box below instead.'));
    });
  return false;
}

function uploadMetadata() {
  var f = el('wsfed_metadata_file');
  if (f) f.click();
  return false;
}
function onMetadataFile(evt) {
  var file = evt && evt.target && evt.target.files && evt.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function () {
    setVal('wsfed_metadata_doc', reader.result);
    parseWsFedMetadata(reader.result);
    saveState();
    autoBuildRequest();
  };
  reader.readAsText(file);
}

// Parse an XML federation-metadata document and populate the config fields. The
// WS-Federation IdP/STS role is a <RoleDescriptor> whose xsi:type is
// SecurityTokenServiceType; rather than resolve the xsi:type prefix we simply
// pick the RoleDescriptor that CONTAINS a PassiveRequestorEndpoint. Endpoints and
// the signing certificate are read namespace-agnostically.
function parseWsFedMetadata(xmlText) {
  var doc;
  try { doc = new DOMParser().parseFromString(xmlText || '', 'application/xml'); }
  catch (e) { setStatus('wsfed_metadata_status', 'Parse error: ' + e.message); return; }
  if (!doc || !doc.documentElement || doc.getElementsByTagName('parsererror').length) {
    setStatus('wsfed_metadata_status', 'Metadata is not well-formed XML.');
    return;
  }

  var entityId = doc.documentElement.getAttribute('entityID') || '';
  if (entityId) setVal('wsfed_idp_entity_id', entityId);

  // Find the RoleDescriptor containing the passive endpoint (fall back to the
  // whole document if the metadata is flat).
  var scope = doc;
  var roles = tags(doc, 'RoleDescriptor');
  for (var i = 0; i < roles.length; i++) {
    if (tags(roles[i], 'PassiveRequestorEndpoint').length) { scope = roles[i]; break; }
  }

  var passive = tags(scope, 'PassiveRequestorEndpoint')[0];
  if (passive) {
    var addr = firstText(passive, 'Address');
    if (addr) {
      setVal('wsfed_signin_endpoint', addr);
      // Passive sign-out uses the same endpoint with wa=wsignout1.0 unless a
      // dedicated sign-out endpoint is advertised.
      if (!val('wsfed_signout_endpoint')) setVal('wsfed_signout_endpoint', addr);
    }
  }
  // Optional dedicated sign-out endpoints (rare).
  var signout = tags(scope, 'SingleSignOutNotificationEndpoint')[0] || tags(scope, 'SingleSignOutSubscriptionEndpoint')[0];
  if (signout) { var so = firstText(signout, 'Address'); if (so) setVal('wsfed_signout_endpoint', so); }

  // Optional active (WS-Trust) STS endpoint — handy to seed the WS-Trust page.
  var sts = tags(scope, 'SecurityTokenServiceEndpoint')[0];
  if (sts) { var stsAddr = firstText(sts, 'Address'); if (stsAddr) setVal('wsfed_sts_endpoint', stsAddr); }

  // Token-signing certificate: prefer a KeyDescriptor with use="signing".
  var kds = tags(scope, 'KeyDescriptor');
  var signingCert = '';
  var anyCert = '';
  for (var k = 0; k < kds.length; k++) {
    var use = (kds[k].getAttribute('use') || '').toLowerCase();
    var x509 = firstText(kds[k], 'X509Certificate');
    if (!x509) continue;
    x509 = x509.replace(/\s+/g, '');
    if (!anyCert) anyCert = x509;
    if (use === 'signing' || use === '') { signingCert = x509; break; }
  }
  var cert = signingCert || anyCert;
  if (cert) setVal('wsfed_signer_cert', cert);

  var bits = [];
  if (val('wsfed_signin_endpoint')) bits.push('passive endpoint');
  if (cert) bits.push('signing certificate');
  if (val('wsfed_sts_endpoint')) bits.push('STS endpoint');
  setStatus('wsfed_metadata_status', bits.length
    ? ('Parsed metadata (' + bits.join(', ') + ').')
    : 'Parsed metadata, but no PassiveRequestorEndpoint was found — enter the sign-in endpoint manually.');
}

// ---------------------------------------------------------------------------
// Relying-party key pair (RSA + self-signed cert). The certificate is what you
// register at the IdP so it can encrypt the issued token to the RP; the private
// key is used on the response page to decrypt an EncryptedAssertion.
// ---------------------------------------------------------------------------
function generateKeys() {
  var bits = parseInt(val('wsfed_key_bits'), 10) || 2048;
  setStatus('wsfed_call_status', 'Generating ' + bits + '-bit RSA key pair…');
  setTimeout(function () {
    try {
      var kp = xd.generateKeyPair(bits, 'ws-federation-debugger-rp');
      setVal('wsfed_rp_private_key', kp.privateKeyPem);
      setVal('wsfed_rp_cert', kp.certPem);
      setStatus('wsfed_call_status', 'Key pair generated. The private key is reused on the response page to decrypt an encrypted token.');
      saveState();
    } catch (e) {
      log.error('generateKeys: ' + e.message);
      setStatus('wsfed_call_status', 'Key generation error: ' + e.message);
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
  var priv = val('wsfed_rp_private_key');
  if (!priv) { setStatus('wsfed_call_status', 'Generate a key pair first.'); return false; }
  triggerDownload('wsfed-rp-key.pem', priv, 'application/x-pem-file');
  triggerDownload('wsfed-rp-cert.pem', val('wsfed_rp_cert'), 'application/x-pem-file');
  return false;
}

// ---------------------------------------------------------------------------
// Request construction — delegate the parameter set to the DOM-free wsfed_msg.
// ---------------------------------------------------------------------------
function signInOptions() {
  return {
    realm: val('wsfed_realm'),
    reply: val('wsfed_reply'),
    context: val('wsfed_context'),
    includeTimestamp: checked('wsfed_include_wct'),
    freshness: val('wsfed_freshness'),
    homeRealm: val('wsfed_home_realm'),
    authType: val('wsfed_auth_type'),
    policy: val('wsfed_policy'),
    request: checked('wsfed_include_wreq') ? val('wsfed_wreq') : ''
  };
}

function buildSignInUrl() {
  var endpoint = val('wsfed_signin_endpoint').trim();
  var params = wm.buildSignInParams(signInOptions());
  return wm.buildUrl(endpoint, params);
}
function buildSignOutUrl() {
  var endpoint = (val('wsfed_signout_endpoint') || val('wsfed_signin_endpoint')).trim();
  var params = wm.buildSignOutParams({ reply: val('wsfed_reply'), realm: val('wsfed_realm') });
  return wm.buildUrl(endpoint, params);
}

function autoBuildRequest() { try { buildRequestUi(); } catch (e) { log.error('autoBuildRequest: ' + e.message); } return false; }
function buildRequestUi() {
  try {
    var url = buildSignInUrl();
    setVal('wsfed_generated_request', url);
    setStatus('wsfed_call_status', 'Built wsignin1.0 request' + (checked('wsfed_include_wreq') ? ' (with inline wreq).' : '.'));
  } catch (e) {
    log.error('buildRequestUi: ' + e.message);
    setStatus('wsfed_call_status', 'Build failed: ' + e.message);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Drive the browser to the IdP. Sign-in/out are top-level navigations (the IdP
// then auto-POSTs wresult back to wreply), so there is no fetch/CORS here.
// ---------------------------------------------------------------------------
function callIdp() {
  var endpoint = val('wsfed_signin_endpoint').trim();
  if (!endpoint) { setStatus('wsfed_call_status', 'Enter (or load from metadata) the IdP passive sign-in endpoint first.'); return false; }
  if (!val('wsfed_realm').trim()) { setStatus('wsfed_call_status', 'Enter the RP realm (wtrealm) first.'); return false; }
  var url = buildSignInUrl();
  setStatus('wsfed_call_status', 'Navigating to the IdP…');
  saveState();
  window.location.assign(url);
  return false;
}
function signOut() {
  var endpoint = (val('wsfed_signout_endpoint') || val('wsfed_signin_endpoint')).trim();
  if (!endpoint) { setStatus('wsfed_call_status', 'Enter (or load from metadata) the IdP sign-in/sign-out endpoint first.'); return false; }
  var url = buildSignOutUrl();
  setStatus('wsfed_call_status', 'Navigating to the IdP sign-out…');
  saveState();
  window.location.assign(url);
  return false;
}

// ---------------------------------------------------------------------------
// Misc UI (shared shapes with wstrust_tools.js / saml_tools.js).
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
  if (!pem) { setStatus('wsfed_config_status', 'No certificate to view yet.'); return false; }
  try { if (window.localStorage) localStorage.setItem('saml_cert_view', pem); } catch (e) { /* ignore */ }
  window.open('/saml_cert.html?from=wsfed_tools.html', '_blank');
  return false;
}

// Static (backend-less) build: no API proxy / landing endpoint, so the sign-in
// must be driven directly from the browser and the wresult can't be captured
// server-side. Force the Front radio on and disable the Back radio, mirroring
// wstrust_tools.js / the OAuth2 debugger.
function enforceBackendAvailability() {
  if (appconfig.backendAvailable === false) {
    var front = el('wsfed_initiateFromFrontEnd');
    var back = el('wsfed_initiateFromBackEnd');
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

  var f = el('wsfed_metadata_file');
  if (f) f.addEventListener('change', onMetadataFile);

  // Seed defaults for blank fields (fresh page).
  if (!val('wsfed_metadata_url') && appconfig.wsfedMetadataUrlDefault) setVal('wsfed_metadata_url', appconfig.wsfedMetadataUrlDefault);
  if (!val('wsfed_realm')) setVal('wsfed_realm', appconfig.wsfedRealm || appconfig.spEntityId || '');
  // wreply target: with a backend, the API /wsfed landing captures the POST and
  // redirects to the viewer; on the static build, point at the static response
  // page (the POSTed wresult can't be auto-read there — use manual paste).
  if (!val('wsfed_reply')) {
    var replyDefault = appconfig.backendAvailable
      ? (appconfig.wsfedAcsUrl || '')
      : (window.location.origin + '/wsfed_response.html');
    if (replyDefault) setVal('wsfed_reply', replyDefault);
  }

  show('wsfed_backend_notice', appconfig.backendAvailable === false);
  enforceBackendAvailability();
  onIncludeWreqChange();

  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    els[i].addEventListener('change', saveState);
    els[i].addEventListener('input', saveState);
    els[i].addEventListener('change', autoBuildRequest);
    els[i].addEventListener('input', autoBuildRequest);
  }

  autoBuildRequest();
};

module.exports = {
  loadMetadata,
  uploadMetadata,
  onIncludeWreqChange,
  generateKeys,
  downloadKeys,
  buildRequestUi,
  callIdp,
  signOut,
  viewCertificate,
  copyField,
  showTab,
  togglePane
};
