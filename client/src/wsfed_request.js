// File: wsfed_request.js
//
// Renamed from wsfed_tools.js: this page BUILDS AND SENDS the sign-in request,
// which is what saml_request.html is called for the same reason. The name
// wsfed_tools survives nowhere — see docs/wsfed.md.
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
// The scheme allowlist applied before navigating anywhere. See url_safety.js
// for why this is not DOMPurify.
var urlSafety = require("./url_safety");
var history = require('./wsfed_history');
var wm = require("./wsfed_msg");
var log = bunyan.createLogger({ name: 'wsfed_request', level: appconfig.logLevel });
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

// The relying-party key pair, and whether it may be written to localStorage.
//
// The same exception, and the same opt-out, as the SP key pair on
// saml_request.html and the requestor pair on wstrust_tools.html — see the note
// in saml_request.js. Everything else this page persists is configuration; this
// is key material, and the debugger's standing rule is that credentials stay out
// of localStorage. It is kept anyway by default because the workflow spans
// screens: wsfed_response.html needs this private key to decrypt an
// EncryptedAssertion, and the Passive Requestor Profile means the round trip
// leaves this page entirely.
//
// Clearing the box stops the two fields being written AND removes what was
// written before. wsfed_signer_cert is deliberately NOT in this list: it is the
// IdP's signing certificate, someone else's public credential, not part of this
// key pair — the counterpart of wst_enc_cert on the WS-Trust page.
var KEYPAIR_FIELDS = ['wsfed_rp_private_key', 'wsfed_rp_cert'];

function keyPairMayBeStored() {
  var e = el('wsfed_save_keypair');
  // Absent checkbox (an older cached copy of the page) keeps the previous
  // behaviour rather than silently dropping a key pair the user expects to
  // still be there after a reload.
  return !e || e.checked;
}

function forgetStoredKeyPair() {
  log.debug("Entering forgetStoredKeyPair().");
  if (!window.localStorage) return;
  for (var i = 0; i < KEYPAIR_FIELDS.length; i++) {
    localStorage.removeItem(STORE_PREFIX + KEYPAIR_FIELDS[i]);
  }
  log.debug("Leaving forgetStoredKeyPair().");
}

// Say what clearing the box costs, at the moment it is cleared: the consequence
// lands on the response page after an IdP round trip, which is a long way from
// here to discover it.
function renderKeyPairStorageNote() {
  log.debug("Entering renderKeyPairStorageNote().");
  var note = el('wsfed_keypair_storage_note');
  if (!note) return;
  if (keyPairMayBeStored()) {
    note.textContent = '';
    return;
  }
  // textContent, not innerHTML: this is a message, not markup.
  note.textContent = 'Not saved. Use Download to keep this key pair. After a reload you will need ' +
    'to paste it back into these two fields, and paste the private key into the Decryption Key ' +
    'field on the WS-Federation Response page before an encrypted token can be decrypted.';
  log.debug("Leaving renderKeyPairStorageNote().");
}

function onSaveKeyPairChange() {
  log.debug("Entering onSaveKeyPairChange(). save=" + keyPairMayBeStored());
  // saveState() records the preference itself and, when the box is now clear,
  // removes the key pair it had previously written.
  saveState();
  renderKeyPairStorageNote();
  log.debug("Leaving onSaveKeyPairChange().");
  return false;
}

function saveState() {
  log.debug("Entering saveState().");
  if (!window.localStorage) return;
  var storeKeyPair = keyPairMayBeStored();
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (!els[i].id) continue;
    if (!storeKeyPair && KEYPAIR_FIELDS.indexOf(els[i].id) >= 0) continue;
    var v = els[i].type === 'checkbox' ? (els[i].checked ? '1' : '0') : els[i].value;
    localStorage.setItem(STORE_PREFIX + els[i].id, v);
  }
  // Not merely "skip writing": remove what an earlier save (or an earlier
  // session, before the box was cleared) already put there. saveState() runs on
  // most interactions, so no code path can leave the key pair behind.
  if (!storeKeyPair) forgetStoredKeyPair();
  log.debug("Leaving saveState().");
}
function restoreState() {
  log.debug("Entering restoreState().");
  if (!window.localStorage) return;
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (!els[i].id) continue;
    var v = localStorage.getItem(STORE_PREFIX + els[i].id);
    if (v === null) continue;
    if (els[i].type === 'checkbox') els[i].checked = (v === '1' || v === 'true' || v === 'on');
    else els[i].value = v;
  }
  log.debug("Leaving restoreState().");
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
  log.debug("Entering loadMetadata().");
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
  log.debug("Leaving loadMetadata().");
  return false;
}

function uploadMetadata() {
  var f = el('wsfed_metadata_file');
  if (f) f.click();
  return false;
}
function onMetadataFile(evt) {
  log.debug("Entering onMetadataFile().");
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
  log.debug("Leaving onMetadataFile().");
}

// Parse an XML federation-metadata document and populate the config fields. The
// WS-Federation IdP/STS role is a <RoleDescriptor> whose xsi:type is
// SecurityTokenServiceType; rather than resolve the xsi:type prefix we simply
// pick the RoleDescriptor that CONTAINS a PassiveRequestorEndpoint. Endpoints and
// the signing certificate are read namespace-agnostically.
function parseWsFedMetadata(xmlText) {
  log.debug("Entering parseWsFedMetadata().");
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
  log.debug("Leaving parseWsFedMetadata().");
}

// ---------------------------------------------------------------------------
// Relying-party key pair (RSA + self-signed cert). The certificate is what you
// register at the IdP so it can encrypt the issued token to the RP; the private
// key is used on the response page to decrypt an EncryptedAssertion.
// ---------------------------------------------------------------------------
function generateKeys() {
  log.debug("Entering generateKeys().");
  var bits = parseInt(val('wsfed_key_bits'), 10) || 2048;
  setStatus('wsfed_call_status', 'Generating ' + bits + '-bit RSA key pair…');
  setTimeout(function () {
    try {
      var kp = xd.generateKeyPair(bits, 'ws-federation-debugger-rp');
      setVal('wsfed_rp_private_key', kp.privateKeyPem);
      setVal('wsfed_rp_cert', kp.certPem);
      saveState();
      // Rebuild: with signing on, the request was built unsigned until this
      // moment, and leaving the old one on screen would show a request that is
      // not the one the buttons would now send.
      buildRequestUi();
      if (!signingEnabled()) {
        setStatus('wsfed_call_status', 'Key pair generated. The private key is reused on the response page to decrypt an encrypted token.');
      }
    } catch (e) {
      log.error('generateKeys: ' + e.message);
      setStatus('wsfed_call_status', 'Key generation error: ' + e.message);
    }
  }, 20);
  log.debug("Leaving generateKeys().");
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
  log.debug("Entering signInOptions().");
  log.debug("Leaving signInOptions().");
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

// ---------------------------------------------------------------------------
// Signing the sign-in request.
//
// The Passive Requestor Profile does not REQUIRE a signed sign-in request — the
// IdP is free to ignore one — so this is a debugging affordance: it lets you put
// a signature on the wire and see what an IdP does with it. Two bindings,
// because there are two places a signature can go and they are not
// interchangeable:
//
//   redirect   the SAML HTTP-Redirect construction applied to WS-Federation's
//              query string: append SigAlg, sign the resulting octet string,
//              append Signature. It covers the WHOLE request, which is the only
//              way to protect parameters like wtrealm and wreply — they live in
//              the query and nowhere else.
//
//   enveloped  an XML-DSIG inside the inline `wreq`. It covers only the wreq,
//              because that is the only XML in the request; wtrealm and wreply
//              are outside it and stay unprotected. Choosing this binding
//              therefore IMPLIES an inline wreq — there is nothing to sign
//              without one — and the page turns that on for you rather than
//              silently producing an unsigned request.
//
// Both go through ./xmldsig.js, the same engine the SAML and WS-Trust pages use.
// Nothing here reimplements a signature.
// ---------------------------------------------------------------------------
function signingEnabled() { return checked('wsfed_sign_request'); }
function signingBinding() { return val('wsfed_sig_binding') || 'redirect'; }
function signingAlg() { return val('wsfed_sig_alg') || xd.SIG_ALG_RSA_SHA256; }

// The private key, or null. A signed run without one degrades to UNSIGNED and
// says so — silently sending an unsigned request when the box is ticked is the
// one outcome that would mislead somebody debugging a signature.
function signingKey() {
  var pem = val('wsfed_rp_private_key').trim();
  return /PRIVATE KEY/.test(pem) ? pem : null;
}

// Selecting the enveloped binding needs XML to sign.
function onSigBindingChange() {
  if (signingBinding() === 'enveloped' && !checked('wsfed_include_wreq')) {
    var box = el('wsfed_include_wreq');
    if (box) { box.checked = true; }
    show('wsfed_wreq_section', true);
  }
  saveState();
  autoBuildRequest();
  return false;
}

function onSignRequestChange() {
  show('wsfed_signing_options', signingEnabled());
  saveState();
  autoBuildRequest();
  return false;
}

function buildSignInUrl() {
  var endpoint = val('wsfed_signin_endpoint').trim();
  var opts = signInOptions();
  var wantSigned = signingEnabled();
  var key = wantSigned ? signingKey() : null;

  // Enveloped: sign the wreq itself, then build the query around the signed XML.
  if (wantSigned && key && signingBinding() === 'enveloped') {
    if (!opts.request) {
      lastSigningNote = 'signing is on with the enveloped binding, but there is no inline wreq to ' +
                        'sign — tick "Include wreq" and put the RequestSecurityToken in it.';
    } else {
      opts.request = xd.signEnveloped(opts.request, {
        privateKeyPem: key,
        certPem: val('wsfed_rp_cert').trim() || undefined,
        sigAlg: signingAlg(),
      });
      lastSigningNote = 'enveloped signature on the inline wreq (' + shortAlg(signingAlg()) + ').';
    }
    return wm.buildUrl(endpoint, wm.buildSignInParams(opts));
  }

  var params = wm.buildSignInParams(opts);
  var url = wm.buildUrl(endpoint, params);

  // Redirect: SigAlg is appended BEFORE signing and the signature covers it, so
  // an IdP can tell which algorithm to verify with and cannot be talked into a
  // weaker one by rewriting the parameter.
  if (wantSigned && key) {
    var qIndex = url.indexOf('?');
    var query = qIndex >= 0 ? url.slice(qIndex + 1) : '';
    var base = qIndex >= 0 ? url.slice(0, qIndex) : url;
    var alg = signingAlg();
    var toSign = query + '&SigAlg=' + encodeURIComponent(alg);
    var signature = xd.signQueryString(toSign, { privateKeyPem: key, sigAlg: alg });
    lastSigningNote = 'signed query string (' + shortAlg(alg) + ').';
    return base + '?' + toSign + '&Signature=' + encodeURIComponent(signature);
  }

  if (wantSigned && !key) {
    lastSigningNote = 'NOT signed: no RP private key. Press Generate Keys, or paste one, and the ' +
                      'request will be rebuilt.';
  } else {
    lastSigningNote = '';
  }
  return url;
}

// Last thing the build said about signing, rendered into the status line. Kept
// as state rather than returned, because buildSignInUrl() is also called by the
// two dispatch paths, which want the URL and not a report.
var lastSigningNote = '';

function shortAlg(uri) {
  var m = /#(rsa-sha\d+)$/.exec(String(uri));
  return m ? m[1] : uri;
}
function buildSignOutUrl() {
  var endpoint = (val('wsfed_signout_endpoint') || val('wsfed_signin_endpoint')).trim();
  var params = wm.buildSignOutParams({ reply: val('wsfed_reply'), realm: val('wsfed_realm') });
  return wm.buildUrl(endpoint, params);
}

function autoBuildRequest() { try { buildRequestUi(); } catch (e) { log.error('autoBuildRequest: ' + e.message); } return false; }
function buildRequestUi() {
  log.debug("Entering buildRequestUi().");
  try {
    var url = buildSignInUrl();
    setVal('wsfed_generated_request', url);
    setStatus('wsfed_call_status', 'Built wsignin1.0 request' +
      (checked('wsfed_include_wreq') ? ' (with inline wreq)' : '') +
      (lastSigningNote ? ' — ' + lastSigningNote : '.'));
  } catch (e) {
    log.error('buildRequestUi: ' + e.message);
    setStatus('wsfed_call_status', 'Build failed: ' + e.message);
  }
  log.debug("Leaving buildRequestUi().");
  return false;
}

// ---------------------------------------------------------------------------
// Drive the browser to the IdP. Sign-in/out are top-level navigations (the IdP
// then auto-POSTs wresult back to wreply), so there is no fetch/CORS here.
// ---------------------------------------------------------------------------
function callIdp() {
  log.debug("Entering callIdp().");
  var endpoint = val('wsfed_signin_endpoint').trim();
  if (!endpoint) { setStatus('wsfed_call_status', 'Enter (or load from metadata) the IdP passive sign-in endpoint first.'); return false; }
  if (!val('wsfed_realm').trim()) { setStatus('wsfed_call_status', 'Enter the RP realm (wtrealm) first.'); return false; }
  var url = buildSignInUrl();
  // The endpoint came from a form field (or from IdP metadata), so it is
  // caller-supplied and reaches a navigation sink. Refuse anything that is not
  // http/https rather than execute it.
  var target;
  try {
    target = urlSafety.safeExternalUrl(url, 'The IdP sign-in endpoint');
  } catch (e) {
    setStatus('wsfed_call_status', e.message);
    return false;
  }
  setStatus('wsfed_call_status', 'Navigating to the IdP…');
  saveState();
  // Record the attempt BEFORE navigating: this page is about to be replaced by
  // the IdP's, so anything written after the assign() may never run. The entry
  // goes in as `Sent` and wsfed_response.html resolves it to Success or Failure
  // when the wresult arrives — the two pages match on the operation label, which
  // is why that label is exported from ./wsfed_history rather than typed here.
  history.record({
    operation: history.OP_SIGN_IN,
    result: history.SENT,
    detail: 'sign-in request dispatched to the IdP',
    wtrealm: val('wsfed_realm').trim(),
    wreply: val('wsfed_reply').trim(),
    idp: endpoint,
  });
  window.location.assign(target);
  log.debug("Leaving callIdp().");
  return false;
}
function signOut() {
  log.debug("Entering signOut().");
  var endpoint = (val('wsfed_signout_endpoint') || val('wsfed_signin_endpoint')).trim();
  if (!endpoint) { setStatus('wsfed_call_status', 'Enter (or load from metadata) the IdP sign-in/sign-out endpoint first.'); return false; }
  var url = buildSignOutUrl();
  var target;
  try {
    target = urlSafety.safeExternalUrl(url, 'The IdP sign-out endpoint');
  } catch (e) {
    setStatus('wsfed_call_status', e.message);
    return false;
  }
  setStatus('wsfed_call_status', 'Navigating to the IdP sign-out…');
  saveState();
  history.record({
    operation: history.OP_SIGN_OUT,
    result: history.SENT,
    detail: 'sign-out request dispatched to the IdP',
    wtrealm: val('wsfed_realm').trim(),
    wreply: val('wsfed_reply').trim(),
    idp: endpoint,
  });
  window.location.assign(target);
  log.debug("Leaving signOut().");
  return false;
}

// ---------------------------------------------------------------------------
// Misc UI (shared shapes with wstrust_tools.js / saml_tools.js).
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Operations History (shared with wsfed_response.html via ./wsfed_history.js):
// this page can only record that a sign-in or sign-out was DISPATCHED — the
// IdP's verdict arrives on the response page, which closes the entry out.
// ---------------------------------------------------------------------------
function renderOperationHistory() { history.render(el('wsfed_operation_history')); }
function clearOperationHistory() {
  history.clear();
  renderOperationHistory();
  // Reflect the restored signing preference before the first build.
  show('wsfed_signing_options', signingEnabled());
  return false;
}

function copyField(id) {
  log.debug("Entering copyField().");
  var e = el(id);
  if (!e) return false;
  var text = e.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error('copyField: ' + err); });
  } else {
    try { e.focus(); e.select(); document.execCommand('copy'); } catch (err) { log.error('copyField fallback: ' + err.message); }
  }
  log.debug("Leaving copyField().");
  return false;
}
function togglePane(bodyId) {
  var b = el(bodyId);
  if (b) b.style.display = (b.style.display === 'none') ? 'block' : 'none';
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
function viewCertificate(fieldId) {
  var pem = val(fieldId);
  if (!pem) { setStatus('wsfed_config_status', 'No certificate to view yet.'); return false; }
  try { if (window.localStorage) localStorage.setItem('saml_cert_view', pem); } catch (e) { /* ignore */ }
  window.open('/saml_cert.html?from=wsfed_request.html', '_blank');
  return false;
}

// Static (backend-less) build: no API proxy / landing endpoint, so the sign-in
// must be driven directly from the browser and the wresult can't be captured
// server-side. Force the Front radio on and disable the Back radio, mirroring
// wstrust_tools.js / the OAuth2 debugger.
// Is there anything at wsfedAcsUrl that can receive the IdP's auto-POST?
//
// With the api backend, yes — its /wsfed landing. Without it, only if the
// deployment put a Lambda@Edge on that path (infra/edge/wsfed_landing.js), which
// the env config declares with wsfedEdgeLanding. It is a separate flag rather
// than "wsfedAcsUrl is set" because the static envs have always carried that URL
// while nothing answered it, and rather than being inferred from backendAvailable
// because the edge landing is deployed by Terraform, not by the site build: a
// checkout can be redeployed without the infrastructure having been applied yet.
function hasWsFedLanding() {
  if (appconfig.backendAvailable !== false) return true;
  return appconfig.wsfedEdgeLanding === true && !!appconfig.wsfedAcsUrl;
}

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
  // Reflect the restored preference: if saving was turned off in an earlier
  // session, the note belongs back on the page, and a key pair written before
  // that has to go.
  if (!keyPairMayBeStored()) forgetStoredKeyPair();
  renderKeyPairStorageNote();

  var f = el('wsfed_metadata_file');
  if (f) f.addEventListener('change', onMetadataFile);

  // The log survives page loads (it lives in local storage), so it is rendered
  // on arrival rather than only after a dispatch — coming back from the IdP
  // should show the entry the response page just closed out.
  renderOperationHistory();

  // Seed defaults for blank fields (fresh page).
  if (!val('wsfed_metadata_url') && appconfig.wsfedMetadataUrlDefault) setVal('wsfed_metadata_url', appconfig.wsfedMetadataUrlDefault);
  if (!val('wsfed_realm')) setVal('wsfed_realm', appconfig.wsfedRealm || appconfig.spEntityId || '');
  // wreply target — where the IdP auto-POSTs the token. Three deployments, two
  // of which can receive that POST:
  //   * API backend            -> its /wsfed landing (appconfig.wsfedAcsUrl).
  //   * static + edge landing  -> the SAME path, answered by the Lambda@Edge in
  //     infra/edge/wsfed_landing.js instead of by Express. That is the whole
  //     point of the Lambda: the passive profile has no redirect response
  //     binding to fall back to the way SAML does, so without something at the
  //     edge a static site cannot complete the round trip at all.
  //   * static, no edge landing -> the static response page, which cannot be
  //     POSTed to; the sign-in ends there and the wresult must be pasted in.
  if (!val('wsfed_reply')) {
    var replyDefault = hasWsFedLanding()
      ? (appconfig.wsfedAcsUrl || '')
      : (window.location.origin + '/wsfed_response.html');
    if (replyDefault) setVal('wsfed_reply', replyDefault);
  }

  // The static-deployment notice is shown whenever there is no backend, but the
  // sentence about the token needing a manual paste is only true when there is
  // also no edge landing to catch the POST.
  show('wsfed_backend_notice', appconfig.backendAvailable === false);
  show('wsfed_manual_capture_notice', !hasWsFedLanding());
  show('wsfed_edge_landing_notice', appconfig.backendAvailable === false && hasWsFedLanding());
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
  log.debug("Leaving onload().");
};

module.exports = {
  loadMetadata,
  uploadMetadata,
  onIncludeWreqChange,
  onSignRequestChange,
  onSigBindingChange,
  generateKeys,
  downloadKeys,
  buildRequestUi,
  callIdp,
  signOut,
  viewCertificate,
  copyField,
  clearOperationHistory,
  onSaveKeyPairChange,
  showTab,
  togglePane
};
