// File: saml_request.js
// Author: Robert C. Broeckelmann Jr.
//
// SAML Test Tools — configuration page.
//
//   Pane 1 (IdP Metadata): load a SAML 2.0 metadata document (via the API
//     metadata proxy, to avoid browser CORS to the IdP), parse it, and populate
//     the SSO/SLO endpoint URLs (HTTP-POST / HTTP-Redirect / HTTP-Artifact),
//     the Artifact Resolution Service, the advertised NameIDFormat values, the
//     IdP entityID, and the signer certificate.
//   Pane 2 (SP / Request): choose protocol version + binding, an optional
//     username hint (structure constrained by the selected NameIDFormat),
//     generate an SP RSA key pair + self-signed certificate, build the
//     AuthnRequest, and (Call) sign it and send it to the IdP.
//
// SAML request signing is performed entirely IN THE BROWSER (no server round
// trip): the Redirect binding signs the query string, and the POST binding
// produces an enveloped XML-DSIG, both with node-forge + a small Canonical XML
// (C14N) implementation (deflate-raw via the native CompressionStream). The API
// is only involved for the artifact RESPONSE binding, where the ACS must run a
// SOAP ArtifactResolve (a server back-channel) — the browser registers the SP
// context via /samlartifactctx, then still signs+sends the request itself. Only
// SAML 2.0 is functional; 1.0/1.1 are reference-only (IdP-initiated, no signed
// SP request).
//
// Everything the user configures is persisted to localStorage (keyed by element
// id) so it survives a page reload — including, per design, the generated SP
// private key. That key is a throwaway test key; do not reuse a production key.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var forge = require("node-forge");
var history = require("./saml_history");
var log = bunyan.createLogger({ name: 'saml_request', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// SAML 2.0 binding URIs.
var BINDING = {
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
  redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
  artifact: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
  soap: "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
};
var SIG_ALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
// Unchanged across the saml_tools -> saml_request rename: renaming it would
// orphan every visitor's saved configuration, and saml_cert.js reads the
// signer certificate back out under this same prefix.
var STORE_PREFIX = "samltools_";
var NAMEID_OPTIONS_KEY = STORE_PREFIX + "nameid_options";

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------
function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ''; }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function setStatus(id, msg) { setVal(id, msg); }
function show(id, on) { var e = el(id); if (e) { if (on) e.classList.remove('saml-hidden'); else e.classList.add('saml-hidden'); } }

// RFC 4122-ish id suitable for an XML ID (must be an NCName: start with letter/_)
function genId() {
  var b = new Uint8Array(16);
  (window.crypto || window.msCrypto).getRandomValues(b);
  var hex = '';
  for (var i = 0; i < b.length; i++) { hex += ('0' + b[i].toString(16)).slice(-2); }
  return '_' + hex;
}

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
  log.debug("Entering restoreState().");
  if (!window.localStorage) return;
  // NameIDFormat <select> options come from metadata; rebuild them first so the
  // saved selection has a matching <option>.
  var savedOpts = localStorage.getItem(NAMEID_OPTIONS_KEY);
  if (savedOpts) {
    try {
      populateNameIdOptions(JSON.parse(savedOpts));
    } catch (e) {
      // Not JSON: keep the default.
    }
  }
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
// Metadata loading + parsing
// ---------------------------------------------------------------------------
function loadMetadata() {
  log.debug("Entering loadMetadata().");
  var url = val('saml_metadata_url').trim();
  if (!url) {
    setStatus('saml_metadata_status', 'Enter a metadata URL first.');
    return opFailure('Load IdP Metadata', 'no metadata URL was entered.', { binding: '—' });
  }
  setStatus('saml_metadata_status', 'Loading…');
  // With a backend, go through the API metadata proxy (it dodges cross-origin
  // CORS restrictions on the IdP's metadata endpoint). On the static
  // (backend-less) deployment, fetch the metadata URL directly from the browser —
  // works whenever the IdP serves permissive CORS on its descriptor (a CORS/
  // network failure is surfaced in the status line below).
  var fetchUrl = appconfig.backendAvailable
    ? (appconfig.apiUrl + '/samlmetadata?url=' + encodeURIComponent(btoa(url)))
    : url;
  fetch(fetchUrl)
    .then(function (r) {
      if (!r.ok) { throw new Error('HTTP ' + r.status); }
      return r.text();
    })
    .then(function (xmlText) { applyMetadata(xmlText, url); })
    .catch(function (e) {
      log.error('loadMetadata: ' + e.message);
      opFailure('Load IdP Metadata', e.message, { binding: '—', idpEntityId: '' });
      setStatus('saml_metadata_status', 'Load failed: ' + e.message +
        (appconfig.backendAvailable ? '' : ' — the browser fetched the metadata URL directly; the IdP endpoint may not permit cross-origin (CORS) requests.'));
    });
  log.debug("Leaving loadMetadata().");
  return false;
}

// Show + parse a metadata document (from a URL load or an uploaded file). The
// "Loaded and parsed." status is the signal the test suite waits on.
function applyMetadata(xmlText, url) {
  log.debug("Entering applyMetadata().");
  // Show the raw document in the Metadata Document tab (even if parsing fails).
  setVal('saml_metadata_doc', xmlText);
  try {
    parseMetadata(xmlText);
    setStatus('saml_metadata_status', 'Loaded and parsed.');
    // Recorded after the parse so the IdP entityID it just populated is shown.
    opSuccess('Load IdP Metadata', url ? ('loaded from ' + url) : 'loaded from a local file', { binding: '—' });
    saveState();
    autoBuildRequest(); // metadata populated the destination/NameIDFormat, etc.
    validateConfigUrls();
  } catch (e) {
    log.error('parseMetadata: ' + e.message);
    setStatus('saml_metadata_status', 'Parse error: ' + e.message);
    opFailure('Load IdP Metadata', 'parse error: ' + e.message, { binding: '—' });
  }
  log.debug("Leaving applyMetadata().");
}

// Upload a metadata document from a local file (no URL fetch / backend needed).
function uploadMetadata() {
  var f = el('saml_metadata_file');
  if (f) f.click();
  return false;
}
function onMetadataFileChange(evt) {
  log.debug("Entering onMetadataFileChange().");
  var input = evt && evt.target;
  var file = input && input.files && input.files[0];
  if (!file) return false;
  setStatus('saml_metadata_status', 'Reading ' + file.name + '…');
  var reader = new FileReader();
  reader.onload = function () {
    applyMetadata(String(reader.result || ''));
    if (input) input.value = ''; // allow re-selecting the same file
  };
  reader.onerror = function () { setStatus('saml_metadata_status', 'Could not read file: ' + file.name); };
  reader.readAsText(file);
  log.debug("Leaving onMetadataFileChange().");
  return false;
}

// Namespace-agnostic element lookup (metadata uses md:/ds: prefixes).
function tags(root, localName) {
  return root.getElementsByTagNameNS('*', localName);
}

function parseMetadata(xmlText) {
  log.debug("Entering parseMetadata().");
  var doc = new DOMParser().parseFromString(xmlText, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    throw new Error('malformed XML');
  }
  var ed = tags(doc, 'EntityDescriptor')[0];
  if (!ed) throw new Error('no EntityDescriptor');
  setVal('saml_idp_entity_id', ed.getAttribute('entityID') || '');

  var idp = tags(doc, 'IDPSSODescriptor')[0] || ed;

  // SSO endpoints by binding.
  var ssoPost = '', ssoRedirect = '', ssoArtifact = '';
  var ssos = tags(idp, 'SingleSignOnService');
  for (var i = 0; i < ssos.length; i++) {
    var b = ssos[i].getAttribute('Binding'), loc = ssos[i].getAttribute('Location');
    if (b === BINDING.post) ssoPost = loc;
    else if (b === BINDING.redirect) ssoRedirect = loc;
    else if (b === BINDING.artifact) ssoArtifact = loc;
  }
  setVal('saml_sso_post', ssoPost);
  setVal('saml_sso_redirect', ssoRedirect);
  setVal('saml_sso_artifact', ssoArtifact);

  // SLO endpoints by binding.
  var sloPost = '', sloRedirect = '', sloArtifact = '';
  var slos = tags(idp, 'SingleLogoutService');
  for (var j = 0; j < slos.length; j++) {
    var sb = slos[j].getAttribute('Binding'), sloc = slos[j].getAttribute('Location');
    if (sb === BINDING.post) sloPost = sloc;
    else if (sb === BINDING.redirect) sloRedirect = sloc;
    else if (sb === BINDING.artifact) sloArtifact = sloc;
  }
  setVal('saml_slo_post', sloPost);
  setVal('saml_slo_redirect', sloRedirect);
  setVal('saml_slo_artifact', sloArtifact);

  // Artifact Resolution Service (SOAP back-channel).
  var ars = tags(idp, 'ArtifactResolutionService')[0];
  setVal('saml_ars', ars ? (ars.getAttribute('Location') || '') : '');

  // NameIDFormat list.
  var nifs = tags(idp, 'NameIDFormat');
  var formats = [];
  for (var k = 0; k < nifs.length; k++) {
    var t = (nifs[k].textContent || '').trim();
    if (t) formats.push(t);
  }
  populateNameIdOptions(formats);
  if (window.localStorage) localStorage.setItem(NAMEID_OPTIONS_KEY, JSON.stringify(formats));

  // Signer certificate: KeyDescriptor[use=signing] X509Certificate. Fall back to
  // any KeyDescriptor if none is explicitly marked "signing".
  var signerCert = '';
  var kds = tags(idp, 'KeyDescriptor');
  for (var m = 0; m < kds.length; m++) {
    var use = kds[m].getAttribute('use');
    if (use === 'signing' || use === '' || use === null) {
      var certEl = tags(kds[m], 'X509Certificate')[0];
      if (certEl) {
        signerCert = (certEl.textContent || '').replace(/\s+/g, '');
        if (use === 'signing') break; // prefer an explicit signing key
      }
    }
  }
  setVal('saml_signer_cert', signerCert);
  // Default the encryption certificate to the IdP signer cert. A freshly loaded
  // metadata document OVERWRITES any previous value; between loads the user's
  // edits persist (localStorage). loadMetadata() calls saveState() after this.
  if (signerCert) setVal('saml_enc_cert', signerCert);
  onNameIdFormatChange();
  log.debug("Leaving parseMetadata().");
}

function populateNameIdOptions(formats) {
  log.debug("Entering populateNameIdOptions().");
  var sel = el('saml_nameid_format');
  if (!sel) return;
  sel.innerHTML = '';
  // Default "nothing chosen": the AuthnRequest still sends a <NameIDPolicy> (with
  // AllowCreate) but WITHOUT a Format, so the IdP picks its default and cannot
  // reject the request with InvalidNameIDPolicy. Selecting a specific format
  // below sends that Format explicitly.
  var def = document.createElement('option');
  def.value = '';
  def.text = '(none — send NameIDPolicy without a Format; let the IdP choose)';
  sel.appendChild(def);
  if (formats && formats.length) {
    for (var i = 0; i < formats.length; i++) {
      var opt = document.createElement('option');
      opt.value = formats[i];
      opt.text = shortNameId(formats[i]);
      sel.appendChild(opt);
    }
  }
  sel.value = ''; // default to "none chosen"
  log.debug("Leaving populateNameIdOptions().");
}

// Trim the long urn:...:nameid-format:xxx to its last segment for display.
function shortNameId(fmt) {
  var idx = fmt.lastIndexOf(':');
  return idx >= 0 ? fmt.substring(idx + 1) + '  (' + fmt + ')' : fmt;
}

// ---------------------------------------------------------------------------
// NameIDFormat -> username-hint restriction
// ---------------------------------------------------------------------------
function hintRuleFor(fmt) {
  log.debug("Entering hintRuleFor().");
  var f = (fmt || '').toLowerCase();
  if (f.indexOf('emailaddress') >= 0) {
    return { placeholder: 'user@example.com', help: 'emailAddress format: enter an email address.',
             test: function (v) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v); }, allowed: true };
  }
  if (f.indexOf('x509subjectname') >= 0) {
    return { placeholder: 'CN=User,O=Org,C=US', help: 'X509SubjectName format: enter an X.500 distinguished name.',
             test: function (v) { return /=/.test(v); }, allowed: true };
  }
  if (f.indexOf('windowsdomainqualifiedname') >= 0) {
    return { placeholder: 'DOMAIN\\user', help: 'WindowsDomainQualifiedName: enter DOMAIN\\username.',
             test: function (v) { return /\\/.test(v); }, allowed: true };
  }
  if (f.indexOf('persistent') >= 0 || f.indexOf('transient') >= 0) {
    return { placeholder: '(hint not applicable)', help: 'persistent/transient identifiers are IdP-assigned — a username hint does not apply and will be ignored.',
             test: function () { return true; }, allowed: false };
  }
  // unspecified, kerberos, entity, or unknown -> free text
  log.debug("Leaving hintRuleFor().");
  return { placeholder: 'username', help: 'unspecified format: any value is allowed.',
           test: function () { return true; }, allowed: true };
}

function onNameIdFormatChange() {
  var rule = hintRuleFor(val('saml_nameid_format'));
  var hint = el('saml_username_hint');
  if (hint) {
    hint.placeholder = rule.placeholder;
    hint.disabled = !rule.allowed;
  }
  setVal('saml_hint_help', rule.help);
  validateHint();
  saveState();
  return false;
}

function validateHint() {
  var rule = hintRuleFor(val('saml_nameid_format'));
  var v = val('saml_username_hint').trim();
  var hint = el('saml_username_hint');
  if (!hint) return true;
  if (!v || !rule.allowed) { hint.style.borderColor = ''; return true; }
  var ok = rule.test(v);
  hint.style.borderColor = ok ? '' : '#e0a800';
  setVal('saml_hint_help', rule.help + (ok ? '' : '  ⚠ value does not match the selected format.'));
  saveState();
  return ok;
}

function onVersionChange() {
  var v = val('saml_version');
  show('saml_version_warning', v !== '2.0');
  saveState();
  return false;
}

// Toggle the SP Signing Key Pair section with the "Digitally sign the
// AuthnRequest" checkbox (checked => visible).
function onSignChange() {
  var e = el('saml_sign_request');
  show('saml_signing_section', !e || e.checked);
  saveState();
  return false;
}

// Toggle the AuthnRequest Encryption section with the "Encrypt the AuthnRequest"
// checkbox (checked => visible; default unchecked/hidden).
function onEncryptChange() {
  var e = el('saml_encrypt_request');
  show('saml_encryption_section', !!(e && e.checked));
  saveState();
  return false;
}

// Toggle the WS-Addressing section with the "Add WS-Addressing headers" checkbox
// (checked => visible; default unchecked/hidden). The checkbox is also the enable
// flag read when building the ArtifactResolve SOAP envelope.
function onWsaChange() {
  var e = el('saml_wsa_support');
  show('saml_wsa_section', !!(e && e.checked));
  saveState();
  return false;
}

// ---------------------------------------------------------------------------
// SP key-pair generation (RSA via node-forge) + self-signed certificate
// ---------------------------------------------------------------------------
function generateKeys() {
  log.debug("Entering generateKeys().");
  var bits = parseInt(val('saml_key_bits'), 10) || 2048;
  setStatus('saml_call_status', 'Generating ' + bits + '-bit RSA key pair…');
  // Defer so the status paints before the (synchronous, slow) keygen runs.
  setTimeout(function () {
    try {
      var kp = forge.pki.rsa.generateKeyPair({ bits: bits, e: 0x10001 });
      setVal('saml_sp_private_key', forge.pki.privateKeyToPem(kp.privateKey).trim() + '\n');
      // The SP's public credential is presented as its self-signed certificate.
      // The field id keeps the legacy "saml_sp_public_key" name (localStorage /
      // stored-state compatibility), but it holds the certificate PEM.
      setVal('saml_sp_public_key', spSelfSignedCertPem(kp));
      setStatus('saml_call_status', 'Key pair generated.');
      saveState();
      autoBuildRequest(); // re-sign the request now that a key pair exists
    } catch (e) {
      log.error('generateKeys: ' + e.message);
      setStatus('saml_call_status', 'Key generation error: ' + e.message);
    }
  }, 20);
  log.debug("Leaving generateKeys().");
  return false;
}

function spSelfSignedCertPem(kp) {
  log.debug("Entering spSelfSignedCertPem().");
  var cert = forge.pki.createCertificate();
  cert.publicKey = kp.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
  var attrs = [{ name: 'commonName', value: val('saml_sp_entity_id') || 'saml-debugger-sp' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(kp.privateKey, forge.md.sha256.create());
  log.debug("Leaving spSelfSignedCertPem().");
  return forge.pki.certificateToPem(cert).trim() + '\n';
}

function downloadKeys() {
  var priv = val('saml_sp_private_key');
  if (!priv) { setStatus('saml_call_status', 'Generate a key pair first.'); return false; }
  triggerDownload('sp-private-key.pem', priv, 'application/x-pem-file');
  triggerDownload('sp-certificate.pem', val('saml_sp_public_key'), 'application/x-pem-file');
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

// ---------------------------------------------------------------------------
// SP metadata (EntityDescriptor) — describes this debugger as a Service
// Provider so it can be registered on the IdP.
// ---------------------------------------------------------------------------
function certPemToB64(pem) {
  return String(pem || '')
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

function buildSpMetadata() {
  log.debug("Entering buildSpMetadata().");
  var entityId = val('saml_sp_entity_id');
  var acs = val('saml_acs_url');
  var slo = appconfig.sloUrl || '';
  var fmt = val('saml_nameid_format');
  var certB64 = certPemToB64(val('saml_sp_public_key'));

  var keyDescriptor = certB64
    ? '\n    <md:KeyDescriptor use="signing">' +
      '\n      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      '\n        <ds:X509Data><ds:X509Certificate>' + certB64 + '</ds:X509Certificate></ds:X509Data>' +
      '\n      </ds:KeyInfo>' +
      '\n    </md:KeyDescriptor>'
    : '';
  var sloSvc = slo
    ? '\n    <md:SingleLogoutService Binding="' + BINDING.post + '" Location="' + xmlEscape(slo) + '"/>' +
      '\n    <md:SingleLogoutService Binding="' + BINDING.redirect + '" Location="' + xmlEscape(slo) + '"/>'
    : '';
  var nameIdFmt = fmt ? '\n    <md:NameIDFormat>' + xmlEscape(fmt) + '</md:NameIDFormat>' : '';
  var acsSvc = acs
    ? '\n    <md:AssertionConsumerService Binding="' + BINDING.post + '" Location="' + xmlEscape(acs) + '" index="0" isDefault="true"/>' +
      '\n    <md:AssertionConsumerService Binding="' + BINDING.artifact + '" Location="' + xmlEscape(acs) + '" index="1"/>'
    : '';

  log.debug("Leaving buildSpMetadata().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
         '\n<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' + xmlEscape(entityId) + '">' +
         '\n  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"' +
         ' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
         keyDescriptor + sloSvc + nameIdFmt + acsSvc +
         '\n  </md:SPSSODescriptor>' +
         '\n</md:EntityDescriptor>\n';
}

function downloadSpMetadata() {
  if (!val('saml_sp_entity_id')) { setStatus('saml_call_status', 'Set the SP entityID first.'); return false; }
  triggerDownload('sp-metadata.xml', buildSpMetadata(), 'application/samlmetadata+xml');
  setStatus('saml_call_status', 'SP metadata downloaded.');
  return false;
}

// ---------------------------------------------------------------------------
// AuthnRequest construction
// ---------------------------------------------------------------------------
function xmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function ssoDestination(binding) {
  // The AuthnRequest itself is delivered via HTTP-POST or HTTP-Redirect. The
  // "artifact" choice affects only how the *response* comes back (ProtocolBinding
  // = HTTP-Artifact), so the request is still sent to the Redirect SSO endpoint.
  if (binding === 'post') return val('saml_sso_post');
  return val('saml_sso_redirect');
}

// Which binding the IdP should use to return the response.
//   * artifact request flow → HTTP-Artifact (resolved server-side at the ACS).
//   * with a backend         → HTTP-POST: the ACS is a real POST endpoint that
//                              stashes the (large) SAMLResponse and redirects here.
//   * backendless (static)   → HTTP-Redirect: there is no server to receive a
//                              POST, so ask the IdP to hand the response back as a
//                              GET query (?SAMLResponse=…) that saml_response.html
//                              reads and decodes entirely in the browser. NOTE:
//                              the IdP must permit the Redirect binding for a
//                              (signed) login Response, and the deflated+base64
//                              assertion must fit the URL-length limits of the
//                              browser / CDN — otherwise use the API backend.
function responseProtocolBinding(binding) {
  if (binding === 'artifact') return BINDING.artifact;
  return appconfig.backendAvailable ? BINDING.post : BINDING.redirect;
}

function buildAuthnRequest() {
  log.debug("Entering buildAuthnRequest().");
  var version = val('saml_version');
  var binding = val('saml_binding');
  var dest = ssoDestination(binding);
  var acs = val('saml_acs_url');
  var issuer = val('saml_sp_entity_id');
  var fmt = val('saml_nameid_format');
  var hint = val('saml_username_hint').trim();
  var rule = hintRuleFor(fmt);

  if (version !== '2.0') {
    return '<!-- SAML ' + version + ' has no SP-initiated AuthnRequest. SAML 1.x Web SSO\n' +
           '     is IdP-initiated (Browser/Artifact or Browser/POST) with no signed SP\n' +
           '     request, and SAML 2.0 IdPs (e.g. Keycloak) will not accept a 1.x request.\n' +
           '     Switch to SAML 2.0 to build and send a real request. -->';
  }

  var id = genId();
  var instant = new Date().toISOString();
  var subject = '';
  if (hint && rule.allowed) {
    subject = '\n  <saml:Subject><saml:NameID' + (fmt ? ' Format="' + xmlEscape(fmt) + '"' : '') +
              '>' + xmlEscape(hint) + '</saml:NameID></saml:Subject>';
  }
  var nameIdPolicy = '\n  <samlp:NameIDPolicy' + (fmt ? ' Format="' + xmlEscape(fmt) + '"' : '') + ' AllowCreate="true"/>';

  log.debug("Leaving buildAuthnRequest().");
  return '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
         ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
         ' ID="' + id + '" Version="2.0" IssueInstant="' + instant + '"' +
         (dest ? ' Destination="' + xmlEscape(dest) + '"' : '') +
         ' ProtocolBinding="' + responseProtocolBinding(binding) + '"' +
         (acs ? ' AssertionConsumerServiceURL="' + xmlEscape(acs) + '"' : '') + '>' +
         '\n  <saml:Issuer>' + xmlEscape(issuer) + '</saml:Issuer>' +
         subject + nameIdPolicy +
         '\n</samlp:AuthnRequest>';
}

// ---------------------------------------------------------------------------
// Client-side request signing (no server round-trip).
//   * Redirect binding: DEFLATE (deflate-raw) + base64 + RSA-SHA256 over the
//     query string — a detached signature per saml-bindings-2.0-os §3.4.4.1.
//   * POST binding: enveloped XML-DSIG (RSA-SHA256) using EXCLUSIVE Canonical
//     XML 1.0, computed here with node-forge + the C14N implementation below.
// node-forge is already bundled (key generation); the only extra primitive is
// deflate-raw, provided by the native CompressionStream.
//
// Exclusive (not inclusive) C14N is required: the verifier (Keycloak/Santuario)
// canonicalizes <ds:SignedInfo> as it sits nested inside <ds:Signature> inside
// <samlp:AuthnRequest xmlns:samlp=… xmlns:saml=…>. Inclusive C14N would pull
// those inherited saml/samlp declarations onto SignedInfo — but we sign it
// standalone (only ds in scope), so the two byte streams would differ and the
// signature would never verify. Exclusive C14N renders only the namespaces a
// subtree *visibly utilizes* (SignedInfo → just ds), so standalone == nested.
// ---------------------------------------------------------------------------
var DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
var C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';
var TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
var DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
var XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';
var XENC11_NS = 'http://www.w3.org/2009/xmlenc11#';

function bytesToBase64(bytes) {
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function utf8ToBase64(str) { return btoa(unescape(encodeURIComponent(str))); }

// DEFLATE (raw, no zlib header) via the native CompressionStream (async).
function deflateRaw(str) {
  if (typeof CompressionStream === 'undefined') {
    return Promise.reject(new Error('This browser lacks CompressionStream; cannot DEFLATE for the redirect binding.'));
  }
  var cs = new CompressionStream('deflate-raw');
  var writer = cs.writable.getWriter();
  writer.write(new TextEncoder().encode(str));
  writer.close();
  return new Response(cs.readable).arrayBuffer().then(function (buf) { return new Uint8Array(buf); });
}

function digestBase64(str, mdFactory) {
  var md = mdFactory();
  md.update(str, 'utf8');
  return forge.util.encode64(md.digest().getBytes());
}

// XML Signature SignatureMethod URI -> forge digest factory + the matching
// Reference DigestMethod URI. The selected algorithm drives both the redirect
// SigAlg and the POST enveloped SignatureMethod/DigestMethod. The SP key is RSA,
// so these are the RSA-family methods from xmldsig / xmldsig-more (RFC 6931).
function sigAlgSpec(uri) {
  log.debug("Entering sigAlgSpec().");
  switch (uri) {
    case 'http://www.w3.org/2000/09/xmldsig#rsa-sha1':
      return { md: forge.md.sha1.create, digestUri: 'http://www.w3.org/2000/09/xmldsig#sha1' };
    case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384':
      return { md: forge.md.sha384.create, digestUri: 'http://www.w3.org/2001/04/xmldsig-more#sha384' };
    case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512':
      return { md: forge.md.sha512.create, digestUri: 'http://www.w3.org/2001/04/xmlenc#sha512' };
    case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256':
    default:
      return { md: forge.md.sha256.create, digestUri: 'http://www.w3.org/2001/04/xmlenc#sha256' };
  }
  log.debug("Leaving sigAlgSpec().");
}
function selectedSigAlg() { return val('saml_sig_alg') || SIG_ALG_RSA_SHA256; }

// HTTP-Redirect binding: build the query string, optionally with a detached
// signature (doSign, default true). Returns { location, queryString }. `xml` is
// whatever payload is being sent — the plain AuthnRequest, or the encrypted
// EncryptedData when encryption is enabled (the signature then covers the
// deflated encrypted payload).
function signRedirect(xml, dest, relayState, doSign) {
  log.debug("Entering signRedirect().");
  if (doSign === undefined) doSign = true;
  log.debug("Leaving signRedirect().");
  return deflateRaw(xml).then(function (bytes) {
    var qs = 'SAMLRequest=' + encodeURIComponent(bytesToBase64(bytes));
    if (relayState) qs += '&RelayState=' + encodeURIComponent(relayState);
    if (doSign) {
      var alg = selectedSigAlg();
      qs += '&SigAlg=' + encodeURIComponent(alg);
      var pk = forge.pki.privateKeyFromPem(val('saml_sp_private_key'));
      var md = sigAlgSpec(alg).md();
      md.update(qs, 'utf8'); // the query string is ASCII
      qs += '&Signature=' + encodeURIComponent(forge.util.encode64(pk.sign(md)));
    }
    var location = dest ? (dest + (dest.indexOf('?') >= 0 ? '&' : '?') + qs) : qs;
    return { location: location, queryString: qs };
  });
}

// HTTP-POST binding: enveloped XML-DSIG. Returns the signed XML string. The
// <Signature> is placed after <Issuer> per the SAML schema.
function signPostEnveloped(xml) {
  log.debug("Entering signPostEnveloped().");
  var certB64 = certPemToB64(val('saml_sp_public_key'));
  var alg = selectedSigAlg();
  var spec = sigAlgSpec(alg);
  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  var root = doc.documentElement;
  var id = root.getAttribute('ID') || '';

  // Reference digest: c14n(root) — no <Signature> present yet, which is exactly
  // what the enveloped-signature transform reproduces at verification time.
  var digest = digestBase64(canonicalize(root), spec.md);

  var signedInfo = '<ds:SignedInfo xmlns:ds="' + DS_NS + '">' +
    '<ds:CanonicalizationMethod Algorithm="' + C14N_EXCLUSIVE + '"/>' +
    '<ds:SignatureMethod Algorithm="' + alg + '"/>' +
    '<ds:Reference URI="#' + id + '">' +
    '<ds:Transforms>' +
    '<ds:Transform Algorithm="' + TRANSFORM_ENVELOPED + '"/>' +
    '<ds:Transform Algorithm="' + C14N_EXCLUSIVE + '"/>' +
    '</ds:Transforms>' +
    '<ds:DigestMethod Algorithm="' + spec.digestUri + '"/>' +
    '<ds:DigestValue>' + digest + '</ds:DigestValue>' +
    '</ds:Reference></ds:SignedInfo>';

  // Sign c14n(SignedInfo) with the selected algorithm's digest.
  var siCanon = canonicalize(new DOMParser().parseFromString(signedInfo, 'application/xml').documentElement);
  var pk = forge.pki.privateKeyFromPem(val('saml_sp_private_key'));
  var md = spec.md();
  md.update(siCanon, 'utf8');
  var sigVal = forge.util.encode64(pk.sign(md));

  var signature = '<ds:Signature xmlns:ds="' + DS_NS + '">' + signedInfo +
    '<ds:SignatureValue>' + sigVal + '</ds:SignatureValue>' +
    '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
    '</ds:Signature>';

  var sigNode = doc.importNode(new DOMParser().parseFromString(signature, 'application/xml').documentElement, true);
  var issuer = null, kids = root.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === 'Issuer') { issuer = kids[i]; break; }
  }
  if (issuer) root.insertBefore(sigNode, issuer.nextSibling);
  else root.insertBefore(sigNode, root.firstChild);
  log.debug("Leaving signPostEnveloped().");
  return new XMLSerializer().serializeToString(doc);
}

// --- Exclusive Canonical XML 1.0 (omit-comments) over a DOM element ----------
// Exclusive C14N (xml-exc-c14n#) renders on each element only the namespace
// declarations that element *visibly utilizes* — the prefix of its own name and
// the prefixes of its namespace-qualified attributes — and only when not already
// output (same prefix→uri) by an ancestor. This makes a subtree canonicalize
// identically whether processed standalone or nested (the property SAML relies
// on for the detached SignedInfo signature). No InclusiveNamespaces PrefixList
// is emitted (we never set one). The documents here use no default namespace.
function canonicalize(apex) { return c14nSerialize(apex, {}); }

// All in-scope namespace declarations for `el` (walking ancestors), prefix→uri.
function c14nInScopeNs(el) {
  log.debug("Entering c14nInScopeNs().");
  var map = {};
  var chain = [], n = el;
  while (n && n.nodeType === 1) { chain.unshift(n); n = n.parentNode; }
  chain.forEach(function (e) {
    for (var i = 0; i < e.attributes.length; i++) {
      var a = e.attributes[i];
      if (a.name === 'xmlns') map[''] = a.value;
      else if (a.name.indexOf('xmlns:') === 0) map[a.name.slice(6)] = a.value;
    }
  });
  log.debug("Leaving c14nInScopeNs().");
  return map;
}
function c14nTextEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
}
function c14nAttrEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')
    .replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');
}
// `rendered` maps prefix→uri already output by an ancestor and still in scope.
function c14nSerialize(el, rendered) {
  log.debug("Entering c14nSerialize().");
  var inscope = c14nInScopeNs(el);

  // Prefixes visibly utilized by THIS element: its own prefix, plus the prefix
  // of each namespace-qualified attribute. Unprefixed attributes don't count.
  var utilized = {};
  utilized[el.prefix || ''] = true;
  var attrs = [];
  for (var i = 0; i < el.attributes.length; i++) {
    var a = el.attributes[i];
    if (a.name === 'xmlns' || a.name.indexOf('xmlns:') === 0) continue;
    if (a.prefix) utilized[a.prefix] = true;
    attrs.push(a);
  }

  var childRendered = {};
  for (var k in rendered) { if (rendered.hasOwnProperty(k)) childRendered[k] = rendered[k]; }
  var nsOut = [];
  Object.keys(utilized).forEach(function (prefix) {
    var uri = inscope.hasOwnProperty(prefix) ? inscope[prefix] : (prefix === '' ? '' : undefined);
    if (uri === undefined) return;                                  // prefix not bound
    if (prefix === '' && uri === '' && !rendered.hasOwnProperty('')) return; // no default ns in scope
    if (childRendered[prefix] !== uri) {
      nsOut.push({ prefix: prefix, uri: uri });
      childRendered[prefix] = uri;
    }
  });
  nsOut.sort(function (a, b) {
    if (a.prefix === b.prefix) return 0;
    if (a.prefix === '') return -1;
    if (b.prefix === '') return 1;
    return a.prefix < b.prefix ? -1 : 1;
  });

  var out = '<' + el.nodeName;
  nsOut.forEach(function (n) {
    out += ' ' + (n.prefix ? ('xmlns:' + n.prefix) : 'xmlns') + '="' + c14nAttrEscape(n.uri) + '"';
  });
  attrs.sort(function (a, b) {
    var au = a.namespaceURI || '', bu = b.namespaceURI || '';
    if (au !== bu) return au < bu ? -1 : 1;
    var al = a.localName || a.name, bl = b.localName || b.name;
    return al < bl ? -1 : (al > bl ? 1 : 0);
  });
  attrs.forEach(function (a) { out += ' ' + a.name + '="' + c14nAttrEscape(a.value) + '"'; });
  out += '>';
  var child = el.firstChild;
  while (child) {
    if (child.nodeType === 1) out += c14nSerialize(child, childRendered);
    else if (child.nodeType === 3 || child.nodeType === 4) out += c14nTextEscape(child.nodeValue);
    child = child.nextSibling;
  }
  log.debug("Leaving c14nSerialize().");
  return out + '</' + el.nodeName + '>';
}

// Inclusive Canonical XML 1.0 — used ONLY by the encryption "Inclusive C14N"
// serialization option. Signing always uses the exclusive canonicalize() above;
// this stays separate so the two can't interfere. Apex renders every in-scope
// namespace; descendants render only their own declarations.
function canonicalizeInclusive(apex) { return c14nIncl(apex, {}, true); }
function c14nIncl(el, rendered, isApex) {
  log.debug("Entering c14nIncl().");
  var nsSource = {};
  if (isApex) { nsSource = c14nInScopeNs(el); }
  else {
    for (var a = 0; a < el.attributes.length; a++) {
      var at = el.attributes[a];
      if (at.name === 'xmlns') nsSource[''] = at.value;
      else if (at.name.indexOf('xmlns:') === 0) nsSource[at.name.slice(6)] = at.value;
    }
  }
  var childRendered = {};
  for (var k in rendered) { if (rendered.hasOwnProperty(k)) childRendered[k] = rendered[k]; }
  var nsOut = [];
  Object.keys(nsSource).forEach(function (p) {
    if (childRendered[p] !== nsSource[p]) { nsOut.push({ prefix: p, uri: nsSource[p] }); childRendered[p] = nsSource[p]; }
  });
  nsOut.sort(function (a, b) {
    if (a.prefix === b.prefix) return 0;
    if (a.prefix === '') return -1;
    if (b.prefix === '') return 1;
    return a.prefix < b.prefix ? -1 : 1;
  });
  var out = '<' + el.nodeName;
  nsOut.forEach(function (n) { out += ' ' + (n.prefix ? ('xmlns:' + n.prefix) : 'xmlns') + '="' + c14nAttrEscape(n.uri) + '"'; });
  var attrs = [];
  for (var i = 0; i < el.attributes.length; i++) {
    var aa = el.attributes[i];
    if (aa.name === 'xmlns' || aa.name.indexOf('xmlns:') === 0) continue;
    attrs.push(aa);
  }
  attrs.sort(function (a, b) {
    var au = a.namespaceURI || '', bu = b.namespaceURI || '';
    if (au !== bu) return au < bu ? -1 : 1;
    var al = a.localName || a.name, bl = b.localName || b.name;
    return al < bl ? -1 : (al > bl ? 1 : 0);
  });
  attrs.forEach(function (a) { out += ' ' + a.name + '="' + c14nAttrEscape(a.value) + '"'; });
  out += '>';
  var child = el.firstChild;
  while (child) {
    if (child.nodeType === 1) out += c14nIncl(child, childRendered, false);
    else if (child.nodeType === 3 || child.nodeType === 4) out += c14nTextEscape(child.nodeValue);
    child = child.nextSibling;
  }
  log.debug("Leaving c14nIncl().");
  return out + '</' + el.nodeName + '>';
}

// ---------------------------------------------------------------------------
// AuthnRequest encryption (XML Encryption, W3C xmlenc) — fully in-browser via
// node-forge. Applied AFTER signing (sign-then-encrypt). A random session key
// encrypts the target with the chosen block cipher; that key is RSA-wrapped with
// the recipient (IdP) certificate's public key, and the target is replaced by an
// <xenc:EncryptedData>. NOTE: no standard SAML element carries an encrypted
// AuthnRequest, so IdPs (Keycloak) reject it — this is for inspection/education.
// ---------------------------------------------------------------------------

// Wrap bare base64 DER in PEM so forge can parse it (pass-through if already PEM).
function pemWrapCert(certPemOrB64) {
  var s = String(certPemOrB64 || '');
  if (/-----BEGIN CERTIFICATE-----/.test(s)) return s;
  var b64 = s.replace(/\s+/g, '');
  var lines = b64.match(/.{1,64}/g) || [];
  return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----\n';
}

// Data-encryption algorithm URI -> forge cipher spec.
function dataAlgSpec(uri) {
  switch (uri) {
    case XENC11_NS + 'aes128-gcm': return { cipher: 'AES-GCM', keyBytes: 16, ivBytes: 12, gcm: true };
    case XENC11_NS + 'aes192-gcm': return { cipher: 'AES-GCM', keyBytes: 24, ivBytes: 12, gcm: true };
    case XENC11_NS + 'aes256-gcm': return { cipher: 'AES-GCM', keyBytes: 32, ivBytes: 12, gcm: true };
    case XENC_NS + 'aes128-cbc': return { cipher: 'AES-CBC', keyBytes: 16, ivBytes: 16, gcm: false };
    case XENC_NS + 'aes192-cbc': return { cipher: 'AES-CBC', keyBytes: 24, ivBytes: 16, gcm: false };
    case XENC_NS + 'aes256-cbc': return { cipher: 'AES-CBC', keyBytes: 32, ivBytes: 16, gcm: false };
    case XENC_NS + 'tripledes-cbc': return { cipher: '3DES-CBC', keyBytes: 24, ivBytes: 8, gcm: false };
    default: throw new Error('Unsupported data encryption algorithm: ' + uri);
  }
}
function forgeMdFor(uri) {
  switch (uri) {
    case 'http://www.w3.org/2000/09/xmldsig#sha1': return forge.md.sha1.create();
    case XENC_NS + 'sha256': return forge.md.sha256.create();
    case 'http://www.w3.org/2001/04/xmldsig-more#sha384': return forge.md.sha384.create();
    case XENC_NS + 'sha512': return forge.md.sha512.create();
    default: return forge.md.sha256.create();
  }
}
function mgfMdFor(uri) {
  switch (uri) {
    case XENC11_NS + 'mgf1sha1': return forge.md.sha1.create();
    case XENC11_NS + 'mgf1sha256': return forge.md.sha256.create();
    case XENC11_NS + 'mgf1sha384': return forge.md.sha384.create();
    case XENC11_NS + 'mgf1sha512': return forge.md.sha512.create();
    default: return forge.md.sha1.create();
  }
}

// Serialize the target to the octets that get encrypted, honoring the selected
// canonicalization and Type (Element = whole element, Content = children only).
function encPlaintext(xml, c14nMode, type) {
  log.debug("Entering encPlaintext().");
  var isContent = type && type.indexOf('#Content') >= 0;
  if (c14nMode === 'exc-c14n' || c14nMode === 'c14n') {
    var fn = (c14nMode === 'c14n') ? canonicalizeInclusive : canonicalize;
    var doc = new DOMParser().parseFromString(xml, 'application/xml');
    var root = doc.documentElement;
    if (!isContent) return fn(root);
    var inner = '', ch = root.firstChild;
    while (ch) { if (ch.nodeType === 1) inner += fn(ch); ch = ch.nextSibling; }
    return inner;
  }
  // none: serialize as-is.
  if (!isContent) return xml;
  var d2 = new DOMParser().parseFromString(xml, 'application/xml');
  var r2 = d2.documentElement, s = '', c = r2.firstChild;
  while (c) { s += new XMLSerializer().serializeToString(c); c = c.nextSibling; }
  log.debug("Leaving encPlaintext().");
  return s;
}

function encryptAuthnRequest(xml) {
  log.debug("Entering encryptAuthnRequest().");
  var certField = val('saml_enc_cert');
  if (!certField.trim()) throw new Error('No encryption certificate — load metadata or paste a recipient certificate.');
  var certB64 = certPemToB64(certField);
  var cert = forge.pki.certificateFromPem(pemWrapCert(certField));
  var pub = cert.publicKey;

  var dataAlg = val('saml_enc_data_alg');
  var keyAlg = val('saml_enc_key_alg');
  var type = val('saml_enc_type') || (XENC_NS + 'Element');
  var c14nMode = val('saml_enc_c14n') || 'none';
  var spec = dataAlgSpec(dataAlg);

  // 1. Encrypt the target octets with a random session key + IV.
  var plaintext = encPlaintext(xml, c14nMode, type);
  var ptBytes = forge.util.encodeUtf8(plaintext);
  var sessionKey = forge.random.getBytesSync(spec.keyBytes);
  var iv = forge.random.getBytesSync(spec.ivBytes);
  var cipher = forge.cipher.createCipher(spec.cipher, sessionKey);
  cipher.start(spec.gcm ? { iv: iv, tagLength: 128 } : { iv: iv });
  cipher.update(forge.util.createBuffer(ptBytes));
  if (!cipher.finish()) throw new Error('Data encryption failed.');
  // Per XML-Enc, CipherValue = IV || ciphertext (|| GCM tag).
  var cipherValue = iv + cipher.output.getBytes() + (spec.gcm ? cipher.mode.tag.getBytes() : '');
  var cipherB64 = forge.util.encode64(cipherValue);

  // 2. RSA-wrap the session key with the recipient public key.
  var wrapped, keyMethodInner = '';
  if (keyAlg === XENC_NS + 'rsa-1_5') {
    wrapped = pub.encrypt(sessionKey, 'RSAES-PKCS1-V1_5');
  } else {
    var digestUri = val('saml_enc_digest');
    var oaepOpts = { md: forgeMdFor(digestUri) };
    keyMethodInner = '<ds:DigestMethod xmlns:ds="' + DS_NS + '" Algorithm="' + digestUri + '"/>';
    if (keyAlg === XENC11_NS + 'rsa-oaep') {
      var mgfUri = val('saml_enc_mgf');
      oaepOpts.mgf1 = { md: mgfMdFor(mgfUri) };
      keyMethodInner += '<xenc11:MGF xmlns:xenc11="' + XENC11_NS + '" Algorithm="' + mgfUri + '"/>';
    } else {
      // rsa-oaep-mgf1p: MGF1 is fixed to SHA-1.
      oaepOpts.mgf1 = { md: forge.md.sha1.create() };
    }
    wrapped = pub.encrypt(sessionKey, 'RSA-OAEP', oaepOpts);
  }
  var wrappedB64 = forge.util.encode64(wrapped);

  // 3. Assemble <xenc:EncryptedData> with the nested <xenc:EncryptedKey>.
  log.debug("Leaving encryptAuthnRequest().");
  return '<xenc:EncryptedData xmlns:xenc="' + XENC_NS + '" Type="' + type + '">' +
      '<xenc:EncryptionMethod Algorithm="' + dataAlg + '"/>' +
      '<ds:KeyInfo xmlns:ds="' + DS_NS + '">' +
        '<xenc:EncryptedKey>' +
          '<xenc:EncryptionMethod Algorithm="' + keyAlg + '">' + keyMethodInner + '</xenc:EncryptionMethod>' +
          '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
          '<xenc:CipherData><xenc:CipherValue>' + wrappedB64 + '</xenc:CipherValue></xenc:CipherData>' +
        '</xenc:EncryptedKey>' +
      '</ds:KeyInfo>' +
      '<xenc:CipherData><xenc:CipherValue>' + cipherB64 + '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData>';
}

// Whether signing / encryption are enabled (checkbox state). Signing defaults to
// on when the checkbox is somehow absent; encryption defaults to off.
function signEnabled() { var e = el('saml_sign_request'); return !e || e.checked; }
function encEnabled() { var e = el('saml_encrypt_request'); return !!(e && e.checked); }
function opStatus(signOn, encOn, what) {
  var msg = 'Built ' + (signOn ? 'signed' : 'unsigned') + (encOn ? ' + encrypted' : '') + ' AuthnRequest (' + what + ').';
  if (encOn) msg += ' Note: IdPs such as Keycloak reject encrypted AuthnRequests.';
  return msg;
}

// Regenerate the Generated AuthnRequest field from the current settings. Called
// automatically on any config change (replaces the old "Build Request" button)
// and after programmatic updates (metadata load, key generation) that don't fire
// change events. Guarded so a transient build error can never break the handler.
function autoBuildRequest() {
  try {
    buildRequestUi();
  } catch (e) {
    log.error('autoBuildRequest: ' + e.message);
  }
  return false;
}

function buildRequestUi() {
  log.debug("Entering buildRequestUi().");
  if (!validateHint()) {
    setStatus('saml_call_status', 'Username hint does not match the selected NameIDFormat.');
    return false;
  }
  var xml = buildAuthnRequest();
  setVal('saml_authn_request', xml);
  saveState();

  if (val('saml_version') !== '2.0') {
    setStatus('saml_call_status', 'SAML 1.x is reference-only — see the request box.');
    return false;
  }

  var signOn = signEnabled();
  var encOn = encEnabled();
  var priv = val('saml_sp_private_key');
  var binding = val('saml_binding');

  if (signOn && !priv) {
    setStatus('saml_call_status', 'Signing is enabled but there is no SP private key — generate a key pair or uncheck "Digitally sign the AuthnRequest".');
    return false;
  }

  try {
    if (binding === 'post') {
      // POST binding: enveloped XML-DSIG inside the document, then (optionally)
      // encrypt the whole thing — show the resulting XML.
      var payload = signOn ? signPostEnveloped(xml) : xml;
      if (encOn) payload = encryptAuthnRequest(payload);
      setVal('saml_authn_request', payload);
      setStatus('saml_call_status', opStatus(signOn, encOn, 'POST enveloped XML'));
      return false;
    }

    // Redirect (and artifact, sent via redirect): encryption applies to the XML
    // payload; signing is a detached query-string signature over the deflated
    // payload. Show the full request URL.
    var reqXml = encOn ? encryptAuthnRequest(xml) : xml;
    setStatus('saml_call_status', 'Building redirect request…');
    signRedirect(reqXml, ssoDestination(binding), 'saml_request', signOn)
      .then(function (res) {
        setVal('saml_authn_request', res.location);
        setStatus('saml_call_status', opStatus(signOn, encOn, ssoDestination(binding) ? 'redirect URL' : 'redirect query string — load metadata for the destination'));
      })
      .catch(function (e) {
        log.error('buildRequestUi redirect: ' + e.message);
        setStatus('saml_call_status', 'Build failed: ' + e.message);
      });
    return false;
  } catch (e) {
    log.error('buildRequestUi: ' + e.message);
    setStatus('saml_call_status', 'Build failed: ' + e.message);
    return false;
  }
  log.debug("Leaving buildRequestUi().");
}

// ---------------------------------------------------------------------------
// Call the IdP: build + sign the AuthnRequest in the browser, then send it.
// POST and Redirect are fully client-side. The Artifact response binding still
// needs the API — not to sign the request, but so the ACS can perform the SOAP
// ArtifactResolve later; we register the SP context, then sign+send in-browser.
// ---------------------------------------------------------------------------
function callIdp() {
  log.debug("Entering callIdp().");
  if (val('saml_version') !== '2.0') {
    setStatus('saml_call_status', 'Only SAML 2.0 can be sent. SAML 1.x is IdP-initiated (reference only).');
    return opFailure('Send AuthnRequest', 'SAML 1.x is IdP-initiated — nothing to send.');
  }
  var signOn = signEnabled();
  var encOn = encEnabled();
  var priv = val('saml_sp_private_key');
  if (signOn && !priv) {
    setStatus('saml_call_status', 'Signing is enabled but there is no SP private key — generate a key pair or uncheck "Digitally sign the AuthnRequest".');
    return opFailure('Send AuthnRequest', 'signing is enabled but there is no SP private key.');
  }
  var binding = val('saml_binding');
  var dest = ssoDestination(binding);
  if (!dest) {
    setStatus('saml_call_status', 'No IdP endpoint for the selected binding — load metadata first.');
    return opFailure('Send AuthnRequest', 'no IdP endpoint for the selected binding.');
  }
  if (!validateHint()) {
    setStatus('saml_call_status', 'Username hint does not match the selected NameIDFormat.');
    return opFailure('Send AuthnRequest', 'the username hint does not match the selected NameIDFormat.');
  }

  var xml = buildAuthnRequest();
  setVal('saml_authn_request', xml);
  saveState();

  try {
    if (binding === 'post') {
      // Sign (enveloped XML-DSIG) then encrypt, per sign-then-encrypt.
      var payload = signOn ? signPostEnveloped(xml) : xml;
      if (encOn) payload = encryptAuthnRequest(payload);
      setVal('saml_authn_request', payload);
      // Recorded before the form submit navigates away from this page.
      var postId = opSent('Send AuthnRequest', 'sent to ' + dest);
      try {
        submitPostForm(dest, { SAMLRequest: utf8ToBase64(payload), RelayState: 'saml_request' });
      } catch (e) {
        setStatus('saml_call_status', 'Send failed: ' + e.message);
        return opFailed(postId, e.message);
      }
      return false;
    }

    if (binding === 'artifact') {
      // Register the SP context (ARS URL + key) so the ACS can resolve the
      // artifact via SOAP; then send the (optionally encrypted, optionally
      // query-string-signed) redirect request in-browser.
      if (!appconfig.backendAvailable) {
        setStatus('saml_call_status', 'Artifact binding needs the API backend (for artifact resolution).');
        return opFailure('Send AuthnRequest', 'the Artifact binding needs the API backend.');
      }
      var reqXmlA = encOn ? encryptAuthnRequest(xml) : xml;
      var artifactSent = false;
      setStatus('saml_call_status', 'Preparing artifact request…');
      fetch(appconfig.apiUrl + '/samlartifactctx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          arsUrl: val('saml_ars'), privateKeyPem: priv, certPem: val('saml_sp_public_key'),
          spEntityId: val('saml_sp_entity_id'), sigAlg: SIG_ALG_RSA_SHA256,
          // WS-Addressing headers for the SOAP ArtifactResolve envelope.
          wsa: {
            enabled: (function () { var w = el('saml_wsa_support'); return !!(w && w.checked); })(),
            to: val('saml_wsa_to'),
            action: val('saml_wsa_action'),
            replyTo: val('saml_wsa_replyto'),
            from: val('saml_wsa_from'),
            messageId: val('saml_wsa_messageid')
          }
        })
      })
        .then(function (r) { return r.json().then(function (j) { if (!r.ok) { throw new Error(j && j.error ? j.error : ('HTTP ' + r.status)); } return j; }); })
        .then(function (ctx) { return signRedirect(reqXmlA, dest, ctx.relayState, signOn); })
        .then(function (res) {
          artifactSent = true;
          var id = opSent('Send AuthnRequest', 'sent to ' + dest);
          try {
            window.location.assign(res.location);
          } catch (e) {
            opFailed(id, e.message);
            throw e;
          }
        })
        .catch(function (e) {
          log.error('callIdp artifact: ' + e.message);
          setStatus('saml_call_status', 'Artifact request failed: ' + e.message);
          if (!artifactSent) opFailure('Send AuthnRequest', e.message);
        });
      return false;
    }

    // Redirect binding — fully client-side.
    var redirectSentId = null;
    var reqXmlR = encOn ? encryptAuthnRequest(xml) : xml;
    setStatus('saml_call_status', 'Sending request…');
    signRedirect(reqXmlR, dest, 'saml_request', signOn)
      .then(function (res) {
        redirectSentId = opSent('Send AuthnRequest', 'sent to ' + dest);
        window.location.assign(res.location);
      })
      .catch(function (e) {
        log.error('callIdp: ' + e.message);
        setStatus('saml_call_status', 'Send failed: ' + e.message);
        if (redirectSentId) opFailed(redirectSentId, e.message);
        else opFailure('Send AuthnRequest', e.message);
      });
    return false;
  } catch (e) {
    log.error('callIdp: ' + e.message);
    setStatus('saml_call_status', 'Send failed: ' + e.message);
    return opFailure('Send AuthnRequest', e.message);
  }
  log.debug("Leaving callIdp().");
}

// Auto-submit an HTTP-POST-binding request to the IdP SSO endpoint.
function submitPostForm(action, params) {
  log.debug("Entering submitPostForm().");
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = action;
  Object.keys(params).forEach(function (k) {
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = k;
    input.value = params[k];
    form.appendChild(input);
  });
  document.body.appendChild(form);
  form.submit();
  log.debug("Leaving submitPostForm().");
}

// ---------------------------------------------------------------------------
// Single Logout — build + sign a LogoutRequest for the last-authenticated
// subject (NameID / SessionIndex saved by the response page) and send it.
// ---------------------------------------------------------------------------
function lastLogin(key) { return (window.localStorage && localStorage.getItem(key)) || ''; }

function buildLogoutRequest() {
  log.debug("Entering buildLogoutRequest().");
  var slo = val('saml_slo_redirect') || val('saml_slo_post');
  var issuer = val('saml_sp_entity_id');
  var nameid = lastLogin('saml_last_nameid');
  var fmt = lastLogin('saml_last_nameid_format');
  var sidx = lastLogin('saml_last_session_index');
  log.debug("Leaving buildLogoutRequest().");
  return '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
         ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
         ' ID="' + genId() + '" Version="2.0" IssueInstant="' + new Date().toISOString() + '"' +
         (slo ? ' Destination="' + xmlEscape(slo) + '"' : '') + '>' +
         '\n  <saml:Issuer>' + xmlEscape(issuer) + '</saml:Issuer>' +
         '\n  <saml:NameID' + (fmt ? ' Format="' + xmlEscape(fmt) + '"' : '') + '>' + xmlEscape(nameid) + '</saml:NameID>' +
         (sidx ? '\n  <samlp:SessionIndex>' + xmlEscape(sidx) + '</samlp:SessionIndex>' : '') +
         '\n</samlp:LogoutRequest>';
}

function singleLogout() {
  log.debug("Entering singleLogout().");
  var sloBinding = bindingLabel(val('saml_binding') === 'post' ? 'post' : 'redirect');
  if (val('saml_version') !== '2.0') {
    setStatus('saml_call_status', 'Single Logout requires SAML 2.0.');
    return opFailure('Single Logout', 'Single Logout requires SAML 2.0.', { binding: sloBinding });
  }
  var priv = val('saml_sp_private_key');
  if (!priv) {
    setStatus('saml_call_status', 'Generate an SP key pair first.');
    return opFailure('Single Logout', 'there is no SP private key to sign the LogoutRequest.', { binding: sloBinding });
  }
  if (!lastLogin('saml_last_nameid')) {
    setStatus('saml_call_status', 'No NameID from a prior login — complete an SSO first.');
    return opFailure('Single Logout', 'no NameID from a prior login.', { binding: sloBinding });
  }
  var binding = val('saml_binding') === 'post' ? 'post' : 'redirect';
  var dest = binding === 'post' ? val('saml_slo_post') : val('saml_slo_redirect');
  if (!dest) {
    setStatus('saml_call_status', 'No SLO endpoint for the selected binding — load metadata first.');
    return opFailure('Single Logout', 'no SLO endpoint for the selected binding.', { binding: sloBinding });
  }

  var sloSentId = null;
  var xml = buildLogoutRequest();
  setVal('saml_authn_request', xml);
  setStatus('saml_call_status', 'Signing LogoutRequest…');

  if (binding === 'post') {
    try {
      var signed = signPostEnveloped(xml);
      setVal('saml_authn_request', signed);
      sloSentId = opSent('Single Logout', 'sent to ' + dest, { binding: sloBinding });
      submitPostForm(dest, { SAMLRequest: utf8ToBase64(signed), RelayState: 'slo' });
    } catch (e) {
      log.error('singleLogout post: ' + e.message);
      setStatus('saml_call_status', 'SLO failed: ' + e.message);
      if (sloSentId) opFailed(sloSentId, e.message);
      else opFailure('Single Logout', e.message, { binding: sloBinding });
    }
    return false;
  }
  signRedirect(xml, dest, 'slo')
    .then(function (res) {
      sloSentId = opSent('Single Logout', 'sent to ' + dest, { binding: sloBinding });
      window.location.assign(res.location);
    })
    .catch(function (e) {
      log.error('singleLogout: ' + e.message);
      setStatus('saml_call_status', 'SLO failed: ' + e.message);
      if (sloSentId) opFailed(sloSentId, e.message);
      else opFailure('Single Logout', e.message, { binding: sloBinding });
    });
  log.debug("Leaving singleLogout().");
  return false;
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Operations History — every attempted call to the IdP, recorded in the shared
// store (./saml_history.js) so that saml_response.html can resolve the outcome
// of a call this page could only dispatch.
//
// A dispatched request is recorded as "Sent", NOT as a success: the Redirect,
// POST, and Artifact bindings hand the browser to the IdP, so all this page
// knows is that the request went out. It becomes Success or Failure when the
// IdP's answer is rendered on the SAML Response page. Anything that fails
// before dispatch is a Failure here and now, with its reason.
// ---------------------------------------------------------------------------
function bindingLabel(b) {
  if (b === 'post') return 'HTTP-POST';
  if (b === 'redirect') return 'HTTP-Redirect';
  if (b === 'artifact') return 'HTTP-Artifact';
  return b || '\u2014';
}

function historyEntry(operation, result, detail, opts) {
  opts = opts || {};
  return {
    operation: operation,
    result: result,
    detail: detail || '',
    binding: (opts.binding !== undefined) ? opts.binding : bindingLabel(val('saml_binding')),
    version: opts.version || val('saml_version'),
    spEntityId: (opts.spEntityId !== undefined) ? opts.spEntityId : val('saml_sp_entity_id'),
    idpEntityId: (opts.idpEntityId !== undefined) ? opts.idpEntityId : val('saml_idp_entity_id')
  };
}

// Failed before the request could leave the browser.
function opFailure(operation, reason, opts) {
  history.record(historyEntry(operation, history.FAILURE, reason, opts));
  renderOperationHistory();
  return false;
}
// Dispatched — awaiting the IdP. Returns the entry id so the caller can flip it
// to a failure if the hand-over itself then throws.
function opSent(operation, detail, opts) {
  var id = history.record(historyEntry(operation, history.SENT, detail, opts));
  renderOperationHistory();
  return id;
}
// Something went wrong after the entry was written: correct it in place rather
// than leaving a "Sent" row next to a "Failure" row for the same attempt.
function opFailed(id, reason) {
  if (id) history.update(id, history.FAILURE, reason);
  renderOperationHistory();
  return false;
}
// Completed here and now (no IdP hand-over involved, e.g. a metadata load).
function opSuccess(operation, detail, opts) {
  history.record(historyEntry(operation, history.SUCCESS, detail, opts));
  renderOperationHistory();
  return false;
}

function renderOperationHistory() { history.render(el('saml_operation_history')); }

function clearOperationHistory() {
  history.clear();
  renderOperationHistory();
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

// Collapse/expand a single pane by toggling its body's display. The pane's
// triangle indicator follows the state via a CSS :has() rule (mirrors the
// debugger pages' pane behavior).
function togglePane(bodyId) {
  var b = el(bodyId);
  if (b) b.style.display = (b.style.display === 'none') ? 'block' : 'none';
  return false;
}

// Tab switching scoped to the pane containing the clicked tab, so multiple tab
// groups on the page toggle independently (mirrors saml_response.js).
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

// Open the certificate-details page for the cert in the given field (the IdP
// signer cert or the generated SP cert). The cert is handed over via
// localStorage ('saml_cert_view') and shown in a new tab.
function viewCertificate(fieldId) {
  var pem = val(fieldId);
  if (!pem) { setStatus('saml_metadata_status', 'No certificate to view yet.'); return false; }
  try {
    if (window.localStorage) localStorage.setItem('saml_cert_view', pem);
  } catch (e) {
    // No storage available in this context.
  }
  window.open('/saml_cert.html?from=saml_request.html', '_blank');
  return false;
}

function setReturnLink() {
  // The top-of-page link returns to the landing page (the OAuth2/OIDC vs SAML
  // protocol chooser), not a specific debugger.
  var link = el('return_link');
  if (link) link.setAttribute('href', '/index.html');
}

// ---------------------------------------------------------------------------
// Configuration Parameters URL validation. Endpoint fields must hold a valid
// http(s) URL; the entityID must be a valid absolute URI (URL or URN). Non-empty
// values that don't parse are reported in the config status field; empty fields
// are left alone (many endpoints are optional / IdP-specific).
// ---------------------------------------------------------------------------
var CONFIG_URL_FIELDS = {
  saml_sso_post: 'SSO HTTP-POST',
  saml_sso_redirect: 'SSO HTTP-Redirect',
  saml_sso_artifact: 'SSO HTTP-Artifact',
  saml_ars: 'Artifact Resolution Service',
  saml_slo_post: 'SLO HTTP-POST',
  saml_slo_redirect: 'SLO HTTP-Redirect',
  saml_slo_artifact: 'SLO HTTP-Artifact'
};
var CONFIG_URI_FIELDS = { saml_idp_entity_id: 'IdP entityID' };

function isHttpUrl(v) {
  try {
    var u = new URL(v);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (e) {
    return false;
  }
}
function isAbsoluteUri(v) {
  try {
    new URL(v);
    return true;
  } catch (e) {
    return false;
  }
}

function validateConfigUrls() {
  log.debug("Entering validateConfigUrls().");
  var bad = [];
  Object.keys(CONFIG_URL_FIELDS).forEach(function (id) {
    var v = val(id).trim();
    if (v && !isHttpUrl(v)) bad.push(CONFIG_URL_FIELDS[id]);
  });
  Object.keys(CONFIG_URI_FIELDS).forEach(function (id) {
    var v = val(id).trim();
    if (v && !isAbsoluteUri(v)) bad.push(CONFIG_URI_FIELDS[id]);
  });
  if (bad.length) {
    setStatus('saml_config_status', 'Invalid URL in: ' + bad.join(', ') + '. Enter a full URL (e.g. https://host/path).');
  } else {
    setStatus('saml_config_status', 'Configuration URLs valid.');
  }
  log.debug("Leaving validateConfigUrls().");
  return bad.length === 0;
}

window.onload = function () {
  log.debug('Entering onload().');
  restoreState();
  setReturnLink();

  // Seed defaults where the user hasn't stored anything yet.
  if (!val('saml_metadata_url') && appconfig.samlMetadataUrlDefault) setVal('saml_metadata_url', appconfig.samlMetadataUrlDefault);
  if (!val('saml_sp_entity_id') && appconfig.spEntityId) setVal('saml_sp_entity_id', appconfig.spEntityId);
  // ACS (where the IdP returns its response). With a backend it's the api's
  // /samlacs endpoint (from config). Backendless, there is no server to POST to —
  // so the "ACS" is this static SAML Response page on the same origin, which the
  // Redirect-binding response (see responseProtocolBinding) delivers to as a GET.
  var acsDefault = appconfig.backendAvailable
    ? appconfig.acsUrl
    : (window.location.origin + '/saml_response.html');
  if (!val('saml_acs_url') && acsDefault) setVal('saml_acs_url', acsDefault);
  // Configuration Parameters: fall back to the dummy defaults declared in the HTML
  // (input value / textarea content) when restore left a field blank — so the
  // sample endpoints/cert show on a fresh page even if an earlier visit stored
  // empty values. A real "Load Metadata" or a user edit overrides them.
  ['saml_idp_entity_id', 'saml_sso_post', 'saml_sso_redirect', 'saml_sso_artifact', 'saml_ars',
   'saml_slo_post', 'saml_slo_redirect', 'saml_slo_artifact', 'saml_signer_cert'].forEach(function (id) {
    var e = el(id);
    if (e && !e.value && e.defaultValue) e.value = e.defaultValue;
  });
  // Encryption cert: localStorage (restored above) wins; otherwise default to the
  // signer cert from previously-loaded metadata (also restored above).
  if (!val('saml_enc_cert') && val('saml_signer_cert')) setVal('saml_enc_cert', val('saml_signer_cert'));

  show('saml_backend_notice', !appconfig.backendAvailable);
  onVersionChange();
  onNameIdFormatChange();
  onSignChange();
  onEncryptChange();
  onWsaChange();

  // Persist on any change, and auto-regenerate the AuthnRequest. 'change' (not
  // per-keystroke 'input') drives the rebuild so signing/encryption don't run on
  // every keystroke — text fields rebuild on blur; selects/checkboxes immediately.
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    els[i].addEventListener('change', saveState);
    els[i].addEventListener('input', saveState);
    els[i].addEventListener('change', autoBuildRequest);
  }

  // Live URL validation for the Configuration Parameters fields.
  var urlIds = Object.keys(CONFIG_URL_FIELDS).concat(Object.keys(CONFIG_URI_FIELDS));
  for (var u = 0; u < urlIds.length; u++) {
    var ue = el(urlIds[u]);
    if (ue) {
      ue.addEventListener('input', validateConfigUrls);
      ue.addEventListener('change', validateConfigUrls);
    }
  }

  renderOperationHistory();

  // Initial population of the Generated AuthnRequest field + URL validation.
  autoBuildRequest();
  validateConfigUrls();
};

module.exports = {
  loadMetadata,
  uploadMetadata,
  onMetadataFileChange,
  onNameIdFormatChange,
  onVersionChange,
  onSignChange,
  onEncryptChange,
  onWsaChange,
  validateHint,
  generateKeys,
  downloadKeys,
  downloadSpMetadata,
  buildRequestUi,
  callIdp,
  singleLogout,
  viewCertificate,
  copyField,
  showTab,
  togglePane,
  clearOperationHistory
};
