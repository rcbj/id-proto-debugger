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
// is only involved for the artifact RESPONSE binding, where the back-channel
// resolution is a SOAP call the browser cannot make — the browser registers the
// SP context via /samlartifactctx, then still signs+sends the request itself.
//
// ---------------------------------------------------------------------------
// TWO PROTOCOL VERSIONS ARE FUNCTIONAL HERE, AND THEY ARE TWO PROTOCOLS.
//
// **SAML 1.1 has no request message.** There is no `<AuthnRequest>` in it: the
// browser profiles (saml-profile-1.1 sections 4.1 and 4.2) are
// IDENTITY-PROVIDER-INITIATED, and a flow begins when a browser arrives at the
// inter-site transfer service carrying a `TARGET`. What a real SAML 1.1 service
// provider actually sends is Shibboleth's request profile — identified by
// `urn:mace:shibboleth:1.0:profiles:AuthnRequest`, four query parameters
// (`TARGET`, `shire`, `providerId`, `time`), not a standard, and the one every
// deployment used. That is what this page sends, and it is why five settings in
// the SP / Request pane are greyed out and switched off when 1.1 is selected:
// there is nothing to sign, nothing to encrypt, nowhere to put a subject hint,
// and SAML 1.1 has no Single Logout at all. See applyVersionAvailability(),
// which is the one place that decision is written down.
//
// The three binding choices keep their meanings and get 1.1 spellings:
//
//   redirect  the Shibboleth request as a top-level GET to the inter-site
//             transfer service; the response comes back on Browser/POST.
//   post      the same parameters as a form POST to that endpoint; the response
//             again on Browser/POST. (SAML 1.1 defines no POST-bound request —
//             this is the same non-standard request delivered the other way,
//             which the mock STS accepts and a Shibboleth IdP would not.)
//   artifact  the request as a GET, and the response on Browser/Artifact: a
//             `SAMLart` on a redirect to the assertion consumer, resolved by
//             the API over the SOAP binding at the IdP's SAML responder.
//
// Two of the parameters this page sends are NON-SPEC and are marked as such
// wherever they appear: `profile=post|artifact`, because nothing in SAML 1.1
// lets a relying party choose between the two browser profiles, and `format`,
// because nothing lets it ask for a NameIdentifier format either. Both are
// ignored by an identity provider that does not know them.
//
// SAML 1.0 remains reference-only: it is 1.1 with a MinorVersion of 0 and
// nothing here has an implementation to point at.
//
// Everything the user configures is persisted to localStorage (keyed by element
// id) so it survives a page reload — including, per design, the generated SP
// private key. That key is a throwaway test key; do not reuse a production key.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var forge = require("node-forge");
var history = require("./saml_history");
// The scheme allowlist applied before navigating anywhere, or POSTing a form
// anywhere. See url_safety.js for why this is not DOMPurify.
var urlSafety = require("./url_safety");
// ---------------------------------------------------------------------------
// THE XML SIGNATURE AND CANONICALIZATION ARE NOT THIS PAGE'S ANY MORE.
//
// This file used to carry its own copy of the whole of it: exclusive and
// inclusive Canonical XML, the digest and signature-method tables, the PEM
// helpers, the strict parser, the encryption algorithm specs, and an enveloped
// signer. xmldsig.js's own header says its canonicalizer came from HERE — it
// was copied out for the SAML Assertion Tool and the original stayed, so this
// application had two readings of C14N in it, and this was the one nothing
// else exercised: the SSO page signs the AuthnRequest a real identity provider
// then has to verify.
//
// They had already drifted. The shared canonicalizer emits processing
// instructions, which C14N 1.0 retains in BOTH its variants; the copy that
// used to be here dropped them, so a signed subtree containing one digested
// differently here than in xmlsec, Santuario or xml-crypto — which reads at
// the far end as a document modified in transit, and is not that.
//
// What is left in this file is what is genuinely this page's: which fields
// hold what, how a SAML AuthnRequest is shaped, and the SAML-specific
// EncryptedData it builds around the shared encryption pieces.
// ---------------------------------------------------------------------------
var xmldsig = require("./xmldsig");
var certPemToB64 = xmldsig.certPemToB64;
var pemWrapCert = xmldsig.pemWrapCert;
var digestBase64 = xmldsig.digestBase64;
var sigAlgSpec = xmldsig.sigAlgSpec;
var parseXmlStrict = xmldsig.parseXmlStrict;
var canonicalize = xmldsig.canonicalize;
var canonicalizeInclusive = xmldsig.canonicalizeInclusive;
var dataAlgSpec = xmldsig.dataAlgSpec;
var forgeMdFor = xmldsig.forgeMdFor;
var mgfMdFor = xmldsig.mgfMdFor;
var encPlaintext = xmldsig.encPlaintext;
var xmlEscape = xmldsig.xmlEscape;
var log = bunyan.createLogger({ name: 'saml_request',
    level: appconfig.logLevel });
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

// SAML 1.1's vocabulary. Every URI here carries `1.0` EXCEPT the protocol
// support one, and that is not a typo anywhere: the assertion and protocol
// schemas were never renamed between SAML 1.0 and 1.1 — the version travels in
// MajorVersion/MinorVersion attributes instead — while
// `protocolSupportEnumeration` names the PROTOCOL and is spelled 1.1. Writing
// `urn:oasis:names:tc:SAML:1.1:profiles:browser-post` produces a document that
// looks right in a diff and that nothing will match.
var SAML11 = {
  // The two browser profiles. In a SAML 1.1 metadata descriptor the `Binding`
  // attribute carries a PROFILE identifier rather than a binding one, which
  // reads wrong and is what Shibboleth's own metadata does — the 1.1 profiles
  // bundle their binding into the profile.
  post: 'urn:oasis:names:tc:SAML:1.0:profiles:browser-post',
  artifact: 'urn:oasis:names:tc:SAML:1.0:profiles:artifact-01',
  // Shibboleth's request profile: the only way a SAML 1.1 service provider can
  // tell an identity provider where to send the assertion.
  authnRequest: 'urn:mace:shibboleth:1.0:profiles:AuthnRequest',
  // What the artifact resolution / attribute endpoints are bound with.
  soap: 'urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding',
  protocol: 'urn:oasis:names:tc:SAML:1.1:protocol'
};
var SAML20_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

// Set by parseMetadata() when a loaded document moved the Protocol Version
// selector, and read by applyMetadata() so the status line says so. A metadata
// load is the only thing here that changes a selector the user set, and a
// change nothing announces is one that reads as this page ignoring them.
var metadataVersionSwitch = '';

// The selected protocol version, and the two questions asked of it everywhere
// below. `samlVersion()` never returns '' — an unreadable selector falls back
// to 2.0, which is the version every other default on this page assumes.
function samlVersion() {
  log.debug("Entering samlVersion().");
  log.debug("Leaving samlVersion().");
  return val('saml_version') || '2.0';
}
function isSaml11() {
  log.debug("Entering isSaml11().");
  log.debug("Leaving isSaml11().");
  return samlVersion() === '1.1';
}
// SAML 1.0 is 1.1 with a MinorVersion of 0 and nothing here implements it, so
// it stays what it has always been: a version that builds a note and sends
// nothing.
function isReferenceOnly() {
  log.debug("Entering isReferenceOnly().");
  log.debug("Leaving isReferenceOnly().");
  var v = samlVersion();
  return v !== '2.0' && v !== '1.1';
}

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------
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
function setStatus(id, msg) {
  log.debug("Entering setStatus().");
  setVal(id, msg);
  log.debug("Leaving setStatus().");
}
function show(id, on) {
  log.debug("Entering show().");
  var e = el(id);
  if (e) { if (on) e.classList.remove('saml-hidden'); else e.classList.add(
      'saml-hidden'); }
  log.debug("Leaving show().");
}

// RFC 4122-ish id suitable for an XML ID (must be an NCName: start with
// letter/_)
function genId() {
  log.debug("Entering genId().");
  var b = new Uint8Array(16);
  (window.crypto || window.msCrypto).getRandomValues(b);
  var hex = '';
  for (var i = 0; i < b.length; i++) { hex += ('0' +
       b[i].toString(16)).slice(-2); }
  log.debug("Leaving genId().");
  return '_' + hex;
}

// ---------------------------------------------------------------------------
// localStorage persistence — every .stored element is saved by its id.
// ---------------------------------------------------------------------------
function persistedEls() {
  log.debug("Entering persistedEls().");
  log.debug("Leaving persistedEls().");
  return document.querySelectorAll('.stored');
}

// The SP signing key pair, and whether it may be written to localStorage.
//
// Everything else this page persists is configuration. This is key material,
// and the debugger's standing rule is that credentials do not go to
// localStorage — the password fields on the OAuth2 pages are deliberately
// excluded for exactly that reason. This pane is where the rule got bent, and
// for a real reason: the workflow spans screens, the SAML Response page needs
// this private key to decrypt an EncryptedAssertion, and re-pasting a PEM at
// every hop is the sort of friction people work around by keeping the key
// somewhere worse.
//
// So saving stays the default, but it is now a choice. With the box cleared the
// two fields are never written, AND anything already written is removed on the
// spot — an opt-out that leaves yesterday's private key sitting in storage is
// not an opt-out. The user then carries the pair themselves (the Download
// button beside the fields) and pastes it back here, and pastes the private key
// into the Decryption Key field on the response page, which is already written
// to cope with an empty prefill.
var KEYPAIR_FIELDS = ['saml_sp_private_key', 'saml_sp_public_key'];

function keyPairMayBeStored() {
  log.debug("Entering keyPairMayBeStored().");
  var e = el('saml_save_keypair');
  // Absent checkbox (an older cached copy of the page) keeps the previous
  // behaviour rather than silently dropping a key pair the user expects to
  // still be there after a reload.
  log.debug("Leaving keyPairMayBeStored().");
  return !e || e.checked;
}

function forgetStoredKeyPair() {
  log.debug("Entering forgetStoredKeyPair().");
  if (!window.localStorage) {
    log.debug("Leaving forgetStoredKeyPair().");
    return;
  }
  for (var i = 0; i < KEYPAIR_FIELDS.length; i++) {
    localStorage.removeItem(STORE_PREFIX + KEYPAIR_FIELDS[i]);
  }
  log.debug("Leaving forgetStoredKeyPair().");
}

function saveState() {
  log.debug("Entering saveState().");
  if (!window.localStorage) {
    log.debug("Leaving saveState().");
    return;
  }
  var storeKeyPair = keyPairMayBeStored();
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (!els[i].id) continue;
    if (!storeKeyPair && KEYPAIR_FIELDS.indexOf(els[i].id) >= 0) continue;
    var v = els[i].type === 'checkbox' ? (els[i].checked ?
        '1' : '0') : els[i].value;
    localStorage.setItem(STORE_PREFIX + els[i].id, v);
  }
  // Not merely "skip writing": remove what an earlier save (or an earlier
  // session, before the box was cleared) already put there. saveState() runs on
  // most interactions, so doing it here means no code path can leave the key
  // pair behind.
  if (!storeKeyPair) forgetStoredKeyPair();
  log.debug("Leaving saveState().");
}
function restoreState() {
  log.debug("Entering restoreState().");
  if (!window.localStorage) {
    log.debug("Leaving restoreState().");
    return;
  }
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
    if (els[i].type === 'checkbox') els[i].checked = (v === '1' ||
        v === 'true' || v === 'on');
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
    log.debug("Leaving loadMetadata().");
    return opFailure('Load IdP Metadata', 'no metadata URL was entered.',
                     { binding: '—' });
  }
  setStatus('saml_metadata_status', 'Loading…');
  // With a backend, go through the API metadata proxy (it dodges cross-origin
  // CORS restrictions on the IdP's metadata endpoint). On the static
  // (backend-less) deployment, fetch the metadata URL directly from the browser
  // — works whenever the IdP serves permissive CORS on its descriptor (a CORS/
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
      opFailure('Load IdP Metadata', e.message, { binding: '—',
                idpEntityId: '' });
      setStatus('saml_metadata_status', 'Load failed: ' + e.message +
        (appconfig.backendAvailable ? '' : ' — the browser fetched the ' +
         'metadata URL directly; the IdP endpoint may not permit ' +
         'cross-origin (CORS) requests.'));
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
    setStatus('saml_metadata_status', 'Loaded and parsed.' +
      (metadataVersionSwitch ? ' The document describes a SAML ' +
       metadataVersionSwitch + ' identity provider, so Protocol Version was ' +
       'set to ' + metadataVersionSwitch + '.' : ''));
    // Recorded after the parse so the IdP entityID it just populated is shown.
    opSuccess('Load IdP Metadata', url ? ('loaded from ' +
              url) : 'loaded from a local file', { binding: '—' });
    saveState();
    autoBuildRequest(); // metadata populated the destination/NameIDFormat, etc.
    validateConfigUrls();
  } catch (e) {
    log.error('parseMetadata: ' + e.message);
    setStatus('saml_metadata_status', 'Parse error: ' + e.message);
    opFailure('Load IdP Metadata', 'parse error: ' + e.message,
              { binding: '—' });
  }
  log.debug("Leaving applyMetadata().");
}

// Upload a metadata document from a local file (no URL fetch / backend needed).
function uploadMetadata() {
  log.debug("Entering uploadMetadata().");
  var f = el('saml_metadata_file');
  if (f) f.click();
  log.debug("Leaving uploadMetadata().");
  return false;
}
function onMetadataFileChange(evt) {
  log.debug("Entering onMetadataFileChange().");
  var input = evt && evt.target;
  var file = input && input.files && input.files[0];
  if (!file) {
    log.debug("Leaving onMetadataFileChange().");
    return false;
  }
  setStatus('saml_metadata_status', 'Reading ' + file.name + '…');
  var reader = new FileReader();
  reader.onload = function () {
    log.debug("Entering onload().");
    applyMetadata(String(reader.result || ''));
    if (input) input.value = ''; // allow re-selecting the same file
    log.debug("Leaving onload().");
  };
  reader.onerror = function () {
    log.debug("Entering onerror().");
    setStatus('saml_metadata_status', 'Could not read file: ' + file.name);
    log.debug("Leaving onerror().");
  };
  reader.readAsText(file);
  log.debug("Leaving onMetadataFileChange().");
  return false;
}

// Namespace-agnostic element lookup (metadata uses md:/ds: prefixes).
function tags(root, localName) {
  log.debug("Entering tags().");
  log.debug("Leaving tags().");
  return root.getElementsByTagNameNS('*', localName);
}

function parseMetadata(xmlText) {
  log.debug("Entering parseMetadata().");
  metadataVersionSwitch = '';
  var doc = new DOMParser().parseFromString(xmlText, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    throw new Error('malformed XML');
  }
  var ed = tags(doc, 'EntityDescriptor')[0];
  if (!ed) throw new Error('no EntityDescriptor');
  setVal('saml_idp_entity_id', ed.getAttribute('entityID') || '');

  var idp = tags(doc, 'IDPSSODescriptor')[0] || ed;
  var version = metadataProtocolVersion(idp);

  // SSO endpoints by binding — and, in SAML 1.1, by PROFILE.
  //
  // A SAML 1.1 descriptor names one endpoint (the inter-site transfer service)
  // three times, once per profile it answers: Browser/POST, Browser/Artifact,
  // and Shibboleth's request profile. There is no separate redirect endpoint
  // and no separate artifact endpoint, so all three fields below take that one
  // address. Reading it as though the fields were exclusive is how a SAML 1.1
  // document ends up populating none of them and the page reports "no IdP
  // endpoint for the selected binding" about a document that named it.
  var ssoPost = '', ssoRedirect = '', ssoArtifact = '', its = '';
  var ssos = tags(idp, 'SingleSignOnService');
  for (var i = 0; i < ssos.length; i++) {
    var b = ssos[i].getAttribute('Binding'), loc =
        ssos[i].getAttribute('Location');
    if (b === BINDING.post) ssoPost = loc;
    else if (b === BINDING.redirect) ssoRedirect = loc;
    else if (b === BINDING.artifact) ssoArtifact = loc;
    else if (b === SAML11.post || b === SAML11.artifact ||
             b === SAML11.authnRequest) {
      if (!its) its = loc;
    }
  }
  if (version === '1.1' && its) {
    ssoPost = its;
    ssoRedirect = its;
    ssoArtifact = its;
  }
  setVal('saml_sso_post', ssoPost);
  setVal('saml_sso_redirect', ssoRedirect);
  setVal('saml_sso_artifact', ssoArtifact);

  // SLO endpoints by binding. A SAML 1.1 descriptor has none — the protocol has
  // no Single Logout — and the loop below simply finds nothing, which clears
  // the three fields rather than leaving a 2.0 document's addresses behind.
  var sloPost = '', sloRedirect = '', sloArtifact = '';
  var slos = tags(idp, 'SingleLogoutService');
  for (var j = 0; j < slos.length; j++) {
    var sb = slos[j].getAttribute('Binding'), sloc =
        slos[j].getAttribute('Location');
    if (sb === BINDING.post) sloPost = sloc;
    else if (sb === BINDING.redirect) sloRedirect = sloc;
    else if (sb === BINDING.artifact) sloArtifact = sloc;
  }
  setVal('saml_slo_post', sloPost);
  setVal('saml_slo_redirect', sloRedirect);
  setVal('saml_slo_artifact', sloArtifact);

  // Artifact Resolution Service (SOAP back-channel). SAML 1.1 publishes the
  // same address twice — once here and once as the AttributeService of an
  // <AttributeAuthorityDescriptor>, because a Shibboleth service provider reads
  // the second one and will not look for it inside the IDPSSODescriptor. Either
  // will do for resolving an artifact, so the second is a fallback rather than
  // a separate field.
  var ars = tags(idp, 'ArtifactResolutionService')[0] ||
      tags(doc, 'AttributeService')[0];
  setVal('saml_ars', ars ? (ars.getAttribute('Location') || '') : '');

  // NameIDFormat list.
  var nifs = tags(idp, 'NameIDFormat');
  var formats = [];
  for (var k = 0; k < nifs.length; k++) {
    var t = (nifs[k].textContent || '').trim();
    if (t) formats.push(t);
  }
  populateNameIdOptions(formats);
  if (window.localStorage) localStorage.setItem(NAMEID_OPTIONS_KEY,
      JSON.stringify(formats));

  // Signer certificate: KeyDescriptor[use=signing] X509Certificate. Fall back
  // to any KeyDescriptor if none is explicitly marked "signing".
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
  // THE DOCUMENT DECIDES THE PROTOCOL VERSION, because it is the only thing
  // here that knows: `protocolSupportEnumeration` is what an identity provider
  // says it speaks, and a page left on 2.0 in front of a 1.1-only descriptor
  // would build a request that endpoint cannot read and report the refusal as
  // an IdP problem. It is applied only when the document is unambiguous (one
  // version, and not the one already selected) and the status line says so —
  // an unannounced change to a selector the user set is worse than the wrong
  // default.
  if (version && version !== samlVersion()) {
    setVal('saml_version', version);
    metadataVersionSwitch = version;
  } else {
    metadataVersionSwitch = '';
  }
  applyVersionAvailability();
  log.debug("Leaving parseMetadata().");
}

// What `protocolSupportEnumeration` says the identity provider speaks. '' when
// the document does not say, or says both — in which case whatever the user
// selected stands.
function metadataProtocolVersion(idp) {
  log.debug("Entering metadataProtocolVersion().");
  var pse = (idp && idp.getAttribute &&
      idp.getAttribute('protocolSupportEnumeration')) || '';
  var has20 = pse.indexOf(SAML20_PROTOCOL) >= 0;
  // A descriptor declaring the SAML **1.0** protocol counts as 1.1 here, and
  // that is a decision rather than sloppiness: the two share every namespace
  // they have, their browser profiles are the same two profiles, and 1.1 is the
  // one this page can drive. Selecting the reference-only 1.0 entry on the
  // strength of a `1.0:protocol` string would leave the user in front of a
  // version that builds nothing, from a document describing a service that
  // works.
  var has11 = pse.indexOf(SAML11.protocol) >= 0 ||
      pse.indexOf('urn:oasis:names:tc:SAML:1.0:protocol') >= 0;
  if (has20 && !has11) {
    log.debug("Leaving metadataProtocolVersion(). 2.0.");
    return '2.0';
  }
  if (has11 && !has20) {
    log.debug("Leaving metadataProtocolVersion(). 1.1.");
    return '1.1';
  }
  log.debug("Leaving metadataProtocolVersion(). The document does not say.");
  return '';
}

function populateNameIdOptions(formats) {
  log.debug("Entering populateNameIdOptions().");
  var sel = el('saml_nameid_format');
  if (!sel) {
    log.debug("Leaving populateNameIdOptions().");
    return;
  }
  sel.innerHTML = '';
  // Default "nothing chosen": the AuthnRequest still sends a <NameIDPolicy>
  // (with AllowCreate) but WITHOUT a Format, so the IdP picks its default and
  // cannot reject the request with InvalidNameIDPolicy. Selecting a specific
  // format below sends that Format explicitly.
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
  log.debug("Entering shortNameId().");
  var idx = fmt.lastIndexOf(':');
  log.debug("Leaving shortNameId().");
  return idx >= 0 ? fmt.substring(idx + 1) + '  (' + fmt + ')' : fmt;
}

// ---------------------------------------------------------------------------
// NameIDFormat -> username-hint restriction
// ---------------------------------------------------------------------------
function hintRuleFor(fmt) {
  log.debug("Entering hintRuleFor().");
  var f = (fmt || '').toLowerCase();
  if (f.indexOf('emailaddress') >= 0) {
    log.debug("Leaving hintRuleFor().");
    return { placeholder: 'user@example.com',
            help: 'emailAddress format: enter an email address.',
             test: function (v) {
               log.debug("Entering test().");
               log.debug("Leaving test().");
               return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v);
             }, allowed: true };
  }
  if (f.indexOf('x509subjectname') >= 0) {
    log.debug("Leaving hintRuleFor().");
    return { placeholder: 'CN=User,O=Org,C=US',
            help: 'X509SubjectName format: enter an X.500 distinguished name.',
             test: function (v) {
               log.debug("Entering test().");
               log.debug("Leaving test().");
               return /=/.test(v);
             }, allowed: true };
  }
  if (f.indexOf('windowsdomainqualifiedname') >= 0) {
    log.debug("Leaving hintRuleFor().");
    return { placeholder: 'DOMAIN\\user',
            help: 'WindowsDomainQualifiedName: enter DOMAIN\\username.',
             test: function (v) {
               log.debug("Entering test().");
               log.debug("Leaving test().");
               return /\\/.test(v);
             }, allowed: true };
  }
  if (f.indexOf('persistent') >= 0 || f.indexOf('transient') >= 0) {
    log.debug("Leaving hintRuleFor().");
    return { placeholder: '(hint not applicable)',
            help: 'persistent/transient identifiers are IdP-assigned — a ' +
            'username hint does not apply and will be ignored.',
             test: function () {
               log.debug("Entering test().");
               log.debug("Leaving test().");
               return true;
             }, allowed: false };
  }
  // unspecified, kerberos, entity, or unknown -> free text
  log.debug("Leaving hintRuleFor().");
  return { placeholder: 'username',
          help: 'unspecified format: any value is allowed.',
           test: function () {
             log.debug("Entering test().");
             log.debug("Leaving test().");
             return true;
           }, allowed: true };
}

function onNameIdFormatChange() {
  log.debug("Entering onNameIdFormatChange().");
  var rule = hintRuleFor(val('saml_nameid_format'));
  var hint = el('saml_username_hint');
  if (hint) {
    hint.placeholder = rule.placeholder;
    hint.disabled = !rule.allowed;
  }
  setVal('saml_hint_help', rule.help);
  validateHint();
  saveState();
  log.debug("Leaving onNameIdFormatChange().");
  return false;
}

function validateHint() {
  log.debug("Entering validateHint().");
  var rule = hintRuleFor(val('saml_nameid_format'));
  var v = val('saml_username_hint').trim();
  var hint = el('saml_username_hint');
  if (!hint) {
    log.debug("Leaving validateHint().");
    return true;
  }
  if (!v || !rule.allowed) {
    hint.style.borderColor = '';
    log.debug("Leaving validateHint().");
    return true;
  }
  var ok = rule.test(v);
  hint.style.borderColor = ok ? '' : '#e0a800';
  setVal('saml_hint_help', rule.help + (ok ?
         '' : '  ⚠ value does not match the selected format.'));
  saveState();
  log.debug("Leaving validateHint().");
  return ok;
}

function onVersionChange() {
  log.debug("Entering onVersionChange(). version=" + samlVersion());
  // A version the user chose is not a version a metadata load chose, so the
  // note that says a load moved the selector stops being true here.
  metadataVersionSwitch = '';
  applyVersionAvailability();
  saveState();
  log.debug("Leaving onVersionChange().");
  return false;
}

// ---------------------------------------------------------------------------
// WHICH OF THIS PANE'S SETTINGS APPLY TO THE SELECTED VERSION.
//
// SAML 1.1 is not SAML 2.0 with older element names — it has NO REQUEST
// MESSAGE. Five settings follow from that, and each one is DISABLED and greyed
// rather than silently ignored, because a control that quietly does nothing is
// the version of this that costs somebody an afternoon:
//
//   the username hint      goes in <saml:Subject> on an AuthnRequest, and there
//                          is no request document to put one in.
//   sign the request       there is nothing to sign. Shibboleth's request
//                          profile is four unsigned query parameters.
//   encrypt the request    there is nothing to encrypt either. (The 2.0 option
//                          is already marked non-standard on the page.)
//   Single Logout          SAML 1.1 has none — absent from the protocol, not
//                          unimplemented here.
//   the SLO endpoints      nothing publishes them, so the fields go with it.
//
// **THE SP KEY PAIR IS NOT DISABLED, and that is the one that looks
// inconsistent.** It still signs the SOAP <samlp:Request> that resolves an
// artifact, and it is still the KeyDescriptor in the SP metadata this page
// downloads — so greying that pane would take away two things that work.
//
// Both halves matter, and the second is the one that is easy to leave out: a
// block that only LOOKS dead still submits on a Return keypress in a text
// field, and the refusal in callIdp() is then the first thing that says
// anything. `pki.js`'s disableTlsPane() makes the same argument at pane scale.
// ---------------------------------------------------------------------------
function applyVersionAvailability() {
  log.debug("Entering applyVersionAvailability(). version=" + samlVersion());
  var v = samlVersion();
  var isEleven = v === '1.1';
  var reference = isReferenceOnly();
  // Everything a request document brings with it is gone in 1.1, and gone in
  // 1.0 for the additional reason that nothing here builds one at all.
  var noRequestDoc = isEleven || reference;

  setUnavailable('saml_hint_field', noRequestDoc, ['saml_username_hint']);
  setUnavailable('saml_sign_field', noRequestDoc, ['saml_sign_request']);
  setUnavailable('saml_encrypt_field', noRequestDoc, ['saml_encrypt_request']);
  setUnavailable('saml_slo_section', v !== '2.0',
                 ['saml_slo_post', 'saml_slo_redirect', 'saml_slo_artifact']);
  var logout = el('saml_logout_btn');
  if (logout) {
    logout.disabled = (v !== '2.0');
    if (v !== '2.0') logout.classList.add('saml-unavailable');
    else logout.classList.remove('saml-unavailable');
  }
  // The binding selector keeps all three options in 1.1 and they keep their
  // meanings; only the words change, because "HTTP-Redirect" names a SAML 2.0
  // binding URI that does not exist in 1.1.
  var bindingOpts = {
    redirect: isEleven ? 'HTTP Redirect (GET to the inter-site transfer ' +
        'service)' : 'HTTP-Redirect (GET)',
    post: isEleven ? 'HTTP POST (form POST to the inter-site transfer ' +
        'service)' : 'HTTP-POST',
    artifact: isEleven ? 'HTTP Artifact (Browser/Artifact, section 4.1)' :
        'HTTP-Artifact'
  };
  var sel = el('saml_binding');
  if (sel) {
    for (var i = 0; i < sel.options.length; i++) {
      var o = sel.options[i];
      if (bindingOpts[o.value]) o.text = bindingOpts[o.value];
    }
  }

  setText('saml_version_warning', versionNote(v));
  show('saml_version_warning', v !== '2.0');
  setText('saml_binding_note', bindingNote(v));
  setText('saml_sso_endpoints_note', ssoEndpointsNote(v));
  setText('saml_slo_note', v === '2.0' ? '' :
      'SAML ' + v + ' has no Single Logout. There is no message for one and ' +
      'nothing publishes an endpoint, so these fields do not apply.');
  setText('saml_sp_entity_id_note', isEleven ?
      'Sent as the non-standard providerId parameter, which is the only ' +
      'way a SAML 1.1 relying party can name itself. It becomes the ' +
      'assertion\'s audience restriction.' : '');
  setText('saml_acs_url_note', isEleven ?
      'Sent as Shibboleth\'s shire parameter. It is where the identity ' +
      'provider POSTs the Response, or redirects with a SAMLart.' : '');
  // Note the wording: the checkbox above is DISABLED and still shows whatever
  // it was ticked to, because its state is the SAML 2.0 preference and is
  // persisted — unticking it here would mean a reload on 1.1 silently turned
  // request signing off for 2.0 as well. So the note says the setting does not
  // apply rather than that it is off, which is what a greyed tick would
  // otherwise be read as contradicting.
  setText('saml_keypair_role_note', isEleven ?
      'SAML 1.1 has no request document, so the setting above does not apply ' +
      'here whatever it shows — it is remembered for SAML 2.0. This key pair ' +
      'IS still used: it signs the SOAP <samlp:Request> that resolves an ' +
      'artifact on the HTTP Artifact binding, and it is the KeyDescriptor in ' +
      'the SP metadata this page downloads.' : '');

  // The two sub-sections these checkboxes open have to follow the checkbox
  // rather than their own handler, or switching to 1.1 leaves an encryption
  // pane open over a checkbox that can no longer be ticked.
  onSignChange();
  onEncryptChange();
  log.debug("Leaving applyVersionAvailability().");
}

// Grey a block and switch off the controls in it. Both halves, always: see the
// note above applyVersionAvailability() for why one without the other is worse
// than neither.
function setUnavailable(containerId, off, controlIds) {
  log.debug("Entering setUnavailable(). id=" + containerId + ", off=" + !!off);
  var c = el(containerId);
  if (c) {
    if (off) c.classList.add('saml-unavailable');
    else c.classList.remove('saml-unavailable');
  }
  for (var i = 0; i < (controlIds || []).length; i++) {
    var e = el(controlIds[i]);
    if (e) e.disabled = !!off;
  }
  log.debug("Leaving setUnavailable().");
}

// textContent, not innerHTML: these are messages, not markup.
//
// An EMPTY note is hidden rather than left as an empty element, because these
// are block-level paragraphs with margins — six of them on one pane, each
// contributing its margin on the version that has nothing to say, is a pane
// that grew for no reason and a page a little further from fitting on one
// screen.
function setText(id, text) {
  log.debug("Entering setText().");
  var e = el(id);
  if (!e) {
    log.debug("Leaving setText(). No such element.");
    return;
  }
  e.textContent = text || '';
  show(id, !!text);
  log.debug("Leaving setText().");
}

function versionNote(v) {
  log.debug("Entering versionNote().");
  if (v === '1.1') {
    log.debug("Leaving versionNote(). 1.1.");
    return 'SAML 1.1 has no <AuthnRequest>. Its browser profiles are ' +
      'identity-provider-initiated, and what this page sends is ' +
      'Shibboleth\'s request profile ' +
      '(urn:mace:shibboleth:1.0:profiles:AuthnRequest): the ' +
      'query parameters TARGET, shire, providerId and time, plus the ' +
      'non-standard profile and format. Nothing in that is signed or ' +
      'encrypted, there is no subject hint to send, and the protocol has no ' +
      'Single Logout — so those settings are switched off below rather than ' +
      'ignored. Keycloak has not spoken SAML 1.1 for years; the mock STS ' +
      'does.' + (hasSamlLanding() ? '' :
      ' NOTE: this deployment has nowhere for the identity provider to POST ' +
      'a response, and SAML 1.1 has no redirect-bound response binding to ' +
      'fall back to — Browser/POST is a form POST and Browser/Artifact needs ' +
      'the API. SAML 1.1 cannot complete here.');
  }
  if (v === '2.0') {
    log.debug("Leaving versionNote(). 2.0.");
    return '';
  }
  log.debug("Leaving versionNote(). Reference only.");
  return 'SAML 1.0 is reference only. It is SAML 1.1 with a MinorVersion of ' +
    '0 and nothing here builds one, so no request is sent. Select SAML 1.1 ' +
    'for a working browser-profile round trip, or SAML 2.0 for an ' +
    'SP-initiated one.';
}

function bindingNote(v) {
  log.debug("Entering bindingNote().");
  if (v !== '1.1') {
    log.debug("Leaving bindingNote(). Not 1.1.");
    return '';
  }
  log.debug("Leaving bindingNote(). 1.1.");
  return 'In SAML 1.1 this chooses two things at once. Redirect and POST ' +
    'differ only in how the request reaches the inter-site transfer ' +
    'service — the answer comes back on Browser/POST either way (section ' +
    '4.2), as a form POST of a SAMLResponse to the shire URL. Artifact asks ' +
    'for Browser/Artifact (section 4.1): the browser is redirected to the ' +
    'shire with a SAMLart, and the API resolves it over the SOAP binding at ' +
    'the SAML responder, which destroys it — an artifact is one-shot. Note ' +
    'that SAML 1.1 defines no POST-bound request at all; that option sends ' +
    'the same non-standard parameters as a form and needs an identity ' +
    'provider that reads one.';
}

function ssoEndpointsNote(v) {
  log.debug("Entering ssoEndpointsNote().");
  if (v !== '1.1') {
    log.debug("Leaving ssoEndpointsNote(). Not 1.1.");
    return '';
  }
  log.debug("Leaving ssoEndpointsNote(). 1.1.");
  return 'A SAML 1.1 identity provider has ONE endpoint here — the ' +
    'inter-site transfer service — which its metadata names once per ' +
    'profile it answers, so all three fields above hold the same address. ' +
    'The Artifact Resolution Service is its SAML responder, over the SOAP ' +
    'binding.';
}

// Toggle the SP Signing Key Pair section with the "Digitally sign the
// AuthnRequest" checkbox (checked => visible).
function onSignChange() {
  log.debug("Entering onSignChange().");
  var e = el('saml_sign_request');
  // In SAML 1.1 the checkbox is off and disabled, and the section stays VISIBLE
  // anyway: the key pair still signs the artifact back-channel's SOAP request
  // and is still the SP metadata's KeyDescriptor. See
  // applyVersionAvailability().
  show('saml_signing_section', isSaml11() || !e || e.checked);
  saveState();
  log.debug("Leaving onSignChange().");
  return false;
}

// Say what clearing the box actually costs, at the moment it is cleared. The
// consequence lands on a different page (the response page's prefill goes away)
// and after a reload, so it is not something to leave the user to discover.
function renderKeyPairStorageNote() {
  log.debug("Entering renderKeyPairStorageNote().");
  var note = el('saml_keypair_storage_note');
  if (!note) {
    log.debug("Leaving renderKeyPairStorageNote().");
    return;
  }
  if (keyPairMayBeStored()) {
    note.textContent = '';
    log.debug("Leaving renderKeyPairStorageNote().");
    return;
  }
  // textContent, not innerHTML: this is a message, not markup.
  note.textContent = 'Not saved. Use Download to keep this key pair. After a ' +
      'reload you will need ' +
    'to paste it back into these two fields, and paste the private key into ' +
        'the Decryption Key ' +
    'field on the SAML Response page before an EncryptedAssertion can be decrypted.';
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

// Toggle the AuthnRequest Encryption section with the "Encrypt the
// AuthnRequest" checkbox (checked => visible; default unchecked/hidden).
function onEncryptChange() {
  log.debug("Entering onEncryptChange().");
  var e = el('saml_encrypt_request');
  // Closed and kept closed on a version with no request document to encrypt,
  // whatever a preference stored during a 2.0 session says.
  show('saml_encryption_section', encEnabled());
  saveState();
  log.debug("Leaving onEncryptChange().");
  return false;
}

// Toggle the WS-Addressing section with the "Add WS-Addressing headers"
// checkbox (checked => visible; default unchecked/hidden). The checkbox is also
// the enable flag read when building the ArtifactResolve SOAP envelope.
function onWsaChange() {
  log.debug("Entering onWsaChange().");
  var e = el('saml_wsa_support');
  show('saml_wsa_section', !!(e && e.checked));
  saveState();
  log.debug("Leaving onWsaChange().");
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
      setVal('saml_sp_private_key',
             forge.pki.privateKeyToPem(kp.privateKey).trim() + '\n');
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
  var attrs = [{ name: 'commonName', value: val('saml_sp_entity_id') ||
      'saml-debugger-sp' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(kp.privateKey, forge.md.sha256.create());
  log.debug("Leaving spSelfSignedCertPem().");
  return forge.pki.certificateToPem(cert).trim() + '\n';
}

function downloadKeys() {
  log.debug("Entering downloadKeys().");
  var priv = val('saml_sp_private_key');
  if (!priv) {
    setStatus('saml_call_status', 'Generate a key pair first.');
    log.debug("Leaving downloadKeys().");
    return false;
  }
  triggerDownload('sp-private-key.pem', priv, 'application/x-pem-file');
  triggerDownload('sp-certificate.pem', val('saml_sp_public_key'),
                  'application/x-pem-file');
  log.debug("Leaving downloadKeys().");
  return false;
}

function triggerDownload(filename, data, mime) {
  log.debug("Entering triggerDownload().");
  var blob = new Blob([data], { type: mime || 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  log.debug("Leaving triggerDownload().");
}

// ---------------------------------------------------------------------------
// SP metadata (EntityDescriptor) — describes this debugger as a Service
// Provider so it can be registered on the IdP.
// ---------------------------------------------------------------------------
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
      '\n        <ds:X509Data><ds:X509Certificate>' + certB64 +
          '</ds:X509Certificate></ds:X509Data>' +
      '\n      </ds:KeyInfo>' +
      '\n    </md:KeyDescriptor>'
    : '';
  var sloSvc = slo
    ? '\n    <md:SingleLogoutService Binding="' + BINDING.post +
        '" Location="' + xmlEscape(slo) + '"/>' +
      '\n    <md:SingleLogoutService Binding="' + BINDING.redirect +
          '" Location="' + xmlEscape(slo) + '"/>'
    : '';
  var nameIdFmt = fmt ? '\n    <md:NameIDFormat>' + xmlEscape(fmt) +
      '</md:NameIDFormat>' : '';
  // WHICH BINDINGS THE ASSERTION CONSUMER ANSWERS, and in SAML 1.1 they are
  // PROFILE URIs rather than binding ones — the 1.1 profiles bundle their
  // binding into the profile, which is what Shibboleth's own metadata does. A
  // 1.1 document that advertised the 2.0 HTTP-POST binding URI here describes
  // an endpoint no SAML 1.1 identity provider will use.
  var eleven = isSaml11();
  var acsSvc = acs
    ? '\n    <md:AssertionConsumerService Binding="' +
        (eleven ? SAML11.post : BINDING.post) +
        '" Location="' + xmlEscape(acs) + '" index="0" isDefault="true"/>' +
      '\n    <md:AssertionConsumerService Binding="' +
        (eleven ? SAML11.artifact : BINDING.artifact) +
          '" Location="' + xmlEscape(acs) + '" index="1"/>'
    : '';
  // SAML 1.1 has no Single Logout and no request to sign, so a descriptor for
  // it carries neither the SingleLogoutService endpoints nor
  // AuthnRequestsSigned. Both are attributes an identity provider reads and
  // acts on, so writing them into a 1.1 document is not harmless decoration:
  // it claims this service provider will send something it cannot.
  var elevenSlo = eleven ? '' : sloSvc;
  var signedAttr = eleven ? '' : 'AuthnRequestsSigned="true" ';

  log.debug("Leaving buildSpMetadata().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
         '\n<md:EntityDescriptor ' +
             'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' +
             xmlEscape(entityId) + '">' +
         '\n  <md:SPSSODescriptor ' + signedAttr +
             'WantAssertionsSigned="true"' +
         ' protocolSupportEnumeration="' +
             (eleven ? SAML11.protocol : SAML20_PROTOCOL) + '">' +
         keyDescriptor + elevenSlo + nameIdFmt + acsSvc +
         '\n  </md:SPSSODescriptor>' +
         '\n</md:EntityDescriptor>\n';
}

function downloadSpMetadata() {
  log.debug("Entering downloadSpMetadata().");
  if (!val('saml_sp_entity_id')) {
    setStatus('saml_call_status', 'Set the SP entityID first.');
    log.debug("Leaving downloadSpMetadata().");
    return false;
  }
  triggerDownload('sp-metadata.xml', buildSpMetadata(),
                  'application/samlmetadata+xml');
  setStatus('saml_call_status', 'SP metadata downloaded.');
  log.debug("Leaving downloadSpMetadata().");
  return false;
}

// ---------------------------------------------------------------------------
// AuthnRequest construction
// ---------------------------------------------------------------------------
function ssoDestination(binding) {
  log.debug("Entering ssoDestination().");
  // SAML 1.1 has ONE endpoint — the inter-site transfer service — which its
  // metadata names once per profile, so parseMetadata() puts the same address
  // in all three fields. Any of them will do, and taking the first non-empty
  // one means a document that advertised only Browser/POST still works.
  if (isSaml11()) {
    var its = val('saml_sso_redirect') || val('saml_sso_post') ||
        val('saml_sso_artifact');
    log.debug("Leaving ssoDestination(). The inter-site transfer service.");
    return its;
  }
  // The AuthnRequest itself is delivered via HTTP-POST or HTTP-Redirect. The
  // "artifact" choice affects only how the *response* comes back
  // (ProtocolBinding = HTTP-Artifact), so the request is still sent to the
  // Redirect SSO endpoint.
  if (binding === 'post') {
    log.debug("Leaving ssoDestination().");
    return val('saml_sso_post');
  }
  log.debug("Leaving ssoDestination().");
  return val('saml_sso_redirect');
}

// ---------------------------------------------------------------------------
// THE SAML 1.1 REQUEST, WHICH IS NOT A DOCUMENT.
//
// Shibboleth's AuthnRequest profile: four parameters, unsigned, on the query
// string of a top-level GET (or, for the POST binding here, as form fields).
// Two more are NON-SPEC and are named as such everywhere they appear —
// `profile`, because nothing in SAML 1.1 lets a relying party choose between
// the two browser profiles, and `format`, because nothing lets it ask for a
// NameIdentifier format. An identity provider that does not know them ignores
// them, which is why sending them costs nothing.
//
// `TARGET` is the relay state. The profile intends it as the URL of the
// resource the person was trying to reach, and what the binding actually
// GUARANTEES is that it comes back byte for byte — which is what this page
// needs it for, exactly as RelayState is used on the 2.0 side: the artifact
// flow carries the API's `art:<id>` context handle in it, and there is nowhere
// else in the protocol to put one.
// ---------------------------------------------------------------------------
function saml11RequestParams(target) {
  log.debug("Entering saml11RequestParams().");
  var out = [];
  out.push(['TARGET', target || '']);
  var acs = val('saml_acs_url');
  if (acs) out.push(['shire', acs]);
  var sp = val('saml_sp_entity_id');
  if (sp) out.push(['providerId', sp]);
  // Seconds since the epoch, which is what Shibboleth sends. Not checked by
  // anything here; it is in the profile and a service provider that omitted it
  // would be sending a request no Shibboleth identity provider recognises.
  out.push(['time', String(Math.floor(Date.now() / 1000))]);
  out.push(['profile',
            val('saml_binding') === 'artifact' ? 'artifact' : 'post']);
  var fmt = val('saml_nameid_format');
  if (fmt) out.push(['format', fmt]);
  log.debug("Leaving saml11RequestParams(). " + out.length + " parameters.");
  return out;
}

function saml11QueryString(params) {
  log.debug("Entering saml11QueryString().");
  var parts = [];
  for (var i = 0; i < params.length; i++) {
    parts.push(encodeURIComponent(params[i][0]) + '=' +
               encodeURIComponent(params[i][1]));
  }
  log.debug("Leaving saml11QueryString().");
  return parts.join('&');
}

// The request as it will actually be sent, for the read-only box on the page.
// A URL for the two GET bindings; the endpoint and the form fields for the POST
// one, because there is no URL to show — the parameters are in the body.
function saml11RequestText(dest, params) {
  log.debug("Entering saml11RequestText().");
  var qs = saml11QueryString(params);
  if (val('saml_binding') === 'post') {
    var lines = ['POST ' + (dest || '(no inter-site transfer service — ' +
                 'load metadata)'),
                 'Content-Type: application/x-www-form-urlencoded', ''];
    for (var i = 0; i < params.length; i++) {
      lines.push(params[i][0] + '=' + params[i][1]);
    }
    log.debug("Leaving saml11RequestText(). A form POST.");
    return lines.join('\n');
  }
  log.debug("Leaving saml11RequestText(). A URL.");
  return dest ? (dest + (dest.indexOf('?') >= 0 ? '&' : '?') + qs) : qs;
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
// Is there anything at appconfig.acsUrl that can receive the IdP's POST?
//
// With the api backend, yes — its /samlacs route. Without it, only if the
// deployment put a Lambda@Edge on that path (infra/edge/saml_landing.js), which
// the env config declares with samlEdgeLanding. It is a separate flag rather
// than being inferred from backendAvailable because Terraform and the site
// build ship independently: a checkout can be redeployed before the
// infrastructure has been applied.
function hasSamlLanding() {
  log.debug("Entering hasSamlLanding().");
  if (appconfig.backendAvailable !== false) {
    log.debug("Leaving hasSamlLanding().");
    return true;
  }
  log.debug("Leaving hasSamlLanding().");
  return appconfig.samlEdgeLanding === true && !!appconfig.acsUrl;
}

// Which binding to ask the IdP to return the <Response> on.
//
// HTTP-POST whenever something can receive a POST, because that is what the
// profile requires: saml-profiles-2.0-os section 4.1.2 step 5 says the Response
// goes over HTTP POST or HTTP Artifact and that "the HTTP Redirect binding MUST
// NOT be used, as the response will typically exceed the URL length permitted
// by most user agents".
//
// HTTP-Redirect is the fallback for a deployment with no landing — a static
// site with no edge function. It is out of profile, and the spec's stated
// reason is exactly what bites: an encrypted assertion is ciphertext, which
// does not DEFLATE, so the redirect URL roughly doubles and runs at
// CloudFront's 8,192-byte cap. It is kept because it is the only thing that
// works there, and because real deployments do use the Redirect binding; it is
// not the default anywhere a POST can land.
function responseProtocolBinding(binding) {
  log.debug("Entering responseProtocolBinding().");
  if (binding === 'artifact') {
    log.debug("Leaving responseProtocolBinding().");
    return BINDING.artifact;
  }
  log.debug("Leaving responseProtocolBinding().");
  return hasSamlLanding() ? BINDING.post : BINDING.redirect;
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

  // SAML 1.1: there is no request DOCUMENT, so what goes in this box is the
  // request itself — the inter-site transfer URL, or the endpoint and the form
  // fields. buildRequestUi() and callIdp() both compose it from the same
  // saml11RequestParams(), so what is shown is what is sent.
  if (version === '1.1') {
    log.debug("Leaving buildAuthnRequest(). SAML 1.1 sends no document.");
    return saml11RequestText(dest, saml11RequestParams('saml_request'));
  }

  if (version !== '2.0') {
    log.debug("Leaving buildAuthnRequest().");
    return '<!-- SAML ' + version +
        ' is reference only here. It is SAML 1.1 with a MinorVersion of\n' +
           '     0, and nothing in this page builds one. Select SAML 1.1 for ' +
               'a working\n' +
           '     browser-profile round trip (Browser/POST or ' +
               'Browser/Artifact), or\n' +
           '     SAML 2.0 for an SP-initiated one. -->';
  }

  var id = genId();
  var instant = new Date().toISOString();
  var subject = '';
  if (hint && rule.allowed) {
    subject = '\n  <saml:Subject><saml:NameID' + (fmt ? ' Format="' +
        xmlEscape(fmt) + '"' : '') +
              '>' + xmlEscape(hint) + '</saml:NameID></saml:Subject>';
  }
  var nameIdPolicy = '\n  <samlp:NameIDPolicy' + (fmt ? ' Format="' +
      xmlEscape(fmt) + '"' : '') + ' AllowCreate="true"/>';

  log.debug("Leaving buildAuthnRequest().");
  return '<samlp:AuthnRequest ' +
      'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
         ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
         ' ID="' + id + '" Version="2.0" IssueInstant="' + instant + '"' +
         (dest ? ' Destination="' + xmlEscape(dest) + '"' : '') +
         ' ProtocolBinding="' + responseProtocolBinding(binding) + '"' +
         (acs ? ' AssertionConsumerServiceURL="' + xmlEscape(acs) + '"' : '') +
          '>' +
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
var TRANSFORM_ENVELOPED =
    'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
var DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
var XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';
var XENC11_NS = 'http://www.w3.org/2009/xmlenc11#';

function bytesToBase64(bytes) {
  log.debug("Entering bytesToBase64().");
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  log.debug("Leaving bytesToBase64().");
  return btoa(bin);
}
function utf8ToBase64(str) {
  log.debug("Entering utf8ToBase64().");
  log.debug("Leaving utf8ToBase64().");
  return btoa(unescape(encodeURIComponent(str)));
}

// DEFLATE (raw, no zlib header) via the native CompressionStream (async).
function deflateRaw(str) {
  log.debug("Entering deflateRaw().");
  if (typeof CompressionStream === 'undefined') {
    log.debug("Leaving deflateRaw().");
    return Promise.reject(new Error('This browser lacks CompressionStream; ' +
                          'cannot DEFLATE for the redirect binding.'));
  }
  var cs = new CompressionStream('deflate-raw');
  var writer = cs.writable.getWriter();
  writer.write(new TextEncoder().encode(str));
  writer.close();
  log.debug("Leaving deflateRaw().");
  return new Response(cs.readable).arrayBuffer()
                      .then(function (buf) { return new Uint8Array(buf); });
}

function selectedSigAlg() {
  log.debug("Entering selectedSigAlg().");
  log.debug("Leaving selectedSigAlg().");
  return val('saml_sig_alg') || SIG_ALG_RSA_SHA256;
}

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
      // saml-bindings-2.0-os section 3.4.4.1: the signature is over the
      // query string as it will be SENT, SigAlg included — which is why it is
      // appended before this call and not after.
      qs += '&Signature=' + encodeURIComponent(
        xmldsig.signQueryString(qs, {
          privateKeyPem: val('saml_sp_private_key'), sigAlg: alg }));
    }
    var location = dest ? (dest + (dest.indexOf('?') >= 0 ? '&' : '?') +
        qs) : qs;
    return { location: location, queryString: qs };
  });
}

// HTTP-POST binding: enveloped XML-DSIG. Returns the signed XML string. The
// <Signature> is placed after <Issuer> per the SAML schema.
// HTTP-POST binding: enveloped XML-DSIG. Returns the signed XML string.
//
// xmldsig.js's signEnveloped() produces exactly what this function used to:
// the same exclusive C14N, the same enveloped-signature + C14N transform
// pair, the same X509Data KeyInfo, and the <Signature> placed directly after
// <Issuer>, which is where the SAML schema requires it. The one thing that
// looks like a difference is not one — that module canonicalizes SignedInfo
// after inserting it rather than while detached, and under EXCLUSIVE C14N the
// two byte streams are identical, which is the whole reason SAML uses it.
function signPostEnveloped(xml) {
  log.debug("Entering signPostEnveloped().");
  var signed = xmldsig.signEnveloped(xml, {
    privateKeyPem: val('saml_sp_private_key'),
    certPem: val('saml_sp_public_key'),
    sigAlg: selectedSigAlg(),
    placement: 'after-issuer'
  });
  log.debug("Leaving signPostEnveloped().");
  return signed;
}

function encryptAuthnRequest(xml) {
  log.debug("Entering encryptAuthnRequest().");
  var certField = val('saml_enc_cert');
  if (!certField.trim()) throw new Error('No encryption certificate — load ' +
      'metadata or paste a recipient certificate.');
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
  var cipherValue = iv + cipher.output.getBytes() + (spec.gcm ?
      cipher.mode.tag.getBytes() : '');
  var cipherB64 = forge.util.encode64(cipherValue);

  // 2. RSA-wrap the session key with the recipient public key.
  var wrapped, keyMethodInner = '';
  if (keyAlg === XENC_NS + 'rsa-1_5') {
    wrapped = pub.encrypt(sessionKey, 'RSAES-PKCS1-V1_5');
  } else {
    var digestUri = val('saml_enc_digest');
    var oaepOpts = { md: forgeMdFor(digestUri) };
    keyMethodInner = '<ds:DigestMethod xmlns:ds="' + DS_NS + '" Algorithm="' +
        digestUri + '"/>';
    if (keyAlg === XENC11_NS + 'rsa-oaep') {
      var mgfUri = val('saml_enc_mgf');
      oaepOpts.mgf1 = { md: mgfMdFor(mgfUri) };
      keyMethodInner += '<xenc11:MGF xmlns:xenc11="' + XENC11_NS +
          '" Algorithm="' + mgfUri + '"/>';
    } else {
      // rsa-oaep-mgf1p: MGF1 is fixed to SHA-1.
      oaepOpts.mgf1 = { md: forge.md.sha1.create() };
    }
    wrapped = pub.encrypt(sessionKey, 'RSA-OAEP', oaepOpts);
  }
  var wrappedB64 = forge.util.encode64(wrapped);

  // 3. Assemble <xenc:EncryptedData> with the nested <xenc:EncryptedKey>.
  log.debug("Leaving encryptAuthnRequest().");
  return '<xenc:EncryptedData xmlns:xenc="' + XENC_NS + '" Type="' + type +
      '">' +
      '<xenc:EncryptionMethod Algorithm="' + dataAlg + '"/>' +
      '<ds:KeyInfo xmlns:ds="' + DS_NS + '">' +
        '<xenc:EncryptedKey>' +
          '<xenc:EncryptionMethod Algorithm="' + keyAlg + '">' +
              keyMethodInner + '</xenc:EncryptionMethod>' +
          '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 +
              '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
          '<xenc:CipherData><xenc:CipherValue>' + wrappedB64 +
              '</xenc:CipherValue></xenc:CipherData>' +
        '</xenc:EncryptedKey>' +
      '</ds:KeyInfo>' +
      '<xenc:CipherData><xenc:CipherValue>' + cipherB64 +
          '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData>';
}

// Whether signing / encryption are enabled. Signing defaults to on when the
// checkbox is somehow absent; encryption defaults to off.
//
// **BOTH READ THE VERSION FIRST, and that is the enforcement rather than a
// convenience.** The checkboxes are disabled on a version with no request
// document, but their state is PERSISTED — so a page restored from a 2.0
// session arrives with "sign" ticked, and a caller that read the checkbox alone
// would try to sign a document that does not exist. The disabled attribute is
// what the reader sees; this is what the code obeys.
function signEnabled() {
  log.debug("Entering signEnabled().");
  if (samlVersion() !== '2.0') {
    log.debug("Leaving signEnabled(). No request document to sign.");
    return false;
  }
  var e = el('saml_sign_request');
  log.debug("Leaving signEnabled().");
  return !e || e.checked;
}
function encEnabled() {
  log.debug("Entering encEnabled().");
  if (samlVersion() !== '2.0') {
    log.debug("Leaving encEnabled(). No request document to encrypt.");
    return false;
  }
  var e = el('saml_encrypt_request');
  log.debug("Leaving encEnabled().");
  return !!(e && e.checked);
}
function opStatus(signOn, encOn, what) {
  log.debug("Entering opStatus().");
  var msg = 'Built ' + (signOn ? 'signed' : 'unsigned') + (encOn ?
      ' + encrypted' : '') + ' AuthnRequest (' + what + ').';
  if (encOn) msg += ' Note: IdPs such as Keycloak reject encrypted AuthnRequests.';
  log.debug("Leaving opStatus().");
  return msg;
}

// Regenerate the Generated AuthnRequest field from the current settings. Called
// automatically on any config change (replaces the old "Build Request" button)
// and after programmatic updates (metadata load, key generation) that don't
// fire change events. Guarded so a transient build error can never break the
// handler.
function autoBuildRequest() {
  log.debug("Entering autoBuildRequest().");
  try {
    buildRequestUi();
  } catch (e) {
    log.error('autoBuildRequest: ' + e.message);
  }
  log.debug("Leaving autoBuildRequest().");
  return false;
}

function buildRequestUi() {
  log.debug("Entering buildRequestUi().");
  // The hint is only sent on a version that has a request document to carry it,
  // and its field is disabled on the others — so a value left over from a 2.0
  // session must not be able to refuse a 1.1 build.
  if (samlVersion() === '2.0' && !validateHint()) {
    setStatus('saml_call_status',
              'Username hint does not match the selected NameIDFormat.');
    log.debug("Leaving buildRequestUi().");
    return false;
  }
  var xml = buildAuthnRequest();
  setVal('saml_authn_request', xml);
  saveState();

  if (isSaml11()) {
    var dest11 = ssoDestination(val('saml_binding'));
    setStatus('saml_call_status', dest11
      ? ('Built the SAML 1.1 ' + (val('saml_binding') === 'post' ?
         'form POST' : 'inter-site transfer request') + ' for the ' +
         (val('saml_binding') === 'artifact' ? 'Browser/Artifact' :
          'Browser/POST') + ' profile. Nothing in it is signed — SAML 1.1 ' +
         'has no request document.')
      : 'Built the SAML 1.1 request parameters — load metadata for the ' +
        'inter-site transfer service address.');
    log.debug("Leaving buildRequestUi(). SAML 1.1.");
    return false;
  }

  if (isReferenceOnly()) {
    setStatus('saml_call_status',
              'SAML 1.0 is reference-only — see the request box.');
    log.debug("Leaving buildRequestUi().");
    return false;
  }

  var signOn = signEnabled();
  var encOn = encEnabled();
  var priv = val('saml_sp_private_key');
  var binding = val('saml_binding');

  if (signOn && !priv) {
    setStatus('saml_call_status', 'Signing is enabled but there is no SP ' +
              'private key — generate a key pair or uncheck "Digitally sign ' +
              'the AuthnRequest".');
    log.debug("Leaving buildRequestUi().");
    return false;
  }

  try {
    if (binding === 'post') {
      // POST binding: enveloped XML-DSIG inside the document, then (optionally)
      // encrypt the whole thing — show the resulting XML.
      var payload = signOn ? signPostEnveloped(xml) : xml;
      if (encOn) payload = encryptAuthnRequest(payload);
      setVal('saml_authn_request', payload);
      setStatus('saml_call_status', opStatus(signOn, encOn,
                'POST enveloped XML'));
      log.debug("Leaving buildRequestUi().");
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
        setStatus('saml_call_status', opStatus(signOn, encOn,
                  ssoDestination(binding) ? 'redirect URL' : 'redirect query ' +
                  'string — load metadata for the destination'));
      })
      .catch(function (e) {
        log.error('buildRequestUi redirect: ' + e.message);
        setStatus('saml_call_status', 'Build failed: ' + e.message);
      });
    log.debug("Leaving buildRequestUi().");
    return false;
  } catch (e) {
    log.error('buildRequestUi: ' + e.message);
    setStatus('saml_call_status', 'Build failed: ' + e.message);
    log.debug("Leaving buildRequestUi().");
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
  log.debug("Entering callIdp(). version=" + samlVersion());
  if (isSaml11()) {
    log.debug("Leaving callIdp(). Handed to the SAML 1.1 path.");
    return callIdpSaml11();
  }
  if (isReferenceOnly()) {
    setStatus('saml_call_status', 'SAML 1.0 is reference only — nothing is ' +
              'built to send. Select SAML 1.1 or SAML 2.0.');
    log.debug("Leaving callIdp().");
    return opFailure('Send AuthnRequest',
                     'SAML 1.0 is reference only — nothing to send.');
  }
  var signOn = signEnabled();
  var encOn = encEnabled();
  var priv = val('saml_sp_private_key');
  if (signOn && !priv) {
    setStatus('saml_call_status', 'Signing is enabled but there is no SP ' +
              'private key — generate a key pair or uncheck "Digitally sign ' +
              'the AuthnRequest".');
    log.debug("Leaving callIdp().");
    return opFailure('Send AuthnRequest',
                     'signing is enabled but there is no SP private key.');
  }
  var binding = val('saml_binding');
  var dest = ssoDestination(binding);
  if (!dest) {
    setStatus('saml_call_status',
        'No IdP endpoint for the selected binding — load metadata first.');
    log.debug("Leaving callIdp().");
    return opFailure('Send AuthnRequest',
                     'no IdP endpoint for the selected binding.');
  }
  if (!validateHint()) {
    setStatus('saml_call_status',
              'Username hint does not match the selected NameIDFormat.');
    log.debug("Leaving callIdp().");
    return opFailure('Send AuthnRequest',
        'the username hint does not match the selected NameIDFormat.');
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
        submitPostForm(dest, { SAMLRequest: utf8ToBase64(payload),
                       RelayState: 'saml_request' });
      } catch (e) {
        setStatus('saml_call_status', 'Send failed: ' + e.message);
        log.debug("Leaving callIdp().");
        return opFailed(postId, e.message);
      }
      log.debug("Leaving callIdp().");
      return false;
    }

    if (binding === 'artifact') {
      // Register the SP context (ARS URL + key) so the ACS can resolve the
      // artifact via SOAP; then send the (optionally encrypted, optionally
      // query-string-signed) redirect request in-browser.
      if (!appconfig.backendAvailable) {
        setStatus('saml_call_status', 'Artifact binding needs the API ' +
                  'backend (for artifact resolution).');
        log.debug("Leaving callIdp().");
        return opFailure('Send AuthnRequest',
                         'the Artifact binding needs the API backend.');
      }
      var reqXmlA = encOn ? encryptAuthnRequest(xml) : xml;
      var artifactSent = false;
      setStatus('saml_call_status', 'Preparing artifact request…');
      fetch(appconfig.apiUrl + '/samlartifactctx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          arsUrl: val('saml_ars'), privateKeyPem: priv,
                      certPem: val('saml_sp_public_key'),
          spEntityId: val('saml_sp_entity_id'), sigAlg: SIG_ALG_RSA_SHA256,
          // WS-Addressing headers for the SOAP ArtifactResolve envelope.
          wsa: {
            enabled: (function () { var w =
                      el('saml_wsa_support'); return !!(w && w.checked); })(),
            to: val('saml_wsa_to'),
            action: val('saml_wsa_action'),
            replyTo: val('saml_wsa_replyto'),
            from: val('saml_wsa_from'),
            messageId: val('saml_wsa_messageid')
          }
        })
      })
        .then(function (r) { return r.json()
            .then(function (j) { if (!r.ok) { throw new Error(j && j.error ?
            j.error : ('HTTP ' + r.status)); } return j; }); })
        .then(function (ctx) { return signRedirect(reqXmlA, dest,
            ctx.relayState, signOn); })
        .then(function (res) {
          artifactSent = true;
          var id = opSent('Send AuthnRequest', 'sent to ' + dest);
          try {
            // A refusal throws, and the existing handler below records it as a
            // failed operation and reports it — which is what should happen.
            window.location.assign(urlSafety.safeExternalUrl(res.location,
                                   'The IdP destination'));
          } catch (e) {
            opFailed(id, e.message);
            throw e;
          }
        })
        .catch(function (e) {
          log.error('callIdp artifact: ' + e.message);
          setStatus('saml_call_status', 'Artifact request failed: ' +
                    e.message);
          if (!artifactSent) opFailure('Send AuthnRequest', e.message);
        });
      log.debug("Leaving callIdp().");
      return false;
    }

    // Redirect binding — fully client-side.
    var redirectSentId = null;
    var reqXmlR = encOn ? encryptAuthnRequest(xml) : xml;
    setStatus('saml_call_status', 'Sending request…');
    signRedirect(reqXmlR, dest, 'saml_request', signOn)
      .then(function (res) {
        redirectSentId = opSent('Send AuthnRequest', 'sent to ' + dest);
        window.location.assign(urlSafety.safeExternalUrl(res.location,
                               'The IdP destination'));
      })
      .catch(function (e) {
        log.error('callIdp: ' + e.message);
        setStatus('saml_call_status', 'Send failed: ' + e.message);
        if (redirectSentId) opFailed(redirectSentId, e.message);
        else opFailure('Send AuthnRequest', e.message);
      });
    log.debug("Leaving callIdp().");
    return false;
  } catch (e) {
    log.error('callIdp: ' + e.message);
    setStatus('saml_call_status', 'Send failed: ' + e.message);
    log.debug("Leaving callIdp().");
    return opFailure('Send AuthnRequest', e.message);
  }
  log.debug("Leaving callIdp().");
}

// ---------------------------------------------------------------------------
// SEND THE SAML 1.1 REQUEST.
//
// There is nothing to sign, nothing to encrypt and no document to build, so
// this is much shorter than its 2.0 sibling and the whole of the difference
// between the three bindings is here:
//
//   redirect  navigate to the inter-site transfer service with the parameters
//             on the query string. A top-level GET, which is what carries a
//             SameSite=Lax session cookie — so an identity provider that has
//             already signed this browser in answers without a screen.
//   post      the same parameters as a form POST. SAML 1.1 defines no
//             POST-bound request; this is Shibboleth's parameters delivered
//             the other way, and it needs an identity provider that reads one.
//   artifact  register the SP context with the API first (it is the API that
//             will have to make the SOAP call), then send the request as a GET
//             carrying the returned `art:<id>` handle IN TARGET — which is
//             the only round-tripped value SAML 1.1 has, RelayState not
//             existing until 2.0.
//
// Every path records a "Sent" entry BEFORE handing the browser over, for the
// reason the 2.0 one does: after the navigation this page is gone, and an entry
// written afterwards is an entry never written.
// ---------------------------------------------------------------------------
function callIdpSaml11() {
  log.debug("Entering callIdpSaml11().");
  var binding = val('saml_binding');
  var dest = ssoDestination(binding);
  if (!dest) {
    setStatus('saml_call_status', 'No inter-site transfer service address — ' +
              'load the IdP metadata first, or fill in one of the SSO ' +
              'endpoint fields.');
    log.debug("Leaving callIdpSaml11().");
    return opFailure('Send AuthnRequest',
                     'no inter-site transfer service address.');
  }
  if (!val('saml_acs_url')) {
    // shire is what tells the identity provider where the assertion goes. With
    // no request message there is no other way to say it, and an IdP that has
    // to guess sends the response to its own mock relying party — which looks
    // exactly like this page never being answered.
    setStatus('saml_call_status', 'Set the ACS URL first — SAML 1.1 has no ' +
              'request message, so the shire parameter is the only way to ' +
              'say where the assertion should go.');
    log.debug("Leaving callIdpSaml11().");
    return opFailure('Send AuthnRequest',
                     'no ACS URL to send as the shire parameter.');
  }

  if (binding === 'artifact') {
    if (!appconfig.backendAvailable) {
      setStatus('saml_call_status', 'The Artifact profile needs the API ' +
                'backend: resolving an artifact is a SOAP call a browser ' +
                'cannot make.');
      log.debug("Leaving callIdpSaml11().");
      return opFailure('Send AuthnRequest',
                       'the Browser/Artifact profile needs the API backend.');
    }
    var artifactSent = false;
    setStatus('saml_call_status', 'Preparing the Browser/Artifact request…');
    fetch(appconfig.apiUrl + '/samlartifactctx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        // SAML 1.1's responder, not a SAML 2.0 Artifact Resolution Service:
        // the API builds a <samlp:Request> carrying an <AssertionArtifact>
        // rather than an <ArtifactResolve>, and this is what tells it which.
        samlVersion: '1.1',
        arsUrl: val('saml_ars'),
        privateKeyPem: val('saml_sp_private_key'),
        certPem: val('saml_sp_public_key'),
        spEntityId: val('saml_sp_entity_id'),
        sigAlg: selectedSigAlg(),
        wsa: {
          enabled: (function () { var w =
                    el('saml_wsa_support'); return !!(w && w.checked); })(),
          to: val('saml_wsa_to'),
          action: val('saml_wsa_action'),
          replyTo: val('saml_wsa_replyto'),
          from: val('saml_wsa_from'),
          messageId: val('saml_wsa_messageid')
        }
      })
    })
      .then(function (r) { return r.json()
          .then(function (j) { if (!r.ok) { throw new Error(j && j.error ?
          j.error : ('HTTP ' + r.status)); } return j; }); })
      .then(function (ctx) {
        var params = saml11RequestParams(ctx.relayState);
        var url = dest + (dest.indexOf('?') >= 0 ? '&' : '?') +
            saml11QueryString(params);
        setVal('saml_authn_request', saml11RequestText(dest, params));
        artifactSent = true;
        var id = opSent('Send AuthnRequest', 'sent to ' + dest +
                        ' (Browser/Artifact)');
        try {
          window.location.assign(urlSafety.safeExternalUrl(url,
                                 'The IdP inter-site transfer service'));
        } catch (e) {
          opFailed(id, e.message);
          throw e;
        }
      })
      .catch(function (e) {
        log.error('callIdpSaml11 artifact: ' + e.message);
        setStatus('saml_call_status', 'Artifact request failed: ' + e.message);
        if (!artifactSent) opFailure('Send AuthnRequest', e.message);
      });
    log.debug("Leaving callIdpSaml11(). Browser/Artifact.");
    return false;
  }

  var postParams = saml11RequestParams('saml_request');
  setVal('saml_authn_request', saml11RequestText(dest, postParams));
  saveState();

  if (binding === 'post') {
    var form = {};
    for (var i = 0; i < postParams.length; i++) {
      form[postParams[i][0]] = postParams[i][1];
    }
    var postId = opSent('Send AuthnRequest', 'sent to ' + dest +
                        ' (form POST, Browser/POST profile)');
    try {
      submitPostForm(dest, form);
    } catch (e) {
      setStatus('saml_call_status', 'Send failed: ' + e.message);
      log.debug("Leaving callIdpSaml11().");
      return opFailed(postId, e.message);
    }
    log.debug("Leaving callIdpSaml11(). Form POST.");
    return false;
  }

  var redirectUrl = dest + (dest.indexOf('?') >= 0 ? '&' : '?') +
      saml11QueryString(postParams);
  var sentId = opSent('Send AuthnRequest', 'sent to ' + dest +
                      ' (GET, Browser/POST profile)');
  try {
    window.location.assign(urlSafety.safeExternalUrl(redirectUrl,
                           'The IdP inter-site transfer service'));
  } catch (e) {
    setStatus('saml_call_status', 'Send failed: ' + e.message);
    log.debug("Leaving callIdpSaml11().");
    return opFailed(sentId, e.message);
  }
  log.debug("Leaving callIdpSaml11(). GET.");
  return false;
}

// Auto-submit an HTTP-POST-binding request to the IdP SSO endpoint.
function submitPostForm(action, params) {
  log.debug("Entering submitPostForm().");
  var form = document.createElement('form');
  form.method = 'POST';
  // The action is the IdP SSO endpoint, which came from a form field or from
  // fetched metadata. A form submitted to a `javascript:` action executes it,
  // so the scheme is checked here rather than trusted.
  form.action = urlSafety.safeExternalUrl(action, 'The IdP SSO endpoint');
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
function lastLogin(key) {
  log.debug("Entering lastLogin().");
  log.debug("Leaving lastLogin().");
  return (window.localStorage && localStorage.getItem(key)) || '';
}

function buildLogoutRequest() {
  log.debug("Entering buildLogoutRequest().");
  var slo = val('saml_slo_redirect') || val('saml_slo_post');
  var issuer = val('saml_sp_entity_id');
  var nameid = lastLogin('saml_last_nameid');
  var fmt = lastLogin('saml_last_nameid_format');
  var sidx = lastLogin('saml_last_session_index');
  log.debug("Leaving buildLogoutRequest().");
  return '<samlp:LogoutRequest ' +
      'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
         ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
         ' ID="' + genId() + '" Version="2.0" IssueInstant="' +
             new Date().toISOString() + '"' +
         (slo ? ' Destination="' + xmlEscape(slo) + '"' : '') + '>' +
         '\n  <saml:Issuer>' + xmlEscape(issuer) + '</saml:Issuer>' +
         '\n  <saml:NameID' + (fmt ? ' Format="' + xmlEscape(fmt) + '"' : '') +
             '>' + xmlEscape(nameid) + '</saml:NameID>' +
         (sidx ? '\n  <samlp:SessionIndex>' + xmlEscape(sidx) +
          '</samlp:SessionIndex>' : '') +
         '\n</samlp:LogoutRequest>';
}

function singleLogout() {
  log.debug("Entering singleLogout().");
  var sloBinding = bindingLabel(val('saml_binding') === 'post' ?
      'post' : 'redirect');
  if (samlVersion() !== '2.0') {
    // Not "unimplemented here" — SAML 1.1 has no Single Logout at all. There is
    // no LogoutRequest in the protocol, nothing publishes an endpoint for one,
    // and the button is disabled on this version. This refusal is the guard
    // behind that, for a caller that reaches the function some other way.
    setStatus('saml_call_status', 'SAML ' + samlVersion() + ' has no Single ' +
              'Logout — the protocol has no logout message and no endpoint ' +
              'for one. Single Logout arrived with SAML 2.0.');
    log.debug("Leaving singleLogout().");
    return opFailure('Single Logout',
                     'SAML ' + samlVersion() + ' has no Single Logout.',
                     { binding: sloBinding });
  }
  var priv = val('saml_sp_private_key');
  if (!priv) {
    setStatus('saml_call_status', 'Generate an SP key pair first.');
    log.debug("Leaving singleLogout().");
    return opFailure('Single Logout',
                     'there is no SP private key to sign the LogoutRequest.',
                     { binding: sloBinding });
  }
  if (!lastLogin('saml_last_nameid')) {
    setStatus('saml_call_status',
              'No NameID from a prior login — complete an SSO first.');
    log.debug("Leaving singleLogout().");
    return opFailure('Single Logout', 'no NameID from a prior login.',
                     { binding: sloBinding });
  }
  var binding = val('saml_binding') === 'post' ? 'post' : 'redirect';
  var dest = binding === 'post' ?
      val('saml_slo_post') : val('saml_slo_redirect');
  if (!dest) {
    setStatus('saml_call_status',
        'No SLO endpoint for the selected binding — load metadata first.');
    log.debug("Leaving singleLogout().");
    return opFailure('Single Logout',
                     'no SLO endpoint for the selected binding.',
                     { binding: sloBinding });
  }

  var sloSentId = null;
  var xml = buildLogoutRequest();
  setVal('saml_authn_request', xml);
  setStatus('saml_call_status', 'Signing LogoutRequest…');

  if (binding === 'post') {
    try {
      var signed = signPostEnveloped(xml);
      setVal('saml_authn_request', signed);
      sloSentId = opSent('Single Logout', 'sent to ' + dest,
          { binding: sloBinding });
      submitPostForm(dest, { SAMLRequest: utf8ToBase64(signed),
                     RelayState: 'slo' });
    } catch (e) {
      log.error('singleLogout post: ' + e.message);
      setStatus('saml_call_status', 'SLO failed: ' + e.message);
      if (sloSentId) opFailed(sloSentId, e.message);
      else opFailure('Single Logout', e.message, { binding: sloBinding });
    }
    log.debug("Leaving singleLogout().");
    return false;
  }
  signRedirect(xml, dest, 'slo')
    .then(function (res) {
      sloSentId = opSent('Single Logout', 'sent to ' + dest,
          { binding: sloBinding });
      window.location.assign(urlSafety.safeExternalUrl(res.location,
                             'The IdP SLO destination'));
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
  log.debug("Entering bindingLabel().");
  if (b === 'post') {
    log.debug("Leaving bindingLabel().");
    return 'HTTP-POST';
  }
  if (b === 'redirect') {
    log.debug("Leaving bindingLabel().");
    return 'HTTP-Redirect';
  }
  if (b === 'artifact') {
    log.debug("Leaving bindingLabel().");
    return 'HTTP-Artifact';
  }
  log.debug("Leaving bindingLabel().");
  return b || '\u2014';
}

function historyEntry(operation, result, detail, opts) {
  log.debug("Entering historyEntry().");
  opts = opts || {};
  log.debug("Leaving historyEntry().");
  return {
    operation: operation,
    result: result,
    detail: detail || '',
    binding: (opts.binding !== undefined) ?
              opts.binding : bindingLabel(val('saml_binding')),
    version: opts.version || val('saml_version'),
    spEntityId: (opts.spEntityId !== undefined) ?
                 opts.spEntityId : val('saml_sp_entity_id'),
    idpEntityId: (opts.idpEntityId !== undefined) ?
                  opts.idpEntityId : val('saml_idp_entity_id')
  };
}

// Failed before the request could leave the browser.
function opFailure(operation, reason, opts) {
  log.debug("Entering opFailure().");
  history.record(historyEntry(operation, history.FAILURE, reason, opts));
  renderOperationHistory();
  log.debug("Leaving opFailure().");
  return false;
}
// Dispatched — awaiting the IdP. Returns the entry id so the caller can flip it
// to a failure if the hand-over itself then throws.
function opSent(operation, detail, opts) {
  log.debug("Entering opSent().");
  var id = history.record(historyEntry(operation, history.SENT, detail, opts));
  renderOperationHistory();
  log.debug("Leaving opSent().");
  return id;
}
// Something went wrong after the entry was written: correct it in place rather
// than leaving a "Sent" row next to a "Failure" row for the same attempt.
function opFailed(id, reason) {
  log.debug("Entering opFailed().");
  if (id) history.update(id, history.FAILURE, reason);
  renderOperationHistory();
  log.debug("Leaving opFailed().");
  return false;
}
// Completed here and now (no IdP hand-over involved, e.g. a metadata load).
function opSuccess(operation, detail, opts) {
  log.debug("Entering opSuccess().");
  history.record(historyEntry(operation, history.SUCCESS, detail, opts));
  renderOperationHistory();
  log.debug("Leaving opSuccess().");
  return false;
}

function renderOperationHistory() {
  log.debug("Entering renderOperationHistory().");
  history.render(el('saml_operation_history'));
  log.debug("Leaving renderOperationHistory().");
}

function clearOperationHistory() {
  log.debug("Entering clearOperationHistory().");
  history.clear();
  renderOperationHistory();
  log.debug("Leaving clearOperationHistory().");
  return false;
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

// Collapse/expand a single pane by toggling its body's display. The pane's
// triangle indicator follows the state via a CSS :has() rule (mirrors the
// debugger pages' pane behavior).
function togglePane(bodyId) {
  log.debug("Entering togglePane().");
  var b = el(bodyId);
  if (b) b.style.display = (b.style.display === 'none') ? 'block' : 'none';
  log.debug("Leaving togglePane().");
  return false;
}

// Tab switching scoped to the pane containing the clicked tab, so multiple tab
// groups on the page toggle independently (mirrors saml_response.js).
function showTab(evt, tabId) {
  log.debug("Entering showTab().");
  var target = el(tabId);
  var scope = (target && target.closest && target.closest('.saml-pane')) ||
      document;
  var contents = scope.getElementsByClassName('saml-tabcontent');
  for (var i = 0; i < contents.length; i++) { contents[i].style.display =
       'none'; }
  var links = scope.getElementsByClassName('tablinks');
  for (var k = 0; k < links.length; k++) { links[k].className =
       links[k].className.replace(' active', ''); }
  if (target) target.style.display = 'block';
  if (evt && evt.currentTarget) evt.currentTarget.className += ' active';
  log.debug("Leaving showTab().");
  return false;
}

// Open the certificate-details page for the cert in the given field (the IdP
// signer cert or the generated SP cert). The cert is handed over via
// localStorage ('saml_cert_view') and shown in a new tab.
function viewCertificate(fieldId) {
  log.debug("Entering viewCertificate().");
  var pem = val(fieldId);
  if (!pem) {
    setStatus('saml_metadata_status', 'No certificate to view yet.');
    log.debug("Leaving viewCertificate().");
    return false;
  }
  try {
    if (window.localStorage) localStorage.setItem('saml_cert_view', pem);
  } catch (e) {
    // No storage available in this context.
  }
  window.open('/saml_cert.html?from=saml_request.html', '_blank');
  log.debug("Leaving viewCertificate().");
  return false;
}

function setReturnLink() {
  log.debug("Entering setReturnLink().");
  // The top-of-page link returns to the landing page (the OAuth2/OIDC vs SAML
  // protocol chooser), not a specific debugger.
  var link = el('return_link');
  if (link) link.setAttribute('href', '/index.html');
  log.debug("Leaving setReturnLink().");
}

// ---------------------------------------------------------------------------
// Configuration Parameters URL validation. Endpoint fields must hold a valid
// http(s) URL; the entityID must be a valid absolute URI (URL or URN).
// Non-empty values that don't parse are reported in the config status field;
// empty fields are left alone (many endpoints are optional / IdP-specific).
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
  log.debug("Entering isHttpUrl().");
  try {
    var u = new URL(v);
    log.debug("Leaving isHttpUrl().");
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (e) {
    log.debug("Leaving isHttpUrl().");
    return false;
  }
}
function isAbsoluteUri(v) {
  log.debug("Entering isAbsoluteUri().");
  try {
    new URL(v);
    log.debug("Leaving isAbsoluteUri().");
    return true;
  } catch (e) {
    log.debug("Leaving isAbsoluteUri().");
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
    setStatus('saml_config_status', 'Invalid URL in: ' + bad.join(', ') +
              '. Enter a full URL (e.g. https://host/path).');
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
  // Reflect the restored preference: if the user turned saving off in an
  // earlier session, the note has to be back on the page, and any key pair
  // written before that has to be gone (restoreState leaves the fields empty,
  // but the storage entries would otherwise survive an upgrade to this build).
  if (!keyPairMayBeStored()) forgetStoredKeyPair();
  renderKeyPairStorageNote();

  // Seed defaults where the user hasn't stored anything yet.
  if (!val('saml_metadata_url') &&
      appconfig.samlMetadataUrlDefault) setVal('saml_metadata_url',
      appconfig.samlMetadataUrlDefault);
  if (!val('saml_sp_entity_id') &&
      appconfig.spEntityId) setVal('saml_sp_entity_id', appconfig.spEntityId);
  // ACS (where the IdP returns its response). With a backend it's the api's
  // /samlacs endpoint (from config); on a static deployment with the edge ACS
  // deployed it is the SAME path, answered by the Lambda@Edge instead of by
  // Express. With neither there is nothing that can receive a POST, so the
  // "ACS" is this static SAML Response page on the same origin, which the
  // Redirect-binding response (see responseProtocolBinding) delivers to as a
  // GET.
  var acsDefault = hasSamlLanding()
    ? appconfig.acsUrl
    : (window.location.origin + '/saml_response.html');
  if (!val('saml_acs_url') && acsDefault) setVal('saml_acs_url', acsDefault);
  // Configuration Parameters: fall back to the dummy defaults declared in the
  // HTML (input value / textarea content) when restore left a field blank — so
  // the sample endpoints/cert show on a fresh page even if an earlier visit
  // stored empty values. A real "Load Metadata" or a user edit overrides them.
  ['saml_idp_entity_id', 'saml_sso_post', 'saml_sso_redirect',
   'saml_sso_artifact', 'saml_ars',
   'saml_slo_post', 'saml_slo_redirect', 'saml_slo_artifact',
       'saml_signer_cert'].forEach(function (id) {
    var e = el(id);
    if (e && !e.value && e.defaultValue) e.value = e.defaultValue;
  });
  // Encryption cert: localStorage (restored above) wins; otherwise default to
  // the signer cert from previously-loaded metadata (also restored above).
  if (!val('saml_enc_cert') && val('saml_signer_cert')) setVal('saml_enc_cert',
      val('saml_signer_cert'));

  // The static notice always shows without a backend, but WHICH binding
  // sentence applies depends on whether the edge ACS is deployed.
  show('saml_backend_notice', !appconfig.backendAvailable);
  show('saml_edge_acs_notice', appconfig.backendAvailable === false &&
       hasSamlLanding());
  show('saml_redirect_fallback_notice', !hasSamlLanding());
  // applyVersionAvailability() rather than onVersionChange(): the latter clears
  // the "a metadata load moved this" note, which is a statement about a load
  // that has not happened yet. It calls onSignChange()/onEncryptChange()
  // itself, so the two sub-sections still open to match their checkboxes.
  applyVersionAvailability();
  onNameIdFormatChange();
  onWsaChange();

  // Persist on any change, and auto-regenerate the AuthnRequest. 'change' (not
  // per-keystroke 'input') drives the rebuild so signing/encryption don't run
  // on every keystroke — text fields rebuild on blur; selects/checkboxes
  // immediately.
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    els[i].addEventListener('change', saveState);
    els[i].addEventListener('input', saveState);
    els[i].addEventListener('change', autoBuildRequest);
  }

  // Live URL validation for the Configuration Parameters fields.
  var urlIds =
      Object.keys(CONFIG_URL_FIELDS).concat(Object.keys(CONFIG_URI_FIELDS));
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
  log.debug("Leaving onload().");
};

module.exports = {
  loadMetadata,
  uploadMetadata,
  onMetadataFileChange,
  onNameIdFormatChange,
  onVersionChange,
  onSignChange,
  onSaveKeyPairChange,
  onEncryptChange,
  onWsaChange,
  validateHint,
  generateKeys,
  downloadKeys,
  downloadSpMetadata,
  // The DOCUMENT rather than the download. Exported because what has to be
  // asserted about it is its content, and the download goes through a browser
  // save dialogue — tests/saml11_options.js reads it here instead, which is
  // also the only way to compare the SAML 1.1 and SAML 2.0 shapes in one run.
  buildSpMetadata,
  buildRequestUi,
  callIdp,
  singleLogout,
  viewCertificate,
  copyField,
  showTab,
  togglePane,
  clearOperationHistory
};
