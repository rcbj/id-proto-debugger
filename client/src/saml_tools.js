// File: saml_tools.js
// Author: Robert C. Broeckelmann Jr.
//
// SAML Assertion Tool — compose, sign, and encrypt a SAML assertion entirely in
// the browser. Three panes, modeled on the JWT Tools page:
//
//   Pane 1 (Compose): pick the assertion version (SAML 1.0 / 1.1 / 2.0) and
//     which optional elements it carries (Subject / SubjectConfirmation,
//     Conditions, AudienceRestriction, OneTimeUse or DoNotCacheCondition,
//     ProxyRestriction, Advice, Authn(entication)Statement + SubjectLocality,
//     AttributeStatement, Authz(orization)DecisionStatement), set the NameID,
//     and add custom attributes (value type + URI prefix + name + value). The
//     ID and every instant (IssueInstant / NotBefore / NotOnOrAfter /
//     AuthnInstant) are auto-populated with the current time and can be edited
//     or refreshed. The Issuer defaults to this debugger's URL.
//   Pane 2 (Sign): an enveloped XML Signature (XML-DSIG) over the assertion —
//     the same options the SAML Test Tools page offers for the AuthnRequest.
//   Pane 3 (Encrypt): XML Encryption of the (optionally signed) assertion,
//     with the same algorithm knobs as the SAML Test Tools encryption pane,
//     wrapped in <saml:EncryptedAssertion> for SAML 2.0.
//
// All XML security uses the shared in-browser primitives in ./xmldsig.js — the
// same exclusive Canonical XML 1.0, RSA-SHA* enveloped signing, W3C
// XML-Encryption, verification, and decryption that back saml_request.html. No
// server round-trip is involved. Everything the user configures (including the
// generated throwaway private keys) is persisted to localStorage by element id,
// exactly like the other SAML pages.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var xd = require("./xmldsig");
var log = bunyan.createLogger({ name: 'saml_tools', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var forge = xd.forge;
// Unchanged across the saml_assertion -> saml_tools rename: the page state
// (including generated keys) is keyed by this prefix, and renaming it would
// orphan it. It also keeps this page's keys distinct from saml_request.js,
// which uses "samltools_".
var STORE_PREFIX = "samlassert_";
var ATTRS_KEY = STORE_PREFIX + "attributes";

// Assertion namespaces. SAML 1.0 and 1.1 share the 1.0 namespace and are told
// apart by MajorVersion/MinorVersion; 2.0 has its own.
var SAML1_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
var SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
var XS_NS = "http://www.w3.org/2001/XMLSchema";
var XSI_NS = "http://www.w3.org/2001/XMLSchema-instance";
var ACTION_NS_RWEDC = "urn:oasis:names:tc:SAML:1.0:action:rwedc";

// Subject confirmation methods differ only in their version segment, so the
// <select> carries the bare token and the URI is built per version.
var CM_PREFIX = { '2.0': 'urn:oasis:names:tc:SAML:2.0:cm:', '1.1': 'urn:oasis:names:tc:SAML:1.0:cm:', '1.0': 'urn:oasis:names:tc:SAML:1.0:cm:' };

// NameID formats introduced by SAML 2.0 — flagged by the compliance check when
// the selected version is 1.x.
var V2_ONLY_NAMEID = /^urn:oasis:names:tc:SAML:2\.0:nameid-format:/;

// ---------------------------------------------------------------------------
// Small DOM helpers (mirror saml_request.js).
// ---------------------------------------------------------------------------
function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ''; }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function setStatus(id, msg) { setVal(id, msg); }
function isOn(id) { var e = el(id); return !!(e && e.checked); }
function show(id, on) { var e = el(id); if (e) { if (on) e.classList.remove('saml-hidden'); else e.classList.add('saml-hidden'); } }
function esc(s) { return xd.xmlEscape(s); }

function version() { return val('sa_version') || '2.0'; }
function isV2() { return version() === '2.0'; }

// ---------------------------------------------------------------------------
// localStorage persistence — every .stored element is saved by its id. The
// timestamp fields are deliberately NOT .stored: a stale IssueInstant would
// produce an expired assertion on the next visit, so they are regenerated.
// ---------------------------------------------------------------------------
function persistedEls() { return document.querySelectorAll('.stored'); }
function saveState() {
  log.debug("Entering saveState().");
  if (!window.localStorage) return;
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (!els[i].id) continue;
    var v = els[i].type === 'checkbox' ? (els[i].checked ? '1' : '0') : els[i].value;
    localStorage.setItem(STORE_PREFIX + els[i].id, v);
  }
  try {
    localStorage.setItem(ATTRS_KEY, JSON.stringify(attributes));
  } catch (e) {
    // No storage available in this context.
  }
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
  var saved = localStorage.getItem(ATTRS_KEY);
  if (saved) {
    try {
      var parsed = JSON.parse(saved);
      if (Object.prototype.toString.call(parsed) === '[object Array]') attributes = parsed;
    } catch (e) {
      // A stored value from an older build, or hand-edited: start from the
      // built-in attributes rather than failing to load the page.
    }
  }
  log.debug("Leaving restoreState().");
}

// ---------------------------------------------------------------------------
// Timestamps. SAML instants are xs:dateTime in UTC ("Z"), and the spec forbids
// a trailing offset other than Z, so everything is emitted as ...Z with second
// precision.
// ---------------------------------------------------------------------------
function toInstant(d) { return d.toISOString().replace(/\.\d{3}Z$/, 'Z'); }
function num(id, dflt) { var n = parseInt(val(id), 10); return isNaN(n) ? dflt : n; }

// (Re)populate IssueInstant, the Conditions window, AuthnInstant, and the
// SubjectConfirmationData / session expiries from "now". Called on load and by
// the Refresh button, and whenever the validity window is changed.
function refreshTimestamps() {
  log.debug("Entering refreshTimestamps().");
  var now = new Date();
  var skewMs = num('sa_skew_seconds', 60) * 1000;
  var lifeMs = num('sa_validity_minutes', 5) * 60 * 1000;
  setVal('sa_issue_instant', toInstant(now));
  setVal('sa_authn_instant', toInstant(now));
  setVal('sa_not_before', toInstant(new Date(now.getTime() - skewMs)));
  setVal('sa_not_on_or_after', toInstant(new Date(now.getTime() + lifeMs)));
  setVal('sa_confirm_notonorafter', toInstant(new Date(now.getTime() + lifeMs)));
  setVal('sa_session_notonorafter', toInstant(new Date(now.getTime() + (lifeMs * 12))));
  autoBuild();
  log.debug("Leaving refreshTimestamps().");
  return false;
}

function newId() { return xd.genId(); }
function refreshId() {
  setVal('sa_id', newId());
  saveState();
  autoBuild();
  return false;
}

// ---------------------------------------------------------------------------
// Custom attributes: [{ type, prefix, name, value }]
//
//   SAML 2.0 — Name = prefix + name, NameFormat derived (a prefix implies the
//              "uri" name format), value typed with xsi:type.
//   SAML 1.x — AttributeName = name, AttributeNamespace = prefix (required by
//              the 1.x schema, so it falls back to the assertion namespace).
// ---------------------------------------------------------------------------
var attributes = [];
var ATTR_NAMEFORMAT_URI = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
var ATTR_NAMEFORMAT_UNSPEC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';

function addAttribute() {
  log.debug("Entering addAttribute().");
  var name = val('sa_attr_name').trim();
  if (!name) { setStatus('sa_compose_status', 'Enter an attribute name.'); return false; }
  attributes.push({
    type: val('sa_attr_type') || 'string',
    prefix: val('sa_attr_prefix').trim(),
    name: name,
    value: val('sa_attr_value')
  });
  setVal('sa_attr_name', '');
  setVal('sa_attr_value', '');
  renderAttributes();
  saveState();
  autoBuild();
  setStatus('sa_compose_status', 'Attribute added (' + attributes.length + ' total).');
  log.debug("Leaving addAttribute().");
  return false;
}

function removeAttribute(idx) {
  if (idx >= 0 && idx < attributes.length) attributes.splice(idx, 1);
  renderAttributes();
  saveState();
  autoBuild();
  return false;
}

function clearAttributes() {
  attributes = [];
  renderAttributes();
  saveState();
  autoBuild();
  return false;
}

// Render the attribute table. Values come from user input, so every cell is
// escaped before it goes near innerHTML.
function renderAttributes() {
  log.debug("Entering renderAttributes().");
  var body = el('sa_attr_rows');
  if (!body) return;
  if (!attributes.length) {
    body.innerHTML = '<tr><td colspan="5" class="sa-empty">No custom attributes.</td></tr>';
    return;
  }
  var html = '';
  for (var i = 0; i < attributes.length; i++) {
    var a = attributes[i];
    html += '<tr>' +
      '<td>' + esc(a.name) + '</td>' +
      '<td class="sa-wrap">' + esc(a.prefix) + '</td>' +
      '<td>' + esc(a.type) + '</td>' +
      '<td class="sa-wrap">' + esc(a.value) + '</td>' +
      '<td><button type="button" class="saml-copy" onclick="return saml_tools.removeAttribute(' + i + ');">Remove</button></td>' +
      '</tr>';
  }
  body.innerHTML = html;
  log.debug("Leaving renderAttributes().");
}

function attrFullName(a) { return (a.prefix || '') + a.name; }
function attrsUseXsiType() {
  for (var i = 0; i < attributes.length; i++) {
    if (attributes[i].type && attributes[i].type !== 'unspecified') return true;
  }
  return false;
}
function xsiTypeAttr(a) {
  return (a.type && a.type !== 'unspecified') ? ' xsi:type="xs:' + a.type + '"' : '';
}

// ---------------------------------------------------------------------------
// Assertion construction
// ---------------------------------------------------------------------------
function attrOpt(name, value) { return value ? ' ' + name + '="' + esc(value) + '"' : ''; }
function confirmationMethod() {
  return (CM_PREFIX[version()] || CM_PREFIX['2.0']) + (val('sa_confirm_method') || 'bearer');
}

// <saml:Subject> for SAML 2.0 — NameID plus an optional SubjectConfirmation.
function subject20(pad) {
  log.debug("Entering subject20().");
  var lines = [];
  lines.push(pad + '<saml:Subject>');
  lines.push(pad + '  <saml:NameID' + attrOpt('Format', val('sa_nameid_format')) +
    attrOpt('NameQualifier', val('sa_nameid_qualifier')) +
    attrOpt('SPNameQualifier', val('sa_nameid_spqualifier')) + '>' +
    esc(val('sa_nameid_value')) + '</saml:NameID>');
  if (isOn('sa_opt_subjconf')) {
    lines.push(pad + '  <saml:SubjectConfirmation Method="' + esc(confirmationMethod()) + '">');
    lines.push(pad + '    <saml:SubjectConfirmationData' +
      attrOpt('NotOnOrAfter', val('sa_confirm_notonorafter')) +
      attrOpt('Recipient', val('sa_confirm_recipient')) +
      attrOpt('InResponseTo', val('sa_confirm_inresponseto')) +
      attrOpt('Address', val('sa_confirm_address')) + '/>');
    lines.push(pad + '  </saml:SubjectConfirmation>');
  }
  lines.push(pad + '</saml:Subject>');
  log.debug("Leaving subject20().");
  return lines.join('\n') + '\n';
}

// <saml:Subject> for SAML 1.x — NameIdentifier (no SPNameQualifier) plus an
// optional SubjectConfirmation carrying a <ConfirmationMethod> element. In 1.x
// the Subject belongs to each statement, not to the assertion.
function subject1x(pad) {
  log.debug("Entering subject1x().");
  var lines = [];
  lines.push(pad + '<saml:Subject>');
  lines.push(pad + '  <saml:NameIdentifier' + attrOpt('Format', val('sa_nameid_format')) +
    attrOpt('NameQualifier', val('sa_nameid_qualifier')) + '>' +
    esc(val('sa_nameid_value')) + '</saml:NameIdentifier>');
  if (isOn('sa_opt_subjconf')) {
    lines.push(pad + '  <saml:SubjectConfirmation>');
    lines.push(pad + '    <saml:ConfirmationMethod>' + esc(confirmationMethod()) + '</saml:ConfirmationMethod>');
    lines.push(pad + '  </saml:SubjectConfirmation>');
  }
  lines.push(pad + '</saml:Subject>');
  log.debug("Leaving subject1x().");
  return lines.join('\n') + '\n';
}

function attributeElements20(pad) {
  log.debug("Entering attributeElements20().");
  var out = '';
  for (var i = 0; i < attributes.length; i++) {
    var a = attributes[i];
    var fmt = a.prefix ? ATTR_NAMEFORMAT_URI : ATTR_NAMEFORMAT_UNSPEC;
    out += pad + '<saml:Attribute Name="' + esc(attrFullName(a)) + '" NameFormat="' + fmt + '"' +
      attrOpt('FriendlyName', a.prefix ? a.name : '') + '>\n';
    out += pad + '  <saml:AttributeValue' + xsiTypeAttr(a) + '>' + esc(a.value) + '</saml:AttributeValue>\n';
    out += pad + '</saml:Attribute>\n';
  }
  log.debug("Leaving attributeElements20().");
  return out;
}

function attributeElements1x(pad) {
  log.debug("Entering attributeElements1x().");
  var out = '';
  for (var i = 0; i < attributes.length; i++) {
    var a = attributes[i];
    // AttributeNamespace is required in 1.x; fall back to the assertion namespace.
    out += pad + '<saml:Attribute AttributeName="' + esc(a.name) + '" AttributeNamespace="' +
      esc(a.prefix || SAML1_NS) + '">\n';
    out += pad + '  <saml:AttributeValue' + xsiTypeAttr(a) + '>' + esc(a.value) + '</saml:AttributeValue>\n';
    out += pad + '</saml:Attribute>\n';
  }
  log.debug("Leaving attributeElements1x().");
  return out;
}

// SAML 2.0 assertion (saml-core-2.0-os §2.3.3). Child order is fixed by the
// schema: Issuer, [Signature], [Subject], [Conditions], [Advice], statements*.
function buildAssertion20() {
  log.debug("Entering buildAssertion20().");
  var ns = ' xmlns:saml="' + SAML2_NS + '"';
  if (attrsUseXsiType() && isOn('sa_opt_attrs')) ns += ' xmlns:xs="' + XS_NS + '" xmlns:xsi="' + XSI_NS + '"';

  var out = '<saml:Assertion' + ns +
    ' ID="' + esc(val('sa_id')) + '"' +
    ' Version="2.0"' +
    ' IssueInstant="' + esc(val('sa_issue_instant')) + '">\n';
  out += '  <saml:Issuer>' + esc(val('sa_issuer')) + '</saml:Issuer>\n';

  if (isOn('sa_opt_subject')) out += subject20('  ');

  if (isOn('sa_opt_conditions')) {
    out += '  <saml:Conditions' + attrOpt('NotBefore', val('sa_not_before')) +
      attrOpt('NotOnOrAfter', val('sa_not_on_or_after')) + '>\n';
    if (isOn('sa_opt_audience')) {
      out += '    <saml:AudienceRestriction>\n';
      out += '      <saml:Audience>' + esc(val('sa_audience')) + '</saml:Audience>\n';
      out += '    </saml:AudienceRestriction>\n';
    }
    if (isOn('sa_opt_onetimeuse')) out += '    <saml:OneTimeUse/>\n';
    if (isOn('sa_opt_proxy')) {
      out += '    <saml:ProxyRestriction Count="' + esc(String(num('sa_proxy_count', 0))) + '"/>\n';
    }
    out += '  </saml:Conditions>\n';
  }

  if (isOn('sa_opt_advice')) {
    out += '  <saml:Advice>\n';
    out += '    <saml:AssertionIDRef>' + esc(val('sa_advice_ref') || newId()) + '</saml:AssertionIDRef>\n';
    out += '  </saml:Advice>\n';
  }

  if (isOn('sa_opt_authn')) {
    out += '  <saml:AuthnStatement AuthnInstant="' + esc(val('sa_authn_instant')) + '"' +
      attrOpt('SessionIndex', val('sa_session_index')) +
      attrOpt('SessionNotOnOrAfter', val('sa_session_notonorafter')) + '>\n';
    if (isOn('sa_opt_locality')) {
      out += '    <saml:SubjectLocality' + attrOpt('Address', val('sa_locality_address')) +
        attrOpt('DNSName', val('sa_locality_dns')) + '/>\n';
    }
    out += '    <saml:AuthnContext>\n';
    out += '      <saml:AuthnContextClassRef>' + esc(val('sa_authn_context')) + '</saml:AuthnContextClassRef>\n';
    out += '    </saml:AuthnContext>\n';
    out += '  </saml:AuthnStatement>\n';
  }

  if (isOn('sa_opt_attrs') && attributes.length) {
    out += '  <saml:AttributeStatement>\n';
    out += attributeElements20('    ');
    out += '  </saml:AttributeStatement>\n';
  }

  if (isOn('sa_opt_authz')) {
    out += '  <saml:AuthzDecisionStatement Resource="' + esc(val('sa_authz_resource')) +
      '" Decision="' + esc(val('sa_authz_decision') || 'Permit') + '">\n';
    out += '    <saml:Action Namespace="' + esc(val('sa_authz_action_ns') || ACTION_NS_RWEDC) + '">' +
      esc(val('sa_authz_action') || 'Read') + '</saml:Action>\n';
    out += '  </saml:AuthzDecisionStatement>\n';
  }

  out += '</saml:Assertion>';
  log.debug("Leaving buildAssertion20().");
  return out;
}

// SAML 1.0 / 1.1 assertion (saml-core-1.1 §2.3.2). Child order: Conditions,
// Advice, statements+, [Signature] — note the signature is the LAST child here,
// unlike 2.0 where it follows the Issuer. The Subject lives inside each
// statement, and 1.0 has no DoNotCacheCondition (added in 1.1).
function buildAssertion1x() {
  log.debug("Entering buildAssertion1x().");
  var minor = version() === '1.1' ? '1' : '0';
  var ns = ' xmlns:saml="' + SAML1_NS + '"';
  if (attrsUseXsiType() && isOn('sa_opt_attrs')) ns += ' xmlns:xs="' + XS_NS + '" xmlns:xsi="' + XSI_NS + '"';

  var out = '<saml:Assertion' + ns +
    ' MajorVersion="1" MinorVersion="' + minor + '"' +
    ' AssertionID="' + esc(val('sa_id')) + '"' +
    ' Issuer="' + esc(val('sa_issuer')) + '"' +
    ' IssueInstant="' + esc(val('sa_issue_instant')) + '">\n';

  if (isOn('sa_opt_conditions')) {
    out += '  <saml:Conditions' + attrOpt('NotBefore', val('sa_not_before')) +
      attrOpt('NotOnOrAfter', val('sa_not_on_or_after')) + '>\n';
    if (isOn('sa_opt_audience')) {
      out += '    <saml:AudienceRestrictionCondition>\n';
      out += '      <saml:Audience>' + esc(val('sa_audience')) + '</saml:Audience>\n';
      out += '    </saml:AudienceRestrictionCondition>\n';
    }
    // DoNotCacheCondition is the 1.1 counterpart of 2.0's OneTimeUse.
    if (isOn('sa_opt_onetimeuse') && minor === '1') out += '    <saml:DoNotCacheCondition/>\n';
    out += '  </saml:Conditions>\n';
  }

  if (isOn('sa_opt_advice')) {
    out += '  <saml:Advice>\n';
    out += '    <saml:AssertionIDReference>' + esc(val('sa_advice_ref') || newId()) + '</saml:AssertionIDReference>\n';
    out += '  </saml:Advice>\n';
  }

  if (isOn('sa_opt_authn')) {
    out += '  <saml:AuthenticationStatement AuthenticationMethod="' + esc(val('sa_authn_method')) +
      '" AuthenticationInstant="' + esc(val('sa_authn_instant')) + '">\n';
    out += subject1x('    ');
    if (isOn('sa_opt_locality')) {
      out += '    <saml:SubjectLocality' + attrOpt('IPAddress', val('sa_locality_address')) +
        attrOpt('DNSAddress', val('sa_locality_dns')) + '/>\n';
    }
    out += '  </saml:AuthenticationStatement>\n';
  }

  if (isOn('sa_opt_attrs') && attributes.length) {
    out += '  <saml:AttributeStatement>\n';
    out += subject1x('    ');
    out += attributeElements1x('    ');
    out += '  </saml:AttributeStatement>\n';
  }

  if (isOn('sa_opt_authz')) {
    out += '  <saml:AuthorizationDecisionStatement Resource="' + esc(val('sa_authz_resource')) +
      '" Decision="' + esc(val('sa_authz_decision') || 'Permit') + '">\n';
    out += subject1x('    ');
    out += '    <saml:Action Namespace="' + esc(val('sa_authz_action_ns') || ACTION_NS_RWEDC) + '">' +
      esc(val('sa_authz_action') || 'Read') + '</saml:Action>\n';
    out += '  </saml:AuthorizationDecisionStatement>\n';
  }

  out += '</saml:Assertion>';
  log.debug("Leaving buildAssertion1x().");
  return out;
}

function buildAssertion() { return isV2() ? buildAssertion20() : buildAssertion1x(); }

// ---------------------------------------------------------------------------
// The compose → sign → encrypt pipeline.
//
// `baseAssertion` is the unsigned assertion built from the form (pane 1 may show
// something further along). Once Sign Assertion has been clicked, signing stays
// ON: every later edit — in any pane, including a different signature algorithm
// or a new key — rebuilds the assertion and re-signs it, and pane 1's Generated
// Assertion box shows the signed result, so what is displayed is always exactly
// what the tool would hand over. Encryption behaves the same way once Encrypt
// Assertion has been clicked (sign-then-encrypt).
// ---------------------------------------------------------------------------
var baseAssertion = '';
var signActive = false;
var encActive = false;
var lastSigned = '';
var lastPushedPlaintext = '';

// Point pane 3 at the current artifact (the signed assertion if there is one,
// otherwise the plain one) — but never overwrite text the user typed there.
function syncEncryptInput(xml) {
  var current = val('sa_enc_plaintext');
  if (current === '' || current === lastPushedPlaintext) {
    setVal('sa_enc_plaintext', xml);
    lastPushedPlaintext = xml;
  }
}

// Re-apply every step the user has already applied, in order, and show the
// furthest-along signed form in pane 1.
function refreshPipeline() {
  log.debug("Entering refreshPipeline().");
  var displayed = baseAssertion;

  if (signActive) {
    if (!val('sa_private_key')) {
      signActive = false;
      setVal('sa_signed_assertion', '');
      setStatus('sa_sign_status', 'Signing stopped — there is no private key. Generate one and sign again.');
    } else {
      try {
        var signed = xd.signEnveloped(baseAssertion, {
          privateKeyPem: val('sa_private_key'),
          certPem: val('sa_public_key'),
          sigAlg: val('sa_sig_alg'),
          c14nAlg: val('sa_sig_c14n'),
          refUri: signatureRefUri(),
          placement: signaturePlacement()
        });
        setVal('sa_signed_assertion', signed);
        // The verification box follows the newest signature unless the user has
        // pasted something else into it.
        if (val('sa_verify_input') === '' || val('sa_verify_input') === lastSigned) {
          setVal('sa_verify_input', signed);
          setVal('sa_verify_output', '');
        }
        lastSigned = signed;
        displayed = signed;
        setStatus('sa_sign_status', 'Assertion signed (' +
          (isV2() ? 'Signature after <Issuer>' : 'Signature as last child') +
          ', Reference URI="' + signatureRefUri() + '"). Re-signed automatically on every change.');
      } catch (e) {
        signActive = false;
        log.error('refreshPipeline/sign: ' + e.message);
        setStatus('sa_sign_status', 'Signing error: ' + e.message);
      }
    }
  }

  setVal('sa_assertion', displayed);
  syncEncryptInput(displayed);
  if (encActive) runEncrypt();
  log.debug("Leaving refreshPipeline().");
  return displayed;
}

// Regenerate the Assertion field from the current settings. Called on every
// change; guarded so a transient build error can never break the handler.
function autoBuild() {
  try {
    buildAssertionUi();
  } catch (e) {
    log.error('autoBuild: ' + e.message);
  }
  return false;
}

// Re-indent the generated assertion: one element per line, nested by depth.
// The assertion is emitted pretty-printed already, so this mainly normalizes it
// — and it is safe here because pane 1 holds the *unsigned* assertion (the
// signature is computed from whatever this field holds when Sign is clicked).
// It is deliberately not offered for the signed assertion, where reformatting
// would change the digested octets and invalidate the signature.
function formatXmlElement(node, indent) {
  log.debug("Entering formatXmlElement().");
  var attrs = '';
  for (var i = 0; i < node.attributes.length; i++) {
    attrs += ' ' + node.attributes[i].name + '="' + esc(node.attributes[i].value) + '"';
  }
  var kids = [], text = '', c = node.firstChild;
  while (c) {
    if (c.nodeType === 1) kids.push(c);
    else if (c.nodeType === 3 || c.nodeType === 4) text += c.nodeValue;
    c = c.nextSibling;
  }
  var open = indent + '<' + node.nodeName + attrs;
  if (!kids.length) {
    var t = text.trim();
    return t ? (open + '>' + esc(t) + '</' + node.nodeName + '>') : (open + '/>');
  }
  var lines = [open + '>'];
  // Mixed content does not occur in a SAML assertion, but keep any text rather
  // than silently dropping it.
  if (text.trim()) lines.push(indent + '  ' + esc(text.trim()));
  for (var k = 0; k < kids.length; k++) lines.push(formatXmlElement(kids[k], indent + '  '));
  lines.push(indent + '</' + node.nodeName + '>');
  log.debug("Leaving formatXmlElement().");
  return lines.join('\n');
}

function prettyPrintAssertion() {
  log.debug("Entering prettyPrintAssertion().");
  if (!baseAssertion.trim()) { setStatus('sa_compose_status', 'Nothing to format yet.'); return false; }
  var doc = new DOMParser().parseFromString(baseAssertion, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    setStatus('sa_compose_status', 'Cannot pretty print: the assertion is not well-formed XML.');
    return false;
  }
  // Format the *unsigned* assertion and run it back through the pipeline, so a
  // signature that is already applied is recomputed over the re-indented form
  // rather than being invalidated by it.
  baseAssertion = formatXmlElement(doc.documentElement, '');
  refreshPipeline();
  setStatus('sa_compose_status', 'Assertion pretty printed' + (signActive ? ' and re-signed' : '') + '.');
  log.debug("Leaving prettyPrintAssertion().");
  return false;
}

function buildAssertionUi() {
  baseAssertion = buildAssertion();
  var displayed = refreshPipeline();
  saveState();
  setStatus('sa_compose_status', 'SAML ' + version() + ' assertion built (' + displayed.length + ' bytes)' +
    (signActive ? ', signed' : '') + (encActive ? ', encrypted' : '') + '.');
  return false;
}

// ---------------------------------------------------------------------------
// Spec compliance check. Parses the generated assertion and applies the
// structural rules of the selected version's schema/spec.
// ---------------------------------------------------------------------------
function isAbsoluteUri(v) {
try {
  new URL(v);
  return true;
} catch (e) {
  return false;
} }
function isInstant(v) { return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(v || ''); }
function isNCName(v) { return /^[A-Za-z_][A-Za-z0-9._\-]*$/.test(v || ''); }
function firstLocal(root, name) {
  var e = root.getElementsByTagNameNS('*', name);
  return e && e.length ? e[0] : null;
}
function countLocal(root, name) {
  var e = root.getElementsByTagNameNS('*', name);
  return e ? e.length : 0;
}

function checkCompliance() {
  log.debug("Entering checkCompliance().");
  var results = [];
  function pass(c, m) { results.push('PASS  ' + c + ': ' + m); }
  function fail(c, m) { results.push('FAIL  ' + c + ': ' + m); }
  function warn(c, m) { results.push('WARN  ' + c + ': ' + m); }

  var xml = val('sa_assertion');
  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    setVal('sa_compliance_output', 'FAIL  xml: the assertion is not well-formed XML.');
    return false;
  }
  var root = doc.documentElement;
  var v = version();
  pass('xml', 'Well-formed.');

  // --- Common: namespace, identifier, issuer, instant ---
  var wantNs = isV2() ? SAML2_NS : SAML1_NS;
  if (root.namespaceURI === wantNs) pass('namespace', wantNs);
  else fail('namespace', 'Expected ' + wantNs + ', found ' + root.namespaceURI);

  var idAttr = isV2() ? 'ID' : 'AssertionID';
  var id = root.getAttribute(idAttr) || '';
  if (!id) fail(idAttr, 'Required attribute is missing.');
  else if (!isNCName(id)) fail(idAttr, 'Must be an xs:ID (NCName — start with a letter or "_"): "' + id + '"');
  else pass(idAttr, id);

  var instant = root.getAttribute('IssueInstant') || '';
  if (!instant) fail('IssueInstant', 'Required attribute is missing.');
  else if (!isInstant(instant)) fail('IssueInstant', 'Must be an xs:dateTime in UTC ending in "Z": "' + instant + '"');
  else pass('IssueInstant', instant);

  if (isV2()) {
    if (root.getAttribute('Version') === '2.0') pass('Version', '2.0');
    else fail('Version', 'Must be exactly "2.0".');
    var issuerEl = firstLocal(root, 'Issuer');
    var issuerText = issuerEl ? (issuerEl.textContent || '').trim() : '';
    if (!issuerText) fail('Issuer', 'A <saml:Issuer> element with a value is required.');
    else pass('Issuer', issuerText);
  } else {
    var major = root.getAttribute('MajorVersion'), minor = root.getAttribute('MinorVersion');
    var wantMinor = v === '1.1' ? '1' : '0';
    if (major === '1' && minor === wantMinor) pass('Version', 'MajorVersion=1 MinorVersion=' + wantMinor);
    else fail('Version', 'Expected MajorVersion="1" MinorVersion="' + wantMinor + '".');
    var issuerAttr = root.getAttribute('Issuer') || '';
    if (!issuerAttr) fail('Issuer', 'The Issuer attribute is required on a SAML 1.x assertion.');
    else pass('Issuer', issuerAttr);
  }

  // --- Statements / Subject ---
  var stmtCount = countLocal(root, 'AuthnStatement') + countLocal(root, 'AuthenticationStatement') +
    countLocal(root, 'AttributeStatement') + countLocal(root, 'AuthzDecisionStatement') +
    countLocal(root, 'AuthorizationDecisionStatement');
  if (isV2()) {
    var hasSubject = !!firstLocal(root, 'Subject');
    if (!stmtCount && !hasSubject) {
      fail('content', 'An assertion with no statements must carry a <saml:Subject> (saml-core §2.3.3).');
    } else {
      pass('content', stmtCount + ' statement(s)' + (hasSubject ? ' + Subject' : ''));
    }
  } else {
    if (!stmtCount) fail('content', 'A SAML 1.x assertion requires at least one statement.');
    else pass('content', stmtCount + ' statement(s)');
    // Every 1.x statement is a SubjectStatement and needs its own <Subject>.
    var stmtNames = ['AuthenticationStatement', 'AttributeStatement', 'AuthorizationDecisionStatement'];
    var missing = [];
    for (var s = 0; s < stmtNames.length; s++) {
      var list = root.getElementsByTagNameNS('*', stmtNames[s]);
      for (var k = 0; k < list.length; k++) {
        if (!firstLocal(list[k], 'Subject')) missing.push(stmtNames[s]);
      }
    }
    if (missing.length) fail('Subject', 'Missing <saml:Subject> in: ' + missing.join(', '));
    else if (stmtCount) pass('Subject', 'Present in every statement.');
  }

  // --- NameID / NameIdentifier ---
  var nameEl = firstLocal(root, isV2() ? 'NameID' : 'NameIdentifier');
  if (nameEl) {
    var nameVal = (nameEl.textContent || '').trim();
    if (!nameVal) fail('NameID', 'The identifier has no value.');
    else pass('NameID', nameVal);
    var fmt = nameEl.getAttribute('Format') || '';
    if (fmt && !isAbsoluteUri(fmt)) fail('NameID/Format', 'Must be an absolute URI: "' + fmt + '"');
    else if (fmt && !isV2() && V2_ONLY_NAMEID.test(fmt)) {
      warn('NameID/Format', fmt + ' was introduced in SAML 2.0 and is not defined for 1.x.');
    } else if (fmt) pass('NameID/Format', fmt);
  }

  // --- Conditions ---
  var cond = firstLocal(root, 'Conditions');
  if (cond) {
    var nb = cond.getAttribute('NotBefore') || '', noa = cond.getAttribute('NotOnOrAfter') || '';
    if (nb && !isInstant(nb)) fail('Conditions/NotBefore', 'Must be a UTC xs:dateTime: "' + nb + '"');
    if (noa && !isInstant(noa)) fail('Conditions/NotOnOrAfter', 'Must be a UTC xs:dateTime: "' + noa + '"');
    if (nb && noa && isInstant(nb) && isInstant(noa)) {
      if (new Date(nb).getTime() >= new Date(noa).getTime()) {
        fail('Conditions', 'NotBefore must be earlier than NotOnOrAfter.');
      } else {
        pass('Conditions', nb + ' → ' + noa);
      }
    }
    var aud = firstLocal(cond, 'Audience');
    if (aud) {
      var audText = (aud.textContent || '').trim();
      if (!isAbsoluteUri(audText)) fail('Audience', 'Must be an absolute URI: "' + audText + '"');
      else pass('Audience', audText);
    }
    if (!isV2() && countLocal(cond, 'DoNotCacheCondition') && v === '1.0') {
      fail('DoNotCacheCondition', 'Introduced in SAML 1.1 — not valid in a 1.0 assertion.');
    }
    if (!isV2() && countLocal(cond, 'ProxyRestriction')) {
      fail('ProxyRestriction', 'A SAML 2.0-only condition.');
    }
  }

  // --- Statements detail ---
  var authn = firstLocal(root, 'AuthnStatement');
  if (authn) {
    if (!isInstant(authn.getAttribute('AuthnInstant') || '')) fail('AuthnStatement', 'AuthnInstant is required and must be a UTC xs:dateTime.');
    else if (!firstLocal(authn, 'AuthnContext')) fail('AuthnStatement', '<saml:AuthnContext> is required.');
    else pass('AuthnStatement', authn.getAttribute('AuthnInstant'));
  }
  var authn1x = firstLocal(root, 'AuthenticationStatement');
  if (authn1x) {
    var am = authn1x.getAttribute('AuthenticationMethod') || '';
    if (!isAbsoluteUri(am)) fail('AuthenticationStatement', 'AuthenticationMethod must be an absolute URI.');
    else if (!isInstant(authn1x.getAttribute('AuthenticationInstant') || '')) fail('AuthenticationStatement', 'AuthenticationInstant must be a UTC xs:dateTime.');
    else pass('AuthenticationStatement', am);
  }

  var attrEls = root.getElementsByTagNameNS('*', 'Attribute');
  if (attrEls.length) {
    var badAttrs = [];
    for (var i = 0; i < attrEls.length; i++) {
      var a = attrEls[i];
      if (isV2()) {
        if (!a.getAttribute('Name')) badAttrs.push('(missing Name)');
      } else if (!a.getAttribute('AttributeName') || !a.getAttribute('AttributeNamespace')) {
        badAttrs.push(a.getAttribute('AttributeName') || '(missing AttributeName)');
      }
      if (!firstLocal(a, 'AttributeValue')) badAttrs.push((a.getAttribute('Name') || a.getAttribute('AttributeName') || '?') + ' (no AttributeValue)');
    }
    if (badAttrs.length) fail('Attribute', 'Invalid: ' + badAttrs.join(', '));
    else pass('Attribute', attrEls.length + ' attribute(s) well-formed.');
  } else if (isOn('sa_opt_attrs')) {
    warn('AttributeStatement', 'Enabled, but no attributes were added — the statement is omitted (it requires at least one <Attribute>).');
  }

  var authz = firstLocal(root, 'AuthzDecisionStatement') || firstLocal(root, 'AuthorizationDecisionStatement');
  if (authz) {
    var res = authz.getAttribute('Resource') || '';
    var dec = authz.getAttribute('Decision') || '';
    if (!res) fail('AuthzDecisionStatement', 'Resource is required (an absolute URI, or "" for all resources in 2.0).');
    else if (!isAbsoluteUri(res)) fail('AuthzDecisionStatement', 'Resource must be an absolute URI: "' + res + '"');
    else if (['Permit', 'Deny', 'Indeterminate'].indexOf(dec) < 0) fail('AuthzDecisionStatement', 'Decision must be Permit, Deny, or Indeterminate.');
    else if (!firstLocal(authz, 'Action')) fail('AuthzDecisionStatement', 'At least one <saml:Action> is required.');
    else pass('AuthzDecisionStatement', dec + ' on ' + res);
  }

  // --- Signature placement (only meaningful once signed) ---
  var sig = firstLocal(root, 'Signature');
  if (sig) {
    var kids = root.childNodes, elems = [];
    for (var c = 0; c < kids.length; c++) { if (kids[c].nodeType === 1) elems.push(kids[c].localName); }
    var pos = elems.indexOf('Signature');
    if (isV2()) {
      if (pos === 1 && elems[0] === 'Issuer') pass('Signature', 'Correctly placed immediately after <saml:Issuer>.');
      else fail('Signature', 'In SAML 2.0 the <ds:Signature> must directly follow <saml:Issuer>.');
    } else if (pos === elems.length - 1) {
      pass('Signature', 'Correctly placed as the last child of the assertion.');
    } else {
      fail('Signature', 'In SAML 1.x the <ds:Signature> must be the last child of <saml:Assertion>.');
    }
  }

  var failures = results.filter(function (r) { return r.indexOf('FAIL') === 0; }).length;
  var warnings = results.filter(function (r) { return r.indexOf('WARN') === 0; }).length;
  results.unshift('SAML ' + v + ' compliance: ' + (failures ? failures + ' failure(s)' : 'no failures') +
    (warnings ? ', ' + warnings + ' warning(s)' : '') + '.');
  setVal('sa_compliance_output', results.join('\n'));
  log.debug("Leaving checkCompliance().");
  return false;
}

// ---------------------------------------------------------------------------
// Pane 2 — signing key pair + enveloped XML Signature
// ---------------------------------------------------------------------------
function generateKeys() {
  log.debug("Entering generateKeys().");
  var bits = num('sa_key_bits', 2048);
  setStatus('sa_sign_status', 'Generating ' + bits + '-bit RSA key pair…');
  // Defer so the status paints before the (synchronous, slow) keygen runs.
  setTimeout(function () {
    try {
      var kp = xd.generateKeyPair(bits, val('sa_issuer') || 'saml-assertion-issuer');
      setVal('sa_private_key', kp.privateKeyPem);
      setVal('sa_public_key', kp.certPem);
      setStatus('sa_sign_status', 'Key pair generated.');
      saveState();
    } catch (e) {
      log.error('generateKeys: ' + e.message);
      setStatus('sa_sign_status', 'Key generation error: ' + e.message);
    }
  }, 20);
  log.debug("Leaving generateKeys().");
  return false;
}

function generateEncryptionKeys() {
  log.debug("Entering generateEncryptionKeys().");
  var bits = num('sa_enc_key_bits', 2048);
  setStatus('sa_enc_status', 'Generating ' + bits + '-bit RSA key pair…');
  setTimeout(function () {
    try {
      var kp = xd.generateKeyPair(bits, 'saml-assertion-recipient');
      setVal('sa_enc_private_key', kp.privateKeyPem);
      setVal('sa_enc_cert', kp.certPem);
      setStatus('sa_enc_status', 'Recipient key pair generated.');
      saveState();
    } catch (e) {
      log.error('generateEncryptionKeys: ' + e.message);
      setStatus('sa_enc_status', 'Key generation error: ' + e.message);
    }
  }, 20);
  log.debug("Leaving generateEncryptionKeys().");
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
  if (!val('sa_private_key')) { setStatus('sa_sign_status', 'Generate a key pair first.'); return false; }
  triggerDownload('assertion-signing-key.pem', val('sa_private_key'), 'application/x-pem-file');
  triggerDownload('assertion-signing-cert.pem', val('sa_public_key'), 'application/x-pem-file');
  return false;
}

function downloadEncryptionKeys() {
  if (!val('sa_enc_private_key')) { setStatus('sa_enc_status', 'Generate a recipient key pair first.'); return false; }
  triggerDownload('assertion-recipient-key.pem', val('sa_enc_private_key'), 'application/x-pem-file');
  triggerDownload('assertion-recipient-cert.pem', val('sa_enc_cert'), 'application/x-pem-file');
  return false;
}

function downloadAssertion() {
  var xml = val('sa_encrypted') || val('sa_signed_assertion') || val('sa_assertion');
  if (!xml) { setStatus('sa_compose_status', 'Nothing to download yet.'); return false; }
  triggerDownload('assertion.xml', xml, 'application/samlassertion+xml');
  return false;
}

// Where the <ds:Signature> goes, and what the Reference points at. SAML 1.0's
// AssertionID is not an xs:ID, so the whole-document reference (URI="") is the
// interoperable form there; 1.1 made it an xs:ID and 2.0 uses ID.
function signaturePlacement() { return isV2() ? 'after-issuer' : 'last'; }
function signatureRefUri() {
  if (version() === '1.0') return '';
  return '#' + val('sa_id');
}

// Turn signing on. From here the signature is recomputed on every change until
// Reset (or until the private key goes away), and pane 1 shows the signed form.
function signAssertion() {
  log.debug("Entering signAssertion().");
  if (!baseAssertion) { setStatus('sa_sign_status', 'Compose an assertion first.'); return false; }
  if (!val('sa_private_key')) {
    setStatus('sa_sign_status', 'No signing key — click Generate Keys (or paste a PKCS#8 private key).');
    return false;
  }
  signActive = true;
  // The freshly signed assertion becomes the verification input as well.
  setVal('sa_verify_input', '');
  refreshPipeline();
  saveState();
  log.debug("Leaving signAssertion().");
  return false;
}

function verifySignature() {
  log.debug("Entering verifySignature().");
  var xml = val('sa_verify_input') || val('sa_signed_assertion');
  if (!xml) { setVal('sa_verify_output', 'Nothing to verify — sign an assertion or paste one above.'); return false; }
  try {
    var r = xd.verifyXmlSignature(xml, { certPem: val('sa_verify_cert') || undefined });
    if (r.error) { setVal('sa_verify_output', 'INVALID: ' + r.error); return false; }
    var lines = [];
    lines.push(r.valid ? 'VALID — signature and all reference digests check out.' : 'INVALID');
    lines.push('SignatureValue over SignedInfo: ' + (r.signatureValid ? 'valid' : 'INVALID'));
    lines.push('Reference digests: ' + (r.referencesValid ? 'valid' : 'INVALID'));
    (r.references || []).forEach(function (ref) {
      lines.push('  URI="' + ref.uri + '" → ' + (ref.ok ? 'ok' : 'MISMATCH' +
        (ref.reason ? ' (' + ref.reason + ')' : ' computed=' + ref.computed + ' declared=' + ref.declared)));
    });
    lines.push('SignatureMethod: ' + r.signatureMethod);
    lines.push('Canonicalization: ' + r.canonicalization);
    if (r.signerSubject) lines.push('Signer: CN=' + r.signerSubject);
    setVal('sa_verify_output', lines.join('\n'));
  } catch (e) {
    log.error('verifySignature: ' + e.message);
    setVal('sa_verify_output', 'Verification error: ' + e.message);
  }
  log.debug("Leaving verifySignature().");
  return false;
}

// ---------------------------------------------------------------------------
// Pane 3 — XML Encryption
// ---------------------------------------------------------------------------
// Turn encryption on. Like signing, it then tracks every change: the assertion
// is rebuilt, re-signed if signing is on, and re-encrypted.
function encryptAssertion() {
  encActive = true;
  runEncrypt();
  saveState();
  return false;
}

function runEncrypt() {
  log.debug("Entering runEncrypt().");
  var xml = val('sa_enc_plaintext') || val('sa_signed_assertion') || val('sa_assertion');
  if (!xml) { setStatus('sa_enc_status', 'Nothing to encrypt.'); return false; }
  try {
    var encryptedData = xd.encryptXml(xml, {
      certPem: val('sa_enc_cert'),
      dataAlg: val('sa_enc_data_alg'),
      keyAlg: val('sa_enc_key_alg'),
      type: val('sa_enc_type'),
      c14nMode: val('sa_enc_c14n'),
      digest: val('sa_enc_digest'),
      mgf: val('sa_enc_mgf')
    });
    // SAML 2.0 carries an encrypted assertion in <saml:EncryptedAssertion>.
    // SAML 1.x has no such element, so the bare <xenc:EncryptedData> is emitted.
    var out = (isV2() && isOn('sa_enc_wrap'))
      ? '<saml:EncryptedAssertion xmlns:saml="' + SAML2_NS + '">' + encryptedData + '</saml:EncryptedAssertion>'
      : encryptedData;
    // The decrypt box follows the newest ciphertext unless the user pasted
    // something else into it.
    if (val('sa_dec_input') === '' || val('sa_dec_input') === val('sa_encrypted')) {
      setVal('sa_dec_input', out);
      setVal('sa_dec_output', '');
    }
    setVal('sa_encrypted', out);
    setStatus('sa_enc_status', 'Assertion encrypted' +
      (val('sa_signed_assertion') && xml === val('sa_signed_assertion') ? ' (sign-then-encrypt)' : '') +
      '. Re-encrypted automatically on every change.');
  } catch (e) {
    encActive = false;
    log.error('runEncrypt: ' + e.message);
    setStatus('sa_enc_status', 'Encryption error: ' + e.message);
  }
  log.debug("Leaving runEncrypt().");
  return false;
}

function decryptAssertion() {
  log.debug("Entering decryptAssertion().");
  var xml = val('sa_dec_input') || val('sa_encrypted');
  if (!xml) { setVal('sa_dec_output', 'Nothing to decrypt.'); return false; }
  var priv = val('sa_enc_private_key');
  if (!priv) { setVal('sa_dec_output', 'No recipient private key — generate a key pair or paste the PKCS#8 key that matches the encryption certificate.'); return false; }
  try {
    setVal('sa_dec_output', xd.decryptXml(xml, { privateKeyPem: priv }));
    setStatus('sa_enc_status', 'Decrypted.');
  } catch (e) {
    log.error('decryptAssertion: ' + e.message);
    setVal('sa_dec_output', 'Decryption error: ' + e.message);
  }
  log.debug("Leaving decryptAssertion().");
  return false;
}

// ---------------------------------------------------------------------------
// UI plumbing (mirrors saml_request.js)
// ---------------------------------------------------------------------------
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

function togglePane(bodyId) {
  var b = el(bodyId);
  if (b) b.style.display = (b.style.display === 'none') ? 'block' : 'none';
  return false;
}

function viewCertificate(fieldId) {
  log.debug("Entering viewCertificate().");
  var pem = val(fieldId);
  if (!pem) { setStatus('sa_sign_status', 'No certificate to view yet — generate a key pair first.'); return false; }
  try {
    if (window.localStorage) localStorage.setItem('saml_cert_view', pem);
  } catch (e) {
    // No storage available in this context.
  }
  window.open('/saml_cert.html?from=saml_tools.html', '_blank');
  log.debug("Leaving viewCertificate().");
  return false;
}

// Hide a <select> option that the selected version does not define, and fall
// back to a supported value if it was the current selection.
function setOptionAvailable(selectId, optValue, available, fallback) {
  var sel = el(selectId);
  if (!sel) return;
  for (var i = 0; i < sel.options.length; i++) {
    if (sel.options[i].value !== optValue) continue;
    sel.options[i].hidden = !available;
    sel.options[i].disabled = !available;
    if (!available && sel.value === optValue && fallback) sel.value = fallback;
  }
}

// Single source of truth for what is on screen. Two rules combine:
//   * version — controls for elements the selected SAML version does not define
//     are hidden (in every pane, down to individual <select> options);
//   * dependency — an unchecked box collapses the fields it governs, including
//     the conditions nested inside <Conditions> and the fields nested inside the
//     authentication statement.
// Called on load, on every version change, and on every checkbox change.
function applyVisibility() {
  log.debug("Entering applyVisibility().");
  var v = version();
  var v2 = isV2();

  // --- Pane 1: Subject -------------------------------------------------------
  // SAML 1.x has no assertion-level Subject to opt out of (it lives in each
  // statement), so the checkbox is hidden and the NameID fields always show.
  show('sa_opt_subject_row', v2);
  var subjectOn = !v2 || isOn('sa_opt_subject');
  show('sa_subject_group', subjectOn);
  show('sa_row_spqualifier', v2);                       // SPNameQualifier: 2.0 only
  show('sa_subjconf_group', subjectOn && isOn('sa_opt_subjconf'));
  show('sa_row_confirm_data', v2);                      // SubjectConfirmationData: 2.0 only
  setOptionAvailable('sa_confirm_method', 'artifact', !v2, 'bearer');
  // The 2.0 name-identifier formats are not defined for a 1.x assertion.
  ['persistent', 'transient', 'entity', 'kerberos'].forEach(function (f) {
    setOptionAvailable('sa_nameid_format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:' + f, v2,
      'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
  });

  // --- Pane 1: Conditions ----------------------------------------------------
  var condOn = isOn('sa_opt_conditions');
  show('sa_row_conditions_times', condOn);              // NotBefore / NotOnOrAfter
  show('sa_conditions_group', condOn);
  show('sa_row_audience', isOn('sa_opt_audience'));
  show('sa_row_onetimeuse', v !== '1.0');               // DoNotCacheCondition arrived in 1.1
  show('sa_row_proxy', v2);                             // ProxyRestriction: 2.0 only
  show('sa_row_proxy_count', isOn('sa_opt_proxy'));

  // --- Pane 1: Advice / statements ------------------------------------------
  show('sa_row_advice_ref', isOn('sa_opt_advice'));
  show('sa_authn_group', isOn('sa_opt_authn'));
  show('sa_row_authn_context', v2);                     // AuthnContextClassRef: 2.0
  show('sa_row_authn_method', !v2);                     // AuthenticationMethod: 1.x
  show('sa_row_session', v2);                           // SessionIndex / SessionNotOnOrAfter: 2.0
  show('sa_row_locality_fields', isOn('sa_opt_locality'));
  show('sa_authz_group', isOn('sa_opt_authz'));
  show('sa_attr_group', isOn('sa_opt_attrs'));

  // --- Pane 3: encryption ----------------------------------------------------
  show('sa_row_enc_wrap', v2);                          // EncryptedAssertion: 2.0 only
  // RSA-1_5 uses neither a digest nor an MGF; rsa-oaep-mgf1p fixes MGF1 to SHA-1.
  var keyAlg = val('sa_enc_key_alg');
  show('sa_row_enc_digest', keyAlg.indexOf('rsa-1_5') < 0);
  show('sa_row_enc_mgf', keyAlg.indexOf('xmlenc11#rsa-oaep') >= 0);

  // --- Labels / notes that differ by version ---------------------------------
  var otu = el('sa_label_onetimeuse');
  if (otu) otu.textContent = v2 ? 'OneTimeUse condition' : 'DoNotCacheCondition (SAML 1.1)';
  var note = el('sa_version_note');
  if (note) {
    note.textContent = v2
      ? 'SAML 2.0: the Subject sits at the assertion level, conditions use <AudienceRestriction> / <OneTimeUse> / <ProxyRestriction>, and attributes carry a NameFormat.'
      : (v === '1.1'
        ? 'SAML 1.1: the Subject belongs to each statement, conditions use <AudienceRestrictionCondition> / <DoNotCacheCondition>, and attributes use AttributeName + AttributeNamespace.'
        : 'SAML 1.0: the Subject belongs to each statement, conditions use <AudienceRestrictionCondition> (there is no DoNotCacheCondition), and attributes use AttributeName + AttributeNamespace.');
  }
  var placement = el('sa_sign_placement_note');
  if (placement) {
    placement.textContent = v2
      ? 'SAML 2.0: the <ds:Signature> is placed immediately after <saml:Issuer>, and the Reference points at the assertion ID.'
      : (v === '1.1'
        ? 'SAML 1.1: the <ds:Signature> is the assertion’s last child, and the Reference points at AssertionID (an xs:ID as of 1.1).'
        : 'SAML 1.0: the <ds:Signature> is the assertion’s last child, and the Reference uses URI="" (the whole document) because 1.0’s AssertionID is not an xs:ID.');
  }
  log.debug("Leaving applyVisibility().");
}

// Show only the controls that exist in the selected version, then rebuild.
function onVersionChange() {
  applyVisibility();
  autoBuild();
  return false;
}

function setReturnLink() {
  var link = el('return_link');
  if (link) link.setAttribute('href', '/saml_request.html');
}

// Values that are computed rather than declared in the markup: the Issuer (and
// the other endpoint-shaped fields) follow wherever this debugger is deployed.
// Applied on load and by Reset, and only to fields the user has left empty.
function seedDefaults() {
  log.debug("Entering seedDefaults().");
  var origin = (window.location && window.location.origin) || appconfig.uiUrl || '';
  if (!val('sa_issuer')) setVal('sa_issuer', origin ? origin.replace(/\/+$/, '') + '/issuer' : '');
  if (!val('sa_audience')) setVal('sa_audience', appconfig.spEntityId || (origin + '/saml/sp'));
  if (!val('sa_confirm_recipient')) setVal('sa_confirm_recipient', appconfig.acsUrl || (origin + '/saml_response.html'));
  if (!val('sa_authz_resource')) setVal('sa_authz_resource', origin + '/protected');
  if (!val('sa_nameid_value')) setVal('sa_nameid_value', 'testuser@example.com');
  // The encryption pane defaults to the signing certificate so an encrypt →
  // decrypt round-trip works out of the box once keys are generated.
  if (!val('sa_enc_cert') && val('sa_public_key')) {
    setVal('sa_enc_cert', val('sa_public_key'));
    setVal('sa_enc_private_key', val('sa_private_key'));
  }
  log.debug("Leaving seedDefaults().");
}

// Every control in all three panes, excluding the buttons.
function paneFields() {
  return document.querySelectorAll('.saml-pane input, .saml-pane select, .saml-pane textarea');
}

// Restore every field in all three panes to the value the markup declares, drop
// the custom attributes and the persisted state, and rebuild. This also clears
// the generated key pairs and any signed/encrypted output — they are throwaway
// test material, and the defaults for those fields are empty.
function resetToDefaults() {
  log.debug("Entering resetToDefaults().");
  if (window.localStorage) {
    var stored = persistedEls();
    for (var s = 0; s < stored.length; s++) {
      if (stored[s].id) localStorage.removeItem(STORE_PREFIX + stored[s].id);
    }
    localStorage.removeItem(ATTRS_KEY);
  }

  var fields = paneFields();
  for (var i = 0; i < fields.length; i++) {
    var e = fields[i];
    if (e.type === 'button' || e.type === 'submit') continue;
    if (e.type === 'checkbox') { e.checked = e.defaultChecked; continue; }
    if (e.tagName === 'SELECT') {
      var pick = e.options.length ? e.options[0] : null;
      for (var o = 0; o < e.options.length; o++) {
        if (e.options[o].defaultSelected) { pick = e.options[o]; break; }
      }
      if (pick) e.value = pick.value;
      continue;
    }
    e.value = e.defaultValue;
  }

  // Back to a plain, unsigned, unencrypted assertion.
  attributes = [];
  baseAssertion = '';
  signActive = false;
  encActive = false;
  lastSigned = '';
  lastPushedPlaintext = '';
  setVal('sa_id', newId());
  seedDefaults();
  renderAttributes();
  applyVisibility();
  refreshTimestamps();   // rebuilds the assertion
  setStatus('sa_compose_status', 'All three panes reset to their default values.');
  saveState();
  log.debug("Leaving resetToDefaults().");
  return false;
}

// Any edit anywhere re-persists the state, re-applies the visibility rules, and
// regenerates the assertion. Bound to 'input' as well as 'change' so the
// Generated Assertion box tracks typing rather than waiting for a blur.
function onFieldChanged() {
  saveState();
  applyVisibility();
  autoBuild();
}

window.onload = function () {
  log.debug('Entering onload().');
  restoreState();
  setReturnLink();
  seedDefaults();

  setVal('sa_id', newId());
  refreshTimestamps();
  renderAttributes();
  onVersionChange();

  var fields = paneFields();
  for (var i = 0; i < fields.length; i++) {
    var e = fields[i];
    // Read-only boxes are outputs; the buttons have their own handlers.
    if (e.type === 'button' || e.type === 'submit' || e.readOnly) continue;
    e.addEventListener('input', onFieldChanged);
    e.addEventListener('change', onFieldChanged);
  }

  autoBuild();
  log.debug("Leaving onload().");
};

module.exports = {
  onVersionChange,
  prettyPrintAssertion,
  refreshTimestamps,
  refreshId,
  addAttribute,
  removeAttribute,
  clearAttributes,
  resetToDefaults,
  checkCompliance,
  generateKeys,
  downloadKeys,
  signAssertion,
  verifySignature,
  generateEncryptionKeys,
  downloadEncryptionKeys,
  encryptAssertion,
  decryptAssertion,
  downloadAssertion,
  viewCertificate,
  copyField,
  togglePane
};
