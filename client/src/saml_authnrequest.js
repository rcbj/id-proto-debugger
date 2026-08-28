// File: saml_authnrequest.js
//
// The SAML Request Decoder: take an AuthnRequest off the wire and read it.
//
// WHAT THIS PAGE IS FOR. saml_request.html BUILDS a request and sends it; this
// page reads one somebody else built. That is the case you are in when a
// federation is refusing a sign-in — you have a URL out of a browser's network
// tab, or a form body out of a proxy log, and the question is what is actually
// in it. Nothing here talks to an identity provider and nothing here needs the
// api: it is a decoder, so it works on a static deployment and over plain HTTP.
//
// THE THREE BINDINGS DO NOT LOOK ALIKE, AND THE SIGNATURE IS THE REASON THAT
// MATTERS. saml_message.js works out which one a blob arrived on; what follows
// from that is where the signature lives, and the two places have nothing in
// common:
//
//   HTTP-POST      an enveloped <ds:Signature> INSIDE the document, with a
//                  KeyInfo, so the message carries everything needed to check
//                  it — xmldsig.js's verifyXmlSignature() does the whole job.
//   HTTP-Redirect  a DETACHED signature over the query string
//                  (saml-bindings-2.0-os section 3.4.4.1), which has nowhere
//                  to put a KeyInfo. So the signer's certificate has to be
//                  supplied, and the octets have to be rebuilt in the order
//                  they were SENT — which is why this page never re-encodes
//                  the parameters it decoded. It hands
//                  saml_message.redirectSignedOctets() the ordered, still
//                  percent-encoded pairs. Re-encoding them would produce a
//                  clean "INVALID" on a signature that is perfectly good, and
//                  no message anywhere would say why.
//   HTTP-Artifact  there is no message here at all. The artifact is 44 bytes
//                  REFERENCING a message the issuer holds and hands over the
//                  SOAP back-channel. What can be said is what the bytes say,
//                  and that turns out to be worth saying: a SourceID that does
//                  not match the identity provider you think you are talking
//                  to is a complete diagnosis.
//
// NO CRYPTOGRAPHY IS IMPLEMENTED HERE. Signature verification and decryption
// are common/xmldsig.js — the same module the SAML, WS-Trust and
// WS-Federation pages sign with and api/server.js signs the redirect binding
// with. Reading the wire format is client/src/saml_message.js, shared with
// saml_response.js. This file is the DOM between them.
//
// NOTHING PASTED HERE IS STORED. Every other page in this family keeps its key
// pair in localStorage behind the opt-out the repo-root CLAUDE.md describes,
// because those pages GENERATE a pair and need it again on the next screen.
// This one generates nothing and has no next screen: the private key is
// somebody else's, pasted once to read one message. So there is no checkbox —
// the key is read out of the field when Decrypt is clicked and never written
// anywhere. The prefill runs the other way (out of the SAML Test Tools page's
// stored pair, when it has one), which reads storage and does not add to it.
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var xd = require("./xmldsig");
var sm = require("./saml_message");
var log = bunyan.createLogger({ name: 'saml_authnrequest',
    level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// The last DECODE's results, held so that the signature and decryption panes
// operate on the same message the tabs are showing.
//
// `originalXml` is the message AS DECODED, never the pretty-printed textarea
// value: formatXml() adds whitespace between elements, and whitespace inside a
// signed subtree changes its digest. Verifying what is on screen instead of
// what arrived is the classic way to make a good signature report INVALID.
var originalXml = '';
// The ordered, still-percent-encoded query pairs of a Redirect message, and
// the SigAlg/Signature it carried. Kept as the classify() result rather than
// re-derived, for the reason in the header.
var lastClassified = null;
// The serialized <xenc:EncryptedData> (or its enclosing element, when the
// wrapped key is a sibling) currently on offer to the Decryption pane.
var lastEncryptedXml = '';
// The signer certificate this page last showed, handed to saml_cert.html.
var lastSignerCertB64 = '';

// ---------------------------------------------------------------------------
// Small DOM helpers.
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

function setStatus(msg) {
  log.debug("Entering setStatus().");
  setVal('sar_status', msg);
  log.debug("Leaving setStatus().");
}

function esc(s) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function show(id, visible) {
  log.debug("Entering show().");
  var e = el(id);
  if (!e) {
    log.debug("Leaving show(). No element.");
    return;
  }
  // Both halves are needed and the class is the one that bites: the markup
  // hides these blocks with saml-hidden, so setting only the inline style
  // leaves the class winning and the block invisible. (The same trap
  // client/CLAUDE.md records against pki.js's show().)
  if (visible) {
    e.classList.remove('saml-hidden');
    e.style.display = 'block';
  } else {
    e.classList.add('saml-hidden');
    e.style.display = 'none';
  }
  log.debug("Leaving show().");
}

function isOn(id) {
  log.debug("Entering isOn().");
  var e = el(id);
  log.debug("Leaving isOn().");
  return !!(e && e.checked);
}

function togglePane(bodyId) {
  log.debug("Entering togglePane().");
  var body = el(bodyId);
  if (body) {
    body.style.display = (body.style.display === 'none') ? 'block' : 'none';
  }
  log.debug("Leaving togglePane().");
  return false;
}

function showTab(evt, tabId) {
  log.debug("Entering showTab().");
  var target = el(tabId);
  var scope = (target && target.closest && target.closest('.saml-pane')) ||
      document;
  var contents = scope.getElementsByClassName('saml-tabcontent');
  for (var i = 0; i < contents.length; i++) {
    contents[i].style.display = 'none';
  }
  var links = scope.getElementsByClassName('tablinks');
  for (var k = 0; k < links.length; k++) {
    links[k].className = links[k].className.replace(' active', '');
  }
  if (target) target.style.display = 'block';
  if (evt && evt.currentTarget) evt.currentTarget.className += ' active';
  log.debug("Leaving showTab().");
  return false;
}

// Move to a tab from code (a decode that found ciphertext should land on the
// Encrypted tab, not leave it for the user to find). The button has to be made
// active too or the highlight and the content disagree.
function selectTab(tabId) {
  log.debug("Entering selectTab().");
  var btn = el(tabId + '_btn');
  showTab(null, tabId);
  if (btn) btn.className += ' active';
  log.debug("Leaving selectTab().");
}

function copyField(id) {
  log.debug("Entering copyField().");
  var e = el(id);
  if (!e) {
    log.debug("Leaving copyField(). No element.");
    return false;
  }
  var text = e.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) {
      log.error('copyField: ' + err);
    });
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

function kv(k, v) {
  log.debug("Entering kv().");
  log.debug("Leaving kv().");
  return '<tr><td class="saml-key">' + esc(k) + '</td><td>' + v + '</td></tr>';
}

// A value that may be long and unbreakable (a base64 artifact field, a URI).
// word-break so it wraps inside its cell rather than widening the table past
// the pane — the fieldset min-content trap the SCIM and SD-JWT pages both hit.
function wrapped(v) {
  log.debug("Entering wrapped().");
  log.debug("Leaving wrapped().");
  return '<span style="word-break:break-all;">' + esc(v) + '</span>';
}

// ---------------------------------------------------------------------------
// The optional panes.
// ---------------------------------------------------------------------------
function toggleVerify() {
  log.debug("Entering toggleVerify().");
  show('sar_verify_body', isOn('sar_verify_enabled'));
  log.debug("Leaving toggleVerify().");
  return true;
}

function toggleDecrypt() {
  log.debug("Entering toggleDecrypt().");
  var on = isOn('sar_decrypt_enabled');
  show('sar_decrypt_body', on);
  if (on) prefillDecryptionKey();
  log.debug("Leaving toggleDecrypt().");
  return true;
}

// Fill the decryption key pair from what the SAML Test Tools page kept, if it
// kept anything. That page's key-pair opt-out means there may be nothing to
// read, which is not an error — so the note says which of the two happened
// rather than leaving an empty field to be read as a broken prefill.
function prefillDecryptionKey() {
  log.debug("Entering prefillDecryptionKey().");
  var note = el('sar_dec_key_note');
  var priv = '', cert = '';
  try {
    if (window.localStorage) {
      priv = localStorage.getItem('samltools_saml_sp_private_key') || '';
      cert = localStorage.getItem('samltools_saml_sp_public_key') || '';
    }
  } catch (e) {
    // No storage at all (a private window, or storage blocked). The fields are
    // simply left for the user to paste into, which is the ordinary case here
    // anyway — this page usually reads somebody else's message.
    log.debug("prefillDecryptionKey(): storage unreadable: " + e.message);
  }
  if (priv && !val('sar_dec_key')) setVal('sar_dec_key', priv);
  if (cert && !val('sar_dec_cert')) setVal('sar_dec_cert', cert);
  if (note && !val('sar_dec_key')) {
    note.textContent = 'Paste the recipient\'s private key (PKCS#8 PEM) to ' +
      'decrypt. Nothing was prefilled — either no key pair has been ' +
      'generated on the SAML Test Tools page, or "Save this key pair in ' +
      'browser localStorage" is turned off there. The certificate is ' +
      'optional and only says whether this is the key the sender wrapped ' +
      'to. Nothing pasted here is stored.';
  }
  log.debug("Leaving prefillDecryptionKey().");
}

function loadSpKeyPair() {
  log.debug("Entering loadSpKeyPair().");
  setVal('sar_dec_key', '');
  setVal('sar_dec_cert', '');
  prefillDecryptionKey();
  setVal('sar_dec_status', val('sar_dec_key')
    ? 'Loaded the SP key pair kept by the SAML Test Tools page.'
    : 'No SP key pair is stored in this browser.');
  log.debug("Leaving loadSpKeyPair().");
  return false;
}

// ---------------------------------------------------------------------------
// Decoding.
// ---------------------------------------------------------------------------

// What the Binding selector says, honoured over auto-detection. It is here for
// the blob auto-detection cannot settle: a bare base64 parameter is a POST
// message and a Redirect one that was never signed, and the two are told apart
// only by whether the bytes inflate. Detection does try that — but a user who
// KNOWS which it is should be able to say so and get a straight answer rather
// than a guess.
function forcedBinding() {
  log.debug("Entering forcedBinding().");
  var b = val('sar_binding');
  log.debug("Leaving forcedBinding().");
  return (b && b !== 'auto') ? b : '';
}

// The binding parameters table — what travelled beside the message.
function renderParams(c, deflated) {
  log.debug("Entering renderParams().");
  var container = el('sar_params');
  if (!container) {
    log.debug("Leaving renderParams(). No container.");
    return;
  }
  var html = '<table class="saml-table">';
  html += kv('Binding', esc(bindingLabel(c.binding)));
  if (c.endpoint) html += kv('Endpoint', wrapped(c.endpoint));
  if (c.direction) {
    html += kv('Parameter', c.direction === 'request' ? 'SAMLRequest' :
               'SAMLResponse');
  }
  if (deflated !== null && deflated !== undefined) {
    // The one observation that separates the two non-artifact bindings, and it
    // is a FACT about the bytes rather than a reading of the parameters — so
    // it is worth its own row even when it agrees with the binding above.
    html += kv('DEFLATE-compressed', deflated
      ? 'yes — the Redirect binding compresses; POST does not'
      : 'no — the POST binding does not compress; Redirect does');
  }
  if (c.relayState) html += kv('RelayState', wrapped(c.relayState));
  if (c.target) html += kv('TARGET (SAML 1.1)', wrapped(c.target));
  if (c.sigAlg) html += kv('SigAlg', wrapped(c.sigAlg));
  if (c.signature) {
    html += kv('Signature (query-string)', wrapped(c.signature.length > 64
      ? c.signature.substring(0, 64) + '…' : c.signature));
  }
  if (c.artifact) html += kv('SAMLart', wrapped(c.artifact));
  html += '</table>';
  if (c.note) html += '<p class="saml-note">' + esc(c.note) + '</p>';
  container.innerHTML = html;
  log.debug("Leaving renderParams().");
}

function bindingLabel(binding) {
  log.debug("Entering bindingLabel().");
  var labels = {
    redirect: 'HTTP-Redirect',
    post: 'HTTP-POST',
    artifact: 'HTTP-Artifact',
    none: 'none — no binding parameters found'
  };
  log.debug("Leaving bindingLabel().");
  return labels[binding] || binding;
}

// The artifact tab and table. An artifact carries no message, so the XML tab
// stays empty and saying so plainly is the whole of what a decoder can do.
function renderArtifact(c) {
  log.debug("Entering renderArtifact().");
  var art = sm.parseArtifact(c.artifact);
  var container = el('sar_details');
  var html = '<table class="saml-table">';
  if (art.error) {
    html += kv('Artifact', '<span style="color:#b00;">' + esc(art.error) +
               '</span>');
  } else {
    html += kv('Artifact Type', esc(art.type));
    html += kv('TypeCode', '0x' + ('000' + art.typeCode.toString(16))
               .slice(-4));
    if (art.endpointIndex !== undefined) {
      html += kv('EndpointIndex', String(art.endpointIndex));
    }
    if (art.sourceId) {
      html += kv('SourceID', wrapped(art.sourceId) +
        '<div class="saml-note">SHA-1 of the issuer\'s entity ID in SAML ' +
        '2.0. It does not name the issuer, but it does confirm or refute ' +
        'one you already suspect.</div>');
    }
    if (art.messageHandle) {
      html += kv('MessageHandle', wrapped(art.messageHandle));
    }
    if (art.assertionHandle) {
      html += kv('AssertionHandle', wrapped(art.assertionHandle));
    }
    if (art.sourceLocation) {
      html += kv('SourceLocation', wrapped(art.sourceLocation));
    }
    html += kv('Length', art.length + ' bytes');
    html += kv('Raw', wrapped(art.raw));
    if (art.warning) {
      html += kv('Warning', '<span style="color:#b00;">' +
                 esc(art.warning) + '</span>');
    }
  }
  html += '</table>';
  html += '<p class="saml-note">An artifact is a one-shot REFERENCE. The ' +
    'message it points at is held by its issuer and handed over the SOAP ' +
    'back-channel to whoever resolves it &mdash; which destroys it. There is ' +
    'nothing here to decode, sign-check or decrypt; resolving it is what the ' +
    '<a href="/saml_request.html">SAML Test Tools</a> page does, and it ' +
    'needs the api for the back-channel.</p>';
  if (container) container.innerHTML = html;
  log.debug("Leaving renderArtifact().");
}

// The details table for a decoded message.
function renderDetails(summary) {
  log.debug("Entering renderDetails().");
  var container = el('sar_details');
  if (!container) {
    log.debug("Leaving renderDetails(). No container.");
    return;
  }
  if (summary.error) {
    container.innerHTML = '<em>' + esc(summary.error) + '</em>';
    log.debug("Leaving renderDetails(). Not XML.");
    return;
  }
  var html = '<table class="saml-table">';
  summary.rows.forEach(function (r) {
    // A row's value may be several lines (AuthnContext class refs, session
    // indexes). They are separate values rather than one string, so they get
    // separate lines rather than being run together with commas.
    var cell = esc(r.value).replace(/\n/g, '<br>');
    if (r.value.length > 60 && r.value.indexOf(' ') < 0) {
      cell = '<span style="word-break:break-all;">' + cell + '</span>';
    }
    if (r.note) {
      cell += '<div class="saml-note">' + esc(r.note) + '</div>';
    }
    html += kv(r.key, cell);
  });
  html += '</table>';
  // The signer certificate is the one value in the table worth a page of its
  // own, so it gets the same "View certificate details" hand-off the rest of
  // this family has.
  if (summary.signature && summary.signature.certB64) {
    lastSignerCertB64 = summary.signature.certB64;
    html += '<p class="saml-note"><a href="/saml_cert.html?from=' +
      'saml_authnrequest.html" onclick="return ' +
      'saml_authnrequest.viewSignerCert();">View the signing certificate ' +
      '&rarr;</a></p>';
  }
  container.innerHTML = html;
  log.debug("Leaving renderDetails(). rows=" + summary.rows.length);
}

// Put a decoded message into the three content tabs and the details table.
function renderMessage(xml) {
  log.debug("Entering renderMessage().");
  originalXml = xml;
  setVal('sar_xml', sm.formatXml(xml));
  var summary = sm.summarize(xml);
  renderDetails(summary);
  var enc = summary.encrypted;
  lastEncryptedXml = enc ? enc.xml : '';
  setVal('sar_encrypted', enc ? sm.formatXml(enc.xml) : '');
  var note = el('sar_enc_note');
  if (note && !enc) {
    note.textContent = 'No <xenc:EncryptedData> in this message — it is not ' +
      'encrypted. An AuthnRequest is rarely encrypted as a whole; the ' +
      'ordinary case is an <saml:EncryptedID> inside the Subject, which ' +
      'would show here too.';
  }
  log.debug("Leaving renderMessage(). encrypted=" + !!enc);
  return summary;
}

// Clear everything a previous decode left behind. Called at the top of
// decode(), because a decode that fails half way through must not leave the
// previous message's XML under the new message's parameters — the tabs would
// then be describing two different things at once and nothing would say so.
function resetResults() {
  log.debug("Entering resetResults().");
  originalXml = '';
  lastClassified = null;
  lastEncryptedXml = '';
  lastSignerCertB64 = '';
  setVal('sar_payload', '');
  setVal('sar_xml', '');
  setVal('sar_encrypted', '');
  setVal('sar_sig_status', '');
  setVal('sar_dec_status', '');
  var details = el('sar_details');
  if (details) details.innerHTML = '&nbsp;';
  var sig = el('sar_sig_details');
  if (sig) sig.innerHTML = '';
  var params = el('sar_params');
  if (params) params.innerHTML = '&nbsp;';
  log.debug("Leaving resetResults().");
}

function decode() {
  log.debug("Entering decode().");
  var raw = val('sar_input');
  resetResults();
  setVal('sar_original', raw);
  if (!raw || !raw.trim()) {
    setStatus('Nothing to decode — paste a request above.');
    log.debug("Leaving decode(). Empty input.");
    return false;
  }

  var c = sm.classify(raw);
  var forced = forcedBinding();
  if (forced) {
    // A forced artifact reading has to find the bytes somewhere: a bare blob
    // pasted with "HTTP-Artifact" selected is the artifact itself, which
    // classify() had no way to know.
    if (forced === 'artifact' && !c.artifact) {
      c.artifact = c.message || raw.trim();
      c.message = '';
    }
    c.binding = forced;
  }
  lastClassified = c;

  if (c.binding === 'artifact') {
    renderParams(c, null);
    renderArtifact(c);
    selectTab('tab_sar_details');
    setStatus('Read as an artifact. There is no message here to decode — an ' +
              'artifact references one held by its issuer.');
    log.debug("Leaving decode(). Artifact.");
    return false;
  }

  // Pasted XML: nothing to base64-decode, and it is already the message.
  if (c.kind === 'xml') {
    renderParams(c, null);
    var summaryXml = renderMessage(c.xml);
    selectTab(summaryXml.encrypted ? 'tab_sar_encrypted' : 'tab_sar_details');
    setStatus('Read as XML: ' + (summaryXml.messageType || 'an unrecognised ' +
              'element') + (summaryXml.version ? ', SAML ' +
              summaryXml.version : '') + '.');
    log.debug("Leaving decode(). XML.");
    return false;
  }

  if (!c.message) {
    renderParams(c, null);
    setStatus('No SAMLRequest, SAMLResponse or SAMLart parameter, and the ' +
              'blob is not XML. Check that the whole value was pasted.');
    log.debug("Leaving decode(). No message.");
    return false;
  }

  setVal('sar_payload', c.message);
  setStatus('Decoding…');
  sm.decodeSamlParam(c.message)
    .then(function (res) {
      // The decode is the ONLY thing that can tell a POST message from an
      // unsigned Redirect one, so the binding is settled here rather than in
      // classify() — unless the user forced it, in which case they are
      // telling us something the bytes cannot.
      if (!forcedBinding() && c.kind !== 'url') {
        c.binding = res.deflated ? 'redirect' : 'post';
      }
      renderParams(c, res.deflated);
      var summary = renderMessage(res.xml);
      if (summary.error) {
        setStatus('Decoded, but the result is not well-formed XML. The ' +
                  'bytes are in the XML tab.');
        selectTab('tab_sar_xml');
        return;
      }
      selectTab(summary.encrypted ? 'tab_sar_encrypted' : 'tab_sar_details');
      setStatus('Decoded a ' + (summary.messageType || 'message') +
        (summary.version ? ' (SAML ' + summary.version + ')' : '') +
        ' from the ' + bindingLabel(c.binding) + ' binding.' +
        (summary.encrypted ? ' It is ENCRYPTED — switch on Decryption and ' +
         'supply the recipient private key.' : '') +
        (summary.signature ? ' It carries an enveloped signature — switch ' +
         'on Digital Signature to check it.' : ''));
    })
    .catch(function (e) {
      log.error('decode: ' + e.message);
      setStatus('Could not decode: ' + e.message);
    });
  log.debug("Leaving decode().");
  return false;
}

function clearAll() {
  log.debug("Entering clearAll().");
  setVal('sar_input', '');
  setVal('sar_original', '');
  setVal('sar_signer_cert', '');
  setVal('sar_dec_key', '');
  setVal('sar_dec_cert', '');
  resetResults();
  setStatus('Cleared.');
  log.debug("Leaving clearAll().");
  return false;
}

// ---------------------------------------------------------------------------
// Signature validation — two completely different checks behind one button.
// ---------------------------------------------------------------------------

// The verification result of an enveloped XML signature, as a table. Same
// shape as the SAML Response page's, because it is the same result object out
// of the same function and two renderings of it would drift.
function formatXmlSigResult(res) {
  log.debug("Entering formatXmlSigResult().");
  if (res.error) {
    log.debug("Leaving formatXmlSigResult(). Refused.");
    return '<span style="color:#b00;">Cannot validate: ' + esc(res.error) +
        '</span>';
  }
  var color = res.valid ? '#2e7d32' : '#b00';
  var refs = (res.references || []).length;
  var html = '<table class="saml-table">';
  html += kv('Signature', '<strong style="color:' + color + ';">' +
             (res.valid ? 'VALID' : 'INVALID') + '</strong>');
  html += kv('SignatureValue', res.signatureValid ? 'verified' : 'FAILED');
  html += kv('Reference digests', (res.referencesValid ? 'match' :
             'MISMATCH') + ' (' + refs + ')');
  html += kv('Signature Method', wrapped(res.signatureMethod || ''));
  html += kv('Canonicalization', wrapped(res.canonicalization || ''));
  html += kv('Signer (cert CN)', esc(res.signerSubject || '(from KeyInfo)'));
  html += '</table>';
  log.debug("Leaving formatXmlSigResult().");
  return html;
}

// The verification result of a detached query-string signature.
function formatQuerySigResult(res, octets) {
  log.debug("Entering formatQuerySigResult().");
  if (res.error) {
    log.debug("Leaving formatQuerySigResult(). Refused.");
    return '<span style="color:#b00;">Cannot validate: ' + esc(res.error) +
        '</span>';
  }
  var color = res.valid ? '#2e7d32' : '#b00';
  var html = '<table class="saml-table">';
  html += kv('Signature', '<strong style="color:' + color + ';">' +
             (res.valid ? 'VALID' : 'INVALID') + '</strong>');
  html += kv('SigAlg', wrapped(res.signatureMethod || ''));
  html += kv('Algorithm', esc(res.label || ''));
  html += kv('Signer (cert CN)', esc(res.signerSubject || ''));
  // The signed octets are shown because they are the thing that goes wrong.
  // A signature that fails on a message that is fine is almost always the
  // parameters rebuilt in the wrong order or decoded before hashing, and the
  // only way to see that is to look at what was hashed.
  html += kv('Signed octets', wrapped(octets));
  html += '</table>';
  log.debug("Leaving formatQuerySigResult().");
  return html;
}

function validateSignature() {
  log.debug("Entering validateSignature().");
  var details = el('sar_sig_details');
  if (details) details.innerHTML = '';
  var c = lastClassified;
  if (!c) {
    setVal('sar_sig_status', 'Decode a request first.');
    log.debug("Leaving validateSignature(). Nothing decoded.");
    return false;
  }
  var cert = val('sar_signer_cert').trim();

  // A Redirect message signs the query string; the document inside it is
  // unsigned, and running the XML check on it would report "no signature" on
  // a message that is signed. So the binding decides which check runs.
  if (c.binding === 'redirect' || c.signature) {
    if (!c.signature) {
      setVal('sar_sig_status', 'This Redirect message carries no Signature ' +
             'parameter — it was sent unsigned.');
      log.debug("Leaving validateSignature(). Unsigned redirect.");
      return false;
    }
    var octets = sm.redirectSignedOctets(c.pairs);
    var qres = xd.verifyQueryString(octets, {
      signature: c.signature,
      sigAlg: c.sigAlg,
      certPem: cert
    });
    setVal('sar_sig_status', qres.error ? ('Cannot validate: ' + qres.error)
      : (qres.valid ? 'Query-string signature VALID.'
                    : 'Query-string signature INVALID.'));
    if (details) details.innerHTML = formatQuerySigResult(qres, octets);
    log.debug("Leaving validateSignature(). Redirect.");
    return false;
  }

  if (!originalXml) {
    setVal('sar_sig_status', 'There is no decoded message to validate.');
    log.debug("Leaving validateSignature(). No XML.");
    return false;
  }
  var res;
  try {
    // originalXml, NOT the pretty-printed textarea: added whitespace changes
    // the digest of a signed subtree.
    res = xd.verifyXmlSignature(originalXml, cert ? { certPem: cert } : {});
  } catch (e) {
    setVal('sar_sig_status', 'Validation error: ' + e.message);
    log.debug("Leaving validateSignature(). Threw.");
    return false;
  }
  setVal('sar_sig_status', res.error ? ('Cannot validate: ' + res.error)
    : (res.valid ? 'Enveloped signature VALID.'
                 : 'Enveloped signature INVALID.'));
  if (details) details.innerHTML = formatXmlSigResult(res);
  log.debug("Leaving validateSignature(). POST.");
  return false;
}

// Hand the signer certificate to the shared certificate-details page. The same
// localStorage key every other page in this family uses.
function viewSignerCert() {
  log.debug("Entering viewSignerCert().");
  var cert = lastSignerCertB64 || val('sar_signer_cert').trim();
  if (!cert) {
    setVal('sar_sig_status', 'No signer certificate to view.');
    log.debug("Leaving viewSignerCert(). None.");
    return false;
  }
  try {
    if (window.localStorage) localStorage.setItem('saml_cert_view', cert);
  } catch (e) {
    // Storage refused. The certificate-details page opens with whatever it
    // had; better than not opening at all, and the field here still holds it.
    log.error('viewSignerCert: could not stash the certificate: ' + e.message);
  }
  window.open('/saml_cert.html?from=saml_authnrequest.html', '_blank');
  log.debug("Leaving viewSignerCert().");
  return false;
}

// ---------------------------------------------------------------------------
// Decryption.
// ---------------------------------------------------------------------------

// Whether the supplied certificate is the one the sender wrapped the session
// key to. The sender MAY name the recipient in the EncryptedKey's KeyInfo; when
// it does and the certificates differ, decryption is going to fail and this is
// the only place that can say why — forge's message for the wrong key is
// "could not unwrap the session key", which reads identically to a corrupted
// message. When the sender named nobody there is nothing to compare and this
// says so rather than guessing.
function recipientMismatch(encryptedXml, certPem) {
  log.debug("Entering recipientMismatch().");
  if (!certPem) {
    log.debug("Leaving recipientMismatch(). No certificate supplied.");
    return '';
  }
  var doc = sm.parseXml(encryptedXml);
  if (!doc) {
    log.debug("Leaving recipientMismatch(). Unparseable.");
    return '';
  }
  var named = sm.tags(doc, 'X509Certificate')[0];
  if (!named) {
    log.debug("Leaving recipientMismatch(). Recipient not named.");
    return '';
  }
  var theirs = (named.textContent || '').replace(/\s+/g, '');
  var ours = certPem.replace(/-----[^-]*-----/g, '').replace(/\s+/g, '');
  log.debug("Leaving recipientMismatch().");
  return theirs === ours ? '' : 'The message names a different recipient ' +
    'certificate than the one supplied, so this key is very unlikely to ' +
    'unwrap it.';
}

function decrypt() {
  log.debug("Entering decrypt().");
  if (!lastEncryptedXml) {
    setVal('sar_dec_status', 'Nothing encrypted was found in the decoded ' +
           'message.');
    log.debug("Leaving decrypt(). Nothing encrypted.");
    return false;
  }
  var key = val('sar_dec_key').trim();
  if (!key) {
    setVal('sar_dec_status', 'Paste the recipient private key to decrypt.');
    log.debug("Leaving decrypt(). No key.");
    return false;
  }
  var warning = recipientMismatch(lastEncryptedXml, val('sar_dec_cert').trim());
  var plaintext;
  try {
    plaintext = xd.decryptXml(lastEncryptedXml, { privateKeyPem: key });
  } catch (e) {
    setVal('sar_dec_status', 'Decryption failed: ' + e.message +
           (warning ? ' ' + warning : ''));
    log.debug("Leaving decrypt(). Failed.");
    return false;
  }
  // What comes out is the message: re-render everything from it, so the XML
  // tab, the details table and the signature check all operate on the
  // plaintext rather than on the ciphertext that produced it.
  var summary = renderMessage(plaintext);
  selectTab('tab_sar_details');
  setVal('sar_dec_status', 'Decrypted' + (summary.messageType ? ' a ' +
         summary.messageType : '') + '. The plaintext is in the XML tab and ' +
         'the values are in Details.');
  setStatus('Decrypted. Any signature INSIDE the ciphertext can now be ' +
            'checked — a signature outside it never covered the plaintext.');
  log.debug("Leaving decrypt().");
  return false;
}

// ---------------------------------------------------------------------------
// Arriving with a request already in hand.
//
// ?SAMLRequest= / ?SAMLart= / ?url= let this page be reached from a bookmark
// or from a link, which is how somebody debugging pastes a whole redirect URL
// once instead of twice. The parameter is put in the input box and decoded
// exactly as if it had been pasted — there is no second code path.
// ---------------------------------------------------------------------------
function inputFromQuery() {
  log.debug("Entering inputFromQuery().");
  var qp = new URLSearchParams(window.location.search);
  var direct = qp.get('url') || qp.get('request');
  if (direct) {
    log.debug("Leaving inputFromQuery(). A whole URL.");
    return direct;
  }
  var req = qp.get('SAMLRequest');
  if (req) {
    var qs = 'SAMLRequest=' + encodeURIComponent(req);
    ['RelayState', 'SigAlg', 'Signature'].forEach(function (name) {
      var v = qp.get(name);
      if (v) qs += '&' + name + '=' + encodeURIComponent(v);
    });
    log.debug("Leaving inputFromQuery(). Reassembled parameters.");
    return qs;
  }
  var art = qp.get('SAMLart');
  if (art) {
    log.debug("Leaving inputFromQuery(). An artifact.");
    return 'SAMLart=' + encodeURIComponent(art);
  }
  log.debug("Leaving inputFromQuery(). Nothing.");
  return '';
}

window.onload = function () {
  log.debug("Entering onload().");
  // Both optional panes start closed, and the markup already hides their
  // bodies — this makes the two agree if a browser restored a checked box on
  // a reload, which Firefox and Chrome both do.
  toggleVerify();
  toggleDecrypt();
  var seeded = inputFromQuery();
  if (seeded) {
    setVal('sar_input', seeded);
    decode();
  } else {
    setStatus('Paste a SAML request above and click Decode.');
  }
  log.debug("Leaving onload().");
};

module.exports = {
  togglePane,
  showTab,
  copyField,
  toggleVerify,
  toggleDecrypt,
  loadSpKeyPair,
  decode,
  clearAll,
  validateSignature,
  viewSignerCert,
  decrypt
};
