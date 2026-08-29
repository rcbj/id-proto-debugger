// File: saml_response_decoder.js
//
// The SAML Response Decoder: take a SAML response off the wire and read it, in
// either protocol version.
//
// WHAT THIS PAGE IS FOR. saml_response.html renders the response THIS
// application's own SSO round trip just produced — it is the last screen of a
// workflow, and it is handed its message by the Assertion Consumer Service.
// This page reads a response somebody else produced, pasted from a browser's
// network tab or a proxy log, with no workflow around it and no api behind it.
// It is the counterpart of saml_authnrequest.html on the other half of the
// exchange, and it is built the same way and out of the same two modules.
//
// THREE THINGS MAKE A RESPONSE HARDER TO READ THAN A REQUEST, and each of them
// is a place a decoder can be confidently wrong:
//
//   THE STATUS. A request has none; a response IS one. SAML 2.0 writes the
//   code as a URI ending `:status:Success` and SAML 1.1 writes it as a QName
//   (`samlp:Success`) resolved against the document's own namespace
//   declarations, so a check written for either version reads the other's
//   SUCCESS AS A FAILURE. That is not hypothetical: it is what the SAML
//   Response page did to every SAML 1.1 sign-in until 2026-08-25. The reading
//   is in saml_message.js — one implementation, matching the local part after
//   the last colon, which is the only rule that covers both.
//
//   TWO SIGNATURES THAT MEAN DIFFERENT THINGS. The identity provider may sign
//   the <samlp:Response>, or each <saml:Assertion>, or both, and the
//   difference is not presentational. An assertion signature travels with the
//   assertion and survives it being lifted out and forwarded; it does NOT
//   cover the status, the Destination or the InResponseTo. A message signature
//   covers all three and is lost the moment anything extracts the assertion.
//   So this page verifies EVERY signature it finds and reports each on its own
//   line, naming what it covers. One "signature: VALID" line over a response
//   whose assertion is unsigned would be the most dangerous thing this page
//   could say.
//
//   MORE THAN ONE ASSERTION, ANY OF THEM ENCRYPTED. Decrypting an
//   <saml:EncryptedAssertion> puts the plaintext back into the response in
//   place of the ciphertext, so everything below re-renders from it — but the
//   signature check on that assertion runs against the plaintext AS
//   DECRYPTED, never against the spliced document, because re-serializing a
//   subtree into a new parent can change which namespace declarations are in
//   scope at its apex, and under inclusive C14N that changes the digest.
//
// NO CRYPTOGRAPHY IS IMPLEMENTED HERE. Signature verification and decryption
// are common/xmldsig.js; reading the wire format and both versions' spelling
// of every field is client/src/saml_message.js, shared with saml_response.js
// and saml_authnrequest.js. This file is the DOM between them.
//
// NOTHING PASTED HERE IS STORED, and that is the same deliberate exception
// saml_authnrequest.js makes: every other page in this family GENERATES a key
// pair and needs it on the next screen, so it keeps one behind the opt-out the
// repo-root CLAUDE.md describes. This page generates nothing and has no next
// screen — the private key is somebody else's, pasted once to read one
// message — so it is read out of the field when Decrypt is clicked and never
// written anywhere. The prefill runs the other way, out of the SAML Test Tools
// page's stored pair when it has one, which reads storage and does not add
// to it.
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var xd = require("./xmldsig");
var sm = require("./saml_message");
var log = bunyan.createLogger({ name: 'saml_response_decoder',
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
// The summarizeResponse() result the tabs are currently drawn from.
var lastSummary = null;
// The serialized <xenc:EncryptedData> (or its enclosing element, when the
// wrapped key is a sibling) currently on offer to the Decryption pane.
var lastEncryptedXml = '';
// The signer certificate this page last showed, handed to saml_cert.html.
var lastSignerCertB64 = '';
// Assertions recovered from ciphertext, keyed by their own id and held AS
// DECRYPTED. See the header: an assertion's signature is checked against these
// bytes rather than against the assertion re-serialized out of the response it
// was spliced into.
var plaintextById = {};

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
  setVal('srd_status', msg);
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
  // leaves the class winning and the block invisible.
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
    // No secure context, so navigator.clipboard does not exist at all — which
    // is every containerized run of this suite.
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
  show('srd_verify_body', isOn('srd_verify_enabled'));
  log.debug("Leaving toggleVerify().");
  return true;
}

function toggleDecrypt() {
  log.debug("Entering toggleDecrypt().");
  var on = isOn('srd_decrypt_enabled');
  show('srd_decrypt_body', on);
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
  var note = el('srd_dec_key_note');
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
  if (priv && !val('srd_dec_key')) setVal('srd_dec_key', priv);
  if (cert && !val('srd_dec_cert')) setVal('srd_dec_cert', cert);
  if (note && !val('srd_dec_key')) {
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
  setVal('srd_dec_key', '');
  setVal('srd_dec_cert', '');
  prefillDecryptionKey();
  setVal('srd_dec_status', val('srd_dec_key')
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
  var b = val('srd_binding');
  log.debug("Leaving forcedBinding().");
  return (b && b !== 'auto') ? b : '';
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

// The binding parameters table — what travelled beside the message.
function renderParams(c, deflated) {
  log.debug("Entering renderParams().");
  var container = el('srd_params');
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
  if (c.direction === 'request') {
    // A request pasted into the response decoder still decodes, and saying so
    // is better than a page of empty status rows — but the two pages answer
    // different questions and the other one is one click away.
    html += kv('Note', 'this blob carries a <strong>SAMLRequest</strong>, ' +
      'not a response. It is decoded below, but the <a href=' +
      '"/saml_authnrequest.html?from=saml_response_decoder.html">SAML ' +
      'Request Decoder</a> is the page written for it.');
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

// The artifact tab and table. An artifact carries no message, so the XML tab
// stays empty and saying so plainly is the whole of what a decoder can do.
function renderArtifact(c) {
  log.debug("Entering renderArtifact().");
  var art = sm.parseArtifact(c.artifact);
  var container = el('srd_details');
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
  html += '<p class="saml-note">An artifact is a one-shot REFERENCE. On the ' +
    'response half of the exchange it is what the identity provider hands ' +
    'the browser INSTEAD of the assertion: the <code>&lt;samlp:Response' +
    '&gt;</code> itself stays at the issuer and is fetched over the SOAP ' +
    'back-channel by whoever resolves the artifact &mdash; which destroys ' +
    'it. There is nothing here to decode, sign-check or decrypt; resolving ' +
    'it is what the <a href="/saml_request.html">SAML Test Tools</a> page ' +
    'does, and it needs the api for the back-channel.</p>';
  if (container) container.innerHTML = html;
  var banner = el('srd_status_banner');
  if (banner) banner.innerHTML = '&nbsp;';
  log.debug("Leaving renderArtifact().");
}

// The status, above the details table and in colour, because it is the answer
// the page was opened for. A failure is stated in the version's own spelling
// AND in plain words: `urn:oasis:names:tc:SAML:2.0:status:Responder` over
// `…:NoPassive` is an identity provider saying it would have had to ask the
// user something, which is not what most people read out of those two URIs.
function renderStatusBanner(summary) {
  log.debug("Entering renderStatusBanner().");
  var banner = el('srd_status_banner');
  if (!banner) {
    log.debug("Leaving renderStatusBanner(). No container.");
    return;
  }
  var status = summary ? summary.status : null;
  if (!status || !status.present) {
    banner.innerHTML = '&nbsp;';
    log.debug("Leaving renderStatusBanner(). No status.");
    return;
  }
  var color = status.success ? '#2e7d32' : '#b00';
  var html = '<p class="saml-note" style="font-size:0.95em;">' +
    '<strong style="color:' + color + ';">' + esc(status.short) +
    '</strong> <span style="color:#888; word-break:break-all;">' +
    esc(status.top) + '</span>';
  if (status.note) html += '<br>' + esc(status.note);
  for (var i = 1; i < status.chain.length; i++) {
    html += '<br>Sub-status: ' + esc(status.chain[i]);
  }
  if (status.message) html += '<br>Message: ' + esc(status.message);
  html += '</p>';
  banner.innerHTML = html;
  log.debug("Leaving renderStatusBanner(). " + status.short);
}

// The details table for a decoded message.
function renderDetails(summary) {
  log.debug("Entering renderDetails().");
  var container = el('srd_details');
  if (!container) {
    log.debug("Leaving renderDetails(). No container.");
    return;
  }
  if (summary.error) {
    container.innerHTML = '<em>' + esc(summary.error) + '</em>';
    log.debug("Leaving renderDetails(). Not XML.");
    return;
  }
  var html = rowsTable(summary.rows);
  // The signer certificate is the one value in the table worth a page of its
  // own, so it gets the same "View certificate details" hand-off the rest of
  // this family has.
  if (summary.signature && summary.signature.certB64) {
    lastSignerCertB64 = summary.signature.certB64;
  }
  if (!lastSignerCertB64) {
    for (var i = 0; i < summary.assertions.length; i++) {
      var s = summary.assertions[i].summary;
      if (s && s.signature && s.signature.certB64) {
        lastSignerCertB64 = s.signature.certB64;
        break;
      }
    }
  }
  if (lastSignerCertB64) {
    html += '<p class="saml-note"><a href="/saml_cert.html?from=' +
      'saml_response_decoder.html" onclick="return ' +
      'saml_response_decoder.viewSignerCert();">View the signing certificate ' +
      '&rarr;</a></p>';
  }
  container.innerHTML = html;

  // The message carried INSIDE an ArtifactResponse gets a CONTAINER OF ITS
  // OWN rather than a section appended to the table above, and that is not
  // presentation: the two tables have the same row keys — Message Type,
  // Status Code, Issuer — so anything reading this pane, a person included,
  // has to be able to say which of the two it is looking at. Sharing one
  // container makes the second table silently overwrite the first for any
  // reader that goes by key.
  var carried = el('srd_carried');
  if (!carried) {
    log.debug("Leaving renderDetails(). No carried-message container.");
    return;
  }
  if (!summary.nested) {
    carried.innerHTML = '&nbsp;';
    log.debug("Leaving renderDetails(). Nothing carried.");
    return;
  }
  carried.innerHTML = '<div class="saml-sub"><div class="saml-sub-title">' +
    'Carried message: &lt;' + esc(summary.nested.messageType) + '&gt;</div>' +
    '<p class="saml-note">A <code>&lt;samlp:ArtifactResponse&gt;</code> is ' +
    'an ENVELOPE. Its own Status above says only whether the artifact ' +
    'RESOLVED; everything below is the message it carries, whose status is ' +
    'the answer being looked for.</p>' + rowsTable(summary.nested.rows) +
    '</div>';
  log.debug("Leaving renderDetails(). rows=" + summary.rows.length);
}

// One { key, value, note } list as a table. Shared by the message details, the
// carried message and every assertion block, because three renderings of the
// same row shape is three chances for one of them to drop the notes.
function rowsTable(rows) {
  log.debug("Entering rowsTable().");
  var html = '<table class="saml-table">';
  (rows || []).forEach(function (r) {
    // A row's value may be several lines (AuthnContext class refs, session
    // indexes, audiences). They are separate values rather than one string, so
    // they get separate lines rather than being run together with commas.
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
  log.debug("Leaving rowsTable().");
  return html;
}

// The attributes of one assertion, as the four-column table the SAML Response
// page draws. Attributes are the reason most people open a response at all —
// an application is not getting the claim it expected — so they get a table of
// their own rather than a row in the details list.
function attributesTable(attributes) {
  log.debug("Entering attributesTable().");
  if (!attributes || !attributes.length) {
    log.debug("Leaving attributesTable(). None.");
    return '<p class="saml-note">This assertion carries no ' +
      '&lt;saml:Attribute&gt; at all. An authentication statement with no ' +
      'attribute statement beside it is perfectly legal and says only that ' +
      'the subject signed in.</p>';
  }
  var html = '<table class="saml-table"><tr><th>Name</th><th>Value(s)</th>' +
      '<th>Format</th><th>FriendlyName</th></tr>';
  attributes.forEach(function (a) {
    html += '<tr><td>' + wrapped(a.name) + '</td><td>' +
      a.values.map(function (v) { return esc(v); }).join('<br>') +
      '</td><td>' + wrapped(a.format) + '</td><td>' +
      esc(a.friendlyName) + '</td></tr>';
  });
  html += '</table>';
  log.debug("Leaving attributesTable(). " + attributes.length + " rows.");
  return html;
}

// The Assertions tab: one block per assertion, in document order.
function renderAssertions(summary) {
  log.debug("Entering renderAssertions().");
  var container = el('srd_assertions');
  if (!container) {
    log.debug("Leaving renderAssertions(). No container.");
    return;
  }
  var list = summary ? summary.assertions : [];
  if (!list || !list.length) {
    container.innerHTML = '<p class="saml-note">This message carries no ' +
      'assertion. That is ordinary and not an error: a ' +
      '<code>&lt;samlp:LogoutResponse&gt;</code> never carries one, and ' +
      'neither does a <code>&lt;samlp:Response&gt;</code> whose status is a ' +
      'failure — the status IS the whole message.</p>';
    log.debug("Leaving renderAssertions(). None.");
    return;
  }
  var html = '';
  list.forEach(function (entry, i) {
    var label = 'Assertion ' + (i + 1) + ' of ' + list.length;
    if (entry.encrypted) label += ' — ENCRYPTED';
    if (entry.advice) label += ' — inside <saml:Advice>';
    html += '<div class="saml-sub"><div class="saml-sub-title">' +
        esc(label) + '</div>';
    if (entry.advice) {
      html += '<p class="saml-note">An assertion in an ' +
        '<code>&lt;saml:Advice&gt;</code> is SUPPORTING material — the ' +
        'issuer offering its own evidence — and is not the subject of this ' +
        'response. A relying party may ignore it entirely, so an ' +
        'application reading its attributes is reading something it was ' +
        'never promised.</p>';
    }
    if (entry.encrypted) {
      html += '<table class="saml-table">';
      html += kv('Encryption (data)', wrapped(entry.dataAlg || '(not stated)'));
      html += kv('Encryption (key transport)',
                 wrapped(entry.keyAlg || '(the key is not in this document)'));
      html += '</table>';
      html += '<p class="saml-note">Nothing can be said about this ' +
        'assertion until it is decrypted — switch on Decryption above and ' +
        'supply the recipient private key. A decoder that guessed at its ' +
        'contents would be reading ciphertext.</p>';
      html += '</div>';
      return;
    }
    html += rowsTable(entry.summary ? entry.summary.rows : []);
    html += '<div class="saml-sub-title">Attributes</div>';
    html += attributesTable(entry.summary ? entry.summary.attributes : []);
    html += '<div class="saml-field"><label class="saml-has-copy">' +
      'Assertion XML <button type="button" class="saml-copy" onclick=' +
      '"return saml_response_decoder.copyField(\'srd_assertion_' + i +
      '\');">Copy</button></label>' +
      '<textarea rows="10" id="srd_assertion_' + i + '" readonly>' +
      esc(sm.formatXml(assertionXmlFor(entry))) + '</textarea></div>';
    html += '</div>';
  });
  container.innerHTML = html;
  log.debug("Leaving renderAssertions(). " + list.length + " assertions.");
}

// The bytes of one assertion for display and for verification: the plaintext
// as decrypted when it came out of ciphertext, and the serialized subtree
// otherwise. See the file header — re-serializing a decrypted assertion out of
// the response it was spliced into can change the namespace declarations in
// scope at its apex, which under inclusive C14N changes its digest.
function assertionXmlFor(entry) {
  log.debug("Entering assertionXmlFor().");
  var id = entry && entry.summary ? entry.summary.id : '';
  if (id && plaintextById[id]) {
    log.debug("Leaving assertionXmlFor(). Plaintext as decrypted.");
    return plaintextById[id];
  }
  log.debug("Leaving assertionXmlFor(). As serialized.");
  return entry ? entry.xml : '';
}

// Put a decoded message into the tabs and the tables.
function renderMessage(xml) {
  log.debug("Entering renderMessage().");
  originalXml = xml;
  setVal('srd_xml', sm.formatXml(xml));
  var summary = sm.summarizeResponse(xml);
  lastSummary = summary;
  renderStatusBanner(summary);
  renderDetails(summary);
  renderAssertions(summary);
  var enc = summary.encrypted;
  lastEncryptedXml = enc ? enc.xml : '';
  setVal('srd_encrypted', enc ? sm.formatXml(enc.xml) : '');
  var note = el('srd_enc_note');
  if (note && !enc) {
    note.textContent = 'No <xenc:EncryptedData> in this response — nothing ' +
      'in it is encrypted. The ordinary case is a whole ' +
      '<saml:EncryptedAssertion>; an <saml:EncryptedID> inside a Subject, ' +
      'or an <saml:EncryptedAttribute>, would show here too.';
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
  lastSummary = null;
  lastEncryptedXml = '';
  lastSignerCertB64 = '';
  plaintextById = {};
  setVal('srd_payload', '');
  setVal('srd_xml', '');
  setVal('srd_encrypted', '');
  setVal('srd_sig_status', '');
  setVal('srd_dec_status', '');
  var details = el('srd_details');
  if (details) details.innerHTML = '&nbsp;';
  var carried = el('srd_carried');
  if (carried) carried.innerHTML = '&nbsp;';
  var banner = el('srd_status_banner');
  if (banner) banner.innerHTML = '&nbsp;';
  var assertions = el('srd_assertions');
  if (assertions) assertions.innerHTML = '&nbsp;';
  var sig = el('srd_sig_details');
  if (sig) sig.innerHTML = '';
  var params = el('srd_params');
  if (params) params.innerHTML = '&nbsp;';
  log.debug("Leaving resetResults().");
}

// What the status line says about a decoded message, in one sentence: the
// message type, its version, its SAML status, and what is left to do about it.
function decodeSummaryLine(summary, binding) {
  log.debug("Entering decodeSummaryLine().");
  var line = 'Decoded a ' + (summary.messageType || 'message') +
      (summary.version ? ' (SAML ' + summary.version + ')' : '');
  if (binding) line += ' from the ' + bindingLabel(binding) + ' binding';
  line += '.';
  if (summary.status && summary.status.present) {
    line += ' Status: ' + summary.status.short +
        (summary.status.success ? '.' : ' — NOT a success.');
  }
  var encrypted = summary.assertions.filter(function (a) {
    return a.encrypted;
  }).length;
  if (encrypted || summary.encrypted) {
    line += ' It is ENCRYPTED — switch on Decryption and supply the ' +
        'recipient private key.';
  }
  var signed = !!summary.signature || summary.assertions.some(function (a) {
    return a.summary && a.summary.signature;
  });
  if (signed) {
    line += ' It carries at least one signature — switch on Digital ' +
        'Signatures to check them.';
  }
  log.debug("Leaving decodeSummaryLine().");
  return line;
}

function decode() {
  log.debug("Entering decode().");
  var raw = val('srd_input');
  resetResults();
  setVal('srd_original', raw);
  if (!raw || !raw.trim()) {
    setStatus('Nothing to decode — paste a response above.');
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
    renderAssertions(null);
    selectTab('tab_srd_details');
    setStatus('Read as an artifact. There is no message here to decode — an ' +
              'artifact references one held by its issuer.');
    log.debug("Leaving decode(). Artifact.");
    return false;
  }

  // Pasted XML: nothing to base64-decode, and it is already the message.
  if (c.kind === 'xml') {
    renderParams(c, null);
    var summaryXml = renderMessage(c.xml);
    selectTab(landingTab(summaryXml));
    setStatus(summaryXml.error ? 'That does not parse as XML.'
      : decodeSummaryLine(summaryXml, ''));
    log.debug("Leaving decode(). XML.");
    return false;
  }

  if (!c.message) {
    renderParams(c, null);
    setStatus('No SAMLResponse, SAMLRequest or SAMLart parameter, and the ' +
              'blob is not XML. Check that the whole value was pasted.');
    log.debug("Leaving decode(). No message.");
    return false;
  }

  setVal('srd_payload', c.message);
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
        selectTab('tab_srd_xml');
        return;
      }
      selectTab(landingTab(summary));
      setStatus(decodeSummaryLine(summary, c.binding));
    })
    .catch(function (e) {
      log.error('decode: ' + e.message);
      setStatus('Could not decode: ' + e.message);
    });
  log.debug("Leaving decode().");
  return false;
}

// Which tab a fresh decode should land on. Ciphertext first, because nothing
// else can be read until it is dealt with; then the assertions, because a
// successful response is opened to see what it says about somebody; then the
// details, which is where a FAILED response's whole content is.
function landingTab(summary) {
  log.debug("Entering landingTab().");
  var hasCiphertext = summary.encrypted || summary.assertions.some(
    function (a) { return a.encrypted; });
  if (hasCiphertext) {
    log.debug("Leaving landingTab(). Encrypted.");
    return 'tab_srd_encrypted';
  }
  var readable = summary.assertions.some(function (a) {
    return !a.encrypted;
  });
  if (readable) {
    log.debug("Leaving landingTab(). Assertions.");
    return 'tab_srd_assertions';
  }
  log.debug("Leaving landingTab(). Details.");
  return 'tab_srd_details';
}

function clearAll() {
  log.debug("Entering clearAll().");
  setVal('srd_input', '');
  setVal('srd_original', '');
  setVal('srd_signer_cert', '');
  setVal('srd_dec_key', '');
  setVal('srd_dec_cert', '');
  resetResults();
  setStatus('Cleared.');
  log.debug("Leaving clearAll().");
  return false;
}

// ---------------------------------------------------------------------------
// Signature validation — every signature the response carries, separately.
// ---------------------------------------------------------------------------

// One row of the results table. `covers` is the half that matters: a reader
// who has been told VALID and not told what was signed has been told the least
// useful true thing available.
function sigRow(where, covers, res, extra) {
  log.debug("Entering sigRow().");
  var html;
  if (res.error) {
    html = '<tr><td class="saml-key">' + esc(where) + '</td><td>' +
      '<span style="color:#b00;">Cannot validate: ' + esc(res.error) +
      '</span><div class="saml-note">' + esc(covers) + '</div></td></tr>';
    log.debug("Leaving sigRow(). Refused.");
    return html;
  }
  var color = res.valid ? '#2e7d32' : '#b00';
  var detail = 'Method: ' + (res.signatureMethod || '(not stated)');
  if (res.signerSubject) detail += ' · Signer: ' + res.signerSubject;
  if (res.references) {
    detail += ' · Reference digests: ' +
      (res.referencesValid ? 'match' : 'MISMATCH') +
      ' (' + res.references.length + ')';
  }
  if (res.signatureValid !== undefined) {
    detail += ' · SignatureValue: ' +
      (res.signatureValid ? 'verified' : 'FAILED');
  }
  html = '<tr><td class="saml-key">' + esc(where) + '</td><td>' +
    '<strong style="color:' + color + ';">' +
    (res.valid ? 'VALID' : 'INVALID') + '</strong>' +
    '<div class="saml-note">' + esc(covers) + '</div>' +
    '<div class="saml-note" style="word-break:break-all;">' + esc(detail) +
    '</div>' + (extra || '') + '</td></tr>';
  log.debug("Leaving sigRow().");
  return html;
}

function validateSignatures() {
  log.debug("Entering validateSignatures().");
  var details = el('srd_sig_details');
  if (details) details.innerHTML = '';
  if (!lastSummary && !lastClassified) {
    setVal('srd_sig_status', 'Decode a response first.');
    log.debug("Leaving validateSignatures(). Nothing decoded.");
    return false;
  }
  var cert = val('srd_signer_cert').trim();
  var rows = '';
  var checked = 0, valid = 0;

  // 1. THE DETACHED QUERY-STRING SIGNATURE. It exists only on the Redirect
  //    binding, it covers the parameters as SENT and nothing inside the
  //    document, and it has nowhere to carry a certificate — so it is the one
  //    check here that cannot run without something pasted above.
  var c = lastClassified;
  if (c && c.signature) {
    var octets = sm.redirectSignedOctets(c.pairs);
    var qres = xd.verifyQueryString(octets, {
      signature: c.signature,
      sigAlg: c.sigAlg,
      certPem: cert
    });
    checked++;
    if (qres.valid) valid++;
    rows += sigRow('Query string (Redirect binding)',
      'covers the SAMLResponse, RelayState and SigAlg parameters as sent — ' +
      'not the document inside them, and not the assertion.', qres,
      '<div class="saml-note" style="word-break:break-all;">Signed octets: ' +
      esc(octets) + '</div>');
  }

  // 2. THE MESSAGE-LEVEL ENVELOPED SIGNATURE.
  if (lastSummary && lastSummary.signature && originalXml) {
    var mres;
    try {
      // originalXml, NOT the pretty-printed textarea: added whitespace changes
      // the digest of a signed subtree.
      mres = xd.verifyXmlSignature(originalXml, cert ? { certPem: cert } : {});
    } catch (e) {
      mres = { valid: false, error: e.message };
    }
    checked++;
    if (mres.valid) valid++;
    rows += sigRow('Message <' + lastSummary.messageType + '>',
      'covers the whole response — the Status, the Destination and the ' +
      'InResponseTo included. It is LOST the moment anything extracts the ' +
      'assertion from the response.', mres);
  }

  // 3. EVERY ASSERTION'S OWN SIGNATURE, each against the assertion's own
  //    bytes. An assertion inside an <saml:Advice> is checked too and labelled
  //    as such: a valid signature on supporting material is still not a
  //    statement about the subject of this response.
  var list = lastSummary ? lastSummary.assertions : [];
  list.forEach(function (entry, i) {
    if (entry.encrypted) {
      rows += '<tr><td class="saml-key">Assertion ' + (i + 1) +
        '</td><td>still encrypted — decrypt it before its signature can be ' +
        'checked. A signature outside the ciphertext never covered it.' +
        '</td></tr>';
      return;
    }
    if (!entry.summary || !entry.summary.signature) {
      rows += '<tr><td class="saml-key">Assertion ' + (i + 1) +
        '</td><td>carries no &lt;ds:Signature&gt; of its own.' +
        (lastSummary.signature ? ' The message signature above covers it ' +
         'while it stays inside this response, and only while it does.'
         : ' Nothing signs this assertion at all.') + '</td></tr>';
      return;
    }
    var ares;
    try {
      ares = xd.verifyXmlSignature(assertionXmlFor(entry),
                                   cert ? { certPem: cert } : {});
    } catch (e) {
      ares = { valid: false, error: e.message };
    }
    checked++;
    if (ares.valid) valid++;
    rows += sigRow('Assertion ' + (i + 1) + (entry.advice ?
      ' (in <saml:Advice>)' : ''),
      'covers this assertion only. It travels with the assertion and ' +
      'survives it being lifted out of the response — and it says nothing ' +
      'about the response\'s Status or InResponseTo.', ares);
  });

  var table = rows ? ('<table class="saml-table">' + rows + '</table>') : '';
  // NOTHING WAS SIGNED is a verdict rather than an empty result, and it has to
  // be said as one. The rows above may still be there — an assertion reported
  // as unsigned, or one still encrypted — so they are kept and the headline
  // goes beside them; a blank pane here reads as a check that did not run,
  // which is the reading that gets an unsigned response accepted.
  if (!checked) {
    setVal('srd_sig_status', 'No signature was found on this response, on ' +
           'any readable assertion in it, or on the query string it arrived ' +
           'in.');
    if (details) {
      details.innerHTML = table + '<p class="saml-note">An unsigned response ' +
        'is not an error here — it is a finding. A relying party that ' +
        'accepts one accepts anything anybody posts to its Assertion ' +
        'Consumer Service.</p>';
    }
    log.debug("Leaving validateSignatures(). Nothing signed.");
    return false;
  }
  if (details) details.innerHTML = table;
  setVal('srd_sig_status', valid + ' of ' + checked + ' signature' +
         (checked === 1 ? '' : 's') + ' VALID.');
  log.debug("Leaving validateSignatures(). " + valid + "/" + checked);
  return false;
}

// Hand the signer certificate to the shared certificate-details page. The same
// localStorage key every other page in this family uses.
function viewSignerCert() {
  log.debug("Entering viewSignerCert().");
  var cert = lastSignerCertB64 || val('srd_signer_cert').trim();
  if (!cert) {
    setVal('srd_sig_status', 'No signer certificate to view.');
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
  window.open('/saml_cert.html?from=saml_response_decoder.html', '_blank');
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

// Put a decrypted assertion back into the response IN PLACE OF the ciphertext
// it came out of, and return the new response XML. Splicing rather than
// replacing the whole document is what keeps the status, the InResponseTo and
// any other assertion on screen — a response whose encrypted assertion has
// been read is still a response, and throwing the envelope away to show the
// plaintext would lose the half that says whether the sign-in succeeded.
//
// Returns '' when there is nothing to splice into, which is the case when the
// whole pasted blob was the ciphertext.
function spliceDecrypted(responseXml, encryptedXml, plaintext) {
  log.debug("Entering spliceDecrypted().");
  var doc = sm.parseXml(responseXml);
  var fragment = sm.parseXml(plaintext);
  if (!doc || !fragment || !fragment.documentElement) {
    log.debug("Leaving spliceDecrypted(). Unparseable.");
    return '';
  }
  // The element the ciphertext lives in: the <saml:EncryptedAssertion> when
  // there is one, and the <xenc:EncryptedData> itself otherwise.
  var target = sm.tags(doc, 'EncryptedAssertion')[0] ||
      sm.tags(doc, 'EncryptedData')[0];
  if (!target || !target.parentNode) {
    log.debug("Leaving spliceDecrypted(). Nowhere to splice.");
    return '';
  }
  var imported;
  try {
    imported = doc.importNode(fragment.documentElement, true);
    target.parentNode.replaceChild(imported, target);
  } catch (e) {
    log.error('spliceDecrypted: ' + e.message);
    log.debug("Leaving spliceDecrypted(). Refused.");
    return '';
  }
  log.debug("Leaving spliceDecrypted().");
  return sm.serialize(doc.documentElement);
}

function decrypt() {
  log.debug("Entering decrypt().");
  if (!lastEncryptedXml) {
    setVal('srd_dec_status', 'Nothing encrypted was found in the decoded ' +
           'response.');
    log.debug("Leaving decrypt(). Nothing encrypted.");
    return false;
  }
  var key = val('srd_dec_key').trim();
  if (!key) {
    setVal('srd_dec_status', 'Paste the recipient private key to decrypt.');
    log.debug("Leaving decrypt(). No key.");
    return false;
  }
  var warning = recipientMismatch(lastEncryptedXml, val('srd_dec_cert').trim());
  var plaintext;
  try {
    plaintext = xd.decryptXml(lastEncryptedXml, { privateKeyPem: key });
  } catch (e) {
    setVal('srd_dec_status', 'Decryption failed: ' + e.message +
           (warning ? ' ' + warning : ''));
    log.debug("Leaving decrypt(). Failed.");
    return false;
  }

  // Remember the plaintext under the assertion's own id BEFORE it is spliced,
  // because that is the copy its signature has to be checked against.
  var fragment = sm.parseXml(plaintext);
  var recovered = fragment && fragment.documentElement ?
      fragment.documentElement : null;
  if (recovered && recovered.localName === 'Assertion') {
    var id = recovered.getAttribute('ID') ||
        recovered.getAttribute('AssertionID');
    if (id) plaintextById[id] = plaintext;
  }

  var spliced = spliceDecrypted(originalXml, lastEncryptedXml, plaintext);
  var summary = renderMessage(spliced || plaintext);
  selectTab(spliced ? 'tab_srd_assertions' : 'tab_srd_details');
  setVal('srd_dec_status', 'Decrypted' + (recovered ? ' a ' +
         recovered.localName : '') + '. ' + (spliced
    ? 'It has been put back into the response in place of the ciphertext, ' +
      'so the tables above now describe the plaintext.'
    : 'The plaintext is in the XML tab and the values are in Details.'));
  setStatus(decodeSummaryLine(summary, lastClassified ?
            lastClassified.binding : '') + ' Any signature INSIDE the ' +
            'ciphertext can now be checked — a signature outside it never ' +
            'covered the plaintext.');
  log.debug("Leaving decrypt().");
  return false;
}

// ---------------------------------------------------------------------------
// Arriving with a response already in hand.
//
// ?SAMLResponse= / ?SAMLart= / ?url= let this page be reached from a bookmark
// or from a link, which is how somebody debugging pastes a whole URL once
// instead of twice. The parameter is put in the input box and decoded exactly
// as if it had been pasted — there is no second code path.
// ---------------------------------------------------------------------------
function inputFromQuery() {
  log.debug("Entering inputFromQuery().");
  var qp = new URLSearchParams(window.location.search);
  var direct = qp.get('url') || qp.get('response');
  if (direct) {
    log.debug("Leaving inputFromQuery(). A whole URL.");
    return direct;
  }
  var resp = qp.get('SAMLResponse');
  if (resp) {
    var qs = 'SAMLResponse=' + encodeURIComponent(resp);
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
    setVal('srd_input', seeded);
    decode();
  } else {
    setStatus('Paste a SAML response above and click Decode.');
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
  validateSignatures,
  viewSignerCert,
  decrypt
};
