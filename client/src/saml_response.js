// File: saml_response.js
// Author: Robert C. Broeckelmann Jr.
//
// SAML Response debugger page. It shows the full IdP response, the extracted
// assertion, and the assertion attributes (incl. NameID) in a table.
//
// Four ways the response reaches this page, all handled below:
//
//   ?id=<stash>       the API ACS (/samlacs) captured the IdP's POST server-side
//                     and stashed the XML; fetched here with GET
//                     /samlresponse?id=.
//   ?posted=1         the STATIC deployments' Lambda@Edge ACS
//                     (infra/edge/saml_landing.js) captured the POST at the
//                     edge and, having nowhere to stash it, handed it to the
//                     browser in sessionStorage under the edge_landing.js SAML
//                     keys. Read ONCE and deleted — a response left behind
//                     would make the next visit render a stale login as though
//                     it had just happened. The value arrives still
//                     base64-encoded, exactly as the IdP sent it, and goes
//                     through the same decodeSamlParam() as the query-string
//                     form.
//   ?SAMLResponse=    the HTTP-Redirect binding delivering straight to this page,
//                     which is what a deployment with no ACS landing asks the
//                     IdP for (responseProtocolBinding() in saml_request.js).
//                     Also useful for pasting a response in by hand.
//   none              nothing arrived; the last rendered response is restored
//                     from localStorage, or paste one in.
//
// ---------------------------------------------------------------------------
// IT READS BOTH PROTOCOL VERSIONS, AND SAML 1.1 IS NOT SAML 2.0 WITH OLDER
// NAMES. Every field this page shows is spelled differently there, and each of
// the differences below produced a blank cell rather than an error when this
// file knew only 2.0:
//
//   the message id        ResponseID, not ID
//   the version           MajorVersion="1" MinorVersion="1", not Version="2.0"
//   the issuer            an ATTRIBUTE on the message and on the assertion,
//                         not a <saml:Issuer> child element
//   where it was sent     Recipient, not Destination
//   the status code       a **QName** (`samlp:Success`), resolved against the
//                         document's namespace declarations — NOT a URI. This
//                         is the one that matters most: `Value` ends in
//                         ":status:Success" in 2.0 and in ":Success" in 1.1,
//                         so a check written for one reads the other as a
//                         failure and the Operations History row goes red on a
//                         sign-in that worked.
//   the assertion id      AssertionID, not ID
//   the subject           <saml:NameIdentifier>, not <saml:NameID>
//   the audience          <saml:AudienceRestrictionCondition>, not
//                         <saml:AudienceRestriction>
//   an attribute's name   AttributeName + AttributeNamespace, two halves of
//                         what 2.0 spells as one Name
//   how it was confirmed  <saml:ConfirmationMethod> — and in the browser
//                         profiles it IS the profile: cm:artifact for
//                         Browser/Artifact, cm:bearer for Browser/POST
//
// There is no Single Logout in SAML 1.1, so a 1.1 message is always a login
// Response and nothing here saves a subject for a logout that cannot happen.

var appconfig = require(process.env.CONFIG_FILE);
var history = require("./saml_history");
var bunyan = require("bunyan");
var xd = require("./xmldsig");
var edge = require("./edge_landing"); // the static landings' hand-off contract
var log = bunyan.createLogger({ name: 'saml_response',
    level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// Signer certificate extracted from the response-level <Signature>; handed to
// the certificate-details page via localStorage when "View" is clicked.
var responseSignerCertPem = '';

// The last successfully-rendered SAMLResponse/LogoutResponse XML, cached in
// localStorage so returning to this page (e.g. from the certificate-details
// page, which drops the ?id= query param) can repopulate the fields.
var SAML_RESP_KEY = 'saml_last_response';

// The extracted <Assertion> as originally serialized (NOT the pretty-printed
// textarea value, whose added whitespace would break canonicalization) — used
// by the signature-validation option.
var lastAssertionXml = '';

// The first <xenc:EncryptedData> in the response (an EncryptedAssertion, or a
// message/wrapper-level EncryptedData), serialized — used by the decrypt
// option.
var lastEncryptedXml = '';

// SAML 1.0/1.1 protocol and assertion namespaces. Both carry `1.0` and that is
// not a typo: the schemas were never renamed between 1.0 and 1.1 — the version
// travels in MajorVersion/MinorVersion attributes instead.
var NS_SAML1P = 'urn:oasis:names:tc:SAML:1.0:protocol';

// The version of a SAML protocol message or assertion, as "2.0" or "1.1"
// ("1.0" for a MinorVersion of 0). Read off the element rather than guessed
// from the namespace, because MajorVersion/MinorVersion is where SAML 1.x puts
// it and a 1.0 document and a 1.1 one share every namespace they have.
function samlVersionOf(elem) {
  log.debug("Entering samlVersionOf().");
  if (!elem || !elem.getAttribute) {
    log.debug("Leaving samlVersionOf(). No element.");
    return '';
  }
  var v = elem.getAttribute('Version');
  if (v) {
    log.debug("Leaving samlVersionOf(). From Version.");
    return v;
  }
  var major = elem.getAttribute('MajorVersion');
  var minor = elem.getAttribute('MinorVersion');
  if (major) {
    log.debug("Leaving samlVersionOf(). From MajorVersion/MinorVersion.");
    return major + '.' + (minor || '0');
  }
  // Nothing said. A SAML 1.x namespace is the only remaining evidence, and it
  // cannot tell 1.0 from 1.1 — so say 1.x rather than pick one.
  if (elem.namespaceURI === NS_SAML1P) {
    log.debug("Leaving samlVersionOf(). From the namespace alone.");
    return '1.x';
  }
  log.debug("Leaving samlVersionOf(). Unknown.");
  return '';
}

function isSaml1(version) {
  log.debug("Entering isSaml1().");
  log.debug("Leaving isSaml1().");
  return String(version || '').charAt(0) === '1';
}

// WHETHER A STATUS SAYS SUCCESS, in either version's spelling — and this is the
// single most consequential difference between them on this page.
//
// SAML 2.0's StatusCode/@Value is a URI ending
// `:status:Success`. SAML 1.1's is a **QName**: `samlp:Success`, resolved
// against the namespace declarations in scope, so what a strict reader sees is
// `{urn:oasis:names:tc:SAML:1.0:protocol}Success`. The old check was
// `indexOf(':status:Success') >= 0`, which is false for every SAML 1.1
// success — so a sign-in that worked rendered a red status and closed its
// Operations History row as a FAILURE, which is the worst possible way to be
// wrong about a working flow.
//
// Matching the LOCAL PART after the last colon covers both and refuses a
// lookalike: `Success` as the whole value, `samlp:Success` as a QName, and
// `urn:…:status:Success` as a URI all pass, while `RequesterSuccess` or a
// status message containing the word does not.
function isSuccessStatus(value) {
  log.debug("Entering isSuccessStatus().");
  var text = String(value || '');
  var local = text.substring(text.lastIndexOf(':') + 1);
  log.debug("Leaving isSuccessStatus().");
  return local === 'Success';
}

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}
function setVal(id, v) {
  log.debug("Entering setVal().");
  var e = el(id);
  if (e) e.value = (v == null ? '' : v);
  log.debug("Leaving setVal().");
}
function setStatus(msg) {
  log.debug("Entering setStatus().");
  setVal('saml_resp_status', msg);
  log.debug("Leaving setStatus().");
}
function esc(s) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function qp(name) {
  log.debug("Entering qp().");
  log.debug("Leaving qp().");
  return new URLSearchParams(window.location.search).get(name);
}
function tags(root, localName) {
  log.debug("Entering tags().");
  log.debug("Leaving tags().");
  return root.getElementsByTagNameNS('*', localName);
}

// Minimal, dependency-free XML pretty-printer.
function formatXml(xml) {
  log.debug("Entering formatXml().");
  if (!xml) {
    log.debug("Leaving formatXml().");
    return '';
  }
  var reg = /(>)(<)(\/*)/g;
  xml = xml.replace(reg, '$1\n$2$3');
  var pad = 0, out = '';
  xml.split('\n').forEach(function (node) {
    var indent = 0;
    if (/^<\/\w/.test(node)) { pad = Math.max(pad - 1, 0); }
    else if (/^<\w[^>]*[^\/]>.*$/.test(node) && !/<\/\w/.test(node)) { indent =
             1; }
    out += new Array(pad + 1).join('  ') + node + '\n';
    pad += indent;
  });
  log.debug("Leaving formatXml().");
  return out.trim();
}

function serialize(node) {
  log.debug("Entering serialize().");
  try {
    log.debug("Leaving serialize().");
    return new XMLSerializer().serializeToString(node);
  } catch (e) {
    log.debug("Leaving serialize().");
    return '';
  }
}

// --- decoding a SAMLResponse handed in via the URL query --------------------
// Backendless (static) deployments have no ACS server: the IdP is asked to
// return its response over the HTTP-Redirect binding, so it arrives here as a
// GET ?SAMLResponse= parameter that we decode in the browser. Redirect-binding
// messages are DEFLATE-compressed then base64-encoded; POST-binding messages
// (or a value pasted in for manual testing) are just base64. decodeSamlParam()
// tries inflate first and falls back to a plain base64 decode.
function base64ToBytes(b64) {
  log.debug("Entering base64ToBytes().");
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  log.debug("Leaving base64ToBytes().");
  return bytes;
}
function bytesToUtf8(bytes) {
  log.debug("Entering bytesToUtf8().");
  try {
    log.debug("Leaving bytesToUtf8().");
    return new TextDecoder('utf-8').decode(bytes);
  } catch (e) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    try {
      log.debug("Leaving bytesToUtf8().");
      return decodeURIComponent(escape(s));
    } catch (e2) {
      // Not UTF-8 after all: hand back the byte-per-character reading.
      log.debug("Leaving bytesToUtf8().");
      return s;
    }
  }
  log.debug("Leaving bytesToUtf8().");
}
// RAW DEFLATE inflate (no zlib header) via the native DecompressionStream — the
// mirror of the deflate-raw saml_request.js uses to build a Redirect request.
function inflateRaw(bytes) {
  log.debug("Entering inflateRaw().");
  if (typeof DecompressionStream === 'undefined') {
    log.debug("Leaving inflateRaw().");
    return Promise.reject(new Error('This browser lacks DecompressionStream; ' +
                          'cannot inflate a Redirect-binding response.'));
  }
  var ds = new DecompressionStream('deflate-raw');
  var writer = ds.writable.getWriter();
  writer.write(bytes);
  writer.close();
  log.debug("Leaving inflateRaw().");
  return new Response(ds.readable).arrayBuffer().then(function (buf) {
    return bytesToUtf8(new Uint8Array(buf));
  });
}
function decodeSamlParam(b64) {
  log.debug("Entering decodeSamlParam().");
  var bytes;
  try {
    bytes = base64ToBytes(b64);
  } catch (e) {
    log.debug("Leaving decodeSamlParam().");
    return Promise.reject(new Error('not valid base64: ' + e.message));
  }
  log.debug("Leaving decodeSamlParam().");
  return inflateRaw(bytes)
    // A successful inflate that yields XML is a Redirect-binding message; if
    // the bytes weren't actually deflated, treat the base64 as a raw (POST)
    // message.
    .then(function (xml) { return (xml && xml.indexOf('<') >= 0) ?
        xml : bytesToUtf8(bytes); })
    .catch(function () { return bytesToUtf8(bytes); });
}

// ---------------------------------------------------------------------------
// Operations History (shared with saml_request.html): the request page can only
// record that a call was dispatched — the IdP's verdict arrives here. Close out
// the pending entry with the top-level <samlp:StatusCode>.
// ---------------------------------------------------------------------------
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

function resolveHistoryFromStatus(doc, msgType) {
  log.debug("Entering resolveHistoryFromStatus().");
  // A LogoutResponse answers the Single Logout; anything else answers the
  // AuthnRequest.
  var operation = (msgType === 'LogoutResponse') ?
      'Single Logout' : 'Send AuthnRequest';
  var statusEl = tags(doc, 'Status')[0];
  var codes = statusEl ? tags(statusEl, 'StatusCode') : [];
  var top = codes.length ? (codes[0].getAttribute('Value') || '') : '';
  var sub = codes.length > 1 ? (codes[1].getAttribute('Value') || '') : '';
  var smEl = statusEl ? tags(statusEl, 'StatusMessage')[0] : null;
  var message = smEl ? (smEl.textContent || '').trim() : '';

  if (!top) {
    history.resolvePending(history.FAILURE,
                           'the response carries no <samlp:Status>.',
                           operation);
    renderOperationHistory();
    log.debug("Leaving resolveHistoryFromStatus().");
    return;
  }
  if (isSuccessStatus(top)) {
    history.resolvePending(history.SUCCESS, 'IdP returned Success', operation);
    renderOperationHistory();
    log.debug("Leaving resolveHistoryFromStatus().");
    return;
  }
  var detail = 'IdP returned ' + shortStatus(top);
  if (sub) detail += ' / ' + shortStatus(sub);
  if (message) detail += ' — ' + message;
  history.resolvePending(history.FAILURE, detail, operation);
  renderOperationHistory();
  log.debug("Leaving resolveHistoryFromStatus().");
}

// The answer never arrived (or could not be read) — the call still failed.
function resolveHistoryUnreadable(reason) {
  log.debug("Entering resolveHistoryUnreadable().");
  history.resolvePending(history.FAILURE, reason);
  renderOperationHistory();
  log.debug("Leaving resolveHistoryUnreadable().");
}

function render(responseXml, isFresh) {
  log.debug("Entering render().");
  setVal('saml_resp_xml', formatXml(responseXml));

  var doc = new DOMParser().parseFromString(responseXml, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    setStatus('Response received, but XML is malformed.');
    if (isFresh) resolveHistoryUnreadable('the IdP response was ' +
        'malformed XML.');
    log.debug("Leaving render().");
    return;
  }

  // Cache so a return trip to this page (which may lack the ?id=) repopulates.
  try {
    if (window.localStorage) localStorage.setItem(SAML_RESP_KEY, responseXml);
  } catch (e) {
    // No storage available in this context.
  }

  // The root element is the protocol message: <Response> (login) or
  // <LogoutResponse> (SLO) — both carry Version/IssueInstant/InResponseTo/ID/
  // Issuer/Signature/Status; only a login Response carries an <Assertion>.
  var msgType = doc.documentElement ? doc.documentElement.localName : '';
  var isLogout = msgType === 'LogoutResponse';
  var version = samlVersionOf(doc.documentElement);

  buildResponseDetailsTable(doc);

  var assertion = tags(doc, 'Assertion')[0];
  var assertionXml = assertion ? serialize(assertion) : '';
  lastAssertionXml = assertionXml;

  // Detect an encrypted assertion / message-level EncryptedData for the decrypt
  // option (the response may carry <saml:EncryptedAssertion> instead of a
  // plaintext <Assertion>). Prefer the <saml:EncryptedAssertion> wrapper (it
  // also contains any sibling <xenc:EncryptedKey> referenced by
  // RetrievalMethod), else the bare EncryptedData.
  var encEl = tags(doc, 'EncryptedAssertion')[0] || tags(doc,
      'EncryptedData')[0];
  lastEncryptedXml = encEl ? serialize(encEl) : '';
  if (encEl && !assertion) {
    setVal('saml_dec_status', 'Response contains encrypted content — ' +
           'paste/confirm the recipient key and click Decrypt.');
  }
  var noAssertionNote = isLogout
    ? '(LogoutResponse carries no assertion — see the Details tab for the logout status.)'
    : (isSaml1(version)
       ? '(no <saml:Assertion> — the Response carries a status and nothing ' +
         'else. SAML 1.1 has no encrypted assertion in the browser profiles, ' +
         'so this is an error rather than something to decrypt; see the ' +
         'Details tab.)'
       : '(no <Assertion> — the response may be an error or encrypted)');
  setVal('saml_assertion_xml', assertionXml ?
         formatXml(assertionXml) : noAssertionNote);

  buildAttributesTable(assertion);
  saveSubjectForLogout(assertion);
  if (isSaml1(version)) {
    // Not a warning and not an omission: SAML 1.1 has no Single Logout, so
    // there is nothing on the request page for a saved subject to drive. Said
    // here so the absence of the usual "logout is ready" state is explained on
    // the page rather than discovered on the other one.
    log.info('A SAML ' + version + ' Response was rendered. No subject was ' +
             'saved for Single Logout: SAML 1.1 has no logout message and no ' +
             'endpoint for one.');
  }
  // Only a response that just arrived closes out a pending Operations History
  // entry; a cached one redisplayed on a later visit says nothing about it.
  if (isFresh) resolveHistoryFromStatus(doc, msgType);
  setStatus((msgType || 'Response') + ' loaded.');
  log.debug("Leaving render().");
}

// Persist the NameID + SessionIndex so the config page's Single Logout can
// build a LogoutRequest for this session.
function saveSubjectForLogout(assertion) {
  log.debug("Entering saveSubjectForLogout().");
  if (!assertion || !window.localStorage) {
    log.debug("Leaving saveSubjectForLogout().");
    return;
  }
  // ONLY SAML 2.0 WRITES HERE. A SAML 1.1 assertion has a subject and a session
  // of a sort, and there is no LogoutRequest in that protocol to spend them on
  // — writing them would leave the request page's Logout button looking armed
  // on a version where it is disabled, and would overwrite a genuine 2.0
  // session's NameID with one that cannot log anything out.
  if (isSaml1(samlVersionOf(assertion))) {
    log.debug("Leaving saveSubjectForLogout(). SAML 1.x has no Single Logout.");
    return;
  }
  var subj = tags(assertion, 'Subject')[0];
  var nameId = subj ? tags(subj, 'NameID')[0] : null;
  if (nameId) {
    localStorage.setItem('saml_last_nameid', (nameId.textContent || '').trim());
    localStorage.setItem('saml_last_nameid_format',
                         nameId.getAttribute('Format') || '');
  }
  var authn = tags(assertion, 'AuthnStatement')[0];
  if (authn) localStorage.setItem('saml_last_session_index',
      authn.getAttribute('SessionIndex') || '');
  log.debug("Leaving saveSubjectForLogout().");
}

function row(cells) {
  log.debug("Entering row().");
  log.debug("Leaving row().");
  return '<tr>' + cells.map(function (c) { return '<td>' + c +
      '</td>'; }).join('') + '</tr>';
}

function buildAttributesTable(assertion) {
  log.debug("Entering buildAttributesTable().");
  var container = el('saml_attrs_table');
  if (!assertion) {
    container.innerHTML = '<em>No assertion available.</em>';
    log.debug("Leaving buildAttributesTable().");
    return;
  }

  var version = samlVersionOf(assertion);
  var saml1 = isSaml1(version);

  var html = '<table class="saml-table"><tr><th>Name</th><th>Value(s)</th><th>Format</th><th>FriendlyName</th></tr>';

  // Assertion metadata. SAML 1.1 spells the id `AssertionID` and carries the
  // issuer as an ATTRIBUTE rather than a child element, so both are read here
  // — a 2.0-only reader shows an empty cell for each and says nothing about
  // why.
  html += row(['<span class="saml-key">Assertion ID</span>',
              esc(assertion.getAttribute('ID') ||
                  assertion.getAttribute('AssertionID') || ''), '', '']);
  if (version) {
    html += row(['<span class="saml-key">Assertion Version</span>',
                esc(version), '', '']);
  }
  if (saml1 && assertion.getAttribute('Issuer')) {
    html += row(['<span class="saml-key">Assertion Issuer</span>',
                esc(assertion.getAttribute('Issuer')), '', '']);
  }
  html += row(['<span class="saml-key">IssueInstant</span>',
              esc(assertion.getAttribute('IssueInstant') || ''), '', '']);

  // Conditions: validity window plus every restriction (Audience, etc.).
  // Wrapped so an unexpected condition shape can never blank the whole table
  // (which would drop the NameID/attribute rows built below).
  try {
    var cond = tags(assertion, 'Conditions')[0];
    if (cond) {
      if (cond.getAttribute('NotBefore')) {
        html += row(['<span class="saml-key">Conditions NotBefore</span>',
                    esc(cond.getAttribute('NotBefore')), '', '']);
      }
      if (cond.getAttribute('NotOnOrAfter')) {
        html += row(['<span class="saml-key">Conditions NotOnOrAfter</span>',
                    esc(cond.getAttribute('NotOnOrAfter')), '', '']);
      }
      var cc = cond.firstChild;
      while (cc) {
        if (cc.nodeType === 1) {
          if (cc.localName === 'AudienceRestriction' ||
              cc.localName === 'AudienceRestrictionCondition') {
            var auds = tags(cc, 'Audience'), list = [];
            for (var ci = 0; ci < auds.length; ci++) { list.push(esc((auds[ci]
                 .textContent || '').trim())); }
            // Labelled with the element's OWN name rather than a fixed string:
            // SAML 1.1 spells it AudienceRestrictionCondition and 2.0 spells it
            // AudienceRestriction, and which one arrived is exactly the kind of
            // thing somebody reads this table to find out. A fixed label would
            // report a 1.1 document in 2.0's vocabulary.
            html += row(['<span class="saml-key">Condition: ' +
                        esc(cc.localName) + '</span>', list.join('<br>'), '',
                        '']);
          } else {
            html += row(['<span class="saml-key">Condition: ' +
                        esc(cc.localName) + '</span>', esc((cc.textContent ||
                        '').trim()) || '(present)', '', '']);
          }
        }
        cc = cc.nextSibling;
      }
    }
  } catch (e) {
    log.error('buildAttributesTable conditions: ' + e.message);
  }

  // The subject, shown first. <saml:NameID> in SAML 2.0 and
  // <saml:NameIdentifier> in 1.1 — a different element, not a renamed
  // attribute, so a reader that knows one finds nothing in the other and the
  // table renders without the row every SSO test looks for.
  var subj = tags(assertion, 'Subject')[0];
  if (subj) {
    var nameId = tags(subj, 'NameID')[0] || tags(subj, 'NameIdentifier')[0];
    if (nameId) {
      html += row([
        '<span class="saml-key">NameID</span>',
        esc((nameId.textContent || '').trim()),
        esc(nameId.getAttribute('Format') || ''),
        esc(nameId.getAttribute('NameQualifier') || '')
      ]);
    }
    // HOW THE ASSERTION CLAIMS TO HAVE ARRIVED, which in the SAML 1.1 browser
    // profiles IS the profile: saml-profile-1.1 section 4.1.1.4 requires
    // cm:artifact for Browser/Artifact and 4.2.1.4 requires cm:bearer for
    // Browser/POST. A relying party that does not check works perfectly with
    // either, which is exactly why it is worth showing.
    var cms = tags(subj, 'ConfirmationMethod');
    for (var c = 0; c < cms.length; c++) {
      html += row(['<span class="saml-key">ConfirmationMethod</span>',
                  esc((cms[c].textContent || '').trim()), '', '']);
    }
  }

  // The authentication statement. SAML 1.1 puts the method and the instant on
  // <saml:AuthenticationStatement>; SAML 2.0 spells them as a child
  // <saml:AuthnContextClassRef> and an AuthnInstant attribute, which the
  // Details tab already covers for that version.
  var authnStmt = tags(assertion, 'AuthenticationStatement')[0];
  if (authnStmt) {
    html += row(['<span class="saml-key">AuthenticationMethod</span>',
                esc(authnStmt.getAttribute('AuthenticationMethod') || ''),
                '', '']);
    html += row(['<span class="saml-key">AuthenticationInstant</span>',
                esc(authnStmt.getAttribute('AuthenticationInstant') || ''),
                '', '']);
    var locality = tags(authnStmt, 'SubjectLocality')[0];
    if (locality) {
      html += row(['<span class="saml-key">SubjectLocality</span>',
                  esc((locality.getAttribute('IPAddress') || '') +
                      (locality.getAttribute('DNSAddress') ?
                       ' / ' + locality.getAttribute('DNSAddress') : '')),
                  '', '']);
    }
  }

  // Attributes from every AttributeStatement. SAML 1.1 splits what 2.0 spells
  // as one `Name` URI into `AttributeName` and `AttributeNamespace`, so the
  // name column joins them the way the claim URI they came from was written
  // and the format column shows the namespace half on its own.
  var attrs = tags(assertion, 'Attribute');
  for (var i = 0; i < attrs.length; i++) {
    var a = attrs[i];
    var vals = tags(a, 'AttributeValue');
    var valStrs = [];
    for (var j =
         0; j < vals.length; j++) { valStrs.push(esc((vals[j].textContent ||
         '').trim())); }
    var ns = a.getAttribute('AttributeNamespace') || '';
    var name = a.getAttribute('Name') || a.getAttribute('AttributeName') || '';
    var shown = (ns && !a.getAttribute('Name'))
      ? (ns.replace(/\/$/, '') + '/' + name)
      : name;
    html += row([
      esc(shown),
      valStrs.join('<br>'),
      esc(a.getAttribute('NameFormat') || ns),
      esc(a.getAttribute('FriendlyName') || '')
    ]);
  }
  html += '</table>';
  container.innerHTML = html;
  log.debug("Leaving buildAttributesTable().");
}

// Two-column key/value row (value may already contain HTML).
function kv(k, v) {
  log.debug("Entering kv().");
  log.debug("Leaving kv().");
  return '<tr><td class="saml-key">' + esc(k) + '</td><td>' + v + '</td></tr>';
}

// Text of a direct-child element by local name (avoids grabbing a nested
// element of the same name, e.g. the assertion's Issuer vs the response's).
function directChildText(parent, localName) {
  log.debug("Entering directChildText().");
  var kids = parent.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === localName) {
      log.debug("Leaving directChildText().");
      return (kids[i].textContent || '').trim();
    }
  }
  log.debug("Leaving directChildText().");
  return '';
}

// The X509Certificate from the response-level <Signature> (a direct child of
// <Response>), not the assertion's signature.
function responseSignerCert(responseEl) {
  log.debug("Entering responseSignerCert().");
  var kids = responseEl.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === 'Signature') {
      var c = tags(kids[i], 'X509Certificate')[0];
      log.debug("Leaving responseSignerCert().");
      return c ? (c.textContent || '').replace(/\s+/g, '') : '';
    }
  }
  log.debug("Leaving responseSignerCert().");
  return '';
}

function buildResponseDetailsTable(doc) {
  log.debug("Entering buildResponseDetailsTable().");
  var container = el('saml_resp_details');
  // The document root is the protocol message (Response / LogoutResponse / …).
  var msg = doc.documentElement;
  if (!msg) {
    container.innerHTML = '<em>No SAML message element found.</em>';
    log.debug("Leaving buildResponseDetailsTable().");
    return;
  }

  var certB64 = responseSignerCert(msg);
  responseSignerCertPem = certB64; // saml_cert.js accepts bare base64 DER

  var certCell;
  if (certB64) {
    certCell = '<a href="/saml_cert.html?from=saml_response.html" ' +
        'onclick="return saml_response.viewSignerCert();">View certificate ' +
        'details &rarr;</a>' +
      '<div style="word-break:break-all; font-size:0.85em; margin-top:4px;">' +
      esc(certB64.substring(0, 96)) + (certB64.length > 96 ? '…' : '') +
          '</div>';
  } else {
    certCell = '<em>(not signed / no certificate)</em>';
  }

  // EVERY ROW BELOW IS SPELLED DIFFERENTLY IN THE TWO VERSIONS, so each reads
  // both. What SAML 1.1 does NOT have is worth as much as what it has: no
  // Destination (it has Recipient, which names where the response was sent),
  // and no <saml:Issuer> element — the issuer is an attribute, and on a
  // Browser/POST Response there is often none at all, because the assertion
  // inside carries it.
  var version = samlVersionOf(msg);
  var html = '<table class="saml-table">';
  html += kv('Message Type', esc(msg.localName || ''));
  html += kv('SAML Version', esc(version));
  html += kv('Issue Date (IssueInstant)',
             esc(msg.getAttribute('IssueInstant') || ''));
  html += kv('In Response To', esc(msg.getAttribute('InResponseTo') || ''));
  html += kv('ID', esc(msg.getAttribute('ID') ||
                       msg.getAttribute('ResponseID') || ''));
  var dest = msg.getAttribute('Destination') || '';
  if (dest) html += kv('Destination', esc(dest));
  var recipient = msg.getAttribute('Recipient') || '';
  if (recipient) html += kv('Recipient', esc(recipient));
  // The assertion's issuer stands in when the message has none, which is the
  // ordinary case on a SAML 1.1 Browser/POST Response — an empty Issuer row
  // over a signed assertion reads as an unidentified identity provider.
  var issuer = directChildText(msg, 'Issuer') ||
      msg.getAttribute('Issuer') || '';
  if (!issuer) {
    var firstAssertion = tags(msg, 'Assertion')[0];
    if (firstAssertion) {
      issuer = firstAssertion.getAttribute('Issuer') ||
          directChildText(firstAssertion, 'Issuer') || '';
    }
  }
  html += kv('Issuer', esc(issuer));
  html += kv('Signer Certificate', certCell);
  html += kv('SAML Status', statusHtml(msg));
  html += '</table>';
  container.innerHTML = html;
  log.debug("Leaving buildResponseDetailsTable().");
}

// Render <samlp:Status>: a colored friendly label for the top-level StatusCode,
// the full code URI, an optional nested (second-level) StatusCode, and any
// StatusMessage — this is the key result for a LogoutResponse and error
// responses.
function statusHtml(msg) {
  log.debug("Entering statusHtml().");
  var statusEl = tags(msg, 'Status')[0];
  if (!statusEl) {
    log.debug("Leaving statusHtml().");
    return '<em>(no Status)</em>';
  }
  var codes = tags(statusEl, 'StatusCode');
  var top = codes[0] ? (codes[0].getAttribute('Value') || '') : '';
  var sub = codes[1] ? (codes[1].getAttribute('Value') || '') : '';
  var smEl = tags(statusEl, 'StatusMessage')[0];
  var sm = smEl ? (smEl.textContent || '').trim() : '';

  var isSuccess = isSuccessStatus(top);
  var out = '<strong style="color:' + (isSuccess ? '#2e7d32' : '#b00') + ';">' +
      esc(shortStatus(top)) + '</strong>';
  if (top) out += ' <span style="color:#888; word-break:break-all;">' +
      esc(top) + '</span>';
  if (sub) out += '<br>Sub-status: ' + esc(sub);
  if (sm) out += '<br>Message: ' + esc(sm);
  log.debug("Leaving statusHtml().");
  return out;
}

// The readable part of a status code, in either version's spelling: the last
// segment of a SAML 2.0 URI (…:status:Success -> "Success") and the local part
// of a SAML 1.1 QName (samlp:Success -> "Success"). One rule covers both,
// because a colon is the separator in each — which is also why the full value
// is printed beside it: `Requester` means different things in the two and the
// short form alone does not say which was read.
function shortStatus(uri) {
  log.debug("Entering shortStatus().");
  if (!uri) {
    log.debug("Leaving shortStatus().");
    return '(none)';
  }
  var i = uri.lastIndexOf(':');
  log.debug("Leaving shortStatus().");
  return i >= 0 ? uri.substring(i + 1) : uri;
}

function viewSignerCert() {
  log.debug("Entering viewSignerCert().");
  if (!responseSignerCertPem) {
    log.debug("Leaving viewSignerCert().");
    return false;
  }
  try {
    if (window.localStorage) localStorage.setItem('saml_cert_view',
        responseSignerCertPem);
  } catch (e) {
    // No storage available in this context.
  }
  window.open('/saml_cert.html?from=saml_response.html', '_blank');
  log.debug("Leaving viewSignerCert().");
  return false;
}

// Tab switching scoped to the pane containing the clicked tab, so the two tab
// groups (SAMLResponse pane, Assertion pane) toggle independently.
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

// Repopulate from the last response saved in localStorage. Returns true if a
// cached response was found and rendered.
function renderFromStorage(msgIfMissing) {
  log.debug("Entering renderFromStorage().");
  var saved = null;
  try {
    saved = window.localStorage && localStorage.getItem(SAML_RESP_KEY);
  } catch (e) {
    saved = null;
  }
  if (saved) {
    render(saved);
    log.debug("Leaving renderFromStorage().");
    return true;
  }
  if (msgIfMissing) setStatus(msgIfMissing);
  log.debug("Leaving renderFromStorage().");
  return false;
}

// Render a signature-verification result (from xd.verifyXmlSignature) as a
// table.
function formatSigResult(res) {
  log.debug("Entering formatSigResult().");
  if (res.error) {
    log.debug("Leaving formatSigResult().");
    return '<span style="color:#b00;">Cannot validate: ' + esc(res.error) +
        '</span>';
  }
  var color = res.valid ? '#2e7d32' : '#b00';
  var refs = (res.references || []).length;
  var html = '<table class="saml-table">';
  html += '<tr><td class="saml-key">Signature</td><td><strong style="color:' +
      color + ';">' + (res.valid ? 'VALID' : 'INVALID') + '</strong></td></tr>';
  html += '<tr><td class="saml-key">SignatureValue</td><td>' +
      (res.signatureValid ? 'verified' : 'FAILED') + '</td></tr>';
  html += '<tr><td class="saml-key">Reference digests</td><td>' +
      (res.referencesValid ? 'match' : 'MISMATCH') + ' (' + refs +
      ')</td></tr>';
  html += '<tr><td class="saml-key">Signature Method</td><td>' +
      esc(res.signatureMethod || '') + '</td></tr>';
  html += '<tr><td class="saml-key">Canonicalization</td><td>' +
      esc(res.canonicalization || '') + '</td></tr>';
  html += '<tr><td class="saml-key">Signer (cert CN)</td><td>' +
      esc(res.signerSubject || '(from KeyInfo)') + '</td></tr>';
  html += '</table>';
  log.debug("Leaving formatSigResult().");
  return html;
}

// Validate the enveloped XML digital signature on the extracted assertion,
// using the certificate embedded in the signature's KeyInfo. Reuses xmldsig.js.
function validateAssertionSignature() {
  log.debug("Entering validateAssertionSignature().");
  var details = el('saml_sig_details');
  if (!lastAssertionXml || lastAssertionXml.indexOf('<') < 0) {
    setVal('saml_sig_status', 'No assertion available to validate.');
    if (details) details.innerHTML = '';
    log.debug("Leaving validateAssertionSignature().");
    return false;
  }
  var res;
  try {
    res = xd.verifyXmlSignature(lastAssertionXml);
  } catch (e) {
    setVal('saml_sig_status', 'Validation error: ' + e.message);
    log.debug("Leaving validateAssertionSignature().");
    return false;
  }
  setVal('saml_sig_status', res.error ? ('Cannot validate: ' +
         res.error) : (res.valid ?
         'Assertion signature VALID.' : 'Assertion signature INVALID.'));
  if (details) details.innerHTML = formatSigResult(res);
  log.debug("Leaving validateAssertionSignature().");
  return false;
}

// Decrypt an <xenc:EncryptedData> / <saml:EncryptedAssertion> in the response
// with the recipient (SP) private key, then show + re-render the plaintext
// assertion. Reuses xmldsig.js decryptXml.
function decryptAssertion() {
  log.debug("Entering decryptAssertion().");
  if (!lastEncryptedXml) {
    setVal('saml_dec_status', 'No <xenc:EncryptedData> / ' +
           '<saml:EncryptedAssertion> found in this response.');
    log.debug("Leaving decryptAssertion().");
    return false;
  }
  var keyEl = el('saml_dec_key');
  var key = keyEl ? keyEl.value : '';
  if (!key.trim()) {
    setVal('saml_dec_status',
           'Paste the recipient (SP) private key to decrypt.');
    log.debug("Leaving decryptAssertion().");
    return false;
  }
  var plaintext;
  try {
    plaintext = xd.decryptXml(lastEncryptedXml, { privateKeyPem: key });
  } catch (e) {
    setVal('saml_dec_status', 'Decryption failed: ' + e.message);
    log.debug("Leaving decryptAssertion().");
    return false;
  }
  lastAssertionXml = plaintext;
  setVal('saml_assertion_xml', formatXml(plaintext));
  try {
    var adoc = new DOMParser().parseFromString(plaintext, 'application/xml');
    var a = tags(adoc, 'Assertion')[0] || null;
    buildAttributesTable(a);
    saveSubjectForLogout(a);
  } catch (e) {
    log.error('decrypt render: ' + e.message);
  }
  setVal('saml_dec_status', 'Decrypted. The assertion is shown in the XML ' +
         'tab; use Validate Signature to verify it.');
  log.debug("Leaving decryptAssertion().");
  return false;
}

// ---------------------------------------------------------------------------
// The edge ACS's hand-off (static deployments — infra/edge/saml_landing.js).
//
// The value handed over is the SAMLResponse exactly as the IdP sent it: base64,
// and DEFLATE-compressed if it came over the Redirect binding.
// decodeSamlParam() already distinguishes the two — it is the decoder the
// ?SAMLResponse= path has always used — so nothing is decoded at the edge and
// there is one decoder here.
// ---------------------------------------------------------------------------
function handleEdgeHandoff(posted) {
  log.debug('Entering handleEdgeHandoff(). posted=' + posted);
  if (posted === 'blocked') {
    setStatus('The IdP\'s POST was captured at the edge, but this browser ' +
              'would not let that page store ' +
              'the response (sessionStorage is blocked), so it could not be ' +
                  'handed over. Capture the POST ' +
              'with the developer tools and paste the SAMLResponse below.');
    resolveHistoryUnreadable('the browser blocked the edge landing\'s ' +
                             'hand-off (sessionStorage).');
    log.debug("Leaving handleEdgeHandoff().");
    return;
  }
  var handoff = edge.takeHandoff({
    response: edge.SAML.responseKey,
    relayState: edge.SAML.relayStateKey
  });
  if (!handoff.ok) { log.error('handleEdgeHandoff: sessionStorage could ' +
      'not be read.'); }
  if (!handoff.response) {
    // Most often a reload: the response is deliberately read once and removed,
    // so say that rather than showing an empty page. Fall back to the cached
    // last response if there is one, exactly as the ?id= path does.
    if (!renderFromStorage()) {
      setStatus('The edge landing redirected here but no SAMLResponse was ' +
                'waiting in sessionStorage. ' +
                'A reload will do this — it is read once and removed. Sign ' +
                    'in again, or paste a ' +
                'response below.');
      resolveHistoryUnreadable('no SAMLResponse was waiting from the ' +
                               'edge landing.');
    }
    log.debug("Leaving handleEdgeHandoff().");
    return;
  }
  setStatus('Decoding SAMLResponse…');
  decodeSamlParam(handoff.response)
    .then(function (xml) { render(xml, true); })
    .catch(function (e) {
      log.error('decode edge SAMLResponse: ' + e.message);
      setStatus('Could not decode the SAMLResponse handed over by the edge ' +
                'landing: ' + e.message);
      resolveHistoryUnreadable('could not decode the IdP response: ' +
                               e.message);
    });
  log.debug('Leaving handleEdgeHandoff().');
}

window.onload = function () {
  log.debug("Entering onload().");
  renderOperationHistory();
  // Prefill the decryption key from the SP private key stored by the SAML Test
  // Tools page (the IdP encrypts to the SP's certificate).
  try {
    var dk = el('saml_dec_key');
    var sk = window.localStorage &&
        localStorage.getItem('samltools_saml_sp_private_key');
    if (dk && !dk.value && sk) dk.value = sk;
    // The Test Tools page can be told not to keep the key pair in localStorage,
    // in which case there is nothing to prefill from and the standing
    // "Prefilled from…" wording would be a promise this page did not keep. Say
    // what is actually true, so an empty field reads as expected rather than
    // broken. This page never WRITES the key: whatever is pasted here stays in
    // the field.
    var note = el('saml_dec_key_note');
    if (note && dk && !dk.value) {
      note.textContent =
          'If the response carries an EncryptedAssertion (or a message-level ' +
        'EncryptedData), decrypt it in the browser with the recipient (SP) ' +
            'private key. Nothing was ' +
        'prefilled — either no key pair has been generated yet, or "Save ' +
            'this key pair in browser ' +
        'localStorage" is turned off on the SAML Test Tools page. Paste the private key below.';
    }
  } catch (e) {
    // No storage, or nothing stashed by the SAML Test Tools page: the field is
    // simply left for the user to paste into.
  }

  // The static deployments' edge ACS hands the response over in sessionStorage
  // rather than by id — it has no server-side stash to put it in.
  var posted = qp(edge.SAML.handoffParam);
  if (posted) {
    handleEdgeHandoff(posted);
    log.debug("Leaving onload().");
    return;
  }

  var id = qp('id');
  var direct = qp('SAMLResponse');
  if (id) {
    setStatus('Loading response…');
    fetch(appconfig.apiUrl + '/samlresponse?id=' + encodeURIComponent(id))
      .then(function (r) { if (!r.ok) { throw new Error('HTTP ' +
          r.status); } return r.json(); })
      .then(function (j) {
        // Stash expired/unknown — fall back to the last response we cached.
        if (!j || !j.responseXml) {
          if (!renderFromStorage()) {
            setStatus('No response found for that id (it may have expired).');
            resolveHistoryUnreadable('no response was captured for that id.');
          }
          return;
        }
        render(j.responseXml, true);
      })
      .catch(function (e) {
        log.error('fetch response: ' + e.message);
        if (!renderFromStorage()) {
          setStatus('Failed to load response: ' + e.message);
          resolveHistoryUnreadable('could not load the IdP response: ' +
                                   e.message);
        }
      });
  } else if (direct) {
    setStatus('Decoding SAMLResponse…');
    decodeSamlParam(direct)
      .then(function (xml) { render(xml, true); })
      .catch(function (e) {
        log.error('decode SAMLResponse: ' + e.message);
        setStatus('Could not decode SAMLResponse parameter: ' + e.message);
        resolveHistoryUnreadable('could not decode the SAMLResponse: ' +
                                 e.message);
      });
  } else {
    // No id/param (e.g. returned from the certificate-details page, which drops
    // the ?id=) — repopulate the fields from the last cached response.
    renderFromStorage('No response id in the URL. Start from the SAML Test ' +
                      'Tools page and click "Call IdP".');
  }
  log.debug("Leaving onload().");
};

module.exports = {
  showTab,
  viewSignerCert,
  copyField,
  validateAssertionSignature,
  decryptAssertion,
  clearOperationHistory
};
