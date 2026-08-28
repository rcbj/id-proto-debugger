// File: saml_message.js
//
// READING a SAML protocol message off the wire — the half of the SAML pages
// that is not cryptography.
//
// The XML security is in common/xmldsig.js and stays there: this module signs
// nothing, verifies nothing and decrypts nothing. What it does is everything
// that has to happen BEFORE a signature can be checked or a key applied, and
// getting any of it wrong produces a clean "invalid signature" on a message
// that is perfectly good:
//
//   * work out which BINDING a blob arrived on, from the blob alone;
//   * undo the binding's encoding — base64, and RAW DEFLATE for Redirect;
//   * rebuild the signed octets of a Redirect message IN THE ORDER THEY WERE
//     SENT, which is the only order that verifies;
//   * pull apart a SAML artifact, which is not a message at all but 44 bytes
//     of binary;
//   * summarise a request message's important values in both protocol
//     versions.
//
// IT IS SHARED, AND THE DUPLICATION IT ENDS WAS REAL. formatXml() existed four
// times (saml_response.js, wsfed_response.js, wstrust_tools.js,
// wstrust_response.js — three of them byte-identical and the fourth differing
// only in whether the regex was held in a variable), and the base64 / inflate /
// decodeSamlParam set existed in saml_response.js, which is where this copy
// came from. A fifth copy for the AuthnRequest decoder is what this module
// exists to avoid.
//
// NO DOM IDS AND NO PAGE STATE. Everything here takes a string and returns a
// value, which is what lets tests/saml_message.js drive the whole of it in node
// with @xmldom standing in for the browser's parser — the only kind of check
// that catches a Redirect signature rebuilt in the wrong parameter order, since
// in a browser that failure is indistinguishable from a wrong key.
var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "saml_message",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// SAML 1.0/1.1 protocol namespace. It carries `1.0` in both versions and that
// is not a typo: the schemas were never renamed between 1.0 and 1.1 — the
// version travels in MajorVersion/MinorVersion attributes instead.
var NS_SAML1P = 'urn:oasis:names:tc:SAML:1.0:protocol';
var NS_SAML2P = 'urn:oasis:names:tc:SAML:2.0:protocol';

// ---------------------------------------------------------------------------
// Bytes, base64 and UTF-8.
// ---------------------------------------------------------------------------
function base64ToBytes(b64) {
  log.debug("Entering base64ToBytes().");
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  log.debug("Leaving base64ToBytes().");
  return bytes;
}

function bytesToBase64(bytes) {
  log.debug("Entering bytesToBase64().");
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  log.debug("Leaving bytesToBase64().");
  return btoa(bin);
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

function bytesToHex(bytes) {
  log.debug("Entering bytesToHex().");
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    out += ('0' + bytes[i].toString(16)).slice(-2);
  }
  log.debug("Leaving bytesToHex().");
  return out;
}

// Whether a string could be base64 at all. Deliberately permissive about
// whitespace and about base64url, because both turn up in a pasted blob: a
// SAMLRequest copied out of a URL bar arrives percent-decoded but a value
// copied out of a log may have been base64url-encoded by whatever wrote it.
function looksLikeBase64(text) {
  log.debug("Entering looksLikeBase64().");
  var t = String(text || '').replace(/\s+/g, '');
  if (!t) {
    log.debug("Leaving looksLikeBase64(). Empty.");
    return false;
  }
  var ok = /^[A-Za-z0-9+/_-]+={0,2}$/.test(t);
  log.debug("Leaving looksLikeBase64().");
  return ok;
}

// base64url -> base64, with the padding put back. atob() rejects `-` and `_`
// outright and rejects an unpadded length of 2 or 3 mod 4, so a value that was
// base64url-encoded somewhere upstream fails as "not valid base64" — a message
// about the encoding, on a blob whose encoding is fine.
function normalizeBase64(text) {
  log.debug("Entering normalizeBase64().");
  var t = String(text || '').replace(/\s+/g, '').replace(/-/g, '+')
      .replace(/_/g, '/');
  while (t.length % 4 !== 0) t += '=';
  log.debug("Leaving normalizeBase64().");
  return t;
}

// ---------------------------------------------------------------------------
// RAW DEFLATE (no zlib header), the Redirect binding's compression. The mirror
// of the deflate-raw saml_request.js uses to BUILD a Redirect request.
// ---------------------------------------------------------------------------
function inflateRaw(bytes) {
  log.debug("Entering inflateRaw().");
  if (typeof DecompressionStream === 'undefined') {
    log.debug("Leaving inflateRaw(). No DecompressionStream.");
    return Promise.reject(new Error('This browser lacks DecompressionStream; ' +
                          'cannot inflate a Redirect-binding message.'));
  }
  var ds = new DecompressionStream('deflate-raw');
  var writer = ds.writable.getWriter();
  // The failure this catch swallows is the ORDINARY case, not an exception:
  // every POST-binding message is plain base64, so the inflate attempt that
  // tells the two bindings apart is EXPECTED to fail about half the time.
  // The readable side's rejection is what the caller handles; these two are
  // the writable side reporting the same one error a second time, and left
  // alone they are an unhandled rejection in the console of a page that
  // worked. (Inherited from the copy in saml_response.js, where a decoded
  // POST message has always logged one.)
  var swallow = function () {};
  writer.write(bytes).catch(swallow);
  writer.close().catch(swallow);
  log.debug("Leaving inflateRaw().");
  return new Response(ds.readable).arrayBuffer().then(function (buf) {
    return bytesToUtf8(new Uint8Array(buf));
  });
}

// Decode a SAMLRequest / SAMLResponse parameter value. Redirect-binding
// messages are DEFLATE-compressed then base64-encoded; POST-binding messages
// (or a value pasted in by hand) are base64 only. Try inflate first and fall
// back to a plain base64 decode — a raw base64 XML document is not valid
// DEFLATE, and on the rare occasion it inflates to something, the result does
// not contain a `<`.
function decodeSamlParam(b64) {
  log.debug("Entering decodeSamlParam().");
  var bytes;
  try {
    bytes = base64ToBytes(normalizeBase64(b64));
  } catch (e) {
    log.debug("Leaving decodeSamlParam(). Not base64.");
    return Promise.reject(new Error('not valid base64: ' + e.message));
  }
  log.debug("Leaving decodeSamlParam().");
  return inflateRaw(bytes)
    .then(function (xml) { return (xml && xml.indexOf('<') >= 0) ?
        { xml: xml, deflated: true } : { xml: bytesToUtf8(bytes),
          deflated: false }; })
    .catch(function () { return { xml: bytesToUtf8(bytes),
        deflated: false }; });
}

// ---------------------------------------------------------------------------
// Pretty-printing. Minimal and dependency-free — this is the ONE copy; four
// pages carried their own until this module existed.
// ---------------------------------------------------------------------------
function formatXml(xml) {
  log.debug("Entering formatXml().");
  if (!xml) {
    log.debug("Leaving formatXml(). Empty.");
    return '';
  }
  xml = xml.replace(/(>)(<)(\/*)/g, '$1\n$2$3');
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

function parseXml(xml) {
  log.debug("Entering parseXml().");
  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    log.debug("Leaving parseXml(). Malformed.");
    return null;
  }
  log.debug("Leaving parseXml().");
  return doc;
}

function serialize(node) {
  log.debug("Entering serialize().");
  try {
    log.debug("Leaving serialize().");
    return new XMLSerializer().serializeToString(node);
  } catch (e) {
    // A node from a document this browser refused to parse. The caller shows
    // an empty pane rather than a stack trace.
    log.debug("Leaving serialize(). Not serializable.");
    return '';
  }
}

function tags(root, localName) {
  log.debug("Entering tags().");
  log.debug("Leaving tags().");
  return root.getElementsByTagNameNS('*', localName);
}

// ---------------------------------------------------------------------------
// WHICH BINDING DID THIS ARRIVE ON?
//
// The three the SAML browser profiles define look nothing alike on the wire,
// which is what makes detection possible from the blob alone:
//
//   Redirect   a GET. The message is a query PARAMETER, deflated then base64'd
//              then percent-encoded, beside RelayState / SigAlg / Signature.
//   POST       a form body. The message is a base64 parameter and is NOT
//              deflated; a signature, if any, is INSIDE the XML.
//   Artifact   a GET carrying SAMLart (2.0) or TARGET+SAMLart (1.1) — 44 bytes
//              of binary that REFERENCE a message held by the issuer. There is
//              no message here to decode at all, and saying that plainly is
//              more useful than an empty XML pane.
//
// The user may paste any of: a full URL, a bare query string, a form body, a
// bare base64 parameter value, or the XML itself. All five are handled, and the
// answer records which one it was — because "I pasted the XML" and "I pasted a
// POST body" want different things said about the signature.
// ---------------------------------------------------------------------------

// The parameter names the three bindings carry, in either protocol version.
// A blob with no endpoint in front of it is a parameter list when one of these
// is followed by an `=`, and the `=` is part of the test on purpose: base64
// padding is full of them, and a payload that happens to BEGIN with the
// letters SAML would otherwise be read as a parameter list with no parameters
// in it.
var BINDING_PARAMS = ['SAMLRequest', 'SAMLResponse', 'SAMLart', 'RelayState',
  'SigAlg', 'Signature', 'TARGET', 'shire', 'providerId'];
var BINDING_PARAM_RE = new RegExp('(^|&)(' + BINDING_PARAMS.join('|') + ')=');

// Split a query string into ordered [name, rawValue] pairs. ORDERED, and the
// values left percent-ENCODED, because that is what the Redirect signature is
// over: URLSearchParams would decode them and lose the exact octets.
function queryPairs(qs) {
  log.debug("Entering queryPairs().");
  var pairs = [];
  String(qs || '').split('&').forEach(function (part) {
    if (!part) return;
    var i = part.indexOf('=');
    if (i < 0) {
      pairs.push([part, '']);
      return;
    }
    pairs.push([part.substring(0, i), part.substring(i + 1)]);
  });
  log.debug("Leaving queryPairs().");
  return pairs;
}

function pairValue(pairs, name) {
  log.debug("Entering pairValue().");
  for (var i = 0; i < pairs.length; i++) {
    if (pairs[i][0] === name) {
      log.debug("Leaving pairValue(). Found.");
      return decodeURIComponent(pairs[i][1].replace(/\+/g, '%20'));
    }
  }
  log.debug("Leaving pairValue(). Absent.");
  return '';
}

// The octets a Redirect-binding signature is computed over: the parameters in
// the order they appear, still percent-encoded, with Signature itself removed.
// saml-bindings-2.0-os section 3.4.4.1 is explicit that the signature covers
// the query string AS SENT with SigAlg included, so anything that re-orders or
// decodes has produced a different message and gets a clean INVALID for a
// signature that is fine.
function redirectSignedOctets(pairs) {
  log.debug("Entering redirectSignedOctets().");
  var kept = pairs.filter(function (p) {
    return p[0] !== 'Signature' && (p[0] === 'SAMLRequest' ||
        p[0] === 'SAMLResponse' || p[0] === 'RelayState' ||
        p[0] === 'SigAlg');
  });
  var qs = kept.map(function (p) { return p[0] + '=' + p[1]; }).join('&');
  log.debug("Leaving redirectSignedOctets().");
  return qs;
}

// A SAML artifact: 44 bytes for SAML 2.0 type 0x0004, 42 for the SAML 1.1
// types. It is a REFERENCE, not a message — the SourceID identifies the issuer
// (SHA-1 of its entity ID in 2.0) and the MessageHandle is a one-shot ticket
// the issuer redeems over the SOAP back-channel. Nothing here can resolve one;
// showing what it says is the whole of what a decoder can do, and it is more
// than it looks: a SourceID that does not match the identity provider you think
// you are talking to is a complete diagnosis.
function parseArtifact(b64) {
  log.debug("Entering parseArtifact().");
  var bytes;
  try {
    bytes = base64ToBytes(normalizeBase64(b64));
  } catch (e) {
    log.debug("Leaving parseArtifact(). Not base64.");
    return { error: 'The artifact is not valid base64: ' + e.message };
  }
  if (bytes.length < 4) {
    log.debug("Leaving parseArtifact(). Too short.");
    return { error: 'An artifact is at least 4 bytes; this is ' +
             bytes.length + '.' };
  }
  var typeCode = (bytes[0] << 8) | bytes[1];
  var out = { typeCode: typeCode, length: bytes.length,
              raw: bytesToHex(bytes) };
  if (typeCode === 4) {
    // saml-bindings-2.0-os section 3.6.4.2: TypeCode 0x0004, EndpointIndex,
    // SourceId (20 bytes, SHA-1 of the issuer's entity ID), MessageHandle (20).
    out.type = 'SAML 2.0 type 0x0004';
    out.endpointIndex = (bytes[2] << 8) | bytes[3];
    out.sourceId = bytesToHex(bytes.subarray(4, 24));
    out.messageHandle = bytesToHex(bytes.subarray(24, 44));
    out.expectedLength = 44;
  } else if (typeCode === 1 || typeCode === 2) {
    // SAML 1.1 (cs-sstc-bindings-01 section 4.1.1): type 0x0001 is
    // SourceID + AssertionHandle, type 0x0002 is AssertionHandle +
    // SourceLocation (a URL, so the remainder is text rather than a handle).
    out.type = 'SAML 1.1 type 0x000' + typeCode;
    if (typeCode === 1) {
      out.sourceId = bytesToHex(bytes.subarray(2, 22));
      out.assertionHandle = bytesToHex(bytes.subarray(22, 42));
      out.expectedLength = 42;
    } else {
      out.assertionHandle = bytesToHex(bytes.subarray(2, 22));
      out.sourceLocation = bytesToUtf8(bytes.subarray(22));
    }
  } else {
    out.type = 'unrecognised (TypeCode 0x' +
        ('000' + typeCode.toString(16)).slice(-4) + ')';
  }
  if (out.expectedLength && out.expectedLength !== bytes.length) {
    out.warning = 'A ' + out.type + ' artifact is ' + out.expectedLength +
        ' bytes; this one is ' + bytes.length + '.';
  }
  log.debug("Leaving parseArtifact().");
  return out;
}

// Classify a pasted blob. Returns, always:
//   { kind, binding, pairs, message, relayState, sigAlg, signature,
//     artifact, target, direction, note }
// `kind` is what the user pasted ('url' | 'query' | 'param' | 'xml'); `binding`
// is what it says it arrived on ('redirect' | 'post' | 'artifact' | 'none').
// `message` is the still-encoded SAMLRequest/SAMLResponse value, if there is
// one. Nothing is decoded here — classification is synchronous and decoding is
// not.
function classify(text) {
  log.debug("Entering classify().");
  var raw = String(text || '').trim();
  var out = { kind: '', binding: 'none', pairs: [], message: '',
              relayState: '', sigAlg: '', signature: '', artifact: '',
              target: '', direction: '', note: '', endpoint: '' };
  if (!raw) {
    log.debug("Leaving classify(). Empty.");
    return out;
  }
  if (raw.charAt(0) === '<') {
    out.kind = 'xml';
    out.binding = 'post';
    out.message = '';
    out.xml = raw;
    out.note = 'Pasted as XML. A Redirect-binding message is signed over the ' +
        'query string rather than inside the document, so only an enveloped ' +
        '<ds:Signature> can be checked from XML alone.';
    log.debug("Leaving classify(). XML.");
    return out;
  }

  // A URL, or a bare query string / form body. Everything after the first `?`
  // is the query; a body has no `?` at all but does have `name=value&…`.
  var qs = raw, endpoint = '';
  var q = raw.indexOf('?');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    out.kind = 'url';
    endpoint = q >= 0 ? raw.substring(0, q) : raw;
    qs = q >= 0 ? raw.substring(q + 1) : '';
    // A fragment is not part of the query, and a message that ended up after a
    // `#` is a message nothing at the far end ever received.
    var hash = qs.indexOf('#');
    if (hash >= 0) qs = qs.substring(0, hash);
  } else if (q >= 0) {
    out.kind = 'url';
    endpoint = raw.substring(0, q);
    qs = raw.substring(q + 1);
  } else if (BINDING_PARAM_RE.test(raw)) {
    // A form body, or a query string with the endpoint already trimmed off.
    out.kind = 'query';
  } else {
    // No `=` anywhere: a bare parameter value, which is by far the commonest
    // thing to have on the clipboard.
    out.kind = 'param';
    out.message = raw;
    out.binding = 'post';
    out.note = 'Pasted as a bare parameter value. Whether it was deflated ' +
        '(Redirect) or not (POST) is decided by decoding it, not by this.';
    log.debug("Leaving classify(). Bare parameter.");
    return out;
  }

  out.endpoint = endpoint;
  out.pairs = queryPairs(qs);
  var req = pairValue(out.pairs, 'SAMLRequest');
  var resp = pairValue(out.pairs, 'SAMLResponse');
  out.relayState = pairValue(out.pairs, 'RelayState');
  out.sigAlg = pairValue(out.pairs, 'SigAlg');
  out.signature = pairValue(out.pairs, 'Signature');
  out.artifact = pairValue(out.pairs, 'SAMLart');
  out.target = pairValue(out.pairs, 'TARGET');
  if (req) {
    out.message = req;
    out.direction = 'request';
  } else if (resp) {
    out.message = resp;
    out.direction = 'response';
  }

  if (out.artifact) {
    out.binding = 'artifact';
    out.note = 'An artifact REFERENCES a message held by its issuer; the ' +
        'message itself travels over the SOAP back-channel and is not here.';
  } else if (out.message && out.kind === 'url') {
    // A GET carrying the message itself is the Redirect binding by definition —
    // the POST binding puts it in a form body, which has no endpoint in front
    // of it.
    out.binding = 'redirect';
  } else if (out.message) {
    out.binding = out.sigAlg ? 'redirect' : 'post';
    if (!out.sigAlg) {
      out.note = 'No SigAlg parameter, so this reads as a POST form body. A ' +
          'Redirect message that was never signed looks exactly the same ' +
          'here; the decode below tells the two apart, because only Redirect ' +
          'is DEFLATE-compressed.';
    }
  } else if (out.target) {
    out.binding = 'artifact';
    out.note = 'A SAML 1.1 TARGET with no SAMLart — an inter-site transfer ' +
        'request. SAML 1.1 has no request document at all, so there is ' +
        'nothing to decode; the parameters below are the whole message.';
  }
  log.debug("Leaving classify(). binding=" + out.binding);
  return out;
}

// ---------------------------------------------------------------------------
// The important values in a request message, in both protocol versions.
// ---------------------------------------------------------------------------

// The version of a SAML protocol message. Read off the element rather than
// guessed from the namespace, because MajorVersion/MinorVersion is where SAML
// 1.x puts it and a 1.0 document and a 1.1 one share every namespace they have.
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
  if (elem.namespaceURI === NS_SAML1P) {
    log.debug("Leaving samlVersionOf(). From the namespace alone.");
    return '1.x';
  }
  log.debug("Leaving samlVersionOf(). Unknown.");
  return '';
}

function directChild(parent, localName) {
  log.debug("Entering directChild().");
  var kids = parent ? parent.childNodes : [];
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === localName) {
      log.debug("Leaving directChild(). Found.");
      return kids[i];
    }
  }
  log.debug("Leaving directChild(). Absent.");
  return null;
}

function directChildText(parent, localName) {
  log.debug("Entering directChildText().");
  var kid = directChild(parent, localName);
  log.debug("Leaving directChildText().");
  return kid ? (kid.textContent || '').trim() : '';
}

// One row of the details table. `value` may be empty — the caller decides
// whether an absent optional attribute is worth a row, and mostly it is: on a
// request, "ForceAuthn: (absent)" and "ForceAuthn: false" mean the same thing
// to a specification and very different things to somebody who thinks they set
// it.
function push(rows, key, value, note) {
  log.debug("Entering push().");
  if (value === null || value === undefined || value === '') {
    log.debug("Leaving push(). Nothing to add.");
    return;
  }
  rows.push({ key: key, value: String(value), note: note || '' });
  log.debug("Leaving push().");
}

function attr(elem, name) {
  log.debug("Entering attr().");
  log.debug("Leaving attr().");
  return (elem && elem.getAttribute) ? (elem.getAttribute(name) || '') : '';
}

// The <saml:NameID> / <saml:NameIdentifier> inside a Subject, as a printable
// string. The two spellings are the 2.0 and 1.1 ones.
function subjectNameId(subject) {
  log.debug("Entering subjectNameId().");
  if (!subject) {
    log.debug("Leaving subjectNameId(). No Subject.");
    return null;
  }
  var nid = directChild(subject, 'NameID') ||
      directChild(subject, 'NameIdentifier');
  if (!nid) {
    log.debug("Leaving subjectNameId(). No NameID.");
    return null;
  }
  log.debug("Leaving subjectNameId().");
  return {
    value: (nid.textContent || '').trim(),
    format: attr(nid, 'Format'),
    nameQualifier: attr(nid, 'NameQualifier'),
    spNameQualifier: attr(nid, 'SPNameQualifier')
  };
}

// The <samlp:RequestedAuthnContext> class references, in order. The ORDER is
// the point: with Comparison="exact" an identity provider matches the list,
// and a debugger that sorted or de-duplicated them would hide the reason a
// request is being refused.
function authnContextRefs(req) {
  log.debug("Entering authnContextRefs().");
  var rac = directChild(req, 'RequestedAuthnContext');
  if (!rac) {
    log.debug("Leaving authnContextRefs(). Absent.");
    return null;
  }
  var refs = [];
  var kids = rac.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType !== 1) continue;
    if (kids[i].localName === 'AuthnContextClassRef' ||
        kids[i].localName === 'AuthnContextDeclRef') {
      refs.push((kids[i].textContent || '').trim());
    }
  }
  log.debug("Leaving authnContextRefs().");
  return { comparison: attr(rac, 'Comparison'), refs: refs };
}

// Whether the document carries XML Encryption, and the FIRST EncryptedData in
// it serialized — which is what a decryption pane operates on. An
// <saml:EncryptedID> inside a Subject counts: a request whose subject is
// encrypted is the ordinary reason an AuthnRequest needs a key at all.
function findEncrypted(doc) {
  log.debug("Entering findEncrypted().");
  if (!doc) {
    log.debug("Leaving findEncrypted(). No document.");
    return null;
  }
  var ed = tags(doc, 'EncryptedData')[0];
  if (!ed) {
    log.debug("Leaving findEncrypted(). None.");
    return null;
  }
  // The wrapped key may be a SIBLING of EncryptedData rather than a child of
  // its KeyInfo — the layout Keycloak and several other implementations emit —
  // so the serialized fragment has to be the enclosing element when there is
  // one, or xmldsig.js's decryptXml() finds the data and not the key.
  var container = ed.parentNode && ed.parentNode.nodeType === 1 &&
      tags(ed.parentNode, 'EncryptedKey').length &&
      !tags(ed, 'EncryptedKey').length ? ed.parentNode : ed;
  var out = {
    xml: serialize(container),
    wrapper: container === ed ? '' : container.localName,
    dataAlg: attr(directChild(ed, 'EncryptionMethod'), 'Algorithm'),
    type: attr(ed, 'Type')
  };
  var ek = tags(container, 'EncryptedKey')[0];
  out.keyAlg = ek ? attr(directChild(ek, 'EncryptionMethod'), 'Algorithm') : '';
  log.debug("Leaving findEncrypted().");
  return out;
}

// The enveloped <ds:Signature> that is a DIRECT CHILD of the message, and what
// it says about itself. A direct child, because a signature nested deeper
// belongs to something else — an assertion inside a response, most often — and
// reporting it as the message's signature is how a debugger tells somebody
// their unsigned request is signed.
function messageSignature(msg) {
  log.debug("Entering messageSignature().");
  var sig = directChild(msg, 'Signature');
  if (!sig) {
    log.debug("Leaving messageSignature(). Unsigned.");
    return null;
  }
  var si = directChild(sig, 'SignedInfo');
  var certEl = tags(sig, 'X509Certificate')[0];
  log.debug("Leaving messageSignature().");
  return {
    signatureMethod: attr(directChild(si, 'SignatureMethod'), 'Algorithm'),
    canonicalization: attr(directChild(si, 'CanonicalizationMethod'),
        'Algorithm'),
    digestMethod: (function () {
      var ref = si ? directChild(si, 'Reference') : null;
      return attr(directChild(ref, 'DigestMethod'), 'Algorithm');
    })(),
    reference: attr(si ? directChild(si, 'Reference') : null, 'URI'),
    certB64: certEl ? (certEl.textContent || '').replace(/\s+/g, '') : ''
  };
}

// The important values of a request message, as ordered { key, value, note }
// rows. Every row below is spelled differently in the two protocol versions
// where it exists at all, which is why each reads both — a reader written for
// 2.0 renders a perfectly good 1.1 message as a page of blanks.
//
// Returns { rows, messageType, version, signature, encrypted, subject }.
function summarize(xml) {
  log.debug("Entering summarize().");
  var doc = parseXml(xml);
  if (!doc || !doc.documentElement) {
    log.debug("Leaving summarize(). Not XML.");
    return { rows: [], messageType: '', version: '', error:
             'The decoded value is not well-formed XML.' };
  }
  var msg = doc.documentElement;
  var version = samlVersionOf(msg);
  var rows = [];
  var out = { rows: rows, messageType: msg.localName || '', version: version,
              signature: null, encrypted: findEncrypted(doc), subject: null,
              doc: doc };

  // An encrypted message has a root of EncryptedData: there is no request in
  // it to describe until a key has been applied, and pretending otherwise
  // produces a table of empty cells.
  if (msg.localName === 'EncryptedData' || msg.localName === 'EncryptedID' ||
      msg.localName === 'EncryptedAssertion') {
    push(rows, 'Message Type', msg.localName);
    push(rows, 'Encryption (data)', out.encrypted ? out.encrypted.dataAlg : '');
    push(rows, 'Encryption (key transport)',
         out.encrypted ? out.encrypted.keyAlg : '');
    push(rows, 'Status', 'Encrypted. Supply the recipient private key in the ' +
         'Decryption pane to read it.');
    log.debug("Leaving summarize(). Encrypted root.");
    return out;
  }

  push(rows, 'Message Type', msg.localName);
  push(rows, 'SAML Version', version || '(not stated)');
  push(rows, 'ID', attr(msg, 'ID') || attr(msg, 'RequestID') ||
       attr(msg, 'AssertionID'));
  push(rows, 'Issue Instant', attr(msg, 'IssueInstant'));
  push(rows, 'Destination', attr(msg, 'Destination'));
  push(rows, 'Consent', attr(msg, 'Consent'));
  // The issuer is a CHILD ELEMENT in 2.0 and an ATTRIBUTE in 1.1.
  push(rows, 'Issuer', directChildText(msg, 'Issuer') || attr(msg, 'Issuer'));

  if (msg.localName === 'AuthnRequest') {
    // saml-core-2.0-os section 3.4.1. Every one of these is optional, and the
    // three booleans are the ones worth printing even when absent — see push()
    // above for why they are not.
    push(rows, 'ForceAuthn', attr(msg, 'ForceAuthn') || '(absent — false)');
    push(rows, 'IsPassive', attr(msg, 'IsPassive') || '(absent — false)');
    push(rows, 'ProtocolBinding', attr(msg, 'ProtocolBinding'),
         'the binding the response is asked to come back on');
    push(rows, 'AssertionConsumerServiceURL',
         attr(msg, 'AssertionConsumerServiceURL'));
    push(rows, 'AssertionConsumerServiceIndex',
         attr(msg, 'AssertionConsumerServiceIndex'));
    push(rows, 'AttributeConsumingServiceIndex',
         attr(msg, 'AttributeConsumingServiceIndex'));
    push(rows, 'ProviderName', attr(msg, 'ProviderName'));

    var nidp = directChild(msg, 'NameIDPolicy');
    if (nidp) {
      push(rows, 'NameIDPolicy Format', attr(nidp, 'Format'));
      push(rows, 'NameIDPolicy SPNameQualifier', attr(nidp, 'SPNameQualifier'));
      push(rows, 'NameIDPolicy AllowCreate',
           attr(nidp, 'AllowCreate') || '(absent — false)');
    }

    var subject = directChild(msg, 'Subject');
    var nid = subjectNameId(subject);
    if (nid) {
      out.subject = nid;
      push(rows, 'Subject NameID', nid.value);
      push(rows, 'Subject NameID Format', nid.format);
      push(rows, 'Subject NameQualifier', nid.nameQualifier);
      push(rows, 'Subject SPNameQualifier', nid.spNameQualifier);
    } else if (subject && directChild(subject, 'EncryptedID')) {
      push(rows, 'Subject', 'an <saml:EncryptedID> — supply the recipient ' +
           'private key in the Decryption pane to read it.');
    }

    var conds = directChild(msg, 'Conditions');
    if (conds) {
      push(rows, 'Conditions NotBefore', attr(conds, 'NotBefore'));
      push(rows, 'Conditions NotOnOrAfter', attr(conds, 'NotOnOrAfter'));
      var auds = tags(conds, 'Audience');
      var list = [];
      for (var a = 0; a < auds.length; a++) {
        list.push((auds[a].textContent || '').trim());
      }
      push(rows, 'Audience Restriction', list.join(', '));
    }

    var rac = authnContextRefs(msg);
    if (rac) {
      push(rows, 'RequestedAuthnContext Comparison',
           rac.comparison || '(absent — exact)');
      push(rows, 'AuthnContext Class/Decl Refs', rac.refs.join('\n'));
    }

    var scoping = directChild(msg, 'Scoping');
    if (scoping) {
      push(rows, 'Scoping ProxyCount', attr(scoping, 'ProxyCount'));
      var idps = tags(scoping, 'IDPEntry');
      var entries = [];
      for (var s = 0; s < idps.length; s++) {
        entries.push(attr(idps[s], 'ProviderID'));
      }
      push(rows, 'Scoping IDPList', entries.join('\n'));
      var reqs = tags(scoping, 'RequesterID');
      var rlist = [];
      for (var r = 0; r < reqs.length; r++) {
        rlist.push((reqs[r].textContent || '').trim());
      }
      push(rows, 'Scoping RequesterID', rlist.join('\n'));
    }
    push(rows, 'Extensions', directChild(msg, 'Extensions') ?
         'present' : '');
  } else if (msg.localName === 'LogoutRequest') {
    // saml-core-2.0-os section 3.7.1 — the other request the SAML pages send.
    push(rows, 'Reason', attr(msg, 'Reason'));
    push(rows, 'NotOnOrAfter', attr(msg, 'NotOnOrAfter'));
    var lnid = subjectNameId(msg) || (function () {
      var n = directChild(msg, 'NameID') || directChild(msg, 'BaseID');
      return n ? { value: (n.textContent || '').trim(),
                   format: attr(n, 'Format'),
                   nameQualifier: attr(n, 'NameQualifier'),
                   spNameQualifier: attr(n, 'SPNameQualifier') } : null;
    })();
    if (lnid) {
      out.subject = lnid;
      push(rows, 'NameID', lnid.value);
      push(rows, 'NameID Format', lnid.format);
      push(rows, 'SPNameQualifier', lnid.spNameQualifier);
    }
    var si = tags(msg, 'SessionIndex');
    var slist = [];
    for (var k = 0; k < si.length; k++) {
      slist.push((si[k].textContent || '').trim());
    }
    push(rows, 'SessionIndex', slist.join('\n'));
  } else if (msg.localName === 'ArtifactResolve') {
    push(rows, 'Artifact', directChildText(msg, 'Artifact'));
  } else if (msg.localName === 'AttributeQuery' ||
             msg.localName === 'AuthnQuery' ||
             msg.localName === 'AuthzDecisionQuery') {
    var qnid = subjectNameId(directChild(msg, 'Subject'));
    if (qnid) {
      out.subject = qnid;
      push(rows, 'Subject NameID', qnid.value);
      push(rows, 'Subject NameID Format', qnid.format);
    }
    push(rows, 'Resource', attr(msg, 'Resource'));
  } else if (msg.localName === 'Request') {
    // SAML 1.1's one protocol request element, which wraps a query rather than
    // being one. What it CARRIES is the interesting part, and it is a different
    // element for each of the four kinds.
    var carried = ['AuthenticationQuery', 'AttributeQuery',
                   'AuthorizationDecisionQuery', 'AssertionArtifact',
                   'AssertionIDReference'];
    for (var c = 0; c < carried.length; c++) {
      var kid = directChild(msg, carried[c]);
      if (!kid) continue;
      push(rows, 'Query Type', carried[c]);
      if (carried[c] === 'AssertionArtifact' ||
          carried[c] === 'AssertionIDReference') {
        push(rows, carried[c], (kid.textContent || '').trim());
      } else {
        var snid = subjectNameId(directChild(kid, 'Subject'));
        if (snid) {
          out.subject = snid;
          push(rows, 'Subject NameIdentifier', snid.value);
          push(rows, 'Subject Format', snid.format);
        }
        push(rows, 'Resource', attr(kid, 'Resource'));
      }
      break;
    }
  }

  out.signature = messageSignature(msg);
  if (out.signature) {
    push(rows, 'Signature', 'present (enveloped)');
    push(rows, 'Signature Method', out.signature.signatureMethod);
    push(rows, 'Canonicalization', out.signature.canonicalization);
    push(rows, 'Digest Method', out.signature.digestMethod);
    push(rows, 'Signed Reference URI', out.signature.reference ||
         '(empty — the whole document)');
    push(rows, 'KeyInfo certificate', out.signature.certB64 ?
         'present' : 'absent (a key has to be supplied to verify)');
  } else {
    push(rows, 'Signature', 'no enveloped <ds:Signature> on the message');
  }
  if (out.encrypted) {
    push(rows, 'Encrypted content', out.encrypted.wrapper ?
         ('<' + out.encrypted.wrapper + '>') : '<xenc:EncryptedData>');
    push(rows, 'Encryption (data)', out.encrypted.dataAlg);
    push(rows, 'Encryption (key transport)', out.encrypted.keyAlg);
  }
  log.debug("Leaving summarize(). type=" + out.messageType);
  return out;
}

module.exports = {
  NS_SAML1P: NS_SAML1P,
  NS_SAML2P: NS_SAML2P,
  base64ToBytes: base64ToBytes,
  bytesToBase64: bytesToBase64,
  bytesToUtf8: bytesToUtf8,
  bytesToHex: bytesToHex,
  looksLikeBase64: looksLikeBase64,
  normalizeBase64: normalizeBase64,
  inflateRaw: inflateRaw,
  decodeSamlParam: decodeSamlParam,
  formatXml: formatXml,
  parseXml: parseXml,
  serialize: serialize,
  tags: tags,
  queryPairs: queryPairs,
  pairValue: pairValue,
  redirectSignedOctets: redirectSignedOctets,
  parseArtifact: parseArtifact,
  classify: classify,
  samlVersionOf: samlVersionOf,
  directChild: directChild,
  directChildText: directChildText,
  subjectNameId: subjectNameId,
  findEncrypted: findEncrypted,
  messageSignature: messageSignature,
  summarize: summarize
};
