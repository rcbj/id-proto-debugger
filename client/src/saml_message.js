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
//     versions;
//   * and, since 2026-08-28, the same for a RESPONSE — its status (a URI in
//     SAML 2.0 and a QName in SAML 1.1), the assertions inside it, and what
//     each of those assertions says. That half is at the bottom of the file,
//     under its own header, and it is bigger than this one for a reason a
//     request does not have: a response carries a status, may carry more than
//     one assertion, and is signed in TWO places that mean different things.
//
// IT IS SHARED, AND THE DUPLICATION IT ENDS WAS REAL. formatXml() existed four
// times (saml_response.js, wsfed_response.js, wstrust_tools.js,
// wstrust_response.js — three of them byte-identical and the fourth differing
// only in whether the regex was held in a variable), and the base64 / inflate /
// decodeSamlParam set existed in saml_response.js, which is where this copy
// came from. A fifth copy for the AuthnRequest decoder is what this module
// exists to avoid — and the response half exists for the same reason a day
// later: saml_response.js knew how to read an assertion in both versions and
// the SAML Response Decoder needed exactly that, so the READER moved here and
// both pages render it. The two pages draw different tables from the same
// data, which is the point: a second reader would disagree with the first
// about SAML 1.1 within a month, and the way it would show is a blank cell.
//
// NO DOM IDS AND NO PAGE STATE. Everything here takes a string and returns a
// value, which is what lets tests/saml_authnrequest_page.js and
// tests/saml_response_decoder_page.js BUILD their fixtures with it in node,
// under @xmldom standing in for the browser's parser — a real deflated, signed
// redirect URL and a real signed, encrypted response, rather than recorded
// strings that rot. (Neither test is called saml_message.js, and cannot be:
// tests/Dockerfile stages this module FLAT beside the test scripts, so a test
// of that name would silently replace it.) That is the only kind of check that
// catches a Redirect signature rebuilt in the wrong parameter order, since in
// a browser that failure is indistinguishable from a wrong key.
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
  var doc;
  try {
    doc = new DOMParser().parseFromString(xml, 'application/xml');
  } catch (e) {
    // A BROWSER never throws here — it returns a document containing a
    // <parsererror> — but @xmldom, which the node tests parse with, THROWS on
    // a namespace error (`prefix is non-null and namespace is null`). That is
    // exactly what a <saml:Assertion> sliced out of a response and pasted on
    // its own produces, which is one of the commonest things anybody does with
    // one, so the two parsers have to be made to answer the same way here or
    // a decoder that says "not well-formed XML" in a browser is a stack trace
    // in a test.
    log.debug("Leaving parseXml(). The parser refused: " + e.message);
    return null;
  }
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

// ---------------------------------------------------------------------------
// THE RESPONSE SIDE.
//
// A response is not a request under another name, and four of the differences
// are the whole reason this half exists.
//
//   * THE STATUS. A request has none; a response IS one, and the failure a
//     debugger is opened for is almost always written there. SAML 2.0 spells
//     the code as a URI and SAML 1.1 spells it as a **QName** resolved against
//     the document's own namespace declarations — `Value` ends in
//     `:status:Success` in one and in `:Success` in the other, so a check
//     written for either reads the other as a failure. That exact bug turned a
//     working SAML 1.1 sign-in red on the SAML Response page, and it is why
//     isSuccessStatus() below matches the LOCAL PART rather than a suffix.
//   * THE SIGNATURE IS IN TWO PLACES AT ONCE AND THEY MEAN DIFFERENT THINGS.
//     An identity provider may sign the <samlp:Response>, or each
//     <saml:Assertion>, or both. Only the assertion signature survives the
//     assertion being lifted out of the response; only the response signature
//     covers the STATUS and the InResponseTo. "The response is signed" and
//     "the assertion is signed" are therefore different claims, and a reader
//     that collapses them into one tells somebody their unsigned assertion is
//     safe. Everything below reports them separately, and says which is
//     absent rather than leaving a blank.
//   * THERE MAY BE MORE THAN ONE ASSERTION, and any of them may be encrypted,
//     and an <saml:Advice> may carry assertions that are NOT the subject of
//     the response at all.
//   * THE MESSAGE MAY CONTAIN ANOTHER MESSAGE. A <samlp:ArtifactResponse> is
//     an envelope whose payload is the message the artifact referenced —
//     which is the actual answer, and is where the status that matters lives.
//
// Nothing here verifies or decrypts anything; that is common/xmldsig.js.
// ---------------------------------------------------------------------------

// What a second-level status code MEANS, keyed by local part. SAML 2.0 core
// section 3.2.2.2 defines these; a debugger that prints the URI and stops has
// printed the one thing the user could already see. `NoPassive` in particular
// is the answer to a question the user asked without knowing it.
var STATUS_NOTES = {
  Success: 'the request succeeded',
  Requester: 'the REQUEST was at fault (the service provider)',
  Responder: 'the RESPONDER was at fault (the identity provider)',
  VersionMismatch: 'the responder cannot process the SAML version sent',
  AuthnFailed: 'the subject could not be authenticated',
  InvalidAttrNameOrValue: 'an attribute name or value was unrecognised',
  InvalidNameIDPolicy: 'the requested NameIDPolicy cannot be satisfied',
  NoAuthnContext: 'no requested authentication context could be met',
  NoAvailableIDP: 'none of the identity providers in Scoping is available',
  NoPassive: 'IsPassive was asked for and the responder cannot authenticate ' +
      'without interacting with the user',
  NoSupportedIDP: 'none of the identity providers in Scoping is supported',
  PartialLogout: 'not every session participant could be logged out',
  ProxyCountExceeded: 'proxying was needed and the ProxyCount was exhausted',
  RequestDenied: 'the responder refused the request',
  RequestUnsupported: 'the responder does not support the request',
  RequestVersionDeprecated: 'the SAML version of the request is deprecated',
  RequestVersionTooHigh: 'the request version is newer than the responder ' +
      'supports',
  RequestVersionTooLow: 'the request version is older than the responder ' +
      'supports',
  ResourceNotRecognized: 'the resource named in the request is unknown',
  TooManyResponses: 'the response would carry more elements than the ' +
      'responder can return',
  UnknownAttrProfile: 'the attribute profile is not supported',
  UnknownPrincipal: 'the responder does not recognise the subject',
  UnsupportedBinding: 'the responder cannot deliver over the binding asked for'
};

// The readable part of a status code, in either version's spelling: the last
// segment of a SAML 2.0 URI (…:status:Success -> "Success") and the local part
// of a SAML 1.1 QName (samlp:Success -> "Success"). One rule covers both,
// because a colon is the separator in each — which is also why callers print
// the full value beside it: `Requester` names different things in the two
// versions and the short form alone does not say which was read.
function shortStatus(value) {
  log.debug("Entering shortStatus().");
  if (!value) {
    log.debug("Leaving shortStatus(). None.");
    return '';
  }
  var i = String(value).lastIndexOf(':');
  log.debug("Leaving shortStatus().");
  return i >= 0 ? String(value).substring(i + 1) : String(value);
}

// WHETHER A STATUS SAYS SUCCESS, in either version's spelling. Matching the
// local part after the last colon accepts `Success`, `samlp:Success` and
// `urn:oasis:names:tc:SAML:2.0:status:Success`, and refuses a lookalike —
// `RequesterSuccess`, or a StatusMessage with the word in it.
function isSuccessStatus(value) {
  log.debug("Entering isSuccessStatus().");
  log.debug("Leaving isSuccessStatus().");
  return shortStatus(value) === 'Success';
}

// Resolve a SAML 1.1 status QName against the declarations in scope, which is
// what a strict reader does with it. Worth showing rather than hiding: a
// `samlp:Success` whose prefix is declared nowhere is a malformed document
// that every lenient reader in the world accepts, and this is the only place
// it will ever be mentioned.
function resolveQName(elem, value) {
  log.debug("Entering resolveQName().");
  var text = String(value || '');
  var parts = text.split(':');
  // A QName has exactly ONE colon with an NCName either side of it. SAML 2.0's
  // status codes are URIs and have several; a bare local part has none.
  // Neither resolves to anything, and neither is an error.
  if (parts.length !== 2 || !parts[1] ||
      !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(parts[0])) {
    log.debug("Leaving resolveQName(). Not a QName.");
    return '';
  }
  var prefix = parts[0];
  var local = parts[1];
  if (!elem || !elem.lookupNamespaceURI) {
    log.debug("Leaving resolveQName(). No resolver.");
    return '';
  }
  var ns;
  try {
    ns = elem.lookupNamespaceURI(prefix);
  } catch (e) {
    // @xmldom has raised on this in the past. A decoder that cannot resolve a
    // prefix says nothing about it rather than failing the whole render.
    log.debug("resolveQName(): lookup refused: " + e.message);
    ns = null;
  }
  log.debug("Leaving resolveQName().");
  return ns ? '{' + ns + '}' + local : '(the prefix "' + prefix +
      '" is declared nowhere in this document)';
}

// The <samlp:Status> of a response, in either version. The nested codes are
// walked as a CHAIN of direct children rather than collected flat: SAML 2.0
// core section 3.2.2.1 nests them to qualify the one above, so `Responder`
// then `NoPassive` is one answer with two parts and a flat list of the same
// two values loses which qualified which.
//
// Returns { present, top, topResolved, short, success, chain, message,
//           detail, note }.
function statusOf(msg) {
  log.debug("Entering statusOf().");
  var out = { present: false, top: '', topResolved: '', short: '',
              success: false, chain: [], message: '', detail: '', note: '' };
  var statusEl = msg ? tags(msg, 'Status')[0] : null;
  if (!statusEl) {
    log.debug("Leaving statusOf(). No Status.");
    return out;
  }
  out.present = true;
  var code = directChild(statusEl, 'StatusCode');
  while (code) {
    var value = attr(code, 'Value');
    out.chain.push(value);
    code = directChild(code, 'StatusCode');
  }
  out.top = out.chain.length ? out.chain[0] : '';
  out.topResolved = resolveQName(statusEl, out.top);
  out.short = shortStatus(out.top);
  out.success = isSuccessStatus(out.top);
  out.message = directChildText(statusEl, 'StatusMessage');
  var detailEl = directChild(statusEl, 'StatusDetail');
  out.detail = detailEl ? serialize(detailEl) : '';
  // The note describes the MOST SPECIFIC code, which is the last of the chain:
  // a top-level `Responder` says only that it was not the request's fault.
  for (var i = out.chain.length - 1; i >= 0; i--) {
    var note = STATUS_NOTES[shortStatus(out.chain[i])];
    if (note) {
      out.note = note;
      break;
    }
  }
  log.debug("Leaving statusOf(). " + out.short);
  return out;
}

// Every <saml:Attribute> under an element, in both versions' spelling. SAML
// 1.1 splits what 2.0 writes as one `Name` URI into `AttributeName` and
// `AttributeNamespace`, so the displayed name joins the two halves back into
// the claim URI they came from and the namespace half is also reported on its
// own — a reader that knows only `Name` shows a column of blanks on a document
// that is perfectly well formed.
function attributesOf(root) {
  log.debug("Entering attributesOf().");
  var out = [];
  var attrs = root ? tags(root, 'Attribute') : [];
  for (var i = 0; i < attrs.length; i++) {
    var a = attrs[i];
    var vals = tags(a, 'AttributeValue');
    var values = [];
    for (var j = 0; j < vals.length; j++) {
      values.push((vals[j].textContent || '').trim());
    }
    var ns = attr(a, 'AttributeNamespace');
    var name = attr(a, 'Name') || attr(a, 'AttributeName');
    var shown = (ns && !attr(a, 'Name'))
      ? (ns.replace(/\/$/, '') + '/' + name)
      : name;
    out.push({
      name: shown,
      rawName: name,
      namespace: ns,
      values: values,
      format: attr(a, 'NameFormat') || ns,
      friendlyName: attr(a, 'FriendlyName')
    });
  }
  log.debug("Leaving attributesOf(). " + out.length + " attributes.");
  return out;
}

// HOW THE ASSERTION CLAIMS TO HAVE REACHED THE RELYING PARTY. The two
// versions put this in different places and in the SAML 1.1 browser profiles
// it IS the profile: saml-profile-1.1 section 4.1.1.4 requires cm:artifact for
// Browser/Artifact and 4.2.1.4 requires cm:bearer for Browser/POST, and a
// relying party that never looks works perfectly with either. SAML 2.0 puts
// the method on <saml:SubjectConfirmation> and the interesting part —
// Recipient, NotOnOrAfter, InResponseTo, Address — in the
// <saml:SubjectConfirmationData> beneath it, which is the bearer check every
// service provider is supposed to perform and many do not.
function subjectConfirmations(subject) {
  log.debug("Entering subjectConfirmations().");
  var out = [];
  if (!subject) {
    log.debug("Leaving subjectConfirmations(). No Subject.");
    return out;
  }
  var kids = subject.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType !== 1) continue;
    if (kids[i].localName !== 'SubjectConfirmation') continue;
    var sc = kids[i];
    var data = directChild(sc, 'SubjectConfirmationData');
    var row = {
      method: attr(sc, 'Method'),
      recipient: attr(data, 'Recipient'),
      notBefore: attr(data, 'NotBefore'),
      notOnOrAfter: attr(data, 'NotOnOrAfter'),
      inResponseTo: attr(data, 'InResponseTo'),
      address: attr(data, 'Address')
    };
    // SAML 1.1 does not put the method in an attribute at all: it is one or
    // more <saml:ConfirmationMethod> CHILD elements of the
    // <saml:SubjectConfirmation>. A reader that looks only for @Method finds
    // an empty string on every 1.1 assertion and reports the profile as
    // unstated — which, in the 1.1 browser profiles, is the whole of what
    // distinguishes Browser/POST from Browser/Artifact.
    var methods = [];
    var sub = sc.childNodes;
    for (var m = 0; m < sub.length; m++) {
      if (sub[m].nodeType === 1 && sub[m].localName === 'ConfirmationMethod') {
        methods.push((sub[m].textContent || '').trim());
      }
    }
    if (!row.method && methods.length) {
      methods.forEach(function (name) {
        var copy = { method: name, recipient: row.recipient,
                     notBefore: row.notBefore, notOnOrAfter: row.notOnOrAfter,
                     inResponseTo: row.inResponseTo, address: row.address };
        out.push(copy);
      });
      continue;
    }
    out.push(row);
  }
  log.debug("Leaving subjectConfirmations(). " + out.length + " found.");
  return out;
}

// The <saml:Conditions> of an assertion: the validity window, plus EVERY
// condition element under it rather than only the audience. A condition this
// code does not recognise is still reported, by its own element name — an
// unrecognised condition is one a relying party MUST reject (saml-core-2.0-os
// section 2.5.1), so silently dropping it is the one thing a reader must not
// do here.
function conditionsOf(assertion) {
  log.debug("Entering conditionsOf().");
  var cond = assertion ? tags(assertion, 'Conditions')[0] : null;
  if (!cond) {
    log.debug("Leaving conditionsOf(). None.");
    return null;
  }
  var out = { notBefore: attr(cond, 'NotBefore'),
              notOnOrAfter: attr(cond, 'NotOnOrAfter'), entries: [] };
  var kids = cond.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType !== 1) continue;
    var entry = { localName: kids[i].localName, values: [], text: '' };
    // AudienceRestriction (2.0) and AudienceRestrictionCondition (1.1) are the
    // same condition under two names, and WHICH ONE ARRIVED is exactly what
    // somebody reads this for — so the element's own name is kept rather than
    // normalised to either.
    var auds = tags(kids[i], 'Audience');
    for (var a = 0; a < auds.length; a++) {
      entry.values.push((auds[a].textContent || '').trim());
    }
    if (!entry.values.length) {
      entry.text = (kids[i].textContent || '').trim();
    }
    out.entries.push(entry);
  }
  log.debug("Leaving conditionsOf(). " + out.entries.length + " conditions.");
  return out;
}

// The authentication statement, in either version. SAML 1.1 puts the method
// and the instant on <saml:AuthenticationStatement> as attributes; SAML 2.0
// spells the method as a child <saml:AuthnContextClassRef> and the instant as
// an AuthnInstant attribute on <saml:AuthnStatement>, and adds the two session
// fields that Single Logout is built on.
function authnStatementOf(assertion) {
  log.debug("Entering authnStatementOf().");
  var st = assertion ? (tags(assertion, 'AuthnStatement')[0] ||
      tags(assertion, 'AuthenticationStatement')[0]) : null;
  if (!st) {
    log.debug("Leaving authnStatementOf(). None.");
    return null;
  }
  var out = {
    element: st.localName,
    instant: attr(st, 'AuthnInstant') || attr(st, 'AuthenticationInstant'),
    method: attr(st, 'AuthenticationMethod'),
    sessionIndex: attr(st, 'SessionIndex'),
    sessionNotOnOrAfter: attr(st, 'SessionNotOnOrAfter'),
    contextRefs: [],
    locality: ''
  };
  var refs = tags(st, 'AuthnContextClassRef');
  for (var i = 0; i < refs.length; i++) {
    out.contextRefs.push((refs[i].textContent || '').trim());
  }
  var decl = tags(st, 'AuthnContextDeclRef');
  for (var d = 0; d < decl.length; d++) {
    out.contextRefs.push((decl[d].textContent || '').trim());
  }
  var loc = tags(st, 'SubjectLocality')[0];
  if (loc) {
    out.locality = (attr(loc, 'IPAddress') || attr(loc, 'Address')) +
        (attr(loc, 'DNSAddress') || attr(loc, 'DNSName')
          ? ' / ' + (attr(loc, 'DNSAddress') || attr(loc, 'DNSName')) : '');
  }
  log.debug("Leaving authnStatementOf().");
  return out;
}

// Everything worth reading out of one <saml:Assertion>, in either version, as
// data rather than markup — the SAML Response page and the SAML Response
// Decoder both render this and neither reads an assertion for itself.
//
// Returns { id, version, saml1, issuer, issueInstant, subject, confirmations,
//           conditions, authn, authzDecisions, attributes, signature,
//           advice, statements, rows }.
function assertionSummary(assertion) {
  log.debug("Entering assertionSummary().");
  if (!assertion) {
    log.debug("Leaving assertionSummary(). No assertion.");
    return null;
  }
  var version = samlVersionOf(assertion);
  var subject = tags(assertion, 'Subject')[0] || null;
  var out = {
    id: attr(assertion, 'ID') || attr(assertion, 'AssertionID'),
    version: version,
    saml1: String(version || '').charAt(0) === '1',
    // The issuer is a CHILD ELEMENT in 2.0 and an ATTRIBUTE in 1.1.
    issuer: directChildText(assertion, 'Issuer') || attr(assertion, 'Issuer'),
    issueInstant: attr(assertion, 'IssueInstant'),
    subject: subjectNameId(subject),
    encryptedSubject: !!(subject && directChild(subject, 'EncryptedID')),
    confirmations: subjectConfirmations(subject),
    conditions: conditionsOf(assertion),
    authn: authnStatementOf(assertion),
    authzDecisions: [],
    attributes: attributesOf(assertion),
    signature: messageSignature(assertion),
    advice: !!directChild(assertion, 'Advice'),
    statements: [],
    rows: []
  };

  // Which statements the assertion carries at all. An assertion with no
  // statement in it is legal in 2.0 and says nothing about anybody, which is
  // worth showing rather than rendering as an empty table.
  var kids = assertion.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType !== 1) continue;
    if (/Statement$/.test(kids[i].localName || '')) {
      out.statements.push(kids[i].localName);
    }
  }

  var decisions = tags(assertion, 'AuthzDecisionStatement');
  if (!decisions.length) {
    decisions = tags(assertion, 'AuthorizationDecisionStatement');
  }
  for (var d = 0; d < decisions.length; d++) {
    var actions = tags(decisions[d], 'Action');
    var list = [];
    for (var a = 0; a < actions.length; a++) {
      list.push((actions[a].textContent || '').trim());
    }
    out.authzDecisions.push({
      resource: attr(decisions[d], 'Resource'),
      decision: attr(decisions[d], 'Decision'),
      actions: list
    });
  }

  // The ordered rows a details table renders. Same order in both versions,
  // spelled from whichever one arrived.
  var rows = out.rows;
  push(rows, 'Assertion ID', out.id);
  push(rows, 'Assertion Version', out.version);
  push(rows, 'Assertion Issuer', out.issuer);
  push(rows, 'IssueInstant', out.issueInstant);
  if (out.conditions) {
    push(rows, 'Conditions NotBefore', out.conditions.notBefore);
    push(rows, 'Conditions NotOnOrAfter', out.conditions.notOnOrAfter);
    out.conditions.entries.forEach(function (entry) {
      push(rows, 'Condition: ' + entry.localName,
           entry.values.length ? entry.values.join('\n')
                               : (entry.text || '(present)'));
    });
  }
  if (out.subject) {
    push(rows, 'NameID', out.subject.value);
    push(rows, 'NameID Format', out.subject.format);
    push(rows, 'NameQualifier', out.subject.nameQualifier);
    push(rows, 'SPNameQualifier', out.subject.spNameQualifier);
  } else if (out.encryptedSubject) {
    push(rows, 'Subject', 'an <saml:EncryptedID> — supply the recipient ' +
         'private key in the Decryption pane to read it.');
  }
  out.confirmations.forEach(function (c) {
    push(rows, 'ConfirmationMethod', c.method);
    push(rows, 'Confirmation Recipient', c.recipient);
    push(rows, 'Confirmation NotOnOrAfter', c.notOnOrAfter);
    push(rows, 'Confirmation InResponseTo', c.inResponseTo);
    push(rows, 'Confirmation Address', c.address);
  });
  if (out.authn) {
    push(rows, 'Authn Statement', out.authn.element);
    push(rows, 'AuthenticationInstant', out.authn.instant);
    push(rows, 'AuthenticationMethod', out.authn.method);
    push(rows, 'AuthnContext Class/Decl Refs',
         out.authn.contextRefs.join('\n'));
    push(rows, 'SessionIndex', out.authn.sessionIndex);
    push(rows, 'SessionNotOnOrAfter', out.authn.sessionNotOnOrAfter);
    push(rows, 'SubjectLocality', out.authn.locality);
  }
  out.authzDecisions.forEach(function (d2) {
    push(rows, 'AuthzDecision Resource', d2.resource);
    push(rows, 'AuthzDecision', d2.decision);
    push(rows, 'AuthzDecision Actions', d2.actions.join('\n'));
  });
  push(rows, 'Statements', out.statements.join(', '));
  push(rows, 'Attributes', String(out.attributes.length));
  if (out.advice) {
    push(rows, 'Advice', 'present — assertions in an <saml:Advice> are ' +
         'SUPPORTING material, not the subject of this response, and a ' +
         'relying party may ignore them entirely.');
  }
  if (out.signature) {
    push(rows, 'Assertion Signature', 'present (enveloped)');
    push(rows, 'Signature Method', out.signature.signatureMethod);
    push(rows, 'Canonicalization', out.signature.canonicalization);
    push(rows, 'Digest Method', out.signature.digestMethod);
    push(rows, 'Signed Reference URI', out.signature.reference ||
         '(empty — the whole document)');
    push(rows, 'KeyInfo certificate', out.signature.certB64 ?
         'present' : 'absent (a key has to be supplied to verify)');
  } else {
    push(rows, 'Assertion Signature', 'this assertion carries no enveloped ' +
         '<ds:Signature> of its own');
  }
  log.debug("Leaving assertionSummary(). rows=" + rows.length);
  return out;
}

// Serialize a subtree so that it still verifies OUT of its document.
//
// A <saml:Assertion> is signed in place and then read on its own — the
// signature pane is handed the assertion, not the response around it. A
// serializer performs namespace fixup as it goes, so a prefix the subtree
// actually USES is declared for you and the fragment parses. What it does NOT
// carry down is a declaration that is merely IN SCOPE, and there are two of
// those that matter:
//
//   * a prefix used only inside an ATTRIBUTE VALUE. SAML 1.1's status code is
//     a QName (`samlp:Success`) and `xsi:type` on an <saml:AttributeValue> is
//     another; no serializer can see those, so the fragment comes out naming
//     a prefix bound to nothing.
//   * under INCLUSIVE C14N, the apex of a subtree carries every namespace in
//     scope — so a declaration dropped on the way out changes the digest, and
//     the signature reports INVALID on a message that is perfectly good.
//     (Exclusive C14N emits only what is visibly used, so the same additions
//     are invisible to it, which is why this is safe for both.)
//
// So the inherited declarations are copied down, EXCEPT the ones the
// serializer is going to emit anyway — adding one of those produces a
// duplicate `xmlns:` attribute, which is not well-formed XML at all. "Going to
// emit" is decided from the DOM rather than from the output: a prefix used by
// an element or an attribute NAME in the subtree is the serializer's job, and
// everything else is this function's.
function usedPrefixes(elem) {
  log.debug("Entering usedPrefixes().");
  var used = {};
  var stack = [elem];
  while (stack.length) {
    var node = stack.pop();
    if (!node || node.nodeType !== 1) continue;
    used[node.prefix || ''] = true;
    for (var i = 0; i < node.attributes.length; i++) {
      var a = node.attributes[i];
      var name = a.name || '';
      if (name === 'xmlns' || name.indexOf('xmlns:') === 0) continue;
      if (a.prefix) used[a.prefix] = true;
    }
    var kids = node.childNodes;
    for (var k = 0; k < kids.length; k++) {
      stack.push(kids[k]);
    }
  }
  log.debug("Leaving usedPrefixes().");
  return used;
}

function serializeSubtree(elem) {
  log.debug("Entering serializeSubtree().");
  if (!elem) {
    log.debug("Leaving serializeSubtree(). Nothing.");
    return '';
  }
  var declared = {};
  var i;
  for (i = 0; i < elem.attributes.length; i++) {
    var own = elem.attributes[i];
    var ownName = own.name || '';
    if (ownName === 'xmlns' || ownName.indexOf('xmlns:') === 0) {
      declared[ownName] = true;
    }
  }
  var used = usedPrefixes(elem);
  var missing = [];
  var node = elem.parentNode;
  while (node && node.nodeType === 1) {
    for (i = 0; i < node.attributes.length; i++) {
      var a = node.attributes[i];
      var name = a.name || '';
      if (name !== 'xmlns' && name.indexOf('xmlns:') !== 0) continue;
      if (declared[name]) continue;
      declared[name] = true;
      // The serializer declares this one itself; adding it again would emit
      // the attribute twice and the fragment would not parse.
      if (used[name === 'xmlns' ? '' : name.substring(6)]) continue;
      missing.push([name, a.value]);
    }
    node = node.parentNode;
  }
  if (!missing.length) {
    log.debug("Leaving serializeSubtree(). Nothing to carry down.");
    return serialize(elem);
  }
  // The copy is made on a CLONE: the live node is what a later signature check
  // or a re-render reads, and adding attributes to it would change what the
  // rest of the page is looking at.
  var clone = elem.cloneNode(true);
  missing.forEach(function (pair) {
    try {
      clone.setAttribute(pair[0], pair[1]);
    } catch (e) {
      // A DOM that refuses an xmlns attribute set this way. The fragment is
      // still returned; it is the one the serializer would have produced.
      log.debug("serializeSubtree(): " + pair[0] + " refused: " + e.message);
    }
  });
  log.debug("Leaving serializeSubtree(). " + missing.length + " carried down.");
  return serialize(clone);
}

// Every assertion the message carries, plaintext and encrypted, in document
// order, each labelled with WHERE it sits. The place matters: an assertion
// inside an <saml:Advice> is supporting material rather than the subject of
// the response, and one inside an <saml:EncryptedAssertion> cannot be read at
// all until a key is applied.
//
// Returns [{ kind, xml, element, encrypted, advice, summary }].
function assertionsOf(msg) {
  log.debug("Entering assertionsOf().");
  var out = [];
  if (!msg) {
    log.debug("Leaving assertionsOf(). No message.");
    return out;
  }
  // An assertion pasted on its own IS the message, which is much the commonest
  // thing on a clipboard after a full response.
  if (msg.localName === 'Assertion') {
    out.push({ kind: 'assertion', xml: serializeSubtree(msg), element: msg,
               encrypted: false, advice: false,
               summary: assertionSummary(msg) });
    log.debug("Leaving assertionsOf(). The message is an assertion.");
    return out;
  }
  var all = tags(msg, 'Assertion');
  for (var i = 0; i < all.length; i++) {
    var a = all[i];
    var advice = false;
    var node = a.parentNode;
    while (node && node.nodeType === 1 && node !== msg) {
      if (node.localName === 'Advice') advice = true;
      node = node.parentNode;
    }
    out.push({ kind: advice ? 'advice' : 'assertion',
               xml: serializeSubtree(a), element: a, encrypted: false,
               advice: advice, summary: assertionSummary(a) });
  }
  var enc = tags(msg, 'EncryptedAssertion');
  for (var e = 0; e < enc.length; e++) {
    var ed = tags(enc[e], 'EncryptedData')[0];
    out.push({
      kind: 'encrypted',
      xml: serializeSubtree(enc[e]),
      element: enc[e],
      encrypted: true,
      advice: false,
      summary: null,
      dataAlg: attr(directChild(ed, 'EncryptionMethod'), 'Algorithm'),
      keyAlg: (function () {
        var ek = tags(enc[e], 'EncryptedKey')[0];
        return ek ? attr(directChild(ek, 'EncryptionMethod'), 'Algorithm') : '';
      })()
    });
  }
  log.debug("Leaving assertionsOf(). " + out.length + " assertions.");
  return out;
}

// The important values of a RESPONSE message, as ordered { key, value, note }
// rows plus the structured halves a page needs to render separately.
//
// Returns { rows, messageType, version, saml1, status, signature, assertions,
//           encrypted, nested, doc, message, error }.
//
// `nested` is the message INSIDE a <samlp:ArtifactResponse>, summarized one
// level deep. An ArtifactResponse is an envelope: its own status says only
// whether the artifact resolved, and the answer the user is looking for is the
// status of the message inside it. Reporting the envelope's Success as the
// result is how a debugger reports a failed sign-in as a successful one.
function summarizeResponse(xml, depth) {
  log.debug("Entering summarizeResponse().");
  var doc = parseXml(xml);
  if (!doc || !doc.documentElement) {
    log.debug("Leaving summarizeResponse(). Not XML.");
    return { rows: [], messageType: '', version: '', assertions: [],
             status: null, error: 'The decoded value is not well-formed XML.' };
  }
  var msg = doc.documentElement;
  var version = samlVersionOf(msg);
  var rows = [];
  var out = { rows: rows, messageType: msg.localName || '', version: version,
              saml1: String(version || '').charAt(0) === '1', status: null,
              signature: null, assertions: [], encrypted: findEncrypted(doc),
              nested: null, doc: doc, message: msg };

  // An encrypted root has nothing readable in it, and a table of empty cells
  // over ciphertext is worse than one row saying so.
  if (msg.localName === 'EncryptedData' || msg.localName === 'EncryptedID' ||
      msg.localName === 'EncryptedAssertion') {
    push(rows, 'Message Type', msg.localName);
    push(rows, 'Encryption (data)', out.encrypted ? out.encrypted.dataAlg : '');
    push(rows, 'Encryption (key transport)',
         out.encrypted ? out.encrypted.keyAlg : '');
    push(rows, 'Status', 'Encrypted. Supply the recipient private key in the ' +
         'Decryption pane to read it.');
    log.debug("Leaving summarizeResponse(). Encrypted root.");
    return out;
  }

  push(rows, 'Message Type', msg.localName);
  push(rows, 'SAML Version', version || '(not stated)');
  // SAML 1.1 spells the message id ResponseID; an assertion pasted on its own
  // spells it AssertionID.
  push(rows, 'ID', attr(msg, 'ID') || attr(msg, 'ResponseID') ||
       attr(msg, 'AssertionID'));
  push(rows, 'Issue Instant', attr(msg, 'IssueInstant'));
  push(rows, 'In Response To', attr(msg, 'InResponseTo'),
       'the request this answers. A response carrying none is UNSOLICITED — ' +
       'IdP-initiated, which is the only kind SAML 1.1 has.');
  // Destination is 2.0's; Recipient is 1.1's, and it names the same thing.
  push(rows, 'Destination', attr(msg, 'Destination'));
  push(rows, 'Recipient', attr(msg, 'Recipient'));
  push(rows, 'Consent', attr(msg, 'Consent'));

  out.assertions = assertionsOf(msg);

  // The issuer is a child element in 2.0 and an attribute in 1.1 — and on a
  // SAML 1.1 Browser/POST Response there is frequently none at all, because
  // the assertion inside carries it. An empty Issuer row above a signed
  // assertion reads as an unidentified identity provider, so the assertion's
  // stands in and says that it did.
  var issuer = directChildText(msg, 'Issuer') || attr(msg, 'Issuer');
  var issuerNote = '';
  if (!issuer) {
    for (var i = 0; i < out.assertions.length; i++) {
      if (out.assertions[i].summary && out.assertions[i].summary.issuer) {
        issuer = out.assertions[i].summary.issuer;
        issuerNote = 'read off the assertion — the message itself names no ' +
            'issuer, which is ordinary in SAML 1.1.';
        break;
      }
    }
  }
  push(rows, 'Issuer', issuer, issuerNote);

  out.status = statusOf(msg);
  if (out.status.present) {
    push(rows, 'Status', out.status.short + (out.status.success ? '' :
         ' — NOT a success'), out.status.note);
    push(rows, 'Status Code', out.status.top);
    if (out.status.topResolved) {
      push(rows, 'Status Code (resolved)', out.status.topResolved,
           'SAML 1.1 writes the code as a QName rather than a URI, so it ' +
           'means nothing without the namespace its prefix is bound to.');
    }
    for (var c = 1; c < out.status.chain.length; c++) {
      push(rows, 'Sub-status ' + c, out.status.chain[c],
           STATUS_NOTES[shortStatus(out.status.chain[c])] || '');
    }
    push(rows, 'Status Message', out.status.message);
    push(rows, 'Status Detail', out.status.detail ? 'present' : '');
  } else if (msg.localName !== 'Assertion') {
    push(rows, 'Status', 'no <samlp:Status> element', 'every SAML protocol ' +
         'response carries one; a message without it is not a response.');
  }

  push(rows, 'Assertions', String(out.assertions.length));
  var encryptedCount = out.assertions.filter(function (a) {
    return a.encrypted;
  }).length;
  push(rows, 'Encrypted assertions', encryptedCount ? String(encryptedCount)
       : '');

  // THE MESSAGE-LEVEL SIGNATURE, which is not the assertion's. Both are
  // reported, and the absence of either is stated rather than left blank —
  // "the response is signed" and "the assertion is signed" are different
  // security claims and only the second survives the assertion being lifted
  // out of the response.
  //
  // UNLESS THE MESSAGE IS THE ASSERTION, which is what a bare <saml:Assertion>
  // pasted on its own is. Then there is one signature and it is the
  // assertion's: reporting it a second time as the message's would make a
  // caller check the identical bytes twice and count two, which reads as a
  // response signed at both levels — the opposite of what is in front of it.
  out.signature = msg.localName === 'Assertion' ? null : messageSignature(msg);
  if (out.signature) {
    push(rows, 'Message Signature', 'present (enveloped, on <' +
         msg.localName + '>)');
    push(rows, 'Signature Method', out.signature.signatureMethod);
    push(rows, 'Canonicalization', out.signature.canonicalization);
    push(rows, 'Digest Method', out.signature.digestMethod);
    push(rows, 'Signed Reference URI', out.signature.reference ||
         '(empty — the whole document)');
    push(rows, 'KeyInfo certificate', out.signature.certB64 ?
         'present' : 'absent (a key has to be supplied to verify)');
  } else if (msg.localName !== 'Assertion') {
    push(rows, 'Message Signature', 'no enveloped <ds:Signature> on the ' +
         'message itself', 'an assertion inside it may still be signed, ' +
         'which is a different claim: an assertion signature does not cover ' +
         'the status or the InResponseTo.');
  }
  if (out.encrypted) {
    push(rows, 'Encrypted content', out.encrypted.wrapper ?
         ('<' + out.encrypted.wrapper + '>') : '<xenc:EncryptedData>');
    push(rows, 'Encryption (data)', out.encrypted.dataAlg);
    push(rows, 'Encryption (key transport)', out.encrypted.keyAlg);
  }

  // The payload of an ArtifactResponse, one level down. Guarded on depth
  // rather than trusted: an envelope containing itself is a document somebody
  // built to see what would happen.
  if (msg.localName === 'ArtifactResponse' && !(depth > 0)) {
    var inner = null;
    var kids = msg.childNodes;
    for (var k = 0; k < kids.length; k++) {
      if (kids[k].nodeType !== 1) continue;
      if (kids[k].localName === 'Signature' ||
          kids[k].localName === 'Issuer' ||
          kids[k].localName === 'Extensions' ||
          kids[k].localName === 'Status') continue;
      inner = kids[k];
      break;
    }
    if (inner) {
      out.nested = summarizeResponse(serializeSubtree(inner), 1);
      out.nestedXml = serializeSubtree(inner);
      push(rows, 'Carried message', inner.localName, 'an ArtifactResponse is ' +
           'an ENVELOPE. Its own Status says only whether the artifact ' +
           'resolved; the answer being looked for is the status of the ' +
           'message inside it.');
    }
  }

  log.debug("Leaving summarizeResponse(). type=" + out.messageType);
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
  summarize: summarize,
  STATUS_NOTES: STATUS_NOTES,
  shortStatus: shortStatus,
  isSuccessStatus: isSuccessStatus,
  resolveQName: resolveQName,
  statusOf: statusOf,
  attributesOf: attributesOf,
  subjectConfirmations: subjectConfirmations,
  conditionsOf: conditionsOf,
  authnStatementOf: authnStatementOf,
  assertionSummary: assertionSummary,
  usedPrefixes: usedPrefixes,
  serializeSubtree: serializeSubtree,
  assertionsOf: assertionsOf,
  summarizeResponse: summarizeResponse
};
