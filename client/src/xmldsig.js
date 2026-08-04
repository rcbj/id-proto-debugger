// File: xmldsig.js
//
// Shared in-browser XML security primitives used by the WS-Trust workflow
// (and available to any other page that needs XML-DSIG / XML-Encryption without
// a server round-trip). The implementations here are lifted from the proven
// SAML code in saml_request.js — the same exclusive Canonical XML 1.0, RSA-SHA*
// signing, and W3C XML-Encryption (xmlenc / xmlenc11) — but factored into a
// reusable module whose functions take explicit arguments/options instead of
// reading specific DOM element ids, so they are not tied to the SAML page.
//
// node-forge does all the crypto (RSA sign/keygen, block ciphers, RSA key wrap).
// Only browser-native APIs (DOMParser/XMLSerializer, window.crypto) are used
// besides forge, so this bundles cleanly with browserify + envify.


var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "xmldsig",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var forge = require("node-forge");

// --- namespace / algorithm URIs --------------------------------------------
var DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
var XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';
var XENC11_NS = 'http://www.w3.org/2009/xmlenc11#';
var C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';
var TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
var SIG_ALG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

// RFC 4122-ish id suitable for an XML ID (an NCName: starts with '_').
function genId() {
  var b = new Uint8Array(16);
  (window.crypto || window.msCrypto).getRandomValues(b);
  var hex = '';
  for (var i = 0; i < b.length; i++) { hex += ('0' + b[i].toString(16)).slice(-2); }
  return '_' + hex;
}

function xmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

// Strip PEM armor to bare base64 DER.
function certPemToB64(pem) {
  return String(pem || '')
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

// Wrap bare base64 DER in PEM (pass-through if already PEM) so forge can parse it.
function pemWrapCert(certPemOrB64) {
  var s = String(certPemOrB64 || '');
  if (/-----BEGIN CERTIFICATE-----/.test(s)) return s;
  var b64 = s.replace(/\s+/g, '');
  var lines = b64.match(/.{1,64}/g) || [];
  return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----\n';
}

function digestBase64(str, mdFactory) {
  var md = mdFactory();
  md.update(str, 'utf8');
  return forge.util.encode64(md.digest().getBytes());
}

// SignatureMethod URI -> forge digest factory + matching Reference DigestMethod
// URI. The keys are RSA, so these are the RSA-family methods from xmldsig /
// xmldsig-more (RFC 6931).
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

// --- Exclusive Canonical XML 1.0 (omit-comments) over a DOM element ----------
// Renders on each element only the namespace declarations it *visibly utilizes*
// (its own prefix + the prefixes of namespace-qualified attributes), so a
// subtree canonicalizes identically standalone or nested — the property the
// detached SignedInfo signature relies on. (Verbatim from saml_request.js.)
function canonicalize(apex) { return c14nSerialize(apex, {}); }

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
function c14nSerialize(el, rendered) {
  log.debug("Entering c14nSerialize().");
  var inscope = c14nInScopeNs(el);
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
    if (uri === undefined) return;
    if (prefix === '' && uri === '' && !rendered.hasOwnProperty('')) return;
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

// Inclusive Canonical XML 1.0 — only for the encryption "Inclusive C14N" option.
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

// --- XML Encryption (W3C xmlenc / xmlenc11) ---------------------------------
function dataAlgSpec(uri) {
  log.debug("Entering dataAlgSpec().");
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
  log.debug("Leaving dataAlgSpec().");
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
// Parse caller-supplied XML, refusing anything that is not well-formed.
//
// This is the correct control for an XML input, and note what it deliberately
// does NOT do: it does not alter a single byte. XML-DSIG signs the exact octets
// that get canonicalized, so any "cleaning" applied before this point silently
// invalidates the signature it is about to produce or check — which is why an
// HTML sanitizer has no business on this path. What can go wrong with XML here
// is that it is malformed and the code then operates on a `parsererror`
// document (or a null documentElement) as though it were the caller's message;
// that is what this catches, at the point of parsing, with a named error.
//
// External entities are not a concern to defend against here: the browser's
// DOMParser does not resolve them at all, and neither does @xmldom/xmldom,
// which is what the node-side tests load this module with.
function parseXmlStrict(xml, what) {
  log.debug("Entering parseXmlStrict().");
  var label = what || 'XML';
  if (typeof xml !== 'string' || xml.trim() === '') {
    throw new Error(label + ' is empty.');
  }
  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (!doc || doc.getElementsByTagName('parsererror').length || !doc.documentElement) {
    throw new Error('malformed ' + label + ' — it is not well-formed XML.');
  }
  log.debug("Leaving parseXmlStrict().");
  return doc;
}

function encPlaintext(xml, c14nMode, type) {
  log.debug("Entering encPlaintext().");
  var isContent = type && type.indexOf('#Content') >= 0;
  if (c14nMode === 'exc-c14n' || c14nMode === 'c14n') {
    var fn = (c14nMode === 'c14n') ? canonicalizeInclusive : canonicalize;
    var doc = parseXmlStrict(xml, 'the XML to encrypt');
    var root = doc.documentElement;
    if (!isContent) return fn(root);
    var inner = '', ch = root.firstChild;
    while (ch) { if (ch.nodeType === 1) inner += fn(ch); ch = ch.nextSibling; }
    return inner;
  }
  if (!isContent) return xml;
  var d2 = parseXmlStrict(xml, 'the XML to encrypt');
  var r2 = d2.documentElement, s = '', c = r2.firstChild;
  while (c) { s += new XMLSerializer().serializeToString(c); c = c.nextSibling; }
  log.debug("Leaving encPlaintext().");
  return s;
}

// Encrypt an XML string, returning an <xenc:EncryptedData> element string.
// opts: { certPem, dataAlg, keyAlg, type, c14nMode, digest, mgf } — the same
// knobs the SAML encryption panel exposes.
function encryptXml(xml, opts) {
  log.debug("Entering encryptXml().");
  opts = opts || {};
  var certField = opts.certPem || '';
  if (!String(certField).trim()) throw new Error('No encryption certificate — paste a recipient certificate.');
  var certB64 = certPemToB64(certField);
  var cert = forge.pki.certificateFromPem(pemWrapCert(certField));
  var pub = cert.publicKey;

  var dataAlg = opts.dataAlg || (XENC11_NS + 'aes256-gcm');
  var keyAlg = opts.keyAlg || (XENC11_NS + 'rsa-oaep');
  var type = opts.type || (XENC_NS + 'Element');
  var c14nMode = opts.c14nMode || 'none';
  var spec = dataAlgSpec(dataAlg);

  var plaintext = encPlaintext(xml, c14nMode, type);
  var ptBytes = forge.util.encodeUtf8(plaintext);
  var sessionKey = forge.random.getBytesSync(spec.keyBytes);
  var iv = forge.random.getBytesSync(spec.ivBytes);
  var cipher = forge.cipher.createCipher(spec.cipher, sessionKey);
  cipher.start(spec.gcm ? { iv: iv, tagLength: 128 } : { iv: iv });
  cipher.update(forge.util.createBuffer(ptBytes));
  if (!cipher.finish()) throw new Error('Data encryption failed.');
  var cipherValue = iv + cipher.output.getBytes() + (spec.gcm ? cipher.mode.tag.getBytes() : '');
  var cipherB64 = forge.util.encode64(cipherValue);

  var wrapped, keyMethodInner = '';
  if (keyAlg === XENC_NS + 'rsa-1_5') {
    wrapped = pub.encrypt(sessionKey, 'RSAES-PKCS1-V1_5');
  } else {
    var digestUri = opts.digest || (XENC_NS + 'sha256');
    var oaepOpts = { md: forgeMdFor(digestUri) };
    keyMethodInner = '<ds:DigestMethod xmlns:ds="' + DS_NS + '" Algorithm="' + digestUri + '"/>';
    if (keyAlg === XENC11_NS + 'rsa-oaep') {
      var mgfUri = opts.mgf || (XENC11_NS + 'mgf1sha256');
      oaepOpts.mgf1 = { md: mgfMdFor(mgfUri) };
      keyMethodInner += '<xenc11:MGF xmlns:xenc11="' + XENC11_NS + '" Algorithm="' + mgfUri + '"/>';
    } else {
      oaepOpts.mgf1 = { md: forge.md.sha1.create() };
    }
    wrapped = pub.encrypt(sessionKey, 'RSA-OAEP', oaepOpts);
  }
  var wrappedB64 = forge.util.encode64(wrapped);

  log.debug("Leaving encryptXml().");
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

// --- WS-Security message signing (XML-DSIG) ---------------------------------
// A detached enveloped-style signature placed in the <wsse:Security> header,
// referencing the SOAP Body and (optionally) the Timestamp by their wsu:Id,
// using exclusive C14N + RSA-SHA* — the same primitives above. Pure (no DOM
// element ids): the caller passes the SOAP string and the signing material, so
// this is unit-testable against an external verifier (xml-crypto).
//
// opts: { privateKeyPem, certPem, sigAlg, signTimestamp }
var WSU_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
function firstByLocal(root, name) {
  var els = root.getElementsByTagNameNS('*', name);
  return els && els.length ? els[0] : null;
}
function signWsSecurity(soapXml, opts) {
  log.debug("Entering signWsSecurity().");
  opts = opts || {};
  if (!opts.privateKeyPem) throw new Error('signWsSecurity: privateKeyPem is required.');
  var sigAlg = opts.sigAlg || SIG_ALG_RSA_SHA256;
  var spec = sigAlgSpec(sigAlg);

  var doc = parseXmlStrict(soapXml, 'the SOAP envelope to sign');
  var security = firstByLocal(doc, 'Security');
  if (!security) throw new Error('No <wsse:Security> header to hold the signature — enable a timestamp or a credential.');

  var targets = [];
  var body = firstByLocal(doc, 'Body');
  if (body) targets.push(body);
  if (opts.signTimestamp) {
    var ts = firstByLocal(doc, 'Timestamp');
    if (ts) targets.push(ts);
  }

  var refs = targets.map(function (t) {
    var id = t.getAttributeNS(WSU_NS, 'Id') || t.getAttribute('wsu:Id') || '';
    var digest = digestBase64(canonicalize(t), spec.md);
    return '<ds:Reference URI="#' + id + '">' +
      '<ds:Transforms><ds:Transform Algorithm="' + C14N_EXCLUSIVE + '"/></ds:Transforms>' +
      '<ds:DigestMethod Algorithm="' + spec.digestUri + '"/>' +
      '<ds:DigestValue>' + digest + '</ds:DigestValue></ds:Reference>';
  }).join('');

  var signedInfo = '<ds:SignedInfo xmlns:ds="' + DS_NS + '">' +
    '<ds:CanonicalizationMethod Algorithm="' + C14N_EXCLUSIVE + '"/>' +
    '<ds:SignatureMethod Algorithm="' + sigAlg + '"/>' + refs + '</ds:SignedInfo>';
  var siCanon = canonicalize(new DOMParser().parseFromString(signedInfo, 'application/xml').documentElement);
  var pk = forge.pki.privateKeyFromPem(opts.privateKeyPem);
  var md = spec.md(); md.update(siCanon, 'utf8');
  var sigVal = forge.util.encode64(pk.sign(md));
  var certB64 = certPemToB64(opts.certPem);

  var signature = '<ds:Signature xmlns:ds="' + DS_NS + '">' + signedInfo +
    '<ds:SignatureValue>' + sigVal + '</ds:SignatureValue>' +
    '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
    '</ds:Signature>';
  var sigNode = doc.importNode(new DOMParser().parseFromString(signature, 'application/xml').documentElement, true);
  security.insertBefore(sigNode, security.firstChild);
  log.debug("Leaving signWsSecurity().");
  return new XMLSerializer().serializeToString(doc);
}

// --- Enveloped XML Signature (XML-DSIG) -------------------------------------
// The generic form of saml_request.js's signPostEnveloped(): digest the document
// element, build a <ds:SignedInfo> referencing it, insert the <ds:Signature>
// into the document, then sign the canonicalized SignedInfo in place. Same
// primitives (exclusive C14N + RSA-SHA*, node-forge) — only the reference URI
// and the placement of the <ds:Signature> are parameterized, because the SAML
// schemas disagree about both:
//
//   SAML 2.0   ID="_x"          Reference URI="#_x"  Signature after <Issuer>
//   SAML 1.1   AssertionID="_x" Reference URI="#_x"  Signature is the LAST child
//   SAML 1.0   AssertionID="_x" Reference URI=""     Signature is the LAST child
//                               (1.0's AssertionID is not an xs:ID, so the
//                                whole-document reference is the safe form)
//
// opts: { privateKeyPem, certPem, sigAlg, digestUri, c14nAlg, refUri,
//         placement: 'after-issuer' | 'last' | 'first', includeKeyInfo }
function signEnveloped(xml, opts) {
  log.debug("Entering signEnveloped().");
  opts = opts || {};
  if (!opts.privateKeyPem) throw new Error('signEnveloped: privateKeyPem is required.');
  var sigAlg = opts.sigAlg || SIG_ALG_RSA_SHA256;
  var spec = sigAlgSpec(sigAlg);
  var digestUri = opts.digestUri || spec.digestUri;
  var c14nAlg = opts.c14nAlg || C14N_EXCLUSIVE;
  var c14nFn = c14nForAlg(c14nAlg);

  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) throw new Error('malformed XML — cannot sign.');
  var root = doc.documentElement;

  var refUri = opts.refUri;
  if (refUri == null) {
    var id = root.getAttribute('ID') || root.getAttribute('AssertionID') || root.getAttribute('Id') || '';
    refUri = id ? ('#' + id) : '';
  }

  // Reference digest: c14n(root) with no <Signature> present — exactly what the
  // enveloped-signature transform reproduces at verification time.
  var digest = digestBase64(c14nFn(root), spec.md);

  var signedInfo = '<ds:SignedInfo xmlns:ds="' + DS_NS + '">' +
    '<ds:CanonicalizationMethod Algorithm="' + c14nAlg + '"/>' +
    '<ds:SignatureMethod Algorithm="' + sigAlg + '"/>' +
    '<ds:Reference URI="' + refUri + '">' +
    '<ds:Transforms>' +
    '<ds:Transform Algorithm="' + TRANSFORM_ENVELOPED + '"/>' +
    '<ds:Transform Algorithm="' + c14nAlg + '"/>' +
    '</ds:Transforms>' +
    '<ds:DigestMethod Algorithm="' + digestUri + '"/>' +
    '<ds:DigestValue>' + digest + '</ds:DigestValue>' +
    '</ds:Reference></ds:SignedInfo>';

  var keyInfo = '';
  if (opts.includeKeyInfo !== false && opts.certPem) {
    keyInfo = '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
      certPemToB64(opts.certPem) + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>';
  }
  // Insert the signature with an empty SignatureValue FIRST, then canonicalize
  // the SignedInfo in place. Inclusive C14N pulls in every namespace declared by
  // the ancestors, so a SignedInfo canonicalized while detached would not match
  // the octets a verifier computes from the finished document. (Exclusive C14N
  // is unaffected — it only renders visibly-utilized prefixes — so this ordering
  // is correct for both.)
  var signature = '<ds:Signature xmlns:ds="' + DS_NS + '">' + signedInfo +
    '<ds:SignatureValue></ds:SignatureValue>' + keyInfo + '</ds:Signature>';
  var sigNode = doc.importNode(new DOMParser().parseFromString(signature, 'application/xml').documentElement, true);

  var placement = opts.placement || 'after-issuer';
  if (placement === 'last') {
    root.appendChild(sigNode);
  } else if (placement === 'first') {
    root.insertBefore(sigNode, root.firstChild);
  } else {
    var issuer = null, kids = root.childNodes;
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].nodeType === 1 && kids[i].localName === 'Issuer') { issuer = kids[i]; break; }
    }
    if (issuer) root.insertBefore(sigNode, issuer.nextSibling);
    else root.insertBefore(sigNode, root.firstChild);
  }

  var siNode = directChildByLocal(sigNode, 'SignedInfo');
  var pk = forge.pki.privateKeyFromPem(opts.privateKeyPem);
  var md = spec.md();
  md.update(c14nFn(siNode), 'utf8');
  directChildByLocal(sigNode, 'SignatureValue')
    .appendChild(doc.createTextNode(forge.util.encode64(pk.sign(md))));

  log.debug("Leaving signEnveloped().");
  return new XMLSerializer().serializeToString(doc);
}

// --- XML Signature VERIFICATION (enveloped) --------------------------------
// Verify an enveloped XML digital signature such as the one on a SAML assertion
// (or any signed element): checks every Reference digest (after applying the
// enveloped-signature + C14N transforms) and the SignatureValue over the
// canonicalized SignedInfo, using the certificate embedded in KeyInfo
// (or opts.certPem if supplied). Reuses the same exclusive/inclusive C14N,
// digest, and sigAlgSpec helpers used for signing. RSA keys (RSASSA-PKCS1-v1_5).
//
// Returns { valid, signatureValid, referencesValid, references[], signatureMethod,
//           canonicalization, signerSubject, signerCertB64 } or { valid:false, error }.
function findById(root, id) {
  log.debug("Entering findById().");
  var all = root.getElementsByTagName('*');
  for (var i = 0; i < all.length; i++) {
    var e = all[i];
    for (var j = 0; j < e.attributes.length; j++) {
      var a = e.attributes[j];
      var ln = a.localName || a.name;
      // Id/ID/id cover SAML 2.0 (ID), WS-Security (wsu:Id) and generic ids;
      // AssertionID is the SAML 1.1 assertion id attribute (WS-Fed tokens are
      // frequently SAML 1.1), whose enveloped signature references #<AssertionID>.
      if ((ln === 'Id' || ln === 'ID' || ln === 'id' || ln === 'AssertionID') && a.value === id) return e;
    }
  }
  log.debug("Leaving findById().");
  return null;
}
function c14nForAlg(alg) {
  alg = alg || '';
  if (alg.indexOf('exc-c14n') >= 0) return canonicalize;
  if (alg.indexOf('xml-c14n') >= 0) return canonicalizeInclusive; // inclusive C14N 1.0
  return canonicalize; // default to exclusive (what SAML/WS-Trust use)
}
function certSubjectCN(cert) {
  try {
    var f = cert.subject.getField('CN');
    return f ? f.value : '';
  } catch (e) {
    return '';
  }
}

function verifyXmlSignature(xml, opts) {
  log.debug("Entering verifyXmlSignature().");
  opts = opts || {};
  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) return { valid: false, error: 'malformed XML' };

  var sig = firstByLocal(doc, 'Signature');
  if (!sig) return { valid: false, error: 'No <ds:Signature> element found.' };
  var si = firstByLocal(sig, 'SignedInfo');
  if (!si) return { valid: false, error: 'Signature has no <SignedInfo>.' };
  var smEl = firstByLocal(si, 'SignatureMethod');
  var sigAlg = smEl ? smEl.getAttribute('Algorithm') : '';
  var cmEl = firstByLocal(si, 'CanonicalizationMethod');
  var c14nAlg = cmEl ? cmEl.getAttribute('Algorithm') : C14N_EXCLUSIVE;
  var svEl = firstByLocal(sig, 'SignatureValue');
  if (!svEl) return { valid: false, error: 'Signature has no <SignatureValue>.' };
  var spec = sigAlgSpec(sigAlg);

  // Signing certificate: prefer a supplied cert, else the one in KeyInfo.
  var certB64 = '';
  var x509 = firstByLocal(sig, 'X509Certificate');
  if (x509) certB64 = (x509.textContent || '').replace(/\s+/g, '');
  var certPem = opts.certPem ? pemWrapCert(opts.certPem) : (certB64 ? pemWrapCert(certB64) : '');
  if (!certPem) return { valid: false, error: 'No signing certificate in KeyInfo and none supplied.' };
  var cert, pub;
  try {
    cert = forge.pki.certificateFromPem(certPem);
    pub = cert.publicKey;
  } catch (e) {
    return { valid: false, error: 'Could not parse signing certificate: ' + e.message };
  }

  // 1) SignatureValue over C14N(SignedInfo) — compute before detaching the
  //    signature (exclusive C14N is position-independent, but keep it in-tree).
  var siCanon = c14nForAlg(c14nAlg)(si);
  var signatureBytes = forge.util.decode64((svEl.textContent || '').replace(/\s+/g, ''));
  var signatureValid = false;
  try {
    var md1 = spec.md();
    md1.update(siCanon, 'utf8');
    signatureValid = pub.verify(md1.digest().bytes(), signatureBytes);
  } catch (e) {
    signatureValid = false;
  }

  // 2) Reference digests. Apply the enveloped-signature transform by removing
  //    the <Signature> from the tree, then C14N the referenced element.
  if (sig.parentNode) sig.parentNode.removeChild(sig);
  var references = [];
  var refs = si.getElementsByTagNameNS('*', 'Reference');
  for (var i = 0; i < refs.length; i++) {
    var ref = refs[i];
    var uri = ref.getAttribute('URI') || '';
    var dmEl = firstByLocal(ref, 'DigestMethod');
    var digAlg = dmEl ? dmEl.getAttribute('Algorithm') : (XENC_NS + 'sha256');
    var dvEl = firstByLocal(ref, 'DigestValue');
    var declared = dvEl ? (dvEl.textContent || '').replace(/\s+/g, '') : '';
    var target = uri === '' ? doc.documentElement : findById(doc, uri.replace(/^#/, ''));
    if (!target) { references.push({ uri: uri, ok: false, reason: 'referenced element not found' }); continue; }
    var c14nRef = C14N_EXCLUSIVE;
    var trs = ref.getElementsByTagNameNS('*', 'Transform');
    for (var t = 0; t < trs.length; t++) { var ta = trs[t].getAttribute('Algorithm') || ''; if (ta.indexOf('c14n') >= 0) c14nRef = ta; }
    var canon = c14nForAlg(c14nRef)(target);
    var rmd = forgeMdFor(digAlg); rmd.update(canon, 'utf8');
    var computed = forge.util.encode64(rmd.digest().getBytes());
    references.push({ uri: uri, ok: computed === declared, computed: computed, declared: declared, digestAlg: digAlg });
  }
  var referencesValid = references.length > 0 && references.every(function (r) { return r.ok; });

  log.debug("Leaving verifyXmlSignature().");
  return {
    valid: signatureValid && referencesValid,
    signatureValid: signatureValid,
    referencesValid: referencesValid,
    references: references,
    signatureMethod: sigAlg,
    canonicalization: c14nAlg,
    signerSubject: certSubjectCN(cert),
    signerCertB64: certB64
  };
}

// --- XML DECRYPTION (W3C xmlenc) -------------------------------------------
// Inverse of encryptXml(): given an <xenc:EncryptedData> (as a string, or an
// element containing one — e.g. a <saml:EncryptedAssertion>), RSA-unwrap the
// session key with the recipient private key and decrypt the data, returning
// the plaintext XML. Handles the same algorithm set encryptXml produces
// (AES-GCM/CBC + 3DES-CBC data; RSA-OAEP / RSA-OAEP-MGF1P / RSA-1_5 key wrap).
//
// opts: { privateKeyPem }  (the recipient's RSA private key, PEM)
function directChildByLocal(el, name) {
  var c = el.firstChild;
  while (c) { if (c.nodeType === 1 && (c.localName === name)) return c; c = c.nextSibling; }
  return null;
}
function cipherValueOf(container) {
  // The <xenc:CipherData><xenc:CipherValue> directly under `container`.
  var cd = directChildByLocal(container, 'CipherData');
  if (!cd) return '';
  var cv = directChildByLocal(cd, 'CipherValue');
  return cv ? (cv.textContent || '').replace(/\s+/g, '') : '';
}

function decryptXml(xml, opts) {
  log.debug("Entering decryptXml().");
  opts = opts || {};
  if (!opts.privateKeyPem) throw new Error('decryptXml: privateKeyPem is required.');
  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) throw new Error('malformed XML');

  var ed = firstByLocal(doc, 'EncryptedData');
  if (!ed) throw new Error('no <xenc:EncryptedData> to decrypt.');
  var emEl = firstByLocal(ed, 'EncryptionMethod');
  var dataAlg = emEl ? emEl.getAttribute('Algorithm') : '';
  var spec = dataAlgSpec(dataAlg);

  // The wrapped session key may be nested in EncryptedData/KeyInfo, or a sibling
  // <xenc:EncryptedKey> (referenced by a ds:RetrievalMethod) — the layout
  // Keycloak and other IdPs emit. Look inside EncryptedData first, then anywhere.
  var ek = firstByLocal(ed, 'EncryptedKey') || firstByLocal(doc, 'EncryptedKey');
  if (!ek) throw new Error('no <xenc:EncryptedKey> — could not find the wrapped session key.');
  var kmEl = firstByLocal(ek, 'EncryptionMethod');
  var keyAlg = kmEl ? kmEl.getAttribute('Algorithm') : '';
  var wrappedB64 = cipherValueOf(ek);
  if (!wrappedB64) throw new Error('EncryptedKey has no CipherValue.');

  var priv = forge.pki.privateKeyFromPem(opts.privateKeyPem);
  var wrapped = forge.util.decode64(wrappedB64);
  var sessionKey;
  try {
    if (keyAlg === XENC_NS + 'rsa-1_5') {
      sessionKey = priv.decrypt(wrapped, 'RSAES-PKCS1-V1_5');
    } else {
      var digEl = kmEl ? firstByLocal(kmEl, 'DigestMethod') : null;
      var digestUri = digEl ? digEl.getAttribute('Algorithm') : (XENC_NS + 'sha256');
      var oaep = { md: forgeMdFor(digestUri) };
      if (keyAlg === XENC11_NS + 'rsa-oaep') {
        var mgfEl = kmEl ? firstByLocal(kmEl, 'MGF') : null;
        var mgfUri = mgfEl ? mgfEl.getAttribute('Algorithm') : (XENC11_NS + 'mgf1sha1');
        oaep.mgf1 = { md: mgfMdFor(mgfUri) };
      } else {
        // rsa-oaep-mgf1p: MGF1 is fixed to SHA-1.
        oaep.mgf1 = { md: forge.md.sha1.create() };
      }
      sessionKey = priv.decrypt(wrapped, 'RSA-OAEP', oaep);
    }
  } catch (e) {
    throw new Error('could not unwrap the session key (wrong private key or key-transport algorithm mismatch): ' + e.message);
  }

  var dataB64 = cipherValueOf(ed);
  if (!dataB64) throw new Error('EncryptedData has no CipherValue.');
  var cipherRaw = forge.util.decode64(dataB64);
  var iv = cipherRaw.substring(0, spec.ivBytes);
  var decipher = forge.cipher.createDecipher(spec.cipher, sessionKey);
  if (spec.gcm) {
    var tag = cipherRaw.substring(cipherRaw.length - 16);
    var body = cipherRaw.substring(spec.ivBytes, cipherRaw.length - 16);
    decipher.start({ iv: iv, tag: forge.util.createBuffer(tag), tagLength: 128 });
    decipher.update(forge.util.createBuffer(body));
  } else {
    decipher.start({ iv: iv });
    decipher.update(forge.util.createBuffer(cipherRaw.substring(spec.ivBytes)));
  }
  if (!decipher.finish()) throw new Error('data decryption failed (wrong key or corrupted ciphertext).');
  log.debug("Leaving decryptXml().");
  return forge.util.decodeUtf8(decipher.output.getBytes());
}

// Generate an RSA key pair + self-signed certificate (for a fresh signing key).
function generateKeyPair(bits, cn) {
  log.debug("Entering generateKeyPair().");
  var kp = forge.pki.rsa.generateKeyPair({ bits: bits || 2048, e: 0x10001 });
  var cert = forge.pki.createCertificate();
  cert.publicKey = kp.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
  var attrs = [{ name: 'commonName', value: cn || 'ws-trust-debugger' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(kp.privateKey, forge.md.sha256.create());
  log.debug("Leaving generateKeyPair().");
  return {
    privateKeyPem: forge.pki.privateKeyToPem(kp.privateKey).trim() + '\n',
    certPem: forge.pki.certificateToPem(cert).trim() + '\n'
  };
}

module.exports = {
  forge: forge,
  DS_NS: DS_NS,
  XENC_NS: XENC_NS,
  XENC11_NS: XENC11_NS,
  C14N_EXCLUSIVE: C14N_EXCLUSIVE,
  TRANSFORM_ENVELOPED: TRANSFORM_ENVELOPED,
  SIG_ALG_RSA_SHA256: SIG_ALG_RSA_SHA256,
  genId: genId,
  xmlEscape: xmlEscape,
  certPemToB64: certPemToB64,
  pemWrapCert: pemWrapCert,
  digestBase64: digestBase64,
  sigAlgSpec: sigAlgSpec,
  canonicalize: canonicalize,
  canonicalizeInclusive: canonicalizeInclusive,
  parseXmlStrict: parseXmlStrict,
  encryptXml: encryptXml,
  decryptXml: decryptXml,
  signEnveloped: signEnveloped,
  signWsSecurity: signWsSecurity,
  verifyXmlSignature: verifyXmlSignature,
  generateKeyPair: generateKeyPair
};
