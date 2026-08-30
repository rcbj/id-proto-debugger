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
// node-forge does all the crypto (RSA sign/keygen, block ciphers, RSA key
// wrap). Only browser-native APIs (DOMParser/XMLSerializer, window.crypto) are
// used besides forge, so this bundles cleanly with browserify + envify.


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
var TRANSFORM_ENVELOPED =
    'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
var SIG_ALG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

// RFC 4122-ish id suitable for an XML ID (an NCName: starts with '_').
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

function xmlEscape(s) {
  log.debug("Entering xmlEscape().");
  log.debug("Leaving xmlEscape().");
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

// Strip PEM armor to bare base64 DER.
function certPemToB64(pem) {
  log.debug("Entering certPemToB64().");
  log.debug("Leaving certPemToB64().");
  return String(pem || '')
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

// Wrap bare base64 DER in PEM (pass-through if already PEM) so forge can parse
// it.
function pemWrapCert(certPemOrB64) {
  log.debug("Entering pemWrapCert().");
  var s = String(certPemOrB64 || '');
  if (/-----BEGIN CERTIFICATE-----/.test(s)) {
    log.debug("Leaving pemWrapCert().");
    return s;
  }
  var b64 = s.replace(/\s+/g, '');
  var lines = b64.match(/.{1,64}/g) || [];
  log.debug("Leaving pemWrapCert().");
  return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') +
      '\n-----END CERTIFICATE-----\n';
}

function digestBase64(str, mdFactory) {
  log.debug("Entering digestBase64().");
  var md = mdFactory();
  md.update(str, 'utf8');
  log.debug("Leaving digestBase64().");
  return forge.util.encode64(md.digest().getBytes());
}

// SignatureMethod URI -> forge digest factory + matching Reference DigestMethod
// URI. The keys are RSA, so these are the RSA-family methods from xmldsig /
// xmldsig-more (RFC 6931).
function sigAlgSpec(uri) {
  log.debug("Entering sigAlgSpec().");
  switch (uri) {
    case 'http://www.w3.org/2000/09/xmldsig#rsa-sha1':
      log.debug("Leaving sigAlgSpec().");
      return { md: forge.md.sha1.create,
              digestUri: 'http://www.w3.org/2000/09/xmldsig#sha1' };
    case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384':
      log.debug("Leaving sigAlgSpec().");
      return { md: forge.md.sha384.create,
              digestUri: 'http://www.w3.org/2001/04/xmldsig-more#sha384' };
    case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512':
      log.debug("Leaving sigAlgSpec().");
      return { md: forge.md.sha512.create,
              digestUri: 'http://www.w3.org/2001/04/xmlenc#sha512' };
    case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256':
    default:
      log.debug("Leaving sigAlgSpec().");
      return { md: forge.md.sha256.create,
              digestUri: 'http://www.w3.org/2001/04/xmlenc#sha256' };
  }
  log.debug("Leaving sigAlgSpec().");
}

// --- Canonical XML 1.0 over a DOM element ----------------------------------
// Exclusive C14N renders on each element only the namespace declarations it
// *visibly utilizes* (its own prefix + the prefixes of namespace-qualified
// attributes), so a subtree canonicalizes identically standalone or nested —
// the property the detached SignedInfo signature relies on. (Verbatim from
// saml_request.js.)
//
// THE LAST PARAMETER IS NEW AND EVERY PRE-EXISTING CALLER OMITS IT. `opts`
// carries the three things the XML Signature pane on the Digital Signature
// page needs and the SAML / WS-Trust / WS-Federation callers never asked for:
//
//   comments  — emit comment nodes, which is the whole of the difference
//               between each C14N URI and its "#WithComments" twin. A
//               signature made under one and verified under the other fails on
//               a document that contains a single comment and passes on every
//               document that does not, which is the kind of defect that ships.
//   prefixes  — the exclusive transform's InclusiveNamespaces PrefixList, as a
//               set. A prefix named there is rendered wherever it is in scope
//               rather than only where it is visibly utilized — which is the
//               point of the option: a signed subtree that MENTIONS a prefix
//               inside attribute VALUES (a QName in an xsi:type, a SOAP
//               actor) loses that declaration under plain exclusive C14N,
//               because "visibly utilized" does not look inside values.
//   include   — a node-set membership test. This is how a transform that
//               REMOVES nodes (enveloped-signature, XPath, XPath Filter 2.0)
//               reaches the canonicalizer. An element that fails it
//               contributes no tags of its own AND ITS CHILDREN ARE STILL
//               VISITED, which is what C14N of a node-set does; a subtree
//               deletion would be a different, easier, wrong thing.
//
// ONE DELIBERATE SIMPLIFICATION, stated because it is invisible from the
// output: attributes are not filtered. An element that is in the node-set
// contributes all of its attributes. XMLDSIG allows a transform to select an
// element without its attributes; no transform anybody uses does that, and
// pretending to support it would be worse than saying so here.
function canonicalize(apex, opts) {
  log.debug("Entering canonicalize().");
  log.debug("Leaving canonicalize().");
  return c14nSerialize(apex, {}, opts);
}

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
  log.debug("Entering c14nTextEscape().");
  log.debug("Leaving c14nTextEscape().");
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g,
                '&gt;').replace(/\r/g, '&#xD;');
}
function c14nAttrEscape(s) {
  log.debug("Entering c14nAttrEscape().");
  log.debug("Leaving c14nAttrEscape().");
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g,
                '&quot;')
    .replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');
}
// Whether a node is in the node-set being canonicalized. No predicate means
// "everything", which is what every caller that predates the XML Signature
// pane wants and gets by passing nothing.
function c14nIncluded(node, opts) {
  log.debug("Entering c14nIncluded().");
  if (!opts || !opts.include) {
    log.debug("Leaving c14nIncluded(). No filter.");
    return true;
  }
  log.debug("Leaving c14nIncluded().");
  return !!opts.include(node);
}
// The non-element children shared by both canonicalizers: text and CDATA
// become escaped text, comments appear only under a "#WithComments" method,
// and processing instructions are emitted in the C14N form. A node the
// node-set does not contain contributes nothing.
function c14nLeaf(child, opts) {
  log.debug("Entering c14nLeaf().");
  if (!c14nIncluded(child, opts)) {
    log.debug("Leaving c14nLeaf(). Filtered out.");
    return '';
  }
  if (child.nodeType === 3 || child.nodeType === 4) {
    log.debug("Leaving c14nLeaf(). Text.");
    return c14nTextEscape(child.nodeValue);
  }
  if (child.nodeType === 8 && opts && opts.comments) {
    log.debug("Leaving c14nLeaf(). Comment.");
    return '<!--' + String(child.nodeValue) + '-->';
  }
  if (child.nodeType === 7) {
    var data = child.data || child.nodeValue || '';
    log.debug("Leaving c14nLeaf(). Processing instruction.");
    return '<?' + child.target + (data ? ' ' + data : '') + '?>';
  }
  log.debug("Leaving c14nLeaf(). Nothing.");
  return '';
}
function c14nSerialize(el, rendered, opts) {
  log.debug("Entering c14nSerialize().");
  var o = opts || {};
  var included = c14nIncluded(el, o);
  var childRendered = {};
  for (var k in rendered) { if (rendered.hasOwnProperty(k)) childRendered[k] =
       rendered[k]; }
  var out = '';
  if (included) {
    var inscope = c14nInScopeNs(el);
    var utilized = {};
    utilized[el.prefix || ''] = true;
    // InclusiveNamespaces PrefixList. "#default" is how the list names the
    // default namespace, because a list of prefixes has no way to write an
    // empty one.
    if (o.prefixes) {
      Object.keys(o.prefixes).forEach(function (p) {
        utilized[p === '#default' ? '' : p] = true;
      });
    }
    var attrs = [];
    for (var i = 0; i < el.attributes.length; i++) {
      var a = el.attributes[i];
      if (a.name === 'xmlns' || a.name.indexOf('xmlns:') === 0) continue;
      if (a.prefix) utilized[a.prefix] = true;
      attrs.push(a);
    }
    var nsOut = [];
    Object.keys(utilized).forEach(function (prefix) {
      var uri = inscope.hasOwnProperty(prefix) ?
          inscope[prefix] : (prefix === '' ? '' : undefined);
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
    out = '<' + el.nodeName;
    nsOut.forEach(function (n) {
      out += ' ' + (n.prefix ? ('xmlns:' + n.prefix) : 'xmlns') + '="' +
          c14nAttrEscape(n.uri) + '"';
    });
    attrs.sort(function (a, b) {
      var au = a.namespaceURI || '', bu = b.namespaceURI || '';
      if (au !== bu) return au < bu ? -1 : 1;
      var al = a.localName || a.name, bl = b.localName || b.name;
      return al < bl ? -1 : (al > bl ? 1 : 0);
    });
    attrs.forEach(function (a) { out += ' ' + a.name + '="' +
                  c14nAttrEscape(a.value) + '"'; });
    out += '>';
  }
  var child = el.firstChild;
  while (child) {
    if (child.nodeType === 1) out += c14nSerialize(child, childRendered, o);
    else out += c14nLeaf(child, o);
    child = child.nextSibling;
  }
  log.debug("Leaving c14nSerialize().");
  return included ? (out + '</' + el.nodeName + '>') : out;
}

// Inclusive Canonical XML 1.0 — the encryption pane's "Inclusive C14N" option,
// and the CanonicalizationMethod half of the XML Signature pane. Same `opts`
// as the exclusive form above, minus `prefixes`, which is an exclusive-only
// idea (inclusive C14N already carries every in-scope declaration).
function canonicalizeInclusive(apex, opts) {
  log.debug("Entering canonicalizeInclusive().");
  log.debug("Leaving canonicalizeInclusive().");
  return c14nIncl(apex, {}, true, opts);
}
function c14nIncl(el, rendered, isApex, opts) {
  log.debug("Entering c14nIncl().");
  var o = opts || {};
  var included = c14nIncluded(el, o);
  var childRendered = {};
  for (var k in rendered) { if (rendered.hasOwnProperty(k)) childRendered[k] =
       rendered[k]; }
  var out = '';
  if (included) {
    var nsSource = {};
    if (isApex) { nsSource = c14nInScopeNs(el); }
    else {
      for (var a = 0; a < el.attributes.length; a++) {
        var at = el.attributes[a];
        if (at.name === 'xmlns') nsSource[''] = at.value;
        else if (at.name.indexOf('xmlns:') === 0) nsSource[at.name.slice(6)] =
                 at.value;
      }
    }
    var nsOut = [];
    Object.keys(nsSource).forEach(function (p) {
      if (childRendered[p] !== nsSource[p]) { nsOut.push({ prefix: p,
          uri: nsSource[p] }); childRendered[p] = nsSource[p]; }
    });
    nsOut.sort(function (a, b) {
      if (a.prefix === b.prefix) return 0;
      if (a.prefix === '') return -1;
      if (b.prefix === '') return 1;
      return a.prefix < b.prefix ? -1 : 1;
    });
    out = '<' + el.nodeName;
    nsOut.forEach(function (n) { out += ' ' + (n.prefix ? ('xmlns:' +
                  n.prefix) : 'xmlns') + '="' + c14nAttrEscape(n.uri) + '"'; });
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
    attrs.forEach(function (a) { out += ' ' + a.name + '="' +
                  c14nAttrEscape(a.value) + '"'; });
    out += '>';
  }
  var child = el.firstChild;
  while (child) {
    if (child.nodeType === 1) out += c14nIncl(child, childRendered, false, o);
    else out += c14nLeaf(child, o);
    child = child.nextSibling;
  }
  log.debug("Leaving c14nIncl().");
  return included ? (out + '</' + el.nodeName + '>') : out;
}

// --- XML Encryption (W3C xmlenc / xmlenc11) ---------------------------------
function dataAlgSpec(uri) {
  log.debug("Entering dataAlgSpec().");
  switch (uri) {
    case XENC11_NS + 'aes128-gcm':
      log.debug("Leaving dataAlgSpec().");
      return { cipher: 'AES-GCM', keyBytes: 16, ivBytes: 12, gcm: true };
    case XENC11_NS + 'aes192-gcm':
      log.debug("Leaving dataAlgSpec().");
      return { cipher: 'AES-GCM', keyBytes: 24, ivBytes: 12, gcm: true };
    case XENC11_NS + 'aes256-gcm':
      log.debug("Leaving dataAlgSpec().");
      return { cipher: 'AES-GCM', keyBytes: 32, ivBytes: 12, gcm: true };
    case XENC_NS + 'aes128-cbc':
      log.debug("Leaving dataAlgSpec().");
      return { cipher: 'AES-CBC', keyBytes: 16, ivBytes: 16, gcm: false };
    case XENC_NS + 'aes192-cbc':
      log.debug("Leaving dataAlgSpec().");
      return { cipher: 'AES-CBC', keyBytes: 24, ivBytes: 16, gcm: false };
    case XENC_NS + 'aes256-cbc':
      log.debug("Leaving dataAlgSpec().");
      return { cipher: 'AES-CBC', keyBytes: 32, ivBytes: 16, gcm: false };
    case XENC_NS + 'tripledes-cbc':
      log.debug("Leaving dataAlgSpec().");
      return { cipher: '3DES-CBC', keyBytes: 24, ivBytes: 8, gcm: false };
    default: throw new Error('Unsupported data encryption algorithm: ' + uri);
  }
  log.debug("Leaving dataAlgSpec().");
}
function forgeMdFor(uri) {
  log.debug("Entering forgeMdFor().");
  switch (uri) {
    case 'http://www.w3.org/2000/09/xmldsig#sha1':
      log.debug("Leaving forgeMdFor().");
      return forge.md.sha1.create();
    case XENC_NS + 'sha256':
      log.debug("Leaving forgeMdFor().");
      return forge.md.sha256.create();
    case 'http://www.w3.org/2001/04/xmldsig-more#sha384':
      log.debug("Leaving forgeMdFor().");
      return forge.md.sha384.create();
    case XENC_NS + 'sha512':
      log.debug("Leaving forgeMdFor().");
      return forge.md.sha512.create();
    default:
      log.debug("Leaving forgeMdFor().");
      return forge.md.sha256.create();
  }
}
function mgfMdFor(uri) {
  log.debug("Entering mgfMdFor().");
  switch (uri) {
    case XENC11_NS + 'mgf1sha1':
      log.debug("Leaving mgfMdFor().");
      return forge.md.sha1.create();
    case XENC11_NS + 'mgf1sha256':
      log.debug("Leaving mgfMdFor().");
      return forge.md.sha256.create();
    case XENC11_NS + 'mgf1sha384':
      log.debug("Leaving mgfMdFor().");
      return forge.md.sha384.create();
    case XENC11_NS + 'mgf1sha512':
      log.debug("Leaving mgfMdFor().");
      return forge.md.sha512.create();
    default:
      log.debug("Leaving mgfMdFor().");
      return forge.md.sha1.create();
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
  var doc;
  try {
    doc = new DOMParser().parseFromString(xml, 'application/xml');
  } catch (e) {
    // The two DOMParsers refuse differently and BOTH have to be caught here.
    // The browser's puts a <parsererror> element in the document it returns;
    // @xmldom/xmldom (which the node-side tests load this module with) THROWS.
    // A caller that only checked for the element saw the throw escape as an
    // unrelated failure two frames up, naming a tag mismatch rather than the
    // document it was asked about.
    throw new Error('malformed ' + label + ' — it is not well-formed XML: ' +
        e.message);
  }
  if (!doc || doc.getElementsByTagName('parsererror').length ||
      !doc.documentElement) {
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
    if (!isContent) {
      log.debug("Leaving encPlaintext().");
      return fn(root);
    }
    var inner = '', ch = root.firstChild;
    while (ch) { if (ch.nodeType === 1) inner += fn(ch); ch = ch.nextSibling; }
    log.debug("Leaving encPlaintext().");
    return inner;
  }
  if (!isContent) {
    log.debug("Leaving encPlaintext().");
    return xml;
  }
  var d2 = parseXmlStrict(xml, 'the XML to encrypt');
  var r2 = d2.documentElement, s = '', c = r2.firstChild;
  while (c) { s += new XMLSerializer().serializeToString(c); c =
         c.nextSibling; }
  log.debug("Leaving encPlaintext().");
  return s;
}

// Encrypt an XML string, returning an <xenc:EncryptedData> element string.
// opts: { certPem, dataAlg, keyAlg, type, c14nMode, digest, mgf } — the same
// knobs the SAML encryption panel exposes.
// ---------------------------------------------------------------------------
// ENCRYPTION TO A KEM RECIPIENT. See the KEM section header for why this is a
// separate path rather than another branch inside the wrap: the content
// encryption key is not chosen here and not carried — it is DERIVED, on both
// sides, from a secret the encapsulation produces.
//
// `opts.kem` is the primitive: `encapsulate(publicKeyBytes)` returning
// `{ ciphertext, sharedSecret }`. `opts.kemPublicKey` is the recipient's
// encapsulation key, raw. Both are the caller's because the lattice does not
// belong in this file — the same rule the signature side follows.
//
// `Info` binds the derivation to THIS document's two algorithms, so a shared
// secret cannot be reused across a different pairing, and it is written into
// the document so a recipient reproduces it by reading rather than by
// agreeing.
// ---------------------------------------------------------------------------
function encapsulateXml(xml, opts, ctx) {
  log.debug("Entering encapsulateXml(). alg=" + ctx.kem.alg);
  if (!opts.kem || typeof opts.kem.encapsulate !== 'function') {
    log.debug("Leaving encapsulateXml(). No KEM.");
    throw new Error(ctx.kem.label + ' needs an encapsulation function — this ' +
        'file holds the identifiers and the key derivation, not the lattice ' +
        '(the same split it makes for post-quantum signatures). Pass ' +
        'opts.kem, which client/src/xmldsig_pqc.js builds from ' +
        'client/src/pk_encryption.js.');
  }
  var recipient = opts.kemPublicKey;
  if (!recipient || !recipient.length) {
    log.debug("Leaving encapsulateXml(). No recipient key.");
    throw new Error(ctx.kem.label + ' needs the recipient\'s encapsulation ' +
        'key (opts.kemPublicKey, ' + ctx.kem.pubBytes + ' bytes). There is ' +
        'no certificate for one: no X.509 profile for an ML-KEM key is ' +
        'defined by the draft, so it travels as a dsig11:DEREncodedKeyValue.');
  }
  var encapsulated = opts.kem.encapsulate(recipient);
  var kemCiphertext = toBinaryString(encapsulated.ciphertext);
  var sharedSecret = toBinaryString(encapsulated.sharedSecret);
  var hkdfParams = {
    prf: opts.prf || HMAC_SHA256_URI,
    salt: opts.kdfSalt || '',
    info: opts.kdfInfo === undefined
      ? forge.util.encodeUtf8(ctx.keyAlg + '|' + ctx.dataAlg)
      : opts.kdfInfo,
    length: ctx.spec.keyBytes
  };
  var sessionKey = hkdf(hkdfParams.prf, sharedSecret, hkdfParams.salt,
      hkdfParams.info, hkdfParams.length);

  var plaintext = encPlaintext(xml, ctx.c14nMode, ctx.type);
  var ptBytes = forge.util.encodeUtf8(plaintext);
  var iv = forge.random.getBytesSync(ctx.spec.ivBytes);
  var cipher = forge.cipher.createCipher(ctx.spec.cipher, sessionKey);
  cipher.start(ctx.spec.gcm ? { iv: iv, tagLength: 128 } : { iv: iv });
  cipher.update(forge.util.createBuffer(ptBytes));
  if (!cipher.finish()) {
    log.debug("Leaving encapsulateXml(). Data encryption failed.");
    throw new Error('Data encryption failed.');
  }
  var cipherValue = iv + cipher.output.getBytes() +
      (ctx.spec.gcm ? cipher.mode.tag.getBytes() : '');

  log.debug("Leaving encapsulateXml(). " + ctx.kem.alg + ".");
  return '<xenc:EncryptedData xmlns:xenc="' + XENC_NS + '" Type="' + ctx.type +
      '">' +
      '<xenc:EncryptionMethod Algorithm="' + ctx.dataAlg + '"/>' +
      '<ds:KeyInfo xmlns:ds="' + DS_NS + '">' +
        '<xenc:EncryptedKey>' +
          '<xenc:EncryptionMethod Algorithm="' + ctx.keyAlg + '">' +
              hkdfParamsXml(hkdfParams) + '</xenc:EncryptionMethod>' +
          '<ds:KeyInfo>' + derEncodedKeyValueXml(recipient) + '</ds:KeyInfo>' +
          '<xenc:CipherData><xenc:CipherValue>' +
              forge.util.encode64(kemCiphertext) +
              '</xenc:CipherValue></xenc:CipherData>' +
        '</xenc:EncryptedKey>' +
      '</ds:KeyInfo>' +
      '<xenc:CipherData><xenc:CipherValue>' +
          forge.util.encode64(cipherValue) +
          '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData>';
}

// Bytes to the forge binary string the rest of this file speaks. One character
// per byte — see client/src/xmldsig_pqc.js on why this is not a TextEncoder.
function toBinaryString(value) {
  log.debug("Entering toBinaryString().");
  if (typeof value === 'string') {
    log.debug("Leaving toBinaryString(). Already one.");
    return value;
  }
  log.debug("Leaving toBinaryString().");
  return forge.util.binary.raw.encode(new Uint8Array(value));
}

function encryptXml(xml, opts) {
  log.debug("Entering encryptXml().");
  opts = opts || {};
  var dataAlg = opts.dataAlg || (XENC11_NS + 'aes256-gcm');
  var keyAlg = opts.keyAlg || (XENC11_NS + 'rsa-oaep');
  var type = opts.type || (XENC_NS + 'Element');
  var c14nMode = opts.c14nMode || 'none';
  var spec = dataAlgSpec(dataAlg);

  // A KEM RECIPIENT HAS NO CERTIFICATE, so the check below cannot come first
  // any more. There is no standard X.509 profile for an ML-KEM encapsulation
  // key that anything here could parse, and the draft defines none — the key
  // travels as raw bytes in a dsig11:DEREncodedKeyValue. See the KEM section
  // header for what else is different about this path.
  var kem = kemMethod(keyAlg);
  if (kem) {
    log.debug("Leaving encryptXml(). Encapsulating.");
    return encapsulateXml(xml, opts, { kem: kem, keyAlg: keyAlg,
        dataAlg: dataAlg, type: type, c14nMode: c14nMode, spec: spec });
  }

  var certField = opts.certPem || '';
  if (!String(certField).trim()) throw new Error('No encryption certificate ' +
      '— paste a recipient certificate.');
  var certB64 = certPemToB64(certField);
  var cert = forge.pki.certificateFromPem(pemWrapCert(certField));
  var pub = cert.publicKey;

  var plaintext = encPlaintext(xml, c14nMode, type);
  var ptBytes = forge.util.encodeUtf8(plaintext);
  var sessionKey = forge.random.getBytesSync(spec.keyBytes);
  var iv = forge.random.getBytesSync(spec.ivBytes);
  var cipher = forge.cipher.createCipher(spec.cipher, sessionKey);
  cipher.start(spec.gcm ? { iv: iv, tagLength: 128 } : { iv: iv });
  cipher.update(forge.util.createBuffer(ptBytes));
  if (!cipher.finish()) throw new Error('Data encryption failed.');
  var cipherValue = iv + cipher.output.getBytes() + (spec.gcm ?
      cipher.mode.tag.getBytes() : '');
  var cipherB64 = forge.util.encode64(cipherValue);

  var wrapped, keyMethodInner = '';
  if (keyAlg === XENC_NS + 'rsa-1_5') {
    wrapped = pub.encrypt(sessionKey, 'RSAES-PKCS1-V1_5');
  } else {
    var digestUri = opts.digest || (XENC_NS + 'sha256');
    var oaepOpts = { md: forgeMdFor(digestUri) };
    keyMethodInner = '<ds:DigestMethod xmlns:ds="' + DS_NS + '" Algorithm="' +
        digestUri + '"/>';
    if (keyAlg === XENC11_NS + 'rsa-oaep') {
      var mgfUri = opts.mgf || (XENC11_NS + 'mgf1sha256');
      oaepOpts.mgf1 = { md: mgfMdFor(mgfUri) };
      keyMethodInner += '<xenc11:MGF xmlns:xenc11="' + XENC11_NS +
          '" Algorithm="' + mgfUri + '"/>';
    } else {
      oaepOpts.mgf1 = { md: forge.md.sha1.create() };
    }
    wrapped = pub.encrypt(sessionKey, 'RSA-OAEP', oaepOpts);
  }
  var wrappedB64 = forge.util.encode64(wrapped);

  log.debug("Leaving encryptXml().");
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
  log.debug("Entering firstByLocal().");
  var els = root.getElementsByTagNameNS('*', name);
  log.debug("Leaving firstByLocal().");
  return els && els.length ? els[0] : null;
}
function signWsSecurity(soapXml, opts) {
  log.debug("Entering signWsSecurity().");
  opts = opts || {};
  var sigAlg = opts.sigAlg || SIG_ALG_RSA_SHA256;
  // Post-quantum, additively — the same shape signEnveloped() takes, and for
  // the same three reasons: only a URI in the registry takes this path, the
  // RSA family is byte-for-byte what it was, and `sigAlgSpec()` must not be
  // asked about an identifier it does not know because it answers SHA-256.
  var pqSpec = (SIG_METHODS[sigAlg] && SIG_METHODS[sigAlg].postQuantum)
    ? SIG_METHODS[sigAlg] : null;
  if (pqSpec && typeof opts.signer !== 'function') {
    log.debug("Leaving signWsSecurity(). Post-quantum with no signer.");
    throw new Error('signWsSecurity: ' + pqSpec.label + ' needs opts.signer. ' +
        'This module holds the identifiers and not the lattice; ' +
        'client/src/xmldsig_pqc.js builds the signer.');
  }
  if (!pqSpec && !opts.privateKeyPem) {
    log.debug("Leaving signWsSecurity(). No private key.");
    throw new Error('signWsSecurity: privateKeyPem is required.');
  }
  var spec = pqSpec
    ? { md: function () { return forgeMdFor(pqSpec.digestUri); },
        digestUri: pqSpec.digestUri }
    : sigAlgSpec(sigAlg);

  var doc = parseXmlStrict(soapXml, 'the SOAP envelope to sign');
  var security = firstByLocal(doc, 'Security');
  if (!security) throw new Error('No <wsse:Security> header to hold the ' +
      'signature — enable a timestamp or a credential.');

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
      '<ds:Transforms><ds:Transform Algorithm="' + C14N_EXCLUSIVE +
          '"/></ds:Transforms>' +
      '<ds:DigestMethod Algorithm="' + spec.digestUri + '"/>' +
      '<ds:DigestValue>' + digest + '</ds:DigestValue></ds:Reference>';
  }).join('');

  var signedInfo = '<ds:SignedInfo xmlns:ds="' + DS_NS + '">' +
    '<ds:CanonicalizationMethod Algorithm="' + C14N_EXCLUSIVE + '"/>' +
    '<ds:SignatureMethod Algorithm="' + sigAlg + '"/>' + refs +
        '</ds:SignedInfo>';
  var siCanon = canonicalize(new DOMParser().parseFromString(signedInfo,
      'application/xml').documentElement);
  var sigVal;
  if (pqSpec) {
    var rawSig = opts.signer(forge.util.encodeUtf8(siCanon), pqSpec, sigAlg);
    sigVal = typeof rawSig === 'string' ? forge.util.encode64(rawSig)
      : forge.util.encode64(forge.util.binary.raw.encode(rawSig));
  } else {
    var pk = forge.pki.privateKeyFromPem(opts.privateKeyPem);
    var md = spec.md(); md.update(siCanon, 'utf8');
    sigVal = forge.util.encode64(pk.sign(md));
  }
  // A post-quantum signer has no certificate — the draft defines no X.509
  // profile — so its KeyInfo is the caller's DEREncodedKeyValue. WS-Security's
  // BinarySecurityToken reference is the shape a real STS expects for a
  // certificate and there is no equivalent registered for one of these, which
  // is worth knowing before pointing this at Apache CXF: what goes out is a
  // valid XMLDSIG KeyInfo and not a WS-Security token reference.
  var keyInfoXml = pqSpec
    ? '<ds:KeyInfo>' + (opts.keyInfoXml || '') + '</ds:KeyInfo>'
    : '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
      certPemToB64(opts.certPem) +
      '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>';

  var signature = '<ds:Signature xmlns:ds="' + DS_NS + '">' + signedInfo +
    '<ds:SignatureValue>' + sigVal + '</ds:SignatureValue>' +
    keyInfoXml +
    '</ds:Signature>';
  var sigNode = doc.importNode(new DOMParser().parseFromString(signature,
      'application/xml').documentElement, true);
  security.insertBefore(sigNode, security.firstChild);
  log.debug("Leaving signWsSecurity().");
  return new XMLSerializer().serializeToString(doc);
}

// --- Enveloped XML Signature (XML-DSIG) -------------------------------------
// The generic form of saml_request.js's signPostEnveloped(): digest the
// document element, build a <ds:SignedInfo> referencing it, insert the
// <ds:Signature> into the document, then sign the canonicalized SignedInfo in
// place. Same primitives (exclusive C14N + RSA-SHA*, node-forge) — only the
// reference URI and the placement of the <ds:Signature> are parameterized,
// because the SAML schemas disagree about both:
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
  var sigAlg = opts.sigAlg || SIG_ALG_RSA_SHA256;
  // ---------------------------------------------------------------------
  // POST-QUANTUM, AND EVERY PRE-EXISTING CALLER IS UNTOUCHED BY IT.
  //
  // This function signs ONE SHAPE of document with almost every XMLDSIG
  // choice fixed, and it stayed that way on purpose when the general engine
  // was added beside it — a SAML assertion that quietly stops verifying is a
  // defect nobody sees until an identity provider refuses it. So the branch
  // below is ADDITIVE: `sigAlgSpec()` still decides for the four RSA URIs,
  // byte for byte, and only a URI that is in the post-quantum registry takes
  // the other path.
  //
  // Note what `sigAlgSpec()` does with a URI it does not know: it returns
  // SHA-256. That is right for the RSA family it was written for and would be
  // silently wrong here — an ML-DSA identifier would have produced a
  // SHA-256-digested Reference and then died on the PEM parse, naming a key.
  // Looking the registry up FIRST is what stops that.
  // ---------------------------------------------------------------------
  var pqSpec = (SIG_METHODS[sigAlg] && SIG_METHODS[sigAlg].postQuantum)
    ? SIG_METHODS[sigAlg] : null;
  if (pqSpec && typeof opts.signer !== 'function') {
    log.debug("Leaving signEnveloped(). Post-quantum with no signer.");
    throw new Error('signEnveloped: ' + pqSpec.label + ' needs opts.signer. ' +
        'This module holds the identifiers and not the lattice (see the ' +
        'section header); client/src/xmldsig_pqc.js builds the signer from ' +
        'pqc.js and hbs.js.');
  }
  if (!pqSpec && !opts.privateKeyPem) {
    log.debug("Leaving signEnveloped(). No private key.");
    throw new Error('signEnveloped: privateKeyPem is required.');
  }
  var spec = pqSpec
    ? { md: function () { return forgeMdFor(pqSpec.digestUri); },
        digestUri: pqSpec.digestUri }
    : sigAlgSpec(sigAlg);
  var digestUri = opts.digestUri || spec.digestUri;
  var c14nAlg = opts.c14nAlg || C14N_EXCLUSIVE;
  var c14nFn = c14nForAlg(c14nAlg);

  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (doc.getElementsByTagName('parsererror')
      .length) throw new Error('malformed XML — cannot sign.');
  var root = doc.documentElement;

  var refUri = opts.refUri;
  if (refUri == null) {
    var id = root.getAttribute('ID') || root.getAttribute('AssertionID') ||
        root.getAttribute('Id') || '';
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
  if (opts.includeKeyInfo !== false && opts.keyInfoXml) {
    // A caller-supplied KeyInfo, which is how a post-quantum public key gets
    // into the document: there is no X.509 certificate for one — the draft
    // defines no profile — so it travels as a dsig11:DEREncodedKeyValue,
    // which derEncodedKeyValueXml() builds.
    keyInfo = '<ds:KeyInfo>' + opts.keyInfoXml + '</ds:KeyInfo>';
  } else if (opts.includeKeyInfo !== false && opts.certPem) {
    keyInfo = '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
      certPemToB64(opts.certPem) +
                   '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>';
  }
  // Insert the signature with an empty SignatureValue FIRST, then canonicalize
  // the SignedInfo in place. Inclusive C14N pulls in every namespace declared
  // by the ancestors, so a SignedInfo canonicalized while detached would not
  // match the octets a verifier computes from the finished document. (Exclusive
  // C14N is unaffected — it only renders visibly-utilized prefixes — so this
  // ordering is correct for both.)
  var signature = '<ds:Signature xmlns:ds="' + DS_NS + '">' + signedInfo +
    '<ds:SignatureValue></ds:SignatureValue>' + keyInfo + '</ds:Signature>';
  var sigNode = doc.importNode(new DOMParser().parseFromString(signature,
      'application/xml').documentElement, true);

  var placement = opts.placement || 'after-issuer';
  if (placement === 'last') {
    root.appendChild(sigNode);
  } else if (placement === 'first') {
    root.insertBefore(sigNode, root.firstChild);
  } else {
    var issuer = null, kids = root.childNodes;
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].nodeType === 1 && kids[i].localName === 'Issuer') { issuer =
          kids[i]; break; }
    }
    if (issuer) root.insertBefore(sigNode, issuer.nextSibling);
    else root.insertBefore(sigNode, root.firstChild);
  }

  var siNode = directChildByLocal(sigNode, 'SignedInfo');
  var sigB64;
  if (pqSpec) {
    // THE SAME OCTETS THE RSA BRANCH HASHES. `c14nFn` returns a JS string and
    // forge's `md.update(s, 'utf8')` encodes it — so the signer is handed
    // `encodeUtf8()` of it, which is the binary string signXml()'s signers
    // already take. Handing over the JS string instead would sign a different
    // message on any document with a non-ASCII character in its SignedInfo.
    var rawSig = opts.signer(forge.util.encodeUtf8(c14nFn(siNode)), pqSpec,
                             sigAlg);
    sigB64 = typeof rawSig === 'string' ? forge.util.encode64(rawSig)
      : forge.util.encode64(forge.util.binary.raw.encode(rawSig));
  } else {
    var pk = forge.pki.privateKeyFromPem(opts.privateKeyPem);
    var md = spec.md();
    md.update(c14nFn(siNode), 'utf8');
    sigB64 = forge.util.encode64(pk.sign(md));
  }
  directChildByLocal(sigNode, 'SignatureValue')
    .appendChild(doc.createTextNode(sigB64));

  log.debug("Leaving signEnveloped().");
  return new XMLSerializer().serializeToString(doc);
}

// --- XML Signature VERIFICATION (enveloped) --------------------------------
// Verify an enveloped XML digital signature such as the one on a SAML assertion
// (or any signed element): checks every Reference digest (after applying the
// enveloped-signature + C14N transforms) and the SignatureValue over the
// canonicalized SignedInfo, using the certificate embedded in KeyInfo (or
// opts.certPem if supplied). Reuses the same exclusive/inclusive C14N, digest,
// and sigAlgSpec helpers used for signing. RSA keys (RSASSA-PKCS1-v1_5).
//
// Returns { valid, signatureValid, referencesValid, references[],
// signatureMethod,
//           canonicalization, signerSubject, signerCertB64 } or { valid:false,
//           error }.
function findById(root, id) {
  log.debug("Entering findById().");
  var all = root.getElementsByTagName('*');
  for (var i = 0; i < all.length; i++) {
    var e = all[i];
    for (var j = 0; j < e.attributes.length; j++) {
      var a = e.attributes[j];
      var ln = a.localName || a.name;
      // Id/ID/id cover SAML 2.0 (ID), WS-Security (wsu:Id) and generic ids.
      // The other three are SAML 1.1's, which gives every message type its own
      // spelling of "the id" rather than one shared attribute: AssertionID on
      // an <Assertion> (WS-Fed and WS-Trust tokens are frequently SAML 1.1),
      // ResponseID on a <samlp:Response> and RequestID on a <samlp:Request>.
      // A verifier that knows only the first three resolves #<id> to NOTHING
      // on a signed SAML 1.1 Response — reported as "referenced element not
      // found", which reads like a stripped element rather than like a name
      // this list did not have.
      if ((ln === 'Id' || ln === 'ID' || ln === 'id' ||
           ln === 'AssertionID' || ln === 'ResponseID' ||
           ln === 'RequestID') &&
          a.value === id) {
        log.debug("Leaving findById().");
        return e;
      }
    }
  }
  log.debug("Leaving findById().");
  return null;
}
function c14nForAlg(alg) {
  log.debug("Entering c14nForAlg().");
  alg = alg || '';
  if (alg.indexOf('exc-c14n') >= 0) {
    log.debug("Leaving c14nForAlg().");
    return canonicalize;
  }
  if (alg.indexOf('xml-c14n') >= 0) {
    log.debug("Leaving c14nForAlg().");
    return canonicalizeInclusive;
  } // inclusive C14N 1.0
  log.debug("Leaving c14nForAlg().");
  return canonicalize; // default to exclusive (what SAML/WS-Trust use)
}
function certSubjectCN(cert) {
  log.debug("Entering certSubjectCN().");
  try {
    var f = cert.subject.getField('CN');
    log.debug("Leaving certSubjectCN().");
    return f ? f.value : '';
  } catch (e) {
    log.debug("Leaving certSubjectCN().");
    return '';
  }
}

function verifyXmlSignature(xml, opts) {
  log.debug("Entering verifyXmlSignature().");
  opts = opts || {};
  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    log.debug("Leaving verifyXmlSignature().");
    return { valid: false, error: 'malformed XML' };
  }

  var sig = firstByLocal(doc, 'Signature');
  if (!sig) {
    log.debug("Leaving verifyXmlSignature().");
    return { valid: false, error: 'No <ds:Signature> element found.' };
  }
  var si = firstByLocal(sig, 'SignedInfo');
  if (!si) {
    log.debug("Leaving verifyXmlSignature().");
    return { valid: false, error: 'Signature has no <SignedInfo>.' };
  }
  var smEl = firstByLocal(si, 'SignatureMethod');
  var sigAlg = smEl ? smEl.getAttribute('Algorithm') : '';
  var cmEl = firstByLocal(si, 'CanonicalizationMethod');
  var c14nAlg = cmEl ? cmEl.getAttribute('Algorithm') : C14N_EXCLUSIVE;
  var svEl = firstByLocal(sig, 'SignatureValue');
  if (!svEl) {
    log.debug("Leaving verifyXmlSignature().");
    return { valid: false, error: 'Signature has no <SignatureValue>.' };
  }
  // POST-QUANTUM, ADDITIVELY: only a URI in the registry takes this path, and
  // everything below is exactly what it was for the RSA family. A
  // post-quantum signature has NO SIGNING CERTIFICATE — the draft defines no
  // X.509 profile for one — so the certificate demand below cannot come first
  // any more, and there is nothing for `sigAlgSpec()` to be asked either: it
  // answers SHA-256 for a URI it does not know, which is right for the family
  // it was written for and would be silently wrong here.
  var pqSpec = (SIG_METHODS[sigAlg] && SIG_METHODS[sigAlg].postQuantum)
    ? SIG_METHODS[sigAlg] : null;
  var spec = pqSpec
    ? { md: function () { return forgeMdFor(pqSpec.digestUri); },
        digestUri: pqSpec.digestUri }
    : sigAlgSpec(sigAlg);

  // Signing certificate: prefer a supplied cert, else the one in KeyInfo.
  var certB64 = '';
  var x509 = firstByLocal(sig, 'X509Certificate');
  if (x509) certB64 = (x509.textContent || '').replace(/\s+/g, '');
  var certPem = opts.certPem ? pemWrapCert(opts.certPem) : (certB64 ?
      pemWrapCert(certB64) : '');
  if (pqSpec && typeof opts.verifier !== 'function') {
    log.debug("Leaving verifyXmlSignature(). Post-quantum with no verifier.");
    return { valid: false,
            error: 'This document is signed with ' + pqSpec.label + ', which ' +
                   'needs opts.verifier — this module holds the ' +
                   'identifiers and not the lattice. ' +
                   'client/src/xmldsig_pqc.js builds one from pqc.js and ' +
                   'hbs.js, and the public key is in the ' +
                   'dsig11:DEREncodedKeyValue rather than in a certificate.' };
  }
  if (!pqSpec && !certPem) {
    log.debug("Leaving verifyXmlSignature().");
    return { valid: false,
            error: 'No signing certificate in KeyInfo and none supplied.' };
  }
  var cert = null, pub = null;
  try {
    if (certPem) {
      cert = forge.pki.certificateFromPem(certPem);
      pub = cert.publicKey;
    }
  } catch (e) {
    log.debug("Leaving verifyXmlSignature().");
    return { valid: false, error: 'Could not parse signing certificate: ' +
            e.message };
  }

  // 1) SignatureValue over C14N(SignedInfo) — compute before detaching the
  //    signature (exclusive C14N is position-independent, but keep it in-tree).
  var siCanon = c14nForAlg(c14nAlg)(si);
  var signatureBytes = forge.util.decode64((svEl.textContent ||
      '').replace(/\s+/g, ''));
  var signatureValid = false;
  try {
    if (pqSpec) {
      // The same octets the RSA branch hashes — see signEnveloped() on why
      // this is encodeUtf8() of the canonicalized string rather than the
      // string.
      signatureValid = !!opts.verifier(forge.util.encodeUtf8(siCanon),
                                       signatureBytes, pqSpec, sigAlg);
    } else {
      var md1 = spec.md();
      md1.update(siCanon, 'utf8');
      signatureValid = pub.verify(md1.digest().bytes(), signatureBytes);
    }
  } catch (e) {
    // A verifier that THREW said something a caller can act on — a wrong
    // signature length names the parameter set — so it is kept rather than
    // flattened into `false`. A signature that merely does not hold up
    // returns false and never reaches here.
    log.debug("verifyXmlSignature(): the verifier threw: " + e.message);
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
    var target = uri === '' ? doc.documentElement : findById(doc,
        uri.replace(/^#/, ''));
    if (!target) { references.push({ uri: uri, ok: false,
        reason: 'referenced element not found' }); continue; }
    var c14nRef = C14N_EXCLUSIVE;
    var trs = ref.getElementsByTagNameNS('*', 'Transform');
    for (var t = 0; t < trs.length; t++) { var ta =
         trs[t].getAttribute('Algorithm') ||
         ''; if (ta.indexOf('c14n') >= 0) c14nRef = ta; }
    var canon = c14nForAlg(c14nRef)(target);
    var rmd = forgeMdFor(digAlg); rmd.update(canon, 'utf8');
    var computed = forge.util.encode64(rmd.digest().getBytes());
    references.push({ uri: uri, ok: computed === declared, computed: computed,
                    declared: declared, digestAlg: digAlg });
  }
  var referencesValid = references.length > 0 &&
      references.every(function (r) { return r.ok; });

  log.debug("Leaving verifyXmlSignature().");
  return {
    valid: signatureValid && referencesValid,
    signatureValid: signatureValid,
    referencesValid: referencesValid,
    references: references,
    signatureMethod: sigAlg,
    canonicalization: c14nAlg,
    signerSubject: cert ? certSubjectCN(cert) : '',
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
  log.debug("Entering directChildByLocal().");
  var c = el.firstChild;
  while (c) { if (c.nodeType === 1 && (c.localName === name)) {
    log.debug("Leaving directChildByLocal().");
    return c;
  } c = c.nextSibling; }
  log.debug("Leaving directChildByLocal().");
  return null;
}
function cipherValueOf(container) {
  log.debug("Entering cipherValueOf().");
  // The <xenc:CipherData><xenc:CipherValue> directly under `container`.
  var cd = directChildByLocal(container, 'CipherData');
  if (!cd) {
    log.debug("Leaving cipherValueOf().");
    return '';
  }
  var cv = directChildByLocal(cd, 'CipherValue');
  log.debug("Leaving cipherValueOf().");
  return cv ? (cv.textContent || '').replace(/\s+/g, '') : '';
}

function decryptXml(xml, opts) {
  log.debug("Entering decryptXml().");
  opts = opts || {};
  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (doc.getElementsByTagName('parsererror')
      .length) throw new Error('malformed XML');

  var ed = firstByLocal(doc, 'EncryptedData');
  if (!ed) throw new Error('no <xenc:EncryptedData> to decrypt.');
  var emEl = firstByLocal(ed, 'EncryptionMethod');
  var dataAlg = emEl ? emEl.getAttribute('Algorithm') : '';
  var spec = dataAlgSpec(dataAlg);

  // The wrapped session key may be nested in EncryptedData/KeyInfo, or a
  // sibling <xenc:EncryptedKey> (referenced by a ds:RetrievalMethod) — the
  // layout Keycloak and other IdPs emit. Look inside EncryptedData first, then
  // anywhere.
  var ek = firstByLocal(ed, 'EncryptedKey') || firstByLocal(doc,
      'EncryptedKey');
  if (!ek) throw new Error('no <xenc:EncryptedKey> — could not find the ' +
      'wrapped session key.');
  var kmEl = firstByLocal(ek, 'EncryptionMethod');
  var keyAlg = kmEl ? kmEl.getAttribute('Algorithm') : '';
  var wrappedB64 = cipherValueOf(ek);
  if (!wrappedB64) throw new Error('EncryptedKey has no CipherValue.');

  // A KEM DECAPSULATES RATHER THAN UNWRAPPING, and the derivation it needs is
  // read out of the document rather than assumed — see the KEM section header.
  // This is checked before privateKeyPem, because a KEM recipient has no PEM
  // private key either: it holds raw decapsulation-key bytes.
  var kem = kemMethod(keyAlg);
  if (kem) {
    log.debug("Leaving decryptXml(). Decapsulating.");
    return decapsulateXml(doc, ed, ek, kmEl, wrappedB64, opts,
                          { kem: kem, keyAlg: keyAlg, spec: spec });
  }

  if (!opts.privateKeyPem) {
    log.debug("Leaving decryptXml(). No private key.");
    throw new Error('decryptXml: privateKeyPem is required.');
  }
  var priv = forge.pki.privateKeyFromPem(opts.privateKeyPem);
  var wrapped = forge.util.decode64(wrappedB64);
  var sessionKey;
  try {
    if (keyAlg === XENC_NS + 'rsa-1_5') {
      sessionKey = priv.decrypt(wrapped, 'RSAES-PKCS1-V1_5');
    } else {
      var digEl = kmEl ? firstByLocal(kmEl, 'DigestMethod') : null;
      var digestUri = digEl ? digEl.getAttribute('Algorithm') : (XENC_NS +
          'sha256');
      var oaep = { md: forgeMdFor(digestUri) };
      if (keyAlg === XENC11_NS + 'rsa-oaep') {
        var mgfEl = kmEl ? firstByLocal(kmEl, 'MGF') : null;
        var mgfUri = mgfEl ? mgfEl.getAttribute('Algorithm') : (XENC11_NS +
            'mgf1sha1');
        oaep.mgf1 = { md: mgfMdFor(mgfUri) };
      } else {
        // rsa-oaep-mgf1p: MGF1 is fixed to SHA-1.
        oaep.mgf1 = { md: forge.md.sha1.create() };
      }
      sessionKey = priv.decrypt(wrapped, 'RSA-OAEP', oaep);
    }
  } catch (e) {
    throw new Error('could not unwrap the session key (wrong private key or ' +
                    'key-transport algorithm mismatch): ' + e.message);
  }

  var dataB64 = cipherValueOf(ed);
  if (!dataB64) throw new Error('EncryptedData has no CipherValue.');
  var cipherRaw = forge.util.decode64(dataB64);
  var iv = cipherRaw.substring(0, spec.ivBytes);
  var decipher = forge.cipher.createDecipher(spec.cipher, sessionKey);
  if (spec.gcm) {
    var tag = cipherRaw.substring(cipherRaw.length - 16);
    var body = cipherRaw.substring(spec.ivBytes, cipherRaw.length - 16);
    decipher.start({ iv: iv, tag: forge.util.createBuffer(tag),
                   tagLength: 128 });
    decipher.update(forge.util.createBuffer(body));
  } else {
    decipher.start({ iv: iv });
    decipher.update(forge.util.createBuffer(cipherRaw.substring(spec.ivBytes)));
  }
  if (!decipher.finish()) throw new Error('data decryption failed (wrong key ' +
      'or corrupted ciphertext).');
  log.debug("Leaving decryptXml().");
  return forge.util.decodeUtf8(decipher.output.getBytes());
}

// ---------------------------------------------------------------------------
// DECRYPTION FROM A KEM RECIPIENT. The mirror of encapsulateXml(): decapsulate
// to the shared secret, then derive the content encryption key with EXACTLY
// the parameters the document states — PRF, salt, info and length, all of them
// read rather than defaulted, which is what makes this reproduce a sender that
// is not this file.
//
// `opts.kemPrivateKey` is the raw decapsulation key and `opts.kem` supplies
// `decapsulate(ciphertext, privateKeyBytes)`.
//
// A WRONG DECAPSULATION KEY DOES NOT FAIL HERE, and that is FIPS 203 rather
// than a gap: ML-KEM is implicitly rejecting, so decapsulating with the wrong
// key returns a well-formed shared secret that is simply a different one. The
// failure therefore surfaces at the AEAD tag, which is the right place for it —
// and the message says so, because "data decryption failed" over a KEM
// otherwise reads as a corrupted document rather than as the wrong key.
// ---------------------------------------------------------------------------
function decapsulateXml(doc, ed, ek, kmEl, ciphertextB64, opts, ctx) {
  log.debug("Entering decapsulateXml(). alg=" + ctx.kem.alg);
  if (!opts.kem || typeof opts.kem.decapsulate !== 'function') {
    log.debug("Leaving decapsulateXml(). No KEM.");
    throw new Error(ctx.kem.label + ' needs a decapsulation function — this ' +
        'file holds the identifiers and the key derivation, not the lattice. ' +
        'Pass opts.kem.');
  }
  if (!opts.kemPrivateKey || !opts.kemPrivateKey.length) {
    log.debug("Leaving decapsulateXml(). No decapsulation key.");
    throw new Error(ctx.kem.label + ' needs the recipient\'s decapsulation ' +
        'key (opts.kemPrivateKey), which is raw bytes and not a PEM — there ' +
        'is no PKCS#8 profile for one that this file could read.');
  }
  var ciphertext = forge.util.decode64(ciphertextB64);
  if (ciphertext.length !== ctx.kem.ctBytes) {
    log.debug("Leaving decapsulateXml(). Wrong ciphertext length.");
    throw new Error('An ' + ctx.kem.alg + ' encapsulation is ' +
        ctx.kem.ctBytes + ' bytes and this CipherValue holds ' +
        ciphertext.length + '. Either the base64 is truncated, or the ' +
        'document was made for a different parameter set than its ' +
        'EncryptionMethod names.');
  }
  var params = readHkdfParams(kmEl);
  if (params.length !== ctx.spec.keyBytes) {
    log.debug("Leaving decapsulateXml(). KeyLength disagrees with the cipher.");
    throw new Error('The KeyDerivationMethod asks for a ' + params.length +
        '-byte key and the EncryptionMethod names a cipher that takes ' +
        ctx.spec.keyBytes + '. One of the two is wrong about this document.');
  }
  var shared = toBinaryString(opts.kem.decapsulate(
      forge.util.binary.raw.decode(ciphertext),
      opts.kemPrivateKey));
  var sessionKey = hkdf(params.prf, shared, params.salt, params.info,
                        params.length);

  var dataB64 = cipherValueOf(ed);
  if (!dataB64) {
    log.debug("Leaving decapsulateXml(). No data.");
    throw new Error('EncryptedData has no CipherValue.');
  }
  var cipherRaw = forge.util.decode64(dataB64);
  var iv = cipherRaw.substring(0, ctx.spec.ivBytes);
  var decipher = forge.cipher.createDecipher(ctx.spec.cipher, sessionKey);
  if (ctx.spec.gcm) {
    var tag = cipherRaw.substring(cipherRaw.length - 16);
    var body = cipherRaw.substring(ctx.spec.ivBytes, cipherRaw.length - 16);
    decipher.start({ iv: iv, tag: forge.util.createBuffer(tag),
                     tagLength: 128 });
    decipher.update(forge.util.createBuffer(body));
  } else {
    decipher.start({ iv: iv });
    decipher.update(forge.util.createBuffer(
        cipherRaw.substring(ctx.spec.ivBytes)));
  }
  if (!decipher.finish()) {
    log.debug("Leaving decapsulateXml(). The tag did not check out.");
    throw new Error('The content did not decrypt. With a KEM this is USUALLY ' +
        'THE WRONG DECAPSULATION KEY rather than a corrupted document: ' +
        'ML-KEM is implicitly rejecting (FIPS 203), so the wrong key ' +
        'produces a perfectly well-formed shared secret that is simply a ' +
        'different one, and the first thing that notices is this AEAD tag.');
  }
  log.debug("Leaving decapsulateXml(). Decrypted.");
  return forge.util.decodeUtf8(decipher.output.getBytes());
}

// Generate an RSA key pair + self-signed certificate (for a fresh signing key).
// A self-signed certificate over a key pair the caller ALREADY HAS, which is
// what the XML Signature pane needs: its key pair comes from the shared
// generator in pk_encryption.js (PKCS#8, so the shared keystore matrix can
// export it — a PKCS#1 key is refused there with a bare Web Crypto DataError),
// and only the certificate has to be minted here.
//
// It is node-forge rather than x509.js's issuer, and the reason is the same
// one that keeps the rest of this file off crypto.subtle: x509.js is Web
// Crypto and therefore async and secure-context-only, and generating a key
// pair must not be the one action on the page that stops working over plain
// HTTP. What it produces is a container for a public key in a KeyInfo, not a
// credential anybody validates a chain on.
function selfSignedCertFor(privatePem, publicPem, cn) {
  log.debug("Entering selfSignedCertFor().");
  var cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicPem);
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
  var attrs = [{ name: 'commonName', value: cn || 'ws-trust-debugger' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(forge.pki.privateKeyFromPem(privatePem), forge.md.sha256.create());
  log.debug("Leaving selfSignedCertFor().");
  return forge.pki.certificateToPem(cert).trim() + '\n';
}

function generateKeyPair(bits, cn) {
  log.debug("Entering generateKeyPair().");
  var kp = forge.pki.rsa.generateKeyPair({ bits: bits || 2048, e: 0x10001 });
  var privateKeyPem = forge.pki.privateKeyToPem(kp.privateKey).trim() + '\n';
  var publicKeyPem = forge.pki.publicKeyToPem(kp.publicKey).trim() + '\n';
  log.debug("Leaving generateKeyPair().");
  return {
    privateKeyPem: privateKeyPem,
    publicKeyPem: publicKeyPem,
    certPem: selfSignedCertFor(privateKeyPem, publicKeyPem, cn)
  };
}

// --- Redirect-binding query-string signature -------------------------------
// The SAML HTTP-Redirect binding signs the URL-encoded query string itself
// (see saml_request.js signRedirect): RSA-sign the SHA-* digest of the octet
// string and base64 the result; the caller appends it as the Signature
// parameter, with SigAlg naming the algorithm. Factored here so the WS-Fed page
// can carry a redirect-style signature the same way. Detached (no XML): returns
// the base64 signature over `queryString` exactly as given, so the caller must
// pass the octets it will actually send (including the SigAlg param).
// opts: { privateKeyPem, sigAlg }
function signQueryString(queryString, opts) {
  log.debug("Entering signQueryString().");
  opts = opts || {};
  if (!opts.privateKeyPem) throw new Error('signQueryString: privateKeyPem ' +
      'is required.');
  var sigAlg = opts.sigAlg || SIG_ALG_RSA_SHA256;
  var pk = forge.pki.privateKeyFromPem(opts.privateKeyPem);
  var md = sigAlgSpec(sigAlg).md();
  md.update(queryString, 'utf8'); // the query string is ASCII
  log.debug("Leaving signQueryString().");
  return forge.util.encode64(pk.sign(md));
}

// ===========================================================================
// THE GENERAL XML SIGNATURE ENGINE (the Digital Signature page's XML pane)
//
// Everything above this line signs ONE shape of document each: an enveloped
// assertion for SAML, a WS-Security header for WS-Trust. They are kept exactly
// as they are, because a SAML assertion that stops verifying is a defect
// nobody sees until an identity provider refuses it, and the interoperability
// test holds those two functions against xml-crypto's reading of what they
// produce.
//
// What follows is the same specification with the choices left OPEN, which is
// what a debugger needs: all three signature types, four canonicalization
// methods (each with and without comments), the RSA / ECDSA / HMAC signature
// method families, a transform CHAIN rather than a fixed pair, and the
// InclusiveNamespaces prefix list. It shares this file's canonicalizer,
// digests and parser rather than owning a second copy — a canonicalizer is a
// reading of a specification, and two readings of C14N agree with each other
// and interoperate with nobody.
//
// THE CRYPTOGRAPHY IS INJECTED, and that is deliberate. RSA is built in
// (node-forge, already here for SAML), but ECDSA and HMAC arrive as an
// `opts.signer` / `opts.verifier` pair supplied by the caller. The reason is
// bundle size and blast radius: @noble/curves in this file would land in the
// SAML, WS-Trust and WS-Federation bundles, none of which sign anything with
// an elliptic curve, and the Digital Signature page already has every curve
// loaded. It has a second benefit the tests exploit — the node-side test can
// pass a signer built on node's own OpenSSL, so the ECDSA half of this engine
// is checked against an implementation that is not ours at all.
// ===========================================================================

var DSIG11_NS = 'http://www.w3.org/2009/xmldsig11#';
var C14N_INCLUSIVE = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
var C14N_INCLUSIVE_WC = C14N_INCLUSIVE + '#WithComments';
var C14N_EXCLUSIVE_WC = C14N_EXCLUSIVE + 'WithComments';
var TRANSFORM_BASE64 = DS_NS + 'base64';
var TRANSFORM_XPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116';
var TRANSFORM_XPATH_FILTER2 = 'http://www.w3.org/2002/06/xmldsig-filter2';

// The four canonicalization methods, which are two algorithms times the one
// difference between each URI and its "#WithComments" twin. C14N 1.1
// (http://www.w3.org/2006/12/xml-c14n11) is NOT offered: its whole difference
// from 1.0 is how xml:base, xml:lang and xml:space are inherited into a
// detached subtree, this engine does not implement that inheritance, and an
// option that names a method it does not perform is worse than an absent one.
var C14N_METHODS = {};
C14N_METHODS[C14N_EXCLUSIVE] =
  { exclusive: true, comments: false, label: 'Exclusive C14N 1.0' };
C14N_METHODS[C14N_EXCLUSIVE_WC] =
  { exclusive: true, comments: true,
    label: 'Exclusive C14N 1.0 with comments' };
C14N_METHODS[C14N_INCLUSIVE] =
  { exclusive: false, comments: false, label: 'Inclusive C14N 1.0' };
C14N_METHODS[C14N_INCLUSIVE_WC] =
  { exclusive: false, comments: true,
    label: 'Inclusive C14N 1.0 with comments' };

function c14nMethod(uri) {
  log.debug("Entering c14nMethod().");
  var m = C14N_METHODS[uri];
  if (!m) throw new Error('Unsupported CanonicalizationMethod: ' + uri);
  log.debug("Leaving c14nMethod().");
  return m;
}

// The digest methods, and note that this one THROWS on an algorithm it does
// not know where forgeMdFor() above silently falls back to SHA-256. That
// fallback is right for the encryption path, which reads an algorithm out of a
// document somebody else wrote; it is wrong here, where the algorithm is a
// choice on the screen and a typo would produce a signature whose DigestMethod
// says one thing and whose DigestValue is another.
var DIGEST_METHODS = {};
DIGEST_METHODS['http://www.w3.org/2000/09/xmldsig#sha1'] =
  { md: forge.md.sha1, label: 'SHA-1 (insecure)' };
DIGEST_METHODS['http://www.w3.org/2001/04/xmlenc#sha256'] =
  { md: forge.md.sha256, label: 'SHA-256' };
DIGEST_METHODS['http://www.w3.org/2001/04/xmldsig-more#sha384'] =
  { md: forge.md.sha384, label: 'SHA-384' };
DIGEST_METHODS['http://www.w3.org/2001/04/xmlenc#sha512'] =
  { md: forge.md.sha512, label: 'SHA-512' };

function digestSpec(uri) {
  log.debug("Entering digestSpec().");
  var d = DIGEST_METHODS[uri];
  if (!d) throw new Error('Unsupported DigestMethod: ' + uri);
  log.debug("Leaving digestSpec().");
  return d;
}

var FORGE_MD = { sha1: forge.md.sha1, sha256: forge.md.sha256,
                 sha384: forge.md.sha384, sha512: forge.md.sha512 };

// SignatureMethod URIs. `family` decides who signs: `rsa` is built in here,
// `ecdsa` and `hmac` require the caller's signer. `digestUri` is only the
// DEFAULT pairing for a new Reference — DigestMethod and SignatureMethod are
// independent choices in XMLDSIG and the pane lets them be.
//
// Two notes on the namespaces, both of which have cost somebody an afternoon:
// only rsa-sha1 and hmac-sha1 live under the xmldsig# namespace (they are the
// original 2000 recommendation); everything added since is under
// xmldsig-more# from RFC 4051/6931, INCLUDING rsa-sha256, which people
// reliably write as xmldsig#rsa-sha256 and which no verifier recognises. And
// RSASSA-PSS is under the 2007/05 namespace with the hash FIRST
// (sha256-rsa-MGF1), not the 2001/04 one with the hash last.
var SIG_METHODS = {};
SIG_METHODS['http://www.w3.org/2000/09/xmldsig#rsa-sha1'] =
  { family: 'rsa', pad: 'v1_5', hash: 'sha1', keyKind: 'rsa',
    digestUri: 'http://www.w3.org/2000/09/xmldsig#sha1',
    label: 'RSA-SHA1 (insecure)' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'] =
  { family: 'rsa', pad: 'v1_5', hash: 'sha256', keyKind: 'rsa',
    digestUri: 'http://www.w3.org/2001/04/xmlenc#sha256',
    label: 'RSA-SHA256' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'] =
  { family: 'rsa', pad: 'v1_5', hash: 'sha384', keyKind: 'rsa',
    digestUri: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
    label: 'RSA-SHA384' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'] =
  { family: 'rsa', pad: 'v1_5', hash: 'sha512', keyKind: 'rsa',
    digestUri: 'http://www.w3.org/2001/04/xmlenc#sha512',
    label: 'RSA-SHA512' };
SIG_METHODS['http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1'] =
  { family: 'rsa', pad: 'pss', hash: 'sha256', keyKind: 'rsa',
    digestUri: 'http://www.w3.org/2001/04/xmlenc#sha256',
    label: 'RSASSA-PSS SHA-256 (RFC 9231)' };
SIG_METHODS['http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1'] =
  { family: 'rsa', pad: 'pss', hash: 'sha384', keyKind: 'rsa',
    digestUri: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
    label: 'RSASSA-PSS SHA-384 (RFC 9231)' };
SIG_METHODS['http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1'] =
  { family: 'rsa', pad: 'pss', hash: 'sha512', keyKind: 'rsa',
    digestUri: 'http://www.w3.org/2001/04/xmlenc#sha512',
    label: 'RSASSA-PSS SHA-512 (RFC 9231)' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1'] =
  { family: 'ecdsa', hash: 'sha1', keyKind: 'ec',
    digestUri: 'http://www.w3.org/2000/09/xmldsig#sha1',
    label: 'ECDSA-SHA1 (insecure)' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'] =
  { family: 'ecdsa', hash: 'sha256', keyKind: 'ec',
    digestUri: 'http://www.w3.org/2001/04/xmlenc#sha256',
    label: 'ECDSA-SHA256' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384'] =
  { family: 'ecdsa', hash: 'sha384', keyKind: 'ec',
    digestUri: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
    label: 'ECDSA-SHA384' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512'] =
  { family: 'ecdsa', hash: 'sha512', keyKind: 'ec',
    digestUri: 'http://www.w3.org/2001/04/xmlenc#sha512',
    label: 'ECDSA-SHA512' };
SIG_METHODS['http://www.w3.org/2000/09/xmldsig#hmac-sha1'] =
  { family: 'hmac', hash: 'sha1', keyKind: 'secret',
    digestUri: 'http://www.w3.org/2000/09/xmldsig#sha1',
    label: 'HMAC-SHA1 (insecure)' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#hmac-sha256'] =
  { family: 'hmac', hash: 'sha256', keyKind: 'secret',
    digestUri: 'http://www.w3.org/2001/04/xmlenc#sha256',
    label: 'HMAC-SHA256 (a MAC, not a signature)' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#hmac-sha384'] =
  { family: 'hmac', hash: 'sha384', keyKind: 'secret',
    digestUri: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
    label: 'HMAC-SHA384 (a MAC, not a signature)' };
SIG_METHODS['http://www.w3.org/2001/04/xmldsig-more#hmac-sha512'] =
  { family: 'hmac', hash: 'sha512', keyKind: 'secret',
    digestUri: 'http://www.w3.org/2001/04/xmlenc#sha512',
    label: 'HMAC-SHA512 (a MAC, not a signature)' };

// ===========================================================================
// THE POST-QUANTUM SIGNATURE METHODS — draft-eastlake-rfc9231bis-xmlsec-uris.
//
// XMLDSIG is crypto-agile BY DESIGN: `SignatureMethod/@Algorithm` is a URI and
// nothing in the specification enumerates the legal ones, so a new signature
// scheme needs an identifier and an implementation and NOT a new version of
// XML Signature. That property is why this table can grow at all, and it is
// the whole of what the draft below does.
//
// **THESE URIs ARE FROM AN INDIVIDUAL INTERNET-DRAFT AND ARE NOT A
// RECOMMENDATION.** `draft-eastlake-rfc9231bis-xmlsec-uris-09`, 21 August
// 2026, which is intended to obsolete RFC 9231 and carries no IETF or W3C
// endorsement — its own boilerplate says so, and section 3.3.16 is still
// marked "not yet listed in the indexes in Section 5". W3C has nothing: its
// strategy issue #484 asks for a WORKSHOP on the subject. So every label here
// says "draft", and it says so because a person reading a menu has no other
// way to tell a draft identifier from a REC one — they are both just URIs.
//
// The namespace is the draft's own, `http://www.w3.org/2026/08/xmldsig-more#`,
// used VERBATIM. Apache Santuario's in-flight PR for the same draft hedges
// further and ships `http://www.w3.org/tbd#ml-dsa-44`; matching that would make
// this tool interoperate with one unreleased build and with nothing else,
// where matching the draft makes it interoperate with anything that implements
// the draft. If the draft's namespace changes, it changes in one line here.
//
// WHAT IS NOT HERE, AND WHY. The draft's HashML-DSA pre-hashed variants have no
// identifiers in it — section 3.3.15 says the PURE variant is what these URIs
// name — so there is nothing to add. The composite ML-DSA + traditional
// algorithms of draft-ietf-jose-pq-composite-sigs have no XML identifiers
// anywhere, so they are absent rather than invented: an identifier this project
// made up would be a signature nothing else on earth can verify, which is the
// opposite of what a debugger is for.
//
// THE CRYPTOGRAPHY IS INJECTED, exactly as it is for ECDSA and HMAC — see the
// section header above. `opts.signer` / `opts.verifier` do the work;
// @noble/post-quantum in this file would put ML-DSA and SLH-DSA into the SAML,
// WS-Trust and WS-Federation bundles, none of which had a reason to grow by a
// megabyte. What lives here is the REGISTRY: the URI, the family, the sizes and
// the label, in one place, so that five menus and two services cannot disagree
// about what this project supports.
//
// `digestUri` IS ONLY A DEFAULT PAIRING and is not implied by the algorithm.
// DigestMethod hashes the REFERENCED CONTENT and SignatureMethod signs the
// SignedInfo; XMLDSIG makes them independent and this engine's pane lets them
// be. The default pairs each parameter set with a digest of comparable
// strength — a 128-bit-security signature over a SHA-512 digest is not wrong,
// it is merely a pair nobody chose on purpose.
// ===========================================================================
var XMLDSIG_MORE_2026 = 'http://www.w3.org/2026/08/xmldsig-more#';

var SHA256_URI = 'http://www.w3.org/2001/04/xmlenc#sha256';
var SHA384_URI = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
var SHA512_URI = 'http://www.w3.org/2001/04/xmlenc#sha512';

// [ URI suffix, family, the name the engines know it by, digest pairing,
//   public key bytes, signature bytes, label ]. Written as a table because
//   sixteen hand-written object literals is sixteen chances to transpose a
//   number, and every one of these sizes is checkable against FIPS 204/205.
var PQ_SIGS = [
  // --- ML-DSA, FIPS 204, draft section 3.3.15 -----------------------------
  ['ml-dsa-44', 'mldsa', 'ML-DSA-44', SHA256_URI, 1312, 2420,
   'ML-DSA-44 (FIPS 204, category 2 — draft)'],
  ['ml-dsa-65', 'mldsa', 'ML-DSA-65', SHA384_URI, 1952, 3309,
   'ML-DSA-65 (FIPS 204, category 3 — draft)'],
  ['ml-dsa-87', 'mldsa', 'ML-DSA-87', SHA512_URI, 2592, 4627,
   'ML-DSA-87 (FIPS 204, category 5 — draft)'],

  // --- SLH-DSA, FIPS 205, draft section 3.3.16 ----------------------------
  // Twelve parameter sets: three security levels, two hash families, and the
  // "s"/"f" trade — small signatures with slow signing, or fast signing with
  // signatures two to three times the size. The `f` signatures are the largest
  // objects this engine will ever base64 into a document (49,856 bytes for
  // 256f), which is worth knowing before choosing one in a redirect binding.
  ['slh-dsa-sha2-128s', 'slhdsa', 'SLH-DSA-SHA2-128s', SHA256_URI, 32, 7856,
   'SLH-DSA-SHA2-128s (FIPS 205, small — draft)'],
  ['slh-dsa-sha2-128f', 'slhdsa', 'SLH-DSA-SHA2-128f', SHA256_URI, 32, 17088,
   'SLH-DSA-SHA2-128f (FIPS 205, fast — draft)'],
  ['slh-dsa-sha2-192s', 'slhdsa', 'SLH-DSA-SHA2-192s', SHA384_URI, 48, 16224,
   'SLH-DSA-SHA2-192s (FIPS 205, small — draft)'],
  ['slh-dsa-sha2-192f', 'slhdsa', 'SLH-DSA-SHA2-192f', SHA384_URI, 48, 35664,
   'SLH-DSA-SHA2-192f (FIPS 205, fast — draft)'],
  ['slh-dsa-sha2-256s', 'slhdsa', 'SLH-DSA-SHA2-256s', SHA512_URI, 64, 29792,
   'SLH-DSA-SHA2-256s (FIPS 205, small — draft)'],
  ['slh-dsa-sha2-256f', 'slhdsa', 'SLH-DSA-SHA2-256f', SHA512_URI, 64, 49856,
   'SLH-DSA-SHA2-256f (FIPS 205, fast — draft)'],
  ['slh-dsa-shake-128s', 'slhdsa', 'SLH-DSA-SHAKE-128s', SHA256_URI, 32, 7856,
   'SLH-DSA-SHAKE-128s (FIPS 205, small — draft)'],
  ['slh-dsa-shake-128f', 'slhdsa', 'SLH-DSA-SHAKE-128f', SHA256_URI, 32, 17088,
   'SLH-DSA-SHAKE-128f (FIPS 205, fast — draft)'],
  ['slh-dsa-shake-192s', 'slhdsa', 'SLH-DSA-SHAKE-192s', SHA384_URI, 48, 16224,
   'SLH-DSA-SHAKE-192s (FIPS 205, small — draft)'],
  ['slh-dsa-shake-192f', 'slhdsa', 'SLH-DSA-SHAKE-192f', SHA384_URI, 48, 35664,
   'SLH-DSA-SHAKE-192f (FIPS 205, fast — draft)'],
  ['slh-dsa-shake-256s', 'slhdsa', 'SLH-DSA-SHAKE-256s', SHA512_URI, 64, 29792,
   'SLH-DSA-SHAKE-256s (FIPS 205, small — draft)'],
  ['slh-dsa-shake-256f', 'slhdsa', 'SLH-DSA-SHAKE-256f', SHA512_URI, 64, 49856,
   'SLH-DSA-SHAKE-256f (FIPS 205, fast — draft)']

  // --- HSS/LMS, RFC 8554, draft section 3.3.14 ----------------------------
  // Added below rather than in this table: its sizes are a FUNCTION of the
  // parameter set chosen at key generation rather than of the URI, because the
  // one identifier covers every LMS tree height and Winternitz width there is.
];

// THE ONE STATEFUL SCHEME, AND IT IS THE ONE TO READ TWICE. HSS/LMS is a
// hash-based signature whose PRIVATE KEY CHANGES EVERY TIME IT IS USED: each
// one-time key signs once, and spending one twice hands an attacker the
// material to forge a third message. Nothing else in this table is like that,
// and nothing in XML Signature expresses it — the URI says HSS/LMS and says
// nothing about which leaf was spent, so a document signed with a reused index
// verifies perfectly and is worthless. `client/src/hbs.js` is the
// implementation and its pane keeps the index in the key; this registry exists
// so that a SignatureMethod can name it, not so that this file can manage that
// state.
//
// One URI for the whole scheme, per the draft: there is no per-parameter-set
// identifier, so the sizes below are unknown until a key is chosen.
var HSS_LMS_URI = XMLDSIG_MORE_2026 + 'hss-lms';

PQ_SIGS.forEach(function (row) {
  SIG_METHODS[XMLDSIG_MORE_2026 + row[0]] = {
    family: row[1], alg: row[2], hash: null, keyKind: 'akp',
    digestUri: row[3], pubBytes: row[4], sigBytes: row[5],
    postQuantum: true, draft: true, label: row[6]
  };
});

SIG_METHODS[HSS_LMS_URI] =
  { family: 'hsslms', alg: 'HSS-LMS', hash: null, keyKind: 'hsslms',
    digestUri: SHA256_URI, postQuantum: true, draft: true, stateful: true,
    label: 'HSS/LMS (RFC 8554, STATEFUL — draft)' };

// Every post-quantum SignatureMethod this engine knows, in the order they were
// added above. Exported so that a menu is BUILT from this table rather than
// written out beside it: five pages carry an algorithm menu, and five
// hand-written copies of sixteen URIs is five copies that will disagree.
var PQ_SIG_URIS = Object.keys(SIG_METHODS).filter(function (uri) {
  return SIG_METHODS[uri].postQuantum;
});

// ===========================================================================
// THE POST-QUANTUM KEY ENCAPSULATION METHODS, AND THE ONE THING THAT MAKES
// THEM DIFFERENT FROM EVERY OTHER `EncryptedKey` IN THIS FILE.
//
// **A KEM IS NOT KEY TRANSPORT.** RSA key transport takes the content
// encryption key this file has just generated and WRAPS it, so the recipient
// decrypts the CipherValue and has the key. ML-KEM takes only the recipient's
// public key and produces a ciphertext AND A FRESH SHARED SECRET — there is
// nothing to put a key into. So the CipherValue is an ENCAPSULATION, the
// content encryption key is DERIVED from the shared secret rather than
// carried, and the sender does not choose it at all.
//
// draft-eastlake-rfc9231bis-xmlsec-uris section 3.6.9 gives the three
// identifiers and says the shared secret is "typically used as input to a key
// derivation function, such as HKDF (see Section 3.8.1)". **"TYPICALLY" IS NOT
// A BINDING**, and that gap is the one thing here that could make two correct
// implementations disagree — so this file writes every parameter of the
// derivation INTO THE DOCUMENT and reads them back out, rather than agreeing
// with itself about defaults. The `HKDFParams` element is the draft's own
// (section 3.8.1's schema, verbatim: PRF, Salt, Info, KeyLength); where it
// SITS is not specified for a KEM, and it goes inside the EncryptedKey's
// `EncryptionMethod` because that is exactly where this file already carries
// RSA-OAEP's DigestMethod and MGF — an algorithm's own parameters, beside the
// algorithm.
//
// A document produced here therefore says, in full, how its content encryption
// key was derived: the PRF, the salt, the info string and the length. A
// recipient that reads those needs to agree with nothing.
//
// THE LATTICE IS INJECTED and the KDF IS NOT, which is the same split the
// signature side makes for the same reason: `@noble/post-quantum` in this file
// would land in every bundle, so `opts.kem` supplies encapsulate/decapsulate —
// but HKDF is where two implementations silently diverge, so it is written out
// here, once, on the HMAC forge already provides.
// ===========================================================================
var DSIG_MORE_2021 = 'http://www.w3.org/2021/04/xmldsig-more#';
var HKDF_URI = DSIG_MORE_2021 + 'hkdf';
var HMAC_SHA256_URI = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256';

var KEM_METHODS = {};
[['ml-kem-512', 'ML-KEM-512', 800, 768, 1],
 ['ml-kem-768', 'ML-KEM-768', 1184, 1088, 3],
 ['ml-kem-1024', 'ML-KEM-1024', 1568, 1568, 5]].forEach(function (row) {
  KEM_METHODS[XMLDSIG_MORE_2026 + row[0]] = {
    family: 'mlkem', alg: row[1], pubBytes: row[2], ctBytes: row[3],
    secretBytes: 32, postQuantum: true, draft: true,
    label: row[1] + ' (FIPS 203, category ' + row[4] + ' — draft)'
  };
});

// ---------------------------------------------------------------------------
// FrodoKEM AND eFrodoKEM — draft section 3.6.10, and the only algorithm in
// this project with no library behind it. `client/src/frodokem.js` is written
// from the specification and held to the reference implementation's own Known
// Answer Tests for all twelve, which caught a real defect on its first run.
//
// **eFrodoKEM IS NOT "FrodoKEM WITHOUT THE SALT".** It is the original,
// pre-2023 scheme: the salt was added to the standard variant along with a
// widening of the seed, so every length derived from `CRYPTO_BYTES` differs
// too, and the ciphertext is shorter by more than the salt. Six of these
// twelve are one scheme and six are another, and treating them as one produces
// six that round-trip and match no published vector.
//
// Why offer it at all: the salt gives multi-ciphertext security when one key
// pair answers many encapsulations, and an EPHEMERAL key pair answers one —
// which is what [EUCC-ACM] recommends it for and what the `e` means.
//
// The AES and SHAKE halves of each pair differ only in how the matrix A is
// generated and produce different keys from the same seed; they are not
// interchangeable.
// ---------------------------------------------------------------------------
[[640, 9616, 9752, 9720, 1], [976, 15632, 15792, 15744, 3],
 [1344, 21520, 21696, 21632, 5]].forEach(function (row) {
  ['aes', 'shake'].forEach(function (gen) {
    var upper = gen.toUpperCase();
    KEM_METHODS[XMLDSIG_MORE_2026 + 'frodokem-' + row[0] + '-' + gen] = {
      family: 'frodokem', alg: 'FrodoKEM-' + row[0] + '-' + upper,
      pubBytes: row[1], ctBytes: row[2], secretBytes: row[0] === 640 ? 16
        : (row[0] === 976 ? 24 : 32),
      postQuantum: true, draft: true,
      label: 'FrodoKEM-' + row[0] + '-' + upper + ' (ISO 18033-2, category ' +
             row[4] + ' — draft)'
    };
    KEM_METHODS[XMLDSIG_MORE_2026 + 'e-frodokem-' + row[0] + '-' + gen] = {
      family: 'frodokem', alg: 'eFrodoKEM-' + row[0] + '-' + upper,
      pubBytes: row[1], ctBytes: row[3], secretBytes: row[0] === 640 ? 16
        : (row[0] === 976 ? 24 : 32),
      postQuantum: true, draft: true, ephemeral: true,
      label: 'eFrodoKEM-' + row[0] + '-' + upper + ' (EPHEMERAL, category ' +
             row[4] + ' — draft)'
    };
  });
});

var KEM_URIS = Object.keys(KEM_METHODS);

function kemMethod(uri) {
  log.debug("Entering kemMethod().");
  var m = KEM_METHODS[uri];
  if (!m) {
    log.debug("Leaving kemMethod(). Not a KEM.");
    return null;
  }
  log.debug("Leaving kemMethod().");
  return m;
}

// ---------------------------------------------------------------------------
// HKDF, RFC 5869, on forge's HMAC. Extract then expand, written out because
// this is the step a recipient has to reproduce EXACTLY and because a KDF that
// two implementations read differently produces a key that decrypts nothing
// and names no reason.
//
// Everything is forge binary strings, which is what the rest of this file
// speaks. `salt` empty means RFC 5869 section 2.2's default: HashLen zero
// octets.
// ---------------------------------------------------------------------------
function hkdf(prfUri, ikm, salt, info, lengthBytes) {
  log.debug("Entering hkdf(). length=" + lengthBytes);
  var md = FORGE_MD[hmacHashOf(prfUri)];
  if (!md) {
    log.debug("Leaving hkdf(). Unknown PRF.");
    throw new Error('HKDF: "' + prfUri + '" is not a PRF this file knows. ' +
        'RFC 9231 names the HMAC family; hmac-sha256 is what section 3.8.1 ' +
        'RECOMMENDS.');
  }
  var hashLen = md.create().digestLength;
  var actualSalt = salt && salt.length ? salt
    : new Array(hashLen + 1).join('\x00');
  var extract = forge.hmac.create();
  extract.start(md.create(), actualSalt);
  extract.update(ikm);
  var prk = extract.digest().getBytes();
  // Expand. T(0) is empty; T(n) = HMAC(PRK, T(n-1) || info || n).
  var out = '';
  var previous = '';
  var counter = 1;
  while (out.length < lengthBytes) {
    if (counter > 255) {
      log.debug("Leaving hkdf(). Too much output asked for.");
      throw new Error('HKDF: RFC 5869 section 2.3 allows at most 255 ' +
          'blocks of output.');
    }
    var expand = forge.hmac.create();
    expand.start(md.create(), prk);
    expand.update(previous + (info || '') + String.fromCharCode(counter));
    previous = expand.digest().getBytes();
    out += previous;
    counter++;
  }
  log.debug("Leaving hkdf(). " + lengthBytes + " bytes.");
  return out.substring(0, lengthBytes);
}

// The hash a `hmac-sha*` PRF identifier names. Written as a lookup rather than
// a regex so an identifier this file does not implement is refused by name
// instead of quietly falling back to SHA-1.
var HMAC_PRF_HASHES = {};
HMAC_PRF_HASHES['http://www.w3.org/2000/09/xmldsig#hmac-sha1'] = 'sha1';
HMAC_PRF_HASHES[HMAC_SHA256_URI] = 'sha256';
HMAC_PRF_HASHES['http://www.w3.org/2001/04/xmldsig-more#hmac-sha384'] =
  'sha384';
HMAC_PRF_HASHES['http://www.w3.org/2001/04/xmldsig-more#hmac-sha512'] =
  'sha512';

function hmacHashOf(uri) {
  return HMAC_PRF_HASHES[uri];
}

// The draft's section 3.8.1 element, written with the values that were
// actually used. Salt is omitted when empty, which RFC 5869 defines as the
// zero string — writing an empty element would be a different statement.
function hkdfParamsXml(params) {
  log.debug("Entering hkdfParamsXml().");
  var out = '<xenc11:KeyDerivationMethod xmlns:xenc11="' + XENC11_NS +
      '" Algorithm="' + HKDF_URI + '">' +
      '<dsig-more:HKDFParams xmlns:dsig-more="' + DSIG_MORE_2021 + '">' +
      '<dsig-more:PRF Algorithm="' + xmlEscape(params.prf) + '"/>';
  if (params.salt) {
    out += '<dsig-more:Salt>' + forge.util.encode64(params.salt) +
        '</dsig-more:Salt>';
  }
  out += '<dsig-more:Info>' + forge.util.encode64(params.info || '') +
      '</dsig-more:Info>' +
      '<dsig-more:KeyLength>' + params.length + '</dsig-more:KeyLength>' +
      '</dsig-more:HKDFParams></xenc11:KeyDerivationMethod>';
  log.debug("Leaving hkdfParamsXml().");
  return out;
}

// Read them back. Every value comes from the document — see the section header
// on why nothing here is defaulted from a shared assumption.
function readHkdfParams(kmEl) {
  log.debug("Entering readHkdfParams().");
  var kdm = kmEl ? firstByLocal(kmEl, 'KeyDerivationMethod') : null;
  if (!kdm) {
    log.debug("Leaving readHkdfParams(). None.");
    throw new Error('This EncryptedKey names a key-encapsulation algorithm ' +
        'and carries no KeyDerivationMethod, so there is no way to know how ' +
        'its shared secret became a content encryption key. A KEM produces a ' +
        'SECRET and not a wrapped key — the derivation is not optional, and ' +
        'it is not guessable.');
  }
  var kdfAlg = kdm.getAttribute('Algorithm');
  if (kdfAlg !== HKDF_URI) {
    log.debug("Leaving readHkdfParams(). Unsupported KDF.");
    throw new Error('This file derives with HKDF (' + HKDF_URI + '); this ' +
        'document asks for "' + kdfAlg + '".');
  }
  var prfEl = firstByLocal(kdm, 'PRF');
  var saltEl = firstByLocal(kdm, 'Salt');
  var infoEl = firstByLocal(kdm, 'Info');
  var lenEl = firstByLocal(kdm, 'KeyLength');
  var params = {
    prf: prfEl ? prfEl.getAttribute('Algorithm') : HMAC_SHA256_URI,
    salt: saltEl ? forge.util.decode64(saltEl.textContent || '') : '',
    info: infoEl ? forge.util.decode64(infoEl.textContent || '') : '',
    length: lenEl ? parseInt(lenEl.textContent || '0', 10) : 0
  };
  log.debug("Leaving readHkdfParams(). length=" + params.length);
  return params;
}

function sigMethod(uri) {
  log.debug("Entering sigMethod().");
  var m = SIG_METHODS[uri];
  if (!m) throw new Error('Unsupported SignatureMethod: ' + uri);
  log.debug("Leaving sigMethod().");
  return m;
}

// --- Node-set predicates ----------------------------------------------------
function inSubtree(node, root) {
  log.debug("Entering inSubtree().");
  var n = node;
  while (n) {
    if (n === root) {
      log.debug("Leaving inSubtree(). Inside.");
      return true;
    }
    n = n.parentNode;
  }
  log.debug("Leaving inSubtree(). Outside.");
  return false;
}

function andPredicate(a, b) {
  log.debug("Entering andPredicate().");
  if (!a) {
    log.debug("Leaving andPredicate(). Second only.");
    return b;
  }
  log.debug("Leaving andPredicate().");
  return function (n) { return a(n) && b(n); };
}

// --- XPath, which the browser supplies and @xmldom does not -----------------
// Both XPath transforms are evaluated by the DOM's own engine. There is no
// second implementation here and there should not be: an XPath engine written
// for this file would be a large, subtly-wrong dependency of a signature, and
// the one in the browser is the one a verifier on the other side is using
// too. In node (the engine tests, which load @xmldom/xmldom) `evaluate` is
// absent, and these say so by name rather than failing as a bad signature.
function xpathEngine(doc) {
  log.debug("Entering xpathEngine().");
  if (!doc || typeof doc.evaluate !== 'function') {
    throw new Error('The XPath transforms need the DOM XPath engine ' +
        '(document.evaluate), which this environment does not provide. They ' +
        'work in the browser; they do not work under @xmldom/xmldom.');
  }
  log.debug("Leaving xpathEngine().");
  return doc;
}

// A namespace resolver built from the document itself, plus the three
// namespaces an XMLDSIG expression reaches for whether or not the document
// declares them. Without this, `not(ancestor-or-self::ds:Signature)` — the
// canonical enveloped-signature expression, straight out of RFC 3275 — cannot
// resolve `ds` and silently matches nothing.
function nsResolverFor(doc) {
  log.debug("Entering nsResolverFor().");
  var map = { ds: DS_NS, dsig11: DSIG11_NS, xenc: XENC_NS };
  var all = doc.getElementsByTagName('*');
  for (var i = 0; i < all.length; i++) {
    var el = all[i];
    for (var j = 0; j < el.attributes.length; j++) {
      var a = el.attributes[j];
      if (a.name.indexOf('xmlns:') === 0 && !map[a.name.slice(6)]) {
        map[a.name.slice(6)] = a.value;
      }
    }
  }
  log.debug("Leaving nsResolverFor().");
  return function (prefix) { return map[prefix] || null; };
}

// RFC 3275 section 6.6.3. The transform's output node-set contains every node
// of the input for which the expression, evaluated with that node as the
// context node, is true. NOT implemented: the `here()` function, which needs
// the Transform element itself as a context the DOM evaluator cannot be given.
function xpathIncluder(doc, expr) {
  log.debug("Entering xpathIncluder().");
  xpathEngine(doc);
  var resolver = nsResolverFor(doc);
  log.debug("Leaving xpathIncluder().");
  return function (node) {
    // 3 is XPathResult.BOOLEAN_TYPE. The constant is written out because
    // XPathResult is a window global and this module is also loaded in node.
    return !!doc.evaluate(expr, node, resolver, 3, null).booleanValue;
  };
}

function xpathNodes(doc, expr) {
  log.debug("Entering xpathNodes().");
  xpathEngine(doc);
  // 7 is XPathResult.ORDERED_NODE_SNAPSHOT_TYPE — a snapshot rather than an
  // iterator, because the caller keeps the result while walking the tree.
  var r = doc.evaluate(expr, doc, nsResolverFor(doc), 7, null);
  var out = [];
  for (var i = 0; i < r.snapshotLength; i++) out.push(r.snapshotItem(i));
  log.debug("Leaving xpathNodes().");
  return out;
}

// XPath Filter 2.0 (the W3C Note at .../2002/06/xmldsig-filter2). Where the
// XPath transform above asks a question of every node, this one selects
// SUBTREES and combines them, which is both cheaper and what the filters
// actually mean: `subtract` removes a subtree, `intersect` keeps one, `union`
// adds one back. The starting node-set is the whole document.
function filter2Includer(doc, filters) {
  log.debug("Entering filter2Includer().");
  var predicate = null;
  filters.forEach(function (f) {
    var roots = xpathNodes(doc, f.xpath);
    // HOT PATH: `closure` is asked about EVERY node of the document, once per
    // filter, while the canonicalizer walks the tree — thousands of calls for
    // one signature. It carries no Entering/Leaving pair for the reason
    // cbor.js's item decoder does not: at logLevel "debug", which both test
    // configurations set, a pair here IS the log.
    var closure = function (n) {
      for (var i = 0; i < roots.length; i++) {
        if (inSubtree(n, roots[i])) return true;
      }
      return false;
    };
    var op = (f.filter || 'intersect').toLowerCase();
    if (op === 'subtract') {
      predicate = andPredicate(predicate, function (n) { return !closure(n); });
    } else if (op === 'intersect') {
      predicate = andPredicate(predicate, closure);
    } else if (op === 'union') {
      var prior = predicate;
      predicate = function (n) { return closure(n) || (!prior || prior(n)); };
    } else {
      throw new Error('XPath Filter 2.0: unknown Filter "' + f.filter +
          '" — it must be intersect, subtract or union.');
    }
  });
  log.debug("Leaving filter2Includer().");
  return predicate;
}

// --- Octets -----------------------------------------------------------------
// Everything a Reference digests, and the SignedInfo the SignatureValue covers,
// is normalized to a RAW BINARY STRING here. A canonicalizer returns
// characters; a base64 transform returns bytes; a digest takes bytes. Doing the
// UTF-8 encoding once, at the boundary, is what stops a document with a single
// non-ASCII character from digesting differently here than in the verifier —
// which reads as "the document was modified in transit" and is not that.
function octetsOfC14n(text) {
  log.debug("Entering octetsOfC14n().");
  log.debug("Leaving octetsOfC14n().");
  return forge.util.encodeUtf8(text);
}

function canonicalizeBy(uri, node, opts) {
  log.debug("Entering canonicalizeBy().");
  var m = c14nMethod(uri);
  var o = {
    comments: m.comments,
    include: opts && opts.include ? opts.include : null,
    prefixes: (m.exclusive && opts && opts.prefixes) ? opts.prefixes : null
  };
  var text = m.exclusive ? canonicalize(node, o)
    : canonicalizeInclusive(node, o);
  log.debug("Leaving canonicalizeBy().");
  return octetsOfC14n(text);
}

function prefixSet(prefixList) {
  log.debug("Entering prefixSet().");
  var set = null;
  var list = (prefixList || '').split(/\s+/).filter(function (p) {
    return p !== '';
  });
  if (list.length) {
    set = {};
    list.forEach(function (p) { set[p] = true; });
  }
  log.debug("Leaving prefixSet().");
  return set;
}

function textOfNodeSet(node, include) {
  log.debug("Entering textOfNodeSet().");
  var out = '';
  // HOT PATH, like `closure` above: one call per node of the referenced
  // subtree. The function that CALLS it logs, which is where a trace of this
  // step actually lives.
  function walk(n) {
    if (n.nodeType === 3 || n.nodeType === 4) {
      if (!include || include(n)) out += n.nodeValue;
      return;
    }
    var c = n.firstChild;
    while (c) { walk(c); c = c.nextSibling; }
  }
  walk(node);
  log.debug("Leaving textOfNodeSet().");
  return out;
}

// Apply a Reference's Transforms in order and return the octets to digest.
//
// The pipeline is a NODE-SET until a canonicalization or the base64 transform
// turns it into octets, and nothing may follow that — which is the rule that
// catches the commonest mistake in a hand-written Reference, a c14n transform
// listed before the enveloped-signature one. Read in that order the signature
// is inside the digest, the digest is computed over a DigestValue that is
// still empty, and the result verifies nowhere and reports nothing.
function transformOctets(target, transforms, ctx) {
  log.debug("Entering transformOctets().");
  var include = null;
  var octets = null;
  var c14nUsed = null;
  var list = transforms || [];
  for (var i = 0; i < list.length; i++) {
    var t = list[i];
    var alg = t.algorithm;
    if (octets !== null) {
      throw new Error('Transform ' + (i + 1) + ' (' + alg + ') follows one ' +
          'that already produced octets. A canonicalization or the base64 ' +
          'transform ends the chain.');
    }
    if (alg === TRANSFORM_ENVELOPED) {
      if (!ctx.sigNode) {
        throw new Error('The enveloped-signature transform needs a ' +
            '<ds:Signature> to remove, and this reference has none around ' +
            'it. It applies to an ENVELOPED signature only.');
      }
      include = andPredicate(include, (function (sigNode) {
        return function (n) { return !inSubtree(n, sigNode); };
      })(ctx.sigNode));
    } else if (C14N_METHODS[alg]) {
      octets = canonicalizeBy(alg, target, { include: include,
          prefixes: prefixSet(t.prefixList) });
      c14nUsed = alg;
    } else if (alg === TRANSFORM_BASE64) {
      var text = textOfNodeSet(target, include).replace(/\s+/g, '');
      octets = forge.util.decode64(text);
    } else if (alg === TRANSFORM_XPATH) {
      if (!t.xpath) {
        throw new Error('The XPath transform needs an expression.');
      }
      include = andPredicate(include, xpathIncluder(ctx.doc, t.xpath));
    } else if (alg === TRANSFORM_XPATH_FILTER2) {
      var f2 = filter2Includer(ctx.doc, t.filters || []);
      if (f2) include = andPredicate(include, f2);
    } else {
      throw new Error('Unsupported Transform: ' + alg);
    }
  }
  if (octets === null) {
    // XMLDSIG section 4.3.3.2: a Reference whose transforms leave a node-set
    // is serialized with INCLUSIVE Canonical XML, omitting comments. It is the
    // one default in this specification that most people guess wrong (they
    // guess exclusive, because that is what SAML uses everywhere).
    octets = canonicalizeBy(C14N_INCLUSIVE, target, { include: include });
    c14nUsed = C14N_INCLUSIVE;
  }
  log.debug("Leaving transformOctets().");
  return { octets: octets, c14n: c14nUsed };
}

// --- KeyInfo ---------------------------------------------------------------
// ds:CryptoBinary: the unsigned big-endian octets of the integer with leading
// zero octets removed, base64'd. The leading-zero rule is the part that bites:
// forge hands back an even-length hex string with a leading 00 whenever the
// top bit is set, and leaving it in produces a Modulus one byte longer than
// the key, which some verifiers accept and some reject.
function cryptoBinary(bn) {
  log.debug("Entering cryptoBinary().");
  var hex = bn.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  while (hex.length > 2 && hex.slice(0, 2) === '00') hex = hex.slice(2);
  log.debug("Leaving cryptoBinary().");
  return forge.util.encode64(forge.util.hexToBytes(hex));
}

function rsaKeyValueXml(publicPem) {
  log.debug("Entering rsaKeyValueXml().");
  var pub = forge.pki.publicKeyFromPem(publicPem);
  log.debug("Leaving rsaKeyValueXml().");
  return '<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>' + cryptoBinary(pub.n) +
    '</ds:Modulus><ds:Exponent>' + cryptoBinary(pub.e) +
    '</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>';
}

// The elliptic-curve public key of XMLDSIG 1.1 section 4.5.2.3. It is in the
// dsig11 namespace rather than ds, because ECC postdates the 2002
// recommendation — a ds:ECKeyValue is a thing several tools emit and nothing
// reads.
function ecKeyValueXml(namedCurveUri, publicPoint) {
  log.debug("Entering ecKeyValueXml().");
  var raw = typeof publicPoint === 'string' ? publicPoint
    : forge.util.binary.raw.encode(publicPoint);
  log.debug("Leaving ecKeyValueXml().");
  return '<ds:KeyValue><dsig11:ECKeyValue xmlns:dsig11="' + DSIG11_NS + '">' +
    '<dsig11:NamedCurve URI="' + xmlEscape(namedCurveUri) + '"/>' +
    '<dsig11:PublicKey>' + forge.util.encode64(raw) +
    '</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue>';
}

// ---------------------------------------------------------------------------
// A POST-QUANTUM PUBLIC KEY IN KeyInfo, AND WHY IT IS THIS ELEMENT.
//
// There is no `MLDSAKeyValue`, and there is not going to be one soon:
// draft-eastlake-rfc9231bis-xmlsec-uris defines the SIGNATURE identifiers and
// its section 4 adds only a PKCS #7 bag and some RetrievalMethod types —
// nothing for a lattice or a hash-based key. Inventing an element here would
// produce a KeyInfo no verifier on earth parses.
//
// `dsig11:DEREncodedKeyValue` is the element that already answers this: XML
// Signature 1.1 defines it as the base64 of a DER SubjectPublicKeyInfo, for
// exactly the case of a key type XMLDSIG has no structure for. It is what
// Apache Santuario's in-flight post-quantum PR uses, and a SubjectPublicKeyInfo
// is what every one of these algorithms already has an OID and an encoding for.
//
// The caller passes the SPKI it already holds — `key_material.js` and `x509.js`
// both produce one — because building a SubjectPublicKeyInfo needs the
// algorithm OIDs, and this file is not where the post-quantum encodings live.
// ---------------------------------------------------------------------------
function derEncodedKeyValueXml(spkiDer) {
  log.debug("Entering derEncodedKeyValueXml().");
  var raw = typeof spkiDer === 'string' ? spkiDer
    : forge.util.binary.raw.encode(spkiDer);
  log.debug("Leaving derEncodedKeyValueXml().");
  return '<dsig11:DEREncodedKeyValue xmlns:dsig11="' + DSIG11_NS + '">' +
    forge.util.encode64(raw) + '</dsig11:DEREncodedKeyValue>';
}

function buildKeyInfo(opts) {
  log.debug("Entering buildKeyInfo().");
  if (opts.keyInfoXml) {
    log.debug("Leaving buildKeyInfo(). Caller-supplied.");
    return opts.keyInfoXml;
  }
  var kind = opts.keyInfo || 'x509';
  var parts = [];
  if (kind === 'none') {
    log.debug("Leaving buildKeyInfo(). Omitted.");
    return '';
  }
  if (kind === 'keyname' && !opts.keyName) {
    throw new Error('KeyInfo was set to KeyName but no name was supplied.');
  }
  if (opts.keyName) {
    parts.push('<ds:KeyName>' + xmlEscape(opts.keyName) + '</ds:KeyName>');
  }
  if (kind === 'x509' || kind === 'x509+keyvalue') {
    if (!opts.certPem) {
      throw new Error('KeyInfo was set to X509Data but no certificate was ' +
          'supplied.');
    }
    parts.push('<ds:X509Data><ds:X509Certificate>' +
      certPemToB64(opts.certPem) +
      '</ds:X509Certificate></ds:X509Data>');
  }
  if (kind === 'keyvalue' || kind === 'x509+keyvalue') {
    if (opts.ecNamedCurve) {
      parts.push(ecKeyValueXml(opts.ecNamedCurve, opts.ecPublicPoint));
    } else if (opts.publicKeyPem) {
      parts.push(rsaKeyValueXml(opts.publicKeyPem));
    } else {
      throw new Error('KeyInfo was set to KeyValue but no public key was ' +
          'supplied.');
    }
  }
  if (!parts.length) {
    log.debug("Leaving buildKeyInfo(). Nothing to say.");
    return '';
  }
  log.debug("Leaving buildKeyInfo().");
  return '<ds:KeyInfo>' + parts.join('') + '</ds:KeyInfo>';
}

// --- The built-in RSA signer / verifier ------------------------------------
function pssFor(hash) {
  log.debug("Entering pssFor().");
  var md = FORGE_MD[hash];
  log.debug("Leaving pssFor().");
  return forge.pss.create({ md: md.create(),
      mgf: forge.mgf.mgf1.create(md.create()),
      saltLength: md.create().digestLength });
}

function defaultSign(octets, spec, opts) {
  log.debug("Entering defaultSign().");
  if (spec.family !== 'rsa') {
    throw new Error('A ' + (spec.label || spec.family.toUpperCase()) +
        ' SignatureMethod needs a signer — this module implements RSA only, ' +
        'on purpose (see the section header). Pass opts.signer.' +
        (spec.postQuantum ? ' The post-quantum engines are ' +
          'client/src/pqc.js (ML-DSA and SLH-DSA) and client/src/hbs.js ' +
          '(HSS/LMS); this file holds the identifiers and not the lattice.'
        : ''));
  }
  if (!opts.privateKeyPem) {
    throw new Error('signXml: privateKeyPem is required.');
  }
  var pk = forge.pki.privateKeyFromPem(opts.privateKeyPem);
  var md = FORGE_MD[spec.hash].create();
  md.update(octets);
  log.debug("Leaving defaultSign().");
  return spec.pad === 'pss' ? pk.sign(md, pssFor(spec.hash)) : pk.sign(md);
}

function defaultVerify(octets, signature, spec, publicKey) {
  log.debug("Entering defaultVerify().");
  if (spec.family !== 'rsa') {
    throw new Error('A ' + (spec.label || spec.family.toUpperCase()) +
        ' SignatureMethod needs a verifier — this module implements RSA ' +
        'only, on purpose. Pass opts.verifier.' +
        (spec.postQuantum ? ' The post-quantum engines are ' +
          'client/src/pqc.js (ML-DSA and SLH-DSA) and client/src/hbs.js ' +
          '(HSS/LMS); this file holds the identifiers and not the lattice.'
        : ''));
  }
  if (!publicKey) throw new Error('No RSA public key to verify with.');
  var md = FORGE_MD[spec.hash].create();
  md.update(octets);
  log.debug("Leaving defaultVerify().");
  return spec.pad === 'pss'
    ? publicKey.verify(md.digest().getBytes(), signature, pssFor(spec.hash))
    : publicKey.verify(md.digest().getBytes(), signature);
}

// --- Building the Signature -------------------------------------------------
function transformsXml(transforms) {
  log.debug("Entering transformsXml().");
  if (!transforms || !transforms.length) {
    log.debug("Leaving transformsXml(). None.");
    return '';
  }
  var out = transforms.map(function (t) {
    var inner = '';
    if (t.prefixList && C14N_METHODS[t.algorithm]) {
      inner = '<ec:InclusiveNamespaces xmlns:ec="' + C14N_EXCLUSIVE +
        '" PrefixList="' + xmlEscape(t.prefixList) + '"/>';
    }
    if (t.algorithm === TRANSFORM_XPATH) {
      inner = '<ds:XPath>' + xmlEscape(t.xpath || '') + '</ds:XPath>';
    }
    if (t.algorithm === TRANSFORM_XPATH_FILTER2) {
      inner = (t.filters || []).map(function (f) {
        return '<dsig-xpath:XPath xmlns:dsig-xpath="' +
          TRANSFORM_XPATH_FILTER2 + '" Filter="' + xmlEscape(f.filter) + '">' +
          xmlEscape(f.xpath) + '</dsig-xpath:XPath>';
      }).join('');
    }
    return '<ds:Transform Algorithm="' + xmlEscape(t.algorithm) + '">' +
      inner + '</ds:Transform>';
  }).join('');
  log.debug("Leaving transformsXml().");
  return '<ds:Transforms>' + out + '</ds:Transforms>';
}

function idOf(el) {
  log.debug("Entering idOf().");
  var names = ['ID', 'Id', 'id', 'AssertionID'];
  for (var i = 0; i < names.length; i++) {
    var v = el.getAttribute(names[i]);
    if (v) {
      log.debug("Leaving idOf(). Found " + names[i] + ".");
      return v;
    }
  }
  log.debug("Leaving idOf(). None.");
  return '';
}

// The generic signer.
//
// opts: {
//   mode: 'enveloped' | 'enveloping' | 'detached',
//   sigAlg, digestUri, c14nAlg, c14nPrefixList,
//   transforms: [{ algorithm, prefixList, xpath, filters }],
//   privateKeyPem | signer(octets, spec, sigAlg) -> binary string,
//   keyInfo: 'none'|'x509'|'keyvalue'|'x509+keyvalue'|'keyname',
//   certPem, publicKeyPem, ecNamedCurve, ecPublicPoint, keyName, keyInfoXml,
//   refUri, placement, objectId, signatureId
// }
function signXml(xml, opts) {
  log.debug("Entering signXml().");
  var o = opts || {};
  var mode = o.mode || 'enveloped';
  var sigAlg = o.sigAlg || SIG_ALG_RSA_SHA256;
  var spec = sigMethod(sigAlg);
  var digestUri = o.digestUri || spec.digestUri;
  digestSpec(digestUri);
  var c14nAlg = o.c14nAlg || C14N_EXCLUSIVE;
  c14nMethod(c14nAlg);
  var notes = [];

  var doc = parseXmlStrict(xml, 'the XML to sign');
  var transforms = (o.transforms || []).slice();
  if (mode === 'enveloped') {
    var hasEnveloped = transforms.some(function (t) {
      return t.algorithm === TRANSFORM_ENVELOPED;
    });
    if (!hasEnveloped) {
      // Without it the Reference covers the Signature that carries the
      // Reference, so the digest is taken over an empty DigestValue and can
      // never be reproduced. Adding it is the only useful thing to do, and
      // saying so is the only honest one.
      transforms.unshift({ algorithm: TRANSFORM_ENVELOPED });
      notes.push('Added the enveloped-signature transform: an enveloped ' +
          'signature whose Reference does not remove itself can never ' +
          'verify.');
    }
  }

  var sigDoc, target, refUri, objectNode = null;
  if (mode === 'enveloping') {
    var objectId = o.objectId || ('obj-' + genId().slice(2));
    sigDoc = new DOMParser().parseFromString(
      '<ds:Signature xmlns:ds="' + DS_NS + '"><ds:Object Id="' +
      xmlEscape(objectId) + '"/></ds:Signature>', 'application/xml');
    objectNode = directChildByLocal(sigDoc.documentElement, 'Object');
    objectNode.appendChild(sigDoc.importNode(doc.documentElement, true));
    target = objectNode;
    refUri = '#' + objectId;
  } else if (mode === 'detached') {
    var rootId = idOf(doc.documentElement);
    if (!rootId) {
      // A detached Reference names what it covers, and "" means "the document
      // containing the signature" — which, for a standalone <ds:Signature>, is
      // the signature itself. So the referenced document gets an Id, and the
      // caller is told, because the document that verifies is now this one and
      // not the one they typed.
      rootId = genId();
      doc.documentElement.setAttribute('ID', rootId);
      notes.push('The referenced document had no ID attribute, so ID="' +
          rootId + '" was added to its root element. A detached Reference ' +
          'has to name what it covers, and the document that verifies is the ' +
          'one returned below.');
    }
    sigDoc = new DOMParser().parseFromString(
      '<ds:Signature xmlns:ds="' + DS_NS + '"/>', 'application/xml');
    target = doc.documentElement;
    refUri = '#' + rootId;
  } else if (mode === 'enveloped') {
    sigDoc = doc;
    target = doc.documentElement;
    var id = idOf(doc.documentElement);
    refUri = id ? ('#' + id) : '';
  } else {
    throw new Error('Unknown signature type: ' + mode);
  }
  if (o.refUri != null && o.refUri !== '') refUri = o.refUri;

  var sigId = o.signatureId ? (' Id="' + xmlEscape(o.signatureId) + '"') : '';
  var c14nInner = o.c14nPrefixList
    ? ('<ec:InclusiveNamespaces xmlns:ec="' + C14N_EXCLUSIVE +
       '" PrefixList="' + xmlEscape(o.c14nPrefixList) + '"/>') : '';
  var signedInfo = '<ds:SignedInfo>' +
    '<ds:CanonicalizationMethod Algorithm="' + xmlEscape(c14nAlg) + '">' +
    c14nInner + '</ds:CanonicalizationMethod>' +
    '<ds:SignatureMethod Algorithm="' + xmlEscape(sigAlg) + '"/>' +
    '<ds:Reference URI="' + xmlEscape(refUri) + '">' +
    transformsXml(transforms) +
    '<ds:DigestMethod Algorithm="' + xmlEscape(digestUri) + '"/>' +
    '<ds:DigestValue></ds:DigestValue>' +
    '</ds:Reference></ds:SignedInfo>';

  var signatureXml = '<ds:Signature xmlns:ds="' + DS_NS + '"' + sigId + '>' +
    signedInfo + '<ds:SignatureValue></ds:SignatureValue>' +
    buildKeyInfo(o) + '</ds:Signature>';
  var built = new DOMParser().parseFromString(signatureXml,
      'application/xml').documentElement;

  var sigNode;
  if (mode === 'enveloping') {
    // The Signature element already exists (it holds the Object); move the
    // built children in rather than replacing the element, so the Object the
    // Reference names is not orphaned.
    sigNode = sigDoc.documentElement;
    if (o.signatureId) sigNode.setAttribute('Id', o.signatureId);
    var kid = built.firstChild;
    while (kid) {
      var next = kid.nextSibling;
      sigNode.insertBefore(sigDoc.importNode(kid, true), objectNode);
      kid = next;
    }
  } else if (mode === 'detached') {
    sigNode = sigDoc.importNode(built, true);
    sigDoc.replaceChild(sigNode, sigDoc.documentElement);
  } else {
    sigNode = sigDoc.importNode(built, true);
    var root = sigDoc.documentElement;
    var placement = o.placement || 'last';
    if (placement === 'first') {
      root.insertBefore(sigNode, root.firstChild);
    } else if (placement === 'after-issuer') {
      var issuer = null, kids = root.childNodes;
      for (var i = 0; i < kids.length; i++) {
        if (kids[i].nodeType === 1 && kids[i].localName === 'Issuer') {
          issuer = kids[i];
          break;
        }
      }
      if (issuer) root.insertBefore(sigNode, issuer.nextSibling);
      else root.insertBefore(sigNode, root.firstChild);
    } else {
      root.appendChild(sigNode);
    }
  }

  // The Reference digest, over the transform pipeline, with the Signature
  // already in the tree — which is the state a verifier sees, and the reason
  // the enveloped-signature transform is not optional above.
  var refCtx = { doc: mode === 'detached' ? doc : sigDoc, sigNode: sigNode };
  var refOut = transformOctets(target, transforms, refCtx);
  var dmd = digestSpec(digestUri).md.create();
  dmd.update(refOut.octets);
  var digest = forge.util.encode64(dmd.digest().getBytes());
  var siNode = directChildByLocal(sigNode, 'SignedInfo');
  firstByLocal(siNode, 'DigestValue')
    .appendChild(sigDoc.createTextNode(digest));

  // SignatureValue over C14N(SignedInfo), canonicalized IN PLACE. Inclusive
  // C14N pulls in every namespace the ancestors declare, so a SignedInfo
  // canonicalized while detached would not match what a verifier computes from
  // the finished document.
  var siOctets = canonicalizeBy(c14nAlg, siNode,
      { prefixes: prefixSet(o.c14nPrefixList) });
  var signer = o.signer || function (octets, sp) {
    return defaultSign(octets, sp, o);
  };
  var rawSig = signer(siOctets, spec, sigAlg);
  var sigB64 = typeof rawSig === 'string' ? forge.util.encode64(rawSig)
    : forge.util.encode64(forge.util.binary.raw.encode(rawSig));
  directChildByLocal(sigNode, 'SignatureValue')
    .appendChild(sigDoc.createTextNode(sigB64));

  var serializer = new XMLSerializer();
  log.debug("Leaving signXml().");
  return {
    xml: serializer.serializeToString(sigDoc),
    referencedXml: mode === 'detached' ? serializer.serializeToString(doc)
      : null,
    mode: mode,
    signatureMethod: sigAlg,
    digestMethod: digestUri,
    canonicalization: c14nAlg,
    referenceUri: refUri,
    referenceC14n: refOut.c14n,
    digestValue: digest,
    signatureValue: sigB64,
    signedInfo: forge.util.decodeUtf8(siOctets),
    transforms: transforms.map(function (t) { return t.algorithm; }),
    notes: notes
  };
}

// --- Reading a Signature back -----------------------------------------------
function readTransforms(ref) {
  log.debug("Entering readTransforms().");
  var out = [];
  var container = firstByLocal(ref, 'Transforms');
  if (!container) {
    log.debug("Leaving readTransforms(). None.");
    return out;
  }
  var nodes = container.getElementsByTagNameNS('*', 'Transform');
  for (var i = 0; i < nodes.length; i++) {
    var el = nodes[i];
    var t = { algorithm: el.getAttribute('Algorithm') || '' };
    var incl = firstByLocal(el, 'InclusiveNamespaces');
    if (incl) t.prefixList = incl.getAttribute('PrefixList') || '';
    var xp = el.getElementsByTagNameNS('*', 'XPath');
    if (xp.length && t.algorithm === TRANSFORM_XPATH_FILTER2) {
      t.filters = [];
      for (var j = 0; j < xp.length; j++) {
        t.filters.push({ filter: xp[j].getAttribute('Filter') || 'intersect',
                         xpath: (xp[j].textContent || '').trim() });
      }
    } else if (xp.length) {
      t.xpath = (xp[0].textContent || '').trim();
    }
    out.push(t);
  }
  log.debug("Leaving readTransforms().");
  return out;
}

// An RSA public key rebuilt from a ds:RSAKeyValue, so a signature whose
// KeyInfo carries the key rather than a certificate can still be checked. It
// is a public key and nothing else — there is no identity in it, which is
// exactly what makes KeyValue a poor thing for a relying party to trust and a
// useful thing for a debugger to read.
function rsaKeyFromKeyValue(sig) {
  log.debug("Entering rsaKeyFromKeyValue().");
  var kv = firstByLocal(sig, 'RSAKeyValue');
  if (!kv) {
    log.debug("Leaving rsaKeyFromKeyValue(). None.");
    return null;
  }
  var mod = firstByLocal(kv, 'Modulus'), exp = firstByLocal(kv, 'Exponent');
  if (!mod || !exp) {
    log.debug("Leaving rsaKeyFromKeyValue(). Incomplete.");
    return null;
  }
  function toBig(el) {
    log.debug("Entering toBig().");
    var raw = forge.util.decode64((el.textContent || '').replace(/\s+/g, ''));
    log.debug("Leaving toBig().");
    return new forge.jsbn.BigInteger(forge.util.bytesToHex(raw), 16);
  }
  log.debug("Leaving rsaKeyFromKeyValue().");
  return forge.pki.setRsaPublicKey(toBig(mod), toBig(exp));
}

// The generic verifier. `opts.referencedXml` is what makes a DETACHED
// signature checkable: the references resolve into that document rather than
// into the one carrying the Signature.
//
// opts: { certPem, publicKeyPem, referencedXml,
//         verifier(octets, signatureBytes, spec, sigAlgUri) -> bool }
function verifyXml(xml, opts) {
  log.debug("Entering verifyXml().");
  var o = opts || {};
  var doc;
  try {
    doc = parseXmlStrict(xml, 'the signed XML');
  } catch (e) {
    log.debug("Leaving verifyXml(). Malformed.");
    return { valid: false, error: e.message };
  }
  var refDoc = doc;
  if (o.referencedXml) {
    try {
      refDoc = parseXmlStrict(o.referencedXml, 'the referenced XML');
    } catch (e) {
      log.debug("Leaving verifyXml(). Referenced document malformed.");
      return { valid: false, error: e.message };
    }
  }
  var sig = doc.documentElement.localName === 'Signature'
    ? doc.documentElement : firstByLocal(doc, 'Signature');
  if (!sig) {
    log.debug("Leaving verifyXml(). No signature.");
    return { valid: false, error: 'No <ds:Signature> element found.' };
  }
  var si = directChildByLocal(sig, 'SignedInfo');
  var svEl = directChildByLocal(sig, 'SignatureValue');
  if (!si || !svEl) {
    log.debug("Leaving verifyXml(). Incomplete signature.");
    return { valid: false,
             error: 'The Signature has no SignedInfo or no SignatureValue.' };
  }
  var smEl = firstByLocal(si, 'SignatureMethod');
  var sigAlg = smEl ? smEl.getAttribute('Algorithm') : '';
  var cmEl = firstByLocal(si, 'CanonicalizationMethod');
  var c14nAlg = cmEl ? cmEl.getAttribute('Algorithm') : C14N_EXCLUSIVE;
  var spec, result = { signatureMethod: sigAlg, canonicalization: c14nAlg };
  try {
    spec = sigMethod(sigAlg);
    c14nMethod(c14nAlg);
  } catch (e) {
    log.debug("Leaving verifyXml(). Unknown algorithm.");
    return { valid: false, error: e.message, signatureMethod: sigAlg,
             canonicalization: c14nAlg };
  }
  var cmIncl = cmEl ? firstByLocal(cmEl, 'InclusiveNamespaces') : null;
  var cmPrefixes = cmIncl ? prefixSet(cmIncl.getAttribute('PrefixList')) : null;

  var certB64 = '';
  var x509El = firstByLocal(sig, 'X509Certificate');
  if (x509El) certB64 = (x509El.textContent || '').replace(/\s+/g, '');
  var certPem = o.certPem ? pemWrapCert(o.certPem)
    : (certB64 ? pemWrapCert(certB64) : '');
  var cert = null, publicKey = null;
  if (certPem) {
    try {
      cert = forge.pki.certificateFromPem(certPem);
      publicKey = cert.publicKey;
    } catch (e) {
      log.debug("Leaving verifyXml(). Bad certificate.");
      return { valid: false,
               error: 'Could not parse the signing certificate: ' + e.message };
    }
  } else if (o.publicKeyPem) {
    try {
      publicKey = forge.pki.publicKeyFromPem(o.publicKeyPem);
    } catch (e) {
      // Not an RSA SubjectPublicKeyInfo — an EC or HMAC verification does not
      // need one, and an RSA one with no key is reported by defaultVerify().
      publicKey = null;
    }
  }
  if (!publicKey) publicKey = rsaKeyFromKeyValue(sig);

  var siOctets = canonicalizeBy(c14nAlg, si, { prefixes: cmPrefixes });
  var signatureBytes = forge.util.decode64((svEl.textContent ||
      '').replace(/\s+/g, ''));
  var signatureValid = false, signatureError = null;
  try {
    signatureValid = o.verifier
      ? !!o.verifier(siOctets, signatureBytes, spec, sigAlg)
      : defaultVerify(siOctets, signatureBytes, spec, publicKey);
  } catch (e) {
    signatureValid = false;
    signatureError = e.message;
  }

  var references = [];
  var refs = si.getElementsByTagNameNS('*', 'Reference');
  for (var i = 0; i < refs.length; i++) {
    var ref = refs[i];
    var uri = ref.getAttribute('URI') || '';
    var entry = { uri: uri };
    try {
      var dmEl = firstByLocal(ref, 'DigestMethod');
      var digUri = dmEl ? dmEl.getAttribute('Algorithm') : '';
      var dvEl = firstByLocal(ref, 'DigestValue');
      var declared = dvEl ? (dvEl.textContent || '').replace(/\s+/g, '') : '';
      var bare = uri.replace(/^#/, '');
      var target = uri === ''
        ? refDoc.documentElement
        : (findById(doc, bare) || findById(refDoc, bare));
      if (!target) {
        entry.ok = false;
        entry.reason = 'the referenced element was not found';
        references.push(entry);
        continue;
      }
      var ctx = { doc: target.ownerDocument || refDoc, sigNode: sig };
      var out = transformOctets(target, readTransforms(ref), ctx);
      var md = digestSpec(digUri).md.create();
      md.update(out.octets);
      entry.computed = forge.util.encode64(md.digest().getBytes());
      entry.declared = declared;
      entry.digestMethod = digUri;
      entry.ok = entry.computed === declared;
      if (!entry.ok) entry.reason = 'the digest does not match';
    } catch (e) {
      entry.ok = false;
      entry.reason = e.message;
    }
    references.push(entry);
  }
  var referencesValid = references.length > 0 &&
      references.every(function (r) { return r.ok; });

  result.valid = signatureValid && referencesValid;
  result.signatureValid = signatureValid;
  result.signatureError = signatureError;
  result.referencesValid = referencesValid;
  result.references = references;
  result.signerSubject = cert ? certSubjectCN(cert) : '';
  result.signerCertB64 = certB64;
  result.keyInfo = firstByLocal(sig, 'KeyInfo') ? 'present' : 'absent';
  log.debug("Leaving verifyXml().");
  return result;
}

// --- Verifying a redirect-binding query-string signature --------------------
// The counterpart of signQueryString() above, and it lives down here rather
// than beside it because it reads the GENERAL engine's tables: a message
// arriving from somebody else's identity provider may be signed with anything
// the registry names, while what this application SENDS is the RSA family
// signQueryString() covers. SIG_METHODS knows ECDSA and the RFC 9231 PSS URIs
// as well, and saying "ECDSA-SHA256, pass a verifier" is worth more to
// somebody debugging than "unsupported SigAlg".
//
// What is verified is the octet string EXACTLY as given. saml-bindings-2.0-os
// section 3.4.4.1 signs the query string as it will be SENT — the
// percent-encoded `SAMLRequest=…&RelayState=…&SigAlg=…`, in that order, with
// the Signature parameter itself excluded — so a caller that re-orders the
// parameters or decodes them first has changed the message and will get a
// clean INVALID for a signature that is in fact good. saml_message.js's
// redirectSignedOctets() is what rebuilds them from a URL in the order they
// appeared, which is the only order that can be right.
//
// opts: { signature (base64), sigAlg, certPem | publicKeyPem, verifier }
// Returns { valid, error, signatureMethod, label, signerSubject } — an `error`
// rather than a throw for every reason a debugger's user can cause, because
// this is called on a paste.
function verifyQueryString(queryString, opts) {
  log.debug("Entering verifyQueryString().");
  opts = opts || {};
  if (!opts.signature) {
    log.debug("Leaving verifyQueryString(). No signature.");
    return { valid: false, error: 'No Signature parameter to verify.' };
  }
  var sigAlg = opts.sigAlg || SIG_ALG_RSA_SHA256;
  var spec;
  try {
    spec = sigMethod(sigAlg);
  } catch (e) {
    log.debug("Leaving verifyQueryString(). Unknown SigAlg.");
    return { valid: false, error: e.message, signatureMethod: sigAlg };
  }
  var certPem = opts.certPem ? pemWrapCert(opts.certPem) : '';
  var cert = null, publicKey = null;
  if (certPem) {
    try {
      cert = forge.pki.certificateFromPem(certPem);
      publicKey = cert.publicKey;
    } catch (e) {
      log.debug("Leaving verifyQueryString(). Bad certificate.");
      return { valid: false, signatureMethod: sigAlg, label: spec.label,
              error: 'Could not parse the signing certificate: ' + e.message };
    }
  } else if (opts.publicKeyPem) {
    try {
      publicKey = forge.pki.publicKeyFromPem(opts.publicKeyPem);
    } catch (e) {
      log.debug("Leaving verifyQueryString(). Bad public key.");
      return { valid: false, signatureMethod: sigAlg, label: spec.label,
              error: 'Could not parse the public key: ' + e.message };
    }
  }
  // A redirect-binding signature is DETACHED and carries no KeyInfo — there is
  // nowhere in the query string to put one. So unlike verifyXml(), which can
  // fall back to the certificate the document brought with it, this cannot
  // proceed without a key from the caller, and saying so is the whole message.
  if (!publicKey && !opts.verifier) {
    log.debug("Leaving verifyQueryString(). No key.");
    return { valid: false, signatureMethod: sigAlg, label: spec.label,
            error: 'A redirect-binding signature is detached and carries no ' +
                   'KeyInfo, so the signer\'s certificate has to be ' +
                   'supplied.' };
  }
  var signature;
  try {
    signature = forge.util.decode64(opts.signature);
  } catch (e) {
    log.debug("Leaving verifyQueryString(). Signature not base64.");
    return { valid: false, signatureMethod: sigAlg, label: spec.label,
            error: 'The Signature parameter is not valid base64: ' +
                   e.message };
  }
  // encodeUtf8 rather than the raw string, so these are byte-for-byte the
  // octets signQueryString()'s `md.update(queryString, 'utf8')` hashes. The two
  // agree on every ASCII query string, which is all of them — this is here so
  // that stays true rather than by luck.
  var octets = forge.util.encodeUtf8(queryString);
  var valid;
  try {
    valid = opts.verifier
      ? !!opts.verifier(octets, signature, spec, publicKey)
      : defaultVerify(octets, signature, spec, publicKey);
  } catch (e) {
    log.debug("Leaving verifyQueryString(). Verification threw.");
    return { valid: false, signatureMethod: sigAlg, label: spec.label,
            signerSubject: cert ? certSubjectCN(cert) : '',
            error: e.message };
  }
  log.debug("Leaving verifyQueryString().");
  return {
    valid: !!valid,
    signatureMethod: sigAlg,
    label: spec.label,
    signerSubject: cert ? certSubjectCN(cert) : ''
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
  // The pieces of the encryption path, exported because saml_request.js builds
  // its own SAML-shaped EncryptedData around them rather than calling
  // encryptXml() — and used to carry its own copy of all four.
  dataAlgSpec: dataAlgSpec,
  forgeMdFor: forgeMdFor,
  mgfMdFor: mgfMdFor,
  encPlaintext: encPlaintext,
  decryptXml: decryptXml,
  signEnveloped: signEnveloped,
  // The general engine (the Digital Signature page's XML Signature pane).
  DSIG11_NS: DSIG11_NS,
  C14N_INCLUSIVE: C14N_INCLUSIVE,
  C14N_INCLUSIVE_WC: C14N_INCLUSIVE_WC,
  C14N_EXCLUSIVE_WC: C14N_EXCLUSIVE_WC,
  TRANSFORM_BASE64: TRANSFORM_BASE64,
  TRANSFORM_XPATH: TRANSFORM_XPATH,
  TRANSFORM_XPATH_FILTER2: TRANSFORM_XPATH_FILTER2,
  C14N_METHODS: C14N_METHODS,
  DIGEST_METHODS: DIGEST_METHODS,
  SIG_METHODS: SIG_METHODS,
  c14nMethod: c14nMethod,
  digestSpec: digestSpec,
  sigMethod: sigMethod,
  canonicalizeBy: canonicalizeBy,
  transformOctets: transformOctets,
  rsaKeyValueXml: rsaKeyValueXml,
  ecKeyValueXml: ecKeyValueXml,
  derEncodedKeyValueXml: derEncodedKeyValueXml,
  // The post-quantum half of the table, so that a menu is BUILT from it.
  XMLDSIG_MORE_2026: XMLDSIG_MORE_2026,
  HSS_LMS_URI: HSS_LMS_URI,
  PQ_SIG_URIS: PQ_SIG_URIS,
  // The key-encapsulation half, and the derivation that turns a KEM's shared
  // secret into a content encryption key. `hkdf` is exported because it is
  // held to RFC 5869's own vectors in tests/xmldsig_pqc.js — a KDF is where
  // two implementations diverge silently.
  KEM_METHODS: KEM_METHODS,
  KEM_URIS: KEM_URIS,
  kemMethod: kemMethod,
  HKDF_URI: HKDF_URI,
  HMAC_SHA256_URI: HMAC_SHA256_URI,
  hkdf: hkdf,
  hkdfParamsXml: hkdfParamsXml,
  readHkdfParams: readHkdfParams,
  signXml: signXml,
  verifyXml: verifyXml,
  signQueryString: signQueryString,
  verifyQueryString: verifyQueryString,
  signWsSecurity: signWsSecurity,
  verifyXmlSignature: verifyXmlSignature,
  generateKeyPair: generateKeyPair,
  selfSignedCertFor: selfSignedCertFor
};
