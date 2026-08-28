// File: key_material.js
//
// ---------------------------------------------------------------------------
// Key pairs, and the keystore formats a key pair can leave this browser in.
//
// Extracted from jwt_tools.js, which had all of it and was the only page that
// did: the algorithm table, generation, the PEM<->JWK conversion behind the
// per-pane format toggle, PBES2-encrypted PKCS#8, PKCS#12, and the PBES2 JWE
// that password-protects a JWK set. The PKI page needs every one of those for
// the same reasons — a CA's key is a key pair like any other, and the thing an
// operator does with an issued certificate is import it somewhere else, which
// means a keystore file.
//
// So this is the one implementation, and jwt_tools.js is now a caller of it
// rather than the place it lives. A second copy would not have stayed a copy:
// these encodings are read by OpenSSL, keytool and somebody else's TLS stack,
// and "close enough" is not a thing a wire format can be.
//
// TWO THINGS ARE DELIBERATELY NOT HERE.
//
//   * Certificates. Authoring an X.509 certificate is client/src/x509.js, which
//     requires this module and not the other way round — one direction, so
//     neither can pull the other into a bundle that wanted only keys.
//     buildPkcs12() therefore takes the certificates it is to wrap rather than
//     minting one, which is also what lets the PKI page put a real chain in a
//     .p12 where jwt_tools puts the self-signed cert it makes for the purpose.
//   * The DOM. Everything below works on strings and bytes, and exportKeyPair()
//     RETURNS the files rather than downloading them, so the whole export
//     matrix is checkable in node (tests/pki_key_formats.js does exactly that,
//     against OpenSSL). triggerDownload() is the one browser-only function
//     here, and it is what a page calls with what exportKeyPair() returned.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The byte/base64url/PEM helpers and the flexible key import. Shared rather
// than copied for the reason jose_jwe.js's own header gives.
var jose = require("./jose_jwe");
var pkijs = require("pkijs");
var asn1js = require("asn1js");

// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "key_material",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// PKI.js needs a Web Crypto engine. In the browser the global `crypto` object
// provides it; in node (v18+) the same global exists, which is what lets the
// keystore formats be tested with no browser.
(function initPkiEngine() {
  try {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      pkijs.setEngine('webcrypto', new pkijs.CryptoEngine({ name: 'webcrypto',
                      crypto: crypto }));
    }
  } catch (e) {
    log.error('Failed to init PKI.js engine: ' + e.message);
  }
})();

var derToPem = jose.derToPem;
var pemToDer = jose.pemToDer;
var bytesToB64u = jose.bytesToB64u;
var strToB64u = jose.strToB64u;
var concatBytes = jose.concatBytes;

// ---------------------------------------------------------------------------
// The key algorithms this project generates.
//
// Keyed by the id a page's dropdown carries. `kind` is the family every
// function below switches on, and it is the SAME vocabulary jwt_tools.js's
// certDescriptor() has always produced ('rsa' | 'ec' | 'okp' | 'hmac') — so a
// descriptor from either source is accepted anywhere here.
//
// Ed25519 is Web Crypto's only Edwards curve; Ed448 is defined by RFC 8032 and
// is not available in any browser, so it is absent rather than listed and
// broken. Nothing here generates X25519 or ECDH keys: a certificate's subject
// key has to be able to sign or to be signed for, and a key-agreement-only key
// is a different pane's problem (jose_jwe.js has it).
// ---------------------------------------------------------------------------
var KEY_ALGS = {
  'rsa-2048': { kind: 'rsa', bits: 2048, label: 'RSA 2048' },
  'rsa-3072': { kind: 'rsa', bits: 3072, label: 'RSA 3072' },
  'rsa-4096': { kind: 'rsa', bits: 4096, label: 'RSA 4096' },
  'ec-p256': { kind: 'ec', curve: 'P-256', label: 'ECDSA P-256' },
  'ec-p384': { kind: 'ec', curve: 'P-384', label: 'ECDSA P-384' },
  'ec-p521': { kind: 'ec', curve: 'P-521', label: 'ECDSA P-521' },
  'ed25519': { kind: 'okp', name: 'Ed25519', label: 'Ed25519 (EdDSA)' }
};

// The order the dropdowns show them in — an object's key order is not a
// contract, and two panes listing the same algorithms differently is the kind
// of difference that is only visible in a screenshot.
var KEY_ALG_ORDER = ['rsa-2048', 'rsa-3072', 'rsa-4096', 'ec-p256', 'ec-p384',
                     'ec-p521', 'ed25519'];

function keyAlgIds() {
  log.debug("Entering keyAlgIds().");
  log.debug("Leaving keyAlgIds().");
  return KEY_ALG_ORDER.slice();
}

// The descriptor for a key algorithm id. Returns null for an unknown id rather
// than throwing, so a page can report "this build does not know that algorithm"
// against a stored object generated by a newer one.
function keyAlg(id) {
  log.debug("Entering keyAlg(). id=" + id);
  var found = KEY_ALGS[String(id || '').toLowerCase()] || null;
  log.debug("Leaving keyAlg().");
  return found ? Object.assign({ id: String(id).toLowerCase() }, found) : null;
}

// ---------------------------------------------------------------------------
// Describe how to import a private key for signing, from a JOSE `alg`.
//
// This is jwt_tools.js's certDescriptor(), moved here unchanged in behaviour:
// RSA keys (RS*/PS*/RSA-OAEP*) sign with RSASSA-PKCS1-v1_5/SHA-256, EC keys
// (ES*/ECDH-ES) with ECDSA over the curve's natural hash.
// ---------------------------------------------------------------------------
function certDescriptor(alg) {
  log.debug("Entering certDescriptor().");
  var ecCurve = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };
  var ecHash = { ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512' };
  if (alg[0] === 'H') {
    log.debug("Leaving certDescriptor().");
    return { kind: 'hmac' };
  }
  if (alg === 'EdDSA') {
    log.debug("Leaving certDescriptor().");
    return { kind: 'okp', name: 'Ed25519' };
  }
  if (alg.indexOf('ECDH-ES') === 0) {
    log.debug("Leaving certDescriptor().");
    return { kind: 'ec', curve: 'P-256', hash: 'SHA-256' };
  } // ECDH-ES[+A*KW]
  if (alg[0] === 'E') {
    log.debug("Leaving certDescriptor().");
    return { kind: 'ec', curve: ecCurve[alg], hash: ecHash[alg] };
  }         // ES256/384/512
  log.debug("Leaving certDescriptor().");
  return { kind: 'rsa', hash: 'SHA-256' }; // RS*/PS*/RSA-OAEP*
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------
// Generate a key pair and return it as PEM (PKCS#8 private, SPKI public),
// which is the form every other function here, and every field on every page,
// works in. `spec` is a KEY_ALGS id or a descriptor object.
//
// HMAC is not a key pair and is refused here rather than returned as one: a
// page that offers a symmetric secret (jwt_tools does) reads generateSecret()
// instead, so nothing downstream has to check whether `publicPem` is really a
// public key.
async function generateKeyPair(spec) {
  log.debug("Entering generateKeyPair().");
  var desc = typeof spec === 'string' ? keyAlg(spec) : spec;
  if (!desc) {
    log.debug("Leaving generateKeyPair(). Unknown algorithm.");
    throw new Error('Unknown key algorithm: ' + spec);
  }
  if (desc.kind === 'hmac') {
    log.debug("Leaving generateKeyPair(). HMAC has no key pair.");
    throw new Error('HMAC is symmetric — it has no key pair. Use ' +
                    'generateSecret().');
  }
  var params;
  if (desc.kind === 'rsa') {
    params = { name: 'RSASSA-PKCS1-v1_5',
               modulusLength: desc.bits || 2048,
               publicExponent: new Uint8Array([1, 0, 1]),
               hash: desc.hash || 'SHA-256' };
  } else if (desc.kind === 'okp') {
    params = { name: desc.name || 'Ed25519' };
  } else {
    params = { name: 'ECDSA', namedCurve: desc.curve || 'P-256' };
  }
  var pair = await crypto.subtle.generateKey(params, true, ['sign', 'verify']);
  var privatePem = derToPem(await crypto.subtle.exportKey('pkcs8',
      pair.privateKey), 'PRIVATE KEY');
  var publicPem = derToPem(await crypto.subtle.exportKey('spki',
      pair.publicKey), 'PUBLIC KEY');
  log.debug("Leaving generateKeyPair().");
  return { privatePem: privatePem, publicPem: publicPem,
           alg: desc.id || null, kind: desc.kind };
}

// A symmetric secret, base64url, for the one algorithm family that has no pair.
function generateSecret(bytes) {
  log.debug("Entering generateSecret().");
  var secret = new Uint8Array(bytes || 32);
  crypto.getRandomValues(secret);
  log.debug("Leaving generateSecret().");
  return bytesToB64u(secret);
}

// ---------------------------------------------------------------------------
// PEM <-> JWK conversion for the key fields (driven by a pane's format toggle).
//
// Conversion is key-material only, so any compatible import params work; RSA
// keys go through RSASSA-PKCS1-v1_5 and EC keys through ECDSA.
// ---------------------------------------------------------------------------
function isJwk(text) {
  log.debug("Entering isJwk().");
  log.debug("Leaving isJwk().");
  return (text || '').trim().charAt(0) === '{';
}

// Shared with jose_jwe.js rather than written twice: a JWK carrying `alg` or
// `use` is refused by Web Crypto's import when they disagree with the params.
var stripJwkForImport = jose.stripJwkForImport;

function convParams(desc) {
  log.debug("Entering convParams().");
  if (desc.kind === 'rsa') {
    log.debug("Leaving convParams().");
    return { name: 'RSASSA-PKCS1-v1_5', hash: desc.hash || 'SHA-256' };
  }
  if (desc.kind === 'okp') {
    log.debug("Leaving convParams().");
    return { name: desc.name || 'Ed25519' };
  }
  log.debug("Leaving convParams().");
  return { name: 'ECDSA', namedCurve: desc.curve || 'P-256' };
}

async function privToJwk(pem, desc, jwtAlg, use) {
  log.debug("Entering privToJwk().");
  var key = await crypto.subtle.importKey('pkcs8', pemToDer(pem),
      convParams(desc), true, ['sign']);
  var jwk = await crypto.subtle.exportKey('jwk', key);
  delete jwk.key_ops;
  delete jwk.ext;
  if (jwtAlg) jwk.alg = jwtAlg;
  if (use) jwk.use = use;
  log.debug("Leaving privToJwk().");
  return jwk;
}

async function pubToJwk(pem, desc, jwtAlg, use) {
  log.debug("Entering pubToJwk().");
  var key = await crypto.subtle.importKey('spki', pemToDer(pem),
      convParams(desc), true, ['verify']);
  var jwk = await crypto.subtle.exportKey('jwk', key);
  delete jwk.key_ops;
  delete jwk.ext;
  if (jwtAlg) jwk.alg = jwtAlg;
  if (use) jwk.use = use;
  log.debug("Leaving pubToJwk().");
  return jwk;
}

async function privToPem(jwkText, desc) {
  log.debug("Entering privToPem().");
  var jwk = typeof jwkText === 'string' ? JSON.parse(jwkText) : jwkText;
  var key = await crypto.subtle.importKey('jwk', stripJwkForImport(jwk),
      convParams(desc), true, ['sign']);
  log.debug("Leaving privToPem().");
  return derToPem(await crypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY');
}

async function pubToPem(jwkText, desc) {
  log.debug("Entering pubToPem().");
  var jwk = typeof jwkText === 'string' ? JSON.parse(jwkText) : jwkText;
  var key = await crypto.subtle.importKey('jwk', stripJwkForImport(jwk),
      convParams(desc), true, ['verify']);
  log.debug("Leaving pubToPem().");
  return derToPem(await crypto.subtle.exportKey('spki', key), 'PUBLIC KEY');
}

// Both halves of a pair as JWKs, which is what a JWK-set export needs.
async function keysToJwk(privPem, pubPem, desc, jwtAlg, use) {
  log.debug("Entering keysToJwk().");
  var priv = await privToJwk(privPem, desc, jwtAlg, use);
  var pub = await pubToJwk(pubPem, desc, jwtAlg, use);
  log.debug("Leaving keysToJwk().");
  return { publicKey: pub, privateKey: priv };
}

// Normalize whatever a field holds (PEM or JWK text) to PEM.
async function asPrivatePem(text, desc) {
  log.debug("Entering asPrivatePem().");
  if (isJwk(text)) {
    log.debug("Leaving asPrivatePem(). Converted from JWK.");
    return privToPem(text, desc);
  }
  log.debug("Leaving asPrivatePem().");
  return String(text || '').trim() + '\n';
}

async function asPublicPem(text, desc) {
  log.debug("Entering asPublicPem().");
  if (isJwk(text)) {
    log.debug("Leaving asPublicPem(). Converted from JWK.");
    return pubToPem(text, desc);
  }
  log.debug("Leaving asPublicPem().");
  return String(text || '').trim() + '\n';
}

// ---------------------------------------------------------------------------
// Importing a key pair for certificate work.
//
// Separate from convParams() above because the hash matters here: the imported
// private key's algorithm is what pkijs writes into the certificate's
// signatureAlgorithm, so importing an RSA key as SHA-256 and then asking for a
// SHA-512 signature produces a certificate whose declared algorithm and actual
// signature disagree — which openssl reports as a bad signature and no browser
// error message ever names.
// ---------------------------------------------------------------------------
function signingParams(desc) {
  log.debug("Entering signingParams().");
  if (desc.kind === 'rsa') {
    log.debug("Leaving signingParams().");
    return { name: desc.pss ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
             hash: desc.hash || 'SHA-256' };
  }
  if (desc.kind === 'okp') {
    log.debug("Leaving signingParams().");
    return { name: desc.name || 'Ed25519' };
  }
  log.debug("Leaving signingParams().");
  return { name: 'ECDSA', namedCurve: desc.curve || 'P-256' };
}

function importPrivateKey(privPem, desc, extractable) {
  log.debug("Entering importPrivateKey().");
  log.debug("Leaving importPrivateKey().");
  return crypto.subtle.importKey('pkcs8', pemToDer(privPem),
      signingParams(desc), extractable === true, ['sign']);
}

function importPublicKey(pubPem, desc) {
  log.debug("Entering importPublicKey().");
  log.debug("Leaving importPublicKey().");
  return crypto.subtle.importKey('spki', pemToDer(pubPem), signingParams(desc),
      true, ['verify']);
}

// What algorithm family a PEM public key holds, read from the SPKI itself
// rather than from whatever the caller remembers. A stored key pair carries its
// algorithm id, but a PASTED one does not — and importing an EC key as RSA
// fails with "Unsupported key", which names neither key nor algorithm.
async function describePublicPem(pubPem) {
  log.debug("Entering describePublicPem().");
  var candidates = [
    { kind: 'rsa', hash: 'SHA-256' },
    { kind: 'ec', curve: 'P-256' },
    { kind: 'ec', curve: 'P-384' },
    { kind: 'ec', curve: 'P-521' },
    { kind: 'okp', name: 'Ed25519' }
  ];
  for (var i = 0; i < candidates.length; i++) {
    try {
      var key = await importPublicKey(pubPem, candidates[i]);
      var jwk = await crypto.subtle.exportKey('jwk', key);
      var out = Object.assign({}, candidates[i]);
      if (out.kind === 'rsa' && jwk.n) {
        out.bits = Math.round(jose.b64uToBytes(jwk.n).length * 8);
      }
      log.debug("Leaving describePublicPem(). kind=" + out.kind);
      return out;
    } catch (e) {
      log.debug("describePublicPem(): not " + candidates[i].kind + '/' +
                (candidates[i].curve || candidates[i].name || '') + ': ' +
                e.message);
    }
  }
  log.debug("Leaving describePublicPem(). Unrecognised.");
  return null;
}

// ---------------------------------------------------------------------------
// Keystore formats
// ---------------------------------------------------------------------------
var PKCS12_CERT_OID = '1.2.840.113549.1.12.10.1.3';
var PKCS12_KEY_OID = '1.2.840.113549.1.12.10.1.2';
var OID_LOCAL_KEY_ID = '1.2.840.113549.1.9.21';
var OID_FRIENDLY_NAME = '1.2.840.113549.1.9.20';

var PBES2_OPTS = {
  contentEncryptionAlgorithm: { name: 'AES-CBC', length: 256 },
  hmacHashAlgorithm: 'SHA-256',
  iterationCount: 100000,
  pbkdf2HashAlgorithm: 'SHA-256'
};

function strBuf(s) {
  log.debug("Entering strBuf().");
  log.debug("Leaving strBuf().");
  return new TextEncoder().encode(s).buffer;
}

// Encrypt a PKCS#8 private key into an EncryptedPrivateKeyInfo (PBES2).
// Returns DER bytes.
async function encryptedPkcs8Der(privDer, password) {
  log.debug("Entering encryptedPkcs8Der().");
  var bag = new pkijs.PKCS8ShroudedKeyBag({
      parsedValue: pkijs.PrivateKeyInfo.fromBER(privDer) });
  var opts = Object.assign({ password: strBuf(password) }, PBES2_OPTS);
  await bag.makeInternalValues(opts);
  log.debug("Leaving encryptedPkcs8Der().");
  return new Uint8Array(bag.toSchema().toBER(false));
}

// A certificate, however the caller has it, as a pkijs.Certificate. Accepts a
// pkijs object, DER bytes, or PEM — which is what makes buildPkcs12() usable
// both by jwt_tools (which has just minted one) and by the PKI page (which has
// a chain in storage as PEM).
function asCertificate(cert) {
  log.debug("Entering asCertificate().");
  if (cert && typeof cert.toSchema === 'function') {
    log.debug("Leaving asCertificate(). Already a Certificate.");
    return cert;
  }
  if (typeof cert === 'string') {
    log.debug("Leaving asCertificate(). From PEM.");
    return pkijs.Certificate.fromBER(pemToDer(cert));
  }
  log.debug("Leaving asCertificate(). From DER.");
  return pkijs.Certificate.fromBER(cert);
}

// A PKCS#12 (.p12/.pfx) holding one private key and the certificates given —
// the leaf first, then as much of its chain as the caller wants to ship.
//
// `certs` is REQUIRED and is the whole reason this function is here rather than
// in jwt_tools.js: that page mints a self-signed certificate for the purpose,
// the PKI page has the real one, and a keystore built around the wrong
// certificate imports and then fails to authenticate anything.
async function buildPkcs12(options) {
  log.debug("Entering buildPkcs12().");
  var opts = options || {};
  var certs = (opts.certs || []).map(asCertificate);
  if (!certs.length) {
    log.debug("Leaving buildPkcs12(). No certificate.");
    throw new Error('PKCS#12 needs at least one certificate to wrap the ' +
                    'private key in.');
  }
  if (!opts.password) {
    log.debug("Leaving buildPkcs12(). No password.");
    throw new Error('PKCS#12 requires a password.');
  }
  var privDer = pemToDer(opts.privatePem);
  var keyId = crypto.getRandomValues(new Uint8Array(20));
  var friendly = opts.friendlyName || 'idptools';
  function attrs() {
    log.debug("Entering attrs().");
    log.debug("Leaving attrs().");
    return [
      new pkijs.Attribute({ type: OID_LOCAL_KEY_ID,
          values: [new asn1js.OctetString({ valueHex: keyId })] }),
      new pkijs.Attribute({ type: OID_FRIENDLY_NAME,
          values: [new asn1js.BmpString({ value: friendly })] })
    ];
  }
  var certBags = certs.map(function (cert, index) {
    // Only the leaf carries the localKeyId that pairs it with the private key;
    // a CA certificate in the same file that claims the same pairing makes
    // several tools pick the wrong one as the client certificate.
    return new pkijs.SafeBag({ bagId: PKCS12_CERT_OID,
        bagValue: new pkijs.CertBag({ parsedValue: cert }),
        bagAttributes: index === 0 ? attrs() : [] });
  });
  var keyBag = new pkijs.SafeBag({ bagId: PKCS12_KEY_OID,
      bagValue: new pkijs.PKCS8ShroudedKeyBag({
      parsedValue: pkijs.PrivateKeyInfo.fromBER(privDer) }),
      bagAttributes: attrs() });
  await keyBag.bagValue.makeInternalValues(Object.assign({
      password: strBuf(opts.password) }, PBES2_OPTS));

  var pfx = new pkijs.PFX({
    parsedValue: {
      integrityMode: 0, // password integrity
      authenticatedSafe: new pkijs.AuthenticatedSafe({
        parsedValue: {
          safeContents: [
            { privacyMode: 0,
             value: new pkijs.SafeContents({ safeBags: certBags }) },
            { privacyMode: 0,
             value: new pkijs.SafeContents({ safeBags: [keyBag] }) }
          ]
        }
      })
    }
  });
  await pfx.parsedValue.authenticatedSafe.makeInternalValues({ safeContents: [{
      }, {}] });
  await pfx.makeInternalValues({ password: strBuf(opts.password),
                               iterations: 100000,
                               pbkdf2HashAlgorithm: 'SHA-256',
                               hmacHashAlgorithm: 'SHA-256' });
  log.debug("Leaving buildPkcs12().");
  return new Uint8Array(pfx.toSchema().toBER(false));
}

// Password-protecting a string as a compact PBES2 JWE (RFC 7518 section 4.8)
// is jose_jwe.js's, where the rest of JWE lives — this module had the only
// copy until the Encryption / Decryption page needed the same thing for its
// own key-pair panes. Re-exported below, so every existing caller of
// key_material.pbes2JweEncrypt() is unchanged.
var pbes2JweEncrypt = jose.pbes2JweEncrypt;

// The keystore formats every pane offers, in the order they are offered.
var KEYSTORE_FORMATS = ['pem', 'der', 'jwk', 'pkcs12'];

function keystoreFormats() {
  log.debug("Entering keystoreFormats().");
  log.debug("Leaving keystoreFormats().");
  return KEYSTORE_FORMATS.slice();
}

// ---------------------------------------------------------------------------
// The export matrix.
//
// RETURNS the files rather than downloading them — {name, data, mime} per file,
// plus a one-line status for the pane — so every format can be produced and
// then read back by OpenSSL in a node test. A page hands the result to
// downloadFiles().
//
// options:
//   format      'pem' | 'der' | 'jwk' | 'pkcs12'
//   privatePem  PKCS#8 PEM (or JWK text — converted)
//   publicPem   SPKI PEM (or JWK text — converted)
//   desc        the key descriptor (kind/curve/bits)
//   password    optional; REQUIRED for pkcs12, and encrypts the private half
//               of the other three
//   baseName    the file name stem
//   certs       PEM/DER certificates — required for pkcs12, and when present
//               with 'pem' the chain is appended to the file
//   alg / use   JOSE members stamped into the JWKs, when exporting jwk
// ---------------------------------------------------------------------------
async function exportKeyPair(options) {
  log.debug("Entering exportKeyPair(). format=" + (options || {}).format);
  var opts = options || {};
  var desc = opts.desc || { kind: 'rsa', hash: 'SHA-256' };
  var base = opts.baseName || 'key-pair';
  var format = opts.format || 'pem';
  if (KEYSTORE_FORMATS.indexOf(format) < 0) {
    log.debug("Leaving exportKeyPair(). Unknown format.");
    throw new Error('Unknown keystore format: ' + format);
  }
  if (desc.kind === 'hmac') {
    // A symmetric secret is not a pair, and only a JWK can carry it.
    if (format !== 'jwk') {
      log.debug("Leaving exportKeyPair(). HMAC is JWK-only.");
      throw new Error('HMAC is a symmetric secret — only JWK export ' +
                      'applies. Choose JWK.');
    }
    var secret = isJwk(opts.privatePem)
      ? (JSON.parse(opts.privatePem).k || '')
      : String(opts.privatePem || '').trim();
    if (!secret) {
      log.debug("Leaving exportKeyPair(). No secret.");
      throw new Error('No secret to export.');
    }
    var octText = JSON.stringify({ kty: 'oct', k: secret, alg: opts.alg,
                                  use: opts.use }, null, 2);
    if (opts.password) {
      log.debug("Leaving exportKeyPair(). Encrypted oct JWK.");
      return { files: [{ name: base + '.jwe',
                        data: await pbes2JweEncrypt(octText, opts.password),
                        mime: 'application/jose' }],
               status: 'Downloaded PBES2-encrypted HMAC secret (.jwe).' };
    }
    log.debug("Leaving exportKeyPair(). oct JWK.");
    return { files: [{ name: base + '.jwk.json', data: octText,
                      mime: 'application/jwk+json' }],
             status: 'Downloaded HMAC secret as JWK.' };
  }

  if (!String(opts.privatePem || '').trim() ||
      !String(opts.publicPem || '').trim()) {
    log.debug("Leaving exportKeyPair(). No key pair.");
    throw new Error('No key pair to export. Generate or paste one first.');
  }
  var privPem = await asPrivatePem(opts.privatePem, desc);
  var pubPem = await asPublicPem(opts.publicPem, desc);

  if (format === 'pkcs12') {
    // Ed25519 used to be refused here, and the refusal was misattributed:
    // PKCS#12 carries an Ed25519 key perfectly well (OpenSSL reads both bags —
    // tests/pki_key_formats.js checks exactly that). What failed was building
    // the self-signed CERTIFICATE the keystore has to wrap it in, because
    // pkijs cannot import an Ed25519 public key. client/src/x509.js does that
    // by hand now, so the format works and the refusal has gone.
    if (!opts.password) {
      log.debug("Leaving exportKeyPair(). PKCS#12 needs a password.");
      throw new Error('PKCS#12 requires a password. Enter one in the ' +
                      'password field.');
    }
    var p12 = await buildPkcs12({ privatePem: privPem, certs: opts.certs || [],
                                password: opts.password,
                                friendlyName: opts.friendlyName || base });
    log.debug("Leaving exportKeyPair(). PKCS#12.");
    return { files: [{ name: base + '.p12', data: p12,
                      mime: 'application/x-pkcs12' }],
             status: 'Downloaded password-protected PKCS#12 (.p12) with ' +
                 (opts.certs || []).length + ' certificate(s).' };
  }

  if (format === 'pem') {
    var privBlock;
    if (opts.password) {
      privBlock = derToPem(await encryptedPkcs8Der(pemToDer(privPem),
          opts.password), 'ENCRYPTED PRIVATE KEY');
    } else {
      privBlock = privPem.trim() + '\n';
    }
    var text = privBlock + '\n' + pubPem.trim() + '\n';
    (opts.certs || []).forEach(function (cert) {
      var isPem = typeof cert === 'string' &&
          cert.indexOf('-----BEGIN') >= 0;
      text += '\n' + (isPem ? cert.trim()
        : derToPem(cert, 'CERTIFICATE').trim()) + '\n';
    });
    log.debug("Leaving exportKeyPair(). PEM.");
    return { files: [{ name: base + '.pem', data: text,
                      mime: 'application/x-pem-file' }],
             status: opts.password
               ? 'Downloaded PEM (encrypted private key + public key).'
               : 'Downloaded PEM (private + public key).' };
  }

  if (format === 'der') {
    var privDer = opts.password
      ? await encryptedPkcs8Der(pemToDer(privPem), opts.password)
      : new Uint8Array(pemToDer(privPem));
    log.debug("Leaving exportKeyPair(). DER.");
    return { files: [
               { name: base + '-private.der', data: privDer,
                mime: 'application/pkcs8' },
               { name: base + '-public.der',
                data: new Uint8Array(pemToDer(pubPem)),
                mime: 'application/octet-stream' }
             ],
             status: opts.password
               ? 'Downloaded DER (encrypted private + public), two files.'
               : 'Downloaded DER (private + public), two files.' };
  }

  // jwk
  var pair = await keysToJwk(privPem, pubPem, desc, opts.alg, opts.use);
  var jwksText = JSON.stringify({ keys: [pair.publicKey, pair.privateKey] },
      null, 2);
  if (opts.password) {
    log.debug("Leaving exportKeyPair(). Encrypted JWK set.");
    return { files: [{ name: base + '.jwe',
                      data: await pbes2JweEncrypt(jwksText, opts.password),
                      mime: 'application/jose' }],
             status: 'Downloaded PBES2-encrypted JWK set (.jwe).' };
  }
  log.debug("Leaving exportKeyPair(). JWK set.");
  return { files: [{ name: base + '.jwk.json', data: jwksText,
                    mime: 'application/jwk+json' }],
           status: 'Downloaded JWK set (public + private).' };
}

// ---------------------------------------------------------------------------
// The browser half: hand a file to the user.
// ---------------------------------------------------------------------------
function triggerDownload(filename, data, mime) {
  log.debug("Entering triggerDownload().");
  var blob = new Blob([data], { type: mime || 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  log.debug("Leaving triggerDownload().");
}

// Download everything exportKeyPair() produced, and return its status line.
function downloadFiles(result) {
  log.debug("Entering downloadFiles().");
  (result.files || []).forEach(function (file) {
    triggerDownload(file.name, file.data, file.mime);
  });
  log.debug("Leaving downloadFiles().");
  return result.status || '';
}

module.exports = {
  // algorithms
  KEY_ALGS: KEY_ALGS,
  keyAlgIds: keyAlgIds,
  keyAlg: keyAlg,
  certDescriptor: certDescriptor,
  signingParams: signingParams,
  convParams: convParams,
  // generation
  generateKeyPair: generateKeyPair,
  generateSecret: generateSecret,
  // formats
  isJwk: isJwk,
  stripJwkForImport: stripJwkForImport,
  privToJwk: privToJwk,
  pubToJwk: pubToJwk,
  privToPem: privToPem,
  pubToPem: pubToPem,
  keysToJwk: keysToJwk,
  asPrivatePem: asPrivatePem,
  asPublicPem: asPublicPem,
  describePublicPem: describePublicPem,
  // key import for certificate work
  importPrivateKey: importPrivateKey,
  importPublicKey: importPublicKey,
  asCertificate: asCertificate,
  // keystores
  KEYSTORE_FORMATS: KEYSTORE_FORMATS,
  keystoreFormats: keystoreFormats,
  encryptedPkcs8Der: encryptedPkcs8Der,
  buildPkcs12: buildPkcs12,
  pbes2JweEncrypt: pbes2JweEncrypt,
  exportKeyPair: exportKeyPair,
  // the browser half
  triggerDownload: triggerDownload,
  downloadFiles: downloadFiles
};
