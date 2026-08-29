'use strict';
//
// File: tests/sts_saml_encryption.js
//
// ===========================================================================
// THE MOCK STS'S SAML 2.0 ENCRYPTION, END TO END, OVER HTTP, WITH NO BROWSER.
//
// It sits beside `sts_saml11.js`, `sts_dpop.js` and `vc_did.js` — the tests
// that drive that service DIRECTLY —
// and it is named `sts_*` for their reason: the mock is the thing under test
// and nothing in the debugger is exercised here at all.
//
// **IT IS NOT `saml_encrypted_sso.js`.** That one is Selenium: it drives the
// DEBUGGER'S SAML service provider against Keycloak, loads metadata through the
// page, and decrypts the assertion in the browser with `saml_response.js`. It
// proves the debugger can consume an encrypted assertion from a real identity
// provider. This file proves the MOCK can produce one — and, far more
// importantly, that it REFUSES the things it should, which a browser round trip
// cannot easily reach. Neither replaces the other.
//
// **IT WRITES ITS OWN SERVICE PROVIDER**, generating an RSA key pair per run and
// giving the mock only the certificate. That is `sts_dpop.js`'s rule and it
// matters more here than anywhere: if both ends of the encryption came from one
// implementation, a shared misunderstanding about the ciphertext layout — where
// the IV lives, whether the GCM tag is appended — would pass this test and
// interoperate with nobody. Everything below decrypts with node's own `crypto`,
// NOT with the mock's `decryptElement()`, for exactly that reason.
//
// ---------------------------------------------------------------------------
// WHAT IT IS FOR, WHICH IS NOT "ENCRYPTION WORKS".
//
// An identity provider that hands a working service provider an
// EncryptedAssertion looks finished and can be worth very little. Five things
// this feature most easily gets wrong are invisible on the happy path, and each
// has a check below:
//
//   1. THE ORDER. The assertion must be SIGNED and THEN encrypted, so the
//      signature is inside the ciphertext. Encrypting first and signing the
//      ciphertext produces a document that verifies while nobody can say what
//      was signed. Asserted by decrypting and finding the Signature INSIDE.
//   2. THE CIPHERTEXT LAYOUT, which differs between the two families: GCM is
//      iv(12)||ct||tag(16) and CBC is iv(16)||ct with PKCS#7 padding. Both are
//      decrypted here by hand, so a mock that prepended the wrong number of
//      bytes fails even though its own decryptor would agree with it.
//   3. THE NAMESPACE OF A DECRYPTED FRAGMENT. An <saml:EncryptedID> whose
//      plaintext relies on an ancestor for the `saml:` prefix is a
//      NamespaceError once it is decrypted standalone — the document has no
//      ancestor any more. This was a REAL defect in the mock, found on
//      2026-08-27 by decrypting its own output, and check 9 is the regression.
//   4. THE UNENCRYPTED FALLBACK. With no recipient certificate the mock sends
//      the assertion IN CLEAR rather than refusing to issue. That is a
//      deliberate design decision and it is exactly the kind of decision that
//      rots into a silent hole, so it is pinned here: encryption ON and no
//      certificate must produce a plaintext <saml:Assertion> and no
//      <saml:EncryptedAssertion>.
//   5. THE INBOUND REFUSALS. A LogoutRequest carrying an EncryptedID this
//      service cannot read must be REFUSED, not treated as a logout for
//      nobody — which would report Success while the mock had no idea whose
//      session it was.
//
// ---------------------------------------------------------------------------
// IT RESTORES EVERYTHING IT CHANGES, through `/admin-api/config/reset` rather
// than by writing the old value back — a `set` leaves `source: override` behind
// for the mock's own suite to trip over on the next run against the same
// container.
// The per-application attributes it writes go on entries named after this
// process, so two runs cannot read each other's.
//
// Needs the STS mock and nothing else — no browser, no Keycloak.
// ===========================================================================

const assert = require('assert');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');
const { DOMParser } = require('@xmldom/xmldom');
const { usernameFor, runStamp } = require('./random_username.js');
var appconfig = require(process.env.CONFIG_FILE);
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts_saml_encryption',
                                  level: appconfig.LOG_LEVEL || 'info' });
log.info('Log initialized. logLevel=' + log.level());

// The base URL, in the order the other STS tests take theirs.
const BASE = (process.env.SAML2_IDP_URL ||
              process.env.OID4VCI_ISSUER_URL ||
              (process.env.WSTRUST_STS_URL || '').replace(/\/sts\/?$/, '') ||
              'https://localhost:8081').replace(/\/$/, '');

const STAMP = runStamp();
const USER = usernameFor('saml2enc');

// Four service providers, because the interesting states are combinations and
// one entry cannot hold two of them at once. Each carries this run's stamp: the
// mock never deletes a directory entry, so two runs against one instance would
// otherwise read each other's configuration.
const SP_GCM = 'https://enc-gcm-' + STAMP + '.example.com';
const SP_CBC = 'https://enc-cbc-' + STAMP + '.example.com';
const SP_NOKEY = 'https://enc-nokey-' + STAMP + '.example.com';
const SP_LOGOUT = 'https://enc-logout-' + STAMP + '.example.com';

const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

let cookie = '';
let passed = 0;
const failures = [];

function check(what, condition, detail) {
  if (condition) {
    passed++;
    log.info('  ✓ ' + what + (detail ? '  — ' + detail : ''));
  } else {
    failures.push(what + (detail ? '  — ' + detail : ''));
    log.error('  ✗ ' + what + (detail ? '  — ' + detail : ''));
  }
}

function request(method, path, body, headers) {
  return new Promise(function (resolve, reject) {
    const url = new URL(path.indexOf('http') === 0 ? path : BASE + path);
    const opts = { method: method, headers: Object.assign({}, headers || {}) };
    if (cookie) opts.headers.Cookie = cookie;
    if (body) opts.headers['Content-Length'] = Buffer.byteLength(body);
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, opts, function (res) {
      let data = '';
      res.on('data', function (c) { data += c; });
      res.on('end', function () {
        const set = res.headers['set-cookie'];
        if (set) {
          cookie = set.map(function (c) { return c.split(';')[0]; }).join('; ');
        }
        resolve({ status: res.statusCode, headers: res.headers, body: data });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const JSON_H = { 'Content-Type': 'application/json' };

function form(obj) {
  return Object.keys(obj).map(function (k) {
    return encodeURIComponent(k) + '=' + encodeURIComponent(obj[k]);
  }).join('&');
}

function api(path, payload) {
  return request('POST', '/admin-api' + path, JSON.stringify(payload), JSON_H)
    .then(function (r) {
      let json = {};
      try { json = JSON.parse(r.body); } catch (e) {
        // Not JSON — the status and the raw body are what a caller can act on,
        // and a parse failure here is itself the interesting fact.
      }
      return { status: r.status, json: json };
    });
}

// ---------------------------------------------------------------------------
// THE SERVICE PROVIDER'S OWN KEY PAIR, generated per run. The mock is given the
// CERTIFICATE and never the private key, which is what makes the decryptions
// below mean anything.
//
// A self-signed certificate built with node's own `crypto` and an X.509
// structure assembled by hand — this file deliberately imports nothing from the
// mock, so it cannot borrow node-forge's certificate builder either.
// ---------------------------------------------------------------------------
function spKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { spkiDer: publicKey, privateKeyPem: privateKey };
}

// A minimal DER writer, enough for a self-signed certificate. Hand-rolled for
// the reason above and kept to the few structures a certificate needs.
function der(tag, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  let len;
  if (body.length < 0x80) {
    len = Buffer.from([body.length]);
  } else {
    const n = [];
    let v = body.length;
    while (v > 0) { n.unshift(v & 0xff); v >>= 8; }
    len = Buffer.from([0x80 | n.length].concat(n));
  }
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
const seq = function () { return der(0x30, Buffer.concat(Array.from(arguments))); };
const set = function (b) { return der(0x31, b); };
const oid = function (bytes) { return der(0x06, Buffer.from(bytes)); };
const nul = Buffer.from([0x05, 0x00]);

function utf8(s) { return der(0x0c, Buffer.from(s, 'utf8')); }
function utcTime(d) {
  const p = function (n) { return String(n).padStart(2, '0'); };
  return der(0x17, Buffer.from(
    p(d.getUTCFullYear() % 100) + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) +
    p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + 'Z', 'ascii'));
}

// A self-signed RSA/SHA-256 certificate carrying `spkiDer`.
function selfSignedCertificate(keys, commonName) {
  const SHA256_RSA = oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
  const CN = oid([0x55, 0x04, 0x03]);
  const algorithm = seq(SHA256_RSA, nul);
  const name = seq(set(seq(CN, utf8(commonName))));
  const validity = seq(utcTime(new Date(Date.now() - 86400000)),
                       utcTime(new Date(Date.now() + 86400000)));
  const tbs = seq(
    der(0xa0, der(0x02, Buffer.from([0x02]))),   // version v3
    der(0x02, Buffer.from([0x01])),              // serial
    algorithm, name, validity, name,
    keys.spkiDer
  );
  const signature = crypto.sign('sha256', tbs,
    crypto.createPrivateKey(keys.privateKeyPem));
  const cert = seq(tbs, algorithm, der(0x03, Buffer.concat([Buffer.from([0x00]), signature])));
  return cert.toString('base64');
}

// ---------------------------------------------------------------------------
// DECRYPT AN <EncryptedAssertion> / <EncryptedID> WITH NODE'S OWN CRYPTO.
//
// This is the half that must NOT come from the mock. The layouts are XML
// Encryption section 5.2's and are written out rather than inferred:
//
//   GCM  iv(12) || ciphertext || tag(16)
//   CBC  iv(16) || ciphertext, PKCS#7
// ---------------------------------------------------------------------------
const CIPHERS = {
  'http://www.w3.org/2009/xmlenc11#aes256-gcm':
    { node: 'aes-256-gcm', keyBytes: 32, ivBytes: 12, tagBytes: 16 },
  'http://www.w3.org/2009/xmlenc11#aes128-gcm':
    { node: 'aes-128-gcm', keyBytes: 16, ivBytes: 12, tagBytes: 16 },
  'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
    { node: 'aes-256-cbc', keyBytes: 32, ivBytes: 16, tagBytes: 0 },
  'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
    { node: 'aes-128-cbc', keyBytes: 16, ivBytes: 16, tagBytes: 0 }
};
const TRANSPORTS = {
  'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
    { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, hash: 'sha1' },
  // RSA-1_5 IS UNWRAPPED BY HAND, and that is node's decision rather than a
  // preference here: `crypto.privateDecrypt` with `RSA_PKCS1_PADDING` answers
  // "RSA_PKCS1_PADDING is no longer supported for private decryption" on a
  // modern node, because implementing that operation is what makes a service
  // vulnerable to Bleichenbacher's attack. Node is right and the mock still has
  // to be tested — a great many deployed service providers accept nothing else,
  // which is the whole reason `saml2.keyTransportAlgorithm` offers it.
  //
  // So the padding is removed with BigInt arithmetic below. That is not a
  // workaround so much as the strongest form of this file's own rule: the
  // unwrap here shares no code with the mock, and now shares no LIBRARY with it
  // either.
  'http://www.w3.org/2001/04/xmlenc#rsa-1_5': { raw15: true }
};

// Textbook RSA followed by a PKCS#1 v1.5 type-2 unpad. `m = c^d mod n`, taking
// `n` and `d` off the private key as a JWK so no key parsing is written here.
//
// IT IS DELIBERATELY NOT CONSTANT-TIME and does not need to be: this is a test
// holding both halves of a key pair it generated a moment ago, and there is no
// attacker to leak a timing signal to. Never copy it into anything that
// decrypts somebody else's ciphertext.
function unwrapPkcs1v15(ciphertext, privateKeyPem) {
  const jwk = crypto.createPrivateKey(privateKeyPem).export({ format: 'jwk' });
  const big = function (b64u) {
    return BigInt('0x' + Buffer.from(b64u, 'base64url').toString('hex'));
  };
  const n = big(jwk.n);
  const d = big(jwk.d);
  let c = BigInt('0x' + ciphertext.toString('hex'));
  // Square-and-multiply; a 2048-bit exponent is a few milliseconds.
  let m = 1n;
  c = c % n;
  let e = d;
  while (e > 0n) {
    if (e & 1n) m = (m * c) % n;
    c = (c * c) % n;
    e >>= 1n;
  }
  let hex = m.toString(16);
  // The modulus is 256 bytes and the leading 0x00 of a type-2 block is not
  // representable in the integer, so the buffer is left-padded back to 255.
  if (hex.length % 2) hex = '0' + hex;
  const block = Buffer.from(hex, 'hex');
  // EB = 0x00 || 0x02 || PS(>=8, non-zero) || 0x00 || M, and the leading zero
  // is gone, so this block starts at 0x02.
  if (block[0] !== 0x02) {
    throw new Error('not a PKCS#1 v1.5 type 2 block (starts 0x' +
                    block[0].toString(16) + ')');
  }
  const sep = block.indexOf(0x00, 1);
  if (sep < 9) {
    throw new Error('the PKCS#1 v1.5 padding is too short');
  }
  return block.subarray(sep + 1);
}

function textIn(node, local) {
  const els = node.getElementsByTagNameNS('*', local);
  return els.length ? (els[0].textContent || '').replace(/\s+/g, '') : '';
}

function decryptAsServiceProvider(xml, privateKeyPem) {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const data = doc.getElementsByTagNameNS('*', 'EncryptedData')[0];
  if (!data) return { ok: false, why: 'no EncryptedData' };
  const methods = data.getElementsByTagNameNS('*', 'EncryptionMethod');
  const cipher = CIPHERS[methods[0] ? methods[0].getAttribute('Algorithm') : ''];
  if (!cipher) return { ok: false, why: 'unknown block cipher' };
  const keyEl = data.getElementsByTagNameNS('*', 'EncryptedKey')[0];
  if (!keyEl) return { ok: false, why: 'no EncryptedKey' };
  const keyMethod = keyEl.getElementsByTagNameNS('*', 'EncryptionMethod')[0];
  const transport = TRANSPORTS[keyMethod ? keyMethod.getAttribute('Algorithm') : ''];
  if (!transport) return { ok: false, why: 'unknown key transport' };

  const wrapped = Buffer.from(textIn(keyEl, 'CipherValue'), 'base64');
  // The data's CipherValue is the one that is NOT inside the EncryptedKey.
  const all = data.getElementsByTagNameNS('*', 'CipherValue');
  let bodyB64 = '';
  for (let n = 0; n < all.length; n++) {
    if (!keyEl.contains || !keyEl.contains(all[n])) {
      bodyB64 = (all[n].textContent || '').replace(/\s+/g, '');
    }
  }
  const raw = Buffer.from(bodyB64, 'base64');

  let key;
  try {
    key = transport.raw15
      ? unwrapPkcs1v15(wrapped, privateKeyPem)
      : crypto.privateDecrypt(
          { key: crypto.createPrivateKey(privateKeyPem), padding: transport.padding,
            oaepHash: transport.hash }, wrapped);
  } catch (e) {
    return { ok: false, why: 'the key would not unwrap: ' + e.message };
  }
  if (key.length !== cipher.keyBytes) {
    return { ok: false, why: 'the unwrapped key is ' + key.length + ' bytes, expected ' +
             cipher.keyBytes };
  }
  try {
    const iv = raw.subarray(0, cipher.ivBytes);
    const d = crypto.createDecipheriv(cipher.node, key, iv);
    let body;
    if (cipher.tagBytes) {
      d.setAuthTag(raw.subarray(raw.length - cipher.tagBytes));
      body = raw.subarray(cipher.ivBytes, raw.length - cipher.tagBytes);
    } else {
      body = raw.subarray(cipher.ivBytes);
    }
    const plain = Buffer.concat([d.update(body), d.final()]).toString('utf8');
    return { ok: true, xml: plain,
             algorithm: methods[0].getAttribute('Algorithm'),
             keyTransport: keyMethod.getAttribute('Algorithm') };
  } catch (e) {
    return { ok: false, why: 'the data would not decrypt: ' + e.message };
  }
}

// Encrypt a fragment TO the mock, the way a service provider would, using the
// key it publishes in its metadata. Written here rather than borrowed for the
// same reason the decryptor is.
function encryptAsServiceProvider(xml, certB64) {
  const pem = '-----BEGIN CERTIFICATE-----\n' +
    certB64.replace(/\s+/g, '').match(/.{1,64}/g).join('\n') +
    '\n-----END CERTIFICATE-----\n';
  const publicKey = new crypto.X509Certificate(pem).publicKey;
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([c.update(Buffer.from(xml, 'utf8')), c.final()]);
  const packed = Buffer.concat([iv, body, c.getAuthTag()]).toString('base64');
  const wrapped = crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
    key).toString('base64');
  return '<saml:EncryptedID xmlns:saml="' + NS_SAML + '">' +
    '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"' +
    ' Type="http://www.w3.org/2001/04/xmlenc#Element">' +
    '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>' +
    '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>' +
    '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">' +
    '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
    '</xenc:EncryptionMethod>' +
    '<xenc:CipherData><xenc:CipherValue>' + wrapped + '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedKey></ds:KeyInfo>' +
    '<xenc:CipherData><xenc:CipherValue>' + packed + '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData></saml:EncryptedID>';
}

// --- the flow ---------------------------------------------------------------
function deflateB64(xml) {
  return require('zlib').deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
}

function authnRequest(sp, acs) {
  return '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '"' +
    ' ID="_' + crypto.randomBytes(8).toString('hex') + '" Version="2.0"' +
    ' IssueInstant="' + new Date().toISOString() + '"' +
    ' Destination="' + BASE + '/saml2/sso"' +
    ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"' +
    ' AssertionConsumerServiceURL="' + acs + '">' +
    '<saml:Issuer>' + sp + '</saml:Issuer></samlp:AuthnRequest>';
}

// Sign in and come back with whatever the service provider was sent. The cookie
// is cleared first, so each flow is a fresh session and one service provider's
// result cannot be another's still-live session.
async function signInTo(sp, user) {
  cookie = '';
  let r = await request('GET', '/saml2/sso?SAMLRequest=' +
                        encodeURIComponent(deflateB64(authnRequest(sp, sp + '/acs'))));
  if (r.status !== 302 && r.status !== 303) {
    return { error: 'the SSO endpoint answered ' + r.status + ' rather than a redirect' };
  }
  r = await request('GET', r.headers.location);
  const id = (r.body.match(/name="authn_id"\s+value="([^"]+)"/) || [])[1];
  if (!id) return { error: 'no authn_id on the sign-in screen' };
  r = await request('POST', '/authn/login', form({ authn_id: id, username: user }), FORM);
  if (!r.headers.location) return { error: 'no redirect back after signing in' };
  r = await request('GET', r.headers.location);
  const b64 = (r.body.match(/name="SAMLResponse"\s+value="([^"]+)"/) || [])[1];
  if (!b64) return { error: 'no SAMLResponse in the posted form' };
  return { xml: Buffer.from(b64, 'base64').toString('utf8') };
}

const configured = [];
function setSetting(key, value) {
  if (configured.indexOf(key) < 0) configured.push(key);
  return api('/config/set', { key: key, value: String(value) });
}

async function restoreSettings() {
  for (const key of configured) {
    await api('/config/reset', { key: key });
  }
}

function provision(identifier, fields) {
  return api('/applications/create',
             { identifier: identifier, protocols: ['saml2'], fields: fields });
}

function setField(identifier, attribute, value) {
  return api('/applications/set',
             { application: identifier, attribute: attribute, value: String(value) });
}

async function main() {
  log.info('The mock STS is at ' + BASE + '.');
  const reachable = await request('GET', '/saml2/metadata').catch(function () { return null; });
  if (!reachable || reachable.status !== 200) {
    // Skips rather than fails, the way sts_dpop.js and sts_saml11.js do: an
    // environment with no STS is one this job has nothing to say about, and a
    // job that failed there would report a protocol family as broken.
    log.warn('No SAML 2.0 identity provider at ' + BASE + '. Set WSTRUST_STS_URL or ' +
             'OID4VCI_ISSUER_URL, or start the sts service. Skipping.');
    return 0;
  }

  const keys = spKeyPair();
  const certB64 = selfSignedCertificate(keys, 'sp.example.com');

  log.info('THE ROUND TRIP: an assertion encrypted to a key this service never held');
  await provision(SP_GCM, {
    saml2EncryptAssertion: 'true',
    samlEncryptionCertificate: certB64
  });
  let out = await signInTo(SP_GCM, USER);
  check('a sign-in for an encrypting service provider produced a Response',
        !out.error, out.error || 'ok');
  if (!out.error) {
    check('the Response carries <saml:EncryptedAssertion>',
          /<saml:EncryptedAssertion/.test(out.xml));
    check('and NO plaintext <saml:Assertion> beside it — an identity provider that ' +
          'sent both would leak everything it just encrypted',
          !/<saml:Assertion[\s>]/.test(out.xml));
    const block = (/<saml:EncryptedAssertion[\s\S]*?<\/saml:EncryptedAssertion>/
                   .exec(out.xml) || [])[0];
    const got = block ? decryptAsServiceProvider(block, keys.privateKeyPem) : { ok: false };
    check('THE SERVICE PROVIDER CAN DECRYPT IT with its own private key, which this ' +
          'identity provider has never seen', got.ok, got.ok ? got.algorithm : got.why);
    if (got.ok) {
      const inner = got.xml.trim();
      check('the plaintext IS a <saml:Assertion>', /^<saml:Assertion[\s>]/.test(inner));
      check('SIGNED FIRST AND THEN ENCRYPTED — the signature is INSIDE the ciphertext, ' +
            'so what the service provider verifies is what it decrypted',
            /<Signature|<ds:Signature/.test(inner));
      check('it names the person who signed in',
            inner.indexOf('>' + USER + '<') >= 0);
      check('and the audience is this service provider',
            inner.indexOf('>' + SP_GCM + '<') >= 0);
      check('the default algorithm is AES-256-GCM',
            got.algorithm === 'http://www.w3.org/2009/xmlenc11#aes256-gcm', got.algorithm);
      check('with the key wrapped by RSA-OAEP-MGF1P',
            got.keyTransport === 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
            got.keyTransport);
    }
  }

  log.info('EVERY ALGORITHM PAIR, decrypted by hand — the layouts differ and a mock ' +
           'that prepended the wrong number of IV bytes would still agree with itself');
  await provision(SP_CBC, {
    saml2EncryptAssertion: 'true',
    samlEncryptionCertificate: certB64
  });
  for (const algorithm of ['aes256-gcm', 'aes128-gcm', 'aes256-cbc', 'aes128-cbc']) {
    for (const transport of ['rsa-oaep-mgf1p', 'rsa-1_5']) {
      await setField(SP_CBC, 'saml2EncryptionAlgorithm', algorithm);
      await setField(SP_CBC, 'saml2KeyTransportAlgorithm', transport);
      const r = await signInTo(SP_CBC, USER);
      const b = r.error ? null
        : (/<saml:EncryptedAssertion[\s\S]*?<\/saml:EncryptedAssertion>/.exec(r.xml) || [])[0];
      const d = b ? decryptAsServiceProvider(b, keys.privateKeyPem) : { ok: false, why: 'no block' };
      check(algorithm + ' + ' + transport + ' round-trips to a signed assertion',
            d.ok && /^<saml:Assertion[\s>]/.test(d.xml.trim()) &&
              /<Signature|<ds:Signature/.test(d.xml),
            d.ok ? 'decrypted' : d.why);
    }
  }

  log.info('THE UNENCRYPTED FALLBACK, which is a decision and not an accident');
  await provision(SP_NOKEY, { saml2EncryptAssertion: 'true' });
  out = await signInTo(SP_NOKEY, USER);
  check('a service provider asked for encryption with NO certificate anywhere is still ' +
        'issued an assertion — a mock that refused would be useless exactly when ' +
        'somebody is setting this up', !out.error, out.error || 'ok');
  if (!out.error) {
    check('and it is sent IN CLEAR rather than half-encrypted',
          /<saml:Assertion[\s>]/.test(out.xml) && !/<saml:EncryptedAssertion/.test(out.xml));
  }

  log.info('THE METADATA, which is where a service provider learns the key to encrypt to');
  const md = await request('GET', '/saml2/metadata');
  check('the identity provider metadata publishes a use="encryption" KeyDescriptor — ' +
        'without it the inbound half of this feature is unreachable',
        /KeyDescriptor use="encryption"/.test(md.body));
  check('and still publishes its signing key',
        /KeyDescriptor use="signing"/.test(md.body));
  const idpCert = (md.body.match(
    /use="encryption"[\s\S]*?<ds:X509Certificate>([^<]+)</) || [])[1];
  check('the encryption descriptor carries a certificate', !!idpCert);

  log.info('THE INBOUND HALF: an EncryptedID this service provider sends, and three ' +
           'that must be refused');
  await provision(SP_LOGOUT, {});
  const logoutRequest = function (subject) {
    const nameId = '<saml:NameID xmlns:saml="' + NS_SAML + '">' + subject + '</saml:NameID>';
    return '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '"' +
      ' ID="_' + crypto.randomBytes(8).toString('hex') + '" Version="2.0"' +
      ' IssueInstant="' + new Date().toISOString() + '">' +
      '<saml:Issuer>' + SP_LOGOUT + '</saml:Issuer>' +
      encryptAsServiceProvider(nameId, idpCert) + '</samlp:LogoutRequest>';
  };
  const sendLogout = function (xml) {
    return request('GET', '/saml2/slo?SAMLRequest=' + encodeURIComponent(deflateB64(xml)));
  };

  if (idpCert) {
    let r = await sendLogout(logoutRequest(USER));
    check('a LogoutRequest whose NameID is an <saml:EncryptedID> encrypted to the ' +
          'published key is ACCEPTED', r.status === 302 || r.status === 303 || r.status === 200,
          'status ' + r.status);
    check('and it is not reported as undecryptable',
          !/could not be decrypted/i.test(r.body));

    // The tag must catch an edit. This is the assertion that says AES-GCM is
    // being used as an AEAD rather than as a stream cipher with a decorative
    // tag appended.
    let bad = logoutRequest(USER);
    const i = bad.lastIndexOf('<xenc:CipherValue>') + '<xenc:CipherValue>'.length;
    const j = bad.indexOf('</xenc:CipherValue>', i);
    const b = bad.slice(i, j);
    bad = bad.slice(0, i) + b.slice(0, -6) + (b.slice(-6, -5) === 'A' ? 'B' : 'A') +
          b.slice(-4) + bad.slice(j);
    r = await sendLogout(bad);
    check('an ALTERED ciphertext is REFUSED — the GCM tag is verified rather than ignored',
          r.status === 400, 'status ' + r.status);

    // Encrypted to somebody else's key. The mock must not treat an
    // undecryptable subject as "a logout for nobody" and answer Success.
    const other = selfSignedCertificate(spKeyPair(), 'someone-else');
    const wrongKey = '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' +
      NS_SAML + '" ID="_x' + STAMP + '" Version="2.0" IssueInstant="' +
      new Date().toISOString() + '"><saml:Issuer>' + SP_LOGOUT + '</saml:Issuer>' +
      encryptAsServiceProvider('<saml:NameID xmlns:saml="' + NS_SAML + '">' + USER +
                               '</saml:NameID>', other) + '</samlp:LogoutRequest>';
    r = await sendLogout(wrongKey);
    check('an EncryptedID encrypted to a DIFFERENT key is REFUSED rather than treated ' +
          'as a logout for nobody, which would report Success while this service had no ' +
          'idea whose session it was', r.status === 400, 'status ' + r.status);
  }

  log.info('THE OUTBOUND EncryptedID, and the namespace trap that was a real defect');
  await setField(SP_LOGOUT, 'saml2EncryptLogoutNameId', 'true');
  await setField(SP_LOGOUT, 'samlEncryptionCertificate', certB64);
  out = await signInTo(SP_LOGOUT, USER);
  check('the service provider is signed in, so there is a session to log out of',
        !out.error, out.error || 'ok');
  let slo = await request('GET', '/saml2/slo');
  const link = (slo.body.match(/SAMLRequest=([^"&]+)/) || [])[1];
  check('identity-provider-initiated logout offers a LogoutRequest for it', !!link);
  if (link) {
    let xml = Buffer.from(decodeURIComponent(link), 'base64');
    try { xml = require('zlib').inflateRawSync(xml).toString('utf8'); }
    catch (e) { xml = xml.toString('utf8'); }
    check('the LogoutRequest carries <saml:EncryptedID>', /<saml:EncryptedID/.test(xml));
    check('and no plaintext <saml:NameID> beside it', !/<saml:NameID/.test(xml));
    const block = (/<saml:EncryptedID[\s\S]*?<\/saml:EncryptedID>/.exec(xml) || [])[0];
    const got = block ? decryptAsServiceProvider(block, keys.privateKeyPem) : { ok: false };
    check('the service provider can decrypt it', got.ok, got.ok ? 'ok' : got.why);
    if (got.ok) {
      // THE REGRESSION. A decrypted fragment has no ancestor to inherit
      // `saml:` from, so an identity provider that emitted the NameID without
      // its own xmlns declaration produces something that will not parse
      // standalone — which is what this service did until 2026-08-27.
      //
      // THE PARSE IS WRAPPED because xmldom THROWS on exactly the failure this
      // check exists to catch — `NamespaceError: prefix is non-null and
      // namespace is null` — rather than returning a document with a
      // parsererror in it. Without the try the mutation is still caught, but as
      // an unhandled exception with a stack trace instead of as a named check,
      // and the job reports "sts_saml_encryption failed" without saying which
      // property broke. Verified by mutation on 2026-08-27.
      let standalone = false;
      let why = '';
      try {
        const parsed = new DOMParser().parseFromString(got.xml, 'text/xml');
        standalone = !!(parsed && parsed.documentElement) &&
                     !parsed.getElementsByTagName('parsererror').length;
      } catch (e) {
        why = e.message;
      }
      check('THE DECRYPTED FRAGMENT PARSES ON ITS OWN — it declares its own namespace ' +
            'rather than relying on the LogoutRequest it is no longer inside',
            standalone, why || 'parsed');
      check('and it is the person who signed in',
            got.xml.indexOf('>' + USER + '<') >= 0);
    }
  }

  await restoreSettings();
  log.info('---------------------------------------------------------------');
  if (failures.length) {
    log.error(passed + ' check(s) passed, ' + failures.length + ' FAILED:');
    failures.forEach(function (f) { log.error('  ✗ ' + f); });
    return 1;
  }
  log.info(passed + ' check(s) passed, 0 failed.');
  return 0;
}

main().then(function (code) {
  process.exit(code);
}).catch(function (e) {
  log.error('sts_saml_encryption failed: ' + (e && e.stack ? e.stack : e));
  process.exit(1);
});
