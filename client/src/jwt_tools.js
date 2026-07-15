// File: jwt_tools.js
// Author: Robert C. Broeckelmann Jr.
// Notes:
//
// Client-side tools for composing, signing (JWS), and encrypting (JWE) JWTs,
// plus signature verification and JWE decryption. All cryptography is performed
// in the browser with the Web Crypto API (crypto.subtle). No key material is
// ever written to localStorage.
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var pkijs = require("pkijs");
var asn1js = require("asn1js");
var log = bunyan.createLogger({ name: 'jwt_tools',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// PKI.js needs a Web Crypto engine. In the browser the global `crypto` object
// provides it. (Used only for keystore export — PKCS#12 / encrypted PKCS#8.)
(function initPkiEngine() {
  try {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      pkijs.setEngine('webcrypto', new pkijs.CryptoEngine({ name: 'webcrypto', crypto: crypto }));
    }
  } catch (e) {
    log.error('Failed to init PKI.js engine: ' + e.message);
  }
})();

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------
function val(id) {
  var el = document.getElementById(id);
  return el ? el.value : '';
}

function setVal(id, v) {
  var el = document.getElementById(id);
  if (el) el.value = v;
}

// ---------------------------------------------------------------------------
// Base64url / PEM / byte helpers
// ---------------------------------------------------------------------------
function bytesToB64u(input) {
  var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function strToB64u(str) {
  return bytesToB64u(new TextEncoder().encode(str));
}

function b64uToBytes(b64u) {
  var s = String(b64u).replace(/-/g, '+').replace(/_/g, '/');
  var pad = '==='.slice(0, (4 - s.length % 4) % 4);
  var bin = atob(s + pad);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function b64uToStr(b64u) {
  return new TextDecoder().decode(b64uToBytes(b64u));
}

function derToPem(der, label) {
  var bytes = new Uint8Array(der);
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  var b64 = btoa(bin);
  var lines = b64.match(/.{1,64}/g).join('\n');
  return '-----BEGIN ' + label + '-----\n' + lines + '\n-----END ' + label + '-----\n';
}

function pemToDer(pem) {
  var b64 = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function concatBytes() {
  var total = 0, i;
  for (i = 0; i < arguments.length; i++) total += arguments[i].length;
  var out = new Uint8Array(total);
  var offset = 0;
  for (i = 0; i < arguments.length; i++) {
    out.set(arguments[i], offset);
    offset += arguments[i].length;
  }
  return out;
}

function uint32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

// ---------------------------------------------------------------------------
// Algorithm metadata
// ---------------------------------------------------------------------------
// alg -> Web Crypto sign/verify parameters
var SIGN_ALGS = {
  HS256: { kind: 'hmac', hash: 'SHA-256' },
  HS384: { kind: 'hmac', hash: 'SHA-384' },
  HS512: { kind: 'hmac', hash: 'SHA-512' },
  RS256: { kind: 'rsa', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  RS384: { kind: 'rsa', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  RS512: { kind: 'rsa', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  PS256: { kind: 'rsa', name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 },
  PS384: { kind: 'rsa', name: 'RSA-PSS', hash: 'SHA-384', saltLength: 48 },
  PS512: { kind: 'rsa', name: 'RSA-PSS', hash: 'SHA-512', saltLength: 64 },
  ES256: { kind: 'ec', name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
  ES384: { kind: 'ec', name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' },
  ES512: { kind: 'ec', name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' }
};

// JWE content-encryption key sizes (bytes)
var ENC_KEY_BYTES = { A128GCM: 16, A192GCM: 24, A256GCM: 32 };

// JWE key-management (asymmetric) hash for RSA-OAEP variants
var JWE_RSA_HASH = { 'RSA-OAEP': 'SHA-1', 'RSA-OAEP-256': 'SHA-256' };

// ---------------------------------------------------------------------------
// Composition: keep header / payload / encoded in sync
// ---------------------------------------------------------------------------
function parseJson(id, label) {
  var raw = val(id);
  var obj = JSON.parse(raw);
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error(label + ' must be a JSON object.');
  }
  return obj;
}

// Rebuild the unsigned encoded token (header.payload) from the current
// Header/Payload text. Called whenever either textarea changes.
function updateEncoded() {
  try {
    var header = parseJson('jwt_tools_header', 'JWT Header');
    var payload = parseJson('jwt_tools_payload', 'JWT Payload');
    var encoded = strToB64u(JSON.stringify(header)) + '.' + strToB64u(JSON.stringify(payload)) + '.';
    setVal('jwt_tools_encoded', encoded);
    setVal('jwt_tools_sync_status', 'In sync (unsigned). Sign or encrypt to produce a complete token.');
  } catch (e) {
    setVal('jwt_tools_sync_status', 'Cannot encode: ' + e.message);
  }
  return false;
}

// The Encoded JWT field is editable: when the user pastes/types a token, decode
// its header and payload into those fields. If it carries a signature (third
// segment), capture the whole token into the Sign pane's "Signed JWT" and
// "JWT to Verify" fields. Programmatic setVal() does not fire oninput, so this
// does not loop with updateEncoded().
function onEncodedInput() {
  var encoded = val('jwt_tools_encoded').trim();
  if (!encoded) {
    setVal('jwt_tools_sync_status', 'Encoded JWT is empty.');
    return false;
  }
  var parts = encoded.split('.');
  if (parts.length < 2 || !parts[0] || !parts[1]) {
    setVal('jwt_tools_sync_status', 'Not a JWT — expected header.payload[.signature].');
    return false;
  }
  try {
    var header = JSON.parse(b64uToStr(parts[0]));
    var payload = JSON.parse(b64uToStr(parts[1]));
    setVal('jwt_tools_header', JSON.stringify(header, null, 2));
    setVal('jwt_tools_payload', JSON.stringify(payload, null, 2));

    var signature = parts.length >= 3 ? parts[2] : '';
    if (signature) {
      // Signed token: hand the whole thing to the Sign pane.
      setVal('jwt_tools_signed', encoded);
      setVal('verify_input', encoded);
      setVal('jwt_tools_sync_status', 'Decoded header & payload; signature captured (populated Signed JWT and JWT to Verify in the Sign pane).');
    } else {
      setVal('jwt_tools_sync_status', 'Decoded header & payload (no signature present).');
    }
  } catch (e) {
    setVal('jwt_tools_sync_status', 'Cannot decode JWT: ' + e.message);
  }
  return false;
}

// Add a custom claim to either the Header or the Payload object.
function addClaim() {
  var name = val('custom_claim_name').trim();
  var rawValue = val('custom_claim_value');
  var type = val('custom_claim_type');
  var target = val('custom_claim_target'); // 'jwt_tools_header' | 'jwt_tools_payload'

  if (!name) {
    setVal('jwt_tools_sync_status', 'Custom claim requires a name.');
    return false;
  }

  var value;
  try {
    if (type === 'number') {
      var trimmed = rawValue.trim();
      if (trimmed === '') throw new Error('A numeric value is required.');
      value = Number(trimmed);
      // Number('') is 0 and Number('1e400') is Infinity — reject both so only
      // genuine, JSON-representable numbers are added.
      if (!isFinite(value)) throw new Error('"' + trimmed + '" is not a valid number.');
    } else if (type === 'boolean') {
      value = (rawValue.trim().toLowerCase() === 'true');
    } else if (type === 'json') {
      value = JSON.parse(rawValue);
    } else {
      value = rawValue;
    }
  } catch (e) {
    setVal('jwt_tools_sync_status', 'Cannot add claim: ' + e.message);
    return false;
  }

  try {
    var obj = parseJson(target, target === 'jwt_tools_header' ? 'JWT Header' : 'JWT Payload');
    obj[name] = value;
    setVal(target, JSON.stringify(obj, null, 2));
    setVal('custom_claim_name', '');
    setVal('custom_claim_value', '');
    updateEncoded();
  } catch (e) {
    setVal('jwt_tools_sync_status', 'Cannot add claim: ' + e.message);
  }
  return false;
}

// Confirm the composed header/payload are still spec-compliant (RFC 7519 /
// RFC 7515 for the JOSE header). Reports PASS/FAIL/SKIP per check.
function checkCompliance() {
  var results = [];
  function pass(c, m) { results.push('PASS  ' + c + ': ' + m); }
  function fail(c, m) { results.push('FAIL  ' + c + ': ' + m); }
  function skip(c, m) { results.push('SKIP  ' + c + ': ' + m); }

  var header, payload;
  try {
    header = parseJson('jwt_tools_header', 'JWT Header');
  } catch (e) {
    setVal('compliance_output', 'FAIL  header: ' + e.message);
    return false;
  }
  try {
    payload = parseJson('jwt_tools_payload', 'JWT Payload');
  } catch (e) {
    setVal('compliance_output', 'FAIL  payload: ' + e.message);
    return false;
  }

  // ---- JOSE header (RFC 7515 §4) ----
  if (!header.alg) {
    fail('alg', 'Missing "alg" header parameter (RFC 7515 §4.1.1)');
  } else if (typeof header.alg !== 'string') {
    fail('alg', '"alg" must be a string');
  } else if (header.alg === 'none') {
    fail('alg', '"none" is not permitted for a signed JWT');
  } else if (!SIGN_ALGS[header.alg]) {
    skip('alg', '"' + header.alg + '" is not a signing alg this tool produces');
  } else {
    pass('alg', header.alg);
  }

  if (header.typ === undefined) {
    skip('typ', 'Not present (optional; "JWT" recommended)');
  } else if (typeof header.typ !== 'string') {
    fail('typ', '"typ" must be a string');
  } else {
    pass('typ', '"' + header.typ + '"');
  }

  // ---- Registered claims (RFC 7519 §4.1) ----
  function checkString(name) {
    if (payload[name] === undefined) { skip(name, 'Not present (optional)'); return; }
    if (typeof payload[name] !== 'string') fail(name, 'Must be a StringOrURI (string)');
    else pass(name, '"' + payload[name] + '"');
  }
  function checkNumericDate(name) {
    if (payload[name] === undefined) { skip(name, 'Not present (optional)'); return; }
    if (typeof payload[name] !== 'number' || !Number.isInteger(payload[name])) {
      fail(name, 'Must be an integer NumericDate (RFC 7519 §2)');
    } else {
      pass(name, new Date(payload[name] * 1000).toISOString());
    }
  }

  checkString('iss');
  checkString('sub');

  // aud may be a StringOrURI or an array of StringOrURI (RFC 7519 §4.1.3)
  if (payload.aud === undefined) {
    skip('aud', 'Not present (optional)');
  } else if (typeof payload.aud === 'string') {
    pass('aud', '"' + payload.aud + '"');
  } else if (Array.isArray(payload.aud) && payload.aud.every(function (a) { return typeof a === 'string'; })) {
    pass('aud', payload.aud.length + ' value(s)');
  } else {
    fail('aud', 'Must be a string or array of strings');
  }

  checkNumericDate('exp');
  checkNumericDate('nbf');
  checkNumericDate('iat');
  checkString('jti');

  setVal('compliance_output', results.join('\n'));
  return false;
}

// Validate the composed header/payload as an OAuth 2.0 JWT access token per
// RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens). Output goes to the same
// Compliance Output box. Header (§2.1): typ MUST be "at+jwt" and the token MUST
// be signed (alg present, not "none"). Required claims (§2.2): iss, exp, aud,
// sub, client_id, iat, jti. scope is conditionally recommended (§2.2.3);
// auth_time/acr/amr are optional (§2.2.1) and only type-checked if present.
function checkRfc9068Compliance() {
  var results = [];
  function pass(c, m) { results.push('PASS  ' + c + ': ' + m); }
  function fail(c, m) { results.push('FAIL  ' + c + ': ' + m); }
  function skip(c, m) { results.push('SKIP  ' + c + ': ' + m); }

  var header, payload;
  try {
    header = parseJson('jwt_tools_header', 'JWT Header');
  } catch (e) {
    setVal('compliance_output', 'FAIL  header: ' + e.message);
    return false;
  }
  try {
    payload = parseJson('jwt_tools_payload', 'JWT Payload');
  } catch (e) {
    setVal('compliance_output', 'FAIL  payload: ' + e.message);
    return false;
  }

  results.push('RFC 9068 — OAuth 2.0 JWT Access Token');

  // ---- Header (RFC 9068 §2.1) ----
  // typ is REQUIRED and MUST be "at+jwt" (the "application/" prefix is allowed).
  if (header.typ === undefined) {
    fail('typ', 'Missing — MUST be "at+jwt" (RFC 9068 §2.1)');
  } else if (typeof header.typ !== 'string') {
    fail('typ', '"typ" must be a string');
  } else if (header.typ === 'at+jwt' || header.typ === 'application/at+jwt') {
    pass('typ', '"' + header.typ + '"');
  } else {
    fail('typ', '"' + header.typ + '" — MUST be "at+jwt" (RFC 9068 §2.1)');
  }

  // The token MUST be signed; alg is REQUIRED and MUST NOT be "none".
  if (!header.alg) {
    fail('alg', 'Missing — access tokens MUST be signed (RFC 9068 §2.1)');
  } else if (typeof header.alg !== 'string') {
    fail('alg', '"alg" must be a string');
  } else if (header.alg === 'none') {
    fail('alg', '"none" is not permitted — access tokens MUST be signed (RFC 9068 §2.1)');
  } else {
    pass('alg', header.alg);
  }

  // ---- Required claims (RFC 9068 §2.2) ----
  function requireString(name) {
    if (payload[name] === undefined) fail(name, 'Missing required claim (RFC 9068 §2.2)');
    else if (typeof payload[name] !== 'string') fail(name, 'Must be a string');
    else pass(name, '"' + payload[name] + '"');
  }
  function requireNumericDate(name) {
    if (payload[name] === undefined) fail(name, 'Missing required claim (RFC 9068 §2.2)');
    else if (typeof payload[name] !== 'number' || !Number.isInteger(payload[name])) fail(name, 'Must be an integer NumericDate');
    else pass(name, new Date(payload[name] * 1000).toISOString());
  }

  requireString('iss');
  requireNumericDate('exp');

  // aud is REQUIRED: a StringOrURI or a non-empty array of them.
  if (payload.aud === undefined) {
    fail('aud', 'Missing required claim (RFC 9068 §2.2)');
  } else if (typeof payload.aud === 'string') {
    pass('aud', '"' + payload.aud + '"');
  } else if (Array.isArray(payload.aud) && payload.aud.length > 0 && payload.aud.every(function (a) { return typeof a === 'string'; })) {
    pass('aud', payload.aud.length + ' value(s)');
  } else {
    fail('aud', 'Must be a string or non-empty array of strings');
  }

  requireString('sub');
  requireString('client_id');
  requireNumericDate('iat');
  requireString('jti');

  // ---- Conditional / optional claims ----
  // scope SHOULD be present when a scope was requested (RFC 9068 §2.2.3).
  if (payload.scope === undefined) {
    skip('scope', 'Not present (SHOULD be present if a scope was requested — RFC 9068 §2.2.3)');
  } else if (typeof payload.scope !== 'string') {
    fail('scope', 'Must be a space-delimited string (RFC 9068 §2.2.3)');
  } else {
    pass('scope', '"' + payload.scope + '"');
  }

  // Authentication information claims are optional (RFC 9068 §2.2.1).
  if (payload.auth_time !== undefined) {
    if (typeof payload.auth_time !== 'number' || !Number.isInteger(payload.auth_time)) fail('auth_time', 'Must be an integer NumericDate');
    else pass('auth_time', new Date(payload.auth_time * 1000).toISOString());
  }
  if (payload.acr !== undefined) {
    if (typeof payload.acr !== 'string') fail('acr', 'Must be a string');
    else pass('acr', '"' + payload.acr + '"');
  }
  if (payload.amr !== undefined) {
    if (Array.isArray(payload.amr) && payload.amr.every(function (a) { return typeof a === 'string'; })) pass('amr', payload.amr.length + ' value(s)');
    else fail('amr', 'Must be an array of strings');
  }

  setVal('compliance_output', results.join('\n'));
  return false;
}

// Populate Header, Payload, and the Encoded JWT with a sample RFC 9068 access
// token: header carries alg + typ "at+jwt"; payload carries the required claims
// (iss, exp, aud, sub, client_id, iat, jti) plus a scope. Produced unsigned
// (header.payload.) — sign it in the Sign pane to complete it.
function generateRfc9068Token() {
  var now = Math.floor(Date.now() / 1000);
  var header = { alg: 'RS256', typ: 'at+jwt' };
  var payload = {
    iss: 'https://as.example.com',
    sub: 'user-1234',
    aud: 'https://api.example.com',
    client_id: 'example-client',
    iat: now,
    exp: now + 3600,
    jti: bytesToB64u(crypto.getRandomValues(new Uint8Array(12))),
    scope: 'read write'
  };
  setVal('jwt_tools_header', JSON.stringify(header, null, 2));
  setVal('jwt_tools_payload', JSON.stringify(payload, null, 2));
  updateEncoded(); // fills the Encoded JWT field (header.payload.) from the above
  setVal('jwt_tools_sync_status', 'Generated a sample RFC 9068 access token (unsigned). Sign it in the Sign (JWS) pane to complete it.');
  return false;
}

// ---------------------------------------------------------------------------
// Digital signatures (JWS)
// ---------------------------------------------------------------------------
async function generateSigningKeys() {
  var alg = val('sign_alg');
  var meta = SIGN_ALGS[alg];
  setVal('sign_status', 'Generating ' + alg + ' key material...');
  try {
    if (meta.kind === 'hmac') {
      var secret = new Uint8Array(32);
      crypto.getRandomValues(secret);
      setVal('sign_private_key', bytesToB64u(secret));
      setVal('sign_public_key', '(HMAC is symmetric — the secret above is used for both signing and verification.)');
    } else if (meta.kind === 'rsa') {
      var rsaPair = await crypto.subtle.generateKey(
        { name: meta.name, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: meta.hash },
        true, ['sign', 'verify']);
      setVal('sign_private_key', derToPem(await crypto.subtle.exportKey('pkcs8', rsaPair.privateKey), 'PRIVATE KEY'));
      setVal('sign_public_key', derToPem(await crypto.subtle.exportKey('spki', rsaPair.publicKey), 'PUBLIC KEY'));
    } else {
      var ecPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: meta.namedCurve }, true, ['sign', 'verify']);
      setVal('sign_private_key', derToPem(await crypto.subtle.exportKey('pkcs8', ecPair.privateKey), 'PRIVATE KEY'));
      setVal('sign_public_key', derToPem(await crypto.subtle.exportKey('spki', ecPair.publicKey), 'PUBLIC KEY'));
    }
    await applyKeyFormat('sign'); // honor the PEM/JWK toggle
    await syncVerificationKey();  // keep X.509 verification key in sync
    setVal('sign_status', 'Generated ' + alg + ' key material.');
  } catch (e) {
    log.error('generateSigningKeys: ' + e.message);
    setVal('sign_status', 'Error: ' + e.message);
  }
  return false;
}

async function importSigningKey(meta, keyText) {
  if (meta.kind === 'hmac') {
    var secret = isJwk(keyText) ? (JSON.parse(keyText).k || '') : keyText.trim();
    return crypto.subtle.importKey('raw', b64uToBytes(secret),
      { name: 'HMAC', hash: meta.hash }, false, ['sign']);
  }
  var params = meta.kind === 'rsa'
    ? { name: meta.name, hash: meta.hash }
    : { name: 'ECDSA', namedCurve: meta.namedCurve };
  return importKeyFlexible(keyText, 'pkcs8', params, ['sign']);
}

async function signJWT() {
  var alg = val('sign_alg');
  var meta = SIGN_ALGS[alg];
  setVal('sign_status', 'Signing with ' + alg + '...');
  try {
    // Force the header alg to match the selected signing algorithm.
    var header = parseJson('jwt_tools_header', 'JWT Header');
    header.alg = alg;
    setVal('jwt_tools_header', JSON.stringify(header, null, 2));
    var payload = parseJson('jwt_tools_payload', 'JWT Payload');

    var signingInput = strToB64u(JSON.stringify(header)) + '.' + strToB64u(JSON.stringify(payload));
    var key = await importSigningKey(meta, val('sign_private_key'));

    var signParams;
    if (meta.kind === 'hmac') signParams = { name: 'HMAC' };
    else if (meta.kind === 'rsa' && meta.name === 'RSA-PSS') signParams = { name: 'RSA-PSS', saltLength: meta.saltLength };
    else if (meta.kind === 'rsa') signParams = { name: 'RSASSA-PKCS1-v1_5' };
    else signParams = { name: 'ECDSA', hash: meta.hash };

    var sig = await crypto.subtle.sign(signParams, key, new TextEncoder().encode(signingInput));
    var jws = signingInput + '.' + bytesToB64u(sig);

    setVal('jwt_tools_signed', jws);
    setVal('jwt_tools_encoded', jws);
    setVal('verify_input', jws);
    setVal('jwe_plaintext', jws);
    await syncVerificationKey(); // keep X.509 verification key in sync
    setVal('sign_status', 'Signed JWT produced with ' + alg + '.');
    setVal('jwt_tools_sync_status', 'Encoded field now holds the signed JWT.');
  } catch (e) {
    log.error('signJWT: ' + e.message);
    setVal('sign_status', 'Error: ' + e.message);
  }
  return false;
}

// ---- Signature verification (mirrors token_detail.js) ----
async function verifyHMAC(jwt_, secret, alg) {
  var meta = SIGN_ALGS[alg];
  if (!meta || meta.kind !== 'hmac') throw new Error('Unsupported HMAC algorithm: ' + alg);
  var key = await crypto.subtle.importKey('raw', b64uToBytes(secret.trim()),
    { name: 'HMAC', hash: meta.hash }, false, ['verify']);
  var data = new TextEncoder().encode(jwt_.split('.').slice(0, 2).join('.'));
  return crypto.subtle.verify('HMAC', key, b64uToBytes(jwt_.split('.')[2]), data);
}

async function verifyX509(jwt_, pem, alg) {
  var meta = SIGN_ALGS[alg];
  if (!meta || (meta.kind !== 'rsa' && meta.kind !== 'ec')) {
    throw new Error('Unsupported asymmetric algorithm: ' + alg);
  }
  var importParams, verifyParams;
  if (meta.kind === 'ec') {
    importParams = { name: 'ECDSA', namedCurve: meta.namedCurve };
    verifyParams = { name: 'ECDSA', hash: meta.hash };
  } else {
    importParams = { name: meta.name, hash: meta.hash };
    verifyParams = meta.name === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: meta.saltLength } : { name: 'RSASSA-PKCS1-v1_5' };
  }
  var key = await crypto.subtle.importKey('spki', pemToDer(pem), importParams, false, ['verify']);
  var data = new TextEncoder().encode(jwt_.split('.').slice(0, 2).join('.'));
  return crypto.subtle.verify(verifyParams, key, b64uToBytes(jwt_.split('.')[2]), data);
}

async function verifyJWKS(jwt_, jwks) {
  var header = JSON.parse(b64uToStr(jwt_.split('.')[0]));
  if (!header.kid) throw new Error('No "kid" found in JWT header.');
  var jwk = jwks.keys.find(function (k) { return k.kid === header.kid; });
  if (!jwk) throw new Error('Matching "kid" not found in JWKS.');
  if (jwk.kty !== 'RSA') throw new Error('Only RSA keys are supported for JWKS verification.');
  var meta = SIGN_ALGS[header.alg];
  if (!meta || meta.kind !== 'rsa') throw new Error('Unsupported algorithm: ' + header.alg);
  var key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e },
    { name: meta.name, hash: meta.hash }, false, ['verify']);
  var data = new TextEncoder().encode(jwt_.split('.').slice(0, 2).join('.'));
  var verifyParams = meta.name === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: meta.saltLength } : { name: 'RSASSA-PKCS1-v1_5' };
  return crypto.subtle.verify(verifyParams, key, b64uToBytes(jwt_.split('.')[2]), data);
}

async function verifyJWT() {
  var type = val('jwt_verification_type');
  var key = val('jwt_verification_key');
  var jwt_ = val('verify_input').trim();
  var isValid = false;
  try {
    var parts = jwt_.split('.');
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) throw new Error('Invalid JWS compact format.');
    var header = JSON.parse(b64uToStr(parts[0]));
    if (type === 'hmac') isValid = await verifyHMAC(jwt_, key, header.alg);
    else if (type === 'x509') isValid = await verifyX509(jwt_, key, header.alg);
    else if (type === 'jwks') isValid = await verifyJWKS(jwt_, JSON.parse(key));
    else if (type === 'jwks_url') {
      var response = await fetch(key);
      if (!response.ok) throw new Error('Failed to fetch JWKS.');
      isValid = await verifyJWKS(jwt_, await response.json());
    } else throw new Error('Unsupported verification method.');
    setVal('jwt_verification_output', 'Signature Verified: ' + isValid);
  } catch (err) {
    log.error('verifyJWT: ' + err.message);
    setVal('jwt_verification_output', 'Error: ' + err.message);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Encryption (JWE) — compact serialization, RFC 7516 / 7518
// ---------------------------------------------------------------------------
// ECDH-ES key agreement is limited to the P-256 curve in this tool.
var ECDH_CURVE = 'P-256';
var ECDH_CURVE_BITS = 256;

async function generateEncryptionKeys() {
  var alg = val('jwe_alg');
  setVal('jwe_status', 'Generating ' + alg + ' key material...');
  try {
    var pair;
    if (alg === 'ECDH-ES') {
      pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: ECDH_CURVE }, true, ['deriveBits']);
    } else {
      pair = await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: JWE_RSA_HASH[alg] },
        true, ['encrypt', 'decrypt']);
    }
    setVal('jwe_public_key', derToPem(await crypto.subtle.exportKey('spki', pair.publicKey), 'PUBLIC KEY'));
    setVal('jwe_private_key', derToPem(await crypto.subtle.exportKey('pkcs8', pair.privateKey), 'PRIVATE KEY'));
    await applyKeyFormat('enc'); // honor the PEM/JWK toggle
    setVal('jwe_status', 'Generated ' + alg + ' key material' + (alg === 'ECDH-ES' ? ' (P-256).' : '.'));
  } catch (e) {
    log.error('generateEncryptionKeys: ' + e.message);
    setVal('jwe_status', 'Error: ' + e.message);
  }
  return false;
}

// NIST SP 800-56A Concat KDF with SHA-256 (RFC 7518 §4.6) for ECDH-ES "direct".
async function concatKdf(z, keyBytes, algId) {
  var algBytes = new TextEncoder().encode(algId);
  var otherInfo = concatBytes(
    uint32be(algBytes.length), algBytes, // AlgorithmID
    uint32be(0),                         // PartyUInfo (empty)
    uint32be(0),                         // PartyVInfo (empty)
    uint32be(keyBytes * 8)               // SuppPubInfo = keydatalen in bits
  );                                     // SuppPrivInfo omitted
  // One SHA-256 round covers up to 32 bytes, enough for A128/A192/A256GCM.
  var input = concatBytes(uint32be(1), new Uint8Array(z), otherInfo);
  var hash = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return hash.slice(0, keyBytes);
}

async function deriveEncryptionCek(alg, enc, protectedHeader, recipientPublicPem) {
  var keyBytes = ENC_KEY_BYTES[enc];
  if (alg === 'ECDH-ES') {
    var recipientPub = await importKeyFlexible(recipientPublicPem, 'spki',
      { name: 'ECDH', namedCurve: ECDH_CURVE }, []);
    var ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: ECDH_CURVE }, true, ['deriveBits']);
    var z = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipientPub }, ephemeral.privateKey, ECDH_CURVE_BITS);
    var epk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);
    protectedHeader.epk = { kty: epk.kty, crv: epk.crv, x: epk.x, y: epk.y };
    // For ECDH-ES "direct", the agreed key IS the CEK and encrypted_key is empty.
    var cekBytes = await concatKdf(z, keyBytes, enc);
    var cek = await crypto.subtle.importKey('raw', cekBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    return { cek: cek, encryptedKey: '' };
  }
  // RSA-OAEP / RSA-OAEP-256: random CEK wrapped with the recipient public key.
  var cekBytes2 = new Uint8Array(keyBytes);
  crypto.getRandomValues(cekBytes2);
  var rsaPub = await importKeyFlexible(recipientPublicPem, 'spki',
    { name: 'RSA-OAEP', hash: JWE_RSA_HASH[alg] }, ['encrypt']);
  var wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPub, cekBytes2);
  var cek2 = await crypto.subtle.importKey('raw', cekBytes2, { name: 'AES-GCM' }, false, ['encrypt']);
  return { cek: cek2, encryptedKey: bytesToB64u(wrapped) };
}

async function encryptJWT() {
  var alg = val('jwe_alg');
  var enc = val('jwe_enc');
  var plaintext = val('jwe_plaintext').trim();
  setVal('jwe_status', 'Encrypting with ' + alg + ' / ' + enc + '...');
  try {
    if (!plaintext) throw new Error('Nothing to encrypt. Sign a JWT or enter a payload above.');
    if (!ENC_KEY_BYTES[enc]) throw new Error('Unsupported content encryption: ' + enc);

    var protectedHeader = { alg: alg, enc: enc };
    // A nested JWT (a JWS as the plaintext) is signalled with cty:"JWT" (RFC 7519 §5.2).
    if (plaintext.split('.').length === 3) protectedHeader.cty = 'JWT';

    var derived = await deriveEncryptionCek(alg, enc, protectedHeader, val('jwe_public_key'));
    var protectedB64 = strToB64u(JSON.stringify(protectedHeader));
    var aad = new TextEncoder().encode(protectedB64); // ASCII(BASE64URL(protected header))

    var iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    var full = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, additionalData: aad, tagLength: 128 },
      derived.cek, new TextEncoder().encode(plaintext)));

    // Web Crypto appends the 16-byte auth tag; JWE keeps ciphertext and tag separate.
    var ciphertext = full.slice(0, full.length - 16);
    var tag = full.slice(full.length - 16);

    var jwe = [protectedB64, derived.encryptedKey, bytesToB64u(iv), bytesToB64u(ciphertext), bytesToB64u(tag)].join('.');
    setVal('jwt_tools_jwe', jwe);
    setVal('jwe_decrypt_input', jwe);
    setVal('jwt_tools_encoded', jwe);

    // Reflect the header parameters added by encryption in the Compose pane's
    // JWT Header box. Per RFC 7515/7516/7519, a JWS/JWT "alg" (the signing
    // algorithm) and a JWE "alg" (the key-management algorithm) are distinct
    // header parameters belonging to distinct (JWS vs JWE) headers, so the
    // existing signing "alg" MUST NOT be overwritten by the JWE "alg". Only the
    // newly-introduced JWE parameters (enc, cty [RFC 7519 §5.2], epk, ...) are
    // added; the JWT's own signing "alg" is preserved.
    var composeHeader;
    try {
      composeHeader = JSON.parse(val('jwt_tools_header'));
      if (composeHeader === null || typeof composeHeader !== 'object' || Array.isArray(composeHeader)) composeHeader = {};
    } catch (e) {
      composeHeader = {};
    }
    Object.keys(protectedHeader).forEach(function (k) {
      if (k === 'alg') return; // preserve the JWS signing "alg"
      composeHeader[k] = protectedHeader[k];
    });
    setVal('jwt_tools_header', JSON.stringify(composeHeader, null, 2));

    setVal('jwe_status', 'JWE produced with ' + alg + ' / ' + enc + '.');
    setVal('jwt_tools_sync_status', 'Encoded field now holds the JWE encrypted token.');
  } catch (e) {
    log.error('encryptJWT: ' + e.message);
    setVal('jwe_status', 'Error: ' + e.message);
  }
  return false;
}

async function decryptCek(alg, enc, protectedHeader, encryptedKey, recipientPrivatePem) {
  var keyBytes = ENC_KEY_BYTES[enc];
  if (alg === 'ECDH-ES') {
    if (!protectedHeader.epk) throw new Error('ECDH-ES JWE is missing the "epk" header.');
    var recipientPriv = await importKeyFlexible(recipientPrivatePem, 'pkcs8',
      { name: 'ECDH', namedCurve: protectedHeader.epk.crv }, ['deriveBits']);
    var epk = await crypto.subtle.importKey('jwk', protectedHeader.epk,
      { name: 'ECDH', namedCurve: protectedHeader.epk.crv }, false, []);
    var bits = protectedHeader.epk.crv === 'P-256' ? 256 : (protectedHeader.epk.crv === 'P-384' ? 384 : 521);
    var z = await crypto.subtle.deriveBits({ name: 'ECDH', public: epk }, recipientPriv, bits);
    var cekBytes = await concatKdf(z, keyBytes, enc);
    return crypto.subtle.importKey('raw', cekBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  }
  var rsaPriv = await importKeyFlexible(recipientPrivatePem, 'pkcs8',
    { name: 'RSA-OAEP', hash: JWE_RSA_HASH[alg] }, ['decrypt']);
  var cek = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaPriv, b64uToBytes(encryptedKey));
  return crypto.subtle.importKey('raw', new Uint8Array(cek), { name: 'AES-GCM' }, false, ['decrypt']);
}

async function decryptJWT() {
  var jwe = val('jwe_decrypt_input').trim();
  setVal('jwe_status', 'Decrypting...');
  try {
    var parts = jwe.split('.');
    if (parts.length !== 5) throw new Error('Invalid JWE compact format (expected 5 segments).');
    var protectedHeader = JSON.parse(b64uToStr(parts[0]));
    var alg = protectedHeader.alg;
    var enc = protectedHeader.enc;
    if (!ENC_KEY_BYTES[enc]) throw new Error('Unsupported content encryption: ' + enc);

    var cekKey = await decryptCek(alg, enc, protectedHeader, parts[1], val('jwe_private_key'));
    var aad = new TextEncoder().encode(parts[0]);
    var iv = b64uToBytes(parts[2]);
    var ctPlusTag = concatBytes(b64uToBytes(parts[3]), b64uToBytes(parts[4]));

    var plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, additionalData: aad, tagLength: 128 }, cekKey, ctPlusTag);
    setVal('jwe_decrypt_output', new TextDecoder().decode(plaintext));
    setVal('jwe_status', 'Decrypted with ' + alg + ' / ' + enc + '.');
  } catch (e) {
    log.error('decryptJWT: ' + e.message);
    setVal('jwe_status', 'Error: ' + e.message);
    setVal('jwe_decrypt_output', '');
  }
  return false;
}

// ---------------------------------------------------------------------------
// Keystore export / download (PEM, DER, JWK, PKCS#12)
//
// Key material is only read from the on-page fields and turned into a
// downloadable Blob — nothing is persisted. PKCS#12 wraps the private key in a
// self-signed certificate so it imports into OpenSSL / keytool / etc.
// ---------------------------------------------------------------------------
var PKCS12_CERT_OID = '1.2.840.113549.1.12.10.1.3';
var PKCS12_KEY_OID = '1.2.840.113549.1.12.10.1.2';
var OID_LOCAL_KEY_ID = '1.2.840.113549.1.9.21';
var OID_FRIENDLY_NAME = '1.2.840.113549.1.9.20';

// Describe how to import the private key for self-signing a certificate.
// RSA keys (RS*/PS*/RSA-OAEP*) sign the cert with RSASSA-PKCS1-v1_5/SHA-256;
// EC keys (ES*/ECDH-ES) with ECDSA over the curve's natural hash.
function certDescriptor(alg) {
  var ecCurve = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };
  var ecHash = { ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512' };
  if (alg[0] === 'H') return { kind: 'hmac' };
  if (alg[0] === 'E' && alg !== 'ECDH-ES') return { kind: 'ec', curve: ecCurve[alg], hash: ecHash[alg] };
  if (alg === 'ECDH-ES') return { kind: 'ec', curve: 'P-256', hash: 'SHA-256' };
  return { kind: 'rsa', hash: 'SHA-256' }; // RS*/PS*/RSA-OAEP*
}

function strBuf(s) { return new TextEncoder().encode(s).buffer; }

// ---------------------------------------------------------------------------
// PEM <-> JWK conversion for the key fields (driven by the per-step toggle).
// Conversion is key-material only, so any compatible import params work; we
// pick RSASSA-PKCS1-v1_5 for RSA-family keys and ECDSA for EC-family keys.
// ---------------------------------------------------------------------------
function isJwk(text) { return (text || '').trim().charAt(0) === '{'; }

function stripJwkForImport(jwk) {
  var out = {};
  Object.keys(jwk).forEach(function (k) {
    if (['alg', 'use', 'key_ops', 'ext'].indexOf(k) === -1) out[k] = jwk[k];
  });
  return out;
}

function convParams(desc) {
  return desc.kind === 'rsa'
    ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    : { name: 'ECDSA', namedCurve: desc.curve };
}

async function privToJwk(pem, desc, jwtAlg, use) {
  var key = await crypto.subtle.importKey('pkcs8', pemToDer(pem), convParams(desc), true, ['sign']);
  var jwk = await crypto.subtle.exportKey('jwk', key);
  delete jwk.key_ops; delete jwk.ext; jwk.alg = jwtAlg; jwk.use = use;
  return jwk;
}
async function pubToJwk(pem, desc, jwtAlg, use) {
  var key = await crypto.subtle.importKey('spki', pemToDer(pem), convParams(desc), true, ['verify']);
  var jwk = await crypto.subtle.exportKey('jwk', key);
  delete jwk.key_ops; delete jwk.ext; jwk.alg = jwtAlg; jwk.use = use;
  return jwk;
}
async function privToPem(jwkText, desc) {
  var key = await crypto.subtle.importKey('jwk', stripJwkForImport(JSON.parse(jwkText)), convParams(desc), true, ['sign']);
  return derToPem(await crypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY');
}
async function pubToPem(jwkText, desc) {
  var key = await crypto.subtle.importKey('jwk', stripJwkForImport(JSON.parse(jwkText)), convParams(desc), true, ['verify']);
  return derToPem(await crypto.subtle.exportKey('spki', key), 'PUBLIC KEY');
}

// Import a key that may be PEM or JWK, under the given params/usages.
async function importKeyFlexible(text, format, params, usages) {
  if (isJwk(text)) return crypto.subtle.importKey('jwk', stripJwkForImport(JSON.parse(text)), params, false, usages);
  return crypto.subtle.importKey(format, pemToDer(text), params, false, usages);
}

// Make both key fields of a step match the current toggle (PEM or JWK).
async function applyKeyFormat(step) {
  var s = step === 'sign';
  var toJwk = document.getElementById(s ? 'sign_key_jwk' : 'jwe_key_jwk').checked;
  var alg = val(s ? 'sign_alg' : 'jwe_alg');
  var desc = certDescriptor(alg);
  var privId = s ? 'sign_private_key' : 'jwe_private_key';
  var pubId = s ? 'sign_public_key' : 'jwe_public_key';
  var use = s ? 'sig' : 'enc';
  var statusId = s ? 'sign_status' : 'jwe_status';
  try {
    if (desc.kind === 'hmac') {
      // Symmetric: represent the secret as a base64url string (PEM mode) or oct JWK.
      var cur = val(privId).trim();
      var secret = cur ? (isJwk(cur) ? (JSON.parse(cur).k || '') : cur) : '';
      if (secret) setVal(privId, toJwk ? JSON.stringify({ kty: 'oct', k: secret, alg: alg, use: 'sig' }, null, 2) : secret);
      return false;
    }
    var priv = val(privId).trim();
    if (priv) {
      if (toJwk && !isJwk(priv)) setVal(privId, JSON.stringify(await privToJwk(priv, desc, alg, use), null, 2));
      else if (!toJwk && isJwk(priv)) setVal(privId, await privToPem(priv, desc));
    }
    var pub = val(pubId).trim();
    if (pub) {
      if (toJwk && !isJwk(pub)) setVal(pubId, JSON.stringify(await pubToJwk(pub, desc, alg, use), null, 2));
      else if (!toJwk && isJwk(pub)) setVal(pubId, await pubToPem(pub, desc));
    }
  } catch (e) {
    log.error('applyKeyFormat(' + step + '): ' + e.message);
    setVal(statusId, 'Key format conversion error: ' + e.message);
  }
  return false;
}
function toggleKeyFormat(step) { return applyKeyFormat(step); }

// When the Validate-a-Signature type is "X.509 Certificate (PEM)", default the
// verification key to the step's generated public key (as SPKI PEM). Converts
// from JWK if the key fields are in JWK mode. No-op for other types / HMAC.
async function syncVerificationKey() {
  try {
    if (val('jwt_verification_type') !== 'x509') return false;
    if (val('jwt_verification_key').trim()) return false; // don't clobber a manual entry
    var pub = val('sign_public_key').trim();
    if (!pub) return false;
    var desc = certDescriptor(val('sign_alg'));
    if (desc.kind === 'hmac') return false; // no public key for HMAC
    setVal('jwt_verification_key', isJwk(pub) ? await pubToPem(pub, desc) : pub);
  } catch (e) {
    log.error('syncVerificationKey: ' + e.message);
  }
  return false;
}

async function importCertSigningKey(privPem, desc) {
  if (desc.kind === 'rsa') {
    return crypto.subtle.importKey('pkcs8', pemToDer(privPem), { name: 'RSASSA-PKCS1-v1_5', hash: desc.hash }, false, ['sign']);
  }
  return crypto.subtle.importKey('pkcs8', pemToDer(privPem), { name: 'ECDSA', namedCurve: desc.curve }, false, ['sign']);
}

async function importCertPublicKey(pubPem, desc) {
  if (desc.kind === 'rsa') {
    return crypto.subtle.importKey('spki', pemToDer(pubPem), { name: 'RSASSA-PKCS1-v1_5', hash: desc.hash }, true, ['verify']);
  }
  return crypto.subtle.importKey('spki', pemToDer(pubPem), { name: 'ECDSA', namedCurve: desc.curve }, true, ['verify']);
}

async function buildSelfSignedCert(privPem, pubPem, desc) {
  var privKey = await importCertSigningKey(privPem, desc);
  var pubKey = await importCertPublicKey(pubPem, desc);
  var cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 1 });
  var dn = new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value: 'jwt-tools generated key' }) });
  cert.issuer.typesAndValues.push(dn);
  cert.subject.typesAndValues.push(dn);
  cert.notBefore.value = new Date(Date.UTC(2020, 0, 1));
  cert.notAfter.value = new Date(Date.UTC(2035, 0, 1));
  await cert.subjectPublicKeyInfo.importKey(pubKey);
  await cert.sign(privKey, desc.hash);
  return cert;
}

var PBES2_OPTS = {
  contentEncryptionAlgorithm: { name: 'AES-CBC', length: 256 },
  hmacHashAlgorithm: 'SHA-256',
  iterationCount: 100000,
  pbkdf2HashAlgorithm: 'SHA-256'
};

// Encrypt a PKCS#8 private key into an EncryptedPrivateKeyInfo (PBES2). Returns DER bytes.
async function encryptedPkcs8Der(privDer, password) {
  var bag = new pkijs.PKCS8ShroudedKeyBag({ parsedValue: pkijs.PrivateKeyInfo.fromBER(privDer) });
  var opts = Object.assign({ password: strBuf(password) }, PBES2_OPTS);
  await bag.makeInternalValues(opts);
  return new Uint8Array(bag.toSchema().toBER(false));
}

async function buildPkcs12(privPem, pubPem, desc, password) {
  var cert = await buildSelfSignedCert(privPem, pubPem, desc);
  var privDer = pemToDer(privPem);
  var keyId = crypto.getRandomValues(new Uint8Array(20));
  function attrs() {
    return [
      new pkijs.Attribute({ type: OID_LOCAL_KEY_ID, values: [new asn1js.OctetString({ valueHex: keyId })] }),
      new pkijs.Attribute({ type: OID_FRIENDLY_NAME, values: [new asn1js.BmpString({ value: 'jwt-tools' })] })
    ];
  }
  var certBag = new pkijs.SafeBag({ bagId: PKCS12_CERT_OID, bagValue: new pkijs.CertBag({ parsedValue: cert }), bagAttributes: attrs() });
  var keyBag = new pkijs.SafeBag({ bagId: PKCS12_KEY_OID, bagValue: new pkijs.PKCS8ShroudedKeyBag({ parsedValue: pkijs.PrivateKeyInfo.fromBER(privDer) }), bagAttributes: attrs() });
  await keyBag.bagValue.makeInternalValues(Object.assign({ password: strBuf(password) }, PBES2_OPTS));

  var pfx = new pkijs.PFX({
    parsedValue: {
      integrityMode: 0, // password integrity
      authenticatedSafe: new pkijs.AuthenticatedSafe({
        parsedValue: {
          safeContents: [
            { privacyMode: 0, value: new pkijs.SafeContents({ safeBags: [certBag] }) },
            { privacyMode: 0, value: new pkijs.SafeContents({ safeBags: [keyBag] }) }
          ]
        }
      })
    }
  });
  await pfx.parsedValue.authenticatedSafe.makeInternalValues({ safeContents: [{}, {}] });
  await pfx.makeInternalValues({ password: strBuf(password), iterations: 100000, pbkdf2HashAlgorithm: 'SHA-256', hmacHashAlgorithm: 'SHA-256' });
  return new Uint8Array(pfx.toSchema().toBER(false));
}

async function keysToJwk(privPem, pubPem, desc, jwtAlg, use) {
  var importParams = desc.kind === 'rsa'
    ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    : { name: 'ECDSA', namedCurve: desc.curve };
  var privKey = await crypto.subtle.importKey('pkcs8', pemToDer(privPem), importParams, true, ['sign']);
  var pubKey = await crypto.subtle.importKey('spki', pemToDer(pubPem), importParams, true, ['verify']);
  var jp = await crypto.subtle.exportKey('jwk', privKey);
  var jpub = await crypto.subtle.exportKey('jwk', pubKey);
  [jp, jpub].forEach(function (j) { delete j.key_ops; delete j.ext; j.alg = jwtAlg; j.use = use; });
  return { publicKey: jpub, privateKey: jp };
}

// Password-protect an arbitrary string as a compact PBES2 JWE (RFC 7518 §4.8).
async function pbes2JweEncrypt(plaintext, password) {
  var alg = 'PBES2-HS256+A128KW', enc = 'A256GCM';
  var p2s = crypto.getRandomValues(new Uint8Array(16));
  var p2c = 100000;
  var pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  var saltInput = concatBytes(new TextEncoder().encode(alg), new Uint8Array([0]), p2s);
  var wrapKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: saltInput, iterations: p2c, hash: 'SHA-256' },
    pwKey, { name: 'AES-KW', length: 128 }, false, ['wrapKey']);
  var cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  var wrapped = new Uint8Array(await crypto.subtle.wrapKey('raw', cek, wrapKey, 'AES-KW'));
  var ph = { alg: alg, enc: enc, p2s: bytesToB64u(p2s), p2c: p2c };
  var phB64 = strToB64u(JSON.stringify(ph));
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var full = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, additionalData: new TextEncoder().encode(phB64), tagLength: 128 },
    cek, new TextEncoder().encode(plaintext)));
  var ct = full.slice(0, full.length - 16);
  var tag = full.slice(full.length - 16);
  return [phB64, bytesToB64u(wrapped), bytesToB64u(iv), bytesToB64u(ct), bytesToB64u(tag)].join('.');
}

function triggerDownload(filename, data, mime) {
  var blob = new Blob([data], { type: mime || 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
}

// step === 'sign' | 'enc'
async function downloadKeys(step) {
  var cfg = step === 'sign'
    ? { alg: val('sign_alg'), priv: val('sign_private_key'), pub: val('sign_public_key'),
        fmt: val('sign_ks_format'), pw: val('sign_ks_password'), status: 'sign_status', base: 'jwt-tools-signing-key', use: 'sig' }
    : { alg: val('jwe_alg'), priv: val('jwe_private_key'), pub: val('jwe_public_key'),
        fmt: val('jwe_ks_format'), pw: val('jwe_ks_password'), status: 'jwe_status', base: 'jwt-tools-encryption-key', use: 'enc' };

  function fail(msg) { setVal(cfg.status, msg); }

  try {
    var desc = certDescriptor(cfg.alg);

    // HMAC has no key pair — only a JWK (oct) makes sense.
    if (desc.kind === 'hmac') {
      if (cfg.fmt !== 'jwk') { fail('HMAC is a symmetric secret — only JWK export applies. Choose JWK.'); return false; }
      if (!cfg.priv.trim()) { fail('No secret to export. Generate or paste an HMAC secret first.'); return false; }
      var secret = isJwk(cfg.priv) ? (JSON.parse(cfg.priv).k || '') : cfg.priv.trim();
      var octJwk = { kty: 'oct', k: secret, alg: cfg.alg, use: cfg.use };
      var octText = JSON.stringify(octJwk, null, 2);
      if (cfg.pw) { triggerDownload(cfg.base + '.jwe', await pbes2JweEncrypt(octText, cfg.pw), 'application/jose'); }
      else { triggerDownload(cfg.base + '.jwk.json', octText, 'application/jwk+json'); }
      fail('Downloaded HMAC secret as JWK.');
      return false;
    }

    if (!cfg.priv.trim() || !cfg.pub.trim()) { fail('No key pair to export. Generate or paste a key pair first.'); return false; }

    // The key fields may hold PEM or JWK (per the format toggle); the export
    // paths below all work from PEM, so normalize JWK inputs first.
    if (isJwk(cfg.priv)) cfg.priv = await privToPem(cfg.priv, desc);
    if (isJwk(cfg.pub)) cfg.pub = await pubToPem(cfg.pub, desc);

    if (cfg.fmt === 'pkcs12') {
      if (!cfg.pw) { fail('PKCS#12 requires a password. Enter one in the password field.'); return false; }
      var p12 = await buildPkcs12(cfg.priv, cfg.pub, desc, cfg.pw);
      triggerDownload(cfg.base + '.p12', p12, 'application/x-pkcs12');
      fail('Downloaded password-protected PKCS#12 (.p12).');
      return false;
    }

    if (cfg.fmt === 'pem') {
      var privBlock;
      if (cfg.pw) { privBlock = derToPem(await encryptedPkcs8Der(pemToDer(cfg.priv), cfg.pw), 'ENCRYPTED PRIVATE KEY'); }
      else { privBlock = cfg.priv.trim() + '\n'; }
      var combined = privBlock + '\n' + cfg.pub.trim() + '\n';
      triggerDownload(cfg.base + '.pem', combined, 'application/x-pem-file');
      fail(cfg.pw ? 'Downloaded PEM (encrypted private key + public key).' : 'Downloaded PEM (private + public key).');
      return false;
    }

    if (cfg.fmt === 'der') {
      var privDer = cfg.pw ? await encryptedPkcs8Der(pemToDer(cfg.priv), cfg.pw) : pemToDer(cfg.priv);
      triggerDownload(cfg.base + '-private.der', privDer, 'application/pkcs8');
      triggerDownload(cfg.base + '-public.der', pemToDer(cfg.pub), 'application/octet-stream');
      fail(cfg.pw ? 'Downloaded DER (encrypted private + public), two files.' : 'Downloaded DER (private + public), two files.');
      return false;
    }

    if (cfg.fmt === 'jwk') {
      var pair = await keysToJwk(cfg.priv, cfg.pub, desc, cfg.alg, cfg.use);
      var jwks = { keys: [pair.publicKey, pair.privateKey] };
      var jwksText = JSON.stringify(jwks, null, 2);
      if (cfg.pw) { triggerDownload(cfg.base + '.jwe', await pbes2JweEncrypt(jwksText, cfg.pw), 'application/jose'); fail('Downloaded PBES2-encrypted JWK set (.jwe).'); }
      else { triggerDownload(cfg.base + '.jwk.json', jwksText, 'application/jwk+json'); fail('Downloaded JWK set (public + private).'); }
      return false;
    }

    fail('Unknown keystore format: ' + cfg.fmt);
  } catch (e) {
    log.error('downloadKeys(' + step + '): ' + e.message);
    setVal(cfg.status, 'Error: ' + e.message);
  }
  return false;
}

function downloadSigningKeys() { return downloadKeys('sign'); }
function downloadEncryptionKeys() { return downloadKeys('enc'); }

// ---------------------------------------------------------------------------
// Copy a field's contents to the clipboard.
// ---------------------------------------------------------------------------
function copyField(elementId) {
  var el = document.getElementById(elementId);
  if (!el) { log.error('copyField: element not found: ' + elementId); return false; }
  var text = el.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error('copyField: ' + err); });
  } else {
    // Fallback for browsers without the async clipboard API.
    try { el.focus(); el.select(); document.execCommand('copy'); } catch (e) { log.error('copyField fallback: ' + e.message); }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Tab switching (matches token_detail look and feel)
// ---------------------------------------------------------------------------
function populateTable(evt, tabName) {
  var i, tabcontent = document.getElementsByClassName('tabcontent');
  for (i = 0; i < tabcontent.length; i++) tabcontent[i].style.display = 'none';
  var tablinks = document.getElementsByClassName('tablinks');
  for (i = 0; i < tablinks.length; i++) tablinks[i].className = tablinks[i].className.replace(' active', '');
  document.getElementById(tabName).style.display = 'block';
  evt.currentTarget.className += ' active';
}

// ---------------------------------------------------------------------------
// "Return to debugger" link — point back at whichever page sent us here.
// Only known debugger pages are honoured to avoid an open redirect.
// ---------------------------------------------------------------------------
function setReturnLink() {
  var allowed = { 'debugger.html': '/debugger.html', 'debugger2.html': '/debugger2.html' };
  var from = new URLSearchParams(window.location.search).get('from');
  var target = allowed[from] || '/debugger.html';
  var link = document.getElementById('return_link');
  if (link) link.setAttribute('href', target);
}

// ---------------------------------------------------------------------------
// Initial (garbage) values
// ---------------------------------------------------------------------------
window.onload = function () {
  log.debug('Entering onload function.');
  setReturnLink();
  var now = Math.floor(Date.now() / 1000);
  var header = { alg: 'RS256', typ: 'JWT', kid: 'garbage-key-id-0001' };
  var payload = {
    iss: 'https://garbage.example.com',
    sub: 'garbage-subject-1234',
    aud: 'garbage-audience',
    exp: now + 3600,
    nbf: now,
    iat: now,
    jti: 'garbage-jti-abcdef'
  };
  setVal('jwt_tools_header', JSON.stringify(header, null, 2));
  setVal('jwt_tools_payload', JSON.stringify(payload, null, 2));
  updateEncoded();
};

module.exports = {
  updateEncoded,
  onEncodedInput,
  addClaim,
  checkCompliance,
  checkRfc9068Compliance,
  generateRfc9068Token,
  generateSigningKeys,
  signJWT,
  verifyJWT,
  generateEncryptionKeys,
  encryptJWT,
  decryptJWT,
  downloadSigningKeys,
  downloadEncryptionKeys,
  toggleKeyFormat,
  syncVerificationKey,
  copyField,
  populateTable
};
