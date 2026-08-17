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
// JWE, and the byte helpers it needs, shared with the OID4VCI issuance panes.
var jose = require("./jose_jwe");
// Key pairs, the PEM<->JWK conversion and every keystore format used to live in
// THIS file. They were extracted into these two so that the PKI page
// (client/public/pki.html) could have the same key-pair pane and the same
// export matrix rather than a second implementation of them — these encodings
// are read by OpenSSL, keytool and somebody else's TLS stack, and two readings
// of a wire format can agree with each other and both be wrong. What is left
// here is this page's DOM around them.
var keys = require("./key_material");
var x509 = require("./x509");
var log = bunyan.createLogger({ name: 'jwt_tools',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------
function val(id) {
  log.debug("Entering val().");
  var el = document.getElementById(id);
  log.debug("Leaving val().");
  return el ? el.value : '';
}

function setVal(id, v) {
  log.debug("Entering setVal().");
  var el = document.getElementById(id);
  if (el) el.value = v;
  log.debug("Leaving setVal().");
}

// ---------------------------------------------------------------------------
// Base64url / PEM / byte helpers, and everything JWE.
//
// These live in client/src/jose_jwe.js, which this page and the OID4VCI
// issuance panes share: OID4VCI section 10 has a Credential Issuer and a Wallet
// encrypting to each other, and the Concat KDF in particular must exist exactly
// once — two independent readings of RFC 7518 section 4.6 can agree with each
// other and still be wrong.
// ---------------------------------------------------------------------------
var bytesToB64u = jose.bytesToB64u;
var strToB64u = jose.strToB64u;
var b64uToBytes = jose.b64uToBytes;
var b64uToStr = jose.b64uToStr;
var derToPem = jose.derToPem;
var pemToDer = jose.pemToDer;
var concatBytes = jose.concatBytes;
var uint32be = jose.uint32be;

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
  ES512: { kind: 'ec', name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' },
  // RFC 8037 — EdDSA over the Edwards curve. Web Crypto supports Ed25519
  // (Ed448 is spec-defined but not available in the Web Crypto API).
  EdDSA: { kind: 'okp', name: 'Ed25519' }
};

// JWE algorithm tables, from the shared module.
var ENC_KEY_BYTES = jose.ENC_KEY_BYTES;
var JWE_RSA_HASH = jose.JWE_RSA_HASH;
var ECDH_KW_BYTES = jose.ECDH_KW_BYTES;
var isEcdh = jose.isEcdh;

// ---------------------------------------------------------------------------
// Composition: keep header / payload / encoded in sync
// ---------------------------------------------------------------------------
function parseJson(id, label) {
  log.debug("Entering parseJson().");
  var raw = val(id);
  var obj = JSON.parse(raw);
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error(label + ' must be a JSON object.');
  }
  log.debug("Leaving parseJson().");
  return obj;
}

// Rebuild the unsigned encoded token (header.payload) from the current
// Header/Payload text. Called whenever either textarea changes.
function updateEncoded() {
  log.debug("Entering updateEncoded().");
  try {
    var header = parseJson('jwt_tools_header', 'JWT Header');
    var payload = parseJson('jwt_tools_payload', 'JWT Payload');
    var encoded = strToB64u(JSON.stringify(header)) + '.' +
        strToB64u(JSON.stringify(payload)) + '.';
    setVal('jwt_tools_encoded', encoded);
    setVal('jwt_tools_sync_status',
           'In sync (unsigned). Sign or encrypt to produce a complete token.');
  } catch (e) {
    setVal('jwt_tools_sync_status', 'Cannot encode: ' + e.message);
  }
  log.debug("Leaving updateEncoded().");
  return false;
}

// The Encoded JWT field is editable: when the user pastes/types a token, decode
// its header and payload into those fields. If it carries a signature (third
// segment), capture the whole token into the Sign pane's "Signed JWT" and
// "JWT to Verify" fields. Programmatic setVal() does not fire oninput, so this
// does not loop with updateEncoded().
function onEncodedInput() {
  log.debug("Entering onEncodedInput().");
  var encoded = val('jwt_tools_encoded').trim();
  if (!encoded) {
    setVal('jwt_tools_sync_status', 'Encoded JWT is empty.');
    log.debug("Leaving onEncodedInput().");
    return false;
  }
  var parts = encoded.split('.');
  if (parts.length < 2 || !parts[0] || !parts[1]) {
    setVal('jwt_tools_sync_status',
           'Not a JWT — expected header.payload[.signature].');
    log.debug("Leaving onEncodedInput().");
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
      setVal('jwt_tools_sync_status', 'Decoded header & payload; signature ' +
             'captured (populated Signed JWT and JWT to Verify in the ' +
             'Sign pane).');
    } else {
      setVal('jwt_tools_sync_status',
             'Decoded header & payload (no signature present).');
    }
  } catch (e) {
    setVal('jwt_tools_sync_status', 'Cannot decode JWT: ' + e.message);
  }
  log.debug("Leaving onEncodedInput().");
  return false;
}

// Add a custom claim to either the Header or the Payload object.
function addClaim() {
  log.debug("Entering addClaim().");
  var name = val('custom_claim_name').trim();
  var rawValue = val('custom_claim_value');
  var type = val('custom_claim_type');
  var target =
      val('custom_claim_target'); // 'jwt_tools_header' | 'jwt_tools_payload'

  if (!name) {
    setVal('jwt_tools_sync_status', 'Custom claim requires a name.');
    log.debug("Leaving addClaim().");
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
      if (!isFinite(value)) throw new Error('"' + trimmed +
          '" is not a valid number.');
    } else if (type === 'boolean') {
      value = (rawValue.trim().toLowerCase() === 'true');
    } else if (type === 'json') {
      value = JSON.parse(rawValue);
    } else {
      value = rawValue;
    }
  } catch (e) {
    setVal('jwt_tools_sync_status', 'Cannot add claim: ' + e.message);
    log.debug("Leaving addClaim().");
    return false;
  }

  try {
    var obj = parseJson(target, target === 'jwt_tools_header' ?
        'JWT Header' : 'JWT Payload');
    obj[name] = value;
    setVal(target, JSON.stringify(obj, null, 2));
    setVal('custom_claim_name', '');
    setVal('custom_claim_value', '');
    updateEncoded();
  } catch (e) {
    setVal('jwt_tools_sync_status', 'Cannot add claim: ' + e.message);
  }
  log.debug("Leaving addClaim().");
  return false;
}

// Confirm the composed header/payload are still spec-compliant (RFC 7519 /
// RFC 7515 for the JOSE header). Reports PASS/FAIL/SKIP per check.
function checkCompliance() {
  log.debug("Entering checkCompliance().");
  var results = [];
  function pass(c, m) {
    log.debug("Entering pass().");
    results.push('PASS  ' + c + ': ' + m);
    log.debug("Leaving pass().");
  }
  function fail(c, m) {
    log.debug("Entering fail().");
    results.push('FAIL  ' + c + ': ' + m);
    log.debug("Leaving fail().");
  }
  function skip(c, m) {
    log.debug("Entering skip().");
    results.push('SKIP  ' + c + ': ' + m);
    log.debug("Leaving skip().");
  }

  var header, payload;
  try {
    header = parseJson('jwt_tools_header', 'JWT Header');
  } catch (e) {
    setVal('compliance_output', 'FAIL  header: ' + e.message);
    log.debug("Leaving checkCompliance().");
    return false;
  }
  try {
    payload = parseJson('jwt_tools_payload', 'JWT Payload');
  } catch (e) {
    setVal('compliance_output', 'FAIL  payload: ' + e.message);
    log.debug("Leaving checkCompliance().");
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
    log.debug("Entering checkString().");
    if (payload[name] === undefined) {
      skip(name, 'Not present (optional)');
      log.debug("Leaving checkString().");
      return;
    }
    if (typeof payload[name] !== 'string') fail(name,
        'Must be a StringOrURI (string)');
    else pass(name, '"' + payload[name] + '"');
    log.debug("Leaving checkString().");
  }
  function checkNumericDate(name) {
    log.debug("Entering checkNumericDate().");
    if (payload[name] === undefined) {
      skip(name, 'Not present (optional)');
      log.debug("Leaving checkNumericDate().");
      return;
    }
    if (typeof payload[name] !== 'number' || !Number.isInteger(payload[name])) {
      fail(name, 'Must be an integer NumericDate (RFC 7519 §2)');
    } else {
      pass(name, new Date(payload[name] * 1000).toISOString());
    }
    log.debug("Leaving checkNumericDate().");
  }

  checkString('iss');
  checkString('sub');

  // aud may be a StringOrURI or an array of StringOrURI (RFC 7519 §4.1.3)
  if (payload.aud === undefined) {
    skip('aud', 'Not present (optional)');
  } else if (typeof payload.aud === 'string') {
    pass('aud', '"' + payload.aud + '"');
  } else if (Array.isArray(payload.aud) &&
      payload.aud.every(function (a) { return typeof a === 'string'; })) {
    pass('aud', payload.aud.length + ' value(s)');
  } else {
    fail('aud', 'Must be a string or array of strings');
  }

  checkNumericDate('exp');
  checkNumericDate('nbf');
  checkNumericDate('iat');
  checkString('jti');

  setVal('compliance_output', results.join('\n'));
  log.debug("Leaving checkCompliance().");
  return false;
}

// Validate the composed header/payload as an OAuth 2.0 JWT access token per
// RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens). Output goes to the same
// Compliance Output box. Header (§2.1): typ MUST be "at+jwt" and the token MUST
// be signed (alg present, not "none"). Required claims (§2.2): iss, exp, aud,
// sub, client_id, iat, jti. scope is conditionally recommended (§2.2.3);
// auth_time/acr/amr are optional (§2.2.1) and only type-checked if present.
function checkRfc9068Compliance() {
  log.debug("Entering checkRfc9068Compliance().");
  var results = [];
  function pass(c, m) {
    log.debug("Entering pass().");
    results.push('PASS  ' + c + ': ' + m);
    log.debug("Leaving pass().");
  }
  function fail(c, m) {
    log.debug("Entering fail().");
    results.push('FAIL  ' + c + ': ' + m);
    log.debug("Leaving fail().");
  }
  function skip(c, m) {
    log.debug("Entering skip().");
    results.push('SKIP  ' + c + ': ' + m);
    log.debug("Leaving skip().");
  }

  var header, payload;
  try {
    header = parseJson('jwt_tools_header', 'JWT Header');
  } catch (e) {
    setVal('compliance_output', 'FAIL  header: ' + e.message);
    log.debug("Leaving checkRfc9068Compliance().");
    return false;
  }
  try {
    payload = parseJson('jwt_tools_payload', 'JWT Payload');
  } catch (e) {
    setVal('compliance_output', 'FAIL  payload: ' + e.message);
    log.debug("Leaving checkRfc9068Compliance().");
    return false;
  }

  results.push('RFC 9068 — OAuth 2.0 JWT Access Token');

  // ---- Header (RFC 9068 §2.1) ---- typ is REQUIRED and MUST be "at+jwt" (the
  // "application/" prefix is allowed).
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
    fail('alg', '"none" is not permitted — access tokens MUST be signed (RFC ' +
         '9068 §2.1)');
  } else {
    pass('alg', header.alg);
  }

  // ---- Required claims (RFC 9068 §2.2) ----
  function requireString(name) {
    log.debug("Entering requireString().");
    if (payload[name] === undefined) fail(name,
        'Missing required claim (RFC 9068 §2.2)');
    else if (typeof payload[name] !== 'string') fail(name, 'Must be a string');
    else pass(name, '"' + payload[name] + '"');
    log.debug("Leaving requireString().");
  }
  function requireNumericDate(name) {
    log.debug("Entering requireNumericDate().");
    if (payload[name] === undefined) fail(name,
        'Missing required claim (RFC 9068 §2.2)');
    else if (typeof payload[name] !== 'number' ||
             !Number.isInteger(payload[name])) fail(name,
             'Must be an integer NumericDate');
    else pass(name, new Date(payload[name] * 1000).toISOString());
    log.debug("Leaving requireNumericDate().");
  }

  requireString('iss');
  requireNumericDate('exp');

  // aud is REQUIRED: a StringOrURI or a non-empty array of them.
  if (payload.aud === undefined) {
    fail('aud', 'Missing required claim (RFC 9068 §2.2)');
  } else if (typeof payload.aud === 'string') {
    pass('aud', '"' + payload.aud + '"');
  } else if (Array.isArray(payload.aud) && payload.aud.length > 0 &&
      payload.aud.every(function (a) { return typeof a === 'string'; })) {
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
    skip('scope', 'Not present (SHOULD be present if a scope was requested — ' +
         'RFC 9068 §2.2.3)');
  } else if (typeof payload.scope !== 'string') {
    fail('scope', 'Must be a space-delimited string (RFC 9068 §2.2.3)');
  } else {
    pass('scope', '"' + payload.scope + '"');
  }

  // Authentication information claims are optional (RFC 9068 §2.2.1).
  if (payload.auth_time !== undefined) {
    if (typeof payload.auth_time !== 'number' ||
        !Number.isInteger(payload.auth_time)) fail('auth_time',
        'Must be an integer NumericDate');
    else pass('auth_time', new Date(payload.auth_time * 1000).toISOString());
  }
  if (payload.acr !== undefined) {
    if (typeof payload.acr !== 'string') fail('acr', 'Must be a string');
    else pass('acr', '"' + payload.acr + '"');
  }
  if (payload.amr !== undefined) {
    if (Array.isArray(payload.amr) && payload.amr.every(function (a) {
        return typeof a === 'string'; })) pass('amr', payload.amr.length +
        ' value(s)');
    else fail('amr', 'Must be an array of strings');
  }

  setVal('compliance_output', results.join('\n'));
  log.debug("Leaving checkRfc9068Compliance().");
  return false;
}

// Populate Header, Payload, and the Encoded JWT with a sample RFC 9068 access
// token: header carries alg + typ "at+jwt"; payload carries the required claims
// (iss, exp, aud, sub, client_id, iat, jti) plus a scope. Produced unsigned
// (header.payload.) — sign it in the Sign pane to complete it.
function generateRfc9068Token() {
  log.debug("Entering generateRfc9068Token().");
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
  updateEncoded(
      ); // fills the Encoded JWT field (header.payload.) from the above
  setVal('jwt_tools_sync_status', 'Generated a sample RFC 9068 access token ' +
         '(unsigned). Sign it in the Sign (JWS) pane to complete it.');
  log.debug("Leaving generateRfc9068Token().");
  return false;
}

// ---------------------------------------------------------------------------
// Digital signatures (JWS)
// ---------------------------------------------------------------------------
async function generateSigningKeys() {
  log.debug("Entering generateSigningKeys().");
  var alg = val('sign_alg');
  var meta = SIGN_ALGS[alg];
  setVal('sign_status', 'Generating ' + alg + ' key material...');
  try {
    if (meta.kind === 'hmac') {
      setVal('sign_private_key', keys.generateSecret(32));
      setVal('sign_public_key', '(HMAC is symmetric — the secret above is ' +
             'used for both signing and verification.)');
    } else {
      // One call for all three asymmetric families. The descriptor is this
      // page's SIGN_ALGS entry, whose vocabulary key_material.js shares because
      // that table is where it came from; `curve` is spelled `namedCurve` here,
      // which is the one difference and is bridged rather than propagated.
      var pair = await keys.generateKeyPair({
        kind: meta.kind,
        name: meta.name,
        hash: meta.hash,
        curve: meta.namedCurve,
        bits: parseInt(val('sign_rsa_bits'), 10) || 2048
      });
      setVal('sign_private_key', pair.privatePem);
      setVal('sign_public_key', pair.publicPem);
    }
    await applyKeyFormat('sign'); // honor the PEM/JWK toggle
    await syncVerificationKey();  // keep X.509 verification key in sync
    setVal('sign_status', 'Generated ' + alg + ' key material.');
  } catch (e) {
    log.error('generateSigningKeys: ' + e.message);
    setVal('sign_status', 'Error: ' + e.message);
  }
  log.debug("Leaving generateSigningKeys().");
  return false;
}

async function importSigningKey(meta, keyText) {
  log.debug("Entering importSigningKey().");
  if (meta.kind === 'hmac') {
    var secret = isJwk(keyText) ? (JSON.parse(keyText).k ||
        '') : keyText.trim();
    log.debug("Leaving importSigningKey().");
    return crypto.subtle.importKey('raw', b64uToBytes(secret),
      { name: 'HMAC', hash: meta.hash }, false, ['sign']);
  }
  var params = meta.kind === 'rsa'
    ? { name: meta.name, hash: meta.hash }
    : meta.kind === 'okp'
      ? { name: meta.name }
      : { name: 'ECDSA', namedCurve: meta.namedCurve };
  log.debug("Leaving importSigningKey().");
  return importKeyFlexible(keyText, 'pkcs8', params, ['sign']);
}

async function signJWT() {
  log.debug("Entering signJWT().");
  var alg = val('sign_alg');
  var meta = SIGN_ALGS[alg];
  setVal('sign_status', 'Signing with ' + alg + '...');
  try {
    // Force the header alg to match the selected signing algorithm.
    var header = parseJson('jwt_tools_header', 'JWT Header');
    header.alg = alg;
    setVal('jwt_tools_header', JSON.stringify(header, null, 2));
    var payload = parseJson('jwt_tools_payload', 'JWT Payload');

    var signingInput = strToB64u(JSON.stringify(header)) + '.' +
        strToB64u(JSON.stringify(payload));
    var key = await importSigningKey(meta, val('sign_private_key'));

    var signParams;
    if (meta.kind === 'hmac') signParams = { name: 'HMAC' };
    else if (meta.kind === 'rsa' && meta.name === 'RSA-PSS') signParams =
             { name: 'RSA-PSS', saltLength: meta.saltLength };
    else if (meta.kind === 'rsa') signParams = { name: 'RSASSA-PKCS1-v1_5' };
    else if (meta.kind === 'okp') signParams = { name: meta.name };
    else signParams = { name: 'ECDSA', hash: meta.hash };

    var sig = await crypto.subtle.sign(signParams, key,
        new TextEncoder().encode(signingInput));
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
  log.debug("Leaving signJWT().");
  return false;
}

// ---- Signature verification (mirrors token_detail.js) ----
async function verifyHMAC(jwt_, secret, alg) {
  log.debug("Entering verifyHMAC().");
  var meta = SIGN_ALGS[alg];
  if (!meta ||
      meta.kind !== 'hmac') throw new Error('Unsupported HMAC algorithm: ' +
      alg);
  var key = await crypto.subtle.importKey('raw', b64uToBytes(secret.trim()),
    { name: 'HMAC', hash: meta.hash }, false, ['verify']);
  var data = new TextEncoder().encode(jwt_.split('.').slice(0, 2).join('.'));
  log.debug("Leaving verifyHMAC().");
  return crypto.subtle.verify('HMAC', key, b64uToBytes(jwt_.split('.')[2]),
                              data);
}

async function verifyX509(jwt_, pem, alg) {
  log.debug("Entering verifyX509().");
  var meta = SIGN_ALGS[alg];
  if (!meta || (meta.kind !== 'rsa' && meta.kind !== 'ec' &&
      meta.kind !== 'okp')) {
    throw new Error('Unsupported asymmetric algorithm: ' + alg);
  }
  var importParams, verifyParams;
  if (meta.kind === 'ec') {
    importParams = { name: 'ECDSA', namedCurve: meta.namedCurve };
    verifyParams = { name: 'ECDSA', hash: meta.hash };
  } else if (meta.kind === 'okp') {
    importParams = { name: meta.name };
    verifyParams = { name: meta.name };
  } else {
    importParams = { name: meta.name, hash: meta.hash };
    verifyParams = meta.name === 'RSA-PSS' ? { name: 'RSA-PSS',
        saltLength: meta.saltLength } : { name: 'RSASSA-PKCS1-v1_5' };
  }
  var key = await crypto.subtle.importKey('spki', pemToDer(pem), importParams,
      false, ['verify']);
  var data = new TextEncoder().encode(jwt_.split('.').slice(0, 2).join('.'));
  log.debug("Leaving verifyX509().");
  return crypto.subtle.verify(verifyParams, key,
                              b64uToBytes(jwt_.split('.')[2]), data);
}

async function verifyJWKS(jwt_, jwks) {
  log.debug("Entering verifyJWKS().");
  var header = JSON.parse(b64uToStr(jwt_.split('.')[0]));
  if (!header.kid) throw new Error('No "kid" found in JWT header.');
  var jwk = jwks.keys.find(function (k) { return k.kid === header.kid; });
  if (!jwk) throw new Error('Matching "kid" not found in JWKS.');
  if (jwk.kty !== 'RSA') throw new Error('Only RSA keys are supported for ' +
      'JWKS verification.');
  var meta = SIGN_ALGS[header.alg];
  if (!meta || meta.kind !== 'rsa') throw new Error('Unsupported algorithm: ' +
      header.alg);
  var key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n,
      e: jwk.e },
    { name: meta.name, hash: meta.hash }, false, ['verify']);
  var data = new TextEncoder().encode(jwt_.split('.').slice(0, 2).join('.'));
  var verifyParams = meta.name === 'RSA-PSS' ? { name: 'RSA-PSS',
      saltLength: meta.saltLength } : { name: 'RSASSA-PKCS1-v1_5' };
  log.debug("Leaving verifyJWKS().");
  return crypto.subtle.verify(verifyParams, key,
                              b64uToBytes(jwt_.split('.')[2]), data);
}

async function verifyJWT() {
  log.debug("Entering verifyJWT().");
  var type = val('jwt_verification_type');
  var key = val('jwt_verification_key');
  var jwt_ = val('verify_input').trim();
  var isValid = false;
  try {
    var parts = jwt_.split('.');
    if (parts.length !== 3 || !parts[0] || !parts[1] ||
        !parts[2]) throw new Error('Invalid JWS compact format.');
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
  log.debug("Leaving verifyJWT().");
  return false;
}

// ---------------------------------------------------------------------------
// Encryption (JWE) — compact serialization, RFC 7516 / 7518
// ---------------------------------------------------------------------------
// ECDH-ES key agreement is limited to the P-256 curve in this tool.
var ECDH_CURVE = jose.ECDH_CURVE;

async function generateEncryptionKeys() {
  log.debug("Entering generateEncryptionKeys().");
  var alg = val('jwe_alg');
  setVal('jwe_status', 'Generating ' + alg + ' key material...');
  try {
    var pair;
    if (isEcdh(alg)) {
      pair = await crypto.subtle.generateKey({ name: 'ECDH',
          namedCurve: ECDH_CURVE }, true, ['deriveBits']);
    } else {
      var jweBits = parseInt(val('jwe_rsa_bits'), 10) || 2048;
      pair = await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: jweBits,
         publicExponent: new Uint8Array([1, 0, 1]), hash: JWE_RSA_HASH[alg] },
        true, ['encrypt', 'decrypt']);
    }
    setVal('jwe_public_key', derToPem(await crypto.subtle.exportKey('spki',
           pair.publicKey), 'PUBLIC KEY'));
    setVal('jwe_private_key', derToPem(await crypto.subtle.exportKey('pkcs8',
           pair.privateKey), 'PRIVATE KEY'));
    await applyKeyFormat('enc'); // honor the PEM/JWK toggle
    setVal('jwe_status', 'Generated ' + alg + ' key material' + (isEcdh(alg) ?
           ' (P-256).' : '.'));
  } catch (e) {
    log.error('generateEncryptionKeys: ' + e.message);
    setVal('jwe_status', 'Error: ' + e.message);
  }
  log.debug("Leaving generateEncryptionKeys().");
  return false;
}

async function encryptJWT() {
  log.debug("Entering encryptJWT().");
  var alg = val('jwe_alg');
  var enc = val('jwe_enc');
  var plaintext = val('jwe_plaintext').trim();
  setVal('jwe_status', 'Encrypting with ' + alg + ' / ' + enc + '...');
  try {
    if (!plaintext) throw new Error('Nothing to encrypt. Sign a JWT or enter ' +
        'a payload above.');
    if (!ENC_KEY_BYTES[enc]) throw new Error('Unsupported content ' +
        'encryption: ' + enc);

    var protectedHeader = { alg: alg, enc: enc };
    // A nested JWT (a JWS as the plaintext) is signalled with cty:"JWT" (RFC
    // 7519 §5.2).
    if (plaintext.split('.').length === 3) protectedHeader.cty = 'JWT';

    var derived = await jose.deriveCek(alg, enc, protectedHeader,
        val('jwe_public_key'));
    var protectedB64 = strToB64u(JSON.stringify(protectedHeader));
    var aad = new TextEncoder()
        .encode(protectedB64); // ASCII(BASE64URL(protected header))

    var iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    var full = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, additionalData: aad, tagLength: 128 },
      derived.cek, new TextEncoder().encode(plaintext)));

    // Web Crypto appends the 16-byte auth tag; JWE keeps ciphertext and tag
    // separate.
    var ciphertext = full.slice(0, full.length - 16);
    var tag = full.slice(full.length - 16);

    var jwe = [protectedB64, derived.encryptedKey, bytesToB64u(iv),
        bytesToB64u(ciphertext), bytesToB64u(tag)].join('.');
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
      if (composeHeader === null || typeof composeHeader !== 'object' ||
          Array.isArray(composeHeader)) composeHeader = {};
    } catch (e) {
      composeHeader = {};
    }
    Object.keys(protectedHeader).forEach(function (k) {
      if (k === 'alg') return; // preserve the JWS signing "alg"
      composeHeader[k] = protectedHeader[k];
    });
    setVal('jwt_tools_header', JSON.stringify(composeHeader, null, 2));

    setVal('jwe_status', 'JWE produced with ' + alg + ' / ' + enc + '.');
    setVal('jwt_tools_sync_status',
           'Encoded field now holds the JWE encrypted token.');
  } catch (e) {
    log.error('encryptJWT: ' + e.message);
    setVal('jwe_status', 'Error: ' + e.message);
  }
  log.debug("Leaving encryptJWT().");
  return false;
}

async function decryptJWT() {
  log.debug("Entering decryptJWT().");
  var jwe = val('jwe_decrypt_input').trim();
  setVal('jwe_status', 'Decrypting...');
  try {
    var parts = jwe.split('.');
    if (parts.length !== 5) throw new Error('Invalid JWE compact format ' +
        '(expected 5 segments).');
    var protectedHeader = JSON.parse(b64uToStr(parts[0]));
    var alg = protectedHeader.alg;
    var enc = protectedHeader.enc;
    if (!ENC_KEY_BYTES[enc]) throw new Error('Unsupported content ' +
        'encryption: ' + enc);

    var cekKey = await jose.unwrapCek(alg, enc, protectedHeader, parts[1],
        val('jwe_private_key'));
    var aad = new TextEncoder().encode(parts[0]);
    var iv = b64uToBytes(parts[2]);
    var ctPlusTag = concatBytes(b64uToBytes(parts[3]), b64uToBytes(parts[4]));

    var plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, additionalData: aad, tagLength: 128 }, cekKey,
       ctPlusTag);
    setVal('jwe_decrypt_output', new TextDecoder().decode(plaintext));
    setVal('jwe_status', 'Decrypted with ' + alg + ' / ' + enc + '.');
  } catch (e) {
    log.error('decryptJWT: ' + e.message);
    setVal('jwe_status', 'Error: ' + e.message);
    setVal('jwe_decrypt_output', '');
  }
  log.debug("Leaving decryptJWT().");
  return false;
}

// ---------------------------------------------------------------------------
// Keystore export / download (PEM, DER, JWK, PKCS#12)
//
// Key material is only read from the on-page fields and turned into a
// downloadable Blob — nothing is persisted. PKCS#12 wraps the private key in a
// self-signed certificate so it imports into OpenSSL / keytool / etc.
// ---------------------------------------------------------------------------
// Everything from here to the download button is client/src/key_material.js
// now, named locally so the call sites below read as they always did. The
// descriptor vocabulary is unchanged ('rsa' | 'ec' | 'okp' | 'hmac'), because
// that table came from this file in the first place.
var certDescriptor = keys.certDescriptor;
var isJwk = keys.isJwk;
var privToJwk = keys.privToJwk;
var pubToJwk = keys.pubToJwk;
var privToPem = keys.privToPem;
var pubToPem = keys.pubToPem;

// Import a key that may be PEM or JWK, under the given params/usages. The
// shared JOSE module does exactly this (and also accepts a JWK object or an
// already-imported CryptoKey), so this is its name on this page rather than a
// second copy.
function importKeyFlexible(text, format, params, usages) {
  log.debug("Entering importKeyFlexible().");
  log.debug("Leaving importKeyFlexible().");
  return jose.importKey(text, format, params, usages);
}

// Make both key fields of a step match the current toggle (PEM or JWK).
async function applyKeyFormat(step) {
  log.debug("Entering applyKeyFormat().");
  var s = step === 'sign';
  var toJwk = document.getElementById(s ?
      'sign_key_jwk' : 'jwe_key_jwk').checked;
  var alg = val(s ? 'sign_alg' : 'jwe_alg');
  var desc = certDescriptor(alg);
  var privId = s ? 'sign_private_key' : 'jwe_private_key';
  var pubId = s ? 'sign_public_key' : 'jwe_public_key';
  var use = s ? 'sig' : 'enc';
  var statusId = s ? 'sign_status' : 'jwe_status';
  try {
    if (desc.kind === 'hmac') {
      // Symmetric: represent the secret as a base64url string (PEM mode) or oct
      // JWK.
      var cur = val(privId).trim();
      var secret = cur ? (isJwk(cur) ? (JSON.parse(cur).k || '') : cur) : '';
      if (secret) setVal(privId, toJwk ? JSON.stringify({ kty: 'oct', k: secret,
          alg: alg, use: 'sig' }, null, 2) : secret);
      log.debug("Leaving applyKeyFormat().");
      return false;
    }
    var priv = val(privId).trim();
    if (priv) {
      if (toJwk && !isJwk(priv)) setVal(privId,
          JSON.stringify(await privToJwk(priv, desc, alg, use), null, 2));
      else if (!toJwk && isJwk(priv)) setVal(privId, await privToPem(priv,
               desc));
    }
    var pub = val(pubId).trim();
    if (pub) {
      if (toJwk && !isJwk(pub)) setVal(pubId, JSON.stringify(await pubToJwk(pub,
          desc, alg, use), null, 2));
      else if (!toJwk && isJwk(pub)) setVal(pubId, await pubToPem(pub, desc));
    }
  } catch (e) {
    log.error('applyKeyFormat(' + step + '): ' + e.message);
    setVal(statusId, 'Key format conversion error: ' + e.message);
  }
  log.debug("Leaving applyKeyFormat().");
  return false;
}
function toggleKeyFormat(step) {
  log.debug("Entering toggleKeyFormat().");
  log.debug("Leaving toggleKeyFormat().");
  return applyKeyFormat(step);
}

// When the Validate-a-Signature type is "X.509 Certificate (PEM)", default the
// verification key to the step's generated public key (as SPKI PEM). Converts
// from JWK if the key fields are in JWK mode. No-op for other types / HMAC.
async function syncVerificationKey() {
  log.debug("Entering syncVerificationKey().");
  try {
    if (val('jwt_verification_type') !== 'x509') {
      log.debug("Leaving syncVerificationKey().");
      return false;
    }
    if (val('jwt_verification_key').trim()) {
      log.debug("Leaving syncVerificationKey().");
      return false;
    } // don't clobber a manual entry
    var pub = val('sign_public_key').trim();
    if (!pub) {
      log.debug("Leaving syncVerificationKey().");
      return false;
    }
    var desc = certDescriptor(val('sign_alg'));
    if (desc.kind === 'hmac') {
      log.debug("Leaving syncVerificationKey().");
      return false;
    } // no public key for HMAC
    setVal('jwt_verification_key', isJwk(pub) ? await pubToPem(pub,
           desc) : pub);
  } catch (e) {
    log.error('syncVerificationKey: ' + e.message);
  }
  log.debug("Leaving syncVerificationKey().");
  return false;
}

// The self-signed certificate this page needs in two places: the PKCS#12
// export has to wrap the private key in one, and "View certificate" shows one.
//
// It is client/src/x509.js's issueCertificate() rather than fifteen lines of
// pkijs here, which is not merely tidier: that module knows that pkijs cannot
// import an Ed25519 public key and cannot sign with one, so this page gained
// Ed25519 certificates by deleting code. The subject and the fixed validity are
// this page's, because this certificate exists only to carry a key.
async function buildSelfSignedCertPem(privPem, pubPem, desc) {
  log.debug("Entering buildSelfSignedCertPem().");
  var issued = await x509.issueCertificate({
    subject: 'CN=jwt-tools generated key',
    subjectPublicKey: pubPem,
    issuerPrivateKey: privPem,
    signatureAlg: x509.defaultSignatureAlgorithm(desc),
    serial: '01',
    notBefore: new Date(Date.UTC(2020, 0, 1)),
    notAfter: new Date(Date.UTC(2035, 0, 1)),
    extensions: x509.defaultExtensions('tls-server')
  });
  log.debug("Leaving buildSelfSignedCertPem().");
  return issued.pem;
}

// Build a self-signed cert from the current signing key pair and open the
// certificate-details page (saml_cert.html) in a new tab. HMAC has no cert.
async function viewSigningCert() {
  log.debug("Entering viewSigningCert().");
  var desc = certDescriptor(val('sign_alg'));
  if (desc.kind === 'hmac') {
    setVal('sign_status', 'HMAC is symmetric — there is no X.509 certificate.');
    log.debug("Leaving viewSigningCert().");
    return false;
  }
  var priv = val('sign_private_key'), pub = val('sign_public_key');
  if (!priv.trim() || !pub.trim()) {
    setVal('sign_status', 'Generate a signing key pair first.');
    log.debug("Leaving viewSigningCert().");
    return false;
  }
  try {
    var privPem = await keys.asPrivatePem(priv, desc);
    var pubPem = await keys.asPublicPem(pub, desc);
    var pem = await buildSelfSignedCertPem(privPem, pubPem, desc);
    if (window.localStorage) localStorage.setItem('saml_cert_view', pem);
    window.open('/saml_cert.html?from=jwt_tools.html', '_blank');
  } catch (e) {
    log.error('viewSigningCert: ' + e.message);
    setVal('sign_status', 'Certificate error: ' + e.message);
  }
  log.debug("Leaving viewSigningCert().");
  return false;
}

// step === 'sign' | 'enc'
//
// The whole export matrix — PEM, DER, JWK set, PKCS#12, each of them optionally
// password-protected, plus the HMAC special case — is one call into
// client/src/key_material.js. It returns the FILES rather than downloading
// them, which is what lets tests/pki_key_formats.js produce every combination
// in node and read them back with OpenSSL; this page hands them to the browser
// and shows the status line it came back with.
//
// PKCS#12 needs a certificate to wrap the key in, and this page has none, so it
// mints the self-signed one above for the purpose. The PKI page passes a real
// chain to the same function.
async function downloadKeys(step) {
  log.debug("Entering downloadKeys().");
  var cfg = step === 'sign'
    ? { alg: val('sign_alg'), priv: val('sign_private_key'),
        pub: val('sign_public_key'),
        fmt: val('sign_ks_format'), pw: val('sign_ks_password'),
                 status: 'sign_status', base: 'jwt-tools-signing-key',
                 use: 'sig' }
    : { alg: val('jwe_alg'), priv: val('jwe_private_key'),
       pub: val('jwe_public_key'),
        fmt: val('jwe_ks_format'), pw: val('jwe_ks_password'),
                 status: 'jwe_status', base: 'jwt-tools-encryption-key',
                 use: 'enc' };
  try {
    var desc = certDescriptor(cfg.alg);
    var certs = [];
    if (cfg.fmt === 'pkcs12' && desc.kind !== 'hmac' && cfg.priv.trim() &&
        cfg.pub.trim()) {
      certs = [await buildSelfSignedCertPem(
        await keys.asPrivatePem(cfg.priv, desc),
        await keys.asPublicPem(cfg.pub, desc), desc)];
    }
    var result = await keys.exportKeyPair({
      format: cfg.fmt,
      privatePem: cfg.priv,
      publicPem: cfg.pub,
      desc: desc,
      password: cfg.pw,
      baseName: cfg.base,
      friendlyName: 'jwt-tools',
      alg: cfg.alg,
      use: cfg.use,
      certs: certs
    });
    setVal(cfg.status, keys.downloadFiles(result));
  } catch (e) {
    log.error('downloadKeys(' + step + '): ' + e.message);
    setVal(cfg.status, 'Error: ' + e.message);
  }
  log.debug("Leaving downloadKeys().");
  return false;
}

function downloadSigningKeys() {
  log.debug("Entering downloadSigningKeys().");
  log.debug("Leaving downloadSigningKeys().");
  return downloadKeys('sign');
}
function downloadEncryptionKeys() {
  log.debug("Entering downloadEncryptionKeys().");
  log.debug("Leaving downloadEncryptionKeys().");
  return downloadKeys('enc');
}

// ---------------------------------------------------------------------------
// Copy a field's contents to the clipboard.
// ---------------------------------------------------------------------------
function copyField(elementId) {
  log.debug("Entering copyField().");
  var el = document.getElementById(elementId);
  if (!el) {
    log.error('copyField: element not found: ' + elementId);
    log.debug("Leaving copyField().");
    return false;
  }
  var text = el.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error(
                                  'copyField: ' + err); });
  } else {
    // Fallback for browsers without the async clipboard API.
    try {
      el.focus();
      el.select();
      document.execCommand('copy');
    } catch (e) {
      log.error('copyField fallback: ' + e.message);
    }
  }
  log.debug("Leaving copyField().");
  return false;
}

// ---------------------------------------------------------------------------
// Tab switching (matches token_detail look and feel)
// ---------------------------------------------------------------------------
function populateTable(evt, tabName) {
  log.debug("Entering populateTable().");
  var i, tabcontent = document.getElementsByClassName('tabcontent');
  for (i = 0; i < tabcontent.length; i++) tabcontent[i].style.display = 'none';
  var tablinks = document.getElementsByClassName('tablinks');
  for (i = 0; i < tablinks.length; i++) tablinks[i].className =
       tablinks[i].className.replace(' active', '');
  document.getElementById(tabName).style.display = 'block';
  evt.currentTarget.className += ' active';
  log.debug("Leaving populateTable().");
}

// ---------------------------------------------------------------------------
// "Return to debugger" link — point back at whichever page sent us here.
// Only known debugger pages are honoured to avoid an open redirect.
// ---------------------------------------------------------------------------
function setReturnLink() {
  log.debug("Entering setReturnLink().");
  var allowed = { 'debugger.html': '/debugger.html',
      'debugger2.html': '/debugger2.html' };
  var from = new URLSearchParams(window.location.search).get('from');
  var target = allowed[from] || '/debugger.html';
  var link = document.getElementById('return_link');
  if (link) link.setAttribute('href', target);
  log.debug("Leaving setReturnLink().");
}

// ---------------------------------------------------------------------------
// Initial (garbage) values
// ---------------------------------------------------------------------------
// Mark the JWE options this browser cannot perform. RFC 7518 defines AES-192,
// Chrome's Web Crypto does not implement it, and offering an option that can
// only fail is worse than not offering it — the failure arrives as an
// OperationError from inside a key import, which explains nothing.
async function annotateUnsupportedJweOptions() {
  log.debug("Entering annotateUnsupportedJweOptions().");
  var support = await jose.probeAesSupport();
  [['jwe_alg', jose.algUnsupportedReason], ['jwe_enc',
   jose.encUnsupportedReason]].forEach(function (pair) {
    var select = document.getElementById(pair[0]);
    if (!select) return;
    Array.prototype.slice.call(select.options).forEach(function (option) {
      var reason = pair[1](option.value, support);
      if (!reason) return;
      option.disabled = true;
      if (option.textContent.indexOf("unsupported") === -1) {
        option.textContent = option.textContent + " — unsupported here (" +
            reason + ")";
      }
      log.debug("annotateUnsupportedJweOptions(): " + option.value +
                " is unusable: " + reason);
    });
    // If the page defaulted to one of them, move to something that works.
    if (select.selectedOptions.length && select.selectedOptions[0].disabled) {
      var usable = Array.prototype.slice.call(select.options)
          .filter(function (o) { return !o.disabled; })[0];
      if (usable) select.value = usable.value;
    }
  });
  log.debug("Leaving annotateUnsupportedJweOptions().");
}

window.onload = function () {
  log.debug("Entering onload().");
  log.debug('Entering onload function.');
  setReturnLink();
  annotateUnsupportedJweOptions().catch(function (e) {
    // Not being able to probe is not a reason to fail the page; the options
    // stay as they are and an attempt will report its own error.
    log.debug('annotateUnsupportedJweOptions: ' + e.message);
  });
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
  log.debug("Leaving onload().");
};

module.exports = {
  updateEncoded,
  onEncodedInput,
  addClaim,
  checkCompliance,
  checkRfc9068Compliance,
  generateRfc9068Token,
  generateSigningKeys,
  viewSigningCert,
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
