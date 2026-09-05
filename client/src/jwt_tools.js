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
// THE JWS ITSELF IS NOT THIS PAGE'S ANY MORE.
//
// Signing and verifying a compact JWS used to be written out here — an
// algorithm table, a signing input, three verification helpers — and the same
// four functions, under the same four names, were written out again in
// token_detail.js, whose copy this file's own comment described as the one it
// "mirrors". Two readings of RFC 7515 in one application is two chances to be
// wrong about the same thing, and the ways a JWS goes wrong are exactly the
// ways a round trip through one page cannot see. So the JOSE is jws.js's, and
// tests/jws_engine.js holds it against node's OpenSSL and against
// `jsonwebtoken`.
//
// What stayed here is what is genuinely this page's: which key material the
// fields hold, and how the panes read.
var jwsLib = require("./jws");
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

function isChecked(id) {
  log.debug("Entering isChecked().");
  var el = document.getElementById(id);
  log.debug("Leaving isChecked().");
  return !!(el && el.checked);
}

function setChecked(id, on) {
  log.debug("Entering setChecked().");
  var el = document.getElementById(id);
  if (el) el.checked = !!on;
  log.debug("Leaving setChecked().");
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

    // A header carrying x5c says which certificate signed it and which CAs
    // vouch for that certificate, and both belong in the Sign pane rather
    // than in a box the user has to copy out of by hand.
    var x5cNote = applyX5cFromHeader(header);

    var signature = parts.length >= 3 ? parts[2] : '';
    if (signature) {
      // Signed token: hand the whole thing to the Sign pane.
      setVal('jwt_tools_signed', encoded);
      setVal('verify_input', encoded);
      setVal('jwt_tools_sync_status', 'Decoded header & payload; signature ' +
             'captured (populated Signed JWT and JWT to Verify in the ' +
             'Sign pane).' + x5cNote);
    } else {
      setVal('jwt_tools_sync_status',
             'Decoded header & payload (no signature present).' + x5cNote);
    }
  } catch (e) {
    setVal('jwt_tools_sync_status', 'Cannot decode JWT: ' + e.message);
  }
  log.debug("Leaving onEncodedInput().");
  return false;
}

// ---------------------------------------------------------------------------
// Loading the Encoded JWT from a file.
//
// Pasting is the right way in for a token of ordinary size and stays the
// default. It stops being so somewhere above a megabyte — a real 10MB JWT
// turned up on this page — because a clipboard round trip of one is slow
// enough to look like a hang, and some browsers truncate what they hand over
// without saying so. So the field takes a file as well, behind a checkbox:
// the chooser is hidden until it is asked for, because this is the exception
// rather than the usual route.
// ---------------------------------------------------------------------------
// The cap is on the FILE and is checked before a byte is read. FileReader
// loads the whole thing into memory as one string, so a file chosen by
// mistake — a disk image, a core dump — has to be refused up front rather
// than read and then found wanting.
var MAX_ENCODED_FILE_BYTES = 15 * 1024 * 1024;

// Sizes are reported in the unit the number is legible in: "0.0 MB" for a
// small file says nothing about what was loaded, and a byte count for a
// 10MB one says nothing about how it compares with the limit.
function formatFileSize(bytes) {
  log.debug("Entering formatFileSize().");
  var out;
  if (bytes < 1024) {
    out = bytes + ' bytes';
  } else if (bytes < 1024 * 1024) {
    out = (bytes / 1024).toFixed(1) + ' KB';
  } else {
    out = (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }
  log.debug("Leaving formatFileSize().");
  return out;
}

// The "Load from file" checkbox shows and hides the chooser beside it.
function toggleEncodedFileLoad() {
  log.debug("Entering toggleEncodedFileLoad().");
  var box = document.getElementById('jwt_tools_load_from_file');
  var input = document.getElementById('jwt_tools_encoded_file');
  var on = !!(box && box.checked);
  if (input) {
    input.hidden = !on;
    if (!on) {
      // Forget whatever was chosen, so re-opening the row does not offer the
      // name of a file that is not going to be read, and so choosing the same
      // file again still fires a change event.
      input.value = '';
    }
  }
  log.debug("Leaving toggleEncodedFileLoad(). on=" + on);
  return false;
}

// Read the chosen file into the Encoded JWT field and decode it exactly as a
// paste would — onEncodedInput() does the rest, including populating the Sign
// pane when the token carries a signature.
function onEncodedFileChange(evt) {
  log.debug("Entering onEncodedFileChange().");
  var input = (evt && evt.target) ? evt.target :
      document.getElementById('jwt_tools_encoded_file');
  var file = (input && input.files) ? input.files[0] : null;
  if (!file) {
    setVal('jwt_tools_sync_status', 'No file chosen.');
    log.debug("Leaving onEncodedFileChange(). Nothing chosen.");
    return false;
  }
  if (file.size > MAX_ENCODED_FILE_BYTES) {
    setVal('jwt_tools_sync_status', file.name + ' is ' +
           formatFileSize(file.size) + ' — the limit is ' +
           formatFileSize(MAX_ENCODED_FILE_BYTES) +
           '. Nothing was loaded.');
    input.value = '';
    log.debug("Leaving onEncodedFileChange(). Too large: " + file.size);
    return false;
  }
  setVal('jwt_tools_sync_status', 'Reading ' + file.name + ' (' +
         formatFileSize(file.size) + ') \u2026');
  var reader = new FileReader();
  reader.onload = function () {
    log.debug("Entering onEncodedFileChange onload().");
    // A token saved to a file almost always ends in a newline, and some
    // editors put a BOM in front of it. Either one makes a segment fail to
    // base64url-decode, which reads as a corrupt token rather than as a stray
    // byte the file picked up on its way here.
    var text = String(reader.result || '').replace(/^\uFEFF/, '').trim();
    // Cleared whatever happens next, so the same file can be chosen again
    // after a correction — otherwise the second attempt fires no change event
    // and the chooser looks broken.
    input.value = '';
    if (!text) {
      setVal('jwt_tools_sync_status', file.name + ' is empty.');
      log.debug("Leaving onEncodedFileChange onload(). Empty file.");
      return;
    }
    setVal('jwt_tools_encoded', text);
    // Same work a paste of the same token does, and it is the expensive part
    // for a large one: JSON.parse of the payload plus a pretty-print into the
    // textarea on the left.
    onEncodedInput();
    setVal('jwt_tools_sync_status', 'Loaded ' + file.name + ' (' +
           formatFileSize(file.size) + '). ' + val('jwt_tools_sync_status'));
    log.debug("Leaving onEncodedFileChange onload().");
  };
  reader.onerror = function () {
    log.debug("Entering onEncodedFileChange onerror().");
    setVal('jwt_tools_sync_status', 'Could not read ' + file.name + '.');
    input.value = '';
    log.debug("Leaving onEncodedFileChange onerror().");
  };
  reader.readAsText(file);
  log.debug("Leaving onEncodedFileChange().");
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

// The page's dropdown holds JOSE `alg` values; jws.js keys its table by
// algorithm AND curve, because RFC 8037 gives Ed25519 and Ed448 the same
// `alg` and the curve is in the key. This page offers only Ed25519 — Web
// Crypto has no Ed448 — so the bridge is one line and says why.
function jwsAlgId(alg) {
  log.debug("Entering jwsAlgId().");
  log.debug("Leaving jwsAlgId().");
  return alg === 'EdDSA' ? 'EdDSA-Ed25519' : alg;
}

// What the key fields hold, in the vocabulary jws.js takes. The HMAC secret is
// read as BASE64URL here and that is deliberate: this page generates it with
// key_material.generateSecret(), which returns base64url, and the JWK export
// beside it carries the same string as `k`. The Token Detail page reads its
// own secret field as UTF-8 TEXT, because a secret pasted from an identity
// provider's configuration is text — the two pages disagreed silently before,
// and now each says which it means.
function signingKeyInput(alg, keyText) {
  log.debug("Entering signingKeyInput().");
  var meta = SIGN_ALGS[alg];
  var text = (keyText || '').trim();
  if (meta && meta.kind === 'hmac') {
    log.debug("Leaving signingKeyInput(). Secret.");
    return { secret: isJwk(text) ? (JSON.parse(text).k || '') : text,
             encoding: 'b64u' };
  }
  if (isJwk(text)) {
    log.debug("Leaving signingKeyInput(). JWK.");
    return { jwk: JSON.parse(text) };
  }
  log.debug("Leaving signingKeyInput(). PEM.");
  return text;
}

async function signJWT() {
  log.debug("Entering signJWT().");
  var alg = val('sign_alg');
  setVal('sign_status', 'Signing with ' + alg + '...');
  try {
    // Force the header alg to match the selected signing algorithm, then hand
    // the header over VERBATIM. The JWS is the base64url of these exact bytes,
    // so the member order the user sees in the box is the member order that
    // gets signed — jws.js is told not to rebuild it.
    var header = parseJson('jwt_tools_header', 'JWT Header');
    // `alg` is already the REGISTERED value: this page's dropdown holds JOSE
    // `alg` values and jwsAlgId() bridges to the engine's identifier, which
    // keys Ed25519 and Ed448 separately. So the header takes it unchanged —
    // and must, since a header naming `EdDSA-Ed25519` would name an algorithm
    // no registry has. (This was briefly `jwsLib.algSpec(alg).alg` while the
    // menu held engine identifiers, and `algSpec('EdDSA')` does not exist.)
    header.alg = alg;
    setVal('jwt_tools_header', JSON.stringify(header, null, 2));
    var payload = parseJson('jwt_tools_payload', 'JWT Payload');

    // backend: 'webcrypto' keeps this pane on crypto.subtle, which is what it
    // has always signed with. jws.js's pure-JS backend produces byte-identical
    // output for every deterministic algorithm here (tests/jws_engine.js
    // asserts exactly that), so this is a choice about blast radius rather
    // than about correctness: nothing this page emits changes.
    var result = await jwsLib.signJwsAsync({
      algId: jwsAlgId(alg),
      protectedHeader: header,
      payload: payload,
      privateKey: signingKeyInput(alg, val('sign_private_key')),
      backend: 'webcrypto'
    });

    setVal('jwt_tools_signed', result.serialized);
    setVal('jwt_tools_encoded', result.serialized);
    setVal('verify_input', result.serialized);
    setVal('jwe_plaintext', result.serialized);
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

// ---- Signature verification ----
//
// Three key forms, one verifier. Each of these used to be a function here and
// a second function of the same name in token_detail.js, and both copies were
// RSA-only for the certificate and JWKS cases — so a token signed with ES256
// could be produced by the pane above and not verified by the pane below it.
// jws.js takes any of the forms, so all of them work for every algorithm.
//
// The X.509 case is the one that changed most. Both pages labelled that field
// "X.509 Certificate (PEM)" and both handed the PEM to importKey('spki'),
// which reads a SubjectPublicKeyInfo and cannot read a Certificate at all —
// so an actual certificate failed there with a bare Web Crypto DataError, and
// the only thing that ever worked was the public KEY this page's own
// auto-fill happened to supply. jws.js walks a certificate to its SPKI, so
// the field now accepts what its label promises, and still accepts a bare
// public key.
function verificationKeyInput(type, keyText) {
  log.debug("Entering verificationKeyInput().");
  var text = (keyText || '').trim();
  if (type === 'hmac') {
    log.debug("Leaving verificationKeyInput(). Secret.");
    return { secret: text, encoding: 'b64u' };
  }
  if (type === 'jwks') {
    log.debug("Leaving verificationKeyInput(). JWK Set.");
    return { jwks: JSON.parse(text) };
  }
  // A certificate BUNDLE is one paste, and the key that verifies the
  // signature is the first certificate in it — everything after it is that
  // certificate's issuers. pemToDer() reads ONE block (two padded base64
  // bodies concatenated are not one base64 value), so handing the whole
  // bundle to the verifier fails on the encoding rather than on the
  // signature. Nothing is lost by taking the head here: the trust-chain
  // check below reads the same field and takes the TAIL as CA certificates.
  var certificates = splitPemCertificates(text);
  if (certificates.length > 1) {
    log.debug("Leaving verificationKeyInput(). First of " +
              certificates.length + " certificates.");
    return certificates[0];
  }
  log.debug("Leaving verificationKeyInput(). PEM.");
  return text;
}

// ---------------------------------------------------------------------------
// x5c — the certificates a token carries about itself, and what they are
// worth.
//
// RFC 7515 section 4.1.6 orders the member: the certificate holding the key
// that signed this JWS comes FIRST, and each one after it certifies the one
// before, up to a root. So the head of the list is the key to verify WITH and
// the tail is the issuing chain to check that key AGAINST, and the two halves
// go to two different fields here. Keeping them apart is the whole point: a
// signature that verifies against a certificate the token supplied about
// itself has established that the token is internally consistent and nothing
// else, which is why the trust-chain check below is what turns an x5c into an
// answer.
//
// The member holds base64 DER and NOT base64url — x5c is the one place in a
// JOSE header where that is so, and getting it wrong is common enough that a
// base64url-encoded x5c is read anyway, with a note, rather than refused with
// a message about an invalid character.
// ---------------------------------------------------------------------------

// Whether the fields below were last filled from a token's x5c. A stale chain
// left in the box after a DIFFERENT token is loaded would be checked against
// that token and is exactly the trap this page exists to expose, so what this
// filled in, this clears.
var x5cApplied = false;

function x5cToPems(x5c) {
  log.debug("Entering x5cToPems().");
  var pems = [];
  var wasB64Url = false;
  for (var i = 0; i < x5c.length; i++) {
    var text = String(x5c[i] || '').replace(/\s+/g, '');
    if (!text) continue;
    if (/[-_]/.test(text)) wasB64Url = true;
    // b64uToBytes() reads both alphabets and supplies the padding, so this
    // takes the conforming base64 and the mistaken base64url alike; the flag
    // above is what lets the page SAY which it was handed.
    pems.push(jose.derToPem(jose.b64uToBytes(text), 'CERTIFICATE'));
  }
  log.debug("Leaving x5cToPems(). " + pems.length + " certificate(s).");
  return { pems: pems, wasB64Url: wasB64Url };
}

// Split a PEM bundle into its certificates. Only what lies between a BEGIN
// and its END is taken, so a bundle carrying comments or `openssl x509
// -text` output between the blocks — which is how most CA downloads are
// written — is read rather than refused.
function splitPemCertificates(text) {
  log.debug("Entering splitPemCertificates().");
  var found = String(text || '').match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving splitPemCertificates(). " + found.length + " found.");
  return found;
}

// Fill the verification fields from a decoded header's x5c, or undo that when
// a token without one arrives. Returns a sentence for the sync status, or "".
function applyX5cFromHeader(header) {
  log.debug("Entering applyX5cFromHeader().");
  var x5c = header ? header.x5c : null;
  var haveX5c = !!(x5c && Object.prototype.toString.call(x5c) ===
      '[object Array]' && x5c.length);
  if (!haveX5c) {
    if (!x5cApplied) {
      log.debug("Leaving applyX5cFromHeader(). No x5c, nothing to undo.");
      return '';
    }
    setVal('jwt_verification_key', '');
    setVal('verify_chain_pem', '');
    setChecked('verify_chain_enabled', false);
    toggleTrustChain();
    x5cApplied = false;
    log.debug("Leaving applyX5cFromHeader(). Cleared the previous x5c.");
    return " The previous token's x5c certificates were cleared " +
        "from the Sign pane; this header carries none.";
  }
  try {
    var read = x5cToPems(x5c);
    if (!read.pems.length) {
      log.debug("Leaving applyX5cFromHeader(). x5c held nothing readable.");
      return ' The header has an x5c, but no certificate could be read ' +
          'from it.';
    }
    setVal('jwt_verification_type', 'x509');
    setVal('jwt_verification_key', read.pems[0]);
    var cas = read.pems.slice(1);
    setVal('verify_chain_pem', cas.join(''));
    setChecked('verify_chain_enabled', cas.length > 0);
    toggleTrustChain();
    x5cApplied = true;
    var note = ' Header carries x5c: the signer certificate is now the ' +
        'Verification Key';
    note += cas.length
      ? ', and the ' + cas.length + ' certificate(s) above it are the CA ' +
        'Trust Chain.'
      : ', and there is nothing above it — the x5c is a single certificate, ' +
        'so it carries no chain to check it against.';
    if (read.wasB64Url) {
      note += ' NOTE: that x5c is base64url; RFC 7515 section 4.1.6 says ' +
          'base64. It was read anyway.';
    }
    log.debug("Leaving applyX5cFromHeader(). Applied " + read.pems.length +
              " certificate(s).");
    return note;
  } catch (e) {
    log.error('applyX5cFromHeader: ' + e.message);
    log.debug("Leaving applyX5cFromHeader(). Failed.");
    return " The header's x5c could not be read: " + e.message;
  }
}

// The CA Trust Chain box appears only when the box beside it is ticked.
function toggleTrustChain() {
  log.debug("Entering toggleTrustChain().");
  var field = document.getElementById('verify_chain_field');
  if (field) field.hidden = !isChecked('verify_chain_enabled');
  log.debug("Leaving toggleTrustChain().");
  return false;
}

// Put the CA certificates into issuer order, walking up from the signer.
//
// A pasted bundle arrives in whatever order its source wrote it, and an x5c
// is ordered but may be trimmed; ordering by NAME rather than by position
// means a correct chain in the wrong order validates, and an incomplete one
// says which certificate is missing instead of reporting a name mismatch
// three lines lower down.
async function buildTrustPath(signerPem, caPems) {
  log.debug("Entering buildTrustPath().");
  var signer = await x509.describeCertificate(signerPem);
  var cas = [];
  for (var i = 0; i < caPems.length; i++) {
    var described = await x509.describeCertificate(caPems[i]);
    cas.push({ pem: caPems[i], subject: described.subject,
               issuer: described.issuer, selfSigned: described.selfSigned });
  }
  var path = [signerPem];
  var wanted = signer.issuer;
  var used = {};
  var anchored = signer.selfSigned;
  while (!anchored) {
    var next = -1;
    for (var j = 0; j < cas.length; j++) {
      if (!used[j] && cas[j].subject === wanted) {
        next = j;
        break;
      }
    }
    if (next === -1) break;
    used[next] = true;
    path.push(cas[next].pem);
    if (cas[next].selfSigned) {
      anchored = true;
      break;
    }
    wanted = cas[next].issuer;
  }
  var unused = cas.length - Object.keys(used).length;
  log.debug("Leaving buildTrustPath(). " + path.length + " in path, " +
            unused + " unused, anchored=" + anchored);
  return { path: path, anchored: anchored, missing: anchored ? null : wanted,
           unused: unused, reachedNothing: path.length === 1 && !anchored };
}

// One certificate's KeyUsage as a phrase for the report.
//
// An absent extension is said to be absent rather than printed as an empty
// list, because RFC 5280 section 4.2.1.3 leaves such a key unrestricted —
// that is a fact about the certificate the reader needs, and a blank would
// read as a key permitted nothing, which is the opposite.
function keyUsageText(keyUsage) {
  log.debug("Entering keyUsageText().");
  var text;
  if (!keyUsage || !keyUsage.present) {
    text = 'no KeyUsage extension, so unrestricted';
  } else if (!keyUsage.usages.length) {
    text = 'a KeyUsage extension asserting nothing';
  } else {
    text = keyUsage.usages.join(', ');
  }
  log.debug("Leaving keyUsageText().");
  return text;
}

// What the certificate at `index` of a path is being asked to DO, and so
// which KeyUsage bit has to permit it.
//
// The signer certificate verifies a signature over a JWS, which is not a
// certificate, so RFC 5280 section 4.2.1.3 puts that under digitalSignature.
// Every certificate above it in the path signed the one below, which is
// keyCertSign — a different bit, deliberately, so that a certificate issued
// to sign documents cannot also issue certificates.
function chainUsageFor(index) {
  log.debug("Entering chainUsageFor().");
  log.debug("Leaving chainUsageFor().");
  return index === 0 ? 'digitalSignature' : 'keyCertSign';
}

// Check the signer certificate to a trust anchor and describe every link.
// `trusted` is null when no check applies, which is not the same as false —
// only false stops a signature being reported as verified.
async function trustChainReport(type, keyText) {
  log.debug("Entering trustChainReport().");
  if (type !== 'x509') {
    log.debug("Leaving trustChainReport(). Not an X.509 verification.");
    return { trusted: null, reason: '',
        lines: ['Trust chain: not checked — chain ' +
        'validation applies to the X.509 Certificate verification type, and ' +
        'this verification is by ' + type + '.'] };
  }
  var keyPems = splitPemCertificates(keyText);
  var signerPem = keyPems[0];
  if (!signerPem) {
    log.debug("Leaving trustChainReport(). No signer certificate.");
    return { trusted: false,
        reason: 'the Verification Key field holds no certificate',
        lines: ['Trust chain: the Verification Key ' +
        'field holds no certificate. A bare public key names nobody and can ' +
        'be checked against no CA, so no trust can be established.'] };
  }
  // THE SIGNER CERTIFICATE AND THE CA CHAIN ARE CHECKED AS ONE BUNDLE, and
  // the bundle is BOTH fields: the signer certificate first, then every
  // certificate offered as an issuer — those in the CA Trust Chain box, and
  // any that came after the signer in the Verification Key box, which is how
  // a chain pasted whole into one field arrives. Reading only one of the two
  // would report a chain as unanchored while its anchor sat in the other.
  var caPems = keyPems.slice(1).concat(
    splitPemCertificates(val('verify_chain_pem')));
  if (!caPems.length) {
    log.debug("Leaving trustChainReport(). No CA certificates.");
    return { trusted: false,
        reason: 'no CA certificate was offered to check the signer ' +
            'certificate against',
        lines: ['Trust chain: no CA certificate was supplied — the CA ' +
        'Trust Chain field is empty and the Verification Key field holds ' +
        'nothing above the signer, so there is no anchor to check the ' +
        'signer certificate against.'] };
  }
  var built = await buildTrustPath(signerPem, caPems);
  var lines = [];
  var trusted = built.anchored;
  var usageRefused = false;
  if (built.reachedNothing) {
    lines.push('Trust chain: no certificate offered as its chain was ' +
        'issued to "' + built.missing + '", which is who issued the signer ' +
        'certificate. The chain does not belong to this signer.');
    log.debug("Leaving trustChainReport(). Nothing chained to the signer.");
    return { trusted: false, lines: lines,
             reason: 'the certificates offered as its chain do not belong ' +
                 'to this signer' };
  }
  var links = await x509.verifyChain(built.path);
  lines.push('Trust chain: ' + built.path.length + ' certificate(s), ' +
      'signer first.');
  for (var i = 0; i < links.length; i++) {
    var link = links[i];
    var last = i === links.length - 1;
    var problems = [];
    if (last && !built.anchored) {
      // The last certificate of an unanchored path is compared with ITSELF by
      // verifyChain, so both its verdict and its "signed by" are about a
      // comparison nobody asked for: calling that signature invalid would
      // blame the certificate for the anchor nobody supplied, and naming
      // itself as its issuer would contradict the line beside it.
      problems.push('NO TRUST ANCHOR: its issuer is not in the chain');
    } else {
      if (!link.namesMatch) problems.push('issuer name does not match');
      if (!link.signatureValid) {
        problems.push(link.error ? 'signature not checked: ' + link.error
                                 : 'SIGNATURE INVALID');
      }
      if (link.expired) problems.push('EXPIRED');
      if (link.notYetValid) problems.push('NOT YET VALID');
    }
    // THE KEY USAGE CHECK, and it applies to every certificate in the path
    // including one that reached no anchor: a certificate whose KeyUsage
    // forbids the operation being performed with it is not made acceptable
    // by the certificate above it. `verifyChain()` reports the extension and
    // this decides, because only the caller knows the POSITION — see
    // chainUsageFor().
    var usage = chainUsageFor(i);
    if (!x509.keyUsagePermits(link.keyUsage, usage)) {
      usageRefused = true;
      problems.push(usage === 'digitalSignature'
        ? 'KEY USAGE FORBIDS SIGNING: its KeyUsage extension asserts ' +
          keyUsageText(link.keyUsage) + ', which does not include ' +
          'digitalSignature, so this key may not sign a JWS'
        : 'KEY USAGE FORBIDS ISSUING: its KeyUsage extension asserts ' +
          keyUsageText(link.keyUsage) + ', which does not include ' +
          'keyCertSign, so this key may not issue the certificate below it');
    }
    if (problems.length) trusted = false;
    var by = (last && !built.anchored) ? link.issuer : link.signedBy;
    lines.push('  ' + (i === 0 ? '[signer] ' : '') + link.subject +
        ' — issued by ' + by +
        (last && built.anchored ? ' (self-signed root)' : '') + ': ' +
        (problems.length ? problems.join('; ') : 'ok') +
        ' [key usage: ' + keyUsageText(link.keyUsage) + ']');
  }
  if (built.unused) {
    lines.push('  (' + built.unused + ' certificate(s) offered as the ' +
        'chain were not part of this path and were not checked.)');
  }
  var reason = usageRefused
    ? 'a certificate in its chain is not permitted the use being made of ' +
      'it (see the KEY USAGE line below)'
    : !built.anchored
      ? 'the signer certificate could not be validated to a trust anchor'
      : 'a link in its chain did not check out';
  log.debug("Leaving trustChainReport(). trusted=" + trusted +
            " usageRefused=" + usageRefused);
  return { trusted: trusted, lines: lines, reason: reason };
}

async function verifyJWT() {
  log.debug("Entering verifyJWT().");
  var type = val('jwt_verification_type');
  var key = val('jwt_verification_key');
  var jwt_ = val('verify_input').trim();
  try {
    var keyInput;
    if (type === 'jwks_url') {
      var response = await fetch(key);
      if (!response.ok) throw new Error('Failed to fetch JWKS.');
      keyInput = { jwks: await response.json() };
    } else if (type === 'hmac' || type === 'x509' || type === 'jwks') {
      keyInput = verificationKeyInput(type, key);
    } else {
      throw new Error('Unsupported verification method.');
    }
    // No algId: this pane verifies a token somebody else produced and has no
    // algorithm selector, so the header's `alg` is all there is to go on.
    // That is RFC 8725 §3.1's bad case, and it is what a debugger is FOR —
    // the pane's job is to tell you what the token says, not to decide.
    var result = await jwsLib.verifyJwsAsync({
      jws: jwt_, publicKey: keyInput, backend: 'webcrypto'
    });
    var first = result.signatures[0] || {};

    // The chain is checked SECOND and reported FIRST, and the verdict is the
    // two together: a signature that verifies against a certificate nothing
    // vouches for is a signature by whoever wrote the token. So an
    // unestablished chain makes the answer false, and the line below it says
    // that the cryptography was fine — which is the distinction a debugger
    // exists to draw, and which one boolean would destroy.
    var chain = { trusted: null, lines: [], reason: '' };
    if (isChecked('verify_chain_enabled')) {
      chain = await trustChainReport(type, key);
    }
    var verified = !!result.valid && chain.trusted !== false;
    var head = 'Signature Verified: ' + (verified ? 'true' : 'false');
    if (!result.valid) {
      head += first.reason ? ' — ' + first.reason : '';
    } else if (chain.trusted === false) {
      head += ' — the signature is cryptographically valid, but ' +
          (chain.reason || 'the signer certificate could not be validated ' +
              'to a trust anchor') + '.';
    } else if (chain.trusted === true) {
      head += ' — signer certificate validated to a trust anchor.';
    }
    setVal('jwt_verification_output', [head].concat(chain.lines).join('\n'));
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

    // A nested JWT (a JWS as the plaintext) is signalled with cty:"JWT" (RFC
    // 7519 §5.2).
    var extraHeader = {};
    if (plaintext.split('.').length === 3) extraHeader.cty = 'JWT';

    // THE SHARED SERIALIZER, not a second copy of it. This function used to
    // assemble the five segments itself — derive the CEK, take a 12-byte IV,
    // AES-GCM, split off the tag — which was fine while AES-GCM was the only
    // content encryption this application spoke. It is not any more: the
    // AES-CBC-HMAC family has a CEK of twice the size, a SIXTEEN-byte IV and a
    // MAC that is not the cipher's, so a private assembly here would have to
    // learn all three or silently produce a JWE that no other implementation
    // can open. encryptCompact() already knows, and is checked against RFC
    // 7518's Appendix B vector and OpenSSL by tests/jose_jwe_encryption.js.
    var produced = await jose.encryptCompact({
      alg: alg, enc: enc, plaintext: plaintext,
      key: val('jwe_public_key'), header: extraHeader
    });
    var jwe = produced.jwe;
    var protectedHeader = produced.header;
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

    // The shared reader, for the reason encryptJWT() above uses the shared
    // writer: an AES-CBC-HMAC JWE is not opened the way an AES-GCM one is, and
    // a private copy here would refuse half of what the far end may send.
    var opened = await jose.decryptCompact({ jwe: jwe,
        key: val('jwe_private_key') });
    setVal('jwe_decrypt_output', opened.plaintext);
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
// The throwaway certificate a PKCS#12 has to wrap the key in, and the one the
// View certificate button shows. It is x509.js's now — the Encryption /
// Decryption page's key panes need the same thing for the same reason, and a
// second copy of a certificate profile is a second set of extensions to get
// wrong. Only the subject differs between the two callers.
async function buildSelfSignedCertPem(privPem, pubPem, desc) {
  log.debug("Entering buildSelfSignedCertPem().");
  var pem = await x509.selfSignedCertPem({
    subject: 'CN=jwt-tools generated key',
    publicPem: pubPem,
    privatePem: privPem,
    desc: desc
  });
  log.debug("Leaving buildSelfSignedCertPem().");
  return pem;
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
  var allowed = { 'oauth2_oidc_1.html': '/oauth2_oidc_1.html',
      'oauth2_oidc_2.html': '/oauth2_oidc_2.html' };
  var from = new URLSearchParams(window.location.search).get('from');
  var target = allowed[from] || '/oauth2_oidc_1.html';
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
  toggleEncodedFileLoad,
  onEncodedFileChange,
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
  toggleTrustChain,
  copyField,
  populateTable
};
