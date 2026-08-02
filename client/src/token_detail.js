// File: token_detail.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/28/2020
// Notes:
//
// Node modules are needed to be able to read the JWT tokens.
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var $ = require("jquery");
// DOMParser is the browser-native global here (token_detail runs only in the
// browser). Do not bundle an xmldom implementation: besides being redundant,
// strict parsers throw on the non-XML body returned when /claimdescription is
// absent (e.g. the static site), which would break JWT payload rendering. The
// native parser is lenient and simply yields no <record> elements in that case.
var log = bunyan.createLogger({ name: 'token_detail',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
// `jsonwebtoken` used to be required here for the one call below. It reaches
// `elliptic` (jsonwebtoken -> jwa -> crypto, which browserify fills in with
// crypto-browserify -> browserify-sign/create-ecdh -> elliptic), and `elliptic`
// carries GHSA-848j-6mx2-7j84 with no patched version in existence. Decoding a
// JWT needs no cryptography at all, so decodeJWT() below does it directly and a
// permanently-vulnerable ECDSA implementation stops being shipped to the
// browser. Signature VERIFICATION on this page was already Web Crypto's job.
const vendorClaims = {
  'rfc_jose_header': require('./vendor_claims/rfc_jose_header.json'),
  'microsoft_entra': require('./vendor_claims/microsoft_entra.json')
};

claimDescriptionDictionary = {};
claimUrlDictionary = {};

function getParameterByName(name, url)
{
  log.debug("Entering getParameterByName().");
  if (!url)
  {
    url = window.location.search;
  }
  var urlParams = new URLSearchParams(url);
  return urlParams.get(name);
}

// Exactly three base64url segments, the third allowed to be empty (an unsecured
// JWT). This is `jws`'s own JWS_REGEX; keeping it identical keeps the set of
// strings that decode identical.
var JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;

function b64uToUtf8(segment) {
  var b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 = b64 + "=";
  }
  var raw = atob(b64);
  try {
    // Percent-decoding rather than atob alone: a claim value may hold non-ASCII
    // (a name, an address), and atob yields bytes, not characters.
    return decodeURIComponent(
      raw.split("").map(function (c) {
        return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
      }).join("")
    );
  } catch (e) {
    // Not valid UTF-8. Buffer.from(...).toString('utf8') — what jsonwebtoken
    // used — substitutes replacement characters rather than failing, so show
    // the bytes instead of refusing to decode a token that is merely mis-encoded.
    log.debug("Segment is not valid UTF-8; showing the raw bytes: " + e.message);
    return raw;
  }
}

// The contract callers depend on is jsonwebtoken's decode(token, {complete:true}):
// { header, payload, signature } back, or NULL — never a throw — when the string
// is not a JWT or its header is not JSON. validateClaims() below turns that null
// into its own error message, so returning null matters as much as the object.
// The payload is JSON.parse'd when it parses to an object and left as a string
// otherwise, which is what makes a non-JSON payload display rather than vanish.
function decodeJWT(jwt_) {
  log.debug("Entering decodeJWT().");
  if (typeof jwt_ !== "string" || !JWS_REGEX.test(jwt_)) {
    log.debug("Leaving decodeJWT() — not a JWS.");
    return null;
  }
  var segments = jwt_.split(".");
  var header;
  try {
    header = JSON.parse(b64uToUtf8(segments[0]));
  } catch (e) {
    // An unparseable header is not a JWT. jws.decode treats this the same way,
    // and the caller is written to expect null rather than an exception.
    log.debug("Leaving decodeJWT() — header is not JSON: " + e.message);
    return null;
  }
  if (header === null || typeof header !== "object") {
    log.debug("Leaving decodeJWT() — header is not an object.");
    return null;
  }
  var payload;
  try {
    payload = b64uToUtf8(segments[1]);
  } catch (e) {
    log.debug("Leaving decodeJWT() — payload is not decodable: " + e.message);
    return null;
  }
  try {
    var parsed = JSON.parse(payload);
    if (parsed !== null && typeof parsed === "object") {
      payload = parsed;
    }
  } catch (e) {
    // Deliberately ignored: a payload that is not JSON is legal in a JWS and is
    // shown as the string it is, exactly as jsonwebtoken did.
    log.debug("Payload is not JSON; keeping it as a string.");
  }
  log.debug("Leaving decodeJWT().");
  return { header: header, payload: payload, signature: segments[2] || "" };
}

function resolveTokenFromParams() {
  log.debug("Entering resolveTokenFromParams().");
  var type = getParameterByName('type');
  if (type === 'access') {
    return localStorage.getItem('token_access_token');
  } else if (type === 'refresh') {
    return localStorage.getItem('token_refresh_token');
  } else if (type === 'id') {
    return localStorage.getItem('token_id_token');
  } else if (type === 'refresh_access') {
    return localStorage.getItem('refresh_access_token');
  } else if (type === 'refresh_refresh') {
    return localStorage.getItem('refresh_refresh_token');
  } else if (type === 'refresh_id') {
    return localStorage.getItem('refresh_id_token');
  } else if (type === 'history_access' || type === 'history_refresh' || type === 'history_id_token') {
    var generation = parseInt(getParameterByName('generation'), 10);
    var history = [];
    try {
      history = JSON.parse(localStorage.getItem('token_history') || '[]');
    } catch (e) {
      log.error('Failed to parse token_history: ' + e);
      return null;
    }
    if (isNaN(generation) || generation < 0 || generation >= history.length) {
      log.error('Invalid generation index: ' + generation);
      return null;
    }
    var entry = history[generation];
    if (type === 'history_access')    return entry.access_token || null;
    if (type === 'history_refresh')   return entry.refresh_token || null;
    if (type === 'history_id_token')  return entry.id_token || null;
  } else {
    log.error('Unknown token type: ' + type);
    return null;
  }
  log.debug("Leaving resolveTokenFromParams().");
}

async function verifyJWT() {
  log.debug("Entering verifyJWT().");
  var jwt_verification_type = document.getElementById("jwt_verification_type").value;
  var jwt_verification_key = document.getElementById("jwt_verification_key").value;
  var jwt_ = resolveTokenFromParams();

  try {
    const [headerB64, payloadB64, signatureB64] = jwt_.split('.');
    if (!headerB64 || !payloadB64 || !signatureB64) throw new Error('Invalid JWT format.');

    const header = JSON.parse(atobUrl(headerB64));
    var isValid = false;
    if (jwt_verification_type === 'hmac') {
      isValid = await verifyHMAC(jwt_, jwt_verification_key, header.alg);
    } else if (jwt_verification_type === 'x509') {
      isValid = await verifyX509(jwt_, jwt_verification_key, header.alg);
    } else if (jwt_verification_type === 'jwks') {
      isValid = await verifyJWKS(jwt_, JSON.parse(jwt_verification_key));
    } else if (jwt_verification_type === 'jwks_url') {
      const response = await fetch(jwt_verification_key);
      if (!response.ok) throw new Error('Failed to fetch JWKS.');
      isValid = await verifyJWKS(jwt_, await response.json());
    } else {
      throw new Error('Unsupported verification method.');
    }
  } catch (err) {
    log.error("Error while verifying JWT: " + err.message);
  }

  document.getElementById('jwt_verification_output').value = "Signature Verified: " + isValid;
  log.debug("Leaving verifyJWT().");
}

function atobUrl(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '==='.slice(0, (4 - input.length % 4) % 4);
  return atob(input + pad);
}

function base64UrlToUint8Array(base64UrlString) {
  const binary = atobUrl(base64UrlString);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function pemToArrayBuffer(pem) {
  const binary = atob(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
  const buffer = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  
  return buffer.buffer;
}

async function verifyHMAC(jwt_, secret, alg = 'HS256') {
  log.debug("Entering verifyHMAC().");
  const encoder = new TextEncoder();
  const algo = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' }[alg];
  if (!algo) throw new Error('Unsupported HMAC algorithm: ' + alg);

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: { name: algo } },
    false,
    ['verify']
  );
  const data = encoder.encode(jwt_.split('.').slice(0, 2).join('.'));
  const signature = base64UrlToUint8Array(jwt_.split('.')[2]);

  log.debug("Leaving verifyHMAC().");
  return await crypto.subtle.verify('HMAC', key, signature, data);
}

async function verifyX509(jwt_, pem, alg = 'RS256') {
  log.debug("Entering verifyX509().");
  const encoder = new TextEncoder();
  const algo = { RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512' }[alg];
  if (!algo) throw new Error('Unsupported RSA algorithm: ' + alg);

  const key = await crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(pem),
    { name: 'RSASSA-PKCS1-v1_5', hash: { name: algo } },
    false,
    ['verify']
  );
  const data = encoder.encode(jwt_.split('.').slice(0, 2).join('.'));
  const signature = base64UrlToUint8Array(jwt_.split('.')[2]);

  log.debug("Leaving verifyX509().");
  return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data);
}

async function verifyJWKS(jwt_, jwks) {
  log.debug("Entering verifyJWKS().");
  const header = JSON.parse(atobUrl(jwt_.split('.')[0]));
  if (!header.kid) throw new Error('No "kid" found in JWT header.');

  const jwk = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('Matching "kid" not found in JWKS.');
  if (jwk.kty !== 'RSA') throw new Error('Only RSA keys are supported.');

  const encoder = new TextEncoder();
  const algo = { RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512' }[header.alg];
  if (!algo) throw new Error('Unsupported algorithm: ' + header.alg);

  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e },
    { name: 'RSASSA-PKCS1-v1_5', hash: { name: algo } },
    false,
    ['verify']
  );
  const data = encoder.encode(jwt_.split('.').slice(0, 2).join('.'));
  const signature = base64UrlToUint8Array(jwt_.split('.')[2]);

  log.debug("Leaving verifyJWKS().");
  return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data);
}

async function computeAtHash(value, alg) {
  log.debug("Entering computeAtHash().");
  const hashAlgoMap = {
    RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512',
    ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512',
    PS256: 'SHA-256', PS384: 'SHA-384', PS512: 'SHA-512'
  };
  const hashAlgo = hashAlgoMap[alg];
  if (!hashAlgo) return null;
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest(hashAlgo, encoder.encode(value));
  const hashArray = new Uint8Array(hashBuffer);
  const leftHalf = hashArray.slice(0, hashArray.length / 2);
  let binary = '';
  leftHalf.forEach(b => binary += String.fromCharCode(b));
  log.debug("Leaving computeAtHash().");
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function validateClaims() {
  log.debug("Entering validateClaims().");
  const results = [];
  const now = Math.floor(Date.now() / 1000);
  const clockSkew = parseInt(document.getElementById('jwt_clock_skew').value) || 0;
  const purpose = document.getElementById('jwt_purpose').value;
  const expectedIss = document.getElementById('jwt_expected_iss').value.trim();
  const expectedAud = document.getElementById('jwt_expected_aud').value.trim();
  const clientId = document.getElementById('jwt_claims_client_id').value.trim();
  const expectedScope = document.getElementById('jwt_expected_scope').value.trim();

  function pass(claim, msg) { results.push('PASS  ' + claim + ': ' + msg); }
  function fail(claim, msg) { results.push('FAIL  ' + claim + ': ' + msg); }
  function skip(claim, msg) { results.push('SKIP  ' + claim + ': ' + msg); }

  var jwt_ = resolveTokenFromParams();
  if (!jwt_) {
    document.getElementById('jwt_claims_validation_output').value = 'Error: Unknown or missing token type.';
    return false;
  }

  var decoded;
  try {
    decoded = decodeJWT(jwt_);
    if (!decoded) throw new Error('Could not decode JWT.');
  } catch (e) {
    document.getElementById('jwt_claims_validation_output').value = 'Error: ' + e.message;
    return false;
  }

  const header = decoded.header;
  const payload = decoded.payload;
  const isRequired = purpose !== 'generic';

  // ---- Header checks ----

  // alg — "none" is never acceptable for a signed token
  if (!header.alg) {
    fail('alg', 'Missing alg header claim');
  } else if (header.alg === 'none') {
    fail('alg', '"none" algorithm is not permitted');
  } else {
    pass('alg', header.alg);
  }

  // typ — RFC 9068 requires "at+JWT"
  if (purpose === 'oauth2_access_token') {
    if (!header.typ) {
      fail('typ', 'Missing — must be "at+JWT" (RFC 9068 §2.1)');
    } else if (header.typ !== 'at+JWT') {
      fail('typ', '"' + header.typ + '" — expected "at+JWT" (RFC 9068 §2.1)');
    } else {
      pass('typ', '"at+JWT"');
    }
  } else if (header.typ !== undefined) {
    pass('typ', '"' + header.typ + '"');
  } else {
    skip('typ', 'Not present');
  }

  // ---- RFC 7519 registered claims ----

  // exp (RFC 7519 §4.1.4; required for OIDC and RFC 9068)
  if (!!payload.exp) {
    if (typeof payload.exp !== 'number' || !Number.isInteger(payload.exp)) {
      fail('exp', 'Must be an integer NumericDate (RFC 7519 §4.1.4)');
    } else if (now > payload.exp + clockSkew) {
      fail('exp', 'Token has expired (exp=' + new Date(payload.exp * 1000).toISOString() + ')');
    } else {
      const rem = payload.exp - now;
      const remStr = rem >= 60 ? Math.floor(rem / 60) + 'm ' + (rem % 60) + 's remaining'
                                : rem + 's remaining';
      pass('exp', 'Not expired (' + new Date(payload.exp * 1000).toISOString() + ', ' + remStr + ')');
    }
  } else if (isRequired) {
    fail('exp', 'Missing required claim');
  } else {
    skip('exp', 'Not present');
  }

  // nbf (RFC 7519 §4.1.5 — optional, validate if present)
  if (!!payload.nbf) {
    if (typeof payload.nbf !== 'number' || !Number.isInteger(payload.nbf)) {
      fail('nbf', 'Must be an integer NumericDate (RFC 7519 §4.1.5)');
    } else if (now < payload.nbf - clockSkew) {
      fail('nbf', 'Token not yet valid (nbf=' + new Date(payload.nbf * 1000).toISOString() + ')');
    } else {
      pass('nbf', 'Valid (nbf=' + new Date(payload.nbf * 1000).toISOString() + ')');
    }
  } else {
    skip('nbf', 'Not present');
  }

  // iat (RFC 7519 §4.1.6; required for OIDC and RFC 9068)
  if (!!payload.iat) {
    if (typeof payload.iat !== 'number' || !Number.isInteger(payload.iat)) {
      fail('iat', 'Must be an integer NumericDate (RFC 7519 §4.1.6)');
    } else if (payload.iat > now + clockSkew) {
      fail('iat', 'Issued-at time is in the future (' + new Date(payload.iat * 1000).toISOString() + ')');
    } else {
      pass('iat', 'Current time is after iat (' + new Date(payload.iat * 1000).toISOString() + ')');
    }
  } else if (isRequired) {
    fail('iat', 'Missing required claim');
  } else {
    skip('iat', 'Not present');
  }

  // exp/iat consistency
  if (!!payload.exp && 
      !!payload.iat &&
      typeof payload.exp === 'number' && 
      typeof payload.iat === 'number') {
    if (payload.exp <= payload.iat) {
      fail('exp/iat', 'exp (' + payload.exp + ') must be after iat (' + payload.iat + ')');
    } else {
      pass('exp/iat', 'exp is after iat');
    }
  }

  // iss (RFC 7519 §4.1.1; required for OIDC and RFC 9068)
  if (!!payload.iss) {
    if (typeof payload.iss !== 'string') {
      fail('iss', 'Must be a StringOrURI (RFC 7519 §4.1.1)');
    } else if (purpose === 'oidc_id_token' && payload.iss.endsWith('#')) {
      fail('iss', 'Must not end with "#" (OIDC Core §2)');
    } else if (expectedIss && payload.iss !== expectedIss) {
      fail('iss', 'Mismatch (expected="' + expectedIss + '", got="' + payload.iss + '")');
    } else {
      pass('iss', '"' + payload.iss + '"' + (expectedIss ? ' (matches expected)' : ''));
    }
  } else if (isRequired) {
    fail('iss', 'Missing required claim');
  } else if (expectedIss) {
    fail('iss', 'Expected issuer configured but claim is absent');
  } else {
    skip('iss', 'Not present');
  }

  // sub (RFC 7519 §4.1.2; required for OIDC and RFC 9068)
  if (!!payload.sub) {
    if (typeof payload.sub !== 'string') {
      fail('sub', 'Must be a StringOrURI (RFC 7519 §4.1.2)');
    } else if (purpose === 'oidc_id_token' && payload.sub.length > 255) {
      fail('sub', 'Must not exceed 255 ASCII characters (OIDC Core §2), length=' + payload.sub.length);
    } else {
      pass('sub', '"' + payload.sub + '"');
    }
  } else if (isRequired) {
    fail('sub', 'Missing required claim');
  } else {
    skip('sub', 'Not present');
  }

  // aud (RFC 7519 §4.1.3; required for OIDC and RFC 9068)
  if (!!payload.aud) {
    const audArray = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (expectedAud && !audArray.includes(expectedAud)) {
      fail('aud', 'Expected "' + expectedAud + '" not found in ' + JSON.stringify(payload.aud));
    } else if (expectedAud) {
      pass('aud', '"' + expectedAud + '" found in ' + JSON.stringify(payload.aud));
    } else {
      pass('aud', JSON.stringify(payload.aud));
    }
  } else if (isRequired) {
    fail('aud', 'Missing required claim');
  } else if (expectedAud) {
    fail('aud', 'Expected audience configured but claim is absent');
  } else {
    skip('aud', 'Not present');
  }

  // jti (RFC 7519 §4.1.7; required for RFC 9068)
  if (!!payload.jti) {
    pass('jti', '"' + payload.jti + '"');
  } else if (purpose === 'oauth2_access_token') {
    fail('jti', 'Missing required claim (RFC 9068 §2.2)');
  } else {
    skip('jti', 'Not present');
  }

  // ---- OIDC ID Token specific (OIDC Core 1.0 §3.1.3.7) ----
  if (purpose === 'oidc_id_token') {
    const audArray = !!payload.aud
      ? (Array.isArray(payload.aud) ? payload.aud : [payload.aud]) : [];

    // azp
    if (audArray.length > 1) {
      if (!payload.azp) {
        fail('azp', 'Required when aud has multiple values (OIDC Core §2)');
      } else if (clientId && payload.azp !== clientId) {
        fail('azp', 'Mismatch (expected="' + clientId + '", got="' + payload.azp + '")');
      } else {
        pass('azp', '"' + payload.azp + '"');
      }
    } else if (!!payload.azp) {
      if (clientId && payload.azp !== clientId) {
        fail('azp', 'Mismatch (expected="' + clientId + '", got="' + payload.azp + '")');
      } else {
        pass('azp', '"' + payload.azp + '"');
      }
    } else {
      skip('azp', 'Not present (only required when aud has multiple values)');
    }

    // nonce — presence required (OIDC Core §2)
    if (payload.nonce) {
      pass('nonce', 'Present');
    } else {
      fail('nonce', 'Missing — nonce is required in OIDC ID Tokens');
    }

    // auth_time
    if (!!payload.auth_time) {
      if (typeof payload.auth_time !== 'number' || !Number.isInteger(payload.auth_time)) {
        fail('auth_time', 'Must be an integer NumericDate (OIDC Core §2)');
      } else if (payload.auth_time > now + clockSkew) {
        fail('auth_time', 'Authentication time is in the future (' + new Date(payload.auth_time * 1000).toISOString() + ')');
      } else {
        pass('auth_time', new Date(payload.auth_time * 1000).toISOString());
      }
    } else {
      skip('auth_time', 'Not present');
    }

    // acr
    if (!!payload.acr) {
      pass('acr', '"' + payload.acr + '"');
    } else {
      skip('acr', 'Not present');
    }

    // amr
    if (!!payload.amr) {
      pass('amr', JSON.stringify(payload.amr));
    } else {
      skip('amr', 'Not present');
    }

    // at_hash (OIDC Core §3.1.3.6)
    if (!!payload.at_hash) {
      const accessToken = localStorage.getItem('token_access_token');
      if (!!accessToken) {
        try {
          const computed = await computeAtHash(accessToken, header.alg);
          if (computed === null) {
            fail('at_hash', 'Cannot validate — unsupported algorithm "' + header.alg + '"');
          } else if (computed !== payload.at_hash) {
            fail('at_hash', 'Hash mismatch — does not match stored access token');
          } else {
            pass('at_hash', 'Verified against stored access token');
          }
        } catch (e) {
          fail('at_hash', 'Validation error — ' + e.message);
        }
      } else {
        skip('at_hash', 'Present but no access token available to verify against');
      }
    } else {
      skip('at_hash', 'Not present');
    }

    // c_hash — cannot validate without the authorization code
    if (!!payload.c_hash) {
      skip('c_hash', 'Present — cannot validate (authorization code no longer available)');
    } else {
      skip('c_hash', 'Not present');
    }

    // s_hash (FAPI) — cannot validate without the state value
    if (!!payload.s_hash) {
      skip('s_hash', 'Present — cannot validate (state value no longer available)');
    } else {
      skip('s_hash', 'Not present');
    }
  }

  // ---- OAuth2 Access Token specific (RFC 9068 §2.2) ----
  if (purpose === 'oauth2_access_token') {
    // client_id
    if (!!payload.client_id) {
      if (clientId && payload.client_id !== clientId) {
        fail('client_id', 'Mismatch (expected="' + clientId + '", got="' + payload.client_id + '")');
      } else {
        pass('client_id', '"' + payload.client_id + '"');
      }
    } else {
      fail('client_id', 'Missing required claim (RFC 9068 §2.2)');
    }

    // scope / authorization_details
    if (!!payload.scope) {
      if (expectedScope) {
        const tokenScopes = payload.scope.split(' ');
        const requiredScopes = expectedScope.split(' ').filter(s => s.length > 0);
        const missing = requiredScopes.filter(s => !tokenScopes.includes(s));
        if (missing.length > 0) {
          fail('scope', 'Missing required scope(s): ' + missing.join(', ') + ' (present: "' + payload.scope + '")');
        } else {
          pass('scope', '"' + payload.scope + '" (all required scopes present)');
        }
      } else {
        pass('scope', '"' + payload.scope + '"');
      }
    } else if (payload.authorization_details !== undefined) {
      pass('authorization_details', 'Present (used in place of scope)');
      skip('scope', 'Not present — authorization_details present instead');
    } else {
      fail('scope/authorization_details', 'At least one is required (RFC 9068 §2.2)');
    }
  }

  // ---- Token age summary ----
  var ageLine = '';
  if (!!payload.iat && 
      typeof payload.iat === 'number') {
    const ageSeconds = now - payload.iat;
    const ageMins = Math.floor(ageSeconds / 60);
    const ageSecs = ageSeconds % 60;
    ageLine = 'Token age: ' + (ageMins > 0 ? ageMins + 'm ' + ageSecs + 's' : ageSeconds + 's') +
              ' (iat=' + new Date(payload.iat * 1000).toISOString() + ')';
  }

  const failCount = results.filter(r => r.startsWith('FAIL')).length;
  var output = results.join('\n');
  if (ageLine) output += '\n\n' + ageLine;
  output += '\n\n' + (failCount === 0 ? 'All checks passed.' : failCount + ' check(s) failed.');
  document.getElementById('jwt_claims_validation_output').value = output;
  log.debug("Leaving validateClaims().");
  return false;
}

function writeValuesToLocalStorage() {
  log.debug("Entering writeValuesToLocalStorage().");
  try {
    const vtEl = document.getElementById('jwt_verification_type');
    const vkEl = document.getElementById('jwt_verification_key');
    if (vtEl) localStorage.setItem('jwt_verification_type', vtEl.value);
    if (vkEl) localStorage.setItem('jwt_verification_key', vkEl.value);
    localStorage.setItem('jwt_purpose', document.getElementById('jwt_purpose').value);
    localStorage.setItem('jwt_expected_iss', document.getElementById('jwt_expected_iss').value);
    localStorage.setItem('jwt_expected_aud', document.getElementById('jwt_expected_aud').value);
    localStorage.setItem('jwt_claims_client_id', document.getElementById('jwt_claims_client_id').value);
    localStorage.setItem('jwt_expected_scope', document.getElementById('jwt_expected_scope').value);
    localStorage.setItem('jwt_clock_skew', document.getElementById('jwt_clock_skew').value);
  } catch(e) {
    log.error("Error in writeValuesToLocalStorage: " + e.message);
  }
  log.debug("Leaving writeValuesToLocalStorage().");
}

$(document).on("change", "#jwt_verification_type", function() {
  if (this.value == "jwks_url") {
    document.getElementById('jwt_verification_key').value = localStorage.getItem("jwks_endpoint");
  }
});

// ---------------------------------------------------------------------------
// "Return to debugger" — point back at whichever page sent us here, named by a
// ?from= parameter (the same convention the tools pages use). Only known pages
// are honoured, so the parameter cannot become an open redirect.
//
// debugger2.html additionally wants redirectFromTokenDetail=true: it is what
// tells that page to re-render the token panes it had before the detour.
// ---------------------------------------------------------------------------
var RETURN_TARGETS = {
  'debugger.html': '/debugger.html',
  'debugger2.html': '/debugger2.html?redirectFromTokenDetail=true',
  'vc-issuance-1.html': '/vc-issuance-1.html',
  'vc-issuance-2.html': '/vc-issuance-2.html',
  'vc-issuance-3.html': '/vc-issuance-3.html',
  'vc-issuance-4.html': '/vc-issuance-4.html'
};
var RETURN_LABELS = {
  'vc-issuance-1.html': 'Return to SD-JWT VC issuance (step 1)',
  'vc-issuance-2.html': 'Return to SD-JWT VC issuance (step 2)',
  'vc-issuance-3.html': 'Return to SD-JWT VC issuance (step 3)',
  'vc-issuance-4.html': 'Return to SD-JWT VC issuance (step 4)'
};

function setReturnLinks() {
  var from = getParameterByName('from');
  var target = RETURN_TARGETS[from];
  if (!target) return;                       // no (or unknown) origin: leave the default
  var label = RETURN_LABELS[from];
  var links = document.querySelectorAll('a.return_link');
  for (var i = 0; i < links.length; i++) {
    links[i].setAttribute('href', target);
    if (label) links[i].textContent = label;
  }
  log.debug('Return link points back at ' + target + '.');
}

window.onload = function() {
  log.debug("Entering onload function.");
  setReturnLinks();

  // Restore claims validation fields from localStorage
  const storedPurpose = localStorage.getItem('jwt_purpose');
  if (storedPurpose) document.getElementById('jwt_purpose').value = storedPurpose;
  const storedIss = localStorage.getItem('jwt_expected_iss') || localStorage.getItem('issuer');
  if (storedIss) document.getElementById('jwt_expected_iss').value = storedIss;
  const storedAud = localStorage.getItem('jwt_expected_aud');
  if (storedAud) document.getElementById('jwt_expected_aud').value = storedAud;
  const storedClientId = localStorage.getItem('jwt_claims_client_id');
  if (storedClientId) document.getElementById('jwt_claims_client_id').value = storedClientId;
  else {
    const globalClientId = localStorage.getItem('client_id');
    if (globalClientId) document.getElementById('jwt_claims_client_id').value = globalClientId;
  }
  const storedScope = localStorage.getItem('jwt_expected_scope') || localStorage.getItem('scope');
  if (storedScope) document.getElementById('jwt_expected_scope').value = storedScope;
  const storedSkew = localStorage.getItem('jwt_clock_skew');
  document.getElementById('jwt_clock_skew').value = (storedSkew !== null && storedSkew !== '') ? storedSkew : '30';

  var jwt = resolveTokenFromParams() || "";
  // Retrieve IANA JWT claim assignments
  fetch(appconfig.apiUrl + "/claimdescription")
  .then((response) => response.text())
  .then((body_text) => {
    console.log(body_text);
    parser = new DOMParser();
    xmlDoc = parser.parseFromString(body_text, "application/xml");
    records = xmlDoc.getElementsByTagName("record");
    for (i = 0; i < records.length; i++)
    {
      claim = records[i].getElementsByTagName("value")[0].textContent;
      description = records[i].getElementsByTagName("description")[0].textContent;
  //    console.log(claim + ":" + description);
      claimDescriptionDictionary[claim] = description;
    }
  }).then( () => {
    // Merge vendor claim descriptions for any claim not already covered by IANA
    Object.keys(vendorClaims).forEach(function(vendor) {
      var claims = vendorClaims[vendor];
      Object.keys(claims).forEach(function(claim) {
        if (claim.startsWith('_')) return; // skip metadata keys
        if (!claimDescriptionDictionary[claim]) {
          var entry = claims[claim];
          claimDescriptionDictionary[claim] = (typeof entry === 'object') ? entry.description : entry;
          if (typeof entry === 'object' && entry.url) {
            claimUrlDictionary[claim] = entry.url;
          }
        }
      });
    });
    buildClaimSourcesFootnote();
    Object.keys(claimDescriptionDictionary).forEach( (key) => {
      log.debug("Claims Description Map Entry: " + key + ":" + claimDescriptionDictionary[key]);
      log.debug('jwt: ' + jwt);
      const decodedJWT = decodeJWT(jwt);
      log.debug('decoded jwt: ' + JSON.stringify(decodedJWT));
      // Populate JSON tab.  
      $('#jwt_header').val(JSON.stringify(decodedJWT.header, null, 2));
      $('#jwt_payload').val(JSON.stringify(decodedJWT.payload, null, 2));
      // Populate Key-Pair tab
      keyPairJWTHeader = '<table border="1">'
                       +   '<tr>'
                       +     '<td><b>Claim</b></td><td><b>Value</b></td><td class="description-col"><b>Description</b> <sup><a href="#claim-sources" title="View claim description sources">†</a></sup></td>'
                       +   '</tr>'
      Object.keys(decodedJWT.header).forEach(key => {
        var desc = claimDescriptionDictionary[key];
        var descCell = '';
        if (desc) {
          var url = claimUrlDictionary[key];
          descCell = '<td class="description-col">' + desc
                   + (url ? ' <a href="' + url + '" target="_blank" rel="noopener noreferrer">[ref]</a>' : '')
                   + '</td>';
        }
        if ( typeof decodedJWT.header[key] === "object" )
        {
          keyPairJWTHeader += '<tr>'
                            + '<td>' + key + '</td>'
                            + '<td>' + JSON.stringify(decodedJWT.header[key]) + '</td>'
                            + descCell
                            + '</tr>';
        } else {
          keyPairJWTHeader += '<tr>'
                            + '<td>' + key + '</td>'
                            + '<td>' + decodedJWT.header[key] + '</td>'
                            + descCell
                            + '</tr>';
        }
      });
      keyPairJWTHeader += '</table>';
      $('#key_pair_jwt_header').html(keyPairJWTHeader);
      var TIMESTAMP_CLAIMS = ['iat', 'exp', 'nbf', 'auth_time', 'updated_at'];
      keyPairJWTPayload = '<table border="1">'
                       +   '<tr>'
                       +     '<td><b>Claim</b></td><td><b>Value</b></td><td class="description-col"><b>Description</b> <sup><a href="#claim-sources" title="View claim description sources">†</a></sup></td>'
                       +   '</tr>'
      Object.keys(decodedJWT.payload).forEach(key => {
        var desc = claimDescriptionDictionary[key];
        var descCell = '';
        if (desc) {
          var url = claimUrlDictionary[key];
          descCell = '<td class="description-col">' + desc
                   + (url ? ' <a href="' + url + '" target="_blank" rel="noopener noreferrer">[ref]</a>' : '')
                   + '</td>';
        }
        var valueCell;
        if (typeof decodedJWT.payload[key] === "object") {
          valueCell = '<td>' + JSON.stringify(decodedJWT.payload[key]) + '</td>';
        } else if (TIMESTAMP_CLAIMS.indexOf(key) !== -1 && typeof decodedJWT.payload[key] === 'number') {
          var humanDate = new Date(decodedJWT.payload[key] * 1000).toLocaleString(undefined, { timeZoneName: 'short' });
          valueCell = '<td><span class="ts-tooltip">' + decodedJWT.payload[key]
                    + '<span class="ts-tooltip-text">' + humanDate + '</span>'
                    + '</span></td>';
        } else {
          valueCell = '<td>' + decodedJWT.payload[key] + '</td>';
        }
        keyPairJWTPayload += '<tr><td>' + key + '</td>' + valueCell + descCell + '</tr>';
      });
      keyPairJWTPayload += '</table>';
      $('#key_pair_jwt_payload').html(keyPairJWTPayload);
    });
  })
  .catch( (error) => {
    log.error("An error was encountered: " + error.stack);
  });
}

function populateTable(evt, tabName) {
  log.debug("Entering populateTable().");
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }
  document.getElementById(tabName).style.display = "block";
  evt.currentTarget.className += " active";
  log.debug("Leaving populateTable().");
}

function copyHtmlToClipboard(elementId) {
  log.debug("Entering copyHtmlToClipboard(), elementId=" + elementId);
  const el = document.getElementById(elementId);
  if (!el) {
    log.error("copyHtmlToClipboard: element not found: " + elementId);
    return false;
  }
  navigator.clipboard.writeText(el.innerHTML).catch(function(err) {
    log.error("copyHtmlToClipboard: failed to write to clipboard: " + err);
  });
  return false;
}

function buildClaimSourcesFootnote() {
  log.debug("Entering buildClaimSourcesFootnote().");
  var html = '<p><sup>†</sup> <strong>Claim descriptions were gathered from the following sources:</strong></p>';
  Object.keys(vendorClaims).forEach(function(vendor) {
    var data = vendorClaims[vendor];
    var vendorName = data['_vendor_name'] || vendor;
    var sources = data['_sources'];
    if (!sources || !sources.length) return;
    html += '<p><em>' + vendorName + ':</em></p><ul>';
    sources.forEach(function(source) {
      html += '<li><a href="' + source.url + '" target="_blank" rel="noopener noreferrer">' + source.name + '</a></li>';
    });
    html += '</ul>';
  });
  document.getElementById('claim-sources').innerHTML = html;
  log.debug("Leaving buildClaimSourcesFootnote().");
}

function copyToClipboard(elementId) {
  log.debug("Entering copyToClipboard(), elementId=" + elementId);
  const el = document.getElementById(elementId);
  if (!el) {
    log.error("copyToClipboard: element not found: " + elementId);
    return false;
  }
  var text = el.value;
  const toggleMap = { 'jwt_header': 'strip_newlines_header', 'jwt_payload': 'strip_newlines_payload' };
  const toggleEl = document.getElementById(toggleMap[elementId]);
  if (toggleEl && toggleEl.checked) {
    text = text.replace(/[\r\n]/g, '');
  }
  navigator.clipboard.writeText(text).catch(function(err) {
    log.error("copyToClipboard: failed to write to clipboard: " + err);
  });
  log.debug("Leaving copyToClipboard().");
  return false;
}

function clickLink() {
  log.debug("Entering clickLink().");
  writeValuesToLocalStorage();
  log.debug("Leaving clickLink().");
  return true;
}

module.exports = {
 decodeJWT,
 verifyJWT,
 validateClaims,
 copyToClipboard,
 copyHtmlToClipboard,
 populateTable,
 clickLink
};
