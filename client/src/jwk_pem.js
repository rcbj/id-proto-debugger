// File: jwk_pem.js
//
// ---------------------------------------------------------------------------
// A JWK public key rendered as a SubjectPublicKeyInfo PEM — the one thing the
// JWKS page wanted from `jwk-to-pem`.
//
// It is written out here rather than taken from that package because
// `jwk-to-pem` reaches `elliptic` (it builds the EC point through
// `elliptic.ec`), and `elliptic` carries GHSA-848j-6mx2-7j84 with no patched
// version in existence — the advisory's range is `<=6.6.1` and 6.6.1 is the
// latest release. browserify bundles what a page requires, so that package
// put a permanently-vulnerable ECDSA implementation into the shipped
// jwks.js bundle in exchange for a public-key encoding this file does in
// about sixty lines of DER. Nothing here signs anything, so there is no
// ECDSA implementation to be vulnerable.
//
// The output is byte-identical to what `jwk-to-pem` produced, and
// `tests/jwk_pem.js` is what holds it to that: the encoding is a wire format
// other tools have to read, so "close enough" is not a thing it can be.
//
// Scope is deliberately the same as the call site's: PUBLIC keys, kty RSA and
// EC on the three NIST curves, which is exactly what `jwk-to-pem` supported.
// A `d` member is ignored rather than honoured — the JWKS page displays keys
// an identity provider published, and those are public by definition.
// ---------------------------------------------------------------------------


var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "jwk_pem",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      // A missing log level must not stop the module loading.
      return "info";
    }
  })()
});


// --- the object identifiers, pre-encoded ------------------------------------
//
// Written as finished DER (tag 0x06, length, contents) because these five are
// the only OIDs this module will ever emit, and a general OID encoder would be
// more code than the values it produces.

// 1.2.840.113549.1.1.1  rsaEncryption
var OID_RSA_ENCRYPTION = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
// 1.2.840.10045.2.1     id-ecPublicKey
var OID_EC_PUBLIC_KEY = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

var CURVES = {
  // 1.2.840.10045.3.1.7  prime256v1
  "P-256": { oid: [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], coordinateBytes: 32 },
  // 1.3.132.0.34         secp384r1
  "P-384": { oid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22], coordinateBytes: 48 },
  // 1.3.132.0.35         secp521r1
  "P-521": { oid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23], coordinateBytes: 66 }
};

var DER_NULL = [0x05, 0x00];


// --- base64url --------------------------------------------------------------

function b64uToBytes(value, member) {
  log.debug("Entering b64uToBytes().");
  if (typeof value !== "string" || value === "") {
    throw new TypeError('Invalid JWK: missing or non-string "' + member + '"');
  }
  var b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 = b64 + "=";
  }
  var raw;
  try {
    // atob in the browser bundles, Buffer for the node-based tests. Neither is
    // strict about stray characters, so the shape is checked above and the
    // decoded length is checked by the callers.
    raw = typeof atob === "function"
      ? atob(b64)
      : Buffer.from(b64, "base64").toString("binary");
  } catch (e) {
    throw new TypeError('Invalid JWK: "' + member + '" is not base64url (' + e.message + ")");
  }
  var bytes = new Array(raw.length);
  for (var i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i) & 0xff;
  }
  log.debug("Leaving b64uToBytes().");
  return bytes;
}


// --- DER --------------------------------------------------------------------

function derLength(count) {
  log.debug("Entering derLength().");
  if (count < 0x80) {
    return [count];
  }
  var lengthBytes = [];
  var remaining = count;
  while (remaining > 0) {
    lengthBytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  log.debug("Leaving derLength().");
  return [0x80 | lengthBytes.length].concat(lengthBytes);
}

function derTlv(tag, contents) {
  return [tag].concat(derLength(contents.length), contents);
}

function derSequence(parts) {
  var contents = [];
  for (var i = 0; i < parts.length; i++) {
    contents = contents.concat(parts[i]);
  }
  return derTlv(0x30, contents);
}

// A DER INTEGER is signed and minimally encoded: leading zero bytes come off,
// and a leading zero goes back on when the top bit would otherwise read as a
// negative number. An RSA modulus hits the second case roughly half the time.
function derInteger(bytes) {
  log.debug("Entering derInteger().");
  var start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00) {
    start++;
  }
  var magnitude = bytes.slice(start);
  if ((magnitude[0] & 0x80) !== 0) {
    magnitude = [0x00].concat(magnitude);
  }
  log.debug("Leaving derInteger().");
  return derTlv(0x02, magnitude);
}

// The leading 0x00 is the count of unused bits in the final octet. Everything
// encoded here is whole octets, so it is always zero.
function derBitString(bytes) {
  return derTlv(0x03, [0x00].concat(bytes));
}


// --- PEM --------------------------------------------------------------------

function bytesToBase64(bytes) {
  var chunk = [];
  for (var i = 0; i < bytes.length; i++) {
    chunk.push(String.fromCharCode(bytes[i]));
  }
  var raw = chunk.join("");
  return typeof btoa === "function"
    ? btoa(raw)
    : Buffer.from(raw, "binary").toString("base64");
}

function toPem(derBytes) {
  log.debug("Entering toPem().");
  var body = bytesToBase64(derBytes);
  var lines = [];
  for (var i = 0; i < body.length; i += 64) {
    lines.push(body.slice(i, i + 64));
  }
  log.debug("Leaving toPem().");
  return "-----BEGIN PUBLIC KEY-----\n" + lines.join("\n") + "\n-----END PUBLIC KEY-----\n";
}


// --- the key types ----------------------------------------------------------

// SubjectPublicKeyInfo ::= SEQUENCE {
//   algorithm SEQUENCE { algorithm OID, parameters NULL },
//   subjectPublicKey BIT STRING wrapping
//     RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } }
function rsaSpki(jwk) {
  log.debug("Entering rsaSpki().");
  var modulus = b64uToBytes(jwk.n, "n");
  var exponent = b64uToBytes(jwk.e, "e");
  var rsaPublicKey = derSequence([derInteger(modulus), derInteger(exponent)]);
  log.debug("Leaving rsaSpki().");
  return derSequence([
    derSequence([OID_RSA_ENCRYPTION, DER_NULL]),
    derBitString(rsaPublicKey)
  ]);
}

// SubjectPublicKeyInfo ::= SEQUENCE {
//   algorithm SEQUENCE { algorithm id-ecPublicKey, parameters namedCurve OID },
//   subjectPublicKey BIT STRING wrapping the uncompressed point 0x04 || X || Y }
function ecSpki(jwk) {
  log.debug("Entering ecSpki().");
  var curve = CURVES[jwk.crv];
  if (!curve) {
    throw new TypeError('Unsupported curve "' + jwk.crv + '"');
  }
  var x = b64uToBytes(jwk.x, "x");
  var y = b64uToBytes(jwk.y, "y");
  // RFC 7518 section 6.2.1.2/6.2.1.3: each coordinate is the full field size,
  // zero-padded on the LEFT. Publishers do sometimes trim a leading zero, and
  // an unpadded point is a point at the wrong place, so pad rather than trust.
  var point = [0x04]
    .concat(padCoordinate(x, curve.coordinateBytes, "x", jwk.crv))
    .concat(padCoordinate(y, curve.coordinateBytes, "y", jwk.crv));
  log.debug("Leaving ecSpki().");
  return derSequence([
    derSequence([OID_EC_PUBLIC_KEY, curve.oid]),
    derBitString(point)
  ]);
}

function padCoordinate(bytes, size, member, crv) {
  log.debug("Entering padCoordinate().");
  if (bytes.length > size) {
    throw new TypeError(
      'Invalid JWK: "' + member + '" is ' + bytes.length + " bytes, too long for " + crv
    );
  }
  var padded = bytes;
  while (padded.length < size) {
    padded = [0x00].concat(padded);
  }
  log.debug("Leaving padCoordinate().");
  return padded;
}


// --- the entry point --------------------------------------------------------

// Signature and failure behaviour match `jwk-to-pem`: a PEM string back, and a
// throw naming the key type for anything it did not support. The JWKS page
// relies on the throw to mark one key unrenderable without losing the others.
function jwkToPem(jwk) {
  log.debug("Entering jwkToPem().");
  if (!jwk || typeof jwk !== "object") {
    throw new TypeError("Invalid JWK: expected an object");
  }
  var der;
  switch (jwk.kty) {
    case "RSA":
      der = rsaSpki(jwk);
      break;
    case "EC":
      der = ecSpki(jwk);
      break;
    default:
      throw new TypeError('Unsupported key type "' + jwk.kty + '"');
  }
  log.debug("Leaving jwkToPem().");
  return toPem(der);
}


module.exports = jwkToPem;
module.exports.jwkToPem = jwkToPem;
module.exports.SUPPORTED_CURVES = Object.keys(CURVES);
