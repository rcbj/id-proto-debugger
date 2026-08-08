// File: cose.js
//
// ---------------------------------------------------------------------------
// COSE_Key (RFC 9052 section 7) — the shape a WebAuthn credential public key
// arrives in — rendered as a JWK, and from there as a SubjectPublicKeyInfo PEM.
//
// COSE is CBOR with integer labels: `1` is the key type, `3` is the algorithm,
// and the key material hangs off NEGATIVE labels whose meaning depends on the
// key type — `-1` is the curve for an EC2 key and the modulus for an RSA one.
// That overloading is the whole difficulty, and it is why this file is a table
// per key type rather than one flat lookup: read `-1` without knowing `kty`
// first and an RSA modulus is decoded as a curve identifier.
//
// The PEM comes from `./jwk_pem`, which already encodes a JWK as SPKI DER for
// the JWKS page. Reusing it is not only less code — it is the reason nothing
// here pulls in `elliptic`. See the note at the top of that file: `jwk-to-pem`
// builds its EC point through `elliptic`, which carries GHSA-848j-6mx2-7j84
// with no patched version, and browserify would put it in any bundle that
// required it. `tests/jwk_pem_encoding.js` enforces that rule across `client/src`.
//
// Scope is public keys, because that is all WebAuthn ever hands out. A COSE_Key
// carrying private material (`-4` for EC2) is refused rather than quietly
// stripped, on the grounds that being handed one means something has gone wrong
// upstream and the user should be told rather than reassured.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var jwkPem = require("./jwk_pem");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (a node-based test loading this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "cose",
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

// Common labels (RFC 9052 table 4).
var LABEL_KTY = 1, LABEL_KID = 2, LABEL_ALG = 3;

// Key types (RFC 9053 / the COSE Key Types registry).
var KTY = { 1: "OKP", 2: "EC2", 3: "RSA" };

// Curves (the COSE Elliptic Curves registry), with the JWK name each maps to.
var CURVE = {
  1: "P-256", 2: "P-384", 3: "P-521",
  6: "Ed25519", 7: "Ed448",
  4: "X25519", 5: "X448",
};

// Algorithms (the COSE Algorithms registry), with the JOSE name and enough
// detail to drive Web Crypto without a second table somewhere else.
var ALG = {
  "-7":   { name: "ES256", kty: "EC2", crv: "P-256", hash: "SHA-256", webCrypto: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" }, derSig: true },
  "-35":  { name: "ES384", kty: "EC2", crv: "P-384", hash: "SHA-384", webCrypto: { name: "ECDSA", namedCurve: "P-384" }, verify: { name: "ECDSA", hash: "SHA-384" }, derSig: true },
  "-36":  { name: "ES512", kty: "EC2", crv: "P-521", hash: "SHA-512", webCrypto: { name: "ECDSA", namedCurve: "P-521" }, verify: { name: "ECDSA", hash: "SHA-512" }, derSig: true },
  "-8":   { name: "EdDSA", kty: "OKP", hash: null,   webCrypto: { name: "Ed25519" }, verify: { name: "Ed25519" }, derSig: false },
  "-257": { name: "RS256", kty: "RSA", hash: "SHA-256", webCrypto: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: { name: "RSASSA-PKCS1-v1_5" }, derSig: false },
  "-258": { name: "RS384", kty: "RSA", hash: "SHA-384", webCrypto: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, verify: { name: "RSASSA-PKCS1-v1_5" }, derSig: false },
  "-259": { name: "RS512", kty: "RSA", hash: "SHA-512", webCrypto: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, verify: { name: "RSASSA-PKCS1-v1_5" }, derSig: false },
  "-37":  { name: "PS256", kty: "RSA", hash: "SHA-256", webCrypto: { name: "RSA-PSS", hash: "SHA-256" }, verify: { name: "RSA-PSS", saltLength: 32 }, derSig: false },
  "-38":  { name: "PS384", kty: "RSA", hash: "SHA-384", webCrypto: { name: "RSA-PSS", hash: "SHA-384" }, verify: { name: "RSA-PSS", saltLength: 48 }, derSig: false },
  "-39":  { name: "PS512", kty: "RSA", hash: "SHA-512", webCrypto: { name: "RSA-PSS", hash: "SHA-512" }, verify: { name: "RSA-PSS", saltLength: 64 }, derSig: false },
};

function algorithm(coseAlg) {
  return ALG[String(coseAlg)] || null;
}

function algorithmName(coseAlg) {
  var a = algorithm(coseAlg);
  return a ? a.name : "unrecognised (" + coseAlg + ")";
}

function base64url(bytes) {
  var b64 = (typeof btoa === "function")
    ? btoa(String.fromCharCode.apply(null, bytes))
    : Buffer.from(bytes).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function requireBytes(map, label, what) {
  var v = map.get(label);
  if (!(v instanceof Uint8Array)) {
    throw new Error("the COSE key has no " + what + " (label " + label + "), or it is not a byte string");
  }
  return v;
}

// A COSE_Key (a Map, as cbor.js produces) to a public JWK.
function coseToJwk(coseKey) {
  log.debug("Entering coseToJwk().");
  if (!(coseKey instanceof Map)) {
    throw new Error("expected a COSE_Key as a Map; got " + Object.prototype.toString.call(coseKey));
  }
  var ktyLabel = coseKey.get(LABEL_KTY);
  var kty = KTY[ktyLabel];
  if (!kty) {
    throw new Error("unsupported COSE key type " + JSON.stringify(ktyLabel));
  }
  var coseAlg = coseKey.get(LABEL_ALG);
  var alg = algorithm(coseAlg);
  var jwk;

  if (kty === "EC2") {
    // -4 is the private key `d`. Its presence means we were handed something we
    // should not have been; say so rather than silently publishing the rest.
    if (coseKey.has(-4)) {
      throw new Error("this COSE key carries private key material (label -4); refusing it");
    }
    var crv = CURVE[coseKey.get(-1)];
    if (!crv) {
      throw new Error("unsupported COSE curve " + JSON.stringify(coseKey.get(-1)));
    }
    jwk = {
      kty: "EC", crv: crv,
      x: base64url(requireBytes(coseKey, -2, "x coordinate")),
      y: base64url(requireBytes(coseKey, -3, "y coordinate")),
    };
  } else if (kty === "RSA") {
    if (coseKey.has(-3)) {
      throw new Error("this COSE key carries private key material (label -3); refusing it");
    }
    jwk = {
      kty: "RSA",
      n: base64url(requireBytes(coseKey, -1, "modulus")),
      e: base64url(requireBytes(coseKey, -2, "exponent")),
    };
  } else {
    // OKP — Ed25519 and friends.
    if (coseKey.has(-4)) {
      throw new Error("this COSE key carries private key material (label -4); refusing it");
    }
    var okpCrv = CURVE[coseKey.get(-1)];
    if (!okpCrv) {
      throw new Error("unsupported COSE curve " + JSON.stringify(coseKey.get(-1)));
    }
    jwk = { kty: "OKP", crv: okpCrv, x: base64url(requireBytes(coseKey, -2, "public key")) };
  }

  if (alg) {
    jwk.alg = alg.name;
    // A key whose kty disagrees with its alg is malformed, and the disagreement
    // is the interesting part — report it rather than trusting either.
    if (alg.kty !== kty) {
      throw new Error("the COSE key says kty " + kty + " but alg " + alg.name +
                      ", which is a " + alg.kty + " algorithm");
    }
    if (alg.crv && jwk.crv && alg.crv !== jwk.crv) {
      throw new Error("the COSE key says curve " + jwk.crv + " but alg " + alg.name +
                      ", which is defined on " + alg.crv);
    }
  }
  var kid = coseKey.get(LABEL_KID);
  if (kid instanceof Uint8Array) {
    jwk.kid = base64url(kid);
  }
  log.debug("Leaving coseToJwk(). kty=" + jwk.kty + " alg=" + jwk.alg);
  return jwk;
}

// The whole chain the analyzer's COSE pane shows: COSE_Key -> JWK -> PEM.
// jwk_pem covers RSA and the three NIST curves; an OKP key has no encoder there,
// so the PEM is reported as unavailable rather than the whole call failing —
// one unrenderable field must not cost the user the decoded key.
function describe(coseKey) {
  log.debug("Entering describe().");
  var jwk = coseToJwk(coseKey);
  var out = {
    jwk: jwk,
    coseAlg: coseKey.get(LABEL_ALG),
    algorithm: algorithmName(coseKey.get(LABEL_ALG)),
    pem: null,
    pemUnavailable: null,
  };
  try {
    out.pem = jwkPem(jwk);
  } catch (e) {
    // Not a failure of the key — a gap in the encoder's coverage (OKP today).
    // The JWK above is still correct and still the useful part.
    out.pemUnavailable = e.message;
  }
  log.debug("Leaving describe(). pem=" + (out.pem ? "yes" : "no"));
  return out;
}

module.exports = {
  coseToJwk: coseToJwk,
  describe: describe,
  algorithm: algorithm,
  algorithmName: algorithmName,
  KTY: KTY,
  CURVE: CURVE,
  ALG: ALG,
};
