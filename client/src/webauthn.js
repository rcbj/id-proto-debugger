// File: webauthn.js
//
// ---------------------------------------------------------------------------
// WebAuthn (W3C Web Authentication, Level 3) artifacts: decoding them, and
// verifying an assertion. No DOM in here, which is what lets
// tests/webauthn_decode.js drive it in node against artifacts a real browser
// produced.
//
// What the browser hands JavaScript, and therefore what this can read:
// clientDataJSON, the attestation object, the authenticator data, the
// credential public key, the signature, the extension results. What it never
// hands anybody: the private key, the PIN, the biometric, the authenticator's
// internal state, and the CTAP exchange underneath. That boundary is the
// subject of the Ceremony Trace pane, not a limitation to be worked around.
//
// Three things in here have bitten every implementation that has ever been
// written, and each has a comment at the point it matters:
//
//   1. **ECDSA signatures arrive DER-encoded and Web Crypto wants raw r‖s.**
//      Hand the DER straight to `crypto.subtle.verify` and it returns false —
//      not an error, FALSE — for a perfectly valid signature. The debugger then
//      reports the authenticator as faulty, which is the worst possible outcome
//      for a tool whose whole job is to say what is wrong.
//   2. **The signed message is `authenticatorData ‖ SHA-256(clientDataJSON)`**
//      — the hash of the client data, not the client data, and the raw bytes of
//      the authenticator data, not a re-encoding of the parsed fields.
//   3. **clientDataJSON must be parsed, never compared.** Chrome inserts a
//      filler member (`other_keys_can_be_added_here`) into some ceremonies and
//      not others, at random, specifically to break implementations that
//      compare it against a template. Measured happening here on 2026-08-08.
//
// A note on `crypto`: this module reaches Web Crypto through the GLOBAL
// (`crypto.subtle`), never `require("crypto")`. That is the rule the whole
// client tree follows — browserify substitutes a bare crypto require with
// crypto-browserify, which drags in `elliptic` and its unpatchable
// GHSA-848j-6mx2-7j84 — and it costs nothing, because node has exposed the same
// global since 18. `tests/jwk_pem_encoding.js` enforces it.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var cbor = require("./cbor");
var cose = require("./cose");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (a node-based test loading this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "webauthn",
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

// Authenticator data flags, section 6.1.
var FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 };

function base64urlToBytes(s) {
  log.debug("Entering base64urlToBytes().");
  var t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) {
    t += "=";
  }
  if (typeof atob === "function") {
    var bin = atob(t), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    log.debug("Leaving base64urlToBytes().");
    return out;
  }
  log.debug("Leaving base64urlToBytes().");
  return new Uint8Array(Buffer.from(t, "base64"));
}

function bytesToBase64url(bytes) {
  log.debug("Entering bytesToBase64url().");
  var b64 = (typeof btoa === "function")
    ? btoa(String.fromCharCode.apply(null, bytes))
    : Buffer.from(bytes).toString("base64");
  log.debug("Leaving bytesToBase64url().");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function bytesToHex(bytes) {
  log.debug("Entering bytesToHex().");
  var s = "";
  for (var i = 0; i < bytes.length; i++) {
    s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
  }
  log.debug("Leaving bytesToHex().");
  return s;
}

function equalBytes(a, b) {
  log.debug("Entering equalBytes().");
  if (!a || !b || a.length !== b.length) {
    log.debug("Leaving equalBytes().");
    return false;
  }
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  log.debug("Leaving equalBytes().");
  return diff === 0;
}

// The AAGUID, in the 8-4-4-4-12 form everybody publishes them in.
function formatAaguid(bytes) {
  log.debug("Entering formatAaguid().");
  var h = bytesToHex(bytes);
  log.debug("Leaving formatAaguid().");
  return [h.slice(0, 8), h.slice(8, 12), h.slice(12, 16), h.slice(16, 20),
          h.slice(20)].join("-");
}

// --- clientDataJSON ---------------------------------------------------------

function parseClientDataJSON(bytes) {
  log.debug("Entering parseClientDataJSON(). bytes=" + (bytes && bytes.length));
  var text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  var parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error("clientDataJSON is not JSON: " + e.message);
  }
  var known = ["type", "challenge", "origin", "crossOrigin", "topOrigin",
      "tokenBinding"];
  var extra = Object.keys(parsed).filter(function (k) {
    return known.indexOf(k) === -1;
  });
  var out = {
    type: parsed.type,
    challenge: parsed.challenge,
    origin: parsed.origin,
    crossOrigin: parsed.crossOrigin,
    topOrigin: parsed.topOrigin,
    tokenBinding: parsed.tokenBinding,
    // Kept and surfaced rather than dropped: this is where Chrome's deliberate
    // anti-template filler shows up, and a user staring at an unexpected member
    // should be told what it is instead of wondering.
    extraMembers: extra,
    json: parsed,
    text: text,
    raw: bytes,
  };
  log.debug("Leaving parseClientDataJSON(). type=" + out.type + " origin=" +
            out.origin);
  return out;
}

// --- authenticator data -----------------------------------------------------

function parseAuthenticatorData(bytes) {
  log.debug("Entering parseAuthenticatorData(). bytes=" + (bytes &&
            bytes.length));
  if (!(bytes instanceof Uint8Array) || bytes.length < 37) {
    throw new Error("authenticator data must be at least 37 bytes; got " +
                    (bytes ? bytes.length : "nothing"));
  }
  var flags = bytes[32];
  var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  var out = {
    rpIdHash: bytes.subarray(0, 32),
    rpIdHashHex: bytesToHex(bytes.subarray(0, 32)),
    flagsByte: flags,
    flags: {
      UP: !!(flags & FLAG.UP),
      UV: !!(flags & FLAG.UV),
      BE: !!(flags & FLAG.BE),
      BS: !!(flags & FLAG.BS),
      AT: !!(flags & FLAG.AT),
      ED: !!(flags & FLAG.ED),
    },
    signCount: view.getUint32(33, false),
    aaguid: null,
    aaguidHex: null,
    credentialId: null,
    credentialPublicKey: null,
    credentialPublicKeyJwk: null,
    extensions: null,
    raw: bytes,
  };

  var offset = 37;
  if (out.flags.AT) {
    if (bytes.length < offset + 18) {
      throw new Error("the AT flag is set but there is no room for attested " +
                      "credential data");
    }
    out.aaguid = bytes.subarray(offset, offset + 16);
    out.aaguidHex = formatAaguid(out.aaguid);
    offset += 16;
    // Big-endian uint16, read off the array directly rather than through the
    // DataView: `bytes` may itself be a view into a larger buffer, and mixing
    // the two indexing bases is how an off-by-byteOffset bug gets in.
    var idLength = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    if (bytes.length < offset + idLength) {
      throw new Error("the credential ID claims " + idLength +
                      " bytes but only " +
                      (bytes.length - offset) + " remain");
    }
    out.credentialId = bytes.subarray(offset, offset + idLength);
    offset += idLength;
    // The public key is CBOR of unknown length sitting mid-buffer, which is why
    // cbor.decodeFirst exists: the extension data, if any, begins where it
    // ends.
    var key = cbor.decodeFirst(bytes.subarray(offset));
    out.credentialPublicKey = key.value;
    offset += key.bytesRead;
    try {
      out.credentialPublicKeyJwk = cose.coseToJwk(key.value);
    } catch (e) {
      // An unreadable key is a finding to report, not a reason to lose the
      // flags and sign count the caller also asked for.
      out.credentialPublicKeyError = e.message;
    }
  }

  if (out.flags.ED) {
    var ext = cbor.decodeFirst(bytes.subarray(offset));
    out.extensions = ext.value;
    offset += ext.bytesRead;
  }

  if (offset !== bytes.length) {
    // Not fatal — the fields above are all still true — but it means the buffer
    // is not what the flags describe, which is exactly the sort of thing this
    // tool exists to notice.
    out.trailingBytes = bytes.length - offset;
  }
  log.debug("Leaving parseAuthenticatorData(). signCount=" + out.signCount +
            " AT=" + out.flags.AT + " ED=" + out.flags.ED);
  return out;
}

// --- attestation object -----------------------------------------------------

function parseAttestationObject(bytes) {
  log.debug("Entering parseAttestationObject(). bytes=" + (bytes &&
            bytes.length));
  var decoded = cbor.decode(bytes);
  if (!(decoded instanceof Map)) {
    throw new Error("an attestation object must be a CBOR map");
  }
  var fmt = decoded.get("fmt");
  var authData = decoded.get("authData");
  var attStmt = decoded.get("attStmt");
  if (typeof fmt !== "string") {
    throw new Error("the attestation object has no `fmt`");
  }
  if (!(authData instanceof Uint8Array)) {
    throw new Error("the attestation object has no `authData` byte string");
  }
  var out = {
    fmt: fmt,
    attStmt: attStmt instanceof Map ? attStmt : new Map(),
    authData: parseAuthenticatorData(authData),
    authDataBytes: authData,
    raw: bytes,
  };
  out.attStmtSummary = summariseAttStmt(fmt, out.attStmt);
  log.debug("Leaving parseAttestationObject(). fmt=" + fmt);
  return out;
}

// What is in the attestation statement, per format. The certificate chain is
// reported as present with its lengths rather than parsed: X.509 is a different
// problem, the debugger already has a certificate pane elsewhere, and claiming
// to identify an authenticator from a chain we have not validated would be the
// kind of confident wrongness this tool must not produce.
function summariseAttStmt(fmt, attStmt) {
  log.debug("Entering summariseAttStmt(). fmt=" + fmt);
  var out = { format: fmt, recognised: true, alg: null, algName: null,
      sigBytes: null, x5c: null, note: null };
  var known = ["packed", "tpm", "android-key", "android-safetynet", "apple",
      "fido-u2f", "none"];
  if (known.indexOf(fmt) === -1) {
    out.recognised = false;
    out.note = "Unrecognised attestation format. The statement is shown raw; " +
        "nothing here can " +
               "verify it, which is a gap in this decoder rather than a fault in the credential.";
    log.debug("Leaving summariseAttStmt(). unrecognised");
    return out;
  }
  if (fmt === "none") {
    out.note = "No attestation. The authenticator declined to identify " +
        "itself, which is the " +
               "privacy-preserving default and not an error.";
    log.debug("Leaving summariseAttStmt(). none");
    return out;
  }
  var alg = attStmt.get("alg");
  if (typeof alg === "number") {
    out.alg = alg;
    out.algName = cose.algorithmName(alg);
  }
  var sig = attStmt.get("sig");
  if (sig instanceof Uint8Array) {
    out.sigBytes = sig.length;
  }
  var x5c = attStmt.get("x5c");
  if (Array.isArray(x5c)) {
    out.x5c = x5c.map(function (c) {
      return { bytes: c instanceof Uint8Array ? c.length : null,
              base64: c instanceof Uint8Array ? bytesToBase64url(c) : null };
    });
  }
  log.debug("Leaving summariseAttStmt(). alg=" + out.algName + " x5c=" +
            (out.x5c ? out.x5c.length : 0));
  return out;
}

// --- signature verification -------------------------------------------------

// DER SEQUENCE { INTEGER r, INTEGER s } -> the fixed-width r‖s Web Crypto
// wants. See note 1 in the file header: getting this wrong produces `false`
// rather than an error, so it looks like a bad signature instead of a bad
// decoder.
function derToRawSignature(der, coordinateBytes) {
  log.debug("Entering derToRawSignature(). der=" + der.length + " coord=" +
            coordinateBytes);
  if (der[0] !== 0x30) {
    throw new Error("an ECDSA signature should be a DER SEQUENCE (0x30); " +
                    "this starts 0x" +
                    der[0].toString(16));
  }
  // Length may be short-form or one-byte long-form; nothing here is ever big
  // enough to need more.
  var offset = (der[1] & 0x80) ? 2 + (der[1] & 0x7f) : 2;
  function readInt() {
    log.debug("Entering readInt().");
    if (der[offset] !== 0x02) {
      throw new Error("expected a DER INTEGER at byte " + offset);
    }
    var len = der[offset + 1];
    var start = offset + 2;
    offset = start + len;
    var v = der.subarray(start, start + len);
    // DER pads with a leading zero to keep the value positive; the raw form
    // does not want it. Conversely a short value is left-padded to the
    // coordinate width.
    while (v.length > 1 && v[0] === 0x00) {
      v = v.subarray(1);
    }
    if (v.length > coordinateBytes) {
      throw new Error("an ECDSA component is " + v.length +
                      " bytes, wider than the curve's " +
                      coordinateBytes);
    }
    var padded = new Uint8Array(coordinateBytes);
    padded.set(v, coordinateBytes - v.length);
    log.debug("Leaving readInt().");
    return padded;
  }
  var r = readInt(), s = readInt();
  var raw = new Uint8Array(coordinateBytes * 2);
  raw.set(r, 0);
  raw.set(s, coordinateBytes);
  log.debug("Leaving derToRawSignature().");
  return raw;
}

var COORDINATE_BYTES = { "P-256": 32, "P-384": 48, "P-521": 66 };

// Verify an assertion the way a relying party must (section 7.2), reporting
// every check rather than one boolean — the point of the pane is to show WHICH
// step failed, and a single "invalid" would be useless for that.
//
// `expected` carries the relying party's side: challenge (base64url), origin,
// rpId, requireUserVerification, and previousSignCount when one is known.
async function verifyAssertion(input) {
  log.debug("Entering verifyAssertion().");
  log.info("Entering verifyAssertion().");
  var checks = [];
  function record(name, ok, detail) {
    log.debug("Entering record().");
    checks.push({ name: name, ok: ok, detail: detail });
    log.debug("Leaving record().");
  }

  var authDataBytes = input.authenticatorData;
  var clientDataBytes = input.clientDataJSON;
  var signature = input.signature;
  var jwk = input.publicKeyJwk;
  var expected = input.expected || {};

  var clientData = parseClientDataJSON(clientDataBytes);
  var authData = parseAuthenticatorData(authDataBytes);

  record("clientData.type is webauthn.get", clientData.type === "webauthn.get",
         "type = " + JSON.stringify(clientData.type));

  if (expected.challenge) {
    record("challenge matches the one the RP issued",
           clientData.challenge === expected.challenge,
           "clientData carries " + clientData.challenge + "; expected " +
               expected.challenge);
  }
  if (expected.origin) {
    record("origin matches the RP's origin",
           clientData.origin === expected.origin,
           "clientData carries " + clientData.origin + "; expected " +
               expected.origin);
  }
  if (expected.rpId) {
    var digest = await crypto.subtle.digest("SHA-256",
        new TextEncoder().encode(expected.rpId));
    var ok = equalBytes(authData.rpIdHash, new Uint8Array(digest));
    record("rpIdHash is SHA-256 of the RP ID", ok,
           "authenticator data carries " + authData.rpIdHashHex + "; SHA-256(" +
               expected.rpId +
           ") is " + bytesToHex(new Uint8Array(digest)));
  }

  record("user presence (UP) was demonstrated", authData.flags.UP,
         "UP flag " + (authData.flags.UP ? "set" : "clear"));
  if (expected.requireUserVerification) {
    // Deliberately its own check rather than folded into the signature: an
    // assertion with UV clear is correctly signed, and reporting it as a bad
    // signature would send the user hunting for the wrong thing.
    record("user verification (UV) was performed, as required",
           authData.flags.UV,
           "UV flag " + (authData.flags.UV ? "set" : "clear") +
           (authData.flags.UV ? "" : " — the signature is valid; the " +
            "ceremony simply did not verify the user"));
  }
  if (typeof expected.previousSignCount === "number") {
    var advanced = authData.signCount === 0 && expected.previousSignCount === 0
      ? true
      : authData.signCount > expected.previousSignCount;
    record("signature counter advanced", advanced,
           "counter is " + authData.signCount + ", previously " +
               expected.previousSignCount +
           (advanced ? "" : " — a counter that does not advance can mean a " +
            "cloned authenticator, " +
                            "though authenticators that never increment " +
                                "report 0 throughout"));
  }

  // The signed message: raw authenticator data followed by the HASH of the
  // client data. Note 2 in the header.
  var clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256",
      clientDataBytes));
  var signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
  signedData.set(authDataBytes, 0);
  signedData.set(clientDataHash, authDataBytes.length);

  var algName = jwk.alg || (jwk.kty === "RSA" ? "RS256" : "ES256");
  var spec = null;
  Object.keys(cose.ALG).forEach(function (k) {
    if (cose.ALG[k].name === algName) {
      spec = cose.ALG[k];
    }
  });
  if (!spec) {
    throw new Error("no verification parameters for algorithm " + algName);
  }

  var sigForVerify = signature;
  if (spec.derSig) {
    sigForVerify = derToRawSignature(signature, COORDINATE_BYTES[jwk.crv] ||
        32);
  }

  var key = await crypto.subtle.importKey("jwk", stripAlg(jwk), spec.webCrypto,
      false, ["verify"]);
  var valid = await crypto.subtle.verify(spec.verify, key, sigForVerify,
      signedData);
  record("signature verifies against the credential public key", valid,
         algName + " over " + signedData.length +
             " bytes (authenticatorData ‖ SHA-256(clientDataJSON))");

  var allOk = checks.every(function (c) {
    return c.ok;
  });
  log.info("Leaving verifyAssertion(). valid=" + allOk + " checks=" +
           checks.length);
  log.debug("Leaving verifyAssertion().");
  return {
    valid: allOk,
    signatureValid: valid,
    checks: checks,
    clientData: clientData,
    authenticatorData: authData,
    signedDataLength: signedData.length,
  };
}

// Web Crypto rejects a JWK whose `alg` it does not recognise for the chosen
// import algorithm (COSE names like "ES256" are JOSE names, but the pairing is
// checked strictly), and the algorithm is passed separately anyway.
function stripAlg(jwk) {
  log.debug("Entering stripAlg().");
  var copy = {};
  Object.keys(jwk).forEach(function (k) {
    if (k !== "alg" && k !== "kid") {
      copy[k] = jwk[k];
    }
  });
  copy.ext = true;
  log.debug("Leaving stripAlg().");
  return copy;
}

module.exports = {
  parseClientDataJSON: parseClientDataJSON,
  parseAuthenticatorData: parseAuthenticatorData,
  parseAttestationObject: parseAttestationObject,
  summariseAttStmt: summariseAttStmt,
  verifyAssertion: verifyAssertion,
  derToRawSignature: derToRawSignature,
  base64urlToBytes: base64urlToBytes,
  bytesToBase64url: bytesToBase64url,
  bytesToHex: bytesToHex,
  formatAaguid: formatAaguid,
  FLAG: FLAG,
};
