// File: vci_wallet.js
//
// ---------------------------------------------------------------------------
// The wallet's half of an OID4VCI Credential Request, with no DOM in it.
//
// Two pages make that request, for two different reasons:
//
//   vc-issuance-2.html   the first issuance — the access token has just
//                               been obtained and the credential does not exist
//                               yet;
//   vc-issuance-4.html   a refresh (OID4VCI section 14.5) — the wallet
//                               already holds a credential and asks the issuer
//                               for an up-to-date one.
//
// On the wire those two are the SAME call, so the parts that build it live here
// once: the holder key pair, the c_nonce, the proof of possession, the request
// body, the text of the assembled call, and the reading of a Credential
// Response whether it came back as JSON or as a JWE.
//
// Everything here returns values; nothing touches the page. The pages own their
// own wording, because what a pane should SAY differs even where the bytes do
// not.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (a node-based test loading this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "vci_wallet",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var metadataClient = require("./metadata_client");

// The proof of possession is a JWT of its own media type (OID4VCI Appendix D,
// the jwt proof type). ES256 because it is what OID4VCI wallets use and what
// both issuers in this repository advertise in
// proof_signing_alg_values_supported.
var PROOF_TYP = "openid4vci-proof+jwt";
var PROOF_ALG = "ES256";

// ---------------------------------------------------------------------------
// The holder key pair.
//
// Generated in the browser, and only the public half ever leaves it: it travels
// in the proof's header, and the issuer copies it into the credential's cnf
// claim so a verifier can later demand proof that the presenter holds the
// private half.
// ---------------------------------------------------------------------------
function generateHolderKeyPair() {
  log.debug("Entering generateHolderKeyPair().");
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
    .then(function (pair) {
      return Promise.all([
        crypto.subtle.exportKey("jwk", pair.publicKey),
        crypto.subtle.exportKey("jwk", pair.privateKey)
      ]);
    })
    .then(function (jwks) {
      log.debug("Leaving generateHolderKeyPair().");
      return {
        // Only the members that identify the key: a stray key_ops/ext/alg makes
        // a strict JWK consumer unhappy, and the issuer echoes this object
        // straight into the credential's cnf claim.
        publicJwk: { kty: jwks[0].kty, crv: jwks[0].crv, x: jwks[0].x, y: jwks[0].y },
        privateJwk: jwks[1]
      };
    });
}

// `count` keys in all, the first of which is the one passed in. One proof per
// key, one credential per proof (OID4VCI section 8.3), so a wallet asking for
// several bindings really does have several keys; the extra ones live for that
// request only, which is the honest lifetime.
function holderKeysFor(first, count) {
  log.debug("Entering holderKeysFor(). count=" + count);
  var extra = [];
  for (var i = 1; i < count; i++) {
    extra.push(generateHolderKeyPair());
  }
  log.debug("Leaving holderKeysFor(). Generating " + extra.length + " additional key(s).");
  return Promise.all(extra).then(function (generated) {
    return [first].concat(generated);
  });
}

// ---------------------------------------------------------------------------
// The key an encrypted Credential Response is encrypted to (OID4VCI section
// 8.2). RSA, because RSA-OAEP-256 is what Web Crypto can unwrap directly and
// what the mock issuer advertises; the private half is generated
// non-extractable so it cannot leave the page even by accident.
// ---------------------------------------------------------------------------
function generateResponseEncryptionKey(enc) {
  log.debug("Entering generateResponseEncryptionKey(). enc=" + enc);
  return crypto.subtle.generateKey({
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256"
  }, false, ["encrypt", "decrypt"])
    .then(function (pair) {
      return crypto.subtle.exportKey("jwk", pair.publicKey).then(function (jwk) {
        log.debug("Leaving generateResponseEncryptionKey().");
        return {
          publicJwk: { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RSA-OAEP-256", use: "enc" },
          privateKey: pair.privateKey,
          enc: enc
        };
      });
    });
}

// ---------------------------------------------------------------------------
// The proof of possession.
//
// One proof per key. Every proof in a request carries the same c_nonce — it is
// the ISSUER's nonce for this request, not a per-key value — and each names its
// own key in the header, which is what the issuer binds that credential to.
// ---------------------------------------------------------------------------
function signProof(key, opts) {
  log.debug("Entering signProof().");
  var header = { typ: PROOF_TYP, alg: PROOF_ALG, jwk: key.publicJwk };
  var payload = {
    iss: opts.clientId || "",
    aud: opts.credentialIssuer,
    iat: Math.floor(Date.now() / 1000)
  };
  if (opts.nonce) payload.nonce = opts.nonce;
  var signingInput = metadataClient.utf8ToB64u(JSON.stringify(header)) + "." +
                     metadataClient.utf8ToB64u(JSON.stringify(payload));
  log.debug("Leaving signProof().");
  return crypto.subtle.importKey("jwk", key.privateJwk,
      { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
    .then(function (imported) {
      return crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, imported,
        new TextEncoder().encode(signingInput));
    })
    .then(function (sig) {
      // Web Crypto returns the raw r||s pair, which is exactly the JWS ES256
      // signature encoding.
      return signingInput + "." + metadataClient.bytesToB64u(sig);
    });
}

function signProofs(keys, opts) {
  log.debug("Entering signProofs(). " + keys.length + " key(s).");
  log.debug("Leaving signProofs().");
  return Promise.all(keys.map(function (key) { return signProof(key, opts); }));
}

// ---------------------------------------------------------------------------
// The c_nonce (OID4VCI section 7).
//
// The Nonce Endpoint is OPTIONAL, so "there is no endpoint" is a normal answer
// and not a failure: the result says which happened, and the caller decides
// what to show. A failure to reach an endpoint that IS published is a real
// error and rejects.
// ---------------------------------------------------------------------------
function fetchNonce(nonceEndpoint) {
  log.debug("Entering fetchNonce().");
  if (!nonceEndpoint) {
    log.debug("Leaving fetchNonce(). This issuer publishes no nonce_endpoint.");
    return Promise.resolve({ nonce: "", published: false });
  }
  return fetch(nonceEndpoint, { method: "POST", headers: { "Content-Length": "0" } })
    .then(function (r) {
      if (!r.ok) throw new Error("the nonce endpoint returned HTTP " + r.status + ".");
      return r.json();
    })
    .then(function (body) {
      log.debug("Leaving fetchNonce(). Got a c_nonce.");
      return { nonce: body.c_nonce || "", published: true };
    });
}

// ---------------------------------------------------------------------------
// The Credential Request body (OID4VCI section 8.2).
//
// Exactly one of credential_identifier / credential_configuration_id names the
// credential, and which one is not the wallet's choice: a token response that
// granted credential_identifiers requires one of them and forbids the
// configuration id.
// ---------------------------------------------------------------------------
function buildRequestBody(opts) {
  log.debug("Entering buildRequestBody().");
  var body = {};
  if (opts.credentialIdentifier) {
    body.credential_identifier = opts.credentialIdentifier;
  } else {
    body.credential_configuration_id = opts.credentialConfigurationId;
  }
  // OID4VCI 1.0: proofs is an object keyed by proof type, each an array — one
  // entry per key the credential should be bound to.
  body.proofs = { jwt: (opts.proofs || []).slice() };
  if (opts.encryption) {
    // The wallet supplies the key and the content encryption algorithm; the
    // private half never leaves this browser.
    body.credential_response_encryption = {
      jwk: opts.encryption.publicJwk,
      enc: opts.encryption.enc
    };
  }
  log.debug("Leaving buildRequestBody().");
  return body;
}

// ---------------------------------------------------------------------------
// An HTTP call written out the way the panes show it: method, full URL,
// headers, a blank line, body. The Authorization header is part of it —
// presenting the access token as a Bearer credential IS how the request is
// authorized — so leaving it out would not be the whole call.
// ---------------------------------------------------------------------------
function describeCall(opts) {
  log.debug("Entering describeCall(). " + opts.method + " " + opts.url);
  var lines = [opts.method + " " + opts.url];
  if (opts.contentType) lines.push("Content-Type: " + opts.contentType);
  if (opts.authorization) lines.push("Authorization: " + opts.authorization);
  var body = opts.body == null ? "" : String(opts.body);
  lines.push("Content-Length: " + body.length);
  lines.push("");
  lines.push(body);
  log.debug("Leaving describeCall(). " + lines.length + " line(s).");
  return lines.join("\n");
}

function encodeForm(params) {
  var out = [];
  Object.keys(params).forEach(function (k) {
    out.push(encodeURIComponent(k) + "=" + encodeURIComponent(params[k]));
  });
  return out.join("&");
}

// ---------------------------------------------------------------------------
// Reading a Credential Response, encrypted or not (OID4VCI section 10).
//
// An encrypted one is a JWE in compact serialization with media type
// application/jwt: the content key is wrapped to the key this wallet supplied
// in the request, so unwrapping it here is the only way to see the credential —
// and the private half never left the browser.
//
// Written out against RFC 7516 rather than through client/src/jose_jwe.js: that
// module covers every algorithm a JWE may use, while what a wallet has to open
// here is the one it asked for, with a non-extractable private key it generated
// itself. Keeping this to that one path is what lets the key stay
// non-extractable.
// ---------------------------------------------------------------------------
function decryptJweResponse(compact, encryption) {
  log.debug("Entering decryptJweResponse().");
  var parts = String(compact).trim().split(".");
  if (parts.length !== 5) {
    log.debug("Leaving decryptJweResponse(). Not five parts.");
    return Promise.reject(new Error("an encrypted response must be a JWE in compact serialization " +
                                    "(five parts); this has " + parts.length + "."));
  }
  if (!encryption) {
    log.debug("Leaving decryptJweResponse(). No key was asked for.");
    return Promise.reject(new Error("the issuer encrypted the response, but this request did not ask for " +
                                    "encryption, so there is no key to open it with."));
  }
  var header = metadataClient.b64uToJson(parts[0]);
  var bits = header.enc === "A128GCM" ? 128 : 256;
  log.debug("Leaving decryptJweResponse(). alg=" + header.alg + ", enc=" + header.enc);
  return crypto.subtle.decrypt({ name: "RSA-OAEP" }, encryption.privateKey,
      metadataClient.b64uToBytes(parts[1]))
    .then(function (cek) {
      return crypto.subtle.importKey("raw", cek, { name: "AES-GCM", length: bits }, false, ["decrypt"]);
    })
    .then(function (key) {
      // RFC 7516: the protected header is the additional authenticated data, and
      // the authentication tag is appended to the ciphertext for Web Crypto.
      var ciphertext = metadataClient.b64uToBytes(parts[3]);
      var tag = metadataClient.b64uToBytes(parts[4]);
      var joined = new Uint8Array(ciphertext.length + tag.length);
      joined.set(ciphertext, 0);
      joined.set(tag, ciphertext.length);
      return crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: metadataClient.b64uToBytes(parts[2]),
        additionalData: new TextEncoder().encode(parts[0]),
        tagLength: tag.length * 8
      }, key, joined);
    })
    .then(function (plaintext) {
      return JSON.parse(new TextDecoder().decode(plaintext));
    });
}

// ---------------------------------------------------------------------------
// Credential REQUEST encryption (OID4VCI section 10), the other direction.
//
// The response side above is the wallet's own key, generated here and sent to
// the issuer. This side is the reverse: the ISSUER publishes keys in
// credential_request_encryption.jwks and the wallet encrypts to one of them.
//
// Two rules from section 10 shape the selection, and both are easy to get
// subtly wrong because the response side has neither:
//
//   * "The `alg` parameter MUST be present. The JWE `alg` algorithm used MUST
//     be equal to the `alg` value of the chosen JWK." So the algorithm is read
//     OFF THE KEY. There is deliberately no alg_values_supported for requests,
//     and a key without an alg is not selectable rather than defaultable.
//   * "If the selected public key contains a `kid` parameter, the JWE MUST
//     include the same value in the `kid` JWE Header Parameter." The metadata
//     requires a kid on every key, so in practice it is always echoed — which
//     is what lets an issuer rotate keys and tell a stale wallet so.
//
// The `enc` comes from enc_values_supported, which IS a list, because it is a
// property of the endpoint rather than of the key.
// ---------------------------------------------------------------------------
var REQUEST_ENC_ALG = "RSA-OAEP-256";

// What this wallet can actually perform, most preferred first. Kept separate
// from what the issuer offers so the intersection is explicit: advertising
// agreement the wallet cannot deliver produces a request the issuer cannot
// read, which is a far worse failure than declining to encrypt.
var REQUEST_ENC_PREFERENCE = ["A256GCM", "A128GCM"];

// Read the issuer's offer and decide what, if anything, the wallet would send.
//
// Always returns an object, never null, because "the issuer does not offer
// this" and "the issuer requires it but we cannot do it" are different answers
// and a pane has to be able to say which. `usable` says whether encryption can
// be performed; `required` says whether the issuer insists; the two together
// are what make a blocked state describable rather than just broken.
function requestEncryptionOffer(vciMetadata) {
  log.debug("Entering requestEncryptionOffer().");
  var offer = (vciMetadata || {}).credential_request_encryption;
  if (!offer) {
    log.debug("Leaving requestEncryptionOffer(). Not offered.");
    return { offered: false, required: false, usable: false,
             reason: "This issuer does not advertise credential_request_encryption, so the " +
                     "Credential Request is sent as plain JSON over TLS." };
  }
  var required = offer.encryption_required === true;
  var keys = ((offer.jwks || {}).keys) || [];
  if (!keys.length) {
    return { offered: true, required: required, usable: false,
             reason: "credential_request_encryption.jwks contains no keys, so there is nothing to " +
                     "encrypt to." + (required ? " The issuer nevertheless requires encryption, so " +
                     "this Credential Endpoint cannot be used." : "") };
  }
  // Section 10 leaves the choice open when several keys are offered ("any may be
  // selected based on the information about each key"). This wallet takes the
  // first key it can actually use, and says which — a silent pick among several
  // keys is the sort of thing that makes a failure unexplainable later.
  var chosen = null;
  var skipped = [];
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (k.use && k.use !== "enc") { skipped.push((k.kid || "#" + i) + " (use=" + k.use + ")"); continue; }
    if (!k.alg) { skipped.push((k.kid || "#" + i) + " (no alg, which section 10 requires)"); continue; }
    if (k.alg !== REQUEST_ENC_ALG) { skipped.push((k.kid || "#" + i) + " (alg " + k.alg + ")"); continue; }
    if (k.kty !== "RSA" || !k.n || !k.e) { skipped.push((k.kid || "#" + i) + " (not an RSA public key)"); continue; }
    chosen = k;
    break;
  }
  if (!chosen) {
    return { offered: true, required: required, usable: false, skipped: skipped,
             reason: "None of the " + keys.length + " key(s) offered can be used: this wallet encrypts " +
                     "with " + REQUEST_ENC_ALG + ". Skipped " + skipped.join(", ") + "." };
  }
  var encs = offer.enc_values_supported || [];
  var enc = "";
  for (var j = 0; j < REQUEST_ENC_PREFERENCE.length; j++) {
    if (encs.indexOf(REQUEST_ENC_PREFERENCE[j]) !== -1) { enc = REQUEST_ENC_PREFERENCE[j]; break; }
  }
  if (!enc) {
    return { offered: true, required: required, usable: false, skipped: skipped,
             reason: "This issuer's enc_values_supported (" + (encs.join(", ") || "empty") + ") has " +
                     "nothing in common with what this wallet performs (" +
                     REQUEST_ENC_PREFERENCE.join(", ") + ")." };
  }
  // zip is advertised by the issuer, never chosen unilaterally: "If absent then
  // no compression algorithms are supported". This wallet does not compress, so
  // the header carries no zip and the issuer decrypts without inflating.
  log.debug("Leaving requestEncryptionOffer(). kid=" + chosen.kid + ", enc=" + enc);
  return {
    offered: true, required: required, usable: true, skipped: skipped,
    jwk: chosen, kid: chosen.kid || "", alg: REQUEST_ENC_ALG, enc: enc,
    zipSupported: (offer.zip_values_supported || []).slice(),
    reason: "Encrypting to " + (chosen.kid ? "key " + chosen.kid : "the issuer's key") +
            " with " + REQUEST_ENC_ALG + " / " + enc + "."
  };
}

// The Credential Request as a JWE in compact serialization.
//
// Section 10: "The contents of the message MUST be encoded as a JWT" — a JWE is
// a JWT, so the plaintext is the request JSON and the whole thing is the JWT.
// The media type is set by the caller to application/jwt, which is what tells
// the issuer to decrypt rather than parse.
function encryptRequestBody(body, offer) {
  log.debug("Entering encryptRequestBody(). enc=" + (offer || {}).enc);
  if (!offer || !offer.usable) {
    return Promise.reject(new Error("there is no usable issuer key to encrypt this request to."));
  }
  var bits = offer.enc === "A128GCM" ? 128 : 256;
  var header = { alg: offer.alg, enc: offer.enc, typ: "JWT" };
  // Only when the key has one — section 10 conditions the header on the key
  // carrying a kid, and inventing one would name a key the issuer never
  // published.
  if (offer.kid) header.kid = offer.kid;
  var headerB64 = metadataClient.utf8ToB64u(JSON.stringify(header));
  var plaintext = new TextEncoder().encode(JSON.stringify(body));
  var cek = crypto.getRandomValues(new Uint8Array(bits / 8));
  var iv = crypto.getRandomValues(new Uint8Array(12));

  return crypto.subtle.importKey("jwk",
      { kty: offer.jwk.kty, n: offer.jwk.n, e: offer.jwk.e, alg: "RSA-OAEP-256", ext: true },
      { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"])
    .then(function (publicKey) {
      return crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, cek);
    })
    .then(function (encryptedKey) {
      return crypto.subtle.importKey("raw", cek, { name: "AES-GCM", length: bits }, false, ["encrypt"])
        .then(function (contentKey) {
          // RFC 7516: the AAD is ASCII(BASE64URL(protected header)), so altering
          // the header — the kid, say — breaks the tag rather than going unnoticed.
          return crypto.subtle.encrypt({
            name: "AES-GCM", iv: iv,
            additionalData: new TextEncoder().encode(headerB64),
            tagLength: 128
          }, contentKey, plaintext);
        })
        .then(function (sealed) {
          // Web Crypto appends the 16-byte tag to the ciphertext; the compact
          // serialization keeps them as separate segments.
          var all = new Uint8Array(sealed);
          var ciphertext = all.slice(0, all.length - 16);
          var tag = all.slice(all.length - 16);
          var compact = [
            headerB64,
            metadataClient.bytesToB64u(encryptedKey),
            metadataClient.bytesToB64u(iv),
            metadataClient.bytesToB64u(ciphertext),
            metadataClient.bytesToB64u(tag)
          ].join(".");
          log.debug("Leaving encryptRequestBody(). " + compact.length + " characters.");
          return compact;
        });
    });
}

function readCredentialResponse(r, text, encryption) {
  log.debug("Entering readCredentialResponse(). status=" + r.status);
  var contentType = (r.headers.get("content-type") || "").toLowerCase();
  var encrypted = contentType.indexOf("application/jwt") === 0 ||
                  (!!encryption && r.ok && text.split(".").length === 5);
  if (!encrypted) {
    var parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      // Not JSON: the caller shows the raw text instead.
    }
    log.debug("Leaving readCredentialResponse(). Plain JSON.");
    return Promise.resolve({ ok: r.ok, statusCode: r.status, body: parsed, raw: text, encrypted: false });
  }
  return decryptJweResponse(text, encryption)
    .then(function (body) {
      log.debug("Leaving readCredentialResponse(). Decrypted.");
      return { ok: r.ok, statusCode: r.status, body: body, raw: text, encrypted: true };
    })
    .catch(function (e) {
      log.error("could not decrypt the Credential Response: " + e.message);
      return {
        ok: false, statusCode: r.status, raw: text, encrypted: true,
        body: { error: "decryption_failed", error_description: e.message }
      };
    });
}

// One credential out of a Credential Response, as a STRING.
//
// OID4VCI 1.0 section 8.3 makes the `credential` parameter "a string or a JSON
// object, depending on the Credential Format": the JWS-secured formats
// (dc+sd-jwt, jwt_vc_json) are compact-serialized strings, while ldp_vc is a
// JSON object — a W3C credential with an EMBEDDED Data Integrity proof, which
// is the only shape a BBS signature can take, there being no BBS `alg` in JOSE.
//
// An object is serialized here rather than passed through, because everything
// downstream of this holds a credential as a string: localStorage stores
// strings (an object reaches it as the literal "[object Object]"), the raw
// credential goes into a textarea's .value, and credentialFormat() in
// sd_jwt_vc.js recognizes an ldp_vc precisely by its being JSON text with a
// leading brace. Returning the live object instead moves the failure one page
// along, to a step 3 that cannot parse what it was handed.
function credentialString(value) {
  log.debug("Entering credentialString().");
  if (typeof value === "string") return value;
  // Any non-null object is taken as an ldp_vc-style credential. The format is
  // not checked here: this function's job is the representation, and refusing
  // an unrecognized document would report it as "no credential" — the very
  // failure this distinction exists to stop being silent.
  if (value && typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch (e) {
      // Circular, which a parsed JSON response cannot be — but a caller could
      // hand us anything, and "" here reads as "no credential".
      log.error("a credential could not be serialized: " + e.message);
      return "";
    }
  }
  log.debug("Leaving credentialString().");
  return "";
}

// OID4VCI 1.0 returns credentials: [{credential: …}]. Earlier drafts returned a
// bare `credential`, and some implementations put the credential itself in the
// array — accept all three, in either representation.
function extractCredential(body) {
  log.debug("Entering extractCredential().");
  if (!body) return "";
  var direct = credentialString(body.credential);
  if (direct) return direct;
  var list = body.credentials;
  if (Object.prototype.toString.call(list) === "[object Array]" && list.length) {
    // The wrapper is tested BEFORE the bare form: {credential: {...}} is itself
    // an object, so serializing it as a credential would store the envelope
    // around the credential instead of the credential.
    return entryCredential(list[0]);
  }
  log.debug("Leaving extractCredential().");
  return "";
}

// One entry of a `credentials` array, as a string. An entry is either the
// credential itself or a wrapper carrying it under `credential`.
function entryCredential(entry) {
  if (typeof entry === "string") return entry;
  if (entry && typeof entry === "object" && "credential" in entry) {
    return credentialString(entry.credential);
  }
  return credentialString(entry);
}

// Every credential in a Credential Response, in order, each as a string.
function allCredentials(body) {
  var list = body && body.credentials;
  if (Object.prototype.toString.call(list) !== "[object Array]") {
    var one = extractCredential(body);
    return one ? [one] : [];
  }
  return list.map(entryCredential).filter(Boolean);
}

module.exports = {
  PROOF_TYP: PROOF_TYP,
  PROOF_ALG: PROOF_ALG,
  generateHolderKeyPair: generateHolderKeyPair,
  holderKeysFor: holderKeysFor,
  generateResponseEncryptionKey: generateResponseEncryptionKey,
  signProof: signProof,
  signProofs: signProofs,
  fetchNonce: fetchNonce,
  buildRequestBody: buildRequestBody,
  describeCall: describeCall,
  encodeForm: encodeForm,
  decryptJweResponse: decryptJweResponse,
  requestEncryptionOffer: requestEncryptionOffer,
  encryptRequestBody: encryptRequestBody,
  REQUEST_ENC_ALG: REQUEST_ENC_ALG,
  REQUEST_ENC_PREFERENCE: REQUEST_ENC_PREFERENCE,
  readCredentialResponse: readCredentialResponse,
  extractCredential: extractCredential,
  allCredentials: allCredentials
};
