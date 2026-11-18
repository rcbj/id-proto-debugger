// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
var jws = require("./jws");
// Pure-JS key generation in whichever algorithm the issuer accepts (#475),
// and the JWS a key signs with.
var cryptoProvider = require("./crypto_provider");
var vcFormats = require("./vc_formats");
var dpopLib = require("./dpop");

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
// `alg` is the JOSE algorithm the key is for (vc_formats.holderKeyAlgFor()
// chooses it from what the issuer accepts); ES256 when none is given. The
// key is made by crypto_provider.js, pure JS, so a page served over plain
// HTTP generates an Ed25519, secp256k1 or P-384 key as readily as P-256 —
// Web Crypto does none of that outside a secure context and secp256k1
// nowhere. The private JWK carries `alg`, so every later signature names
// the algorithm the key was made for (EdDSA and Ed25519 are the same key).
function generateHolderKeyPair(alg) {
  log.debug("Entering generateHolderKeyPair(). alg=" + (alg || "ES256"));
  var chosen = alg || PROOF_ALG;
  var spec = vcFormats.HOLDER_KEY_SPECS[chosen];
  if (!spec) {
    log.debug("Leaving generateHolderKeyPair(). Unknown alg.");
    return Promise.reject(new Error("no holder key is made for " +
      JSON.stringify(chosen) + "; this wallet makes " +
      Object.keys(vcFormats.HOLDER_KEY_SPECS).join(", ") + "."));
  }
  var pair = cryptoProvider.generateKeyPair(spec);
  var priv = cryptoProvider.exportKey(pair, "jwk");
  var full = cryptoProvider.exportKey(pair, "jwk", { publicOnly: true });
  // Only the members that identify the key: a stray key_ops/ext/alg makes a
  // strict JWK consumer unhappy, and the issuer echoes this object straight
  // into the credential's cnf claim.
  var members = { EC: ["kty", "crv", "x", "y"], OKP: ["kty", "crv", "x"],
                  RSA: ["kty", "n", "e"] }[full.kty] || Object.keys(full);
  var pub = {};
  members.forEach(function (m) {
    if (full[m] !== undefined) pub[m] = full[m];
  });
  priv.alg = chosen;
  log.debug("Leaving generateHolderKeyPair(). " + full.kty + " " +
            (full.crv || ""));
  return Promise.resolve({ publicJwk: pub, privateJwk: priv });
}

// `count` keys in all, the first of which is the one passed in. One proof per
// key, one credential per proof (OID4VCI section 8.3), so a wallet asking for
// several bindings really does have several keys; the extra ones live for that
// request only, which is the honest lifetime.
function holderKeysFor(first, count) {
  log.debug("Entering holderKeysFor(). count=" + count);
  var extra = [];
  // The extra keys are the same kind as the first, which is the one the
  // wallet chose for this issuer.
  var alg = first && first.privateJwk && first.privateJwk.alg;
  for (var i = 1; i < count; i++) {
    extra.push(generateHolderKeyPair(alg));
  }
  log.debug("Leaving holderKeysFor(). Generating " + extra.length +
            " additional key(s).");
  return Promise.all(extra).then(function (generated) {
    return [first].concat(generated);
  });
}

// ---------------------------------------------------------------------------
// The key an encrypted Credential Response is encrypted to (OID4VCI section
// 8.2). RSA, because RSA-OAEP-256 is what the issuers advertise. Generated
// by crypto_provider.js (#463), in pure JS, so it works on a plain-HTTP page.
// A pure-JS key cannot be non-extractable as the Web Crypto one was; it is
// made per request, held in memory only and never stored.
// ---------------------------------------------------------------------------
function generateResponseEncryptionKey(enc) {
  log.debug("Entering generateResponseEncryptionKey(). enc=" + enc);
  log.debug("Leaving generateResponseEncryptionKey().");
  return new Promise(function (resolve) {
    setTimeout(resolve, 0);
  }).then(function () {
    var pair = cryptoProvider.generateKeyPair("rsa", { bits: 2048 });
    var jwk = cryptoProvider.exportKey(cryptoProvider.publicKeyOf(pair), "jwk");
    return {
      publicJwk: { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RSA-OAEP-256",
                   use: "enc" },
      privateKey: pair,
      enc: enc
    };
  });
}

// ---------------------------------------------------------------------------
// The proof of possession.
//
// One proof per key. Every proof in a request carries the same c_nonce — it is
// the ISSUER's nonce for this request, not a per-key value — and each names its
// own key in the header, which is what the issuer binds that credential to.
// ---------------------------------------------------------------------------
// The algorithm comes from the KEY rather than being fixed at ES256, because
// under Holder of Key the key being proved is the DPoP key and a wallet may
// have chosen RS256 for that. Signing an RSA key's proof with the ECDSA
// parameters fails in Web Crypto with an unhelpful DataError, so the two are
// matched here once instead of at each call site.
// The Web Crypto parameters that used to be here are jws.js's now — the same
// mapping was written out in dpop.js and twice in sd_jwt_vp.js. What this
// module still decides is WHICH algorithm, which is a wallet question rather
// than a JOSE one: under Holder of Key the key being proved is the DPoP key,
// and a wallet may have chosen RS256 for that.
var PROOF_ALGS = { ES256: true, RS256: true };

// The JWS the proof is signed with: { algId, headerAlg } (vc_formats.jwsFor).
// A DPoP key under Holder of Key names its own alg; a holder key made here
// otherwise the curve decides, with the issuer's list choosing between
// EdDSA and Ed25519, or among RSA algorithms.
function proofAlgFor(key, issuerAlgs) {
  log.debug("Entering proofAlgFor().");
  if (key && PROOF_ALGS[key.alg]) {
    log.debug("Leaving proofAlgFor(). The key's own.");
    return { algId: key.alg, headerAlg: key.alg };
  }
  // An Ed25519 key made for "Ed25519" keeps that name when the issuer
  // states no list; otherwise the issuer's list chooses.
  var named = key && key.privateJwk && key.privateJwk.alg;
  var offered = [].concat(issuerAlgs || []);
  if (!offered.length && named) {
    offered = [named];
  }
  var j = vcFormats.jwsFor(key && key.publicJwk, offered);
  if (!j) {
    log.debug("Leaving proofAlgFor(). Default.");
    return { algId: PROOF_ALG, headerAlg: PROOF_ALG };
  }
  log.debug("Leaving proofAlgFor(). " + j.headerAlg);
  return j;
}

function signProof(key, opts) {
  log.debug("Entering signProof().");
  var chosen = proofAlgFor(key, opts.proofAlgs);
  var alg = chosen.headerAlg;
  var header = { typ: PROOF_TYP, alg: alg, jwk: key.publicJwk };
  var payload = {
    iss: opts.clientId || "",
    aud: opts.credentialIssuer,
    iat: Math.floor(Date.now() / 1000)
  };
  if (opts.nonce) payload.nonce = opts.nonce;
  log.debug("Leaving signProof(). alg=" + alg);
  // VERBATIM header: OID4VCI section 8.2.1.1 fixes what a jwt proof carries,
  // and the proof is the base64url of these exact bytes.
  // The pure-JS backend, which signs every algorithm a holder key can be
  // made for; Web Crypto has no secp256k1 and, outside a secure context,
  // nothing at all.
  return jws.signJwsAsync({
    algId: chosen.algId,
    protectedHeader: header,
    payload: payload,
    privateKey: { jwk: key.privateJwk },
    backend: "js"
  }).then(function (signed) { return signed.serialized; });
}

function signProofs(keys, opts) {
  log.debug("Entering signProofs(). " + keys.length + " key(s).");
  log.debug("Leaving signProofs().");
  return Promise.all(keys.map(function (key) { return signProof(key, opts); }));
}

// ---------------------------------------------------------------------------
// Sending a request to a protected endpoint — Bearer or DPoP.
//
// One implementation for every call the wallet makes, because DPoP's whole
// value is in being on EVERY call: an endpoint whose call site forgot the proof
// is the one an attacker uses, and this workflow has six such call sites across
// two pages (token, credential, deferred, notification, and the refresh page's
// copies of the last two). A `"Bearer " + token` written by hand at each of
// them is how one of six ends up wrong.
//
// `context` is what sd_jwt_vc.js's dpopContext() returns, or null for a plain
// Bearer call. Null is the normal case and is not an error: with DPoP off there
// is nothing to attach, and the request goes out exactly as it did before any
// of this existed.
// ---------------------------------------------------------------------------

// The headers for one attempt. Returns what was built as well as the headers,
// so a pane can SHOW the proof it sent — which is the point of a debugger, and
// the reason this returns an object rather than just setting headers.
function dpopHeadersFor(opts) {
  log.debug("Entering dpopHeadersFor(). method=" + opts.method +
            ", withToken=" +
            (opts.accessToken ? "yes" : "no"));
  var context = opts.context;
  var accessToken = opts.accessToken || "";
  if (!context || !context.key) {
    log.debug("Leaving dpopHeadersFor(). No DPoP context; this is a " +
              "Bearer call.");
    return Promise.resolve({
      headers: accessToken ? { Authorization: "Bearer " + accessToken } : {},
      authorization: accessToken ? "Bearer " + accessToken : "",
      proof: "", decoded: null, scheme: "Bearer"
    });
  }
  log.debug("Leaving dpopHeadersFor().");
  return dpopLib.proof({
    key: context.key,
    htm: opts.method || "POST",
    htu: opts.url,
    // Only when there is one. A Token Request has no access token yet, and
    // sending an `ath` there would be a claim about a token that does not
    // exist.
    accessToken: accessToken || null,
    nonce: opts.nonce !== undefined ? opts.nonce : (context.nonce || "")
  }).then(function (made) {
    var headers = { DPoP: made.proof };
    // RFC 9449 section 7.1: a bound token is presented with the DPoP scheme.
    // Sending it as Bearer would be refused by a correct resource server, and
    // ACCEPTED by an incorrect one — which is the outcome to avoid, because it
    // looks like everything works.
    if (accessToken) headers.Authorization =
        dpopLib.authorizationHeader(accessToken);
    log.debug("Leaving dpopHeadersFor(). A DPoP proof was attached.");
    return {
      headers: headers,
      authorization: accessToken ?
          dpopLib.authorizationHeader(accessToken) : "",
      proof: made.proof, decoded: { header: made.header,
          payload: made.payload },
      scheme: "DPoP"
    };
  });
}

// One request, with ONE automatic retry when the server asks for a nonce.
//
// Exactly one, for two reasons. RFC 9449 sections 8 and 9 describe a single
// retry — the server supplies the nonce it wants, so a second refusal means
// something else is wrong — and an unbounded loop against a server that always
// answers `use_dpop_nonce` would hammer it forever. The nonce is remembered
// through context.remember() so the NEXT call carries it without being asked
// again; a wallet that forgets it pays the extra round trip on every single
// request, which is the difference between nonce mode being a nuisance and
// being invisible.
function fetchProtected(opts) {
  log.debug("Entering fetchProtected(). url=" + opts.url);
  var method = opts.method || "POST";
  var attempt = function (nonce, isRetry) {
    log.debug("Entering attempt().");
    log.debug("Leaving attempt().");
    return dpopHeadersFor({
      context: opts.context, accessToken: opts.accessToken, method: method,
      url: opts.url, nonce: nonce
    }).then(function (built) {
      var headers = Object.assign({}, opts.headers || {}, built.headers);
      // opts.signal lets a caller bound the wait (vc_client_auth_pane.js
      // does, for the token request).
      return fetch(opts.url, { method: method, headers: headers,
                   body: opts.body, signal: opts.signal })
        .then(function (response) {
          return response.text().then(function (text) {
            var body = null;
            try {
              body = JSON.parse(text);
            } catch (e) {
              // Not JSON. A Credential Response may be a JWE, and an error page
              // may be HTML; either way the caller reads `text`.
              body = null;
            }
            return { response: response, text: text, body: body, sent: built,
                     retriedForNonce: !!isRetry };
          });
        });
    });
  };

  log.debug("Leaving fetchProtected().");
  return attempt(undefined, false).then(function (first) {
    if (!opts.context) return first;
    var headersObject = {};
    // fetch()'s Headers is iterable but not indexable, and nonceRequested()
    // takes a plain object so it can be unit-tested without one.
    if (first.response && first.response.headers &&
        typeof first.response.headers.forEach === "function") {
      first.response.headers.forEach(function (value, name) {
        headersObject[String(name).toLowerCase()] = value;
      });
    }
    var asked = dpopLib.nonceRequested(first.response.status, first.body,
        headersObject);
    if (!asked.wanted || !asked.nonce) return first;
    log.debug("the server asked for a DPoP nonce; retrying once with it.");
    if (opts.context.remember) opts.context.remember(asked.nonce);
    return attempt(asked.nonce, true).then(function (second) {
      // Both attempts are reported, because "it worked on the second try" is
      // exactly the kind of thing this workflow exists to show.
      second.firstAttempt = first;
      second.nonceUsed = asked.nonce;
      return second;
    });
  });
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
  log.debug("Leaving fetchNonce().");
  return fetch(nonceEndpoint, { method: "POST",
               headers: { "Content-Length": "0" } })
    .then(function (r) {
      if (!r.ok) throw new Error("the nonce endpoint returned HTTP " +
          r.status + ".");
      return r.json();
    })
    .then(function (body) {
      log.debug("Leaving fetchNonce(). Got a c_nonce.");
      return { nonce: body.c_nonce || "", published: true };
    });
}

// Whether a Credential Error Response means "the c_nonce is no good — fetch
// another and build the proofs again". OpenID4VCI 1.0 section 8.3.1.2 gives
// that its own code, invalid_nonce; the drafts before the final text folded it
// into invalid_proof, which is also what an issuer still on them answers. A
// caller retries ONCE on either, so a proof that is bad for any other reason
// costs one extra request and not a loop.
function isStaleNonceError(error) {
  log.debug("Entering isStaleNonceError().");
  var stale = error === "invalid_nonce" || error === "invalid_proof";
  log.debug("Leaving isStaleNonceError().");
  return stale;
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
  // The DPoP proof is a header of the request like any other, and leaving it
  // out of the assembled call would describe a request this wallet does not
  // make. A pane that shows `Authorization: DPoP <token>` with no `DPoP:` line
  // beside it is showing a request every conforming server refuses.
  if (opts.dpop) lines.push("DPoP: " + opts.dpop);
  var body = opts.body == null ? "" : String(opts.body);
  lines.push("Content-Length: " + body.length);
  lines.push("");
  lines.push(body);
  log.debug("Leaving describeCall(). " + lines.length + " line(s).");
  return lines.join("\n");
}

function encodeForm(params) {
  log.debug("Entering encodeForm().");
  var out = [];
  Object.keys(params).forEach(function (k) {
    out.push(encodeURIComponent(k) + "=" + encodeURIComponent(params[k]));
  });
  log.debug("Leaving encodeForm().");
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
    return Promise.reject(new Error("an encrypted response must be a JWE in " +
                          "compact serialization " +
                                    "(five parts); this has " + parts.length +
                                        "."));
  }
  if (!encryption) {
    log.debug("Leaving decryptJweResponse(). No key was asked for.");
    return Promise.reject(new Error("the issuer encrypted the response, but " +
                          "this request did not ask for " +
                                    "encryption, so there is no key to " +
                                        "open it with."));
  }
  var header = metadataClient.b64uToJson(parts[0]);
  var bits = header.enc === "A128GCM" ? 128 : 256;
  log.debug("Leaving decryptJweResponse(). alg=" + header.alg + ", enc=" +
            header.enc);
  // RSA-OAEP-256 unwraps the CEK and AES-GCM opens the content, both by
  // crypto_provider.js (#463). RFC 7516: the protected header, as sent, is
  // the additional authenticated data.
  return Promise.resolve().then(function () {
    var cek = cryptoProvider.rsaDecrypt("rsa-oaep-sha256",
        encryption.privateKey, metadataClient.b64uToBytes(parts[1]));
    if (cek.length * 8 !== bits) {
      throw new Error("the unwrapped content key is " + (cek.length * 8) +
                      " bits and " + header.enc + " takes " + bits + ".");
    }
    return cryptoProvider.aesGcmDecrypt(cek,
        metadataClient.b64uToBytes(parts[2]),
        metadataClient.b64uToBytes(parts[3]),
        metadataClient.b64uToBytes(parts[4]),
        new TextEncoder().encode(parts[0]));
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
             reason: "This issuer does not advertise " +
                 "credential_request_encryption, so the " +
                     "Credential Request is sent as plain JSON over TLS." };
  }
  var required = offer.encryption_required === true;
  var keys = ((offer.jwks || {}).keys) || [];
  if (!keys.length) {
    log.debug("Leaving requestEncryptionOffer().");
    return { offered: true, required: required, usable: false,
             reason: "credential_request_encryption.jwks contains no keys, " +
                 "so there is nothing to " +
                     "encrypt to." + (required ?
                         " The issuer nevertheless requires encryption, so " +
                     "this Credential Endpoint cannot be used." : "") };
  }
  // Section 10 leaves the choice open when several keys are offered ("any may
  // be selected based on the information about each key"). This wallet takes
  // the first key it can actually use, and says which — a silent pick among
  // several keys is the sort of thing that makes a failure unexplainable later.
  var chosen = null;
  var skipped = [];
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (k.use && k.use !== "enc") { skipped.push((k.kid || "#" + i) + " (use=" +
        k.use + ")"); continue; }
    if (!k.alg) { skipped.push((k.kid || "#" + i) +
        " (no alg, which section 10 requires)"); continue; }
    if (k.alg !== REQUEST_ENC_ALG) { skipped.push((k.kid || "#" + i) +
        " (alg " + k.alg + ")"); continue; }
    if (k.kty !== "RSA" || !k.n || !k.e) { skipped.push((k.kid || "#" + i) +
        " (not an RSA public key)"); continue; }
    chosen = k;
    break;
  }
  if (!chosen) {
    log.debug("Leaving requestEncryptionOffer().");
    return { offered: true, required: required, usable: false, skipped: skipped,
             reason: "None of the " + keys.length +
                 " key(s) offered can be used: this wallet encrypts " +
                     "with " + REQUEST_ENC_ALG + ". Skipped " +
                         skipped.join(", ") + "." };
  }
  var encs = offer.enc_values_supported || [];
  var enc = "";
  for (var j = 0; j < REQUEST_ENC_PREFERENCE.length; j++) {
    if (encs.indexOf(REQUEST_ENC_PREFERENCE[j]) !== -1) { enc =
        REQUEST_ENC_PREFERENCE[j]; break; }
  }
  if (!enc) {
    log.debug("Leaving requestEncryptionOffer().");
    return { offered: true, required: required, usable: false, skipped: skipped,
             reason: "This issuer's enc_values_supported (" +
                 (encs.join(", ") || "empty") + ") has " +
                     "nothing in common with what this wallet performs (" +
                     REQUEST_ENC_PREFERENCE.join(", ") + ")." };
  }
  // zip is advertised by the issuer, never chosen unilaterally: "If absent then
  // no compression algorithms are supported". This wallet does not compress, so
  // the header carries no zip and the issuer decrypts without inflating.
  log.debug("Leaving requestEncryptionOffer(). kid=" + chosen.kid + ", enc=" +
            enc);
  return {
    offered: true, required: required, usable: true, skipped: skipped,
    jwk: chosen, kid: chosen.kid || "", alg: REQUEST_ENC_ALG, enc: enc,
    zipSupported: (offer.zip_values_supported || []).slice(),
    reason: "Encrypting to " + (chosen.kid ? "key " +
        chosen.kid : "the issuer's key") +
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
    log.debug("Leaving encryptRequestBody().");
    return Promise.reject(new Error("there is no usable issuer key to " +
                          "encrypt this request to."));
  }
  var bits = offer.enc === "A128GCM" ? 128 : 256;
  var header = { alg: offer.alg, enc: offer.enc, typ: "JWT" };
  // Only when the key has one — section 10 conditions the header on the key
  // carrying a kid, and inventing one would name a key the issuer never
  // published.
  if (offer.kid) header.kid = offer.kid;
  var headerB64 = metadataClient.utf8ToB64u(JSON.stringify(header));
  var plaintext = new TextEncoder().encode(JSON.stringify(body));
  var cek = cryptoProvider.randomBytes(bits / 8);
  var iv = cryptoProvider.randomBytes(12);

  log.debug("Leaving encryptRequestBody().");
  // RSA-OAEP-256 wraps the CEK and AES-GCM seals the request, both by
  // crypto_provider.js (#463).
  return Promise.resolve().then(function () {
    return cryptoProvider.rsaEncrypt("rsa-oaep-sha256",
      cryptoProvider.importKey({ kty: offer.jwk.kty, n: offer.jwk.n,
                                 e: offer.jwk.e }), cek);
  })
    .then(function (encryptedKey) {
      return Promise.resolve()
        .then(function () {
          // RFC 7516: the AAD is ASCII(BASE64URL(protected header)), so
          // altering the header — the kid, say — breaks the tag rather than
          // going unnoticed.
          return cryptoProvider.aesGcmEncrypt(cek, iv, plaintext,
                                        new TextEncoder().encode(headerB64));
        })
        .then(function (sealed) {
          var ciphertext = sealed.ciphertext;
          var tag = sealed.tag;
          var compact = [
            headerB64,
            metadataClient.bytesToB64u(encryptedKey),
            metadataClient.bytesToB64u(iv),
            metadataClient.bytesToB64u(ciphertext),
            metadataClient.bytesToB64u(tag)
          ].join(".");
          log.debug("Leaving encryptRequestBody(). " + compact.length +
                    " characters.");
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
    return Promise.resolve({ ok: r.ok, statusCode: r.status, body: parsed,
                           raw: text, encrypted: false });
  }
  log.debug("Leaving readCredentialResponse().");
  return decryptJweResponse(text, encryption)
    .then(function (body) {
      log.debug("Leaving readCredentialResponse(). Decrypted.");
      return { ok: r.ok, statusCode: r.status, body: body, raw: text,
              encrypted: true };
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
  if (typeof value === "string") {
    log.debug("Leaving credentialString().");
    return value;
  }
  // Any non-null object is taken as an ldp_vc-style credential. The format is
  // not checked here: this function's job is the representation, and refusing
  // an unrecognized document would report it as "no credential" — the very
  // failure this distinction exists to stop being silent.
  if (value && typeof value === "object") {
    try {
      log.debug("Leaving credentialString().");
      return JSON.stringify(value);
    } catch (e) {
      // Circular, which a parsed JSON response cannot be — but a caller could
      // hand us anything, and "" here reads as "no credential".
      log.error("a credential could not be serialized: " + e.message);
      log.debug("Leaving credentialString().");
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
  if (!body) {
    log.debug("Leaving extractCredential().");
    return "";
  }
  var direct = credentialString(body.credential);
  if (direct) {
    log.debug("Leaving extractCredential().");
    return direct;
  }
  var list = body.credentials;
  if (Object.prototype.toString.call(list) === "[object Array]" &&
      list.length) {
    // The wrapper is tested BEFORE the bare form: {credential: {...}} is itself
    // an object, so serializing it as a credential would store the envelope
    // around the credential instead of the credential.
    log.debug("Leaving extractCredential().");
    return entryCredential(list[0]);
  }
  log.debug("Leaving extractCredential().");
  return "";
}

// One entry of a `credentials` array, as a string. An entry is either the
// credential itself or a wrapper carrying it under `credential`.
function entryCredential(entry) {
  log.debug("Entering entryCredential().");
  if (typeof entry === "string") {
    log.debug("Leaving entryCredential().");
    return entry;
  }
  if (entry && typeof entry === "object" && "credential" in entry) {
    log.debug("Leaving entryCredential().");
    return credentialString(entry.credential);
  }
  log.debug("Leaving entryCredential().");
  return credentialString(entry);
}

// Every credential in a Credential Response, in order, each as a string.
function allCredentials(body) {
  log.debug("Entering allCredentials().");
  var list = body && body.credentials;
  if (Object.prototype.toString.call(list) !== "[object Array]") {
    var one = extractCredential(body);
    log.debug("Leaving allCredentials().");
    return one ? [one] : [];
  }
  log.debug("Leaving allCredentials().");
  return list.map(entryCredential).filter(Boolean);
}

module.exports = {
  proofAlgFor: proofAlgFor,
  dpopHeadersFor: dpopHeadersFor,
  fetchProtected: fetchProtected,
  PROOF_TYP: PROOF_TYP,
  PROOF_ALG: PROOF_ALG,
  generateHolderKeyPair: generateHolderKeyPair,
  holderKeysFor: holderKeysFor,
  generateResponseEncryptionKey: generateResponseEncryptionKey,
  signProof: signProof,
  signProofs: signProofs,
  fetchNonce: fetchNonce,
  isStaleNonceError: isStaleNonceError,
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
