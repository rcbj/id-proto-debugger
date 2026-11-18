// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// File: crypto_webcrypto.js
//
// ---------------------------------------------------------------------------
// THE OPTIONAL WEB CRYPTO BACKEND (issue #463, step 5).
//
// crypto_provider.js is pure JS and synchronous, and it never touches Web
// Crypto: that is what makes every operation work on every deployment, plain
// HTTP included (rcbj's rule). This file is the one place a caller may OPT IN
// to the browser's own implementation, and it is built so that opting in can
// never take an operation away:
//
//   * It is ASYNCHRONOUS, because crypto.subtle is. The synchronous provider
//     API is unchanged and always pure JS.
//   * It is OFF BY DEFAULT. It uses Web Crypto only when the provider's
//     backend is "webcrypto" (provider.setBackend("webcrypto")) or a call asks
//     for it ({ backend: "webcrypto" }).
//   * It FALLS BACK. Without crypto.subtle (an insecure origin), for an
//     algorithm Web Crypto has no name for (secp256k1, Ed448, every
//     post-quantum one), and on any error Web Crypto raises, the call is
//     answered by the provider's pure-JS function instead, and the result
//     says which engine produced it.
//
// Output is the provider's in every case: raw r || s for ECDSA unless
// opts.encoding is "der", the same PSS parameters (MGF1 over the message
// hash, a hash-length salt), the same digests. For a deterministic algorithm
// (RSA PKCS#1 v1.5, Ed25519, every digest) the bytes are identical to the
// pure-JS backend's; ECDSA is randomized on Web Crypto and deterministic
// (RFC 6979) in JS, so there each verifies the other's.
// tests/crypto_provider_engine.js holds all of that.
//
// NO DOM.
// ---------------------------------------------------------------------------
var provider = require("./crypto_provider");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "crypto_webcrypto",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// Web Crypto's names for the provider's signature algorithms. ECDSA's hash
// is the provider's per-curve default unless opts.hash overrides it, as X.509
// allows; the curve is the key's.
var EC_CURVE = { "ecdsa-p256-sha256": "P-256", "ecdsa-p384-sha384": "P-384",
                 "ecdsa-p521-sha512": "P-521" };
var EC_HASH = { "ecdsa-p256-sha256": "SHA-256", "ecdsa-p384-sha384": "SHA-384",
                "ecdsa-p521-sha512": "SHA-512" };
var RSA_HASH = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384",
                 sha512: "SHA-512" };
var DIGESTS = { sha1: "SHA-1", "sha-1": "SHA-1", sha256: "SHA-256",
                "sha-256": "SHA-256", sha384: "SHA-384", "sha-384": "SHA-384",
                sha512: "SHA-512", "sha-512": "SHA-512" };
var SALT = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };

// The Web Crypto parameters for `alg`, or null when Web Crypto has none.
function paramsFor(alg, opts) {
  log.debug("Entering paramsFor(). alg=" + alg);
  var o = opts || {};
  if (EC_CURVE[alg]) {
    var hash = o.hash ? DIGESTS[String(o.hash).toLowerCase()] : EC_HASH[alg];
    log.debug("Leaving paramsFor(). ECDSA.");
    return hash ? { imp: { name: "ECDSA", namedCurve: EC_CURVE[alg] },
                    op: { name: "ECDSA", hash: hash }, ecdsa: true } : null;
  }
  var m = /^rsa-(pkcs1|pss)-(sha1|sha256|sha384|sha512)$/.exec(alg);
  if (m) {
    var rh = RSA_HASH[m[2]];
    var pss = m[1] === "pss";
    if (pss && !SALT[rh]) {
      log.debug("Leaving paramsFor(). PSS without a salt length.");
      return null;
    }
    log.debug("Leaving paramsFor(). RSA.");
    return {
      imp: { name: pss ? "RSA-PSS" : "RSASSA-PKCS1-v1_5", hash: rh },
      op: pss ? { name: "RSA-PSS", saltLength: SALT[rh] }
              : { name: "RSASSA-PKCS1-v1_5" }
    };
  }
  if (alg === "ed25519") {
    log.debug("Leaving paramsFor(). Ed25519.");
    return { imp: { name: "Ed25519" }, op: { name: "Ed25519" } };
  }
  log.debug("Leaving paramsFor(). Not in Web Crypto.");
  return null;
}

// crypto.subtle when this call should use it, else null.
function subtleFor(opts) {
  log.debug("Entering subtleFor().");
  var o = opts || {};
  var wanted = (o.backend || provider.backend()) === "webcrypto";
  var g = typeof globalThis !== "undefined" ? globalThis : {};
  var s = wanted && provider.webcryptoAvailable() && g.crypto &&
      g.crypto.subtle ? g.crypto.subtle : null;
  log.debug("Leaving subtleFor(). " + (s ? "Web Crypto" : "js"));
  return s;
}

// A key as the JWK Web Crypto imports: the provider's, with no metadata.
function webJwk(key, wantPrivate) {
  log.debug("Entering webJwk().");
  var jwk = provider.exportKey(wantPrivate ? key : provider.publicKeyOf(key),
                               "jwk");
  delete jwk.alg;
  delete jwk.kid;
  delete jwk.use;
  delete jwk.key_ops;
  log.debug("Leaving webJwk().");
  return jwk;
}

// sign(alg, key, data, opts) -> Promise<{ signature, engine }>. engine is
// "webcrypto" or "js".
async function sign(alg, key, data, opts) {
  log.debug("Entering sign(). alg=" + alg);
  var o = opts || {};
  var subtle = subtleFor(o);
  var p = subtle ? paramsFor(alg, o) : null;
  if (p) {
    try {
      var k = await subtle.importKey("jwk", webJwk(key, true), p.imp, false,
                                     ["sign"]);
      var sig = new Uint8Array(await subtle.sign(p.op, k,
                                                 new Uint8Array(data)));
      if (p.ecdsa && o.encoding === "der") {
        sig = provider.rawToDerEcdsa(sig);
      }
      log.debug("Leaving sign(). Web Crypto.");
      return { signature: sig, engine: "webcrypto" };
    } catch (e) {
      log.debug("sign(): Web Crypto refused (" + e.message + "); js.");
    }
  }
  log.debug("Leaving sign(). js.");
  return { signature: provider.sign(alg, key, data, o), engine: "js" };
}

// verify(alg, key, data, signature, opts) -> Promise<{ valid, engine }>.
// Never rejects on a bad signature, as provider.verify() never throws on one.
async function verify(alg, key, data, signature, opts) {
  log.debug("Entering verify(). alg=" + alg);
  var o = opts || {};
  var subtle = subtleFor(o);
  var p = subtle ? paramsFor(alg, o) : null;
  if (p) {
    try {
      var sig = new Uint8Array(signature);
      if (p.ecdsa && o.encoding === "der") {
        sig = provider.derToRawEcdsa(sig, { "P-256": 32, "P-384": 48,
                                            "P-521": 66 }[p.imp.namedCurve]);
      }
      var k = await subtle.importKey("jwk", webJwk(key, false), p.imp, false,
                                     ["verify"]);
      var ok = await subtle.verify(p.op, k, sig, new Uint8Array(data));
      log.debug("Leaving verify(). Web Crypto " + ok);
      return { valid: !!ok, engine: "webcrypto" };
    } catch (e) {
      log.debug("verify(): Web Crypto refused (" + e.message + "); js.");
    }
  }
  var valid = provider.verify(alg, key, data, signature, o);
  log.debug("Leaving verify(). js " + valid);
  return { valid: valid, engine: "js" };
}

// digest(alg, data, opts) -> Promise<{ digest, engine }>.
async function digest(alg, data, opts) {
  log.debug("Entering digest(). alg=" + alg);
  var subtle = subtleFor(opts);
  var name = DIGESTS[String(alg).toLowerCase()];
  if (subtle && name) {
    try {
      var out = new Uint8Array(await subtle.digest(name, new Uint8Array(data)));
      log.debug("Leaving digest(). Web Crypto.");
      return { digest: out, engine: "webcrypto" };
    } catch (e) {
      log.debug("digest(): Web Crypto refused (" + e.message + "); js.");
    }
  }
  log.debug("Leaving digest(). js.");
  return { digest: provider.digest(alg, data), engine: "js" };
}

module.exports = {
  sign: sign,
  verify: verify,
  digest: digest,
  paramsFor: paramsFor
};
