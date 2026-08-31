'use strict';
//
// File: xmldsig_pqc.js
//
// ===========================================================================
// THE POST-QUANTUM SIGNER AND VERIFIER FOR XML SIGNATURE, IN ONE PLACE.
//
// `common/xmldsig.js` holds the sixteen post-quantum `SignatureMethod`
// identifiers of draft-eastlake-rfc9231bis-xmlsec-uris and NOT the
// cryptography — that file's own header says why, and it is the same argument
// it already makes for ECDSA and HMAC: the primitives arrive through
// `opts.signer` / `opts.verifier`, so that a megabyte of lattice does not land
// in the SAML, WS-Trust and WS-Federation bundles for the pages that never
// sign with one.
//
// This file is that pair. It is one module and not five because five pages
// offer the menu — the SAML Assertion generator, the SAML Request tool, the
// SAML Response tool, WS-Trust and WS-Federation, plus the Digital Signature
// page — and a signer written per page is five readings of "which engine does
// this URI mean", which is precisely the class of duplication this project
// keeps having to undo (see the header of `common/xmldsig.js` on the three
// canonicalizers, and of `client/src/jws.js` on the six JWS implementations).
//
// IT OWNS NO CRYPTOGRAPHY EITHER. `pqc.js` is ML-DSA and SLH-DSA; `hbs.js` is
// HSS/LMS. What lives here is the ROUTING — a `spec` from the registry to the
// engine that performs it — and the two byte conversions XMLDSIG needs, which
// are the part that is easy to get quietly wrong.
//
// ---------------------------------------------------------------------------
// THE TWO CONVERSIONS, BECAUSE THEY ARE WHERE THIS GOES WRONG SILENTLY.
//
// XMLDSIG hands a signer the canonicalized SignedInfo as a forge BINARY STRING
// — one character per byte, already UTF-8 encoded — and takes back either a
// binary string or a byte array. Every post-quantum engine here speaks
// `Uint8Array`. A `new TextEncoder().encode()` applied to that binary string
// would re-encode bytes 0x80-0xFF as two-byte UTF-8 sequences and sign a
// DIFFERENT MESSAGE than the verifier canonicalizes — a signature that is
// perfectly valid over bytes nobody else computes, which verifies against
// itself and against nothing. So the conversion is charCodeAt/fromCharCode,
// deliberately, and it is written once.
// ===========================================================================

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xmldsig_pqc",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var pqc = require("./pqc");
var hbs = require("./hbs");
var pkEncryption = require("./pk_encryption");
// FrodoKEM has no library anywhere — see the header of this file and of
// client/src/frodokem.js, which is written from the specification and held
// to the reference implementation's Known Answer Tests.
var frodokem = require("./frodokem");

// A forge binary string to the bytes it stands for. One character per byte;
// see the header for what a TextEncoder would do here instead.
// Randomness for FrodoKEM's key generation and encapsulation. `crypto` in a
// browser, node's webcrypto under a test — the same shim every module here
// uses, written out because this file must load in both.
function randomBytes(n) {
  log.debug("Entering randomBytes(). " + n + " bytes.");
  var out = new Uint8Array(n);
  var source = (typeof window !== 'undefined' && window.crypto) ||
      (typeof globalThis !== 'undefined' && globalThis.crypto) || null;
  if (source && typeof source.getRandomValues === 'function') {
    // getRandomValues refuses more than 65536 bytes at a time; nothing here
    // asks for that much, but the loop costs nothing and the refusal would be
    // a key generation that fails only on the largest parameter set.
    for (var at = 0; at < n; at += 65536) {
      source.getRandomValues(out.subarray(at, Math.min(at + 65536, n)));
    }
    log.debug("Leaving randomBytes(). Web Crypto.");
    return out;
  }
  // NO `require('crypto')` FALLBACK, and its absence is enforced by
  // tests/jwk_pem_encoding.js: browserify substitutes a bare
  // `require('crypto')` with the whole crypto-browserify shim, which drags in
  // elliptic
  // (GHSA-848j-6mx2-7j84, for which no patched version exists) — and this file
  // IS bundled, so the fallback put it back into ten browser bundles. There is
  // nothing to fall back to anyway: `globalThis.crypto` is present in every
  // browser and in node from 18, which is four majors below what this project
  // pins.
  log.debug("Leaving randomBytes(). No source of randomness.");
  throw new Error('No cryptographic randomness is available: neither ' +
      'window.crypto nor globalThis.crypto has getRandomValues(). In a ' +
      'browser that means a non-secure context; in node it means a runtime ' +
      'older than 18.');
}

function binaryStringToBytes(text) {
  log.debug("Entering binaryStringToBytes().");
  var out = new Uint8Array(text.length);
  for (var i = 0; i < text.length; i++) {
    out[i] = text.charCodeAt(i) & 0xff;
  }
  log.debug("Leaving binaryStringToBytes(). " + out.length + " bytes.");
  return out;
}

// Whatever the caller holds, as bytes: a Uint8Array, an Array, or a binary
// string. Callers hold key material in all three forms — a pane's textarea
// gives a string, `pqc.generateAkpKeyPair()` gives arrays.
function asBytes(value) {
  log.debug("Entering asBytes().");
  if (value instanceof Uint8Array) {
    log.debug("Leaving asBytes(). Already bytes.");
    return value;
  }
  if (typeof value === 'string') {
    log.debug("Leaving asBytes(). From a binary string.");
    return binaryStringToBytes(value);
  }
  log.debug("Leaving asBytes(). From an array.");
  return new Uint8Array(value);
}

// ---------------------------------------------------------------------------
// WHICH ENGINE A SPEC MEANS. The registry's `family` decides and its `alg` is
// the name the engine knows — `SIG_METHODS` carries both, so this function is
// a switch over three values and never a string match on a URI.
// ---------------------------------------------------------------------------
function engineFor(spec) {
  log.debug("Entering engineFor(). family=" +
            (spec ? spec.family : '(none)'));
  if (!spec || !spec.postQuantum) {
    log.debug("Leaving engineFor(). Not a post-quantum method.");
    throw new Error('xmldsig_pqc: "' +
        (spec && spec.label ? spec.label : 'that SignatureMethod') + '" is ' +
        'not one of the post-quantum methods this module signs. It handles ' +
        'the sixteen identifiers of ' +
        'draft-eastlake-rfc9231bis-xmlsec-uris; RSA is built into ' +
        'common/xmldsig.js and ECDSA and HMAC have signers of their own.');
  }
  if (spec.family === 'mldsa' || spec.family === 'slhdsa') {
    log.debug("Leaving engineFor(). pqc.js.");
    return 'pqc';
  }
  if (spec.family === 'hsslms') {
    log.debug("Leaving engineFor(). hbs.js.");
    return 'hbs';
  }
  log.debug("Leaving engineFor(). No engine.");
  throw new Error('xmldsig_pqc: no engine for the "' + spec.family +
      '" family. This module routes mldsa and slhdsa to pqc.js and hsslms ' +
      'to hbs.js.');
}

// ---------------------------------------------------------------------------
// THE SIGNER. `key` is the private key: for ML-DSA the 32-byte seed RFC 9964
// section 3.2 requires, for SLH-DSA its own secret key, and for HSS/LMS the
// serialized private key `hbs.js` reads — which is the one that CHANGES.
//
// **HSS/LMS SPENDS A ONE-TIME KEY EVERY TIME THIS IS CALLED**, and this
// function cannot hide that from the caller: `hssSign()` returns the advanced
// private key beside the signature, and a caller that throws it away and signs
// again from the same bytes has signed twice from one index — which hands an
// attacker the material to forge a third message. So the signer reports it
// through `onKeyAdvanced`, and a caller that does not supply one is REFUSED
// rather than quietly allowed to reuse an index. Nothing else in XML Signature
// behaves this way and nothing in the document records it: a re-signed
// document verifies perfectly and is worthless.
// ---------------------------------------------------------------------------
function signerFor(key, options) {
  log.debug("Entering signerFor().");
  var o = options || {};
  var signer = function (octets, spec) {
    log.debug("Entering the post-quantum signer. alg=" +
              (spec ? spec.alg : '(none)'));
    var engine = engineFor(spec);
    var message = binaryStringToBytes(octets);
    if (engine === 'pqc') {
      var sig = pqc.signWithPriv(spec.alg, message, asBytes(key));
      log.debug("Leaving the post-quantum signer. " + sig.length + " bytes.");
      return sig;
    }
    if (typeof o.onKeyAdvanced !== 'function') {
      log.debug("Leaving the post-quantum signer. No onKeyAdvanced.");
      throw new Error('HSS/LMS is STATEFUL: signing spends a one-time key ' +
          'and returns a new private key, and signing twice from one index ' +
          'hands an attacker the material to forge a third message. Pass ' +
          'onKeyAdvanced(newPrivateKeyBytes) so the spent key is replaced, ' +
          'or sign with a stateless algorithm — ML-DSA or SLH-DSA.');
    }
    var result = hbs.hssSign(asBytes(key), message);
    o.onKeyAdvanced(result.privateKey);
    log.debug("Leaving the post-quantum signer. HSS/LMS, key advanced.");
    return result.signature;
  };
  log.debug("Leaving signerFor().");
  return signer;
}

// ---------------------------------------------------------------------------
// THE VERIFIER. `key` is the public key. It answers false for a signature that
// does not hold up and THROWS only for one it could not attempt — an unknown
// algorithm, key material it cannot read — because those are different facts
// and a caller has to tell them apart: a bad signature is an answer about the
// document, and an unreadable key is a mistake in the pane.
//
// A WRONG LENGTH IS CHECKED FIRST AND NAMED. Every one of these schemes has a
// fixed signature size, and the registry carries it; a truncated base64, or a
// document signed with SLH-DSA-SHA2-128s being checked against the -128f
// identifier, otherwise reaches the engine as bytes it refuses without saying
// which of the twelve parameter sets it expected.
// ---------------------------------------------------------------------------
function verifierFor(key) {
  log.debug("Entering verifierFor().");
  var verifier = function (octets, signature, spec) {
    log.debug("Entering the post-quantum verifier. alg=" +
              (spec ? spec.alg : '(none)'));
    var engine = engineFor(spec);
    var message = binaryStringToBytes(octets);
    var sigBytes = asBytes(signature);
    if (spec.sigBytes && sigBytes.length !== spec.sigBytes) {
      log.debug("Leaving the post-quantum verifier. Wrong length.");
      throw new Error('A ' + spec.alg + ' signature is ' + spec.sigBytes +
          ' bytes and this SignatureValue holds ' + sigBytes.length +
          '. Either the base64 is truncated, or the document was signed ' +
          'with a different parameter set than the SignatureMethod names — ' +
          'the twelve SLH-DSA sets differ only in a suffix.');
    }
    if (engine === 'pqc') {
      var ok = pqc.verifyWithPub(spec.alg, sigBytes, message, asBytes(key));
      log.debug("Leaving the post-quantum verifier. ok=" + ok);
      return ok;
    }
    var hssOk = hbs.hssVerify(asBytes(key), message, sigBytes);
    log.debug("Leaving the post-quantum verifier. HSS/LMS ok=" + hssOk);
    return hssOk;
  };
  log.debug("Leaving verifierFor().");
  return verifier;
}

// ---------------------------------------------------------------------------
// THE KEM, for XML Encryption. `common/xmldsig.js` holds the three ML-KEM
// identifiers and the HKDF that turns a shared secret into a content
// encryption key; what it does not hold is the lattice, for the reason the
// signer above does not hold ML-DSA.
//
// It is `{ encapsulate, decapsulate }` because that is what a KEM IS, and the
// shape is worth stating: `encapsulate` takes only the RECIPIENT'S PUBLIC KEY
// and returns a ciphertext AND a fresh shared secret. There is no message
// argument and no key to pass in — the sender does not choose the secret,
// which is the whole difference from RSA key transport and the reason
// `encryptXml()` needed a second path rather than another branch.
//
// `spec.alg` is the parameter set name `pk_encryption.js` knows, so a URI
// never reaches this function.
// ---------------------------------------------------------------------------
function kemFor(spec) {
  log.debug("Entering kemFor(). alg=" + (spec ? spec.alg : '(none)'));
  if (spec && spec.family === 'frodokem') {
    // FrodoKEM's own module, because there is no library for it anywhere —
    // see the header of client/src/frodokem.js. Its API is already
    // encapsulate/decapsulate, so this is a rename and a byte conversion.
    log.debug("Leaving kemFor(). FrodoKEM.");
    return {
      encapsulate: function (publicKey) {
        log.debug("Entering encapsulate(). alg=" + spec.alg);
        const out = frodokem.encapsulate(spec.alg, asBytes(publicKey),
            function (n) { return randomBytes(n); });
        log.debug("Leaving encapsulate().");
        return { ciphertext: out.ciphertext, sharedSecret: out.sharedSecret };
      },
      decapsulate: function (ciphertext, privateKey) {
        log.debug("Entering decapsulate(). alg=" + spec.alg);
        const secret = frodokem.decapsulate(spec.alg, asBytes(privateKey),
                                            asBytes(ciphertext));
        log.debug("Leaving decapsulate().");
        return secret;
      }
    };
  }
  if (!spec || spec.family !== 'mlkem') {
    log.debug("Leaving kemFor(). Not a key-encapsulation method.");
    throw new Error('xmldsig_pqc: "' +
        (spec && spec.label ? spec.label : 'that EncryptionMethod') + '" is ' +
        'not a key-encapsulation method this module performs. It handles the ' +
        'three ML-KEM identifiers of section 3.6.9 and the twelve FrodoKEM ' +
        'ones of section 3.6.10; RSA key transport is built into ' +
        'common/xmldsig.js.');
  }
  const primitive = pkEncryption.mlkemSet(spec.alg).kem;
  log.debug("Leaving kemFor().");
  return {
    encapsulate: function (publicKey) {
      log.debug("Entering encapsulate(). alg=" + spec.alg);
      const out = primitive.encapsulate(asBytes(publicKey));
      log.debug("Leaving encapsulate().");
      // @noble names it `cipherText`; the rest of this project says
      // `ciphertext`, and one spelling crossing a module boundary is where a
      // silent `undefined` gets base64'd into a document.
      return { ciphertext: out.cipherText, sharedSecret: out.sharedSecret };
    },
    decapsulate: function (ciphertext, privateKey) {
      log.debug("Entering decapsulate(). alg=" + spec.alg);
      const secret = primitive.decapsulate(asBytes(ciphertext),
                                           asBytes(privateKey));
      log.debug("Leaving decapsulate().");
      return secret;
    }
  };
}

// ---------------------------------------------------------------------------
// THE MENU, BUILT FROM THE REGISTRY RATHER THAN WRITTEN OUT BESIDE IT.
//
// Five pages carry a SignatureMethod menu — the SAML Assertion generator, the
// SAML Request tool, WS-Trust, WS-Federation and the Digital Signature page —
// and sixteen options hand-written into five HTML files is five copies that
// will disagree the first time the draft renames anything. So the classical
// options stay in the markup, where they have always been, and the
// post-quantum ones are APPENDED from `SIG_METHODS` at load.
//
// **THE REGISTRY IS PASSED IN RATHER THAN REQUIRED**, and that is not
// ceremony: `common/xmldsig.js` is staged into `client/src/` at BUILD time, so
// a `require("./xmldsig")` here would resolve in a bundle and resolve to
// nothing in a checkout — which is where `tests/xmldsig_pqc.js` loads this
// file. A module that cannot be required in node is a module the node test
// cannot reach.
//
// They go in an `<optgroup>` whose label names the draft, because what
// separates these sixteen from the ones above them is not the algorithm, it is
// how settled the identifier is — and a flat list gives a reader nowhere to be
// told that.
//
// It is idempotent: a page that initialises twice must not offer thirty-two.
// ---------------------------------------------------------------------------
function appendSignatureOptions(select, sigMethods, uris) {
  log.debug("Entering appendSignatureOptions().");
  if (!select || !select.ownerDocument) {
    log.debug("Leaving appendSignatureOptions(). No select element.");
    return 0;
  }
  var doc = select.ownerDocument;
  var existing = select.getElementsByTagName("optgroup");
  for (var e = 0; e < existing.length; e++) {
    if (existing[e].getAttribute("data-pq-options")) {
      log.debug("Leaving appendSignatureOptions(). Already there.");
      return 0;
    }
  }
  var group = doc.createElement("optgroup");
  group.setAttribute("data-pq-options", "1");
  group.setAttribute("label",
      "Post-quantum — draft-eastlake-rfc9231bis-xmlsec-uris");
  var added = 0;
  for (var i = 0; i < uris.length; i++) {
    var spec = sigMethods[uris[i]];
    if (!spec) {
      continue;
    }
    var option = doc.createElement("option");
    option.setAttribute("value", uris[i]);
    option.appendChild(doc.createTextNode(spec.label));
    // The URI in the tooltip, because the label names the algorithm and what
    // actually goes into SignedInfo is the identifier — which is the half a
    // reader needs when an identity provider refuses it.
    option.setAttribute("title", uris[i]);
    group.appendChild(option);
    added++;
  }
  select.appendChild(group);
  log.debug("Leaving appendSignatureOptions(). " + added + " added.");
  return added;
}

module.exports = {
  appendSignatureOptions: appendSignatureOptions,
  signerFor: signerFor,
  verifierFor: verifierFor,
  engineFor: engineFor,
  kemFor: kemFor,
  binaryStringToBytes: binaryStringToBytes,
  asBytes: asBytes
};
