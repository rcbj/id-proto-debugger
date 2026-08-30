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

// A forge binary string to the bytes it stands for. One character per byte;
// see the header for what a TextEncoder would do here instead.
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

module.exports = {
  signerFor: signerFor,
  verifierFor: verifierFor,
  engineFor: engineFor,
  binaryStringToBytes: binaryStringToBytes,
  asBytes: asBytes
};
