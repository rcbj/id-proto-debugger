// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: anoncreds_wallet.js
//
// ---------------------------------------------------------------------------
// AnonCreds in the VC workflows (#479): what anoncreds.js needs around it to
// be a wallet credential. No DOM.
//
//   * The HELD credential is a bundle, because presenting an AnonCreds
//     credential needs its schema and credential definition as well, and a
//     wallet with no ledger cannot fetch them:
//       { "format": "anoncreds", "credential": {...}, "schema": {...},
//         "schema_id": "...", "credential_definition": {...},
//         "cred_def_id": "...",
//         "revocation": { "registry_definition": {...},
//                         "status_list": {...}, "tails": "<base64url>" } }
//     — the revocation member only for a revocable credential, and then
//     the presentation proves non-revocation at the status list's
//     timestamp (the mapping's non_revoked interval is that instant);
//   * The LINK SECRET is the holder's key material, so it lives where the
//     holder key does (sd_jwt_vc.js KEYS.HOLDER_PRIVATE_JWK, behind the same
//     save-key preference and paste field): an oct JWK whose k is the
//     secret's big-endian bytes and whose alg says what it is.
//   * Neither OpenID4VCI 1.0 nor OpenID4VP 1.0 defines AnonCreds, so the
//     mapping of an OpenID4VP request onto an AnonCreds presentation request
//     is THIS DEBUGGER'S, and its labels say so: one requested attribute per
//     DCQL claim (named by the claim path's last segment), and the AnonCreds
//     nonce — which must be decimal digits — the OpenID4VP nonce itself when
//     it is digits, otherwise the decimal of the first 80 bits of SHA-256
//     over its UTF-8 bytes. A Verifier reproducing the same rule verifies.
// ---------------------------------------------------------------------------

var provider = require("./crypto_provider");
var bytes = require("./crypto_bytes");
var anoncreds = require("./anoncreds");
var rev = require("./anoncreds_revocation");
var w3c = require("./anoncreds_w3c");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "anoncreds_wallet",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var FORMAT = "anoncreds";
var LINK_SECRET_ALG = "AnonCreds-link-secret";

function looksLikeBundle(text) {
  log.debug("Entering looksLikeBundle().");
  var raw = String(text || "").trim();
  if (raw.charAt(0) !== "{") {
    log.debug("Leaving looksLikeBundle(). Not JSON.");
    return false;
  }
  try {
    var o = JSON.parse(raw);
    var ok = o.format === FORMAT && !!o.credential &&
      (!!((o.credential.signature || {}).p_credential) ||
       w3c.isW3cCredential(o.credential));
    log.debug("Leaving looksLikeBundle(). " + ok);
    return ok;
  } catch (e) {
    log.debug("Leaving looksLikeBundle(). " + e.message);
    return false;
  }
}

function parseBundle(text) {
  log.debug("Entering parseBundle().");
  var o = JSON.parse(String(text).trim());
  var cred = o.credential;
  if (!o.schema || !o.credential_definition) {
    log.debug("Leaving parseBundle(). Incomplete.");
    throw new Error("an AnonCreds credential is held with its schema and " +
                    "credential definition; this one lacks one of them.");
  }
  // A credential in the W3C form (anoncreds-2023) is held as it came and
  // used as the legacy credential it re-encodes; its presentations go out
  // in the W3C form too.
  var isW3c = w3c.isW3cCredential(cred);
  var w3cCredential = isW3c ? cred : null;
  if (isW3c) cred = w3c.fromW3cCredential(cred);
  log.debug("Leaving parseBundle().");
  return { credential: cred, w3c: isW3c, w3cCredential: w3cCredential,
           schema: o.schema,
           schemaId: o.schema_id || cred.schema_id,
           credentialDefinition: o.credential_definition,
           credDefId: o.cred_def_id || cred.cred_def_id,
           revocation: o.revocation || null };
}

function bundle(credential, schema, credentialDefinition) {
  log.debug("Entering bundle().");
  log.debug("Leaving bundle().");
  return JSON.stringify({ format: FORMAT, credential: credential,
    schema: schema, schema_id: credential.schema_id,
    credential_definition: credentialDefinition,
    cred_def_id: credential.cred_def_id });
}

function linkSecretJwk(linkSecret) {
  log.debug("Entering linkSecretJwk().");
  log.debug("Leaving linkSecretJwk().");
  return { kty: "oct", alg: LINK_SECRET_ALG,
           k: bytes.bytesToB64u(anoncreds.toBytes(BigInt(linkSecret))) };
}

function isLinkSecretJwk(jwk) {
  log.debug("Entering isLinkSecretJwk().");
  log.debug("Leaving isLinkSecretJwk().");
  return !!jwk && jwk.kty === "oct" && jwk.alg === LINK_SECRET_ALG && !!jwk.k;
}

function linkSecretOf(jwk) {
  log.debug("Entering linkSecretOf().");
  if (!isLinkSecretJwk(jwk)) {
    log.debug("Leaving linkSecretOf(). Not a link secret.");
    throw new Error("the holder key is not an AnonCreds link secret (an oct " +
                    "JWK with alg " + LINK_SECRET_ALG + ").");
  }
  var b = bytes.b64uToBytes(jwk.k);
  log.debug("Leaving linkSecretOf().");
  return b.length ? BigInt("0x" + bytes.bytesToHex(b)).toString(10) : "0";
}

// The AnonCreds nonce for an OpenID4VP nonce (this debugger's rule).
function nonceFor(oid4vpNonce) {
  log.debug("Entering nonceFor().");
  var s = String(oid4vpNonce || "");
  if (/^\d+$/.test(s)) {
    log.debug("Leaving nonceFor(). Digits.");
    return s;
  }
  var d = provider.digest("sha256", bytes.strBytes(s)).slice(0, 10);
  log.debug("Leaving nonceFor(). Hashed.");
  return BigInt("0x" + bytes.bytesToHex(d)).toString(10);
}

// The presentation request for a DCQL credential query: one requested
// attribute per claim, its referent the attribute's own name (a referent
// is any string), so a presentation read back without its request still
// names what it reveals.
function presentationRequestFor(names, oid4vpNonce, revocationTimestamp) {
  log.debug("Entering presentationRequestFor(). " + names.length);
  var attrs = {};
  names.forEach(function (n) {
    attrs[String(n)] = { name: String(n) };
  });
  var out = { nonce: nonceFor(oid4vpNonce), name: "OpenID4VP request",
              version: "1.0", requested_attributes: attrs,
              requested_predicates: {} };
  if (revocationTimestamp !== undefined && revocationTimestamp !== null) {
    out.non_revoked = { from: revocationTimestamp, to: revocationTimestamp };
  }
  log.debug("Leaving presentationRequestFor().");
  return out;
}

// The revocation material a bundle carries, as anoncreds.js takes it.
function revocationOf(b) {
  log.debug("Entering revocationOf().");
  if (!b.revocation || !b.credential.rev_reg_id) {
    log.debug("Leaving revocationOf(). Not revocable here.");
    return null;
  }
  var list = Object.assign({ revRegDefId: b.credential.rev_reg_id },
                           b.revocation.status_list);
  var defs = {};
  defs[b.credential.rev_reg_id] = b.revocation.registry_definition;
  log.debug("Leaving revocationOf().");
  return { list: list, definitions: defs,
           definition: b.revocation.registry_definition,
           tails: bytes.b64uToBytes(b.revocation.tails) };
}

// Present the held bundle, revealing `names` (attribute names as the
// credential spells them), to a request with `oid4vpNonce`.
function present(held, names, linkSecretJwkValue, oid4vpNonce) {
  log.debug("Entering present().");
  var b = parseBundle(held);
  var revocation = revocationOf(b);
  var request = presentationRequestFor(names, oid4vpNonce,
    revocation ? revocation.list.timestamp : null);
  var entry = { credential: b.credential };
  if (revocation) {
    entry.timestamp = revocation.list.timestamp;
    entry.revocationState = rev.revocationState({ credential: b.credential,
      credentialDefinition: b.credentialDefinition,
      revocationRegistryDefinition: revocation.definition,
      revocationStatusList: revocation.list, tailsBytes: revocation.tails });
  }
  var schemas = {};
  schemas[b.schemaId] = b.schema;
  var cds = {};
  cds[b.credDefId] = b.credentialDefinition;
  var presentation = anoncreds.createPresentation({
    presentationRequest: request, credentials: [entry],
    credentialsProve: Object.keys(request.requested_attributes).map(
      function (ref) {
        return { entryIndex: 0, referent: ref, isPredicate: false,
                 reveal: true };
      }),
    selfAttest: {}, linkSecret: linkSecretOf(linkSecretJwkValue),
    schemas: schemas, credentialDefinitions: cds });
  if (b.w3c) {
    var issuerIds = {};
    issuerIds[b.credDefId] = b.w3cCredential.issuer;
    log.debug("Leaving present(). W3C form.");
    return { presentation: w3c.toW3cPresentation(presentation, request,
      { issuerIds: issuerIds }), legacy: presentation, request: request };
  }
  log.debug("Leaving present().");
  return { presentation: presentation, request: request };
}

// The legacy presentation anoncreds.js verifies, from either form.
function legacyPresentation(presentation, request) {
  log.debug("Entering legacyPresentation().");
  var p = typeof presentation === "string" ? JSON.parse(presentation) :
      presentation;
  log.debug("Leaving legacyPresentation().");
  return w3c.isW3cPresentation(p) ? w3c.fromW3cPresentation(p, request) : p;
}

// The claims a presentation reveals: requested attribute name -> raw.
function revealedClaims(presentation, request) {
  log.debug("Entering revealedClaims().");
  var out = {};
  if (w3c.isW3cPresentation(presentation)) {
    // credentialSubject: a revealed attribute's raw value; a predicate's
    // attribute is `true`, which reveals nothing and is not a claim.
    [].concat(presentation.verifiableCredential || []).forEach(function (vc) {
      var s = vc.credentialSubject || {};
      Object.keys(s).forEach(function (n) {
        if (s[n] !== true) out[n] = String(s[n]);
      });
    });
    log.debug("Leaving revealedClaims(). W3C form.");
    return out;
  }
  var rp = (presentation || {}).requested_proof || {};
  Object.keys(rp.revealed_attrs || {}).forEach(function (ref) {
    var name = (((request || {}).requested_attributes || {})[ref] || {}).name ||
      ref;
    out[name] = rp.revealed_attrs[ref].raw;
  });
  Object.keys(rp.revealed_attr_groups || {}).forEach(function (ref) {
    var vals = rp.revealed_attr_groups[ref].values || {};
    Object.keys(vals).forEach(function (n) {
      out[n] = vals[n].raw;
    });
  });
  log.debug("Leaving revealedClaims().");
  return out;
}

function looksLikePresentation(text) {
  log.debug("Entering looksLikePresentation().");
  try {
    var o = typeof text === "string" ? JSON.parse(text) : text;
    var ok = !!(o && ((o.proof && o.proof.aggregated_proof &&
                o.requested_proof) || w3c.isW3cPresentation(o)));
    log.debug("Leaving looksLikePresentation(). " + ok);
    return ok;
  } catch (e) {
    log.debug("Leaving looksLikePresentation(). " + e.message);
    return false;
  }
}

module.exports = {
  FORMAT: FORMAT,
  LINK_SECRET_ALG: LINK_SECRET_ALG,
  looksLikeBundle: looksLikeBundle,
  parseBundle: parseBundle,
  bundle: bundle,
  linkSecretJwk: linkSecretJwk,
  isLinkSecretJwk: isLinkSecretJwk,
  linkSecretOf: linkSecretOf,
  nonceFor: nonceFor,
  presentationRequestFor: presentationRequestFor,
  present: present,
  legacyPresentation: legacyPresentation,
  revealedClaims: revealedClaims,
  revocationOf: revocationOf,
  looksLikePresentation: looksLikePresentation
};
