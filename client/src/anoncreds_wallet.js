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
var vpQuery = require("./vp_query");

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
// names what it reveals. `predicates` ([{ referent, name, p_type,
// p_value }], vp_query.js planFor()) adds requested predicates — the
// mapping of a Presentation Exchange predicate or of the debugger's DCQL
// predicate extension (vp_query.js says which parts are standard).
function presentationRequestFor(names, oid4vpNonce, revocationTimestamp,
                                predicates) {
  log.debug("Entering presentationRequestFor(). " + names.length);
  var attrs = {};
  names.forEach(function (n) {
    attrs[String(n)] = { name: String(n) };
  });
  var preds = {};
  (predicates || []).forEach(function (p) {
    preds[p.referent] = { name: p.name, p_type: p.p_type,
                          p_value: p.p_value };
  });
  var out = { nonce: nonceFor(oid4vpNonce), name: "OpenID4VP request",
              version: "1.0", requested_attributes: attrs,
              requested_predicates: preds };
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

// The identifiers an AnonCreds restriction is evaluated against (AnonCreds
// v1.0, "Restrictions"), for a parsed bundle.
function restrictionTagsOf(b) {
  log.debug("Entering restrictionTagsOf().");
  var schema = b.schema || {};
  log.debug("Leaving restrictionTagsOf().");
  return { schema_id: b.schemaId, cred_def_id: b.credDefId,
           schema_name: schema.name, schema_version: schema.version,
           schema_issuer_id: schema.issuerId,
           issuer_id: (b.credentialDefinition || {}).issuerId,
           rev_reg_id: b.credential.rev_reg_id || undefined };
}

// Whether a restrictions value (an object, an array meaning OR, $or / $and
// in the wallet query language's shape) is met by a bundle's tags. An
// attr::<name>::value / ::marker restriction is checked against the
// credential's values.
function restrictionsMet(restrictions, b) {
  log.debug("Entering restrictionsMet().");
  if (restrictions === undefined || restrictions === null) {
    log.debug("Leaving restrictionsMet(). None.");
    return true;
  }
  var tags = restrictionTagsOf(b);
  var values = b.credential.values || {};
  var one = function (r) {
    log.debug("Entering one().");
    var ok = Object.keys(r || {}).every(function (k) {
      if (k === "$or") {
        return [].concat(r[k]).some(one);
      }
      if (k === "$and") {
        return [].concat(r[k]).every(one);
      }
      var m = /^attr::(.+)::(value|marker)$/.exec(k);
      if (m) {
        var name = Object.keys(values).filter(function (n) {
          return anoncreds.attrCommonView(n) ===
            anoncreds.attrCommonView(m[1]);
        })[0];
        if (name === undefined) return false;
        return m[2] === "marker" ? String(r[k]) === "1" :
          String(values[name].raw) === String(r[k]);
      }
      return tags[k] !== undefined && String(tags[k]) === String(r[k]);
    });
    log.debug("Leaving one(). " + ok);
    return ok;
  };
  var ok = Array.isArray(restrictions) ? (restrictions.length === 0 ||
    restrictions.some(one)) : one(restrictions);
  log.debug("Leaving restrictionsMet(). " + ok);
  return ok;
}

// The held credential's attribute for a requested name (AnonCreds: case
// insensitive, spaces ignored), or undefined.
function heldAttribute(b, name) {
  log.debug("Entering heldAttribute().");
  var values = b.credential.values || {};
  var hit = Object.keys(values).filter(function (n) {
    return anoncreds.attrCommonView(n) === anoncreds.attrCommonView(name);
  })[0];
  log.debug("Leaving heldAttribute(). " + (hit !== undefined));
  return hit;
}

// A claim lookup over a parsed bundle, for vp_query.js: a path's last
// segment is an attribute name (or an identifier: schema_id, cred_def_id,
// ...), and a value is the raw value the issuer signed the encoding of.
function claimLookup(b) {
  log.debug("Entering claimLookup().");
  var tags = restrictionTagsOf(b);
  log.debug("Leaving claimLookup().");
  return function (path) {
    var segs = [].concat(path || []).filter(function (x) {
      return typeof x === "string";
    });
    var last = segs[segs.length - 1];
    if (last === undefined) return { found: false };
    if (segs.length === 1 && tags[last] !== undefined) {
      return { found: true, value: tags[last] };
    }
    var name = heldAttribute(b, last);
    return name === undefined ? { found: false } :
      { found: true, value: b.credential.values[name].raw };
  };
}

function compare(value, pType, pValue) {
  log.debug("Entering compare().");
  var v = Number(value);
  var ok = pType === ">=" ? v >= pValue : pType === ">" ? v > pValue :
    pType === "<=" ? v <= pValue : pType === "<" ? v < pValue : false;
  log.debug("Leaving compare(). " + ok);
  return ok;
}

// Present the held bundle to an AnonCreds presentation request — the
// AnonCreds specification's own request object, which is where its
// predicates are standardized, or one this debugger mapped an OpenID4VP
// request onto. Every requested attribute is revealed and every predicate
// proven from the one held credential; what the credential cannot answer
// is refused here, naming it, rather than left for CL to fail on.
// Answers { presentation, request, legacy? }.
function presentRequest(held, request, linkSecretJwkValue) {
  log.debug("Entering presentRequest().");
  var b = typeof held === "string" ? parseBundle(held) : held;
  var revocation = revocationOf(b);
  var entry = { credential: b.credential };
  var nr = request.non_revoked;
  if (revocation && nr) {
    var ts = revocation.list.timestamp;
    if ((nr.from !== undefined && ts < nr.from) ||
        (nr.to !== undefined && ts > nr.to)) {
      log.debug("Leaving presentRequest(). Timestamp outside.");
      throw new Error("the held status list is at " + ts + ", outside the " +
                      "requested non_revoked interval " +
                      JSON.stringify(nr) + ".");
    }
    entry.timestamp = ts;
    entry.revocationState = rev.revocationState({ credential: b.credential,
      credentialDefinition: b.credentialDefinition,
      revocationRegistryDefinition: revocation.definition,
      revocationStatusList: revocation.list, tailsBytes: revocation.tails });
  }
  var prove = [];
  var refusals = [];
  Object.keys(request.requested_attributes || {}).forEach(function (ref) {
    var a = request.requested_attributes[ref];
    [].concat(a.names || a.name).forEach(function (n) {
      if (heldAttribute(b, n) === undefined) {
        refusals.push("the credential has no attribute " +
                      JSON.stringify(n) + " (requested as " + ref + ")");
      }
    });
    if (!restrictionsMet(a.restrictions, b)) {
      refusals.push(ref + "'s restrictions are not met by this credential");
    }
    prove.push({ entryIndex: 0, referent: ref, isPredicate: false,
                 reveal: true });
  });
  Object.keys(request.requested_predicates || {}).forEach(function (ref) {
    var p = request.requested_predicates[ref];
    var name = heldAttribute(b, p.name);
    if (name === undefined) {
      refusals.push("the credential has no attribute " +
                    JSON.stringify(p.name) + " for predicate " + ref);
    } else if (!/^[+-]?\d+$/.test(String(b.credential.values[name].raw))) {
      refusals.push(p.name + " is not an integer, so no predicate can be " +
                    "proven over it");
    } else if (!compare(b.credential.values[name].raw, p.p_type,
                        p.p_value)) {
      refusals.push("the credential does not satisfy " + p.name + " " +
                    p.p_type + " " + p.p_value);
    }
    if (!restrictionsMet(p.restrictions, b)) {
      refusals.push(ref + "'s restrictions are not met by this credential");
    }
    prove.push({ entryIndex: 0, referent: ref, isPredicate: true,
                 reveal: true });
  });
  if (refusals.length) {
    log.debug("Leaving presentRequest(). Refused.");
    throw new Error("this credential cannot answer the presentation " +
                    "request: " + refusals.join("; ") + ".");
  }
  var schemas = {};
  schemas[b.schemaId] = b.schema;
  var cds = {};
  cds[b.credDefId] = b.credentialDefinition;
  var presentation = anoncreds.createPresentation({
    presentationRequest: request, credentials: [entry],
    credentialsProve: prove, selfAttest: {},
    linkSecret: linkSecretOf(linkSecretJwkValue),
    schemas: schemas, credentialDefinitions: cds });
  if (b.w3c) {
    var issuerIds = {};
    issuerIds[b.credDefId] = b.w3cCredential.issuer;
    log.debug("Leaving presentRequest(). W3C form.");
    return { presentation: w3c.toW3cPresentation(presentation, request,
      { issuerIds: issuerIds }), legacy: presentation, request: request };
  }
  log.debug("Leaving presentRequest().");
  return { presentation: presentation, request: request };
}

// Present the held bundle, revealing `names` (attribute names as the
// credential spells them) and proving `predicates` (vp_query.js planFor()
// anoncredsPredicates), to a request with `oid4vpNonce`.
function present(held, names, linkSecretJwkValue, oid4vpNonce, predicates) {
  log.debug("Entering present().");
  var b = parseBundle(held);
  var revocation = revocationOf(b);
  var request = presentationRequestFor(names, oid4vpNonce,
    revocation ? revocation.list.timestamp : null, predicates);
  log.debug("Leaving present().");
  return presentRequest(b, request, linkSecretJwkValue);
}

// What a presentation PROVES without revealing: one row per requested
// predicate the presentation answers, { referent, name, p_type, p_value,
// subProofIndex }.
function provenPredicates(presentation, request) {
  log.debug("Entering provenPredicates().");
  var legacy = legacyPresentation(presentation, request);
  var rp = (legacy || {}).requested_proof || {};
  var out = Object.keys((request || {}).requested_predicates || {}).map(
    function (ref) {
      var p = request.requested_predicates[ref];
      var at = (rp.predicates || {})[ref];
      return { referent: ref, name: p.name, p_type: p.p_type,
               p_value: p.p_value, answered: !!at,
               subProofIndex: at ? at.sub_proof_index : null };
    });
  log.debug("Leaving provenPredicates(). " + out.length);
  return out;
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

// A Verifier's check of an AnonCreds presentation against the QUERY it sent
// (vp_query.js), holding no credential: the AnonCreds request is rebuilt
// from the query item, the OpenID4VP nonce and the attributes the
// presentation reveals, exactly as the wallet built it, and the CL proof is
// verified against it — every predicate the item asks for included, so a
// presentation proving a weaker predicate, or none, fails. opts:
// { presentation, item, nonce (the OpenID4VP one), anoncredsNonce (a raw
// AnonCreds request's own, instead), request (a raw AnonCreds request,
// instead of item), schemas, credentialDefinitions,
// revocationRegistryDefinitions, revocationStatusLists }.
// { valid, errors, warnings, request, revealed, predicates }.
function verifyForQuery(opts) {
  log.debug("Entering verifyForQuery().");
  var pres = typeof opts.presentation === "string" ?
    JSON.parse(opts.presentation) : opts.presentation;
  var isW3c = w3c.isW3cPresentation(pres);
  var request = opts.request;
  if (!request) {
    var names = Object.keys(revealedClaims(pres, null));
    var ids = isW3c ? w3c.fromW3cPresentation(pres, null).identifiers :
      (pres.identifiers || []);
    var ts = (ids[0] || {}).timestamp;
    request = vpQuery.anoncredsRequestFor(vpQuery.nominalPlan(opts.item,
      opts.item.claims.length ? names.filter(function (n) {
        return opts.item.claims.some(function (c) {
          return anoncreds.attrCommonView(c.attribute) ===
            anoncreds.attrCommonView(n);
        });
      }).map(function (n) {
        return opts.item.claims.filter(function (c) {
          return anoncreds.attrCommonView(c.attribute) ===
            anoncreds.attrCommonView(n);
        })[0].attribute;
      }) : []),
      { nonce: opts.anoncredsNonce || nonceFor(opts.nonce),
        revocationTimestamp: ts === null || ts === undefined ? null : ts });
  }
  var legacy;
  try {
    legacy = legacyPresentation(pres, request);
  } catch (e) {
    log.debug("Leaving verifyForQuery(). " + e.message);
    return { valid: false, errors: [e.message], warnings: [],
             request: request, revealed: {}, predicates: [] };
  }
  var r = anoncreds.verifyPresentation(legacy, {
    presentationRequest: request, schemas: opts.schemas || {},
    credentialDefinitions: opts.credentialDefinitions || {},
    revocationRegistryDefinitions: opts.revocationRegistryDefinitions || {},
    revocationStatusLists: opts.revocationStatusLists || [] });
  // The query's restrictions (a PE field on $.cred_def_id, ...), against
  // the credentials the sub-proofs name: the request carries none, so the
  // CL verification above does not see them.
  var restrictions = opts.item && opts.item.restrictions;
  if (restrictions) {
    (legacy.identifiers || []).forEach(function (id, i) {
      var schema = (opts.schemas || {})[id.schema_id] || {};
      var cd = (opts.credentialDefinitions || {})[id.cred_def_id] || {};
      var met = restrictionsMet(restrictions, { schemaId: id.schema_id,
        credDefId: id.cred_def_id, schema: schema, credentialDefinition: cd,
        credential: { rev_reg_id: id.rev_reg_id, values: {} } });
      if (!met) {
        r.valid = false;
        r.errors = r.errors.concat(["sub-proof " + i + "'s credential (" +
          id.cred_def_id + ") does not meet the query's restrictions " +
          JSON.stringify(restrictions) + "."]);
      }
    });
  }
  log.debug("Leaving verifyForQuery(). " + r.valid);
  return { valid: r.valid, errors: r.errors, warnings: r.warnings,
           request: request, revealed: revealedClaims(pres, request),
           predicates: provenPredicates(pres, request), w3c: isW3c };
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
  presentRequest: presentRequest,
  restrictionsMet: restrictionsMet,
  claimLookup: claimLookup,
  provenPredicates: provenPredicates,
  verifyForQuery: verifyForQuery,
  legacyPresentation: legacyPresentation,
  revealedClaims: revealedClaims,
  revocationOf: revocationOf,
  looksLikePresentation: looksLikePresentation
};
