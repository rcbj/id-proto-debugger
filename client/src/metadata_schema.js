// File: metadata_schema.js
//
// ---------------------------------------------------------------------------
// Checking a metadata document against what its specification actually requires.
//
// READ THIS BEFORE LOOKING FOR THE SCHEMA FILE: there isn't one, and not because
// nobody fetched it. Neither specification publishes a machine-readable schema.
// OpenID4VCI 1.0 defines its metadata in prose and tables (section 12.2); the
// spec repository ships thirty-four JSON files and every one of them is an
// EXAMPLE, not a schema. RFC 8414 does the same in section 2, with an IANA
// registry for the member names and no schema either. So "validate against the
// published schema" cannot be done as stated, and pointing a validator at some
// third party's copy would be worse than this: it would check the document
// against somebody's unversioned reading of the spec, fetched over a network
// that — on these two panes especially — may well be the thing that is broken.
//
// What is here instead is the specifications' own normative rules, transcribed,
// with the section cited beside each one so a disagreement can be settled by
// reading the spec rather than by reading this file. Where a rule is a SHOULD or
// a convention rather than a MUST, it is reported as a warning, because a
// debugger that cries "invalid" at a legal document teaches its user to ignore
// it.
//
// Structure and vocabulary are checked; values are not resolved. That an
// endpoint is a syntactically valid https URL is checkable here. That it answers
// is not, and pretending otherwise would make this slow and flaky.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "metadata_schema",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // Loaded outside a configured page (the node tests do this): info is a
      // sane default and a missing config is not a reason to fail to load.
      return "info";
    }
  })()
});

// --- small predicates -------------------------------------------------------
function isObject(v) {
  return v !== null && typeof v === "object" && Object.prototype.toString.call(v) !== "[object Array]";
}
function isArray(v) { return Object.prototype.toString.call(v) === "[object Array]"; }
function isString(v) { return typeof v === "string"; }
function isNonEmptyString(v) { return isString(v) && v.trim() !== ""; }
function isStringArray(v) { return isArray(v) && v.every(isString); }

function parsedUrl(v) {
  if (!isNonEmptyString(v)) return null;
  try {
    return new URL(v);
  } catch (e) {
    // Not a URL at all; the caller reports it. Returning null rather than
    // throwing keeps every rule below a plain boolean.
    return null;
  }
}

// A result set both panes fill in the same way.
function report() {
  var out = { errors: [], warnings: [], plainHttp: [] };
  out.error = function (member, message, cite) {
    out.errors.push({ member: member, message: message, cite: cite });
  };
  out.warn = function (member, message, cite) {
    out.warnings.push({ member: member, message: message, cite: cite });
  };
  return out;
}

// A member that must be present, and a URL.
function requireUrl(r, doc, member, cite, opts) {
  var value = doc[member];
  if (value === undefined || value === null || value === "") {
    r.error(member, "is REQUIRED and is missing.", cite);
    return;
  }
  checkUrl(r, doc, member, cite, opts);
}

function checkUrl(r, doc, member, cite, opts) {
  log.debug("Entering checkUrl().");
  var value = doc[member];
  if (value === undefined || value === null || value === "") return;
  if (!isString(value)) {
    r.error(member, "must be a string containing a URL; this is " + typeName(value) + ".", cite);
    return;
  }
  var u = parsedUrl(value);
  if (!u) {
    r.error(member, 'is not a valid URL: "' + value + '".', cite);
    return;
  }
  if ((opts || {}).https && u.protocol !== "https:") {
    // COLLECTED, not warned about one member at a time. Every local and
    // containerised deployment this tool is used against serves plain http, so
    // per-member warnings meant ten lines on a perfectly good document — which
    // is how a reader learns to skip the warnings and miss the one that matters.
    // One line at the end names them all.
    r.plainHttp.push(member);
  }
  if ((opts || {}).noQueryOrFragment && (u.search || u.hash)) {
    r.error(member, "MUST NOT contain a query string or fragment.", cite);
  }
  log.debug("Leaving checkUrl().");
}

function typeName(v) {
  if (v === null) return "null";
  if (isArray(v)) return "an array";
  if (isObject(v)) return "an object";
  return "a " + typeof v;
}

function checkStringArray(r, doc, member, cite, required) {
  log.debug("Entering checkStringArray().");
  var value = doc[member];
  if (value === undefined) {
    if (required) r.error(member, "is REQUIRED and is missing.", cite);
    return;
  }
  if (!isStringArray(value)) {
    r.error(member, "must be an array of strings; this is " + typeName(value) + ".", cite);
  } else if (required && !value.length) {
    r.error(member, "is REQUIRED and must not be empty.", cite);
  }
  log.debug("Leaving checkStringArray().");
}

function checkBoolean(r, doc, member, cite) {
  if (doc[member] !== undefined && typeof doc[member] !== "boolean") {
    r.error(member, "must be a boolean; this is " + typeName(doc[member]) + ".", cite);
  }
}

// One line for however many members are plain http, added at the end of a
// validation rather than during it. See the note in checkUrl().
function foldPlainHttp(r, cite) {
  if (!r.plainHttp.length) return;
  r.warn(r.plainHttp.length === 1 ? r.plainHttp[0] : r.plainHttp.length + " members",
    (r.plainHttp.length === 1 ? "uses" : "use") + " http:// rather than https:// (" +
    r.plainHttp.join(", ") + "). The specification requires https for a deployed service; this is " +
    "expected for a local or containerised test deployment.", cite);
}

// ---------------------------------------------------------------------------
// OpenID4VCI 1.0 — Credential Issuer Metadata (section 12.2.3).
// ---------------------------------------------------------------------------
var VCI = "OpenID4VCI 1.0 §12.2.3";

// Which member identifies a credential, per format. This is the same
// distinction the issuance workflow itself turns on: an SD-JWT VC is named by
// its vct, a W3C VC by its credential_definition.type. A configuration that
// names neither cannot be requested.
function checkCredentialConfiguration(r, id, cfg) {
  log.debug("Entering checkCredentialConfiguration().");
  var where = 'credential_configurations_supported["' + id + '"]';
  if (!isObject(cfg)) {
    r.error(where, "must be an object; this is " + typeName(cfg) + ".", VCI);
    return;
  }
  if (!isNonEmptyString(cfg.format)) {
    r.error(where + ".format", "is REQUIRED and must be a string naming the credential format.", VCI);
    return;
  }
  var format = cfg.format;
  if (format === "dc+sd-jwt" || format === "vc+sd-jwt") {
    if (!isNonEmptyString(cfg.vct)) {
      r.error(where + ".vct",
        'is REQUIRED for format "' + format + '": an SD-JWT VC is identified by its vct.',
        "OpenID4VCI 1.0 Appendix A.3");
    }
    if (cfg.credential_definition !== undefined) {
      r.warn(where + ".credential_definition",
        'is not used by format "' + format + '" — that member names a W3C credential; an SD-JWT VC ' +
        "uses vct.", "OpenID4VCI 1.0 Appendix A.3");
    }
  } else if (format === "jwt_vc_json" || format === "jwt_vc_json-ld" || format === "ldp_vc") {
    var def = cfg.credential_definition;
    if (!isObject(def)) {
      r.error(where + ".credential_definition",
        'is REQUIRED for format "' + format + '" and must be an object.', "OpenID4VCI 1.0 Appendix A.1");
    } else if (!isStringArray(def.type) || !def.type.length) {
      r.error(where + ".credential_definition.type",
        "is REQUIRED and must be a non-empty array of strings: a W3C credential is identified by its " +
        "type array.", "OpenID4VCI 1.0 Appendix A.1");
    } else if (def.type.indexOf("VerifiableCredential") === -1) {
      r.warn(where + ".credential_definition.type",
        'does not include "VerifiableCredential", which every W3C Verifiable Credential carries.',
        "W3C VCDM");
    }
    if (cfg.vct !== undefined) {
      r.warn(where + ".vct",
        'is not used by format "' + format + '" — that member identifies an SD-JWT VC.',
        "OpenID4VCI 1.0 Appendix A.1");
    }
  } else if (format === "mso_mdoc") {
    if (!isNonEmptyString(cfg.doctype)) {
      r.error(where + ".doctype",
        'is REQUIRED for format "mso_mdoc".', "OpenID4VCI 1.0 Appendix A.2");
    }
  } else {
    r.warn(where + ".format",
      'is "' + format + '", which is not one of the formats this specification defines ' +
      "(dc+sd-jwt, jwt_vc_json, jwt_vc_json-ld, ldp_vc, mso_mdoc). It may be a private extension.", VCI);
  }

  if (cfg.scope !== undefined && !isNonEmptyString(cfg.scope)) {
    r.error(where + ".scope", "must be a string.", VCI);
  }
  if (cfg.cryptographic_binding_methods_supported !== undefined &&
      !isStringArray(cfg.cryptographic_binding_methods_supported)) {
    r.error(where + ".cryptographic_binding_methods_supported", "must be an array of strings.", VCI);
  }
  if (cfg.credential_signing_alg_values_supported !== undefined &&
      !isStringArray(cfg.credential_signing_alg_values_supported)) {
    r.error(where + ".credential_signing_alg_values_supported", "must be an array of strings.", VCI);
  }
  if (cfg.proof_types_supported !== undefined) {
    if (!isObject(cfg.proof_types_supported)) {
      r.error(where + ".proof_types_supported", "must be an object keyed by proof type.", VCI);
    } else {
      Object.keys(cfg.proof_types_supported).forEach(function (proofType) {
        var entry = cfg.proof_types_supported[proofType];
        if (!isObject(entry) || !isStringArray(entry.proof_signing_alg_values_supported) ||
            !entry.proof_signing_alg_values_supported.length) {
          r.error(where + ".proof_types_supported." + proofType + ".proof_signing_alg_values_supported",
            "is REQUIRED and must be a non-empty array of strings.", VCI);
        }
      });
    }
  }
  if (cfg.claims !== undefined && !isArray(cfg.claims)) {
    r.error(where + ".claims",
      "must be an array of claim objects, each with a path. (Earlier drafts used an object here.)", VCI);
  }
  log.debug("Leaving checkCredentialConfiguration().");
}

function validateVciMetadata(doc) {
  log.debug("Entering validateVciMetadata().");
  var r = report();
  if (!isObject(doc)) {
    r.error("(document)", "must be a JSON object; this is " + typeName(doc) + ".", VCI);
    log.debug("Leaving validateVciMetadata(). Not an object.");
    return r;
  }

  requireUrl(r, doc, "credential_issuer", VCI, { https: true });
  requireUrl(r, doc, "credential_endpoint", VCI, { https: true });

  var configs = doc.credential_configurations_supported;
  if (configs === undefined) {
    r.error("credential_configurations_supported",
      "is REQUIRED: without it the issuer advertises no credential a wallet could ask for.", VCI);
  } else if (!isObject(configs)) {
    r.error("credential_configurations_supported",
      "must be an object keyed by credential_configuration_id; this is " + typeName(configs) + ".", VCI);
  } else if (!Object.keys(configs).length) {
    r.error("credential_configurations_supported", "is present but empty.", VCI);
  } else {
    Object.keys(configs).forEach(function (id) {
      checkCredentialConfiguration(r, id, configs[id]);
    });
  }

  // Optional members, checked for type when present.
  checkUrl(r, doc, "nonce_endpoint", VCI, { https: true });
  checkUrl(r, doc, "deferred_credential_endpoint", VCI, { https: true });
  checkUrl(r, doc, "notification_endpoint", VCI, { https: true });

  if (doc.authorization_servers !== undefined) {
    if (!isStringArray(doc.authorization_servers)) {
      r.error("authorization_servers", "must be an array of strings.", VCI);
    } else {
      doc.authorization_servers.forEach(function (v, i) {
        if (!parsedUrl(v)) r.error("authorization_servers[" + i + "]", 'is not a valid URL: "' + v + '".', VCI);
      });
    }
  }
  if (doc.batch_credential_issuance !== undefined) {
    var batch = doc.batch_credential_issuance;
    if (!isObject(batch)) {
      r.error("batch_credential_issuance", "must be an object.", VCI);
    } else if (typeof batch.batch_size !== "number" || batch.batch_size < 1 ||
               batch.batch_size !== Math.floor(batch.batch_size)) {
      r.error("batch_credential_issuance.batch_size",
        "is REQUIRED and must be a positive integer.", VCI);
    }
  }
  if (doc.credential_response_encryption !== undefined) {
    var enc = doc.credential_response_encryption;
    if (!isObject(enc)) {
      r.error("credential_response_encryption", "must be an object.", VCI);
    } else {
      checkStringArray(r, enc, "alg_values_supported", VCI + " (credential_response_encryption)", true);
      checkStringArray(r, enc, "enc_values_supported", VCI + " (credential_response_encryption)", true);
      if (typeof enc.encryption_required !== "boolean") {
        r.error("credential_response_encryption.encryption_required",
          "is REQUIRED and must be a boolean.", VCI);
      }
    }
  }
  // The request side (section 10). Deliberately NOT a copy of the block above:
  // requests have no alg_values_supported — the JWE alg must equal the alg of
  // the JWK the wallet chose — and they carry a jwks whose every key MUST have a
  // kid. Checking it against the response side's rules would pass a document
  // that no wallet can use.
  if (doc.credential_request_encryption !== undefined) {
    var req = doc.credential_request_encryption;
    if (!isObject(req)) {
      r.error("credential_request_encryption", "must be an object.", VCI);
    } else {
      var label = VCI + " (credential_request_encryption)";
      if (!isObject(req.jwks) || !isArray(req.jwks.keys) || !req.jwks.keys.length) {
        r.error("credential_request_encryption.jwks",
          "is REQUIRED and must be a JWK Set with at least one key for the wallet to encrypt to.",
          label);
      } else {
        req.jwks.keys.forEach(function (k, i) {
          if (!isObject(k)) {
            r.error("credential_request_encryption.jwks.keys[" + i + "]", "must be an object.", label);
            return;
          }
          if (typeof k.kid !== "string" || !k.kid) {
            r.error("credential_request_encryption.jwks.keys[" + i + "].kid",
              "is REQUIRED: \"Each JWK in the set MUST have a kid (Key ID) parameter that uniquely " +
              "identifies the key\", and the wallet has to echo it in the JWE header.", label);
          }
          if (typeof k.alg !== "string" || !k.alg) {
            r.error("credential_request_encryption.jwks.keys[" + i + "].alg",
              "is REQUIRED for request encryption: \"The alg parameter MUST be present. The JWE alg " +
              "algorithm used MUST be equal to the alg value of the chosen JWK.\" Without it the " +
              "wallet has no algorithm to use, since requests have no alg_values_supported.", label);
          }
        });
        var kids = req.jwks.keys.map(function (k) { return isObject(k) ? k.kid : null; })
          .filter(function (k) { return typeof k === "string" && k; });
        if (kids.length !== new Set(kids).size) {
          r.error("credential_request_encryption.jwks",
            "has duplicate kid values; each kid must UNIQUELY identify a key, or the issuer cannot " +
            "tell which one a request was encrypted to.", label);
        }
      }
      checkStringArray(r, req, "enc_values_supported", label, true);
      if (req.zip_values_supported !== undefined) {
        checkStringArray(r, req, "zip_values_supported", label, false);
      }
      if (typeof req.encryption_required !== "boolean") {
        r.error("credential_request_encryption.encryption_required",
          "is REQUIRED and must be a boolean.", label);
      }
      if (req.alg_values_supported !== undefined) {
        r.warn("credential_request_encryption.alg_values_supported",
          "is not defined for request encryption — that member belongs to credential_response_" +
          "encryption. The request algorithm comes from the alg of the chosen JWK.", label);
      }
    }
  }
  if (doc.display !== undefined && !isArray(doc.display)) {
    r.error("display", "must be an array of display objects.", VCI);
  }
  if (doc.signed_metadata !== undefined && !isCompactJws(doc.signed_metadata)) {
    r.error("signed_metadata", "must be a JWT in compact serialization (three dot-separated parts).", VCI);
  }

  foldPlainHttp(r, VCI);
  log.debug("Leaving validateVciMetadata(). " + r.errors.length + " error(s), " +
            r.warnings.length + " warning(s).");
  return r;
}

function isCompactJws(v) {
  return isString(v) && v.split(".").length === 3 && v.split(".").every(function (p) { return p !== ""; });
}

// ---------------------------------------------------------------------------
// RFC 8414 — OAuth 2.0 Authorization Server Metadata (section 2).
// ---------------------------------------------------------------------------
var AS = "RFC 8414 §2";

function validateAsMetadata(doc) {
  log.debug("Entering validateAsMetadata().");
  var r = report();
  if (!isObject(doc)) {
    r.error("(document)", "must be a JSON object; this is " + typeName(doc) + ".", AS);
    log.debug("Leaving validateAsMetadata(). Not an object.");
    return r;
  }

  // issuer has rules of its own: https, and no query or fragment, because it is
  // compared byte for byte against the iss of a token.
  requireUrl(r, doc, "issuer", AS, { https: true, noQueryOrFragment: true });
  checkStringArray(r, doc, "response_types_supported", AS, true);

  // "REQUIRED unless no grant type uses it" — so a document without them is
  // legal but unusual, and a warning says so without calling it invalid.
  if (doc.authorization_endpoint === undefined) {
    r.warn("authorization_endpoint",
      "is absent. RFC 8414 requires it unless no supported grant type uses the authorization endpoint.", AS);
  } else {
    checkUrl(r, doc, "authorization_endpoint", AS, { https: true });
  }
  if (doc.token_endpoint === undefined) {
    r.warn("token_endpoint",
      "is absent. RFC 8414 requires it unless only the implicit grant is supported.", AS);
  } else {
    checkUrl(r, doc, "token_endpoint", AS, { https: true });
  }
  if (doc.jwks_uri === undefined) {
    r.warn("jwks_uri",
      "is absent. It is RECOMMENDED, and without it a client cannot verify a signed token or " +
      "signed_metadata.", AS);
  } else {
    checkUrl(r, doc, "jwks_uri", AS, { https: true });
  }
  if (doc.scopes_supported === undefined) {
    r.warn("scopes_supported", "is absent. It is RECOMMENDED.", AS);
  } else {
    checkStringArray(r, doc, "scopes_supported", AS, false);
  }

  ["registration_endpoint", "revocation_endpoint", "introspection_endpoint",
   "device_authorization_endpoint", "userinfo_endpoint", "service_documentation",
   "op_policy_uri", "op_tos_uri"].forEach(function (member) {
    checkUrl(r, doc, member, AS, { https: true });
  });

  ["grant_types_supported", "response_modes_supported", "token_endpoint_auth_methods_supported",
   "token_endpoint_auth_signing_alg_values_supported", "revocation_endpoint_auth_methods_supported",
   "revocation_endpoint_auth_signing_alg_values_supported", "introspection_endpoint_auth_methods_supported",
   "introspection_endpoint_auth_signing_alg_values_supported", "code_challenge_methods_supported",
   "ui_locales_supported", "claims_supported", "id_token_signing_alg_values_supported",
   "subject_types_supported"].forEach(function (member) {
    checkStringArray(r, doc, member, AS, false);
  });

  checkBoolean(r, doc, "require_request_uri_registration", AS);
  checkBoolean(r, doc, "require_pushed_authorization_requests", AS);

  if (doc.signed_metadata !== undefined && !isCompactJws(doc.signed_metadata)) {
    r.error("signed_metadata",
      "must be a JWT in compact serialization (three dot-separated parts).", AS);
  }
  // A cross-member rule worth stating: token_endpoint_auth_signing_alg_values_supported
  // MUST NOT include "none" (RFC 8414 §2).
  if (isStringArray(doc.token_endpoint_auth_signing_alg_values_supported) &&
      doc.token_endpoint_auth_signing_alg_values_supported.indexOf("none") !== -1) {
    r.error("token_endpoint_auth_signing_alg_values_supported",
      'MUST NOT include "none".', AS);
  }

  foldPlainHttp(r, AS);
  log.debug("Leaving validateAsMetadata(). " + r.errors.length + " error(s), " +
            r.warnings.length + " warning(s).");
  return r;
}

// A one-line summary plus the detail, for a status line.
function summarize(result, label) {
  var e = result.errors.length;
  var w = result.warnings.length;
  if (!e && !w) return label + " matches " + (result.spec || "its specification") + ".";
  var parts = [];
  if (e) parts.push(e + " error" + (e === 1 ? "" : "s"));
  if (w) parts.push(w + " warning" + (w === 1 ? "" : "s"));
  return label + ": " + parts.join(", ") + ".";
}

// ---------------------------------------------------------------------------
// DIF Well Known DID Configuration — /.well-known/did-configuration.json
//
// The rules below are transcribed from that specification, not guessed, and the
// citations are per rule so a reader can check them. Two of its habits make a
// document that LOOKS right fail somebody else's verifier, and they are the reason
// this is worth checking at all:
//
//   * the resource permits NO members beyond @context and linked_dids, and each
//     credential permits none beyond what is listed. A spec that says "no
//     additional members" means a well-meaning extra field is a defect.
//   * in the JWT form the header MUST NOT carry `typ` and the payload permits
//     nothing beyond iss/sub/nbf/exp/vc — and both are things a JWT library adds
//     for you unless told otherwise. This is the single most likely way to publish
//     a document that reads correctly and is refused.
//
// What is NOT checked here, because it is not a schema question: whether the
// signature verifies, whether the DID resolves, and whether the origin matches the
// one the document was served from. did.js's verifyDomainLinkage() does all three,
// and the pane runs it alongside this.
// ---------------------------------------------------------------------------
var DIDCFG = "DIF Well Known DID Configuration";
var DIDCFG_CONTEXT = "https://identity.foundation/.well-known/did-configuration/v1";
var VC_V1_CONTEXT = "https://www.w3.org/2018/credentials/v1";
var DIDCFG_RESOURCE_MEMBERS = ["@context", "linked_dids"];
var DIDCFG_JWT_HEADER_MEMBERS = ["alg", "kid"];
var DIDCFG_JWT_CLAIM_MEMBERS = ["iss", "sub", "nbf", "exp", "vc"];
var DIDCFG_LD_MEMBERS = ["@context", "issuer", "issuanceDate", "expirationDate", "type",
                         "credentialSubject", "proof"];

function isDidString(v) { return isNonEmptyString(v) && /^did:[a-z0-9]+:/.test(v); }

// One entry of linked_dids, in whichever of the two forms it takes. `label` names it
// for the report, since a resource may carry several.
function checkLinkedDid(r, entry, label) {
  var where = DIDCFG + " §Domain Linkage Credential";
  // A string is the JWT form; an object is the Linked Data Proof form. Anything else
  // is neither.
  if (isString(entry)) {
    var parts = entry.split(".");
    if (parts.length !== 3) {
      r.error(label, "a JWT-form entry must be a three-part JWS; this has " + parts.length +
              " dot-separated part(s).", where);
      return;
    }
    var header, claims;
    try {
      header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
      claims = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    } catch (e) {
      r.error(label, "the JWT's header or payload is not base64url JSON: " + e.message, where);
      return;
    }
    if (!isNonEmptyString(header.alg)) r.error(label + ".alg", "REQUIRED in the JWT header.", where);
    if (!isNonEmptyString(header.kid)) {
      r.error(label + ".kid", "REQUIRED in the JWT header: it names the verification method.", where);
    }
    if (Object.prototype.hasOwnProperty.call(header, "typ")) {
      r.error(label + ".typ", "MUST NOT be present in the JWT header. Most JWT libraries add " +
              'typ:"JWT" unless told not to, so this is the usual way a correct-looking document is ' +
              "refused.", where);
    }
    var extraHeader = Object.keys(header).filter(function (k) {
      return DIDCFG_JWT_HEADER_MEMBERS.indexOf(k) === -1;
    });
    if (extraHeader.length) {
      r.error(label + " header", "no members beyond alg and kid are permitted; this carries " +
              extraHeader.join(", ") + ".", where);
    }
    var extraClaims = Object.keys(claims).filter(function (k) {
      return DIDCFG_JWT_CLAIM_MEMBERS.indexOf(k) === -1;
    });
    if (extraClaims.length) {
      r.error(label + " claims", "no members beyond iss, sub, nbf, exp and vc are permitted; this " +
              "carries " + extraClaims.join(", ") + ". iat is the usual culprit — most libraries add " +
              "it unless told noTimestamp.", where);
    }
    if (!isDidString(claims.iss)) r.error(label + ".iss", "REQUIRED, and MUST be a DID.", where);
    if (claims.sub !== claims.iss) {
      r.error(label + ".sub", "MUST equal iss: a Domain Linkage Credential is self-issued, because " +
              "nobody but the DID's controller can say which origin it controls.", where);
    }
    if (!isObject(claims.vc)) {
      r.error(label + ".vc", "REQUIRED: the credential, in the Linked Data form minus its proof.", where);
      return;
    }
    checkLinkageCredential(r, claims.vc, label + ".vc", claims.iss, true);
    return;
  }
  if (isObject(entry)) {
    checkLinkageCredential(r, entry, label, entry.issuer, false);
    if (!isObject(entry.proof)) {
      r.error(label + ".proof", "REQUIRED in the Linked Data Proof form.", where);
    }
    return;
  }
  r.error(label, "each linked_dids entry is either a JWT string or a credential object; this is " +
          typeName(entry) + ".", where);
}

// The credential itself, shared by both forms — in the JWT form it is the `vc` claim
// with no proof, which is why `embedded` decides whether a proof is expected.
function checkLinkageCredential(r, vc, label, issuer, embedded) {
  var where = DIDCFG + " §Domain Linkage Credential";
  var contexts = isArray(vc["@context"]) ? vc["@context"] : [];
  if (contexts.indexOf(VC_V1_CONTEXT) === -1 || contexts.indexOf(DIDCFG_CONTEXT) === -1) {
    r.error(label + ".@context", "MUST contain both " + VC_V1_CONTEXT + " and " + DIDCFG_CONTEXT + ".",
            where);
  }
  var types = isArray(vc.type) ? vc.type : (isString(vc.type) ? [vc.type] : []);
  if (types.indexOf("VerifiableCredential") === -1 || types.indexOf("DomainLinkageCredential") === -1) {
    r.error(label + ".type", "MUST contain VerifiableCredential and DomainLinkageCredential.", where);
  }
  if (Object.prototype.hasOwnProperty.call(vc, "id")) {
    r.error(label + ".id", "MUST NOT be present at the credential root. This credential is not an " +
            "addressable thing to be fetched or revoked; it is an assertion about one pair.", where);
  }
  if (!isDidString(vc.issuer)) r.error(label + ".issuer", "REQUIRED, and MUST be a DID.", where);
  if (!isNonEmptyString(vc.issuanceDate)) r.error(label + ".issuanceDate", "REQUIRED.", where);
  if (!isNonEmptyString(vc.expirationDate)) {
    r.warn(label + ".expirationDate", "REQUIRED by the specification. A credential with no expiry " +
           "asks a verifier to trust the linkage indefinitely.", where);
  }
  var subject = isObject(vc.credentialSubject) ? vc.credentialSubject : null;
  if (!subject) {
    r.error(label + ".credentialSubject", "REQUIRED.", where);
    return;
  }
  if (!isDidString(subject.id)) {
    r.error(label + ".credentialSubject.id", "REQUIRED, and MUST be the DID this credential links.",
            where);
  } else if (issuer && subject.id !== issuer) {
    r.error(label + ".credentialSubject.id", "MUST equal the issuer (" + issuer + "): the subject and " +
            "the issuer of a Domain Linkage Credential are the same DID.", where);
  }
  if (!isNonEmptyString(subject.origin)) {
    r.error(label + ".credentialSubject.origin", "REQUIRED: the origin this DID claims.", where);
  } else {
    var parsed = parsedUrl(subject.origin);
    if (!parsed) {
      r.error(label + ".credentialSubject.origin", "MUST be an origin (scheme, host and optional " +
              'port); "' + subject.origin + '" does not parse as one.', where);
    } else {
      foldPlainHttp(r, where);
      if (parsed.pathname && parsed.pathname !== "/") {
        r.warn(label + ".credentialSubject.origin", "an ORIGIN is scheme, host and port — this carries " +
               "the path " + parsed.pathname + ", which a verifier comparing origins will not match.",
               where);
      }
    }
  }
  if (embedded && Object.prototype.hasOwnProperty.call(vc, "proof")) {
    r.error(label + ".proof", "MUST NOT be present inside the JWT's vc claim: the JWS IS the proof.",
            where);
  }
}

function validateDidConfiguration(doc) {
  log.debug("Entering validateDidConfiguration().");
  var r = report();
  if (!isObject(doc)) {
    r.error("(document)", "the resource MUST be a JSON object.", DIDCFG);
    log.debug("Leaving validateDidConfiguration(). Not an object.");
    return r;
  }
  if (doc["@context"] !== DIDCFG_CONTEXT) {
    r.error("@context", 'REQUIRED, and MUST be exactly "' + DIDCFG_CONTEXT + '"; this says ' +
            JSON.stringify(doc["@context"]) + ".", DIDCFG + " §DID Configuration Resource");
  }
  if (!isArray(doc.linked_dids)) {
    r.error("linked_dids", "REQUIRED, and MUST be an array of Domain Linkage Credentials.",
            DIDCFG + " §DID Configuration Resource");
  } else if (!doc.linked_dids.length) {
    r.warn("linked_dids", "present but empty, so this origin vouches for no DID at all.",
           DIDCFG + " §DID Configuration Resource");
  } else {
    doc.linked_dids.forEach(function (entry, i) {
      checkLinkedDid(r, entry, "linked_dids[" + i + "]");
    });
  }
  var extra = Object.keys(doc).filter(function (k) {
    return DIDCFG_RESOURCE_MEMBERS.indexOf(k) === -1;
  });
  if (extra.length) {
    r.error("(document)", "no members beyond @context and linked_dids are permitted; this carries " +
            extra.join(", ") + ".", DIDCFG + " §DID Configuration Resource");
  }
  log.debug("Leaving validateDidConfiguration(). " + r.errors.length + " error(s), " +
            r.warnings.length + " warning(s).");
  return r;
}

module.exports = {
  validateVciMetadata: validateVciMetadata,
  validateAsMetadata: validateAsMetadata,
  validateDidConfiguration: validateDidConfiguration,
  summarize: summarize,
  VCI_SPEC: VCI,
  AS_SPEC: AS,
  DIDCFG_SPEC: DIDCFG,
  DIDCFG_CONTEXT: DIDCFG_CONTEXT
};
