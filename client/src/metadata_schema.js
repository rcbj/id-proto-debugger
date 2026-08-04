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

module.exports = {
  validateVciMetadata: validateVciMetadata,
  validateAsMetadata: validateAsMetadata,
  summarize: summarize,
  VCI_SPEC: VCI,
  AS_SPEC: AS
};
