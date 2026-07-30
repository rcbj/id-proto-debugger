// File: metadata_client.js
//
// ---------------------------------------------------------------------------
// The parts of a "retrieve a metadata document and show it" pane that do not
// depend on WHICH document is being retrieved.
//
// Three panes in this app do the same thing to three different JSON documents:
//
//   debugger.html               OIDC Discovery 1.0 / RFC 8414 (authorization server)
//   sd-jwt-vc-issuance-1.html   OID4VCI credential issuer metadata, and a second
//                               copy of the RFC 8414 pane
//
// They fetch a URL, tabulate what came back (saying which kind of document it is
// and where it came from), keep it in local storage so the table survives a
// reload, and verify the document's signed_metadata JWT against its own JWKS.
// None of that cares about the member names, so it lives here and each pane
// supplies its own element ids, storage keys and labels.
//
// What stays with the pane: which fields the document populates. That IS
// document-specific — see op_metadata.js (OpenID Provider metadata) and
// vci_metadata.js (credential issuer metadata).
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "metadata_client",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// --- escaping ---------------------------------------------------------------
// Every table below is built by string concatenation from a document fetched
// off the network, so nothing reaches the markup unescaped.

function escapeHtmlText(v) {
  if (v === null || v === undefined) return "";
  var s = (typeof v === "object") ? JSON.stringify(v) : String(v);
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// Displaying a metadata value.
//
// Most members are a string or an array of strings. Some are JSON structures —
// OID4VCI's credential_configurations_supported, display,
// credential_response_encryption and batch_credential_issuance, or an
// authorization server's mtls_endpoint_aliases — and those are unreadable on one
// line, so they are pretty-printed wherever they are shown.
//
// A flat array of scalars stays on one line: pretty-printing scopes_supported
// one entry per line makes a table twice as tall for nothing.
// ---------------------------------------------------------------------------
function isJsonStructure(value) {
  if (value === null || typeof value !== "object") return false;
  if (Object.prototype.toString.call(value) === "[object Array]") {
    // An array counts as structured only if it contains structures.
    return value.some(function (v) { return v !== null && typeof v === "object"; });
  }
  return true;
}

function prettyJson(value) { return JSON.stringify(value, null, 2); }

// The string form of a value, for a form field or a table cell.
function valueToDisplay(value) {
  if (value === undefined || value === null) return "";
  if (isJsonStructure(value)) return prettyJson(value);
  if (Object.prototype.toString.call(value) === "[object Array]") return value.join(", ");
  if (typeof value === "boolean") return value ? "true" : "false";
  return String(value);
}

// Is this string a pretty-printed JSON structure? Needed when a value comes back
// out of local storage, where it is only ever a string.
function looksLikeJsonStructure(text) {
  var t = String(text == null ? "" : text).trim();
  if (!(t.charAt(0) === "{" || t.charAt(0) === "[")) return false;
  try {
    return isJsonStructure(JSON.parse(t));
  } catch (e) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Writing a metadata value into a Configuration Parameters pane.
//
// A one-line <input> cannot show pretty-printed JSON, so a field whose value is
// a JSON structure is swapped for a <textarea> — and swapped back when it holds
// a scalar again. The id, name, classes and placeholder travel with it, so
// everything that addresses the field by id (including the tests) is unaffected.
// A <select> — the boolean members — is never swapped.
// ---------------------------------------------------------------------------
function setMetadataField(id, text) {
  log.debug("Entering setMetadataField().");
  var e = document.getElementById(id);
  if (!e) return null;
  var value = (text == null) ? "" : String(text);
  var wantsTextarea = looksLikeJsonStructure(value);
  if (e.tagName !== "SELECT" && wantsTextarea !== (e.tagName === "TEXTAREA")) {
    var replacement = document.createElement(wantsTextarea ? "textarea" : "input");
    if (!wantsTextarea) replacement.type = "text";
    replacement.id = e.id;
    replacement.name = e.name;
    replacement.className = e.className;
    if (e.placeholder) replacement.placeholder = e.placeholder;
    if (wantsTextarea) {
      replacement.classList.add("metadata-json-field");
      replacement.setAttribute("spellcheck", "false");
    } else {
      replacement.classList.remove("metadata-json-field");
    }
    e.parentNode.replaceChild(replacement, e);
    e = replacement;
  }
  // Tall enough for the value, within reason.
  if (e.tagName === "TEXTAREA") {
    e.rows = Math.min(24, Math.max(3, value.split("\n").length));
  }
  e.value = value;
  log.debug("Leaving setMetadataField().");
  return e;
}

// --- base64url --------------------------------------------------------------
function b64uToBytes(str) {
  var s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) { s += "="; }
  var bin = atob(s);
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
  return out;
}
function b64uToJson(str) { return JSON.parse(new TextDecoder().decode(b64uToBytes(str))); }
function bytesToB64u(bytes) {
  var bin = "";
  var arr = new Uint8Array(bytes);
  for (var i = 0; i < arr.length; i++) { bin += String.fromCharCode(arr[i]); }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function utf8ToB64u(s) {
  return bytesToB64u(new TextEncoder().encode(s));
}

// --- JWS verification (Web Crypto) ------------------------------------------
// JWS alg -> the Web Crypto import/verify parameters.
function jwsAlgParams(alg) {
  log.debug("Entering jwsAlgParams().");
  var rsa = { RS256: "SHA-256", RS384: "SHA-384", RS512: "SHA-512" };
  var pss = { PS256: "SHA-256", PS384: "SHA-384", PS512: "SHA-512" };
  var ec = { ES256: ["P-256", "SHA-256"], ES384: ["P-384", "SHA-384"], ES512: ["P-521", "SHA-512"] };
  if (rsa[alg]) {
    return { imp: { name: "RSASSA-PKCS1-v1_5", hash: { name: rsa[alg] } }, ver: { name: "RSASSA-PKCS1-v1_5" } };
  }
  if (pss[alg]) {
    return { imp: { name: "RSA-PSS", hash: { name: pss[alg] } },
             ver: { name: "RSA-PSS", saltLength: parseInt(alg.substring(2), 10) / 8 } };
  }
  if (ec[alg]) {
    return { imp: { name: "ECDSA", namedCurve: ec[alg][0] }, ver: { name: "ECDSA", hash: { name: ec[alg][1] } } };
  }
  log.debug("Leaving jwsAlgParams().");
  return null;
}

// Only the members Web Crypto needs — a stray alg/use/key_ops in the JWK makes
// importKey throw.
function jwkForImport(jwk) {
  if (jwk.kty === "RSA") return { kty: "RSA", n: jwk.n, e: jwk.e };
  if (jwk.kty === "EC") return { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y };
  return null;
}

// Which published keys are worth trying for a JWT that names `kid`.
//
// An exact match is the normal case. Two others are not: an issuer that
// identifies its keys with DID URLs (walt.id does — `did:jwk:…#<thumbprint>`)
// names in the JWT a kid that no JWKS entry carries verbatim, though the
// fragment IS the JWKS kid; and an issuer can simply publish a key under a
// different name than it signs with. A kid is a hint for finding the key, not
// part of the signature, so a JWT that verifies under a key the issuer
// published is verified — the kid never made it more or less so. Trying the
// named key first keeps the reported key honest when several are published.
function candidateKeys(keys, kid) {
  log.debug("Entering candidateKeys(). kid=" + kid);
  if (!kid) {
    log.debug("Leaving candidateKeys(). The JWT names no kid, so every key is a candidate.");
    return keys;
  }
  var exact = keys.filter(function (k) { return k.kid === kid; });
  if (exact.length) {
    log.debug("Leaving candidateKeys(). Exact kid match.");
    return exact;
  }
  // A DID URL's fragment is the key's id within the DID document.
  var fragment = kid.indexOf("#") !== -1 ? kid.slice(kid.indexOf("#") + 1) : "";
  var byFragment = fragment ? keys.filter(function (k) { return k.kid === fragment; }) : [];
  if (byFragment.length) {
    log.debug("Leaving candidateKeys(). Matched the DID URL fragment " + fragment + ".");
    return byFragment;
  }
  log.debug("Leaving candidateKeys(). No kid matched; every published key is a candidate.");
  return keys;
}

// Try every candidate key: the one named by kid, or all of them when the JWT
// does not name one (common for a single-key authorization server). `label`
// names the token in any error, since the same code verifies signed_metadata,
// an SD-JWT VC, and a proof JWT.
async function verifyJwsWithJwks(token, jwks, label) {
  log.debug("Entering verifyJwsWithJwks().");
  label = label || "the JWT";
  var parts = String(token).split(".");
  if (parts.length !== 3) throw new Error(label + " is not a three-part JWS.");
  var header = b64uToJson(parts[0]);
  if (!header.alg || header.alg === "none") throw new Error('unsigned JWT (alg "' + header.alg + '").');
  var params = jwsAlgParams(header.alg);
  if (!params) throw new Error("unsupported JWS algorithm: " + header.alg);

  var keys = (jwks && jwks.keys) || [];
  if (!keys.length) throw new Error("the JWKS carries no keys.");
  var candidates = candidateKeys(keys, header.kid);
  if (!candidates.length) throw new Error('no key in the JWKS matches kid "' + header.kid + '".');

  var data = new TextEncoder().encode(parts[0] + "." + parts[1]);
  var sig = b64uToBytes(parts[2]);
  for (var i = 0; i < candidates.length; i++) {
    var material = jwkForImport(candidates[i]);
    if (!material) continue;
    try {
      var key = await crypto.subtle.importKey("jwk", material, params.imp, false, ["verify"]);
      if (await crypto.subtle.verify(params.ver, key, sig, data)) {
        return { valid: true, header: header, kid: candidates[i].kid || "(no kid)" };
      }
    } catch (e) {
      // wrong key for this alg — try the next one
    }
  }
  log.debug("Leaving verifyJwsWithJwks().");
  return { valid: false, header: header, kid: header.kid || "(no kid)" };
}

// ---------------------------------------------------------------------------
// signed_metadata.
//
// RFC 8414 section 2.1 (and OID4VCI, which adopts the same member) lets an
// issuer publish a JWT of its own metadata. Verifying it is the same work in
// both places: fetch the document's JWKS, check the signature, check that iss
// is the issuer, and report any signed claim that disagrees with the plain JSON
// — the signed value takes precedence, so a disagreement means the JSON cannot
// be trusted.
//
//   doc          the metadata document
//   issuerMember which member holds the issuer identifier ("issuer" for
//                RFC 8414, "credential_issuer" for OID4VCI)
//   jwksUri      where to fetch the keys (defaults to doc.jwks_uri)
//
// Returns a promise for the verdict text; the caller decides where to show it.
// ---------------------------------------------------------------------------
var SIGNED_METADATA_SKIP = ["iss", "sub", "iat", "exp", "nbf", "aud", "jti"];

function validateSignedMetadata(doc, options) {
  log.debug("Entering validateSignedMetadata().");
  options = options || {};
  var issuerMember = options.issuerMember || "issuer";
  var jwksUri = options.jwksUri || (doc && doc.jwks_uri);
  var progress = options.progress || function () {};

  if (!doc || !Object.keys(doc).length) {
    return Promise.resolve("Retrieve a metadata document first.");
  }
  if (!doc.signed_metadata) {
    return Promise.resolve("This document has no signed_metadata member — nothing to validate. " +
      (options.noSignedMetadataNote || ""));
  }
  if (!jwksUri) {
    return Promise.resolve("INVALID: the document has signed_metadata but no jwks_uri to verify it against.");
  }

  progress("Fetching " + jwksUri + " …");
  log.debug("Leaving validateSignedMetadata(). jwksUri=" + jwksUri);
  var jwks = null;
  return fetch(jwksUri)
    .then(function (r) {
      if (!r.ok) { throw new Error("jwks_uri returned HTTP " + r.status); }
      return r.json();
    })
    .then(function (fetched) {
      jwks = fetched;
      return verifyJwsWithJwks(doc.signed_metadata, jwks, "signed_metadata");
    })
    .then(function (res) {
      var claims;
      try {
        claims = b64uToJson(String(doc.signed_metadata).split(".")[1]);
      } catch (e) {
        claims = {};
      }
      var lines = [];
      // Name the URL the keys came from. Without it a failure cannot be told apart
      // from the same failure against somebody else's JWKS — which is exactly the
      // ambiguity that made an OID4VCI verdict unreadable: the keys are resolved
      // indirectly there (through /.well-known/jwt-vc-issuer), so "no key from
      // jwks_uri verified it" begs the question of which jwks_uri was used.
      lines.push(res.valid
        ? "VALID — signature verified (alg " + res.header.alg + ", kid " + res.kid +
          ") against the keys at " + jwksUri + "."
        : "INVALID — the signature does not verify with any key from " + jwksUri +
          " (alg " + res.header.alg + ", kid " + res.kid + ", " +
          ((jwks && jwks.keys && jwks.keys.length) || 0) + " key(s) published, kid(s): " +
          (((jwks && jwks.keys) || []).map(function (k) { return k.kid || "(none)"; }).join(", ") || "—") +
          ").");
      if (claims.iss !== doc[issuerMember]) {
        lines.push('MISMATCH: the iss claim ("' + claims.iss + '") is not the issuer ("' +
                   doc[issuerMember] + '").');
      } else {
        lines.push("iss matches the issuer.");
      }
      var differing = Object.keys(claims).filter(function (k) {
        if (SIGNED_METADATA_SKIP.indexOf(k) >= 0) return false;
        return JSON.stringify(claims[k]) !== JSON.stringify(doc[k]);
      });
      lines.push(differing.length
        ? "Signed claims that differ from the JSON (the signed value takes precedence): " + differing.join(", ")
        : "Every signed claim matches the JSON document.");
      if (claims.exp && (claims.exp * 1000) < Date.now()) lines.push("NOTE: the JWT is expired (exp).");
      return lines.join(" ");
    })
    .catch(function (e) {
      return "Could not validate: " + e.message;
    });
}

// ---------------------------------------------------------------------------
// The document table.
//
// A two-column Attribute/Value table of the document, headed by a note saying
// what kind of document it is and where it came from — the pane can retrieve
// more than one kind, and the table survives a reload, by which point the form
// fields may say something else entirely.
//
//   provenance  { docLabel, url } describing THIS document, or null
// ---------------------------------------------------------------------------
function buildInfoTable(info, provenance) {
  log.debug("Entering buildInfoTable().");
  var note = "";
  if (provenance && (provenance.url || provenance.docLabel)) {
    note = "<p class='discovery-info-note'>Showing <strong>" +
           escapeHtmlText(provenance.docLabel || "metadata") + "</strong>" +
           (provenance.url ? " retrieved from <code>" + escapeHtmlText(provenance.url) + "</code>" : "") +
           ".</p>";
  }
  var html = note + "<table border='2' style='border:2px;'>" +
             "<tr><td><strong>Attribute</strong></td><td><strong>Value</strong></td></tr>";
  Object.keys(info || {}).forEach(function (key) {
    var value = (info || {})[key];
    // A JSON structure keeps its formatting; anything else is one line as before.
    var cell = isJsonStructure(value)
      ? "<pre class='metadata-json'>" + escapeHtmlText(prettyJson(value)) + "</pre>"
      : escapeHtmlText(value);
    html += "<tr><td>" + escapeHtmlText(key) + "</td><td>" + cell + "</td></tr>";
  });
  log.debug("Leaving buildInfoTable().");
  return html + "</table>";
}

// ---------------------------------------------------------------------------
// Storing a retrieved document.
//
// The DOCUMENT is stored, not the table markup: the table is rebuilt from it on
// load, which also restores the in-memory copy the "Populate" button reads. Its
// provenance goes in a separate key so the document's own shape stays exactly
// as it arrived.
// ---------------------------------------------------------------------------
function createStore(infoKey, sourceKey) {
  log.debug("Entering createStore().");
  log.debug("Leaving createStore().");
  return {
    infoKey: infoKey,
    sourceKey: sourceKey,
    save: function (info, provenance) {
      try {
        localStorage.setItem(infoKey, JSON.stringify(info));
        localStorage.setItem(sourceKey, JSON.stringify(provenance || null));
      } catch (e) {
        // No storage, or over quota: the document is still on screen, it just
        // will not survive a reload.
      }
    },
    read: function () {
      try {
        var saved = localStorage.getItem(infoKey);
        if (!saved) return null;
        var info = JSON.parse(saved);
        return (info && typeof info === "object") ? info : null;
      } catch (e) {
        return null;
      }
    },
    readProvenance: function () {
      try {
        return JSON.parse(localStorage.getItem(sourceKey) || "null");
      } catch (e) {
        return null;
      }
    },
    forget: function () {
      try {
        localStorage.removeItem(infoKey);
        localStorage.removeItem(sourceKey);
      } catch (e) {
        // No storage: there was nothing stored to forget.
      }
    }
  };
}

// A plain GET of a JSON document, with the failure reported the same way
// everywhere. Used by the panes that do not go through jQuery.
function fetchJson(url) {
  return fetch(url, { credentials: "omit" }).then(function (r) {
    if (!r.ok) throw new Error("the endpoint returned HTTP " + r.status + ".");
    return r.json();
  });
}

// ---------------------------------------------------------------------------
// Where an issuer's metadata lives.
//
// An issuer identifier can have a path — walt.id's is
// https://host/openid4vci — and then the two specs disagree about where the
// document goes. RFC 8414 section 3.1 (which OID4VCI section 11.2.2 and SD-JWT
// VC follow) INSERTS the well-known segment between the host and that path:
//
//     https://host/.well-known/openid-credential-issuer/openid4vci
//
// OpenID Connect Discovery 1.0 APPENDS it instead:
//
//     https://host/openid4vci/.well-known/openid-configuration
//
// For an issuer with no path both forms are the same string, which is why
// appending works nearly everywhere and fails exactly where walt.id lives. Both
// are tried, insertion first, because that is what the specs governing these
// documents say — and RFC 8414 itself tells clients to try the other form for
// OpenID Connect compatibility.
// ---------------------------------------------------------------------------
function wellKnownCandidates(issuer, wellKnown) {
  log.debug("Entering wellKnownCandidates(). issuer=" + issuer + ", wellKnown=" + wellKnown);
  var trimmed = String(issuer || "").replace(/\/+$/, "");
  if (!trimmed) {
    log.debug("Leaving wellKnownCandidates(). No issuer.");
    return [];
  }
  var path = "";
  var origin = trimmed;
  var slash = trimmed.indexOf("/", trimmed.indexOf("://") + 3);
  if (trimmed.indexOf("://") !== -1 && slash !== -1) {
    origin = trimmed.slice(0, slash);
    path = trimmed.slice(slash);
  }
  var inserted = origin + wellKnown + path;
  var appended = trimmed + wellKnown;
  var out = inserted === appended ? [inserted] : [inserted, appended];
  log.debug("Leaving wellKnownCandidates(). " + out.join(" , "));
  return out;
}

// Fetch the first candidate that answers with a document. Resolves to
// { doc, url } so the caller can say which URL the document actually came from
// — with two candidates in play, a provenance note that guesses would be worse
// than none.
function fetchWellKnown(issuer, wellKnown) {
  log.debug("Entering fetchWellKnown(). issuer=" + issuer);
  var urls = wellKnownCandidates(issuer, wellKnown);
  if (!urls.length) {
    log.debug("Leaving fetchWellKnown(). Nothing to try.");
    return Promise.reject(new Error("no issuer identifier to resolve metadata from."));
  }
  var attempt = function (i, firstError) {
    if (i >= urls.length) throw firstError;
    return fetchJson(urls[i])
      .then(function (doc) {
        return { doc: doc, url: urls[i] };
      })
      .catch(function (e) {
        return attempt(i + 1, firstError || new Error(urls[0] + ": " + e.message));
      });
  };
  log.debug("Leaving fetchWellKnown(). Trying " + urls.length + " candidate(s).");
  return Promise.resolve().then(function () { return attempt(0, null); });
}

module.exports = {
  escapeHtmlText: escapeHtmlText,
  isJsonStructure: isJsonStructure,
  prettyJson: prettyJson,
  valueToDisplay: valueToDisplay,
  looksLikeJsonStructure: looksLikeJsonStructure,
  setMetadataField: setMetadataField,
  b64uToBytes: b64uToBytes,
  b64uToJson: b64uToJson,
  bytesToB64u: bytesToB64u,
  utf8ToB64u: utf8ToB64u,
  jwsAlgParams: jwsAlgParams,
  jwkForImport: jwkForImport,
  verifyJwsWithJwks: verifyJwsWithJwks,
  validateSignedMetadata: validateSignedMetadata,
  buildInfoTable: buildInfoTable,
  createStore: createStore,
  fetchJson: fetchJson,
  wellKnownCandidates: wellKnownCandidates,
  fetchWellKnown: fetchWellKnown
};
