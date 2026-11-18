// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vp_verifier.js
//
// ---------------------------------------------------------------------------
// The debugger as an OpenID4VP 1.0 VERIFIER (issue #364).
//
// Everything else in the presentation workflow plays the Wallet. This module
// plays the other end: it composes the Authorization Request a Verifier sends
// (a DCQL query, a signed Request Object under an x509 Client Identifier,
// the key a direct_post.jwt answer is encrypted to) and then checks the
// Wallet's answer, reporting EVERY check on its own line.
//
// That last part is the point of the module. A Verifier that says only
// "invalid presentation" is the commonest thing a wallet developer meets and
// the least useful, so verifyResponse() never folds two checks into one: a
// wrong nonce, a wrong aud, a stale Key Binding JWT, a Disclosure whose digest
// is in no _sd array and a requested claim nobody disclosed are five lines,
// and a presentation that fails one of them passes the other four.
//
// Where the cryptography runs. The checks this file makes itself (the
// SD-JWT digests and sd_hash, every JWS, every Data Integrity proof, the
// mdoc device signature, the x5c chain checks, the status lists) are pure
// JavaScript — @noble/hashes, @noble/curves, node-forge and jws.js's 'js'
// backend — so they work on an origin with no secure context, and so is
// mdoc.js's issuerAuth and device signature check since #469. Two things
// it borrows are Web Crypto underneath and inherit that module's limits
// (#463): certificate ISSUANCE (x509.js) and the ECDH-ES unwrap of a
// direct_post.jwt answer (jose_jwe.js). Status lists are decompressed with
// the platform's DecompressionStream, which every current browser and node
// 18+ has.
//
// Scope (#364, PRs 1 and 3): every Client Identifier prefix of OpenID4VP 1.0
// section 5.9.3 but openid_federation (refused, see buildersFor()); the
// response modes direct_post, direct_post.jwt, dc_api and dc_api.jwt
// (Appendix A); the four DCQL formats; the IETF Token Status List and the
// W3C Bitstring Status List; and the Data Integrity cryptosuites bbs-2023,
// ecdsa-rdfc-2019, ecdsa-jcs-2019, eddsa-rdfc-2022 and eddsa-jcs-2022.
// Status List Tokens are read in both forms, the JWT and the CWT
// (draft-ietf-oauth-status-list-21 sections 5.1 and 5.2). What it does not
// verify (ecdsa-sd-2023, a status list behind a COSE_Mac0) is a "skip" that
// says so, never a pass.
//
// No DOM: tests/vp_verifier_engine.js drives all of it in node.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vp_verifier",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha1 = require("@noble/hashes/sha1").sha1;
var forge = require("node-forge");
var cbor = require("./cbor");
var nobleSha512 = require("@noble/hashes/sha512");
var p256 = require("@noble/curves/p256").p256;
var p384 = require("@noble/curves/p384").p384;
var p521 = require("@noble/curves/p521").p521;
var ed25519 = require("@noble/curves/ed25519").ed25519;
var bytes = require("./crypto_bytes");
var jws = require("./jws");
var x509 = require("./x509");
var keyMaterial = require("./key_material");
var vpProtocols = require("./vp_protocols");
var joseJwe = require("./jose_jwe");
var sdJwtVc = require("./sd_jwt_vc");
var sdJwtVp = require("./sd_jwt_vp");
var mdoc = require("./mdoc");
var coseLib = require("./cose");
var bbs2023 = require("./bbs2023");
var didLib = require("./did");
var jsonld = require("jsonld");

var FORMAT_SD_JWT = "dc+sd-jwt";
var FORMAT_JWT_VC_JSON = "jwt_vc_json";
var FORMAT_MSO_MDOC = "mso_mdoc";
var FORMAT_LDP_VC = "ldp_vc";
var FORMATS = [FORMAT_SD_JWT, FORMAT_JWT_VC_JSON, FORMAT_MSO_MDOC,
               FORMAT_LDP_VC];

var REQUEST_AUD = "https://self-issued.me/v2";
var REQUEST_TYP = "oauth-authz-req+jwt";
var DEFAULT_ENC_VALUES = ["A128GCM", "A256GCM"];
var DEFAULT_TTL_SECONDS = 600;
// Clock skew allowed either side of a timestamp, and the oldest a Key
// Binding JWT (or VP JWT) may be and still count as made for THIS request.
// MAX_AGE_SECONDS is THIS DEBUGGER'S POLICY, not a number any
// specification gives (#469, C2): RFC 9901 leaves a KB-JWT's acceptable
// age to the Verifier, and OpenID4VP binds a presentation to its request
// by the nonce. verifyResponse({ maxAgeSeconds }) or
// session.maxAgeSeconds changes it; 0 turns the age limit off.
var SKEW_SECONDS = 300;
var MAX_AGE_SECONDS = 600;
var JWT_VC_ISSUER_WELL_KNOWN = "/.well-known/jwt-vc-issuer";

// The response modes this Verifier receives. The dc_api pair are OpenID4VP
// 1.0 Appendix A: the answer comes back from navigator.credentials.get()
// rather than to a response_uri.
var RESPONSE_MODES = ["direct_post", "direct_post.jwt", "dc_api",
                      "dc_api.jwt"];
// Appendix A.1's protocol identifiers for the Digital Credentials API.
var DC_API_PROTOCOLS = {
  unsigned: "openid4vp-v1-unsigned",
  signed: "openid4vp-v1-signed",
  multisigned: "openid4vp-v1-multisigned"
};
var ORIGIN_PREFIX = "origin:";
var VERIFIER_ATTESTATION_TYP = "verifier-attestation+jwt";
var STATUS_LIST_TYP = "statuslist+jwt";
// draft-ietf-oauth-status-list-21 section 5.2: the CWT form's protected
// header type (16), RFC 9596.
var STATUS_LIST_CWT_TYPE = "application/statuslist+cwt";
// Section 8.1 defines two media types for content negotiation, and both
// forms are verified here (#471, E5), so both are asked for.
var STATUS_LIST_ACCEPT = "application/statuslist+jwt, " +
    STATUS_LIST_CWT_TYPE;
// The CWT Claims Set keys section 5.2 names (RFC 8392 section 4 and this
// draft's section 14.3), and the COSE header labels a Status List Token's
// key is named by (RFC 9052 section 3.1, RFC 9360 section 2).
var CWT_ISS = 1;
var CWT_SUB = 2;
var CWT_EXP = 4;
var CWT_NBF = 5;
var CWT_IAT = 6;
var CWT_STATUS_LIST = 65533;
var CWT_TTL = 65534;
var COSE_HDR_ALG = 1;
var COSE_HDR_KID = 4;
var COSE_HDR_TYP = 16;
var COSE_HDR_X5CHAIN = 33;
var COSE_HDR_X5T = 34;
// RFC 9360's x5t is [hash alg, hash]; the two a JOSE header also has.
var COSE_X5T_SHA256 = -16;
var COSE_X5T_SHA1 = -14;
// draft-ietf-oauth-status-list-21 section 7.1: the registered values.
var TOKEN_STATUS_NAMES = { 0: "VALID", 1: "INVALID", 2: "SUSPENDED" };
// Ibid.: "The Status Type value 0x03 and Status Type values in the range
// 0x0C until 0x0F are permanently reserved as application specific ...
// All other Status Type values are reserved for future registration."
var TOKEN_STATUS_APPLICATION = [0x03, 0x0C, 0x0D, 0x0E, 0x0F];
// W3C Bitstring Status List v1.0 section 4: a status list credential "might
// be any media type registered for the purpose of expressing a verifiable
// credential", e.g. application/vc for Data Integrity.
var BITSTRING_ACCEPT = "application/vc, application/vc+jwt, " +
    "application/vc+ld+json;q=0.9, application/ld+json;q=0.8, " +
    "application/json;q=0.5";
// Ibid. section 2.1: the statusPurpose values that "MUST be used for their
// intended purpose".
var BITSTRING_PURPOSES = ["refresh", "revocation", "suspension", "message"];
// draft-ietf-oauth-status-list-21 section 10 defines id-kp-oauthStatusSigning
// as { id-kp TBD }, and section 14.9 asks IANA for "1.3.6.1.5.5.7.3.TBD":
// there is no number yet. A caller whose PKI uses one names it with
// verifyResponse()'s statusSigningEku option.
var STATUS_SIGNING_EKU_NAME = "id-kp-oauthStatusSigning";
// The X.509 signature algorithms a certificate link is checked with, each a
// jws.js row (pure JavaScript), and the ECDSA field length for DER to raw.
var STATUS_CERT_SIG_ALGS = {
  "1.2.840.10045.4.3.2": { alg: "ES256", len: 32 },
  "1.2.840.10045.4.3.3": { alg: "ES384", len: 48 },
  "1.2.840.10045.4.3.4": { alg: "ES512", len: 66 },
  "1.2.840.113549.1.1.11": { alg: "RS256" },
  "1.2.840.113549.1.1.12": { alg: "RS384" },
  "1.2.840.113549.1.1.13": { alg: "RS512" },
  "1.3.101.112": { alg: "EdDSA-Ed25519" }
};
// W3C Bitstring Status List v1.0: a list shorter than this many entries
// gives its subjects no herd privacy (section 6.1); reported, not refused.
var BITSTRING_MIN_ENTRIES = 131072;
// The most a status list may decompress to before it is refused: 16 MiB,
// i.e. 134 million one-bit entries. A small compressed body that inflates
// past this is a decompression bomb, not a status list.
var MAX_INFLATED_BYTES = 16 * 1024 * 1024;
// The Data Integrity cryptosuites verified here, and how each one hashes.
var DI_SUITES = {
  "eddsa-rdfc-2022": { canon: "rdfc", family: "eddsa" },
  "eddsa-jcs-2022": { canon: "jcs", family: "eddsa" },
  "ecdsa-rdfc-2019": { canon: "rdfc", family: "ecdsa" },
  "ecdsa-jcs-2019": { canon: "jcs", family: "ecdsa" }
};
var DI_SUITES_NOT_VERIFIED = {
  "ecdsa-sd-2023": "ecdsa-sd-2023 is not verified by this debugger: a " +
    "derived proof needs the selective-disclosure machinery of that suite " +
    "(HMAC-relabelled blank nodes, a CBOR-encoded proofValue carrying the " +
    "base signature, the ephemeral public key and one signature per " +
    "non-mandatory statement), which is not implemented here.",
  "bbs-2023": "bbs-2023 secures a CREDENTIAL (a reveal document with a " +
    "derived proof), not a presentation: there is no holder key in it to " +
    "sign a VP with."
};
var FEDERATION_NOTE = "openid_federation needs an OpenID Federation 1.0 " +
  "trust chain (entity statements from the Verifier up to a trust anchor), " +
  "which this debugger does not build or resolve. OpenID Federation 1.0 is " +
  "out of scope; see the note in docs/spec-roadmap.md.";

var PASS = "pass";
var FAIL = "fail";
var SKIP = "skip";

// ---------------------------------------------------------------------------
// Small pure helpers.
//
// isArray() and isPlainObject() carry no Entering/Leaving lines ON PURPOSE:
// walkSd() and selectPath() call them once per node of every credential, so
// a pair of log lines here would be most of the log. Their callers log.
// ---------------------------------------------------------------------------
function isArray(v) {
  return Object.prototype.toString.call(v) === "[object Array]";
}

function isPlainObject(v) {
  return !!v && typeof v === "object" && !isArray(v) &&
    !(v instanceof Uint8Array);
}

function nowSeconds(now) {
  log.debug("Entering nowSeconds().");
  var ms = now instanceof Date ? now.getTime()
         : typeof now === "number" ? (now > 1e11 ? now : now * 1000)
         : Date.now();
  log.debug("Leaving nowSeconds().");
  return Math.floor(ms / 1000);
}

// The three digests _sd_alg may name (RFC 9901 section 4.1.1), in pure JS.
function hashFor(sdAlg) {
  log.debug("Entering hashFor(). alg=" + (sdAlg || "sha-256"));
  var alg = String(sdAlg || "sha-256").toLowerCase();
  var fn = { "sha-256": nobleSha256, "sha-384": nobleSha512.sha384,
             "sha-512": nobleSha512.sha512 }[alg] || null;
  log.debug("Leaving hashFor().");
  return fn;
}

function b64uDigest(text, sdAlg) {
  log.debug("Entering b64uDigest().");
  var fn = hashFor(sdAlg);
  if (!fn) {
    log.debug("Leaving b64uDigest(). Unsupported.");
    throw new Error('unsupported _sd_alg "' + sdAlg + '".');
  }
  log.debug("Leaving b64uDigest().");
  return bytes.bytesToB64u(fn(bytes.strBytes(String(text))));
}

function decodeJsonPart(part) {
  log.debug("Entering decodeJsonPart().");
  log.debug("Leaving decodeJsonPart().");
  return JSON.parse(bytes.b64uToStr(part));
}

function decodeJwt(compact) {
  log.debug("Entering decodeJwt().");
  var parts = String(compact || "").split(".");
  if (parts.length !== 3) {
    log.debug("Leaving decodeJwt(). Not three parts.");
    throw new Error("a compact JWS has three parts; this has " +
                    parts.length + ".");
  }
  log.debug("Leaving decodeJwt().");
  return { header: decodeJsonPart(parts[0]),
           payload: decodeJsonPart(parts[1]) };
}

// RFC 7638 thumbprint of an EC or OKP public key, base64url.
function jwkThumbprint(jwk) {
  log.debug("Entering jwkThumbprint().");
  var canonical = jwk.kty === "EC" ?
      JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
    : jwk.kty === "OKP" ?
      JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })
    : JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  log.debug("Leaving jwkThumbprint().");
  return bytes.bytesToB64u(nobleSha256(bytes.strBytes(canonical)));
}

function publicPart(jwk) {
  log.debug("Entering publicPart().");
  var out = {};
  ["kty", "crv", "x", "y", "n", "e", "kid", "use", "alg"].forEach(
    function (k) {
      if (jwk && jwk[k] !== undefined) out[k] = jwk[k];
    });
  log.debug("Leaving publicPart().");
  return out;
}

function sameKey(a, b) {
  log.debug("Entering sameKey().");
  if (!a || !b) {
    log.debug("Leaving sameKey(). Missing.");
    return false;
  }
  log.debug("Leaving sameKey().");
  return jwkThumbprint(a) === jwkThumbprint(b);
}

// A CSPRNG token, base64url. crypto.getRandomValues exists in every browser
// context (secure or not) and in node.
function randomToken(count) {
  log.debug("Entering randomToken().");
  var n = count || 16;
  log.debug("Leaving randomToken().");
  return bytes.bytesToB64u(bytes.randomBytes(n));
}

// ---------------------------------------------------------------------------
// The DCQL query (OpenID4VP 1.0 section 6).
//
// spec: { queries: [{ id, format, vct, doctype, types, claims: [[seg...]],
//                     requireBinding, multiple }], credentialSets }
// ---------------------------------------------------------------------------
function dcqlPath(path, where) {
  log.debug("Entering dcqlPath().");
  var p = isPlainObject(path) ? path.path : path;
  if (!isArray(p) || !p.length) {
    log.debug("Leaving dcqlPath(). Empty.");
    throw new Error(where + ": a claim path must be a non-empty array.");
  }
  p.forEach(function (seg) {
    var ok = typeof seg === "string" ? seg.length > 0
           : typeof seg === "number" ? seg >= 0 && Math.floor(seg) === seg
           : seg === null;
    if (!ok) {
      throw new Error(where + ": a path segment must be a non-empty " +
                      "string, a non-negative integer or null; got " +
                      JSON.stringify(seg) + ".");
    }
  });
  log.debug("Leaving dcqlPath().");
  return p.slice();
}

// A non-empty string, which is all a type identifier can be here.
function isNonEmptyString(v) {
  log.debug("Entering isNonEmptyString().");
  log.debug("Leaving isNonEmptyString().");
  return typeof v === "string" && v.trim().length > 0;
}

// The `meta` of one credential query, with the member its format makes
// REQUIRED (#468, M4). Section 6.1 makes `meta` itself REQUIRED, and each
// format's Appendix B names what goes in it:
//
//   B.3.5  vct_values     "REQUIRED. A non-empty array of strings"
//   B.2.3  doctype_value  "REQUIRED. String that specifies an allowed value
//                         for the doctype"
//   B.1.1  type_values    "REQUIRED. A non-empty array of string arrays",
//                         each inner array "a non-empty array specifying
//                         the fully expanded types"
//
// A query missing one, or carrying an empty array or an empty string, is
// REFUSED rather than emitted: a `meta` of {} or "vct_values": [] is a query
// a conforming Wallet must reject, and a debugger that builds one teaches
// that it is fine.
function queryMeta(q, where) {
  log.debug("Entering queryMeta(). " + q.format);
  var meta = {};
  if (q.format === FORMAT_SD_JWT) {
    var vct = q.vct === undefined || q.vct === null ? [] : [].concat(q.vct);
    if (!vct.length || !vct.every(isNonEmptyString)) {
      log.debug("Leaving queryMeta(). No vct.");
      throw new Error(where + ": a dc+sd-jwt query needs at least one " +
                      "vct. OpenID4VP 1.0 Appendix B.3.5: vct_values is " +
                      "\"REQUIRED. A non-empty array of strings\".");
    }
    meta.vct_values = vct.map(String);
  } else if (q.format === FORMAT_MSO_MDOC) {
    if (!isNonEmptyString(q.doctype)) {
      log.debug("Leaving queryMeta(). No doctype.");
      throw new Error(where + ": an mso_mdoc query needs a doctype. " +
                      "OpenID4VP 1.0 Appendix B.2.3: doctype_value is " +
                      "REQUIRED.");
    }
    meta.doctype_value = String(q.doctype);
  } else {
    var types = isArray(q.types) ? q.types : [];
    var sets = !types.length ? [] : isArray(types[0]) ?
        types.map(function (t) {
          return isArray(t) ? t.slice() : null;
        }) : [types.slice()];
    var good = sets.length > 0 && sets.every(function (set) {
      return isArray(set) && set.length > 0 && set.every(isNonEmptyString);
    });
    if (!good) {
      log.debug("Leaving queryMeta(). No types.");
      throw new Error(where + ": a " + q.format + " query needs at least " +
                      "one type in every alternative. OpenID4VP 1.0 " +
                      "Appendix B.1.1: type_values is \"REQUIRED. A " +
                      "non-empty array of string arrays\", each inner " +
                      "array non-empty.");
    }
    meta.type_values = sets;
  }
  log.debug("Leaving queryMeta().");
  return meta;
}

function buildCredentialQuery(q, index, seen) {
  log.debug("Entering buildCredentialQuery(). index=" + index);
  if (!q || !q.id) {
    log.debug("Leaving buildCredentialQuery(). No id.");
    throw new Error("credential query " + index + " has no id.");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(String(q.id))) {
    log.debug("Leaving buildCredentialQuery(). Bad id.");
    throw new Error('credential query id "' + q.id + '" must be ' +
                    "alphanumeric, underscore or hyphen (section 6.1).");
  }
  if (seen[q.id]) {
    log.debug("Leaving buildCredentialQuery(). Duplicate.");
    throw new Error('credential query id "' + q.id + '" is used twice.');
  }
  seen[q.id] = true;
  if (FORMATS.indexOf(q.format) === -1) {
    log.debug("Leaving buildCredentialQuery(). Unknown format.");
    throw new Error('credential query "' + q.id + '": unknown format "' +
                    q.format + '" (one of ' + FORMATS.join(", ") + ").");
  }
  var where = 'credential query "' + q.id + '"';
  var out = { id: String(q.id), format: q.format,
              meta: queryMeta(q, where) };
  var claims = (q.claims || []).map(function (c) {
    var path = dcqlPath(c, where);
    if (q.format === FORMAT_MSO_MDOC && (path.length !== 2 ||
        typeof path[0] !== "string" || typeof path[1] !== "string")) {
      throw new Error(where + ": an mdoc claim path is [namespace, " +
                      "element].");
    }
    var claim = { path: path };
    if (isPlainObject(c) && c.id) claim.id = c.id;
    if (isPlainObject(c) && isArray(c.values)) claim.values = c.values;
    return claim;
  });
  if (claims.length) out.claims = claims;
  if (q.requireBinding === false) {
    out.require_cryptographic_holder_binding = false;
  }
  if (q.multiple === true) out.multiple = true;
  if (isArray(q.trustedAuthorities) && q.trustedAuthorities.length) {
    // Section 6.1.1: each entry { type, values }, values a non-empty array
    // of strings.
    out.trusted_authorities = q.trustedAuthorities.map(function (ta) {
      if (!isPlainObject(ta) || typeof ta.type !== "string" || !ta.type ||
          !isArray(ta.values) || !ta.values.length ||
          ta.values.some(function (v) {
            return typeof v !== "string" || !v;
          })) {
        throw new Error(where + ": a trusted_authorities entry is " +
                        "{ type, values }, values a non-empty array of " +
                        "strings (section 6.1.1).");
      }
      return { type: ta.type, values: ta.values.slice() };
    });
  }
  log.debug("Leaving buildCredentialQuery().");
  return out;
}

function buildDcql(spec) {
  log.debug("Entering buildDcql().");
  if (!spec || !isArray(spec.queries) || !spec.queries.length) {
    log.debug("Leaving buildDcql(). No queries.");
    throw new Error("a DCQL query needs at least one credential query.");
  }
  var seen = {};
  var dcql = { credentials: spec.queries.map(function (q, i) {
    return buildCredentialQuery(q, i, seen);
  }) };
  if (spec.credentialSets && spec.credentialSets.length) {
    dcql.credential_sets = spec.credentialSets.map(function (set, i) {
      var options = isArray(set) ? set : set && set.options;
      if (!isArray(options) || !options.length) {
        throw new Error("credential set " + i + " has no options.");
      }
      options.forEach(function (option) {
        if (!isArray(option) || !option.length) {
          throw new Error("credential set " + i + " has an empty option.");
        }
        option.forEach(function (id) {
          if (!seen[id]) {
            throw new Error("credential set " + i + ' names "' + id +
                            '", which is no credential query.');
          }
        });
      });
      var out = { options: options.map(function (o) {
        return o.slice();
      }) };
      if (set && set.required === false) out.required = false;
      return out;
    });
  }
  log.debug("Leaving buildDcql(). " + dcql.credentials.length +
            " credential query(ies).");
  return dcql;
}

// ---------------------------------------------------------------------------
// Who the Verifier is: a P-256 Root CA and a leaf under it.
//
// The leaf's SAN dNSName is what x509_san_dns names, its SHA-256 is what
// x509_hash names, and its AIA caIssuers URL is where a wallet that anchors
// by fetching (rcbj/oid4vc-wallet does) finds the root. x5c carries the LEAF
// ONLY, so such a wallet has to fetch it.
//
// THE ROOT OUTLIVES THE REQUEST (#470, B4). A wallet that is CONFIGURED with
// trust anchors, rather than fetching one from AIA, can only trust a root it
// was given before the request arrived, so a root made per request is one
// no such wallet ever trusts. makeVerifierRoot() makes it once; the page
// keeps it (behind its save checkbox) and hands it to makeVerifierIdentity()
// for every request. The LEAF stays per request: its SAN and its AIA URL
// name the api host and the session, which change.
// ---------------------------------------------------------------------------
var ROOT_SUBJECT = "CN=Debugger Verifier Root,O=idptools";

// The DER a P-256 SubjectPublicKeyInfo begins with (RFC 5480: the
// id-ecPublicKey and secp256r1 OIDs, then a 66-byte BIT STRING header), so
// the uncompressed point is the 65 bytes after it. The encoding is fixed,
// which is what lets a certificate's key be compared with a JWK in pure JS.
var P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d03010703" +
    "4200";

function x509HashOf(der) {
  log.debug("Entering x509HashOf().");
  log.debug("Leaving x509HashOf().");
  return bytes.bytesToB64u(nobleSha256(bytes.asBytes(der)));
}

// The uncompressed P-256 point in a certificate's SubjectPublicKeyInfo, or
// null when the certificate's key is not P-256.
function p256PointOfCertificate(der) {
  log.debug("Entering p256PointOfCertificate().");
  var hex = bytes.bytesToHex(bytes.asBytes(der));
  var at = hex.indexOf(P256_SPKI_PREFIX);
  if (at < 0 || at % 2 !== 0) {
    log.debug("Leaving p256PointOfCertificate(). Not P-256.");
    return null;
  }
  var from = at + P256_SPKI_PREFIX.length;
  var point = bytes.hexToBytes(hex.slice(from, from + 130));
  log.debug("Leaving p256PointOfCertificate().");
  return point.length === 65 && point[0] === 4 ? point : null;
}

// A P-256 private JWK, checked (its x and y ARE its d's public key) and
// returned with its public half, a kid (the RFC 7638 thumbprint), use sig
// and alg ES256 — the shape makeRequestKey() returns.
function p256KeyFromJwk(jwk, what) {
  log.debug("Entering p256KeyFromJwk(). " + what);
  if (!isPlainObject(jwk) || jwk.kty !== "EC" || jwk.crv !== "P-256" ||
      !isNonEmptyString(jwk.d)) {
    log.debug("Leaving p256KeyFromJwk(). Not a P-256 private JWK.");
    throw new Error(what + " must be a P-256 private JWK (kty EC, crv " +
                    "P-256, with d).");
  }
  var d = bytes.b64uToBytes(jwk.d);
  var point;
  try {
    point = p256.getPublicKey(d, false);
  } catch (e) {
    log.debug("Leaving p256KeyFromJwk(). Bad d.");
    throw new Error(what + "'s d is not a P-256 private key: " + e.message);
  }
  var x = bytes.bytesToB64u(point.slice(1, 33));
  var y = bytes.bytesToB64u(point.slice(33, 65));
  if ((jwk.x !== undefined && jwk.x !== x) ||
      (jwk.y !== undefined && jwk.y !== y)) {
    log.debug("Leaving p256KeyFromJwk(). x/y disagree with d.");
    throw new Error(what + "'s x and y are not the public key of its d.");
  }
  var publicJwk = { kty: "EC", crv: "P-256", x: x, y: y };
  publicJwk.kid = jwkThumbprint(publicJwk);
  publicJwk.use = "sig";
  publicJwk.alg = "ES256";
  var privateJwk = Object.assign({}, publicJwk, { d: jwk.d });
  log.debug("Leaving p256KeyFromJwk(). kid=" + publicJwk.kid);
  return { privateJwk: privateJwk, publicJwk: publicJwk };
}

// The Verifier's root CA: a self-signed P-256 certificate and its key, the
// key as a JWK (which pure JS can check against the certificate) and as the
// PEM x509.issueCertificate() signs with. Web Crypto, like the leaf.
async function makeVerifierRoot(opts) {
  log.debug("Entering makeVerifierRoot().");
  var o = opts || {};
  var nowMs = nowSeconds(o.now) * 1000;
  var desc = keyMaterial.keyAlg("ec-p256");
  var rootKey = await keyMaterial.generateKeyPair("ec-p256");
  var root = await x509.issueCertificate({
    profile: "root-ca", subject: ROOT_SUBJECT,
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem,
    signatureAlg: "sha256-ecdsa",
    notBefore: new Date(nowMs - 5 * 60 * 1000),
    extensions: x509.defaultExtensions("root-ca", desc)
  });
  var jwk = await keyMaterial.privToJwk(rootKey.privatePem, desc, "ES256");
  var key = p256KeyFromJwk(jwk, "the root's key");
  log.debug("Leaving makeVerifierRoot().");
  return { certificatePem: root.pem, certificateDer: bytes.asBytes(root.der),
           privateJwk: key.privateJwk, privatePem: rootKey.privatePem };
}

// THE HOST AS A NAME OR AN ADDRESS (#470, B5). The leaf names the host of
// response_uri, which is an IP address whenever the api is reached by one
// (a phone on the LAN, `https://192.168.1.20:4000`). RFC 5280 section
// 4.2.1.6 puts an address in an iPAddress general name, as its 4 or 16
// octets, and a dNSName is a DNS name and never an address — so the leaf
// carries an iPAddress SAN then, and x509_san_dns, which OpenID4VP 1.0
// section 5.9.3 makes "a DNS name" matching "a dNSName ... entry", cannot be
// used at all. The host's IPv6 brackets (URL.hostname keeps them) go.
function ipHost(host) {
  log.debug("Entering ipHost().");
  var text = String(host || "").replace(/^\[(.*)\]$/, "$1");
  if (!/^[0-9.]+$/.test(text) && text.indexOf(":") < 0) {
    log.debug("Leaving ipHost(). A name.");
    return null;
  }
  try {
    x509.ipBytes(text);
  } catch (e) {
    log.debug("Leaving ipHost(). Not an address.");
    return null;
  }
  log.debug("Leaving ipHost(). " + text);
  return text;
}

// A root as makeVerifierRoot() or readVerifierIdentityFile() gives it, with
// its signing PEM (made from the JWK when it is not there yet).
async function rootForSigning(root) {
  log.debug("Entering rootForSigning().");
  if (!root || !isNonEmptyString(root.certificatePem) || !root.privateJwk) {
    log.debug("Leaving rootForSigning(). Incomplete.");
    throw new Error("a Verifier root needs certificatePem and privateJwk " +
                    "(makeVerifierRoot()).");
  }
  if (!root.privatePem) {
    root.privatePem = await keyMaterial.privToPem(
      JSON.stringify(root.privateJwk), keyMaterial.keyAlg("ec-p256"));
  }
  if (!root.certificateDer) {
    root.certificateDer = bytes.pemToDer(root.certificatePem);
  }
  log.debug("Leaving rootForSigning().");
  return root;
}

// `opts.root` is the persistent root (makeVerifierRoot()); without one a
// root is made for this identity alone, as before #470. The leaf is always
// new.
async function makeVerifierIdentity(opts) {
  log.debug("Entering makeVerifierIdentity().");
  var o = opts || {};
  if (!o.dnsName) {
    log.debug("Leaving makeVerifierIdentity(). No DNS name.");
    throw new Error("a Verifier identity needs a dnsName for the leaf.");
  }
  var nowMs = nowSeconds(o.now) * 1000;
  var notBefore = new Date(nowMs - 5 * 60 * 1000);
  var desc = keyMaterial.keyAlg("ec-p256");
  var root = await rootForSigning(o.root ||
                                  await makeVerifierRoot({ now: o.now }));
  var leafKey = await keyMaterial.generateKeyPair("ec-p256");
  // The leaf's KeyUsage is read through its P-256 key (#468, M5). The
  // tls-server profile's list is RSA-shaped (digitalSignature,
  // keyEncipherment), and RFC 5480 section 3 permits an id-ecPublicKey
  // end-entity certificate only "digitalSignature; nonRepudiation; and/or
  // keyAgreement" — keyEncipherment makes it non-conformant, and a Wallet
  // that checks refuses the chain. This leaf only signs Request Objects, so
  // digitalSignature is all it asserts.
  var ext = x509.defaultExtensions("tls-server", desc);
  ext.keyUsage.usages = ["digitalSignature"];
  var ip = ipHost(o.dnsName);
  ext.subjectAltName = { present: true, critical: false,
    names: [ip ? { kind: "ip", value: ip }
               : { kind: "dns", value: String(o.dnsName) }] };
  if (o.caIssuersUrl) {
    ext.authorityInfoAccess = { present: true, critical: false,
      entries: [{ method: "caIssuers", url: String(o.caIssuersUrl) }] };
  }
  var leaf = await x509.issueCertificate({
    profile: "tls-server",
    subject: "CN=" + (ip || o.dnsName) + ",O=idptools",
    subjectPublicKey: leafKey.publicPem,
    issuer: { certificatePem: root.certificatePem,
              privateKeyPem: root.privatePem, keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa", notBefore: notBefore, extensions: ext
  });
  var privateJwk = await keyMaterial.privToJwk(leafKey.privatePem, desc,
                                               "ES256");
  var publicJwk = await keyMaterial.pubToJwk(leafKey.publicPem, desc,
                                             "ES256", "sig");
  var leafDer = bytes.asBytes(leaf.der);
  log.debug("Leaving makeVerifierIdentity(). dns=" + o.dnsName);
  return {
    rootPem: root.certificatePem, rootDer: bytes.asBytes(root.certificateDer),
    root: root,
    leafPem: leaf.pem, leafDer: leafDer,
    privateJwk: privateJwk, publicJwk: publicJwk,
    x5c: [bytes.bytesToB64(leafDer)],
    x509Hash: x509HashOf(leafDer),
    // dnsName is the host as given (an x509_san_dns Client Identifier is
    // built from it, and refused when it is an address); ipAddress is set
    // when the SAN is an iPAddress.
    dnsName: String(o.dnsName), ipAddress: ip || "",
    caIssuersUrl: o.caIssuersUrl || ""
  };
}

// ---------------------------------------------------------------------------
// THE IDENTITY FILE (#470, B4): what the page keeps across runs, and what
// its Download button writes and its import field reads. Every part is
// optional, because each is made when a prefix first needs it:
//
//   root         { certificatePem, privateJwk }: x509_hash, x509_san_dns
//   attester     { iss, privateJwk }: verifier_attestation
//   requestKey   { privateJwk }: decentralized_identifier (its DID) and a
//                pre-registered client_id (the JWKS a wallet registered),
//                and the key a Verifier Attestation's cnf names
//
// THE RESPONSE ENCRYPTION KEY IS NOT IN IT, on purpose: nothing about it is
// anchored anywhere (a request carries it in client_metadata), so keeping
// it buys no trust and only lets one leaked key read every later answer.
//
// Private keys are JWKs, so a file can be checked in pure JS: each JWK's x
// and y must be its d's public key, and the root's must be the key in its
// certificate.
// ---------------------------------------------------------------------------
var IDENTITY_FILE_TYPE = "oid4vp-verifier-identity";

function verifierIdentityFile(parts) {
  log.debug("Entering verifierIdentityFile().");
  var p = parts || {};
  var out = { type: IDENTITY_FILE_TYPE, version: 1,
              note: "The debugger's OpenID4VP Verifier identity. It holds " +
                "PRIVATE KEYS: whoever has this file can sign as this " +
                "Verifier." };
  if (p.root) {
    out.root = { certificatePem: p.root.certificatePem,
                 privateJwk: p.root.privateJwk };
  }
  if (p.attester) {
    out.attester = { iss: p.attester.iss,
                     privateJwk: p.attester.privateJwk };
  }
  if (p.requestKey) {
    out.requestKey = { privateJwk: p.requestKey.privateJwk };
  }
  log.debug("Leaving verifierIdentityFile().");
  return out;
}

function readVerifierIdentityFile(input) {
  log.debug("Entering readVerifierIdentityFile().");
  var doc = input;
  if (typeof input === "string") {
    try {
      doc = JSON.parse(input);
    } catch (e) {
      log.debug("Leaving readVerifierIdentityFile(). Not JSON.");
      throw new Error("a Verifier identity file is JSON: " + e.message);
    }
  }
  if (!isPlainObject(doc) || doc.type !== IDENTITY_FILE_TYPE) {
    log.debug("Leaving readVerifierIdentityFile(). Wrong type.");
    throw new Error('this is not a Verifier identity file (its "type" ' +
                    'must be "' + IDENTITY_FILE_TYPE + '").');
  }
  if (doc.version !== 1) {
    log.debug("Leaving readVerifierIdentityFile(). Version.");
    throw new Error("this Verifier identity file is version " +
                    JSON.stringify(doc.version) + "; this page reads 1.");
  }
  var out = {};
  if (doc.root !== undefined) {
    var r = doc.root;
    if (!isPlainObject(r) || !/-----BEGIN CERTIFICATE-----/.test(
        String(r.certificatePem || ""))) {
      log.debug("Leaving readVerifierIdentityFile(). Bad root.");
      throw new Error("root.certificatePem must be a PEM certificate.");
    }
    var rootKey = p256KeyFromJwk(r.privateJwk, "root.privateJwk");
    var der = bytes.pemToDer(r.certificatePem);
    var point = p256PointOfCertificate(der);
    var mine = bytes.concatBytes(new Uint8Array([4]),
      bytes.b64uToBytes(rootKey.publicJwk.x),
      bytes.b64uToBytes(rootKey.publicJwk.y));
    if (!point || !bytes.bytesEqual(point, mine)) {
      log.debug("Leaving readVerifierIdentityFile(). Key mismatch.");
      throw new Error("root.privateJwk is not the key in " +
                      "root.certificatePem.");
    }
    out.root = { certificatePem: String(r.certificatePem).trim() + "\n",
                 certificateDer: der, privateJwk: rootKey.privateJwk };
  }
  if (doc.attester !== undefined) {
    var a = isPlainObject(doc.attester) ? doc.attester : {};
    var attesterKey = p256KeyFromJwk(a.privateJwk, "attester.privateJwk");
    out.attester = makeAttester({ key: attesterKey,
      iss: isNonEmptyString(a.iss) ? a.iss : undefined });
  }
  if (doc.requestKey !== undefined) {
    out.requestKey = p256KeyFromJwk(isPlainObject(doc.requestKey) ?
      doc.requestKey.privateJwk : null, "requestKey.privateJwk");
  }
  log.debug("Leaving readVerifierIdentityFile(). " +
            Object.keys(out).join(", "));
  return out;
}

// A key pair a Request Object is signed with when no certificate is
// involved (decentralized_identifier, verifier_attestation, a pre-registered
// client). P-256, pure JS; the kid is the RFC 7638 thumbprint.
function makeRequestKey() {
  log.debug("Entering makeRequestKey().");
  var priv = p256.utils.randomPrivateKey();
  var pj = jws.publicJwk("ES256", p256.getPublicKey(priv, false));
  var publicJwk = { kty: pj.kty, crv: pj.crv, x: pj.x, y: pj.y };
  publicJwk.kid = jwkThumbprint(publicJwk);
  publicJwk.use = "sig";
  publicJwk.alg = "ES256";
  var privateJwk = Object.assign({}, publicJwk,
                                 { d: bytes.bytesToB64u(priv) });
  log.debug("Leaving makeRequestKey(). kid=" + publicJwk.kid);
  return { privateJwk: privateJwk, publicJwk: publicJwk };
}

// The JWS algorithm a key signs with.
function algForJwk(jwk) {
  log.debug("Entering algForJwk().");
  var crv = String((jwk && jwk.crv) || "");
  var out = crv === "P-384" ? { algId: "ES384", alg: "ES384" }
          : crv === "Ed25519" ? { algId: "EdDSA-Ed25519", alg: "EdDSA" }
          : { algId: "ES256", alg: "ES256" };
  log.debug("Leaving algForJwk(). " + out.alg);
  return out;
}

// The DID a request key is published as: did:jwk (the default) or did:key.
// Both resolve with no network, which is the point: a wallet can check the
// Request Object's signature from the client_id alone.
function didForKey(publicJwk, method) {
  log.debug("Entering didForKey(). method=" + (method || "jwk"));
  if (method === "key") {
    log.debug("Leaving didForKey(). did:key.");
    return didLib.jwkToDidKey(publicPart(publicJwk));
  }
  log.debug("Leaving didForKey(). did:jwk.");
  return didLib.jwkToDidJwk({ kty: publicJwk.kty, crv: publicJwk.crv,
                              x: publicJwk.x, y: publicJwk.y });
}

// The DID URL that names the DID's one key: did:jwk's "#0" (the did:jwk
// method specification) and did:key's own multibase value (did:key 0.7).
function didKidFor(did) {
  log.debug("Entering didKidFor().");
  var base = String(did).split("#")[0];
  if (/^did:key:/.test(base)) {
    log.debug("Leaving didKidFor(). did:key.");
    return base + "#" + base.slice("did:key:".length);
  }
  log.debug("Leaving didKidFor().");
  return base + "#0";
}

// The public key a did:jwk or did:key names, with no network.
function keyOfLocalDid(did) {
  log.debug("Entering keyOfLocalDid().");
  var base = String(did || "").split("#")[0];
  var jwk = /^did:key:/.test(base) ? didLib.didKeyToJwk(base) :
      /^did:jwk:/.test(base) ? sdJwtVc.jwkFromDid(base) : null;
  log.debug("Leaving keyOfLocalDid(). " + !!jwk);
  return jwk || null;
}

// The Client Identifier for a prefix (OpenID4VP 1.0 section 5.9.3).
//
//   x509_hash, x509_san_dns   the certificate in `identity`
//   redirect_uri              opts.redirectUri (an unsigned request)
//   decentralized_identifier  opts.did, else the DID of identity.publicJwk
//                             (opts.didMethod "jwk", the default, or "key")
//   verifier_attestation      opts.value, else identity.dnsName: the
//                             attestation's sub is this value
//   pre-registered            opts.clientId, typed by the reader, no prefix
//   origin                    opts.origin; the DC API's effective Client
//                             Identifier for an UNSIGNED request, which the
//                             Verifier never sends (Appendix A.2)
//   openid_federation         refused: see FEDERATION_NOTE
function clientIdFor(prefix, identity, opts) {
  log.debug("Entering clientIdFor(). prefix=" + prefix);
  var o = opts || {};
  if (prefix === "x509_hash") {
    if (!identity || !identity.x509Hash) {
      log.debug("Leaving clientIdFor(). No certificate.");
      throw new Error("x509_hash needs a Verifier identity.");
    }
    log.debug("Leaving clientIdFor().");
    return "x509_hash:" + identity.x509Hash;
  }
  if (prefix === "x509_san_dns") {
    var dns = o.dnsName || (identity && identity.dnsName);
    if (!dns) {
      log.debug("Leaving clientIdFor(). No DNS name.");
      throw new Error("x509_san_dns needs a dnsName.");
    }
    if (ipHost(dns)) {
      log.debug("Leaving clientIdFor(). An IP address.");
      throw new Error("x509_san_dns cannot name " + dns + ": it is an IP " +
        "address, and OpenID4VP 1.0 section 5.9.3 makes the Client " +
        "Identifier \"a DNS name\" matching a dNSName SAN, which an " +
        "address never is (RFC 5280 section 4.2.1.6 puts it in an " +
        "iPAddress name). Use x509_hash, whose leaf carries the address " +
        "as an iPAddress SAN, or reach the api by a host name " +
        "(oid4vpVerifierPublicBaseUrl, or the page's public base URL).");
    }
    log.debug("Leaving clientIdFor().");
    return "x509_san_dns:" + dns;
  }
  if (prefix === "redirect_uri") {
    if (!o.redirectUri) {
      log.debug("Leaving clientIdFor(). No redirect URI.");
      throw new Error("redirect_uri needs a redirectUri.");
    }
    log.debug("Leaving clientIdFor().");
    return "redirect_uri:" + o.redirectUri;
  }
  if (prefix === "decentralized_identifier") {
    var did = o.did || (identity && identity.publicJwk ?
        didForKey(identity.publicJwk, o.didMethod) : "");
    if (!didLib.isDid(String(did))) {
      log.debug("Leaving clientIdFor(). No DID.");
      throw new Error("decentralized_identifier needs a DID, or a request " +
                      "key to make a did:jwk or did:key of.");
    }
    log.debug("Leaving clientIdFor().");
    return "decentralized_identifier:" + String(did).split("#")[0];
  }
  if (prefix === "verifier_attestation") {
    var value = o.value || (identity && identity.dnsName) || "";
    if (!value) {
      log.debug("Leaving clientIdFor(). No value.");
      throw new Error("verifier_attestation needs a value (the " +
                      "attestation's sub).");
    }
    log.debug("Leaving clientIdFor().");
    return "verifier_attestation:" + value;
  }
  if (prefix === "pre-registered" || prefix === "" ||
      prefix === undefined || prefix === null) {
    var typed = String(o.clientId || "").trim();
    if (!typed) {
      log.debug("Leaving clientIdFor(). Nothing typed.");
      throw new Error("a pre-registered client needs the client_id the " +
                      "wallet knows it by.");
    }
    if (vpProtocols.clientIdPrefix(typed).prefix) {
      log.debug("Leaving clientIdFor(). Prefixed.");
      throw new Error('"' + typed + '" begins with a Client Identifier ' +
                      "prefix, so a wallet would not read it as a " +
                      "pre-registered client (section 5.9.2).");
    }
    log.debug("Leaving clientIdFor(). Pre-registered.");
    return typed;
  }
  if (prefix === "origin") {
    if (!o.origin) {
      log.debug("Leaving clientIdFor(). No origin.");
      throw new Error("the origin prefix needs the page's origin.");
    }
    log.debug("Leaving clientIdFor(). Origin.");
    return ORIGIN_PREFIX + o.origin;
  }
  if (prefix === "openid_federation") {
    log.debug("Leaving clientIdFor(). Federation.");
    throw new Error(FEDERATION_NOTE);
  }
  log.debug("Leaving clientIdFor(). Unsupported.");
  throw new Error('"' + prefix + '" is not a Client Identifier prefix of ' +
                  "OpenID4VP 1.0 section 5.9.3 that this debugger builds.");
}

// The JWK Set a wallet would hold for a pre-registered client: the request
// key, with the kid signRequestObject() puts in the header.
function preRegisteredJwks(identity) {
  log.debug("Entering preRegisteredJwks().");
  var pub = publicPart(identity.publicJwk);
  pub.kid = pub.kid || jwkThumbprint(pub);
  pub.use = "sig";
  pub.alg = algForJwk(pub).alg;
  log.debug("Leaving preRegisteredJwks().");
  return { keys: [pub] };
}

// The party that vouches for a Verifier under verifier_attestation (section
// 12). Its iss is the did:jwk of its own key, so a wallet can be told to
// trust exactly that key: `jwks` is what to give it.
// `opts.key` is a key the attester already has (the identity file's), in
// makeRequestKey()'s shape; without one it gets a new key.
function makeAttester(opts) {
  log.debug("Entering makeAttester().");
  var o = opts || {};
  var key = o.key || makeRequestKey();
  var iss = o.iss || didForKey(key.publicJwk, "jwk");
  log.debug("Leaving makeAttester(). iss=" + iss.slice(0, 40));
  return { iss: iss, privateJwk: key.privateJwk, publicJwk: key.publicJwk,
           jwks: { keys: [publicPart(key.publicJwk)] } };
}

// A Verifier Attestation JWT (OpenID4VP 1.0 section 12): typ
// verifier-attestation+jwt, signed by the attester, sub the Client
// Identifier's value, cnf.jwk the key the Request Object is signed with.
async function verifierAttestation(opts) {
  log.debug("Entering verifierAttestation().");
  var o = opts || {};
  if (!o.attester || !o.attester.privateJwk) {
    log.debug("Leaving verifierAttestation(). No attester.");
    throw new Error("a Verifier Attestation JWT needs an attester " +
                    "(makeAttester()).");
  }
  if (!o.sub) {
    log.debug("Leaving verifierAttestation(). No sub.");
    throw new Error("a Verifier Attestation JWT needs a sub.");
  }
  var iat = nowSeconds(o.now);
  var payload = { iss: o.attester.iss, sub: String(o.sub), iat: iat,
                  exp: iat + (o.ttlSeconds || 24 * 3600),
                  cnf: { jwk: publicPart(o.identity.publicJwk) } };
  if (isArray(o.redirectUris) && o.redirectUris.length) {
    payload.redirect_uris = o.redirectUris.slice();
  }
  var alg = algForJwk(o.attester.privateJwk);
  var signed = await jws.signJwsAsync({
    algId: alg.algId,
    protectedHeader: { alg: alg.alg, typ: VERIFIER_ATTESTATION_TYP,
                       kid: o.attester.publicJwk.kid },
    payload: payload,
    privateKey: { jwk: o.attester.privateJwk },
    backend: "js"
  });
  log.debug("Leaving verifierAttestation().");
  return signed.serialized;
}

// The key a direct_post.jwt answer is encrypted to: P-256, ECDH-ES, pure JS.
async function responseEncryptionKey() {
  log.debug("Entering responseEncryptionKey().");
  var priv = p256.utils.randomPrivateKey();
  var pub = p256.getPublicKey(priv, false);
  var pj = jws.publicJwk("ES256", pub);
  var publicJwk = { kty: pj.kty, crv: pj.crv, x: pj.x, y: pj.y };
  publicJwk.kid = jwkThumbprint(publicJwk);
  publicJwk.use = "enc";
  publicJwk.alg = "ECDH-ES";
  var privateJwk = Object.assign({}, publicJwk,
                                 { d: bytes.bytesToB64u(priv) });
  log.debug("Leaving responseEncryptionKey(). kid=" + publicJwk.kid);
  return { privateJwk: privateJwk, publicJwk: publicJwk };
}

// What this Verifier can read, per format (OpenID4VP 1.0 section 11.1 and
// Appendix B).
//
// SD-JWT VC's two lists are FULLY-SPECIFIED identifiers (#468, M7). Appendix
// B.3.4: sd-jwt_alg_values and kb-jwt_alg_values are each "a non-empty array
// containing fully-specified identifiers of cryptographic algorithms (as
// defined in [I-D.ietf-jose-fully-specified-algorithms])". "EdDSA" is the
// polymorphic one that draft deprecates (the curve is in the key); its
// fully-specified Ed25519 form is "Ed25519". ES256 and ES384 already name one
// curve each. jwt_vc_json's alg_values is only "identifiers of
// cryptographic algorithms" the JOSE alg header "MUST match" (B.1.3.1.3),
// so it lists both spellings of Ed25519: an issuer may write either.
function vpFormatsSupported() {
  log.debug("Entering vpFormatsSupported().");
  log.debug("Leaving vpFormatsSupported().");
  return {
    "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256", "ES384", "Ed25519"],
                   "kb-jwt_alg_values": ["ES256", "ES384", "Ed25519"] },
    "jwt_vc_json": { alg_values: ["ES256", "ES384", "EdDSA", "Ed25519"] },
    // Every COSE algorithm mdoc.js verifies (#469, C8): -7 and -9 (HAIP
    // 1.0 section 7), and the P-384, P-521 and EdDSA ones beside them.
    "mso_mdoc": { issuerauth_alg_values: mdoc.COSE_SIGNATURE_ALG_IDS.slice(),
                  deviceauth_alg_values: mdoc.COSE_SIGNATURE_ALG_IDS.slice() },
    "ldp_vc": { proof_type_values: ["DataIntegrityProof"],
                cryptosuite_values: ["bbs-2023", "ecdsa-rdfc-2019",
                                     "ecdsa-jcs-2019", "eddsa-rdfc-2022",
                                     "eddsa-jcs-2022"] }
  };
}

function isDcApiMode(mode) {
  log.debug("Entering isDcApiMode().");
  log.debug("Leaving isDcApiMode().");
  return mode === "dc_api" || mode === "dc_api.jwt";
}

function isEncryptedMode(mode) {
  log.debug("Entering isEncryptedMode().");
  log.debug("Leaving isEncryptedMode().");
  return mode === "direct_post.jwt" || mode === "dc_api.jwt";
}

// The Authorization Request's parameters (the Request Object's claims when
// it is signed).
//
// Over the Digital Credentials API (responseMode dc_api or dc_api.jwt) a
// request with no clientId, or an origin: one, is UNSIGNED: Appendix A.2 has
// the wallet take the effective Client Identifier from the Origin the
// browser reports, so client_id is omitted, and there is no response_uri and
// no state (the DC API defines neither). A request with a clientId is
// SIGNED, and then expected_origins is REQUIRED (A.2), the wallet comparing
// it to the Origin to detect a replayed request.
//
// opts.walletNonce: the wallet_nonce a wallet sent with request_uri_method
// post (section 5.10), echoed so the wallet can tell this object was made
// for its request.
function requestObjectClaims(opts) {
  log.debug("Entering requestObjectClaims().");
  var o = opts || {};
  var mode = o.responseMode || "direct_post";
  if (RESPONSE_MODES.indexOf(mode) === -1) {
    log.debug("Leaving requestObjectClaims(). Bad mode.");
    throw new Error('response_mode "' + mode + '" is not one this ' +
                    "Verifier receives (" + RESPONSE_MODES.join(", ") +
                    ").");
  }
  var dc = isDcApiMode(mode);
  var prefix = vpProtocols.clientIdPrefix(o.clientId).prefix;
  if (prefix === "openid_federation") {
    log.debug("Leaving requestObjectClaims(). Federation.");
    throw new Error(FEDERATION_NOTE);
  }
  if (prefix === "origin" && !dc) {
    log.debug("Leaving requestObjectClaims(). origin outside the DC API.");
    throw new Error("the origin Client Identifier prefix exists only for " +
                    "unsigned requests over the Digital Credentials API, " +
                    "and a Verifier never sends it (section 5.9.3).");
  }
  var unsigned = dc && (!o.clientId || prefix === "origin");
  var origins = isArray(o.expectedOrigins) ? o.expectedOrigins.filter(
    function (x) {
      return typeof x === "string" && x.length > 0;
    }) : [];
  if (dc && !unsigned && !origins.length) {
    log.debug("Leaving requestObjectClaims(). No expected_origins.");
    throw new Error("a signed request over the Digital Credentials API " +
                    "needs expected_origins (OpenID4VP 1.0 Appendix A.2).");
  }
  var iat = nowSeconds(o.now);
  var claims = {};
  if (!unsigned) {
    if (prefix === "x509_hash" || prefix === "x509_san_dns") {
      claims.iss = o.clientId;
    }
    claims.client_id = o.clientId;
    claims.aud = REQUEST_AUD;
  }
  if (dc && !unsigned) claims.expected_origins = origins;
  claims.response_type = "vp_token";
  claims.response_mode = mode;
  if (!dc) claims.response_uri = o.responseUri;
  claims.nonce = o.nonce;
  if (o.state && !dc) claims.state = o.state;
  claims.dcql_query = o.dcql;
  if (o.walletNonce) claims.wallet_nonce = String(o.walletNonce);
  if (!unsigned) {
    claims.iat = iat;
    claims.exp = iat + (o.ttlSeconds || DEFAULT_TTL_SECONDS);
  }
  var metadata = { vp_formats_supported: vpFormatsSupported() };
  if (isEncryptedMode(mode)) {
    if (!o.encryptionJwk) {
      log.debug("Leaving requestObjectClaims(). No encryption key.");
      throw new Error(mode + " needs an encryption key.");
    }
    metadata.jwks = { keys: [publicPart(o.encryptionJwk)] };
    metadata.encrypted_response_enc_values_supported =
      (o.encValuesSupported || DEFAULT_ENC_VALUES).slice();
  }
  claims.client_metadata = metadata;
  log.debug("Leaving requestObjectClaims(). " + (unsigned ? "unsigned" :
            "to be signed"));
  return claims;
}

// The signed Request Object, its JOSE header chosen by the Client
// Identifier's prefix (section 5.9.3):
//
//   x509_hash, x509_san_dns   x5c: the leaf
//   decentralized_identifier  kid: a DID URL naming the DID's key; no x5c.
//                             The key must be the one the DID names.
//   verifier_attestation      jwt: a Verifier Attestation JWT whose cnf.jwk
//                             is the signing key (opts.attestation, or one
//                             made from opts.attester)
//   pre-registered            kid: the key's thumbprint; no x5c. The wallet
//                             holds preRegisteredJwks().
//   redirect_uri              REFUSED (#469, C17). Section 5.9.3:
//                             "Requests using the redirect_uri Client
//                             Identifier Prefix cannot be signed because
//                             there is no method for the Wallet to obtain a
//                             trusted key for verification." The page sends
//                             them unsigned, by value.
async function signRequestObject(opts) {
  log.debug("Entering signRequestObject().");
  var o = opts || {};
  var claims = o.claims || {};
  var identity = o.identity || {};
  if (!claims.client_id) {
    log.debug("Leaving signRequestObject(). No client_id.");
    throw new Error("a request with no client_id is an unsigned DC API " +
                    "request; there is nothing to sign it as.");
  }
  if (!identity.privateJwk) {
    log.debug("Leaving signRequestObject(). No key.");
    throw new Error("signing a Request Object needs identity.privateJwk.");
  }
  var who = vpProtocols.clientIdPrefix(claims.client_id);
  var alg = algForJwk(identity.privateJwk);
  if (o.algId) {
    // An alg chosen for this wallet (planForWalletMetadata()): it must be
    // one this key signs with.
    if (signingAlgsFor(identity.privateJwk).indexOf(o.algId) === -1) {
      log.debug("Leaving signRequestObject(). Key cannot sign " + o.algId);
      throw new Error("this Verifier's request key (" +
                      (identity.privateJwk.crv || "?") + ") cannot sign " +
                      o.algId + ".");
    }
    alg = { algId: o.algId === "EdDSA" ? "EdDSA-Ed25519" : o.algId,
            alg: o.algId };
  }
  var header = { alg: alg.alg, typ: REQUEST_TYP };
  if (who.prefix === "openid_federation") {
    log.debug("Leaving signRequestObject(). Federation.");
    throw new Error(FEDERATION_NOTE);
  }
  if (who.prefix === "origin") {
    log.debug("Leaving signRequestObject(). origin.");
    throw new Error("an origin: Client Identifier is never signed.");
  }
  if (who.prefix === "redirect_uri") {
    log.debug("Leaving signRequestObject(). redirect_uri.");
    throw new Error("a redirect_uri: Client Identifier is never signed: " +
                    "OpenID4VP 1.0 section 5.9.3, \"Requests using the " +
                    "redirect_uri Client Identifier Prefix cannot be " +
                    "signed because there is no method for the Wallet to " +
                    "obtain a trusted key for verification.\" Send it " +
                    "unsigned, by value.");
  }
  if (who.prefix === "x509_hash" || who.prefix === "x509_san_dns") {
    if (!isArray(identity.x5c) || !identity.x5c.length) {
      log.debug("Leaving signRequestObject(). No x5c.");
      throw new Error(who.prefix + " needs a certificate (x5c).");
    }
    header.x5c = identity.x5c;
  } else if (who.prefix === "decentralized_identifier") {
    var named = keyOfLocalDid(who.value);
    if (named && !sameKey(named, identity.publicJwk)) {
      log.debug("Leaving signRequestObject(). Not the DID's key.");
      throw new Error(who.value + " names another key than the one this " +
                      "request would be signed with.");
    }
    header.kid = o.kid || didKidFor(who.value);
  } else if (who.prefix === "verifier_attestation") {
    header.jwt = o.attestation || await verifierAttestation({
      attester: o.attester, identity: identity, sub: who.value,
      now: o.now, redirectUris: o.redirectUris });
  } else if (who.prefix === "") {
    header.kid = preRegisteredJwks(identity).keys[0].kid;
  }
  var signed = await jws.signJwsAsync({
    algId: alg.algId,
    protectedHeader: header,
    payload: claims,
    privateKey: { jwk: identity.privateJwk },
    backend: "js"
  });
  log.debug("Leaving signRequestObject(). " + (who.prefix ||
            "pre-registered"));
  return signed.serialized;
}

// The JWS alg values a request key signs with, preferred first: P-256 and
// P-384 one each; Ed25519 both its fully-specified name and RFC 8037's
// polymorphic "EdDSA" (draft-ietf-jose-fully-specified-algorithms).
function signingAlgsFor(jwk) {
  log.debug("Entering signingAlgsFor().");
  var crv = String((jwk && jwk.crv) || "");
  var out = crv === "P-384" ? ["ES384"]
          : crv === "Ed25519" ? ["Ed25519", "EdDSA"]
          : ["ES256"];
  log.debug("Leaving signingAlgsFor(). " + out.join(","));
  return out;
}

// The key management alg a Verifier uses to encrypt to a wallet's key:
// the key's own `alg` when this tree performs it, else ECDH-ES for an EC or
// OKP key and RSA-OAEP-256 for an RSA one. "" when none fits.
function requestEncAlgFor(key, listed) {
  log.debug("Entering requestEncAlgFor().");
  var can = joseJwe.supportedAlgs();
  var wanted = isArray(listed) && listed.length ? listed : null;
  var byKty = key.kty === "RSA" ? ["RSA-OAEP-256", "RSA-OAEP"]
            : key.kty === "EC" || key.kty === "OKP"
              ? ["ECDH-ES", "ECDH-ES+A256KW", "ECDH-ES+A128KW"] : [];
  var candidates = key.alg ? [key.alg] : byKty;
  var out = candidates.filter(function (a) {
    return can.indexOf(a) !== -1 && (!wanted || wanted.indexOf(a) !== -1);
  })[0] || "";
  log.debug("Leaving requestEncAlgFor(). " + (out || "none"));
  return out;
}

// HONOURING wallet_metadata (OpenID4VP 1.0 section 5.10), for a Request
// Object signed live for a wallet that POSTed to request_uri. `meta` is
// what the wallet sent (parsed, or the text that arrived); `ctx` is
// { keyJwk, prefix, formats, responseMode, responseAlg, encValues }.
//
// Answers { signAlg, encryptTo, requestEncAlg, requestEnc, encValues,
// findings }. Each finding is { level: "ok" | "warn", text }, for the page
// to show: none of them refuses the wallet, because section 5.10 gives the
// Verifier no MUST to apply to what the wallet lists.
//
//   request_object_signing_alg_values_supported  sign with the first alg the
//       key can make that the wallet lists; when there is none, sign with
//       the key's own and say so. ("the Wallet SHOULD list supported
//       cryptographic algorithms for securing the Request Object")
//   jwks  encrypt the Request Object, signed then encrypted (RFC 9101
//       section 4), to the first key that is not use "sig" and that this
//       tree can encrypt to, by request_object_encryption_alg/enc
//       _values_supported when listed (RFC 9101 section 4, RFC 8414). ("If
//       the Wallet requires the Verifier to encrypt the Request Object, it
//       SHOULD use the jwks parameter within the wallet_metadata")
//   authorization_encryption_alg/enc_values_supported  the response
//       encryption offered in client_metadata is narrowed to the enc values
//       both sides do; an alg the wallet does not list is reported.
//   client_id_prefixes_supported, vp_formats_supported  reported when the
//       request's prefix or a requested format is not among them.
function planForWalletMetadata(meta, ctx) {
  log.debug("Entering planForWalletMetadata().");
  var c = ctx || {};
  var findings = [];
  var keyAlgs = signingAlgsFor(c.keyJwk);
  var plan = { signAlg: keyAlgs[0], encryptTo: null, requestEncAlg: "",
               requestEnc: "", encValues: (c.encValues ||
                 DEFAULT_ENC_VALUES).slice(), findings: findings };
  var m = meta;
  if (typeof m === "string") {
    try {
      m = JSON.parse(m);
    } catch (e) {
      findings.push({ level: "warn", text: "wallet_metadata is not JSON, " +
        "so nothing in it could be honoured." });
      log.debug("Leaving planForWalletMetadata(). Not JSON.");
      return plan;
    }
  }
  if (!m || typeof m !== "object" || isArray(m)) {
    if (m !== undefined && m !== null) {
      findings.push({ level: "warn", text: "wallet_metadata is not a JSON " +
        "object, so nothing in it could be honoured." });
    }
    log.debug("Leaving planForWalletMetadata(). Nothing sent.");
    return plan;
  }
  var signing = m.request_object_signing_alg_values_supported;
  if (isArray(signing)) {
    var pick = keyAlgs.filter(function (a) {
      return signing.indexOf(a) !== -1;
    })[0];
    if (pick) {
      plan.signAlg = pick;
      findings.push({ level: "ok", text: "signed with " + pick + ", which " +
        "the wallet lists in request_object_signing_alg_values_supported." });
    } else {
      findings.push({ level: "warn", text: "the wallet lists " +
        JSON.stringify(signing) + " in request_object_signing_alg_values" +
        "_supported, and this Verifier's request key signs only " +
        keyAlgs.join(" or ") + "; signed with " + keyAlgs[0] + " anyway." });
    }
  }
  var keys = m.jwks && isArray(m.jwks.keys) ? m.jwks.keys : null;
  if (m.jwks !== undefined && !keys) {
    findings.push({ level: "warn", text: "wallet_metadata.jwks has no keys " +
      "array, so the Request Object is not encrypted." });
  }
  if (keys) {
    var algList = m.request_object_encryption_alg_values_supported;
    var encList = m.request_object_encryption_enc_values_supported;
    var to = keys.filter(function (k) {
      return k && typeof k === "object" && k.use !== "sig" &&
        !!requestEncAlgFor(k, algList);
    })[0];
    if (!to) {
      findings.push({ level: "warn", text: "wallet_metadata.jwks carries " +
        keys.length + " key(s) and none is one this Verifier can encrypt " +
        "to" + (isArray(algList) ? " under " + JSON.stringify(algList) :
        "") + ", so the Request Object is sent signed only." });
    } else {
      var encCan = joseJwe.supportedEncs();
      var enc = (isArray(encList) ? encList : ["A256GCM"])
        .filter(function (e) {
          return encCan.indexOf(e) !== -1;
        })[0];
      if (!enc) {
        findings.push({ level: "warn", text: "the wallet's request_object_" +
          "encryption_enc_values_supported " + JSON.stringify(encList) +
          " names no content encryption this Verifier performs, so the " +
          "Request Object is sent signed only." });
      } else {
        plan.encryptTo = to;
        plan.requestEncAlg = requestEncAlgFor(to, algList);
        plan.requestEnc = enc;
        findings.push({ level: "ok", text: "the Request Object is signed " +
          "then encrypted (RFC 9101 section 4) to the wallet's key" +
          (to.kid ? " " + to.kid : "") + " with " + plan.requestEncAlg +
          " / " + enc + "." });
      }
    }
  }
  if (c.responseMode === "direct_post.jwt" || c.responseMode ===
      "dc_api.jwt") {
    var rAlgs = m.authorization_encryption_alg_values_supported;
    var rEncs = m.authorization_encryption_enc_values_supported;
    if (isArray(rAlgs) && c.responseAlg &&
        rAlgs.indexOf(c.responseAlg) === -1) {
      findings.push({ level: "warn", text: "the response is to be " +
        "encrypted with " + c.responseAlg + ", which the wallet does not " +
        "list in authorization_encryption_alg_values_supported " +
        JSON.stringify(rAlgs) + "." });
    }
    if (isArray(rEncs)) {
      var both = plan.encValues.filter(function (e) {
        return rEncs.indexOf(e) !== -1;
      });
      if (both.length) {
        plan.encValues = both;
        findings.push({ level: "ok", text: "encrypted_response_enc_values" +
          "_supported narrowed to " + JSON.stringify(both) + ", the values " +
          "both sides do." });
      } else {
        findings.push({ level: "warn", text: "the wallet's authorization_" +
          "encryption_enc_values_supported " + JSON.stringify(rEncs) +
          " shares nothing with this Verifier's " +
          JSON.stringify(plan.encValues) + ", which are offered unchanged." });
      }
    }
  }
  var prefixes = m.client_id_prefixes_supported;
  var mine = c.prefix || "pre-registered";
  if (isArray(prefixes) && prefixes.indexOf(mine) === -1) {
    findings.push({ level: "warn", text: "the wallet's client_id_prefixes" +
      "_supported " + JSON.stringify(prefixes) + " does not include " +
      mine + ", the prefix this request uses." });
  }
  var formats = m.vp_formats_supported;
  if (formats && typeof formats === "object") {
    (c.formats || []).forEach(function (f) {
      if (!Object.prototype.hasOwnProperty.call(formats, f)) {
        findings.push({ level: "warn", text: "the request asks for " + f +
          ", which is not in the wallet's vp_formats_supported (" +
          Object.keys(formats).join(", ") + ")." });
      }
    });
  }
  log.debug("Leaving planForWalletMetadata(). " + findings.length +
            " finding(s).");
  return plan;
}

// A signed Request Object encrypted to a wallet's key (RFC 9101 section 4:
// "the JWT MUST be signed, then encrypted"): a Nested JWT, so cty is "JWT"
// (RFC 7519 section 5.2). The five-segment compact JWE.
async function encryptRequestObject(jwsCompact, plan) {
  log.debug("Entering encryptRequestObject().");
  var header = { cty: "JWT" };
  if (plan.encryptTo.kid) {
    header.kid = plan.encryptTo.kid;
  }
  var sealed = await joseJwe.encryptCompact({
    alg: plan.requestEncAlg, enc: plan.requestEnc, plaintext: jwsCompact,
    key: plan.encryptTo, header: header });
  log.debug("Leaving encryptRequestObject(). " + sealed.jwe.length);
  return sealed.jwe;
}

// The request handed to navigator.credentials.get({ digital: { requests:
// [ <this> ] } }) (OpenID4VP 1.0 Appendix A.3).
//
//   unsigned  { protocol: "openid4vp-v1-unsigned", data: <the parameters> }
//             client_id and expected_origins are left out (A.2).
//   signed    { protocol: "openid4vp-v1-signed",
//               data: { request: <compact JWS> } }
//             `origin`, when given, must be one of expected_origins.
//
// openid4vp-v1-multisigned (a JWS JSON serialization with one signature per
// Client Identifier) is refused: this debugger is one Verifier.
async function dcApiRequest(opts) {
  log.debug("Entering dcApiRequest().");
  var o = opts || {};
  var claims = o.claims || {};
  if (!isDcApiMode(claims.response_mode)) {
    log.debug("Leaving dcApiRequest(). Wrong mode.");
    throw new Error("a Digital Credentials API request has response_mode " +
                    "dc_api or dc_api.jwt, not " +
                    JSON.stringify(claims.response_mode) + ".");
  }
  if (o.multisigned) {
    log.debug("Leaving dcApiRequest(). Multisigned.");
    throw new Error(DC_API_PROTOCOLS.multisigned + " is not built by this " +
                    "debugger: it signs as one Verifier.");
  }
  if (o.origin && !/^[a-z][a-z0-9+.-]*:\/\/[^/?#]+$/i.test(o.origin)) {
    log.debug("Leaving dcApiRequest(). Bad origin.");
    throw new Error(JSON.stringify(o.origin) + " is not an origin " +
                    "(scheme://host[:port], no path).");
  }
  if (!o.signed) {
    var data = Object.assign({}, claims);
    ["client_id", "iss", "aud", "expected_origins", "iat", "exp",
     "response_uri", "state"].forEach(function (k) {
      delete data[k];
    });
    log.debug("Leaving dcApiRequest(). Unsigned.");
    return { protocol: DC_API_PROTOCOLS.unsigned, data: data };
  }
  var origins = claims.expected_origins || [];
  if (!isArray(origins) || !origins.length) {
    log.debug("Leaving dcApiRequest(). No expected_origins.");
    throw new Error("a signed DC API request carries expected_origins.");
  }
  if (o.origin && origins.indexOf(o.origin) === -1) {
    log.debug("Leaving dcApiRequest(). Origin not expected.");
    throw new Error("this page's origin " + o.origin + " is not in " +
                    "expected_origins (" + origins.join(", ") + "), so " +
                    "every wallet would refuse the request.");
  }
  var compact = await signRequestObject({ claims: claims,
    identity: o.identity, attester: o.attester, attestation: o.attestation,
    kid: o.kid, now: o.now });
  log.debug("Leaving dcApiRequest(). Signed.");
  return { protocol: DC_API_PROTOCOLS.signed, data: { request: compact } };
}

function encodeParam(name, value) {
  log.debug("Entering encodeParam(). " + name);
  log.debug("Leaving encodeParam().");
  return encodeURIComponent(name) + "=" + encodeURIComponent(
    typeof value === "string" ? value : JSON.stringify(value));
}

// The Authorization Request a Wallet is handed. opts: scheme, clientId,
// requestUri (+ requestUriMethod) or requestObject, params (the unsigned
// request's parameters), and clientMetadata.
//
// clientMetadata goes BESIDE request_uri when requestUriMethod is post
// (#468, M8). Section 5.1: "If the Verifier set the request_uri_method
// parameter value to post and there is no other means to convey its
// capabilities to the Wallet, it SHOULD add the client_metadata parameter
// to the Authorization Request", so that the Wallet can choose what to put
// in wallet_metadata. Under get there is nothing for it to choose, and the
// Request Object carries the same metadata, so it is not added.
function authorizationRequestUri(opts) {
  log.debug("Entering authorizationRequestUri().");
  var o = opts || {};
  var scheme = o.scheme || "openid4vp://";
  var pairs = [];
  if (o.clientId) pairs.push(encodeParam("client_id", o.clientId));
  if (o.requestUri) {
    pairs.push(encodeParam("request_uri", o.requestUri));
    if (o.requestUriMethod) {
      pairs.push(encodeParam("request_uri_method", o.requestUriMethod));
    }
    if (o.requestUriMethod === "post" && isPlainObject(o.clientMetadata)) {
      pairs.push(encodeParam("client_metadata", o.clientMetadata));
    }
  } else if (o.requestObject) {
    pairs.push(encodeParam("request", o.requestObject));
  }
  var params = o.params || {};
  Object.keys(params).forEach(function (k) {
    if (k === "client_id" && o.clientId) return;
    if (params[k] === undefined || params[k] === null) return;
    pairs.push(encodeParam(k, params[k]));
  });
  var join = scheme.indexOf("?") === -1 ? "?" :
      (/[?&]$/.test(scheme) ? "" : "&");
  log.debug("Leaving authorizationRequestUri().");
  return scheme + join + pairs.join("&");
}

// ---------------------------------------------------------------------------
// Reading what the Wallet posted.
// ---------------------------------------------------------------------------
function fieldsOf(input) {
  log.debug("Entering fieldsOf().");
  var out = {};
  if (input === null || input === undefined) {
    log.debug("Leaving fieldsOf(). Nothing.");
    return out;
  }
  if (typeof input === "string" || (typeof URLSearchParams !== "undefined" &&
      input instanceof URLSearchParams)) {
    var sp = typeof input === "string" ?
        new URLSearchParams(input.replace(/^\?/, "")) : input;
    sp.forEach(function (v, k) {
      out[k] = v;
    });
    log.debug("Leaving fieldsOf(). Form.");
    return out;
  }
  Object.keys(input).forEach(function (k) {
    out[k] = input[k];
  });
  log.debug("Leaving fieldsOf(). Object.");
  return out;
}

function parseResponse(input) {
  log.debug("Entering parseResponse().");
  var raw = fieldsOf(input);
  var vpToken = raw.vp_token;
  var vpTokenError = "";
  if (typeof vpToken === "string") {
    try {
      vpToken = JSON.parse(vpToken);
    } catch (e) {
      vpTokenError = "vp_token is not JSON: " + e.message;
    }
  }
  log.debug("Leaving parseResponse().");
  return {
    vpToken: vpToken,
    vpTokenError: vpTokenError,
    state: raw.state,
    response: raw.response,
    idToken: raw.id_token,
    error: raw.error,
    errorDescription: raw.error_description,
    raw: raw
  };
}

// ---------------------------------------------------------------------------
// The report.
// ---------------------------------------------------------------------------
// `essential` marks a check that establishes AUTHENTICITY — an issuer
// signature or proof, the trust in an x5c chain, a holder or device
// signature the query depends on. A SKIP of one is a check not performed,
// and finish() will not call such a result a pass (#467, S4).
function addCheck(report, id, group, label, status, detail, essential) {
  log.debug("Entering addCheck(). " + id + " " + status);
  report.checks.push({ id: id, group: group, label: label, status: status,
                       detail: detail || "", essential: !!essential });
  log.debug("Leaving addCheck().");
}

function scope(report, group, prefix) {
  log.debug("Entering scope(). " + prefix);
  log.debug("Leaving scope().");
  return {
    report: report, group: group, prefix: prefix,
    add: function add(key, label, status, detail, essential) {
      log.debug("Entering add(). " + prefix + key);
      addCheck(report, prefix + key, group, label, status, detail,
               essential);
      log.debug("Leaving add().");
    }
  };
}

// The validity window: nbf and exp (and an iat not in the future).
function validityVerdict(win, iat, now) {
  log.debug("Entering validityVerdict().");
  var problems = [];
  if (win.expires !== null && win.expires !== undefined &&
      now > win.expires + SKEW_SECONDS) {
    problems.push(win.expiresMember + " " +
                  new Date(win.expires * 1000).toISOString() + " has passed");
  }
  if (win.notBefore !== null && win.notBefore !== undefined &&
      now + SKEW_SECONDS < win.notBefore) {
    problems.push(win.notBeforeMember + " " +
                  new Date(win.notBefore * 1000).toISOString() +
                  " is still in the future");
  }
  if (typeof iat === "number" && now + SKEW_SECONDS < iat) {
    problems.push("iat is in the future");
  }
  log.debug("Leaving validityVerdict(). " + problems.length + " problem(s).");
  return problems.length ?
    { status: FAIL, detail: problems.join("; ") + "." } :
    { status: PASS, detail: "within its validity window" +
      (win.expires ? " (until " + new Date(win.expires * 1000)
        .toISOString() + ")" : ", which has no end") + "." };
}

// A fetchJson()-backed fetch, for did.js, which wants a Response.
function fetchAdapter(fetchJson) {
  log.debug("Entering fetchAdapter().");
  log.debug("Leaving fetchAdapter().");
  return function (url) {
    return Promise.resolve(fetchJson(url)).then(function (json) {
      var text = typeof json === "string" ? json : JSON.stringify(json);
      return { ok: true, status: 200, text: function () {
        return Promise.resolve(text);
      } };
    });
  };
}

// SD-JWT VC section 5: the well-known segment goes between the host and the
// issuer identifier's path.
function jwtVcIssuerUrl(iss) {
  log.debug("Entering jwtVcIssuerUrl().");
  var u = new URL(iss);
  var path = u.pathname === "/" ? "" : u.pathname.replace(/\/$/, "");
  log.debug("Leaving jwtVcIssuerUrl().");
  return u.origin + JWT_VC_ISSUER_WELL_KNOWN + path;
}

// The members that make a public key, and nothing else: what a signature is
// verified with, so a stray use, alg or kid on a document's key cannot
// refuse a signature the key itself verifies.
function keyMembers(jwk) {
  log.debug("Entering keyMembers().");
  var out = {};
  ["kty", "crv", "x", "y", "n", "e"].forEach(function (k) {
    if (jwk && jwk[k] !== undefined) out[k] = jwk[k];
  });
  log.debug("Leaving keyMembers().");
  return out;
}

// Does a key named `id` answer to a JWS header's `kid` (#469, C7)? `id` is
// a verification method's id — absolute ("did:web:x#key-1") or relative
// ("#key-1"), both legal in a DID document — or a publicKeyJwk's own kid;
// `kid` is a DID URL, a relative "#key-1" or a bare fragment. Under `did`
// all of those name the same method. Without a DID (an https issuer's
// JWK Set) only the exact kid does.
function kidNames(id, kid, did) {
  log.debug("Entering kidNames().");
  var a = String(id || "");
  var k = String(kid || "");
  if (!a || !k) {
    log.debug("Leaving kidNames(). Nothing to compare.");
    return false;
  }
  if (a === k) {
    log.debug("Leaving kidNames(). Exact.");
    return true;
  }
  if (!did) {
    log.debug("Leaving kidNames(). No DID.");
    return false;
  }
  var abs = function absolute(x) {
    log.debug("Entering absolute().");
    log.debug("Leaving absolute().");
    return x.charAt(0) === "#" ? did + x : x;
  };
  var frag = k.indexOf(did + "#") === 0 ? k.slice(did.length + 1) :
      k.charAt(0) === "#" ? k.slice(1) :
      (!didLib.isDid(k) && k.indexOf("#") === -1 ? k : "");
  var named = abs(a) === abs(k) || (!!frag && (abs(a) === did + "#" + frag ||
                                               a === frag));
  log.debug("Leaving kidNames(). " + named);
  return named;
}

// A DID's assertion keys (#469, C7): each with every name it answers to —
// its verification method id and its publicKeyJwk's own kid — so the
// header's kid can be matched the way keyForDidUrl() and did.js
// keyForKid() match it. A did:jwk or did:key IS one key, and whatever
// fragment the kid carries names it.
async function didJwks(did, fetchJson) {
  log.debug("Entering didJwks().");
  var base = String(did).split("#")[0];
  var jwk = sdJwtVc.jwkFromDid(base);
  if (jwk) {
    log.debug("Leaving didJwks(). did:jwk.");
    return { jwks: { keys: [jwk] }, from: "the did:jwk itself", did: base,
             candidates: [{ jwk: keyMembers(jwk), ids: [], any: true }] };
  }
  var res = await didLib.resolve(base,
    { fetch: fetchJson ? fetchAdapter(fetchJson) : undefined });
  var single = /^did:key:/.test(base);
  var candidates = [];
  didLib.assertionKeys(res.document).forEach(function (m) {
    if (!m || !m.jwk) return;
    candidates.push({ jwk: keyMembers(m.jwk), any: single,
                      ids: [m.id, m.jwk.kid].filter(Boolean) });
  });
  var converted = didLib.assertionJwks(res.document);
  log.debug("Leaving didJwks(). " + candidates.length + " key(s).");
  return { jwks: converted.jwks, from: res.from, did: base,
           candidates: candidates };
}

// An error that means "no key could be had" rather than "the credential is
// wrong" (#469 B2, #467 B3's reporting half): a fetch that failed, a DID
// that did not resolve, an issuer with no route to its keys. The issuer
// signature is then a SKIP — not performed, essential, so the verdict is
// incomplete — and never a signature FAIL.
function unresolved(message) {
  log.debug("Entering unresolved().");
  var e = new Error(message);
  e.unresolved = true;
  log.debug("Leaving unresolved().");
  return e;
}

// /.well-known/jwt-vc-issuer, SD-JWT VC section 4. For a dc+sd-jwt it is
// THE key discovery route of an https iss, and its rules are MUSTs (section
// 4.3: the issuer value must be identical to iss), so a document that
// breaks them is a FAIL. For jwt_vc_json no specification defines it
// (#469, B2): it is tried as one route among several, and anything short
// of keys from it is "could not resolve the issuer's key", not a forgery.
async function issuerMetadataKeys(iss, kidDid, fetchJson, jwtVc) {
  log.debug("Entering issuerMetadataKeys().");
  var why = jwtVc ? " (SD-JWT VC's JWT VC Issuer Metadata, tried for " +
    "jwt_vc_json as one route; no jwt_vc_json specification defines it)" :
    "";
  if (!fetchJson) {
    log.debug("Leaving issuerMetadataKeys(). No fetch.");
    throw unresolved("no fetchJson was given to read " + iss + "'s keys.");
  }
  var url = jwtVcIssuerUrl(iss);
  var meta;
  try {
    meta = await fetchJson(url);
  } catch (e) {
    log.debug("Leaving issuerMetadataKeys(). Fetch failed.");
    throw unresolved("could not fetch " + url + why + ": " + e.message);
  }
  if (!meta || meta.issuer !== iss) {
    var wrong = url + " names issuer " + JSON.stringify(meta &&
      meta.issuer) + ", not " + iss + " (SD-JWT VC section 4.3)" + why + ".";
    log.debug("Leaving issuerMetadataKeys(). Wrong issuer.");
    throw jwtVc ? unresolved(wrong) : new Error(wrong);
  }
  var jwks = meta.jwks || null;
  if (!jwks && meta.jwks_uri) {
    try {
      jwks = await fetchJson(meta.jwks_uri);
    } catch (e) {
      log.debug("Leaving issuerMetadataKeys(). jwks_uri failed.");
      throw unresolved("could not fetch " + meta.jwks_uri + " (the " +
                       "jwks_uri of " + url + "): " + e.message);
    }
  }
  if (!jwks || !isArray(jwks.keys)) {
    var none = url + " carries neither jwks nor a jwks_uri that answers " +
      "with keys" + why + ".";
    log.debug("Leaving issuerMetadataKeys(). No keys.");
    throw jwtVc ? unresolved(none) : new Error(none);
  }
  log.debug("Leaving issuerMetadataKeys(). Metadata.");
  return { key: jwks, from: (meta.jwks ? url : meta.jwks_uri) +
           (kidDid ? " (the DID in kid, " + kidDid + ", is not the " +
            "issuer and was not used)" : "") };
}

// Where an issuer's key is: the x5c leaf, else the DID the issuer IS, else
// /.well-known/jwt-vc-issuer under an https issuer (SD-JWT VC section 2.5,
// the two key discovery mechanisms). jwt_vc_json (`opts.format`) takes the
// same routes in that order, but its metadata route is not its own
// specification's (#469, B2; see issuerMetadataKeys()).
//
// The header's kid NEVER chooses the issuer (#467, S1). Until then a DID in
// kid was resolved whenever iss was not a DID, so an SD-JWT VC claiming
// iss https://gov.example and signed by ANY did:jwk the attacker named in
// kid verified "with the key from the did:jwk itself". A DID in kid is used
// only when iss IS that DID; an https iss gets its keys from its own
// metadata, and an x5c chain's trust is reported by x5cTrust().
//
// A thrown error with `unresolved` set means no key could be had (#469):
// the caller reports a SKIP, not a signature FAIL.
async function issuerKey(header, payload, fetchJson, opts) {
  log.debug("Entering issuerKey().");
  var jwtVc = !!(opts && opts.format === FORMAT_JWT_VC_JSON);
  if (isArray(header.x5c) && header.x5c.length) {
    // A Status List Token's own x5c gets no trust row of its own: the
    // `<key>.signer` row (#466 S5) passes only a signer LINKED to the
    // credential's issuer (the same key, or the same CA chain with the
    // status-signing EKU), and the credential's `issuer.trust` row reports
    // whether that issuer's chain is trusted. An unlinked signer is SKIP.
    log.debug("Leaving issuerKey(). x5c.");
    return { key: bytes.derToPem(bytes.b64ToBytes(header.x5c[0]),
                                 "CERTIFICATE"),
             x5c: header.x5c,
             from: "the x5c leaf certificate in its header" };
  }
  var iss = String(payload.iss || issuerIdOf(payload.vc) || "");
  var kid = String(header.kid || "");
  var kidDid = didLib.isDid(kid) ? kid.split("#")[0] : "";
  if (didLib.isDid(iss)) {
    if (kidDid && kidDid !== iss.split("#")[0]) {
      log.debug("Leaving issuerKey(). kid names another DID.");
      throw new Error("kid " + kid + " names a DID that is not the " +
                      "issuer " + iss + "; a kid never chooses the issuer.");
    }
    var found;
    try {
      found = await didJwks(iss, fetchJson);
    } catch (e) {
      log.debug("Leaving issuerKey(). DID unresolved.");
      throw unresolved("the issuer's DID " + iss + " could not be " +
                       "resolved: " + e.message);
    }
    log.debug("Leaving issuerKey(). DID.");
    return { key: found.jwks, from: found.from, did: found.did,
             candidates: found.candidates };
  }
  if (/^https:\/\//.test(iss)) {
    var meta = await issuerMetadataKeys(iss, kidDid, fetchJson, jwtVc);
    log.debug("Leaving issuerKey(). Metadata.");
    return meta;
  }
  if (kidDid) {
    log.debug("Leaving issuerKey(). DID kid without a DID iss.");
    throw unresolved("kid names " + kidDid + " but iss is " +
                     (iss || "absent") + ": a DID in kid is used only " +
                     "when iss IS that DID, so it cannot say who the " +
                     "issuer is (SD-JWT VC section 2.5), and no other " +
                     "route leads to the issuer's key.");
  }
  log.debug("Leaving issuerKey(). Nowhere.");
  throw unresolved("the credential carries no x5c and its iss (" +
                   (iss || "absent") + ") is neither a DID nor an https " +
                   "URL, so there is nowhere to find its key.");
}

// The keys a signature may be by, out of what issuerKey() found (#469,
// C7): those the header's kid names, matched by kidNames(); with no kid,
// EVERY key, each tried in turn — SD-JWT VC section 4.2 makes kid only
// RECOMMENDED, and jws.js's selectFromJwks() calls a set of several keys
// and no kid "not knowable". Answers { list, error }.
function keyCandidates(found, header) {
  log.debug("Entering keyCandidates().");
  var all = found.candidates || ((found.key && isArray(found.key.keys)) ?
    found.key.keys.map(function (k) {
      return { jwk: keyMembers(k), ids: k.kid ? [k.kid] : [] };
    }) : []);
  var kid = String((header && header.kid) || "");
  if (!kid) {
    log.debug("Leaving keyCandidates(). No kid: " + all.length + ".");
    return { list: all, error: all.length ? "" : "there are no keys." };
  }
  var named = all.filter(function (c) {
    return c.any || c.ids.some(function (id) {
      return kidNames(id, kid, found.did || "");
    });
  });
  log.debug("Leaving keyCandidates(). " + named.length + " named.");
  return { list: named, error: named.length ? "" : "no key has kid " +
    JSON.stringify(kid) + " (the keys are " + (all.map(function (c) {
      return c.ids.join(" / ") || "unnamed";
    }).join(", ") || "none") + ")." };
}

// A JWS verified with what issuerKey() found: a certificate as it is, a
// set by keyCandidates(), trying each candidate until one verifies.
function verifyFound(compact, found, header) {
  log.debug("Entering verifyFound().");
  log.debug("Leaving verifyFound().");
  return verifyFoundBy(function (key) {
    return verifyCompact(compact, key);
  }, found, header);
}

// The same, for any signed thing: `verifyOne(key)` answers { valid, reason }
// for one key (a PEM certificate or { jwk }), so a CWT Status List Token is
// held to exactly the key choice a JWT one is (#471, E5).
function verifyFoundBy(verifyOne, found, header) {
  log.debug("Entering verifyFoundBy().");
  if (typeof found.key === "string" || (found.key && found.key.jwk &&
      !found.candidates)) {
    log.debug("Leaving verifyFoundBy(). One key.");
    return verifyOne(found.key);
  }
  var picked = keyCandidates(found, header);
  if (picked.error) {
    log.debug("Leaving verifyFoundBy(). No candidate.");
    return { valid: false, reason: picked.error };
  }
  var reasons = [];
  for (var i = 0; i < picked.list.length; i++) {
    var v = verifyOne({ jwk: picked.list[i].jwk });
    if (v.valid) {
      log.debug("Leaving verifyFoundBy(). Candidate " + i + ".");
      return { valid: true, reason: "", used: picked.list[i].ids[0] || "",
               tried: picked.list.length };
    }
    reasons.push(v.reason);
  }
  log.debug("Leaving verifyFoundBy(). None verifies.");
  return { valid: false, reason: picked.list.length > 1 ? "none of the " +
           picked.list.length + " candidate keys verifies it" +
           (header && header.kid ? "" : " (the header has no kid, so each " +
            "was tried)") : reasons[0] || "" };
}

// One JWS verified, pure JS, refusing unsecured and MAC algorithms.
function verifyCompact(compact, key) {
  log.debug("Entering verifyCompact().");
  var header;
  try {
    header = decodeJwt(compact).header;
  } catch (e) {
    log.debug("Leaving verifyCompact(). Unreadable.");
    return { valid: false, reason: e.message };
  }
  var alg = String(header.alg || "");
  if (!alg || alg === "none" || /^HS/.test(alg)) {
    log.debug("Leaving verifyCompact(). Refused alg.");
    return { valid: false, reason: 'alg "' + alg + '" is not an ' +
             "asymmetric signature." };
  }
  try {
    var v = jws.verifyJws({ jws: compact, publicKey: key, algId: alg,
                            backend: "js" });
    var first = v.signatures[0] || {};
    log.debug("Leaving verifyCompact(). " + v.valid);
    return { valid: !!v.valid, reason: first.reason || "" };
  } catch (e) {
    log.debug("Leaving verifyCompact(). Threw.");
    return { valid: false, reason: e.message };
  }
}

// ---------------------------------------------------------------------------
// The trust in an x5c (or an mdoc x5chain) chain (#467, S3).
//
// A certificate in x5c "is not a trust anchor merely because it is included
// there" (SD-JWT VC section 2.5): the signature row says only that the JWT
// verifies with the leaf's key, and this row says what, if anything, makes
// that leaf the issuer's. It reports, every time: whether the leaf is
// self-signed and whether a trust anchor travels in the chain (HAIP 1.0
// section 6.1.1 forbids both), whether each certificate is signed by the
// next, every certificate's validity at `now`, and whether iss is bound to
// the end-entity certificate by a Subject Alternative Name. With no trust
// anchor given (session.trustAnchors, PEM or base64 DER) nothing anchors
// the chain and the row is a SKIP the verdict counts as a check not
// performed — never a pass.
//
// Pure JavaScript: node-forge's ASN.1 reader, @noble/curves for ECDSA and
// Ed25519 and forge for RSA, so it runs where crypto.subtle does not.
// ---------------------------------------------------------------------------
var OID_EC_KEY = "1.2.840.10045.2.1";
var OID_ED25519 = "1.3.101.112";
var OID_SAN = "2.5.29.17";
var OID_BASIC_CONSTRAINTS = "2.5.29.19";
var OID_AKI = "2.5.29.35";
var OID_SKI = "2.5.29.14";
var EC_CURVES = {
  "1.2.840.10045.3.1.7": p256,
  "1.3.132.0.34": p384,
  "1.3.132.0.35": p521
};
var CERT_SIG_ALGS = {
  "1.2.840.10045.4.3.2": { kind: "ec", hash: "sha256" },
  "1.2.840.10045.4.3.3": { kind: "ec", hash: "sha384" },
  "1.2.840.10045.4.3.4": { kind: "ec", hash: "sha512" },
  "1.2.840.113549.1.1.11": { kind: "rsa", hash: "sha256" },
  "1.2.840.113549.1.1.12": { kind: "rsa", hash: "sha384" },
  "1.2.840.113549.1.1.13": { kind: "rsa", hash: "sha512" },
  "1.3.101.112": { kind: "ed25519" }
};
var CERT_DIGESTS = {
  sha256: nobleSha256,
  sha384: nobleSha512.sha384,
  sha512: nobleSha512.sha512
};

function asn1Of(der) {
  log.debug("Entering asn1Of().");
  log.debug("Leaving asn1Of().");
  return forge.asn1.fromDer(forge.util.binary.raw.encode(bytes.asBytes(der)),
                            { decodeBitStrings: false });
}

function derOf(node) {
  log.debug("Entering derOf().");
  log.debug("Leaving derOf().");
  return forge.util.binary.raw.decode(forge.asn1.toDer(node).getBytes());
}

function asn1Time(node) {
  log.debug("Entering asn1Time().");
  var t = node.type === forge.asn1.Type.UTCTIME ?
      forge.asn1.utcTimeToDate(node.value) :
      forge.asn1.generalizedTimeToDate(node.value);
  log.debug("Leaving asn1Time().");
  return Math.floor(t.getTime() / 1000);
}

function commonName(nameNode) {
  log.debug("Entering commonName().");
  var attrs = [];
  try {
    attrs = forge.pki.RDNAttributesAsArray(nameNode);
  } catch (e) {
    log.debug("commonName(): " + e.message);
  }
  var cn = attrs.filter(function (a) {
    return a.shortName === "CN";
  })[0];
  log.debug("Leaving commonName().");
  return cn ? String(cn.value) : attrs.map(function (a) {
    return (a.shortName || a.type) + "=" + a.value;
  }).join(",") || "(no subject)";
}

// The parts of one certificate this check needs.
function readCertificate(der) {
  log.debug("Entering readCertificate().");
  var root = asn1Of(der);
  var tbs = root.value[0];
  var v = tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC ?
      1 : 0;
  var validity = tbs.value[v + 3].value;
  var spki = tbs.value[v + 5];
  var spkiAlg = spki.value[0].value;
  var out = {
    der: bytes.asBytes(der),
    tbs: derOf(tbs),
    sigAlg: forge.asn1.derToOid(root.value[1].value[0].value),
    signature: forge.util.binary.raw.decode(root.value[2].value).slice(1),
    issuer: bytes.bytesToHex(derOf(tbs.value[v + 2])),
    subject: bytes.bytesToHex(derOf(tbs.value[v + 4])),
    name: commonName(tbs.value[v + 4]),
    notBefore: asn1Time(validity[0]),
    notAfter: asn1Time(validity[1]),
    spkiDer: derOf(spki),
    keyAlg: forge.asn1.derToOid(spkiAlg[0].value),
    curve: spkiAlg[1] && spkiAlg[1].type === forge.asn1.Type.OID ?
      forge.asn1.derToOid(spkiAlg[1].value) : "",
    publicBits: forge.util.binary.raw.decode(spki.value[1].value).slice(1),
    dns: [],
    uri: [],
    ca: false,
    aki: "",
    ski: ""
  };
  var extsNode = tbs.value.filter(function (n) {
    return n.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && n.type === 3;
  })[0];
  var exts = extsNode ? extsNode.value[0].value : [];
  exts.forEach(function (ext) {
    var oid = forge.asn1.derToOid(ext.value[0].value);
    var body = ext.value[ext.value.length - 1].value;
    if (oid === OID_SAN) {
      forge.asn1.fromDer(body).value.forEach(function (gn) {
        if (gn.type === 2) out.dns.push(String(gn.value).toLowerCase());
        if (gn.type === 6) out.uri.push(String(gn.value));
      });
    } else if (oid === OID_AKI) {
      // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT
      // KeyIdentifier OPTIONAL, ... } (RFC 5280 section 4.2.1.1).
      forge.asn1.fromDer(body).value.forEach(function (part) {
        if (part.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC &&
            part.type === 0) {
          out.aki = forge.util.bytesToHex(part.value);
        }
      });
    } else if (oid === OID_SKI) {
      out.ski = forge.util.bytesToHex(forge.asn1.fromDer(body).value);
    } else if (oid === OID_BASIC_CONSTRAINTS) {
      var bc = forge.asn1.fromDer(body).value;
      out.ca = !!(bc[0] && bc[0].type === forge.asn1.Type.BOOLEAN &&
                  bc[0].value === "\xff");
    }
  });
  log.debug("Leaving readCertificate(). " + out.name);
  return out;
}

// Is `child` signed by `issuer`'s key? true, false, or null when this
// debugger cannot check that signature algorithm (RSASSA-PSS, ML-DSA).
function certSignedBy(child, issuer) {
  log.debug("Entering certSignedBy().");
  var alg = CERT_SIG_ALGS[child.sigAlg];
  if (!alg) {
    log.debug("Leaving certSignedBy(). Unsupported " + child.sigAlg);
    return null;
  }
  try {
    if (alg.kind === "ec") {
      var curve = EC_CURVES[issuer.curve];
      if (issuer.keyAlg !== OID_EC_KEY || !curve) {
        log.debug("Leaving certSignedBy(). Issuer key is not EC.");
        return false;
      }
      var ecOk = curve.verify(child.signature,
                              CERT_DIGESTS[alg.hash](child.tbs),
                              issuer.publicBits,
                              { lowS: false, prehash: false });
      log.debug("Leaving certSignedBy(). ECDSA " + ecOk);
      return !!ecOk;
    }
    if (alg.kind === "ed25519") {
      if (issuer.keyAlg !== OID_ED25519) {
        log.debug("Leaving certSignedBy(). Issuer key is not Ed25519.");
        return false;
      }
      var edOk = ed25519.verify(child.signature, child.tbs,
                                issuer.publicBits);
      log.debug("Leaving certSignedBy(). Ed25519 " + edOk);
      return !!edOk;
    }
    var pub = forge.pki.publicKeyFromPem(bytes.derToPem(issuer.spkiDer,
                                                        "PUBLIC KEY"));
    var md = forge.md[alg.hash].create();
    md.update(forge.util.binary.raw.encode(child.tbs));
    var rsaOk = pub.verify(md.digest().getBytes(),
                           forge.util.binary.raw.encode(child.signature));
    log.debug("Leaving certSignedBy(). RSA " + rsaOk);
    return !!rsaOk;
  } catch (e) {
    log.debug("Leaving certSignedBy(). Threw: " + e.message);
    return false;
  }
}

function selfSigned(cert) {
  log.debug("Entering selfSigned().");
  log.debug("Leaving selfSigned().");
  return cert.subject === cert.issuer && certSignedBy(cert, cert) === true;
}

// A PEM or base64 DER trust anchor, read; null when it is neither.
function readAnchor(text) {
  log.debug("Entering readAnchor().");
  try {
    var t = String(text || "").trim();
    var der = /-----BEGIN/.test(t) ? bytes.pemToDer(t) :
        bytes.b64ToBytes(t.replace(/\s+/g, ""));
    log.debug("Leaving readAnchor().");
    return readCertificate(der);
  } catch (e) {
    log.debug("Leaving readAnchor(). Unreadable: " + e.message);
    return null;
  }
}

// Is iss bound to the end-entity certificate? An https iss by a dNSName of
// its host or a URI equal to it; any other iss (a DID) by an equal URI.
function issBinding(leaf, iss) {
  log.debug("Entering issBinding().");
  var trimmed = String(iss).replace(/\/$/, "");
  var uriHit = leaf.uri.some(function (u) {
    return u.replace(/\/$/, "") === trimmed;
  });
  if (uriHit) {
    log.debug("Leaving issBinding(). URI.");
    return { bound: true, how: "a URI subjectAltName equal to it" };
  }
  var host = "";
  try {
    host = /^https:\/\//.test(iss) ? new URL(iss).hostname.toLowerCase() :
        "";
  } catch (e) {
    host = "";
  }
  if (host && leaf.dns.indexOf(host) !== -1) {
    log.debug("Leaving issBinding(). dNSName.");
    return { bound: true, how: "the dNSName subjectAltName " + host };
  }
  log.debug("Leaving issBinding(). Unbound.");
  return { bound: false, how: "the end-entity certificate's " +
           "subjectAltNames are " + JSON.stringify(leaf.dns.concat(
             leaf.uri)) };
}

// FINDINGS ABOUT AN x5c CHAIN THAT ARE REPORTED, NEVER A FAILURE (rcbj,
// 2026-11-17): a self-signed signer and a trust anchor included in x5c
// (HAIP 1.0 section 6.1.1 says neither may be), each a row of its own, a
// SKIP that is not essential, so the verdict is never FAIL because of them.
// Present only when the finding is.
function chainFindingRows(s, keyBase, trust, labelWhose) {
  log.debug("Entering chainFindingRows().");
  if (trust.selfSignedLeaf) {
    s.add(keyBase + "self-signed", labelWhose + " signing certificate is " +
          "not self-signed", SKIP, "reported: the end-entity certificate " +
          "is SELF-SIGNED. HAIP 1.0 section 6.1.1: the signing " +
          "certificate MUST NOT be self-signed. Not a failure of the " +
          "signature, which is checked on its own row.", false);
  }
  if (trust.anchorIncluded) {
    s.add(keyBase + "anchor-included", labelWhose + " x5c does not carry " +
          "its trust anchor", SKIP, "reported: the last certificate (\"" +
          trust.lastName + "\") is self-signed, so a trust anchor is " +
          "INCLUDED in x5c. HAIP 1.0 section 6.1.1: it MUST NOT be. Being " +
          "there does not make it trusted (SD-JWT VC -27 section 2.5).",
          false);
  }
  log.debug("Leaving chainFindingRows().");
}

// SHA-256 of a certificate's DER, lower-case hex.
function certSha256Hex(cert) {
  log.debug("Entering certSha256Hex().");
  log.debug("Leaving certSha256Hex().");
  return bytes.bytesToHex(nobleSha256(cert.der)).toLowerCase();
}

// A configured mapping of iss to a certificate (SD-JWT VC -27 section 2.5
// allows "a mapping ... configured"): session.issuerBindings, each
// { iss, sha256 } (the hex SHA-256 of the end-entity certificate, a
// certificate of its chain, or the anchor it chains to) or { iss, cn }
// (the end-entity certificate's common name). The matching entry, or null.
function configuredBinding(trust, iss, bindings) {
  log.debug("Entering configuredBinding().");
  var trimmed = String(iss).replace(/\/$/, "");
  var mine = (isArray(bindings) ? bindings : []).filter(function (b) {
    return b && String(b.iss || "").replace(/\/$/, "") === trimmed;
  });
  var certs = trust.certs || [];
  var hashes = certs.map(certSha256Hex);
  if (trust.anchoredBy) {
    hashes.push(certSha256Hex(trust.anchoredBy));
  }
  var leafName = certs.length ? certs[0].name : "";
  var hit = mine.filter(function (b) {
    if (b.sha256) {
      return hashes.indexOf(String(b.sha256).toLowerCase()
        .replace(/[^0-9a-f]/g, "")) !== -1;
    }
    return !!b.cn && b.cn === leafName;
  })[0] || null;
  log.debug("Leaving configuredBinding(). " + !!hit);
  return hit;
}

// The base64url aki values a Verifier asks for (section 6.1.1.1) from
// trust anchors: each anchor's SubjectKeyIdentifier, which is the
// AuthorityKeyIdentifier of every certificate it issues (RFC 5280 sections
// 4.2.1.1 and 4.2.1.2). An anchor with no SubjectKeyIdentifier gives none,
// and is named in `missing`.
function akiValuesFromAnchors(anchors) {
  log.debug("Entering akiValuesFromAnchors().");
  var values = [];
  var missing = [];
  (anchors || []).forEach(function (one) {
    var cert = readAnchor(one);
    if (!cert) {
      missing.push("an unreadable certificate");
      return;
    }
    if (!cert.ski) {
      missing.push(cert.name);
      return;
    }
    var b64u = bytes.bytesToB64u(bytes.hexToBytes(cert.ski));
    if (values.indexOf(b64u) === -1) {
      values.push(b64u);
    }
  });
  log.debug("Leaving akiValuesFromAnchors(). " + values.length);
  return { values: values, missing: missing };
}

// The row on DCQL trusted_authorities (OpenID4VP 1.0 section 6.1.1):
// "Every Credential returned by the Wallet SHOULD match at least one of the
// conditions". A SHOULD on the wallet, so a credential that matches none is
// REPORTED (a SKIP that is not essential), never failed; trust in the
// issuer is decided by the trust rows. `certs` is the credential's X.509
// chain (readCertificate() output) or null when it carries none.
//
//   aki                the AuthorityKeyIdentifier keyIdentifier of a
//                      certificate in the chain equals a value, as bytes
//                      (section 6.1.1.1; HAIP 1.0 section 5 makes it a
//                      MUST to support)
//   etsi_tl, openid_federation and any other type: not evaluated here, and
//                      said so by name.
function trustedAuthoritiesRow(s, key, certs, ctx) {
  log.debug("Entering trustedAuthoritiesRow().");
  ctx.authoritiesReported = true;
  var entries = (ctx.query && ctx.query.trusted_authorities) || [];
  if (!isArray(entries) || !entries.length) {
    log.debug("Leaving trustedAuthoritiesRow(). None asked for.");
    return;
  }
  var label = "The credential matches the query's trusted_authorities";
  var notEvaluated = [];
  var matched = null;
  entries.forEach(function (ta) {
    if (matched || !isPlainObject(ta)) {
      return;
    }
    if (ta.type !== "aki") {
      notEvaluated.push(String(ta.type));
      return;
    }
    (certs || []).forEach(function (c) {
      if (matched || !c.aki) {
        return;
      }
      var hit = (ta.values || []).filter(function (v) {
        try {
          return bytes.bytesToHex(bytes.b64uToBytes(String(v)))
            .toLowerCase() === c.aki.toLowerCase();
        } catch (e) {
          return false;
        }
      })[0];
      if (hit) {
        matched = { value: hit, cert: c.name };
      }
    });
  });
  if (matched) {
    s.add(key, label, PASS, "aki " + matched.value + " is the " +
          "AuthorityKeyIdentifier of \"" + matched.cert + "\" in the " +
          "credential's chain (section 6.1.1.1).", false);
    log.debug("Leaving trustedAuthoritiesRow(). Matched.");
    return;
  }
  var why = !certs ? "the credential carries no X.509 chain, so an aki " +
      "value has nothing to match" : "no certificate in its chain of " +
      certs.length + " has an AuthorityKeyIdentifier equal to an aki value";
  s.add(key, label, SKIP, "reported: " + why + (notEvaluated.length ?
        "; types not evaluated by this Verifier: " +
        notEvaluated.join(", ") : "") + ". Section 6.1.1: the wallet " +
        "\"SHOULD\" return a credential that matches; the issuer's trust " +
        "is decided by its own rows.", false);
  log.debug("Leaving trustedAuthoritiesRow(). No match.");
}

// The row on whether iss is bound to an x5c end-entity certificate (SD-JWT
// VC -27 section 2.5). Bound by a URI SAN equal to iss, a dNSName of its
// host, or a configured mapping: PASS. Unbound: REPORTED, never a failure
// (rcbj, 2026-11-17): a SKIP that is not essential, saying iss is NOT
// authenticated by the certificate and that the issuer is the
// certificate's subject. The section's own words: "An iss claim, if
// present, is not authenticated by this mechanism ...; a recipient MAY
// reject an SD-JWT VC whose iss value is not bound to the end-entity
// certificate according to its policy, and Issuers using this mechanism
// SHOULD NOT include an iss claim without such a binding."
function issBindingRow(s, key, trust, iss, session) {
  log.debug("Entering issBindingRow().");
  var label = "iss is bound to the issuer's x5c certificate";
  var leaf = (trust.certs || [])[0];
  if (!leaf) {
    log.debug("Leaving issBindingRow(). No certificate.");
    return;
  }
  var b = issBinding(leaf, iss);
  if (b.bound) {
    s.add(key, label, PASS, "iss " + iss + " is bound to the end-entity " +
          "certificate by " + b.how + ".", false);
    log.debug("Leaving issBindingRow(). Bound.");
    return;
  }
  var mapped = configuredBinding(trust, iss,
                                 session && session.issuerBindings);
  if (mapped) {
    s.add(key, label, PASS, "iss " + iss + " is bound to the certificate " +
          "by this Verifier's configured mapping (" + (mapped.sha256 ?
            "sha256 " + mapped.sha256 : "cn " + mapped.cn) + "), which " +
          "SD-JWT VC -27 section 2.5 allows.", false);
    log.debug("Leaving issBindingRow(). Mapped.");
    return;
  }
  s.add(key, label, SKIP, "reported: iss " + iss + " is NOT bound to the " +
        "end-entity certificate (" + b.how + "; no configured mapping " +
        "matches). The iss claim is therefore NOT authenticated by the " +
        "certificate: the issuer is the certificate's subject, \"" +
        leaf.name + "\" (SD-JWT VC -27 section 2.5). Issuers \"SHOULD NOT " +
        "include an iss claim without such a binding\". Not a failure of " +
        "the signature, which is checked on its own row.", false);
  log.debug("Leaving issBindingRow(). Unbound.");
}

// The verdict on a chain: { status, detail }. `chain` is the DER (or
// base64) certificates, leaf first; opts { iss, now, anchors }.
function x5cTrust(chain, opts) {
  log.debug("Entering x5cTrust().");
  var o = opts || {};
  var now = nowSeconds(o.now);
  var certs;
  try {
    certs = chain.map(function (c) {
      return readCertificate(typeof c === "string" ? bytes.b64ToBytes(c) :
                             c);
    });
  } catch (e) {
    log.debug("Leaving x5cTrust(). Unreadable.");
    return { status: FAIL, detail: "a certificate in the chain is not " +
             "readable X.509: " + e.message };
  }
  var fails = [];
  var notes = [];
  var unknown = false;
  var leaf = certs[0];
  notes.push(certs.length + " certificate(s), end-entity \"" + leaf.name +
             "\"");
  var selfSignedLeaf = selfSigned(leaf);
  if (selfSignedLeaf) {
    notes.push("the end-entity certificate is self-signed (reported on " +
               "its own row)");
  }
  for (var i = 0; i + 1 < certs.length; i++) {
    var signed = certs[i].issuer === certs[i + 1].subject ?
        certSignedBy(certs[i], certs[i + 1]) : false;
    if (signed === null) {
      unknown = true;
      notes.push("certificate " + i + " uses signature algorithm " +
                 certs[i].sigAlg + ", which this debugger cannot check");
    } else if (!signed) {
      fails.push("the chain is BROKEN: certificate " + i + " (\"" +
                 certs[i].name + "\") is not signed by certificate " +
                 (i + 1) + " (\"" + certs[i + 1].name + "\")");
    }
  }
  if (certs.length > 1 && !fails.length && !unknown) {
    notes.push("each certificate is signed by the next");
  }
  var last = certs[certs.length - 1];
  var included = certs.length > 1 && selfSigned(last);
  if (included) {
    notes.push("the last certificate (\"" + last.name + "\") is a " +
               "trust anchor included in the chain (reported on its own " +
               "row); being there does not make it trusted (SD-JWT VC " +
               "section 2.5)");
  }
  certs.forEach(function (c, k) {
    if (now > c.notAfter) {
      fails.push("certificate " + k + " (\"" + c.name + "\") EXPIRED at " +
                 isoOf(c.notAfter));
    } else if (now < c.notBefore) {
      fails.push("certificate " + k + " (\"" + c.name + "\") is not " +
                 "valid until " + isoOf(c.notBefore));
    }
  });
  if (!fails.length) notes.push("every certificate is within its validity");
  // WHETHER iss IS BOUND TO THE CERTIFICATE IS NOT PART OF THIS ROW. SD-JWT
  // VC -27 section 2.5: "An iss claim, if present, is not authenticated by
  // this mechanism ...; a recipient MAY reject an SD-JWT VC whose iss value
  // is not bound to the end-entity certificate according to its policy, and
  // Issuers using this mechanism SHOULD NOT include an iss claim without
  // such a binding." A MAY-reject is a policy, so the binding is reported on
  // a row of its own by issBindingRow(), and this row is about the chain.
  if (!o.iss) {
    notes.push("there is no iss: the issuer is the end-entity " +
               "certificate's subject");
  }
  var anchors = (isArray(o.anchors) ? o.anchors : []).map(readAnchor)
    .filter(Boolean);
  var anchoredBy = null;
  if (anchors.length && !unknown) {
    for (var j = 0; j < certs.length && !anchoredBy; j++) {
      var same = anchors.filter(function (a) {
        return bytes.bytesEqual(a.der, certs[j].der);
      })[0];
      if (same) {
        anchoredBy = same;
      } else if (j === certs.length - 1) {
        anchoredBy = anchors.filter(function (a) {
          return a.subject === certs[j].issuer &&
            certSignedBy(certs[j], a) === true;
        })[0] || null;
      }
    }
    if (anchoredBy && (now > anchoredBy.notAfter ||
                       now < anchoredBy.notBefore)) {
      fails.push("the trust anchor \"" + anchoredBy.name + "\" is " +
                 "outside its own validity");
    }
  }
  var status;
  var verdict;
  if (fails.length) {
    status = FAIL;
    verdict = fails.join("; ") + ".";
  } else if (anchoredBy) {
    status = PASS;
    verdict = "anchored at the supplied trust anchor \"" +
      anchoredBy.name + "\".";
  } else if (anchors.length && !unknown) {
    status = FAIL;
    verdict = "NOT anchored: none of the " + anchors.length +
      " supplied trust anchor(s) issued this chain.";
  } else {
    status = SKIP;
    verdict = "NOT anchored: " + (unknown ? "a signature in the chain " +
      "could not be checked" : "no trust anchor was supplied " +
      "(session.trustAnchors)") + ", so nothing says this certificate " +
      "is the issuer's. A certificate is not trusted because it is in " +
      "the chain (SD-JWT VC section 2.5).";
  }
  log.debug("Leaving x5cTrust(). " + status);
  return { status: status, detail: verdict + " " + notes.join("; ") + ".",
           certs: certs, anchoredBy: anchoredBy,
           selfSignedLeaf: selfSignedLeaf, anchorIncluded: included,
           lastName: last.name };
}

// `opts.format` is the credential's format: jwt_vc_json's issuer key routes
// are not SD-JWT VC's (#469, B2). A key that could not be had is a SKIP —
// essential, so the verdict is incomplete — never a signature FAIL.
async function checkIssuerSignature(s, key, compact, header, payload,
                                    ctx, label, opts) {
  log.debug("Entering checkIssuerSignature().");
  var found;
  try {
    found = await issuerKey(header, payload, ctx.fetchJson, opts);
  } catch (e) {
    s.add(key, label, e.unresolved ? SKIP : FAIL, e.unresolved ?
          "could not resolve the issuer's key: " + e.message :
          "no issuer key: " + e.message, true);
    log.debug("Leaving checkIssuerSignature(). No key.");
    return false;
  }
  var v = verifyFound(compact, found, header);
  s.add(key, label, v.valid ? PASS : FAIL, v.valid ?
        "verifies (" + header.alg + ") with the key from " + found.from +
        (v.used && v.tried > 1 ? ", " + v.used + " (the header names no " +
         "kid, so each of " + v.tried + " keys was tried)" : v.used &&
         header.kid && v.used !== header.kid ? ", " + v.used +
         " (which kid " + header.kid + " names)" : "") + "." :
        "does NOT verify with the key from " + found.from +
        (v.reason ? ": " + v.reason : "."), true);
  if (found.x5c) {
    var trust = x5cTrust(found.x5c, { iss: payload.iss, now: ctx.now,
                                      anchors: ctx.session.trustAnchors });
    s.add(key.replace(/signature$/, "trust"), "The issuer's x5c " +
          "certificate is trusted", trust.status, trust.detail, true);
    var base = key.replace(/signature$/, "");
    chainFindingRows(s, base, trust, "The issuer's");
    trustedAuthoritiesRow(s, base + "trusted-authorities", trust.certs,
                          ctx);
    if (payload.iss) {
      issBindingRow(s, base + "iss", trust, payload.iss, ctx.session);
    }
  }
  log.debug("Leaving checkIssuerSignature(). " + v.valid);
  return v.valid;
}

// ---------------------------------------------------------------------------
// W3C VC Data Integrity proofs (eddsa-rdfc-2022, eddsa-jcs-2022,
// ecdsa-rdfc-2019, ecdsa-jcs-2019).
//
// Every one of the four is the same three steps: canonicalize the proof
// configuration (the proof without proofValue, given the document's
// @context) and the document without its proof — RDFC-1.0 or JCS — hash
// each, and verify the signature over hash(config) || hash(document). EdDSA
// hashes with SHA-256; ECDSA with SHA-256 on P-256 and SHA-384 on P-384.
// RDFC uses jsonld with bbs2023.js's document loader, which serves the
// contexts this deployment ships and never fetches one.
// ---------------------------------------------------------------------------
function rdfc(doc) {
  log.debug("Entering rdfc().");
  log.debug("Leaving rdfc().");
  return jsonld.canonize(doc, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: bbs2023.documentLoader,
    safe: true
  });
}

// The public key a proof's verificationMethod names: a did:key or did:jwk
// read in place, another DID resolved through did.js, an https URL fetched
// as a verification method document.
async function proofKey(vm, fetchJson) {
  log.debug("Entering proofKey().");
  var url = String(vm || "");
  if (!url) {
    log.debug("Leaving proofKey(). None.");
    throw new Error("the proof names no verificationMethod.");
  }
  var local = keyOfLocalDid(url);
  if (local) {
    log.debug("Leaving proofKey(). Local DID.");
    return local;
  }
  if (didLib.isDid(url)) {
    var jwk = await keyForDidUrl(url, fetchJson);
    log.debug("Leaving proofKey(). DID.");
    return jwk;
  }
  var resolved = await didLib.resolveVerificationMethod(url, {
    allowHttp: false,
    fetch: fetchJson ? fetchAdapter(fetchJson) : undefined });
  var m = resolved.method || {};
  log.debug("Leaving proofKey(). Fetched.");
  return m.publicKeyJwk || (m.publicKeyMultibase ?
    didLib.didKeyToJwk("did:key:" + m.publicKeyMultibase) : null);
}

// How a suite signs with a key: the jws.js row and the digest.
function diAlgorithm(family, jwk) {
  log.debug("Entering diAlgorithm(). " + family);
  var crv = String((jwk && jwk.crv) || "");
  if (family === "eddsa" && crv === "Ed25519") {
    log.debug("Leaving diAlgorithm(). Ed25519.");
    return { spec: jws.algSpec("EdDSA-Ed25519"), hash: nobleSha256 };
  }
  if (family === "ecdsa" && crv === "P-256") {
    log.debug("Leaving diAlgorithm(). P-256.");
    return { spec: jws.algSpec("ES256"), hash: nobleSha256 };
  }
  if (family === "ecdsa" && crv === "P-384") {
    log.debug("Leaving diAlgorithm(). P-384.");
    return { spec: jws.algSpec("ES384"), hash: nobleSha512.sha384 };
  }
  log.debug("Leaving diAlgorithm(). Mismatch.");
  return null;
}

// The signature over hash(proof options) || hash(document), pure JS.
function diSignatureValid(alg, jwk, hashData, signature) {
  log.debug("Entering diSignatureValid().");
  var ok = false;
  try {
    ok = !!jws.verifyOctets(alg.spec, jws.jwkToKey(alg.spec, jwk, false),
                            hashData, signature);
  } catch (e) {
    log.debug("diSignatureValid(): verify threw: " + e.message);
    ok = false;
  }
  log.debug("Leaving diSignatureValid(). " + ok);
  return ok;
}

// One Data Integrity proof verified. Answers { valid, unsupported, reason,
// jwk, suite, verificationMethod }. `opts.purpose` is the proofPurpose the
// caller expects (authentication for a VP, assertionMethod for a VC).
async function verifyDataIntegrity(doc, opts) {
  log.debug("Entering verifyDataIntegrity().");
  var o = opts || {};
  var proofs = [].concat((doc && doc.proof) || []);
  if (!proofs.length) {
    log.debug("Leaving verifyDataIntegrity(). No proof.");
    return { valid: false, reason: "there is no proof." };
  }
  var proof = proofs[0] || {};
  var suite = String(proof.cryptosuite || "");
  var vm = String(proof.verificationMethod || "");
  var out = { valid: false, suite: suite, verificationMethod: vm };
  if (proof.type !== "DataIntegrityProof") {
    log.debug("Leaving verifyDataIntegrity(). Not DataIntegrityProof.");
    return Object.assign(out, { unsupported: true, reason: "proof type " +
      JSON.stringify(proof.type) + " is not DataIntegrityProof." });
  }
  var suiteSpec = DI_SUITES[suite];
  if (!suiteSpec) {
    log.debug("Leaving verifyDataIntegrity(). Unsupported suite.");
    return Object.assign(out, { unsupported: true,
      reason: DI_SUITES_NOT_VERIFIED[suite] || "cryptosuite " +
        JSON.stringify(suite) + " is not one this debugger verifies (" +
        Object.keys(DI_SUITES).join(", ") + ", and bbs-2023 on a " +
        "credential)." });
  }
  var pv = String(proof.proofValue || "");
  if (pv.charAt(0) !== "z") {
    log.debug("Leaving verifyDataIntegrity(). Not base58btc.");
    return Object.assign(out, { reason: "proofValue is not multibase " +
                                "base58btc (z)." });
  }
  var jwk;
  try {
    jwk = await proofKey(vm, o.fetchJson);
  } catch (e) {
    log.debug("Leaving verifyDataIntegrity(). Key unresolved.");
    return Object.assign(out, { reason: "verificationMethod " + vm +
                                " could not be resolved: " + e.message });
  }
  if (!jwk) {
    log.debug("Leaving verifyDataIntegrity(). No key.");
    return Object.assign(out, { reason: "verificationMethod " + vm +
                                " resolves to no key." });
  }
  out.jwk = jwk;
  var alg = diAlgorithm(suiteSpec.family, jwk);
  if (!alg) {
    log.debug("Leaving verifyDataIntegrity(). Wrong key type.");
    return Object.assign(out, { reason: suite + " needs " +
      (suiteSpec.family === "eddsa" ? "an Ed25519" : "a P-256 or P-384") +
      " key and " + vm + " is " + (jwk.crv || jwk.kty) + "." });
  }
  var config = Object.assign({}, proof);
  delete config.proofValue;
  var unsecured = Object.assign({}, doc);
  delete unsecured.proof;
  var docCtx = [].concat(doc["@context"] || []);
  var proofCtx = config["@context"] === undefined ? null :
      [].concat(config["@context"]);
  var jcsSuite = suiteSpec.canon === "jcs";
  // The proof's @context against the document's (#469, C14). VC Data
  // Integrity's EdDSA and ECDSA cryptosuites, "Verify Proof" step 4: when
  // the proof options carry an @context, the secured document's @context
  // MUST START WITH all of its values in the same order, and the unsecured
  // document is then given the proof's @context. A JCS suite hashes the
  // proof options EXACTLY AS RECEIVED; an RDFC suite needs a context to
  // expand the proof configuration at all, so it takes the document's,
  // and a proof that names one must name that same one.
  if (proofCtx) {
    var prefixOk = proofCtx.length <= docCtx.length &&
        proofCtx.every(function (c, i) {
          return JSON.stringify(c) === JSON.stringify(docCtx[i]);
        });
    var sameOk = prefixOk && proofCtx.length === docCtx.length;
    if (jcsSuite ? !prefixOk : !sameOk) {
      log.debug("Leaving verifyDataIntegrity(). Context mismatch.");
      return Object.assign(out, { reason: jcsSuite ? "the document's " +
        "@context does not start with the proof's @context, in order " +
        "(VC Data Integrity, Verify Proof step 4.1)." : "the proof's " +
        "@context is not the document's." });
    }
    if (jcsSuite) unsecured["@context"] = config["@context"];
  }
  if (!jcsSuite && doc["@context"]) config["@context"] = doc["@context"];
  var configText;
  var docText;
  if (jcsSuite) {
    configText = vpProtocols.jcs(config);
    docText = vpProtocols.jcs(unsecured);
  } else {
    try {
      configText = await rdfc(config);
      docText = await rdfc(unsecured);
    } catch (e) {
      log.debug("Leaving verifyDataIntegrity(). Canonicalization failed.");
      return Object.assign(out, { reason: "RDFC-1.0 canonicalization " +
        "failed (every context must be one this debugger ships or was " +
        "given, and every term defined): " + e.message });
    }
  }
  var hashData = bytes.concatBytes(alg.hash(bytes.strBytes(configText)),
                                   alg.hash(bytes.strBytes(docText)));
  var signature = didLib.base58Decode(pv.slice(1));
  var ok = diSignatureValid(alg, jwk, hashData, signature);
  // The shape this tree's own wallet signed until #469: a JCS proof that
  // HASHED the document's @context into its proof options and then left
  // it out of the proof. It is a FAIL — the debugger reads the
  // specification, and compatibility is not its business — and the old
  // reading is tried only to say WHY it failed.
  if (!ok && jcsSuite && !proofCtx && doc["@context"]) {
    var injected = Object.assign({ "@context": doc["@context"] }, config);
    if (diSignatureValid(alg, jwk, bytes.concatBytes(
      alg.hash(bytes.strBytes(vpProtocols.jcs(injected))),
      alg.hash(bytes.strBytes(docText))), signature)) {
      log.debug("Leaving verifyDataIntegrity(). Omitted @context.");
      return Object.assign(out, { reason: "non-conformant: the proof was " +
        "signed over an @context it does not carry (" + suite + " Verify " +
        "Proof hashes the proof options exactly as received). It verifies " +
        "only with the document's @context put back into them, which no " +
        "conformant verifier does." });
    }
  }
  if (!ok) {
    log.debug("Leaving verifyDataIntegrity(). Bad signature.");
    return Object.assign(out, { reason: "the signature does not verify " +
      "over the canonical document and proof configuration (altered, or " +
      "signed by another key)." });
  }
  if (o.purpose && proof.proofPurpose !== o.purpose) {
    log.debug("Leaving verifyDataIntegrity(). Wrong purpose.");
    return Object.assign(out, { reason: "the signature verifies, but " +
      "proofPurpose is " + JSON.stringify(proof.proofPurpose) + ", not " +
      o.purpose + "." });
  }
  if (proof.expires && Date.parse(proof.expires) / 1000 + SKEW_SECONDS <
      nowSeconds(o.now)) {
    log.debug("Leaving verifyDataIntegrity(). Expired proof.");
    return Object.assign(out, { reason: "the proof expired at " +
                                proof.expires + "." });
  }
  log.debug("Leaving verifyDataIntegrity(). Valid.");
  return Object.assign(out, { valid: true, reason: suite + " (" +
    alg.spec.alg + ") by " + vm + " verifies" +
    (proofs.length > 1 ? "; it is the first of " + proofs.length +
     " proofs, and only the first is checked" : "") + "." });
}

// ---------------------------------------------------------------------------
// Status lists.
//
// IETF Token Status List (draft-ietf-oauth-status-list): the credential's
// status.status_list = { idx, uri }; uri serves a Status List Token, a JWT
// of typ statuslist+jwt whose sub is that uri and whose status_list.lst is
// base64url(zlib DEFLATE(the list)). Each entry is `bits` bits (1, 2, 4 or
// 8) and entry 0 is the LEAST significant bits of byte 0 (section 4.1).
//
// W3C Bitstring Status List v1.0: credentialStatus entries of type
// BitstringStatusListEntry name a status list credential, an index, a
// purpose and a size; encodedList is multibase base64url ("u") of GZIP(the
// bitstring), and bit 0 is the MOST significant bit of byte 0 (section 3.2).
//
// Both bit orders are read by the two functions below, and the tests build
// lists with node's zlib and their own bit packing to hold them apart.
// ---------------------------------------------------------------------------
var COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

// The decompressed bytes, through the platform's DecompressionStream.
// "deflate" is zlib (RFC 1950), "gzip" is RFC 1952.
async function inflate(data, format) {
  log.debug("Entering inflate(). " + format);
  if (typeof DecompressionStream !== "function") {
    log.debug("Leaving inflate(). No DecompressionStream.");
    throw new Error("this platform has no DecompressionStream.");
  }
  var ds = new DecompressionStream(format);
  var writer = ds.writable.getWriter();
  var reader = ds.readable.getReader();
  var writing = writer.write(bytes.asBytes(data)).then(function () {
    return writer.close();
  });
  writing.catch(function () {
    // Reported through the reader, which fails the same way.
  });
  var chunks = [];
  var total = 0;
  for (;;) {
    var step = await reader.read();
    if (step.done) break;
    total += step.value.length;
    if (total > MAX_INFLATED_BYTES) {
      reader.cancel().catch(function () {
        // Nothing more to read either way.
      });
      log.debug("Leaving inflate(). Too large.");
      throw new Error("it decompresses to more than " + MAX_INFLATED_BYTES +
                      " bytes, which is refused.");
    }
    chunks.push(step.value);
  }
  var out = new Uint8Array(total);
  var at = 0;
  chunks.forEach(function (c) {
    out.set(c, at);
    at += c.length;
  });
  log.debug("Leaving inflate(). " + total + " byte(s).");
  return out;
}

// draft-ietf-oauth-status-list section 4.1: LSB first within each byte.
function tokenStatusAt(list, idx, bits) {
  log.debug("Entering tokenStatusAt().");
  var bit = idx * bits;
  var value = (list[bit >> 3] >> (bit & 7)) & ((1 << bits) - 1);
  log.debug("Leaving tokenStatusAt(). " + value);
  return value;
}

// W3C Bitstring Status List v1.0 section 3.2: MSB first, `size` bits from
// bit index `start`, the first bit the most significant of the value.
function bitstringAt(list, start, size) {
  log.debug("Entering bitstringAt().");
  var value = 0;
  for (var k = start; k < start + size; k++) {
    value = value * 2 + ((list[k >> 3] >> (7 - (k & 7))) & 1);
  }
  log.debug("Leaving bitstringAt(). " + value);
  return value;
}

// A decoded CBOR value (the mdoc MSO's status member) as plain JSON.
function cborToPlain(v) {
  log.debug("Entering cborToPlain().");
  var out = v;
  if (v instanceof Map) {
    out = {};
    v.forEach(function (val, k) {
      out[String(k)] = cborToPlain(val);
    });
  } else if (isArray(v)) {
    out = v.map(cborToPlain);
  } else if (v && typeof v === "object" && "value" in v && "tag" in v) {
    out = cborToPlain(v.value);
  }
  log.debug("Leaving cborToPlain().");
  return out;
}

// What a credential says about where its status is.
// `other` names the status mechanisms beside status_list this debugger
// does not read: draft-ietf-oauth-status-list-21 section 6.1 makes `status`
// a container of mechanisms (registered in sections 14.2 and 14.4), and an
// mdoc's MSO may carry ISO/IEC 18013-5's identifier_list there.
function statusRefsOf(holder) {
  log.debug("Entering statusRefsOf().");
  var h = holder || {};
  var token = h.status && isPlainObject(h.status.status_list) ?
      h.status.status_list : null;
  var other = isPlainObject(h.status) ? Object.keys(h.status).filter(
    function (name) {
      return name !== "status_list";
    }) : [];
  var w3c = [].concat(h.credentialStatus || []).filter(isPlainObject);
  log.debug("Leaving statusRefsOf().");
  return { token: token, w3c: w3c, other: other };
}

function isoOf(seconds) {
  log.debug("Entering isoOf().");
  log.debug("Leaving isoOf().");
  return new Date(seconds * 1000).toISOString();
}

// Fetched once per URL per response, through the caller's fetchText.
async function fetchStatusText(ctx, url, accept) {
  log.debug("Entering fetchStatusText(). " + url);
  ctx.statusCache = ctx.statusCache || {};
  if (!ctx.statusCache[url]) {
    ctx.statusCache[url] = Promise.resolve().then(function () {
      return ctx.fetchText(url, { accept: accept });
    });
  }
  var text = await ctx.statusCache[url];
  log.debug("Leaving fetchStatusText().");
  return text;
}

// What a status list fetch answered, whatever the fetcher handed back: a
// string (text), an ArrayBuffer or a typed array (bytes), or { body,
// contentType } carrying either. Bytes are decoded as UTF-8 only when they
// ARE UTF-8, so a binary body (a CWT) is never turned into replacement
// characters and then misread.
function statusBody(fetched) {
  log.debug("Entering statusBody().");
  var out = { text: null, bytes: null, contentType: "" };
  var body = fetched;
  if (fetched && typeof fetched === "object" &&
      !(fetched instanceof ArrayBuffer) && !ArrayBuffer.isView(fetched) &&
      "body" in fetched) {
    out.contentType = String(fetched.contentType || "");
    body = fetched.body;
  }
  if (typeof body === "string") {
    out.text = body;
  } else if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
    out.bytes = body instanceof ArrayBuffer ? new Uint8Array(body) :
      new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    try {
      out.text = new TextDecoder("utf-8", { fatal: true }).decode(out.bytes);
    } catch (e) {
      out.text = null;
    }
  }
  log.debug("Leaving statusBody().");
  return out;
}

// A COSE_Sign1 found by DECODING the bytes, not by guessing from the first
// one: RFC 9052 section 4.2's four-element array [protected bstr,
// unprotected map, payload, signature bstr], tagged 18 or not, and RFC 8392
// section 6's CWT tag 61 around it — or a COSE_Mac0 (section 6.2, tag 17),
// the same shape with a tag in place of the signature, which
// draft-ietf-oauth-status-list-21 section 5.2 also allows. Null when the
// bytes are not that. `parts` is the four elements, `mac` says which.
function coseSign1Of(raw) {
  log.debug("Entering coseSign1Of().");
  if (!raw || !raw.length) {
    log.debug("Leaving coseSign1Of(). Empty.");
    return null;
  }
  var v;
  try {
    v = cbor.decode(raw);
  } catch (e) {
    log.debug("Leaving coseSign1Of(). Not CBOR: " + e.message);
    return null;
  }
  var tags = [];
  while (v instanceof cbor.Tagged) {
    tags.push(v.tag);
    v = v.value;
  }
  var shaped = isArray(v) && v.length === 4 && v[0] instanceof Uint8Array &&
      v[1] instanceof Map && v[3] instanceof Uint8Array &&
      (v[2] === null || v[2] instanceof Uint8Array);
  var tagsOk = tags.every(function (t) {
    return t === 17 || t === 18 || t === 61;
  });
  var mac = tags.indexOf(17) !== -1;
  if (!shaped || !tagsOk || (mac && tags.indexOf(18) !== -1)) {
    log.debug("Leaving coseSign1Of(). Not a COSE_Sign1.");
    return null;
  }
  log.debug("Leaving coseSign1Of(). Tags " + tags.join(","));
  return { tags: tags, parts: v, mac: mac };
}

// What a body that is not a compact JWS actually is, said plainly: a
// COSE_Sign1, an HTML page (an error or sign-in page served in the list's
// place), binary data, or text that is none of these.
function describeStatusBody(body) {
  log.debug("Entering describeStatusBody().");
  var type = body.contentType.split(";")[0].trim().toLowerCase();
  var served = type ? " (served as " + type + ")" : "";
  var raw = body.bytes ||
      (body.text !== null ? new TextEncoder().encode(body.text) : null);
  var cose = coseSign1Of(raw);
  if (cose) {
    log.debug("Leaving describeStatusBody(). COSE.");
    return { kind: "cose", cose: cose, type: type, detail: "a " +
      (cose.mac ? "COSE_Mac0" : "COSE_Sign1") + " (CBOR" +
      (cose.tags.indexOf(61) !== -1 ? ", in CWT tag 61" : "") + ")" +
      served };
  }
  var text = body.text;
  if (text !== null && (type === "text/html" ||
      /^\s*<(!doctype\s+html|html[\s>])/i.test(text))) {
    log.debug("Leaving describeStatusBody(). HTML.");
    return { kind: "html", detail: "an HTML page" + served + ", most " +
      "likely an error or sign-in page served in its place" };
  }
  if (text === null) {
    log.debug("Leaving describeStatusBody(). Binary.");
    return { kind: "binary", detail: body.bytes.length + " bytes of " +
      "binary data, and not a COSE_Sign1" + served };
  }
  var shown = text.trim().slice(0, 60);
  log.debug("Leaving describeStatusBody(). Text.");
  return { kind: "text", detail: "text that is not a compact JWS" + served +
    (shown ? ", beginning " + JSON.stringify(shown) : ", and empty") };
}

// RFC 7515 section 4.1.9: typ is a media type, so it compares
// case-insensitively (RFC 2045), and "A recipient using the media type
// value MUST treat it as if 'application/' were prepended to any 'typ'
// value not containing a '/'" — so "application/statuslist+jwt" is
// "statuslist+jwt".
function mediaTypeOfTyp(typ) {
  log.debug("Entering mediaTypeOfTyp().");
  var t = String(typ === undefined || typ === null ? "" : typ).trim()
    .toLowerCase();
  log.debug("Leaving mediaTypeOfTyp().");
  return t && t.indexOf("/") === -1 ? "application/" + t : t;
}

// The length of the DER item at `at`, header and contents.
function derItemSize(b, at) {
  log.debug("Entering derItemSize().");
  var first = b[at + 1];
  if (first < 0x80) {
    log.debug("Leaving derItemSize(). Short form.");
    return 2 + first;
  }
  var n = first & 0x7f;
  var len = 0;
  for (var i = 0; i < n; i++) {
    len = len * 256 + b[at + 2 + i];
  }
  log.debug("Leaving derItemSize(). Long form.");
  return 2 + n + len;
}

// The parts of a DER certificate a signer link is judged by, read with
// node-forge's ASN.1 — no Web Crypto: the TBS bytes (sliced from the input,
// never re-encoded), the signature algorithm and value, the issuer and
// subject names as DER, and the extended key usages.
function certParts(der) {
  log.debug("Entering certParts().");
  var b = bytes.asBytes(der);
  var asn = forge.asn1.fromDer(forge.util.binary.raw.encode(b),
                               { decodeBitStrings: false });
  var tbs = asn.value[0];
  var v = tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC ? 1 : 0;
  var tbsAt = (b[1] < 0x80 ? 2 : 2 + (b[1] & 0x7f));
  var ekus = [];
  tbs.value.forEach(function (part) {
    if (part.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC ||
        part.type !== 3) {
      return;
    }
    (part.value[0].value || []).forEach(function (ext) {
      if (forge.asn1.derToOid(ext.value[0].value) !== "2.5.29.37") {
        return;
      }
      var octets = ext.value[ext.value.length - 1].value;
      forge.asn1.fromDer(octets).value.forEach(function (purpose) {
        ekus.push(forge.asn1.derToOid(purpose.value));
      });
    });
  });
  var sigBits = asn.value[2].value;
  log.debug("Leaving certParts().");
  return {
    der: b,
    tbs: b.slice(tbsAt, tbsAt + derItemSize(b, tbsAt)),
    sigAlg: forge.asn1.derToOid(asn.value[1].value[0].value),
    signature: forge.util.binary.raw.decode(sigBits.slice(1)),
    issuer: forge.asn1.toDer(tbs.value[v + 2]).getBytes(),
    subject: forge.asn1.toDer(tbs.value[v + 4]).getBytes(),
    subjectText: tbs.value[v + 4].value.map(function (rdn) {
      return rdn.value.map(function (atv) {
        var oid = forge.asn1.derToOid(atv.value[0].value);
        return (forge.pki.oids[oid] || oid) +
          "=" + atv.value[1].value;
      }).join("+");
    }).join(", "),
    ekus: ekus
  };
}

// Every certificate of a JOSE header's x5c, parsed; [] when it has none or
// one will not parse.
function x5cParts(header) {
  log.debug("Entering x5cParts().");
  var chain = header && isArray(header.x5c) ? header.x5c : [];
  try {
    var out = chain.map(function (b64) {
      return certParts(bytes.b64ToBytes(b64));
    });
    log.debug("Leaving x5cParts(). " + out.length);
    return out;
  } catch (e) {
    log.debug("Leaving x5cParts(). Unreadable: " + e.message);
    return [];
  }
}

// Did `parent`'s key sign `child`? Pure JavaScript, through jws.js's rows.
// For the Status List Token's certificates (certParts() objects); the
// issuer-trust report has its own certSignedBy() over readCertificate().
function statusCertSignedBy(child, parent) {
  log.debug("Entering statusCertSignedBy().");
  var row = STATUS_CERT_SIG_ALGS[child.sigAlg];
  if (!row) {
    log.debug("Leaving statusCertSignedBy(). Unsupported " + child.sigAlg);
    return false;
  }
  try {
    var spec = jws.algSpec(row.alg);
    var key = jws.resolveKey(spec, bytes.derToPem(parent.der, "CERTIFICATE"),
                             "verify").key;
    var sig = row.len ? x509.ecdsaDerToRaw(child.signature, row.len) :
      child.signature;
    var ok = !!jws.verifyOctets(spec, key, child.tbs, sig);
    log.debug("Leaving statusCertSignedBy(). " + ok);
    return ok;
  } catch (e) {
    log.debug("Leaving statusCertSignedBy(). " + e.message);
    return false;
  }
}

// Section 11.3's "same key" references: does the Status List Token name
// the key the credential was signed with — "the same x5c value or an x5t,
// x5t#S256 or kid parameter referencing to the same key as used in the
// Referenced Token"? The reference, or "".
function sameKeyReference(h, ih) {
  log.debug("Entering sameKeyReference().");
  var leaf = isArray(ih.x5c) && ih.x5c.length ? ih.x5c[0] : "";
  if (leaf && isArray(h.x5c) && h.x5c[0] === leaf) {
    log.debug("Leaving sameKeyReference(). x5c.");
    return "the same x5c";
  }
  if (leaf && !isArray(h.x5c)) {
    var der = bytes.b64ToBytes(leaf);
    if (h["x5t#S256"] && h["x5t#S256"] === bytes.bytesToB64u(
      nobleSha256(der))) {
      log.debug("Leaving sameKeyReference(). x5t#S256.");
      return "an x5t#S256 that is the credential's leaf certificate";
    }
    if (h.x5t && h.x5t === bytes.bytesToB64u(nobleSha1(der))) {
      log.debug("Leaving sameKeyReference(). x5t.");
      return "an x5t that is the credential's leaf certificate";
    }
  }
  if (h.kid && ih.kid && h.kid === ih.kid && !isArray(h.x5c)) {
    log.debug("Leaving sameKeyReference(). kid.");
    return "the credential's kid " + JSON.stringify(h.kid);
  }
  log.debug("Leaving sameKeyReference(). None.");
  return "";
}

// The credential issuer's key, found as the issuer signature finds it, once
// per credential.
function credentialIssuerKey(issuer) {
  log.debug("Entering credentialIssuerKey().");
  if (!issuer.keyPromise) {
    issuer.keyPromise = issuerKey(issuer.header || {}, issuer.payload || {},
                                  issuer.ctx.fetchJson,
                                  { format: issuer.format });
    issuer.keyPromise.catch(function () {
      // Reported by each caller that awaits it.
    });
  }
  log.debug("Leaving credentialIssuerKey().");
  return issuer.keyPromise;
}

// The signature on a Status List Token. draft-ietf-oauth-status-list-21
// section 11.3 has a token signed with the credential's own key name it by
// "the same x5c value or an x5t, x5t#S256 or kid parameter", and a Status
// Issuer with its own key name that key (x5c, a DID, an https iss's
// metadata). So the keys tried, in order, until one verifies:
//   1. the credential issuer's key, when the token references it;
//   2. the token's own key, when it names one;
//   3. the credential issuer's key otherwise — when the token names no key
//      of its own, and as the fallback when its own could not be had or did
//      not verify (an https iss with no jwt-vc-issuer metadata), unless the
//      token carries an x5c, which names exactly one key.
// `how` says which verified: "credential" or "own".
//
// `verifyOne(key)` checks the token's own signature with one key: a JWS's
// or a COSE_Sign1's (#471, E5), so both forms take the same keys.
async function statusListSignature(verifyOne, h, p, issuer) {
  log.debug("Entering statusListSignature().");
  var ctx = issuer.ctx;
  var own = (isArray(h.x5c) && h.x5c.length > 0) ||
      didLib.isDid(String(h.kid || "")) ||
      didLib.isDid(String(p.iss || "")) ||
      /^https:\/\//.test(String(p.iss || ""));
  var ref = sameKeyReference(h, issuer.header || {});
  var order = ref ? ["credential", "own"] : ["own", "credential"];
  if (!own) {
    order = ["credential"];
  } else if (!ref && isArray(h.x5c) && h.x5c.length) {
    order = ["own"];
  }
  var failures = [];
  for (var i = 0; i < order.length; i++) {
    var how = order[i];
    var whose = how === "own" ? "its own key" :
      "the credential issuer's key";
    var found;
    try {
      found = how === "own" ? await issuerKey(h, p, ctx.fetchJson) :
        await credentialIssuerKey(issuer);
    } catch (e) {
      failures.push(whose + ": " + e.message);
      continue;
    }
    // The credential's key is the ONE it was signed with (section 11.3:
    // "the same key ... as used in the Referenced Token"), not any member
    // of its issuer's set; the set only when that is ambiguous.
    var signing = how === "own" ? null :
      credentialSigningKey(found.key, issuer.header || {});
    // The credential's key is named by the CREDENTIAL's kid, the list's
    // own by the list's.
    var v = signing ? verifyOne(signing) :
      verifyFoundBy(verifyOne, found, how === "own" ? h :
                    issuer.header || {});
    if (v.valid) {
      var why = how === "own" ? "" : ref ? ", which the list references " +
        "by " + ref : !own ? " (the list names no key of its own)" :
        " (its own key: " + failures.join("; ") + ")";
      log.debug("Leaving statusListSignature(). " + how);
      return { valid: true, how: how, ref: ref, from: (how === "own" ?
        found.from : "the credential issuer's key, from " + found.from) +
        why };
    }
    failures.push(whose + " from " + found.from + (v.reason ?
      " (" + v.reason + ")" : ""));
  }
  log.debug("Leaving statusListSignature(). Nothing verifies.");
  return { valid: false, how: "", ref: ref, from: failures.join("; "),
           reason: "" };
}

// The one key the credential was signed with, out of what issuerKey()
// found: a certificate, a single JWK, or the member of a set its kid names
// (or the only member). Null when a set leaves it ambiguous.
function credentialSigningKey(key, ih) {
  log.debug("Entering credentialSigningKey().");
  if (typeof key === "string") {
    log.debug("Leaving credentialSigningKey(). PEM.");
    return key;
  }
  if (key && key.jwk) {
    log.debug("Leaving credentialSigningKey(). One JWK.");
    return { jwk: key.jwk };
  }
  var keys = key && isArray(key.keys) ? key.keys : [];
  var named = ih.kid ? keys.filter(function (k) {
    return k && k.kid === ih.kid;
  }) : keys;
  if (named.length === 1) {
    log.debug("Leaving credentialSigningKey(). From the set.");
    return { jwk: named[0] };
  }
  log.debug("Leaving credentialSigningKey(). Ambiguous.");
  return null;
}

// Is the Status List Token's signer the credential issuer, or authorised by
// it? draft-ietf-oauth-status-list-21 section 1: the Status Issuer is the
// Issuer or an entity it authorised; section 11.3 names the ways a verifier
// can tell — the same key, the same web-based key resolution, or a
// different key "cryptographically linked ... by a Certificate Authority
// through an x.509 PKI", both certificates "issued by the same Certificate
// Authority and the Status Issuer's certificate should utilize extended key
// usage" (section 10's id-kp-oauthStatusSigning). Anything else is NOT
// linked, and says so as a SKIP: a signature that verifies with a key
// nobody tied to the issuer is not a PASS.
async function statusSignerLink(verifyOne, h, p, issuer, sig) {
  log.debug("Entering statusSignerLink().");
  if (!sig.valid) {
    log.debug("Leaving statusSignerLink(). No signature.");
    return { status: SKIP, detail: "the Status List Token's signature did " +
      "not verify, so there is no signer to link to the credential's " +
      "issuer." };
  }
  var credKey = null;
  try {
    credKey = await credentialIssuerKey(issuer);
  } catch (e) {
    log.debug("statusSignerLink(): no credential key: " + e.message);
  }
  var single = credKey ? credentialSigningKey(credKey.key,
                                              issuer.header || {}) : null;
  if (single && verifyOne(single).valid) {
    log.debug("Leaving statusSignerLink(). Same key.");
    return { status: PASS, detail: "the same key: the list is signed with " +
      "the key the credential was signed with" + (sig.ref ?
      ", which the list references by " + sig.ref : "") + " (section " +
      "11.3)." };
  }
  if (sig.how === "credential") {
    log.debug("Leaving statusSignerLink(). Same key set.");
    return { status: PASS, detail: "the same key resolution: the list " +
      "verifies with " + sig.from + ", a key the credential's issuer " +
      "publishes, though not the one the credential was signed with " +
      "(section 11.3)." };
  }
  var mine = x5cParts(h);
  var theirs = x5cParts(issuer.header || {});
  var oids = [].concat(issuer.ctx.statusSigningEku || []).map(String);
  var notes = [];
  if (mine.length && theirs.length) {
    var cas = mine.slice(1).concat(theirs.slice(1));
    var ca = cas.filter(function (c) {
      return statusCertSignedBy(mine[0], c) &&
        statusCertSignedBy(theirs[0], c);
    })[0];
    if (ca) {
      var eku = mine[0].ekus.filter(function (o) {
        return oids.indexOf(o) !== -1;
      })[0];
      if (eku) {
        log.debug("Leaving statusSignerLink(). Same CA and EKU.");
        return { status: PASS, detail: "the same chain: the list's " +
          "certificate and the credential's were both issued by " +
          ca.subjectText + ", and the list's carries " +
          STATUS_SIGNING_EKU_NAME + " (" + eku + ") in its extended key " +
          "usage (sections 10 and 11.3)." };
      }
      log.debug("Leaving statusSignerLink(). Same CA, no EKU.");
      return { status: SKIP, detail: "NOT linked: the list's certificate " +
        "and the credential's were both issued by " + ca.subjectText +
        ", but the list's does not carry " + STATUS_SIGNING_EKU_NAME +
        ", so that CA has not delegated status signing to it (section " +
        "10)" + (oids.length ? "; its extended key usages are [" +
        mine[0].ekus.join(", ") + "]" : "; that EKU has no OID yet " +
        "(section 14.9 asks IANA for 1.3.6.1.5.5.7.3.TBD), so give " +
        "verifyResponse() statusSigningEku to name the one this PKI " +
        "uses") + "." };
    }
    if (mine[0].issuer === theirs[0].issuer) {
      notes.push("both certificates name the same issuing CA, but no CA " +
        "certificate in either x5c verifies both, so that is unchecked");
    }
  }
  var credIss = String((issuer.payload || {}).iss || issuer.id || "");
  var ownIss = String(p.iss || "") || (didLib.isDid(String(h.kid || "")) ?
    String(h.kid).split("#")[0] : "");
  if (credIss && ownIss === credIss && !mine.length) {
    log.debug("Leaving statusSignerLink(). Same resolution.");
    return { status: PASS, detail: "the same web-based key resolution: " +
      "the list's issuer is the credential's (" + credIss + ") and its " +
      "key came from " + sig.from + " (section 11.3)." };
  }
  log.debug("Leaving statusSignerLink(). None.");
  return { status: SKIP, detail: "NOT linked: the list verifies with " +
    sig.from + ", which is not the credential issuer's key, not issued " +
    "by the same CA with " + STATUS_SIGNING_EKU_NAME + ", and not found " +
    "through the credential issuer's own key resolution" + (notes.length ?
    "; " + notes.join("; ") : "") + ". draft-ietf-oauth-status-list-21 " +
    "section 1: the Status Issuer is the Issuer or an entity it " +
    "authorised; nothing here shows that this one is." };
}

// draft-ietf-oauth-status-list-21 section 7.1, by value.
function tokenStatusName(value) {
  log.debug("Entering tokenStatusName().");
  var hex = "0x" + (value < 16 ? "0" : "") + value.toString(16)
    .toUpperCase();
  var name = TOKEN_STATUS_NAMES[value] ? TOKEN_STATUS_NAMES[value] :
    TOKEN_STATUS_APPLICATION.indexOf(value) !== -1 ? hex + ", reserved as " +
    "application-specific" : hex + ", reserved for future registration";
  log.debug("Leaving tokenStatusName().");
  return name;
}

// ---------------------------------------------------------------------------
// The two forms of a Status List Token, read into the one shape the checks
// in checkTokenStatus() share: { form, header, payload, statusList: { bits,
// lst, aggregationUri }, lstBytes(), verify(key), problems, notes, summary }.
// `header` is JOSE-shaped for both (alg, kid, x5c, x5t, x5t#S256), so the
// key choice and the signer link (section 11.3) are one implementation;
// `verify(key)` checks the token's own signature with one key.
// ---------------------------------------------------------------------------

// Section 5.1. Throws when the compact JWS will not decode.
function readJwtStatusToken(compact) {
  log.debug("Entering readJwtStatusToken().");
  var list = decodeJwt(compact);
  var h = list.header || {};
  var p = list.payload || {};
  var problems = [];
  var notes = [];
  if (mediaTypeOfTyp(h.typ) !== mediaTypeOfTyp(STATUS_LIST_TYP)) {
    problems.push("typ is " + JSON.stringify(h.typ) + ', not "' +
                  STATUS_LIST_TYP + '" (or "application/' +
                  STATUS_LIST_TYP + '", RFC 7515 section 4.1.9)');
  } else if (h.typ !== STATUS_LIST_TYP) {
    notes.push("typ " + JSON.stringify(h.typ) + " is " + STATUS_LIST_TYP +
               " by RFC 7515 section 4.1.9's comparison");
  }
  var sl = isPlainObject(p.status_list) ? p.status_list : {};
  log.debug("Leaving readJwtStatusToken().");
  return {
    form: "JWT", mediaType: "application/" + STATUS_LIST_TYP, header: h,
    payload: p, problems: problems, notes: notes,
    statusList: { bits: sl.bits, lst: typeof sl.lst === "string" ?
      sl.lst : null, aggregationUri: sl.aggregation_uri },
    lstBytes: function lstBytes() {
      log.debug("Entering lstBytes(). JWT.");
      log.debug("Leaving lstBytes().");
      return bytes.b64uToBytes(sl.lst);
    },
    verify: function verify(key) {
      log.debug("Entering verify(). JWT.");
      log.debug("Leaving verify().");
      return verifyCompact(compact, key);
    },
    unreadable: "status_list must carry bits (1, 2, 4 or 8) and lst; it " +
      "has bits " + JSON.stringify(sl.bits),
    summary: "typ " + STATUS_LIST_TYP + ", sub is the credential's uri, " +
      "signed (" + h.alg + ")"
  };
}

// A COSE header parameter, from the protected bucket first (RFC 9052
// section 3: a label appears in one bucket only).
function coseHeaderParam(prot, unprot, label) {
  log.debug("Entering coseHeaderParam(). " + label);
  log.debug("Leaving coseHeaderParam().");
  return prot.has(label) ? prot.get(label) :
    unprot instanceof Map ? unprot.get(label) : undefined;
}

// A COSE kid (a byte string) as the text a JOSE kid would be, or its hex
// when it is not UTF-8.
function coseKidText(kid) {
  log.debug("Entering coseKidText().");
  if (typeof kid === "string") {
    log.debug("Leaving coseKidText(). Text.");
    return kid;
  }
  var b = bytes.asBytes(kid);
  try {
    var text = new TextDecoder("utf-8", { fatal: true }).decode(b);
    log.debug("Leaving coseKidText(). UTF-8.");
    return text;
  } catch (e) {
    log.debug("Leaving coseKidText(). Hex.");
    return Array.prototype.map.call(b, function (x) {
      return (x < 16 ? "0" : "") + x.toString(16);
    }).join("");
  }
}

// Section 5.2: a CWT (RFC 8392) in a COSE_Sign1_Tagged (18), never in the
// CWT tag (61); type (16) application/statuslist+cwt in the protected
// header; the Claims Set's 2 (subject), 6 (issued at), 4 (expiration),
// 65534 (time to live) and 65533 (the section 4.3 StatusList map, whose lst
// is a byte string). The key is named by RFC 9052's kid (4) or RFC 9360's
// x5chain (33) and x5t (34), which section 11.3 lists for COSE. Throws when
// the structure cannot be read at all.
function readCwtStatusToken(cose) {
  log.debug("Entering readCwtStatusToken().");
  var parts = cose.parts;
  var problems = [];
  var notes = [];
  if (cose.tags.indexOf(18) === -1) {
    problems.push("it is not tagged COSE_Sign1_Tagged (18), which section " +
                  "5.2 requires");
  }
  if (cose.tags.indexOf(61) !== -1) {
    problems.push("it is tagged with RFC 8392's CWT tag (61), which " +
                  "section 5.2 says it MUST NOT be");
  }
  var prot;
  try {
    prot = parts[0].length ? cbor.decode(parts[0]) : new Map();
  } catch (e) {
    log.debug("Leaving readCwtStatusToken(). Bad protected header.");
    throw new Error("its protected header is not CBOR: " + e.message);
  }
  if (!(prot instanceof Map)) {
    log.debug("Leaving readCwtStatusToken(). Protected not a map.");
    throw new Error("its protected header is not a CBOR map.");
  }
  var unprot = parts[1];
  var typ = prot.get(COSE_HDR_TYP);
  if (typ === undefined) {
    problems.push(unprot.has(COSE_HDR_TYP) ? "its type (16) is in the " +
      "unprotected header, and section 5.2 puts it in the protected one" :
      "its protected header carries no type (16); section 5.2 requires " +
      STATUS_LIST_CWT_TYPE);
  } else if (typeof typ === "number") {
    notes.push("type (16) is the CoAP Content-Format " + typ + ", and " +
               "section 14.8's number is still TBD, so it is reported and " +
               "not judged");
  } else if (String(typ).trim().toLowerCase() !== STATUS_LIST_CWT_TYPE) {
    problems.push("type (16) is " + JSON.stringify(typ) + ', not "' +
                  STATUS_LIST_CWT_TYPE + '"');
  } else if (typ !== STATUS_LIST_CWT_TYPE) {
    notes.push("type " + JSON.stringify(typ) + " is " +
               STATUS_LIST_CWT_TYPE + " compared as a media type");
  }
  var alg = coseHeaderParam(prot, unprot, COSE_HDR_ALG);
  if (alg !== undefined && !prot.has(COSE_HDR_ALG)) {
    notes.push("alg (1) is in the unprotected header (RFC 9052 section " +
               "3.1 asks for the protected one)");
  }
  var h = { alg: cose.mac ? "MAC" : coseAlgName(alg) };
  var kid = coseHeaderParam(prot, unprot, COSE_HDR_KID);
  if (kid instanceof Uint8Array || typeof kid === "string") {
    h.kid = coseKidText(kid);
  }
  var chain = coseHeaderParam(prot, unprot, COSE_HDR_X5CHAIN);
  chain = chain instanceof Uint8Array ? [chain] : isArray(chain) ? chain : [];
  if (chain.length && chain.every(function (c) {
    return c instanceof Uint8Array;
  })) {
    h.x5c = chain.map(function (c) {
      return bytes.bytesToB64(c);
    });
  }
  var x5t = coseHeaderParam(prot, unprot, COSE_HDR_X5T);
  if (isArray(x5t) && x5t[1] instanceof Uint8Array) {
    if (x5t[0] === COSE_X5T_SHA256) {
      h["x5t#S256"] = bytes.bytesToB64u(x5t[1]);
    } else if (x5t[0] === COSE_X5T_SHA1) {
      h.x5t = bytes.bytesToB64u(x5t[1]);
    } else {
      notes.push("its x5t (34) uses hash " + JSON.stringify(x5t[0]) +
                 ", which this debugger does not match against a " +
                 "certificate");
    }
  }
  if (!(parts[2] instanceof Uint8Array)) {
    log.debug("Leaving readCwtStatusToken(). Detached payload.");
    throw new Error("its payload is detached (null), and a CWT carries " +
                    "its Claims Set as the payload (RFC 8392 section 7.1).");
  }
  var claims;
  try {
    claims = cbor.decode(parts[2]);
  } catch (e) {
    log.debug("Leaving readCwtStatusToken(). Bad Claims Set.");
    throw new Error("its payload is not CBOR: " + e.message);
  }
  if (!(claims instanceof Map)) {
    log.debug("Leaving readCwtStatusToken(). Claims Set not a map.");
    throw new Error("its payload is not a CWT Claims Set (a CBOR map).");
  }
  var p = {};
  [["iss", CWT_ISS], ["sub", CWT_SUB], ["exp", CWT_EXP], ["nbf", CWT_NBF],
   ["iat", CWT_IAT], ["ttl", CWT_TTL]].forEach(function (pair) {
    if (claims.has(pair[1])) p[pair[0]] = claims.get(pair[1]);
  });
  var sl = claims.get(CWT_STATUS_LIST);
  sl = sl instanceof Map ? sl : new Map();
  var lst = sl.get("lst") instanceof Uint8Array ? sl.get("lst") : null;
  var name = cose.mac ? "COSE_Mac0" : "COSE_Sign1";
  log.debug("Leaving readCwtStatusToken().");
  return {
    form: "CWT", mediaType: STATUS_LIST_CWT_TYPE, header: h, payload: p,
    problems: problems, notes: notes,
    statusList: { bits: sl.get("bits"), lst: lst,
                  aggregationUri: sl.get("aggregation_uri") },
    lstBytes: function lstBytes() {
      log.debug("Entering lstBytes(). CWT.");
      log.debug("Leaving lstBytes().");
      return lst;
    },
    verify: function verify(key) {
      log.debug("Entering verify(). CWT.");
      var v = mdoc.verifyCoseSignature(alg, key,
        mdoc.sigStructure(parts[0], parts[2]), parts[3]);
      log.debug("Leaving verify(). " + v.ok);
      return { valid: v.ok, reason: v.reason };
    },
    unreadable: "the status list (65533) must be a map carrying bits (1, " +
      "2, 4 or 8) and lst as a byte string (section 4.3); it has bits " +
      JSON.stringify(sl.get("bits")) + (lst ? "" : " and no byte string lst"),
    summary: "a CWT (" + name + (cose.tags.indexOf(18) !== -1 ?
      "_Tagged" : "") + ", type " + (typeof typ === "string" ? typ :
      JSON.stringify(typ)) + "), sub (2) is the credential's uri, signed (" +
      h.alg + ", COSE " + alg + ")"
  };
}

// The COSE algorithm's name, or the number when it has none here.
function coseAlgName(alg) {
  log.debug("Entering coseAlgName().");
  var a = coseLib.algorithm(alg);
  log.debug("Leaving coseAlgName().");
  return a ? a.name : "COSE " + JSON.stringify(alg);
}

async function checkTokenStatus(s, key, ref, issuer) {
  log.debug("Entering checkTokenStatus().");
  var ctx = issuer.ctx;
  var label = "The credential is VALID in its Token Status List";
  var listLabel = "The Status List Token verifies";
  var signerLabel = "The Status List Token's signer is the credential's " +
      "issuer, or authorised by it";
  var idx = ref.idx;
  var uri = ref.uri;
  if (typeof idx !== "number" || idx < 0 || Math.floor(idx) !== idx ||
      typeof uri !== "string" || !uri) {
    s.add(key, label, FAIL, "status.status_list must carry a non-negative " +
          "integer idx and a uri; it is " + JSON.stringify(ref) + ".");
    log.debug("Leaving checkTokenStatus(). Malformed reference.");
    return;
  }
  var fetched;
  try {
    fetched = await fetchStatusText(ctx, uri, STATUS_LIST_ACCEPT);
  } catch (e) {
    // A list that could not be FETCHED is a check not performed, not a
    // defect in the credential (#470 B3): the fetch may have failed for a
    // reason that is this debugger's (CORS, a proxy, the network). A list
    // that arrives and is wrong is a FAIL, below.
    s.add(key + ".list", listLabel, SKIP, "could not fetch " + uri + ": " +
          e.message);
    s.add(key, label, SKIP, "the status list could not be read (idx " +
          idx + ").");
    log.debug("Leaving checkTokenStatus(). Fetch failed.");
    return;
  }
  var body = statusBody(fetched);
  var compact = body.text !== null ? body.text.trim() : "";
  var tok;
  try {
    if (COMPACT_JWS.test(compact)) {
      tok = readJwtStatusToken(compact);
    } else {
      var what = describeStatusBody(body);
      if (what.kind !== "cose") {
        s.add(key + ".list", listLabel, FAIL, uri + " did not answer " +
              "with a Status List Token: it answered " + what.detail +
              ". draft-ietf-oauth-status-list-21 section 8.2: the body " +
              "is the JWS Compact Serialization of the token, or the " +
              "binary CWT.");
        s.add(key, label, SKIP, "the status list was not read (idx " + idx +
              ").");
        log.debug("Leaving checkTokenStatus(). Neither form: " + what.kind);
        return;
      }
      if (what.cose.mac) {
        s.add(key + ".list", listLabel, SKIP, uri + " answered " +
              what.detail + ": a CWT Status List Token secured with a MAC " +
              "(draft-ietf-oauth-status-list-21 section 5.2 allows " +
              "COSE_Mac0_Tagged), which needs a key the Status Issuer " +
              "shares with its Relying Parties. This Verifier holds none, " +
              "so the list is not verified.");
        s.add(key, label, SKIP, "the status list was not verified (idx " +
              idx + ").");
        log.debug("Leaving checkTokenStatus(). COSE_Mac0.");
        return;
      }
      tok = readCwtStatusToken(what.cose);
    }
  } catch (e) {
    s.add(key + ".list", listLabel, FAIL, "unreadable: " + e.message);
    s.add(key, label, SKIP, "the status list was not read.");
    log.debug("Leaving checkTokenStatus(). Unreadable.");
    return;
  }
  var h = tok.header;
  var p = tok.payload;
  var problems = tok.problems.slice();
  var notes = tok.notes.slice();
  var served = body.contentType.split(";")[0].trim().toLowerCase();
  if (served && served !== tok.mediaType) {
    notes.push("it was served as " + served + ", not " + tok.mediaType +
               " (section 8.2)");
  }
  var subName = tok.form === "CWT" ? "sub (2)" : "sub";
  if (p.sub !== uri) {
    problems.push(subName + " is " + JSON.stringify(p.sub) + ", not the " +
                  "uri the credential names (" + uri + ")");
  }
  if (typeof p.iat !== "number") problems.push("there is no numeric iat");
  if (typeof p.exp === "number") {
    if (ctx.now > p.exp + SKEW_SECONDS) {
      problems.push("it expired at " + isoOf(p.exp));
    } else {
      notes.push("valid until " + isoOf(p.exp));
    }
  }
  if (typeof p.nbf === "number" && ctx.now + SKEW_SECONDS < p.nbf) {
    problems.push("it is not valid before " + isoOf(p.nbf));
  }
  if (p.ttl !== undefined) {
    if (typeof p.ttl !== "number" || !(p.ttl > 0)) {
      problems.push("ttl is " + JSON.stringify(p.ttl) + ", and sections " +
                    "5.1 and 5.2 make it a positive number");
    } else {
      notes.push("ttl " + p.ttl + "s, so a fresh copy is due by " +
                 isoOf((typeof p.iat === "number" ? p.iat : ctx.now) +
                       p.ttl));
    }
  }
  var sl = tok.statusList;
  if (typeof sl.aggregationUri === "string" && sl.aggregationUri) {
    notes.push("its aggregation_uri is " + sl.aggregationUri +
               " (section 9)");
  }
  var readable = [1, 2, 4, 8].indexOf(sl.bits) !== -1 && sl.lst !== null;
  if (!readable) problems.push(tok.unreadable);
  var sig = await statusListSignature(tok.verify, h, p, issuer);
  if (!sig.valid) {
    problems.push("the signature does NOT verify with " + sig.from);
  }
  var credIss = (issuer.payload || {}).iss;
  if (p.iss && credIss && p.iss !== credIss) {
    notes.push("its iss " + p.iss + " is not the credential's issuer " +
               credIss);
  }
  s.add(key + ".list", listLabel, problems.length ? FAIL : PASS,
        problems.length ? (tok.form === "CWT" ? "the CWT Status List " +
        "Token: " : "") + problems.join("; ") + "." : tok.summary +
        " with " + sig.from + (notes.length ? "; " + notes.join("; ") : "") +
        ".");
  var link = await statusSignerLink(tok.verify, h, p, issuer, sig);
  s.add(key + ".signer", signerLabel, link.status, link.detail);
  if (!readable) {
    s.add(key, label, SKIP, "the list itself could not be read.");
    log.debug("Leaving checkTokenStatus(). Unreadable list.");
    return;
  }
  var raw;
  try {
    raw = await inflate(tok.lstBytes(), "deflate");
  } catch (e) {
    s.add(key, label, FAIL, "the status list's lst does not decompress " +
          "as zlib DEFLATE: " + e.message);
    log.debug("Leaving checkTokenStatus(). Not DEFLATE.");
    return;
  }
  var count = raw.length * 8 / sl.bits;
  if (idx >= count) {
    s.add(key, label, FAIL, "idx " + idx + " is beyond the list's " + count +
          " entries.");
    log.debug("Leaving checkTokenStatus(). Out of range.");
    return;
  }
  var value = tokenStatusAt(raw, idx, sl.bits);
  var name = tokenStatusName(value);
  var where = "idx " + idx + " of " + uri + " is " + value + " (" + name +
      ")";
  if (problems.length) {
    s.add(key, label, SKIP, where + ", but the Status List Token did not " +
          "verify, so that value is not relied on.");
    log.debug("Leaving checkTokenStatus(). List not trusted.");
    return;
  }
  var unlinked = link.status === PASS ? "" : "; the list's signer is not " +
      "shown to be the credential's issuer (" + key + ".signer)";
  if (value > 2) {
    // Section 7.1: 0x03 and 0x0C-0x0F are "application specific" and their
    // processing "is application specific"; the rest are unregistered. A
    // debugger that does not know the application cannot call either
    // valid or invalid, so it reports the value and decides nothing.
    s.add(key, label, SKIP, where + ": draft-ietf-oauth-status-list-21 " +
          "section 7.1 leaves its meaning to the application, so this " +
          "Verifier reports it and does not judge it" + unlinked + ".");
    log.debug("Leaving checkTokenStatus(). " + name);
    return;
  }
  s.add(key, label, value === 0 ? PASS : FAIL, value === 0 ? where +
        unlinked + "." : value === 1 ? where + ": the credential is " +
        "revoked" + unlinked + "." : where + ": the credential is " +
        "suspended" + unlinked + ".");
  log.debug("Leaving checkTokenStatus(). " + name);
}

function issuerIdOf(credential) {
  log.debug("Entering issuerIdOf().");
  var iss = credential && credential.issuer;
  log.debug("Leaving issuerIdOf().");
  return typeof iss === "string" ? iss : (iss && iss.id) || "";
}

// The status list credential: a VC JWT (signature by issuerKey()) or a
// JSON-LD credential with a Data Integrity proof this debugger verifies.
async function readStatusListCredential(text, ctx) {
  log.debug("Entering readStatusListCredential().");
  var body = statusBody(text);
  var t = body.text === null ? "" : body.text.trim();
  if (!COMPACT_JWS.test(t) && !/^\{/.test(t)) {
    log.debug("Leaving readStatusListCredential(). Neither.");
    throw new Error("it is " + describeStatusBody(body).detail + ", not a " +
                    "VC JWT or a JSON credential.");
  }
  var problems = [];
  var credential;
  var secured;
  if (COMPACT_JWS.test(t)) {
    var d = decodeJwt(t);
    credential = d.payload.vc || d.payload;
    var keyPayload = Object.assign({}, d.payload);
    if (!keyPayload.iss) keyPayload.iss = issuerIdOf(credential);
    var found = null;
    try {
      found = await issuerKey(d.header, keyPayload, ctx.fetchJson,
                              { format: FORMAT_JWT_VC_JSON });
    } catch (e) {
      problems.push((e.unresolved ? "could not resolve the key for its " +
                     "signature: " : "no key for its signature: ") +
                    e.message);
    }
    if (found) {
      var v = verifyFound(t, found, d.header);
      if (!v.valid) {
        problems.push("its JWT signature does NOT verify with the key from " +
                      found.from + (v.reason ? " (" + v.reason + ")" : ""));
      }
      secured = "a VC JWT (" + d.header.alg + ") verified with the key " +
        "from " + found.from;
    }
    var win = sdJwtVc.validityWindowOf({ payload: d.payload });
    var verdict = validityVerdict(win, d.payload.iat, ctx.now);
    if (verdict.status === FAIL) problems.push(verdict.detail);
    // A VC-JWT carries the credential's own validity too: Bitstring Status
    // List v1.0 section 2.2 names validFrom and validUntil on the status
    // list credential, and a JWT's nbf and exp do not replace them.
    var vcWin = ldpWindow(credential);
    if (vcWin.notBefore !== null || vcWin.expires !== null) {
      var vcVerdict = validityVerdict(vcWin, null, ctx.now);
      if (vcVerdict.status === FAIL) problems.push(vcVerdict.detail);
    }
    if (!credential.issuer && d.payload.iss) {
      credential = Object.assign({ issuer: d.payload.iss }, credential);
    }
    log.debug("Leaving readStatusListCredential(). JWT.");
    return { credential: credential, problems: problems, secured: secured };
  }
  credential = JSON.parse(t);
  if (!isPlainObject(credential)) {
    log.debug("Leaving readStatusListCredential(). Not an object.");
    throw new Error("it is neither a JWT nor a JSON object.");
  }
  if (!credential.proof) {
    problems.push("it is unsecured: neither a JWT nor carrying a proof");
  } else {
    var r = await verifyDataIntegrity(credential, { fetchJson: ctx.fetchJson,
      purpose: "assertionMethod", now: ctx.now });
    if (r.unsupported) {
      problems.push("its proof is not one this debugger verifies: " +
                    r.reason);
    } else if (!r.valid) {
      problems.push("its proof does NOT verify: " + r.reason);
    } else {
      secured = r.reason.replace(/\.$/, "");
      var foreign = vmNotAuthorised(r.verificationMethod,
                                    issuerIdOf(credential));
      if (foreign) problems.push(foreign.replace(/\.$/, ""));
    }
  }
  var w = ldpWindow(credential);
  var lv = validityVerdict(w, null, ctx.now);
  if (lv.status === FAIL) problems.push(lv.detail);
  log.debug("Leaving readStatusListCredential(). JSON.");
  return { credential: credential, problems: problems, secured: secured };
}

// validFrom / validUntil (VCDM 2.0), else issuanceDate / expirationDate.
function ldpWindow(credential) {
  log.debug("Entering ldpWindow().");
  var c = credential || {};
  var from = c.validFrom || c.issuanceDate;
  var until = c.validUntil || c.expirationDate;
  log.debug("Leaving ldpWindow().");
  return {
    notBefore: from ? Math.floor(Date.parse(from) / 1000) : null,
    expires: until ? Math.floor(Date.parse(until) / 1000) : null,
    notBeforeMember: c.validFrom ? "validFrom" : "issuanceDate",
    expiresMember: c.validUntil ? "validUntil" : "expirationDate"
  };
}

var BITSTRING_ENTRY_TYPES = ["BitstringStatusListEntry",
                             "StatusList2021Entry"];
var BITSTRING_LIST_TYPES = ["BitstringStatusListCredential",
                            "StatusList2021Credential"];

async function checkBitstringEntry(s, key, entry, issuer) {
  log.debug("Entering checkBitstringEntry(). " + key);
  var ctx = issuer.ctx;
  var purpose = String(entry.statusPurpose || "");
  var label = "Bitstring Status List: " + (purpose || "(no statusPurpose)");
  var listLabel = "The status list credential verifies (" +
      (purpose || "no purpose") + ")";
  var type = String(entry.type || "");
  if (BITSTRING_ENTRY_TYPES.indexOf(type) === -1) {
    s.add(key, label, SKIP, "credentialStatus type " + JSON.stringify(type) +
          " is not a status method this debugger reads (" +
          BITSTRING_ENTRY_TYPES.join(", ") + ").");
    log.debug("Leaving checkBitstringEntry(). Unknown type.");
    return;
  }
  var url = String(entry.statusListCredential || "");
  var index = Number(entry.statusListIndex);
  var size = entry.statusSize === undefined ? 1 : Number(entry.statusSize);
  if (!url || !/^\d+$/.test(String(entry.statusListIndex)) ||
      !(size >= 1 && Math.floor(size) === size)) {
    s.add(key, label, FAIL, "a " + type + " needs statusListCredential, " +
          "a non-negative integer statusListIndex and a positive integer " +
          "statusSize; it is " + JSON.stringify(entry) + ".");
    log.debug("Leaving checkBitstringEntry(). Malformed.");
    return;
  }
  var messages = entry.statusMessage;
  var wantMessages = Math.pow(2, size);
  if (size > 1 && !isArray(messages)) {
    s.add(key + ".entry", "The status entry is well formed", FAIL,
          "statusSize is " + size + " and there is no statusMessage. " +
          "Bitstring Status List v1.0 section 2.1: \"If statusSize is " +
          "provided and is greater than 1, then the property " +
          "credentialStatus.statusMessage MUST be present\" (a " +
          "MALFORMED_VALUE_ERROR, section 3).");
  } else if (messages !== undefined && (!isArray(messages) ||
             (size <= 16 && messages.length !== wantMessages))) {
    s.add(key + ".entry", "The status entry is well formed", FAIL,
          "statusMessage must be an array of " + wantMessages + " " +
          "element(s) for a statusSize of " + size + " (section 2.1); it " +
          "is " + (isArray(messages) ? "an array of " + messages.length :
          JSON.stringify(messages)) + ".");
  }
  var read;
  var text;
  try {
    text = await fetchStatusText(ctx, url, BITSTRING_ACCEPT);
  } catch (e) {
    // Not fetched is not performed, as in checkTokenStatus() (#470 B3).
    s.add(key + ".list", listLabel, SKIP, "could not fetch " + url + ": " +
          e.message);
    s.add(key, label, SKIP, "the status list could not be read.");
    log.debug("Leaving checkBitstringEntry(). Not fetched.");
    return;
  }
  try {
    read = await readStatusListCredential(text, ctx);
  } catch (e) {
    s.add(key + ".list", listLabel, FAIL, "reading " + url + " failed: " +
          e.message);
    s.add(key, label, SKIP, "the status list could not be read.");
    log.debug("Leaving checkBitstringEntry(). Unreadable.");
    return;
  }
  var cred = read.credential || {};
  var problems = read.problems.slice();
  var types = [].concat(cred.type || []);
  if (!types.some(function (t) {
    return BITSTRING_LIST_TYPES.indexOf(t) !== -1;
  })) {
    problems.push("its type [" + types.join(", ") + "] is not " +
                  BITSTRING_LIST_TYPES.join(" or "));
  }
  var subject = [].concat(cred.credentialSubject || [])[0] || {};
  var purposes = [].concat(subject.statusPurpose || []);
  if (purposes.indexOf(purpose) === -1) {
    problems.push("its statusPurpose " + JSON.stringify(
      subject.statusPurpose) + " is not the entry's " +
      JSON.stringify(purpose));
  }
  var notes = [];
  var listIssuer = issuerIdOf(cred);
  if (issuer.id && listIssuer && listIssuer !== issuer.id) {
    // Section 2.2: "the issuer value of a verifiable credential containing
    // a BitstringStatusListEntry MAY be different from the issuer value of
    // a BitstringStatusListCredential." Reported, not refused; whether to
    // trust that issuer is the Verifier's call (section 3.2's note).
    notes.push("its issuer " + listIssuer + " is not the credential's " +
               "issuer " + issuer.id + ", which section 2.2 allows; " +
               "whether that issuer is trusted to say this is the " +
               "Verifier's decision");
  }
  var encoded = typeof subject.encodedList === "string" ?
      subject.encodedList : "";
  if (!encoded) problems.push("credentialSubject.encodedList is missing");
  s.add(key + ".list", listLabel, problems.length ? FAIL : PASS,
        problems.length ? problems.join("; ") + "." : url + ": " +
        read.secured + "; purpose " + purpose +
        (notes.length ? "; " + notes.join("; ") : "") + ".");
  if (!encoded) {
    s.add(key, label, SKIP, "there is no encodedList to read.");
    log.debug("Leaving checkBitstringEntry(). No list.");
    return;
  }
  var raw;
  try {
    raw = await inflate(bytes.b64uToBytes(encoded.charAt(0) === "u" ?
      encoded.slice(1) : encoded), "gzip");
  } catch (e) {
    s.add(key, label, FAIL, "encodedList is not multibase base64url of " +
          "GZIP data: " + e.message);
    log.debug("Leaving checkBitstringEntry(). Not GZIP.");
    return;
  }
  var entries = Math.floor(raw.length * 8 / size);
  if (index >= entries) {
    s.add(key, label, FAIL, "statusListIndex " + index + " is beyond the " +
          "list's " + entries + " entries.");
    log.debug("Leaving checkBitstringEntry(). Out of range.");
    return;
  }
  var value = bitstringAt(raw, index * size, size);
  var where = "entry " + index + " of " + url + " is " + value +
      (entries < BITSTRING_MIN_ENTRIES ? " (the list has " + entries +
       " entries, fewer than the " + BITSTRING_MIN_ENTRIES + " Bitstring " +
       "Status List v1.0 sets for herd privacy)" : "");
  if (problems.length) {
    s.add(key, label, SKIP, where + ", but the status list credential did " +
          "not verify, so that value is not relied on.");
    log.debug("Leaving checkBitstringEntry(). List not trusted.");
    return;
  }
  if (purpose === "revocation" || purpose === "suspension") {
    var word = purpose === "revocation" ? "revoked" : "suspended";
    s.add(key, label, value === 0 ? PASS : FAIL, where + (value === 0 ?
          ": not " + word + "." : ": the credential is " + word + "."));
  } else if (purpose === "refresh") {
    // Section 2.1: "an updated verifiable credential is available via the
    // credential's refresh service ... This status does not invalidate the
    // verifiable credential and is not reversible."
    s.add(key, label, PASS, where + (value === 0 ? ": no refresh is " +
          "pending." : ": an updated credential is available from its " +
          "refreshService. That does not invalidate this one (section " +
          "2.1)."));
  } else if (purpose === "message") {
    var hex = "0x" + value.toString(16);
    // Section 2.1: each status is "a string representing the hexadecimal
    // value of the status prefixed with 0x", so "0x01" and "0x1" are the
    // same status and are compared as numbers. With no statusMessage, 1
    // and 0 are "set" and "unset".
    var said = [].concat(isArray(messages) ? messages : []).filter(
      function (m) {
        return m && /^0x[0-9a-f]+$/i.test(String(m.status)) &&
          parseInt(String(m.status).slice(2), 16) === value;
      })[0];
    var fallback = !isArray(messages) && size === 1 ?
      (value ? "set" : "unset") : "";
    s.add(key, label, PASS, where + " (" + hex + ")" + (said ?
          ': "' + said.message + '".' : fallback ? ': "' + fallback +
          '" (no statusMessage, section 2.1).' : "; the entry's " +
          "statusMessage names no message for it."));
  } else {
    s.add(key, label, SKIP, where + "; statusPurpose " +
          JSON.stringify(purpose) + " is not one Bitstring Status List " +
          "v1.0 defines (" + BITSTRING_PURPOSES.join(", ") + ").");
  }
  log.debug("Leaving checkBitstringEntry(). " + value);
}

// Every status a credential names, each its own check. `issuer` is
// { header, payload, id } of the credential, for the Status List Token's
// key and the status list credential's issuer.
async function checkCredentialStatus(s, key, refs, issuer, ctx) {
  log.debug("Entering checkCredentialStatus(). " + key);
  var label = "The credential's status";
  var who = Object.assign({ ctx: ctx }, issuer);
  var other = refs.other || [];
  other.forEach(function (name) {
    s.add(key + "." + (slug(name) || "mechanism"), "Status mechanism " +
          name, SKIP, name === "identifier_list" ? "the credential's " +
          "status is an identifier_list (ISO/IEC 18013-5's Identifier " +
          "List), a status mechanism this debugger does not read, so its " +
          "status there is unchecked." : "status." + name + " is a status " +
          "mechanism this debugger does not read (only status_list, " +
          "draft-ietf-oauth-status-list-21 section 6), so its status " +
          "there is unchecked.");
  });
  if (!refs.token && !refs.w3c.length && other.length) {
    log.debug("Leaving checkCredentialStatus(). Unsupported mechanisms.");
    return;
  }
  if (!refs.token && !refs.w3c.length) {
    s.add(key, label, SKIP, "the credential names no status (no " +
          "status.status_list, no credentialStatus), so there is no list " +
          "to check it against.");
    log.debug("Leaving checkCredentialStatus(). None.");
    return;
  }
  if (typeof ctx.fetchText !== "function") {
    var where = (refs.token ? [refs.token.uri] : []).concat(
      refs.w3c.map(function (e) {
        return e.statusListCredential;
      })).join(", ");
    s.add(key, label, SKIP, "no fetchText was given to verifyResponse(), " +
          "so the status list (" + where + ") was not fetched.");
    log.debug("Leaving checkCredentialStatus(). No fetcher.");
    return;
  }
  if (refs.token) await checkTokenStatus(s, key, refs.token, who);
  var used = {};
  for (var i = 0; i < refs.w3c.length; i++) {
    var name = slug(refs.w3c[i].statusPurpose || "entry") || "entry";
    var sub = key + "." + (used[name] ? name + "-" + i : name);
    used[name] = true;
    await checkBitstringEntry(s, sub, refs.w3c[i], who);
  }
  log.debug("Leaving checkCredentialStatus().");
}

// The top-level summary: every status check of every presentation.
function statusSummary(report) {
  log.debug("Entering statusSummary().");
  var mine = report.checks.filter(function (c) {
    return /\.status(\.|$)/.test(c.id);
  });
  var failed = mine.filter(function (c) {
    return c.status === FAIL;
  });
  var passed = mine.filter(function (c) {
    return c.status === PASS;
  });
  var out = failed.length ? { status: FAIL, detail: "failed: " +
      failed.map(function (c) {
        return c.id;
      }).join(", ") + "." } :
    passed.length ? { status: PASS, detail: passed.length + " status " +
      "check(s) passed" + (mine.length > passed.length ? "; " +
      (mine.length - passed.length) + " skipped" : "") + "." } :
    { status: SKIP, detail: mine.length ? "every status check was " +
      "skipped: " + mine.map(function (c) {
        return c.detail;
      }).filter(function (d, i, all) {
        return all.indexOf(d) === i;
      }).join(" ") : "no presentation was checked." };
  log.debug("Leaving statusSummary(). " + out.status);
  return out;
}

// ---------------------------------------------------------------------------
// The mdoc session transcript (OpenID4VP 1.0 Appendix B.2.6), both
// handovers, and the device signature over it, in pure JavaScript.
//
//   OpenID4VPHandover       SHA-256(cbor([client_id, nonce, jwkThumbprint,
//                           response_uri]))       redirects and direct_post
//   OpenID4VPDCAPIHandover  SHA-256(cbor([origin, nonce, jwkThumbprint]))
//                           the DC API; origin WITHOUT the "origin:" prefix
//
// jwkThumbprint is the RFC 7638 thumbprint, as bytes, of the key the
// response is encrypted to (direct_post.jwt, dc_api.jwt), else null.
// ---------------------------------------------------------------------------
function mdocSessionTranscript(session) {
  log.debug("Entering mdocSessionTranscript().");
  var enc = isEncryptedMode(session.responseMode) && session.decryptionJwk ?
      publicPart(session.decryptionJwk) : null;
  var thumb = enc ? bytes.b64uToBytes(jwkThumbprint(enc)) : null;
  if (isDcApiMode(session.responseMode)) {
    var dcInfo = mdoc.encode([String(session.origin || ""),
                              session.nonce, thumb]);
    log.debug("Leaving mdocSessionTranscript(). DC API.");
    return { transcript: [null, null, ["OpenID4VPDCAPIHandover",
                                       nobleSha256(dcInfo)]],
             encrypted: !!enc,
             describe: "OpenID4VPDCAPIHandover transcript (origin " +
               session.origin + ", nonce, " + (enc ? "the encryption " +
               "key's thumbprint" : "no encryption key") + ")" };
  }
  var info = mdoc.encode([session.clientId, session.nonce, thumb,
                          session.responseUri]);
  log.debug("Leaving mdocSessionTranscript().");
  return { transcript: [null, null, ["OpenID4VPHandover",
                                     nobleSha256(info)]],
           encrypted: !!enc,
           describe: "OpenID4VPHandover transcript (client_id, nonce, " +
             (enc ? "the encryption key's thumbprint" : "no encryption " +
             "key") + ", response_uri)" };
}

function mapGet(m, k) {
  log.debug("Entering mapGet().");
  log.debug("Leaving mapGet().");
  return m instanceof Map ? m.get(k) : (m ? m[k] : undefined);
}

// The device signature, by mdoc.js (#469, C8): the COSE alg in its own
// protected header, the Document's docType, and a deviceMac reported as
// not performed. Answers { status, detail }.
function checkMdocDevice(read, transcript) {
  log.debug("Entering checkMdocDevice().");
  var out;
  try {
    out = mdoc.verifyDeviceAuthentication(read, transcript);
  } catch (e) {
    out = { status: FAIL, detail: e.message };
  }
  log.debug("Leaving checkMdocDevice(). " + out.status);
  return out;
}

// The values a DCQL claim path selects (section 7): a string selects a key,
// an integer an array index, null every element.
function selectPath(root, path) {
  log.debug("Entering selectPath().");
  var current = [root];
  path.forEach(function (seg) {
    var next = [];
    current.forEach(function (v) {
      if (seg === null) {
        if (isArray(v)) next = next.concat(v);
      } else if (typeof seg === "number") {
        if (isArray(v) && seg < v.length) next.push(v[seg]);
      } else if (isPlainObject(v) &&
                 Object.prototype.hasOwnProperty.call(v, seg)) {
        next.push(v[seg]);
      }
    });
    current = next;
  });
  log.debug("Leaving selectPath(). " + current.length + " value(s).");
  return current;
}

function pathPresent(root, claim) {
  log.debug("Entering pathPresent().");
  var values = selectPath(root, claim.path);
  if (isArray(claim.values) && claim.values.length) {
    values = values.filter(function (v) {
      return claim.values.indexOf(v) !== -1;
    });
  }
  log.debug("Leaving pathPresent().");
  return values.length > 0;
}

// Every requested claim, or every claim of one claim_set.
function checkRequestedClaims(s, query, present) {
  log.debug("Entering checkRequestedClaims().");
  var claims = (query && query.claims) || [];
  var label = "Every requested claim is disclosed";
  if (!claims.length) {
    s.add("claims", label, PASS, "the query names no claims, so the " +
          "whole credential is what was asked for.");
    log.debug("Leaving checkRequestedClaims(). None asked.");
    return;
  }
  var missing = claims.filter(function (c) {
    return !present(c);
  });
  if (isArray(query.claim_sets) && query.claim_sets.length) {
    var byId = {};
    claims.forEach(function (c) {
      byId[c.id] = c;
    });
    var met = query.claim_sets.filter(function (set) {
      return set.every(function (id) {
        return byId[id] && present(byId[id]);
      });
    });
    s.add("claims", label, met.length ? PASS : FAIL, met.length ?
          "claim set [" + met[0].join(", ") + "] is satisfied." :
          "no claim set is satisfied; missing " + missing.map(function (c) {
            return JSON.stringify(c.path);
          }).join(", ") + ".");
    log.debug("Leaving checkRequestedClaims(). Claim sets.");
    return;
  }
  s.add("claims", label, missing.length ? FAIL : PASS, missing.length ?
        "not disclosed: " + missing.map(function (c) {
          return JSON.stringify(c.path);
        }).join(", ") + "." :
        "all " + claims.length + " requested path(s) are present.");
  log.debug("Leaving checkRequestedClaims().");
}

function requiresBinding(query) {
  log.debug("Entering requiresBinding().");
  log.debug("Leaving requiresBinding().");
  return sdJwtVp.requiresKeyBinding(query);
}

// Freshness of a holder proof: iat within the skew of now and, under this
// debugger's policy (`policy.maxAge`, MAX_AGE_SECONDS unless the caller
// set it), not older than that. `policy.required` says whether iat must
// be there at all: RFC 9901 section 4.3 makes a KB-JWT's iat REQUIRED,
// while OpenID4VP 1.0 Appendix B.1.3.1.5 asks a VP JWT for nonce and aud
// only (#469, C2), so a VP JWT without one is a SKIP that says so.
function freshness(iat, now, policy) {
  log.debug("Entering freshness().");
  var p = policy || {};
  var maxAge = typeof p.maxAge === "number" ? p.maxAge : MAX_AGE_SECONDS;
  var why = " (this debugger's freshness policy, maxAgeSeconds " + maxAge +
      "; no specification sets it)";
  if (typeof iat !== "number") {
    log.debug("Leaving freshness(). No iat.");
    return p.required ? { status: FAIL, detail: "there is no numeric iat, " +
      "and " + (p.what || "it") + " requires one." } :
      { status: SKIP, detail: "there is no iat; " + (p.what || "nothing") +
        " requires one, so freshness rests on the nonce." };
  }
  if (iat > now + SKEW_SECONDS) {
    log.debug("Leaving freshness(). Future.");
    return { status: FAIL, detail: "iat is " + (iat - now) + "s in the " +
             "future (allowed skew " + SKEW_SECONDS + "s)." };
  }
  if (maxAge > 0 && iat < now - maxAge) {
    log.debug("Leaving freshness(). Stale.");
    return { status: FAIL, detail: "iat is " + (now - iat) + "s old; a " +
             "proof older than " + maxAge + "s is not taken as made for " +
             "this request" + why + "." };
  }
  log.debug("Leaving freshness().");
  return { status: PASS, detail: "iat is " + (now - iat) + "s old" +
           (maxAge > 0 ? ", within " + maxAge + "s" + why : "; no age " +
            "limit is set (maxAgeSeconds 0)") + "." };
}

// RFC 7519 section 4.1.3: aud is one string, or an array of them, and the
// recipient must identify itself with one of the values (#469, C15).
function audMatches(aud, clientId) {
  log.debug("Entering audMatches().");
  log.debug("Leaving audMatches().");
  return isArray(aud) ? aud.indexOf(clientId) !== -1 : aud === clientId;
}

// Why an audience that is the DC API's origin: audience plus a "/" is not
// it (#471, E6). OpenID4VP 1.0 Appendix A.4 and section 5.9.3 illustrate
// the audience as "origin:https://verifier.example.com/", but that is an
// example, and the Origin it prefixes is defined without one (section 2,
// "Origin": "The web origin is https://verify.example.com"; Appendix
// B.2.6.2 hashes "https://example.com"). "" when that is not the mismatch.
function originSlashHint(got, audience) {
  log.debug("Entering originSlashHint().");
  var values = isArray(got) ? got : [got];
  var slashed = !!audience && audience.indexOf(ORIGIN_PREFIX) === 0 &&
      values.indexOf(audience + "/") !== -1;
  log.debug("Leaving originSlashHint(). " + slashed);
  return slashed ? " It is the origin with a trailing slash, which is a " +
    "URL and not an Origin: OpenID4VP 1.0 section 2 defines the Origin " +
    "as scheme, host and port (\"The web origin is " +
    "https://verify.example.com\"), the HTML Standard's serialization of " +
    "an origin (window.location.origin) has no slash, and the slash in " +
    "Appendix A.4's \"for example, origin:https://verifier.example.com/\" " +
    "is that example's alone." : "";
}

// ---------------------------------------------------------------------------
// SD-JWT VC (dc+sd-jwt).
// ---------------------------------------------------------------------------

// The payload with every disclosed claim put back where its digest was, at
// any depth, including array elements ({"...": digest}).
function walkSd(node, ctx) {
  log.debug("Entering walkSd().");
  if (isArray(node)) {
    var arr = [];
    node.forEach(function (item) {
      if (isPlainObject(item) && Object.keys(item).length === 1 &&
          typeof item["..."] === "string") {
        var dig = item["..."];
        if (ctx.seen[dig]) {
          ctx.problems.push("digest " + dig + " appears twice.");
          return;
        }
        ctx.seen[dig] = true;
        var d = ctx.byDigest[dig];
        if (!d) return;
        if (!d.arrayElement) {
          ctx.problems.push("Disclosure for " + JSON.stringify(d.name) +
                            " is referenced as an array element.");
          return;
        }
        d.used = true;
        arr.push(walkSd(d.value, ctx));
        return;
      }
      arr.push(walkSd(item, ctx));
    });
    log.debug("Leaving walkSd(). Array.");
    return arr;
  }
  if (!isPlainObject(node)) {
    log.debug("Leaving walkSd(). Scalar.");
    return node;
  }
  var out = {};
  Object.keys(node).forEach(function (k) {
    if (k === "_sd" || k === "_sd_alg") return;
    out[k] = walkSd(node[k], ctx);
  });
  (isArray(node._sd) ? node._sd : []).forEach(function (dig) {
    if (ctx.seen[dig]) {
      ctx.problems.push("digest " + dig + " appears twice.");
      return;
    }
    ctx.seen[dig] = true;
    var d = ctx.byDigest[dig];
    if (!d) return;
    if (d.arrayElement || d.name === null) {
      ctx.problems.push("an array-element Disclosure is referenced from " +
                        "an _sd array.");
      return;
    }
    if (d.name === "_sd" || d.name === "..." ||
        Object.prototype.hasOwnProperty.call(out, d.name)) {
      ctx.problems.push("Disclosure for " + JSON.stringify(d.name) +
                        " would overwrite a claim or a reserved name.");
      return;
    }
    d.used = true;
    out[d.name] = walkSd(d.value, ctx);
  });
  log.debug("Leaving walkSd(). Object.");
  return out;
}

function reconstruct(parsed) {
  log.debug("Entering reconstruct().");
  var sdAlg = (parsed.payload || {})._sd_alg;
  var ctx = { byDigest: {}, seen: {}, problems: [] };
  parsed.disclosures.forEach(function (d) {
    if (d.error) {
      ctx.problems.push("a Disclosure is malformed: " + d.error);
      return;
    }
    d.digest = b64uDigest(d.encoded, sdAlg);
    if (ctx.byDigest[d.digest]) {
      ctx.problems.push("the same Disclosure is presented twice.");
    }
    ctx.byDigest[d.digest] = d;
  });
  var claims = walkSd(parsed.payload || {}, ctx);
  parsed.disclosures.forEach(function (d) {
    if (!d.error && !d.used) {
      ctx.problems.push("the Disclosure " + (d.name !== null ?
        JSON.stringify(d.name) : "(array element)") + " has a digest (" +
        d.digest + ") that is in no _sd array: it was altered, or was not " +
        "issued with this credential.");
    }
  });
  log.debug("Leaving reconstruct(). " + ctx.problems.length +
            " problem(s).");
  return { claims: claims, problems: ctx.problems };
}

// The furthest an `extends` chain is followed, and a guard on its loops.
var MAX_EXTENDS_DEPTH = 8;

// Type Metadata for `vct`, by SD-JWT VC section 5.3.1 (an https vct is a
// URL it may be fetched from), checked as section 5.3 requires: the vct in
// the document is identical to the reference it was fetched by.
async function typeMetadata(vct, fetchJson) {
  log.debug("Entering typeMetadata().");
  var meta = await fetchJson(vct);
  if (!isPlainObject(meta) || meta.vct !== vct) {
    log.debug("Leaving typeMetadata(). Wrong vct.");
    throw new Error("the Type Metadata at " + vct + " names vct " +
                    JSON.stringify(meta && meta.vct) + ", not " + vct +
                    " (SD-JWT VC section 5.3).");
  }
  log.debug("Leaving typeMetadata().");
  return meta;
}

// Is the credential of a type the query asks for (#469, C5)? In order:
//   vct        the type itself;
//   aka_vcts   SD-JWT VC section 2.2.2.2: "a Holder or Verifier treats an
//              SD-JWT VC as being of a given type, if that type is the vct
//              value or one of the values of the aka_vcts array" — the
//              Issuer's own assertion, as trustworthy as the Issuer;
//   extends    OpenID4VP 1.0 Appendix B.3.5: the Wallet "MAY return
//              Credentials that inherit from any of the specified types".
//              Followed through Type Metadata fetched from an https vct
//              (section 5.3.1) when fetchJson can; a cycle is rejected
//              (section 7.4). Section 5.4 is explicit that extends only
//              says which Type Metadata is inherited, so the row says
//              which route matched, and a match by extends alone says the
//              Issuer should have listed the type in aka_vcts.
// The vct#integrity / extends#integrity digests are over the document's
// octets, which fetchJson does not give; the row says they were not
// checked when they are present.
async function checkVct(s, payload, vctValues, ctx) {
  log.debug("Entering checkVct().");
  var label = "vct is one the query asks for";
  var vct = payload.vct;
  if (!vctValues.length) {
    s.add("vct", label, SKIP, "the query names no vct_values (vct is " +
          JSON.stringify(vct) + ").");
    log.debug("Leaving checkVct(). No vct_values.");
    return;
  }
  if (vctValues.indexOf(vct) !== -1) {
    s.add("vct", label, PASS, "vct is " + JSON.stringify(vct) + ".");
    log.debug("Leaving checkVct(). vct.");
    return;
  }
  var aka = payload.aka_vcts;
  var akaProblems = [];
  if (aka !== undefined) {
    if (!isArray(aka) || !aka.length || aka.some(function (t) {
      return typeof t !== "string";
    })) {
      akaProblems.push("aka_vcts is not a non-empty array of strings");
    } else if (aka.indexOf(vct) !== -1) {
      akaProblems.push("aka_vcts contains the vct itself, which section " +
                       "2.2.2.2 forbids");
    }
  }
  var akaHit = isArray(aka) ? aka.filter(function (t) {
    return vctValues.indexOf(t) !== -1;
  })[0] : undefined;
  if (akaHit !== undefined) {
    s.add("vct", label, akaProblems.length ? FAIL : PASS, "vct is " +
          JSON.stringify(vct) + ", and its aka_vcts names " +
          JSON.stringify(akaHit) + ", which the query asks for (matched " +
          "through aka_vcts, SD-JWT VC section 2.2.2.2)" +
          (akaProblems.length ? "; but " + akaProblems.join("; ") : "") +
          ".");
    log.debug("Leaving checkVct(). aka_vcts.");
    return;
  }
  var chain = [];
  var why = "";
  var circular = false;
  var hit = null;
  if (typeof vct === "string" && /^https:\/\//.test(vct) && ctx.fetchJson) {
    var at = vct;
    var seen = {};
    for (var d = 0; d < MAX_EXTENDS_DEPTH && at; d++) {
      if (seen[at]) {
        circular = true;
        break;
      }
      seen[at] = true;
      var meta;
      try {
        meta = await typeMetadata(at, ctx.fetchJson);
      } catch (e) {
        why = "could not read Type Metadata at " + at + ": " + e.message;
        break;
      }
      var parent = typeof meta.extends === "string" ? meta.extends : "";
      if (!parent) break;
      chain.push(parent);
      if (vctValues.indexOf(parent) !== -1) {
        hit = parent;
        break;
      }
      at = /^https:\/\//.test(parent) ? parent : "";
    }
  }
  var shown = "vct is " + JSON.stringify(vct) + (chain.length ?
      ", which extends " + chain.join(" -> ") : "");
  if (circular) {
    s.add("vct", label, FAIL, shown + ", and the chain comes back on " +
          "itself: a circular extends MUST be rejected (SD-JWT VC section " +
          "7.4).");
  } else if (hit) {
    s.add("vct", label, PASS, shown + ": it inherits " + hit + ", which " +
          "the query asks for (matched through the Type Metadata extends " +
          "chain, OpenID4VP 1.0 Appendix B.3.5; SD-JWT VC section 5.4 " +
          "has the Issuer SHOULD list such a type in aka_vcts, and it " +
          "does not)" + (payload["vct#integrity"] ? "; vct#integrity " +
          "was not checked, because fetchJson gives no octets" : "") +
          ".");
  } else if (why) {
    s.add("vct", label, SKIP, shown + ", which is not one of " +
          vctValues.join(", ") + " and has no aka_vcts naming one; " + why +
          ", so whether it inherits a requested type is unknown.");
  } else {
    s.add("vct", label, FAIL, shown + ", not one of " +
          vctValues.join(", ") + (aka !== undefined ? ", and aka_vcts " +
          "names none of them" : "") + (akaProblems.length ? " (" +
          akaProblems.join("; ") + ")" : "") + ".");
  }
  log.debug("Leaving checkVct().");
}

async function verifySdJwt(s, query, presentation, ctx) {
  log.debug("Entering verifySdJwt().");
  var parsed;
  try {
    if (typeof presentation !== "string" ||
        presentation.indexOf("~") === -1) {
      throw new Error("it is not a string in the SD-JWT serialization " +
                      "(no ~).");
    }
    parsed = sdJwtVc.parseSdJwt(presentation);
  } catch (e) {
    s.add("format", "The presentation is an SD-JWT", FAIL, e.message);
    log.debug("Leaving verifySdJwt(). Unreadable.");
    return null;
  }
  s.add("format", "The presentation is an SD-JWT", PASS,
        parsed.disclosures.length + " Disclosure(s), " +
        (parsed.kbJwt ? "with" : "without") + " a Key Binding JWT.");
  var header = parsed.header || {};
  var payload = parsed.payload || {};
  var now = ctx.now;

  var typ = String(header.typ || "");
  s.add("issuer.typ", 'The issuer JWT\'s typ is "dc+sd-jwt"',
        typ === "dc+sd-jwt" ? PASS : FAIL,
        typ === "dc+sd-jwt" ? "typ is dc+sd-jwt." :
        typ === "vc+sd-jwt" ? 'typ is the LEGACY "vc+sd-jwt"; SD-JWT VC ' +
          'renamed it "dc+sd-jwt", and a current Verifier refuses the old ' +
          "name." : 'typ is "' + typ + '", not "dc+sd-jwt".');

  await checkIssuerSignature(s, "issuer.signature", parsed.issuerJwt,
                             header, payload, ctx,
                             "The issuer's signature verifies");

  var built = null;
  try {
    built = reconstruct(parsed);
    s.add("disclosures", "Every Disclosure's digest is in an _sd array",
          built.problems.length ? FAIL : PASS, built.problems.length ?
          built.problems.join(" ") : "all " + parsed.disclosures.length +
          " Disclosure(s) hash (" + (payload._sd_alg || "sha-256") +
          ") to a digest the issuer signed.", true);
  } catch (e) {
    s.add("disclosures", "Every Disclosure's digest is in an _sd array",
          FAIL, e.message, true);
  }

  await checkVct(s, payload, ((query.meta || {}).vct_values) || [], ctx);

  var verdict = validityVerdict(sdJwtVc.validityWindowOf(
    { payload: payload }), payload.iat, now);
  s.add("validity", "The credential is within its validity window",
        verdict.status, verdict.detail);

  await verifyKbJwt(s, query, parsed, ctx);

  await checkCredentialStatus(s, "status", statusRefsOf(payload),
    { header: header, payload: payload, id: payload.iss }, ctx);

  if (built) {
    checkRequestedClaims(s, query, function (c) {
      return pathPresent(built.claims, c);
    });
  } else {
    s.add("claims", "Every requested claim is disclosed", FAIL,
          "the Disclosures could not be read.");
  }
  var claims = built ? built.claims : {};
  log.debug("Leaving verifySdJwt().");
  return claims;
}

async function verifyKbJwt(s, query, parsed, ctx) {
  log.debug("Entering verifyKbJwt().");
  var kbKeys = ["kb.header", "kb.signature", "kb.nonce", "kb.aud",
                "kb.iat", "kb.sd_hash"];
  var labels = {
    "kb.header": 'The KB-JWT\'s typ is "kb+jwt" and it is signed',
    "kb.signature": "The KB-JWT verifies with the credential's cnf key",
    "kb.nonce": "The KB-JWT's nonce is this request's",
    "kb.aud": "The KB-JWT's aud is this Verifier's Client Identifier",
    "kb.iat": "The KB-JWT is fresh",
    "kb.sd_hash": "sd_hash covers exactly what was presented"
  };
  var required = requiresBinding(query);
  if (!parsed.kbJwt) {
    s.add("kb.present", "A Key Binding JWT is present", required ? FAIL :
          PASS, required ? "the query requires cryptographic holder " +
          "binding (DCQL's default) and the presentation ends in ~ with " +
          "no KB-JWT." : "the query does not require holder binding.");
    kbKeys.forEach(function (k) {
      s.add(k, labels[k], SKIP, "there is no KB-JWT.",
            required && k === "kb.signature");
    });
    log.debug("Leaving verifyKbJwt(). None.");
    return;
  }
  s.add("kb.present", "A Key Binding JWT is present", PASS,
        "the presentation ends in a KB-JWT.");
  var kb;
  try {
    kb = decodeJwt(parsed.kbJwt);
  } catch (e) {
    kbKeys.forEach(function (k) {
      s.add(k, labels[k], FAIL, "the KB-JWT is unreadable: " + e.message);
    });
    log.debug("Leaving verifyKbJwt(). Unreadable.");
    return;
  }
  var h = kb.header || {};
  var p = kb.payload || {};
  var alg = String(h.alg || "");
  var headerOk = h.typ === "kb+jwt" && alg && alg !== "none" &&
    !/^HS/.test(alg);
  s.add("kb.header", labels["kb.header"], headerOk ? PASS : FAIL,
        "typ " + JSON.stringify(h.typ) + ", alg " + JSON.stringify(alg) +
        (headerOk ? "." : h.typ !== "kb+jwt" ? ' — typ must be "kb+jwt".' :
         " — a KB-JWT must carry an asymmetric signature."));

  var held = await cnfKeys((parsed.payload || {}).cnf, ctx.fetchJson);
  if (held.error) {
    s.add("kb.signature", labels["kb.signature"], held.unresolved ? SKIP :
          FAIL, held.error, true);
  } else {
    var kv = verifyWithAny(parsed.kbJwt, held.keys);
    s.add("kb.signature", labels["kb.signature"], kv.valid ? PASS : FAIL,
          kv.valid ? "the KB-JWT verifies with " + held.member +
          " (thumbprint " + jwkThumbprint(kv.jwk) + ")." : "the KB-JWT " +
          "does NOT verify with " + held.member + (kv.reason ? ": " +
          kv.reason : "."), true);
  }
  s.add("kb.nonce", labels["kb.nonce"],
        p.nonce === ctx.session.nonce ? PASS : FAIL,
        p.nonce === ctx.session.nonce ? "nonce matches." : "nonce is " +
        JSON.stringify(p.nonce) + ", the request's was " +
        JSON.stringify(ctx.session.nonce) + ".");
  var audOk = !!ctx.audience && audMatches(p.aud, ctx.audience);
  s.add("kb.aud", labels["kb.aud"], audOk ? PASS : FAIL, audOk ?
        "aud is " + ctx.audience + "." : "aud is " +
        JSON.stringify(p.aud) + ", not " + (ctx.audience ||
        "known: the request's origin was not given") + "." +
        originSlashHint(p.aud, ctx.audience));
  var fresh = freshness(p.iat, ctx.now, { required: true,
    maxAge: ctx.maxAgeSeconds, what: "RFC 9901 section 4.3" });
  s.add("kb.iat", labels["kb.iat"], fresh.status, fresh.detail);
  try {
    var prefix = sdJwtVp.presentedPrefix(parsed.issuerJwt,
      parsed.disclosures.map(function (d) {
        return d.encoded;
      }));
    var expected = b64uDigest(prefix, (parsed.payload || {})._sd_alg);
    s.add("kb.sd_hash", labels["kb.sd_hash"],
          p.sd_hash === expected ? PASS : FAIL,
          p.sd_hash === expected ? "sd_hash matches the issuer JWT and " +
          "the " + parsed.disclosures.length + " Disclosure(s) sent." :
          "sd_hash is " + JSON.stringify(p.sd_hash) + "; what was sent " +
          "hashes to " + expected + ".");
  } catch (e) {
    s.add("kb.sd_hash", labels["kb.sd_hash"], FAIL, e.message);
  }
  log.debug("Leaving verifyKbJwt().");
}

// ---------------------------------------------------------------------------
// jwt_vc_json: a VP JWT around one or more VC JWTs.
// ---------------------------------------------------------------------------
async function keyForDidUrl(didUrl, fetchJson) {
  log.debug("Entering keyForDidUrl().");
  var direct = sdJwtVc.jwkFromDid(didUrl);
  if (direct) {
    log.debug("Leaving keyForDidUrl(). did:jwk.");
    return direct;
  }
  var res = await didLib.resolve(String(didUrl).split("#")[0],
    { fetch: fetchJson ? fetchAdapter(fetchJson) : undefined });
  var methods = didLib.verificationMethods(res.document);
  var frag = String(didUrl).split("#")[1];
  var base = String(didUrl).split("#")[0];
  var found = methods.filter(function (m) {
    return m.id === didUrl || (frag && m.id &&
                               m.id.split("#")[1] === frag) ||
      (frag && m.jwk && kidNames(m.jwk.kid, didUrl, base));
  })[0] || (frag && !/^did:key:/.test(base) ? null : methods[0]);
  log.debug("Leaving keyForDidUrl().");
  return found ? found.jwk : null;
}

// The keys a credential's cnf claim names (#469, C4). RFC 7800 gives three
// ways and SD-JWT VC section 2.2.2.3 only RECOMMENDS the first: cnf.jwk,
// the key itself; cnf.kid, a key ID — resolved here when it is a DID URL,
// and otherwise known only to issuer and holder (RFC 7800 section 3.4);
// and cnf.jku, a JWK Set URL fetched through fetchJson, narrowed by
// cnf.kid when there is one. Answers { keys, member } or { error,
// unresolved } — unresolved when a fetch or a resolution failed, which is
// a check not performed rather than a wrong key.
async function cnfKeys(cnf, fetchJson) {
  log.debug("Entering cnfKeys().");
  if (!isPlainObject(cnf)) {
    log.debug("Leaving cnfKeys(). No cnf.");
    return { error: "the credential has no cnf, so there is no key the " +
             "holder can prove." };
  }
  if (isPlainObject(cnf.jwk)) {
    log.debug("Leaving cnfKeys(). jwk.");
    return { keys: [keyMembers(cnf.jwk)], member: "cnf.jwk" };
  }
  var kid = typeof cnf.kid === "string" ? cnf.kid : "";
  if (typeof cnf.jku === "string") {
    if (!fetchJson) {
      log.debug("Leaving cnfKeys(). No fetch for jku.");
      return { unresolved: true, error: "cnf.jku is " + cnf.jku + " and " +
               "no fetchJson was given to read it." };
    }
    var set;
    try {
      set = await fetchJson(cnf.jku);
    } catch (e) {
      log.debug("Leaving cnfKeys(). jku fetch failed.");
      return { unresolved: true, error: "could not fetch cnf.jku " +
               cnf.jku + ": " + e.message };
    }
    var keys = (set && isArray(set.keys) ? set.keys : []).filter(
      function (k) {
        return !kid || k.kid === kid;
      });
    log.debug("Leaving cnfKeys(). jku: " + keys.length + ".");
    return keys.length ? { keys: keys.map(keyMembers), member: "cnf.jku (" +
      cnf.jku + (kid ? ", kid " + kid : "") + ")" } :
      { error: "the JWK Set at cnf.jku " + cnf.jku + " has no key" +
        (kid ? " with kid " + JSON.stringify(kid) : "") + "." };
  }
  if (kid && didLib.isDid(kid)) {
    var jwk;
    try {
      jwk = await keyForDidUrl(kid, fetchJson);
    } catch (e) {
      log.debug("Leaving cnfKeys(). DID unresolved.");
      return { unresolved: true, error: "cnf.kid " + kid + " could not be " +
               "resolved: " + e.message };
    }
    log.debug("Leaving cnfKeys(). DID kid.");
    return jwk ? { keys: [keyMembers(jwk)], member: "cnf.kid (" + kid +
      ")", did: kid.split("#")[0] } : { error: "cnf.kid " + kid +
      " names no verification method in its DID document." };
  }
  if (kid) {
    log.debug("Leaving cnfKeys(). Opaque kid.");
    return { unresolved: true, error: "cnf.kid " + JSON.stringify(kid) +
             " is a key ID that only the issuer and holder can resolve " +
             "(RFC 7800 section 3.4), with no cnf.jku beside it." };
  }
  log.debug("Leaving cnfKeys(). Nothing usable.");
  return { error: "cnf carries none of jwk, kid or jku (RFC 7800)." };
}

// A JWS verified with each of `keys` in turn. Answers { valid, jwk,
// reason }; `jwk` is the one that verified.
function verifyWithAny(compact, keys) {
  log.debug("Entering verifyWithAny(). " + keys.length + " key(s).");
  var reason = "";
  for (var i = 0; i < keys.length; i++) {
    var v = verifyCompact(compact, { jwk: keyMembers(keys[i]) });
    if (v.valid) {
      log.debug("Leaving verifyWithAny(). Key " + i + ".");
      return { valid: true, jwk: keys[i], reason: "" };
    }
    reason = v.reason;
  }
  log.debug("Leaving verifyWithAny(). None.");
  return { valid: false, jwk: null, reason: keys.length > 1 ? "none of " +
           keys.length + " keys verifies it" : reason };
}

// The VP JWT's own key: a jwk in its header, else the DID URL its kid (or
// its iss) names, resolved by did.js — did:jwk, did:key and did:web
// through fetchJson. `did` is the signer's DID, which is what holder
// binding compares with the credential's subject (#469, C3).
async function holderKey(header, payload, fetchJson) {
  log.debug("Entering holderKey().");
  if (header.jwk) {
    log.debug("Leaving holderKey(). Header jwk.");
    return { keys: [header.jwk], from: "the jwk in its header", did: "" };
  }
  var didUrl = didLib.isDid(String(header.kid || "")) ? header.kid :
      didLib.isDid(String(payload.iss || "")) ? payload.iss : "";
  if (didUrl) {
    var jwk = await keyForDidUrl(didUrl, fetchJson);
    if (jwk) {
      log.debug("Leaving holderKey(). DID.");
      return { keys: [jwk], from: didUrl,
               did: String(didUrl).split("#")[0] };
    }
  }
  log.debug("Leaving holderKey(). None.");
  return null;
}

// The keys of a DID, every verification method, for comparing a VP's key
// with a credential subject named by DID.
async function didVerificationKeys(did, fetchJson) {
  log.debug("Entering didVerificationKeys().");
  var direct = sdJwtVc.jwkFromDid(did);
  if (direct) {
    log.debug("Leaving didVerificationKeys(). did:jwk.");
    return [direct];
  }
  var res = await didLib.resolve(did,
    { fetch: fetchJson ? fetchAdapter(fetchJson) : undefined });
  var keys = didLib.verificationMethods(res.document).map(function (m) {
    return m.jwk;
  }).filter(Boolean);
  log.debug("Leaving didVerificationKeys(). " + keys.length + ".");
  return keys;
}

// W3C type_values (#469, C6): OpenID4VP 1.0 Appendix B.1.1 compares
// FULLY EXPANDED types (IRIs), "after applying the @context to the
// Verifiable Credential", and a type no context defines stays the relative
// IRI it was. So the credential's types are expanded with jsonld, offline,
// through bbs2023.js's loader (the contexts this deployment ships or was
// given; never fetched). A context that cannot be loaded leaves the types
// as written, and the row says so.
async function expandedTypes(credential) {
  log.debug("Entering expandedTypes().");
  var written = [].concat((credential && credential.type) || []);
  var ctx = credential && credential["@context"];
  if (!ctx) {
    log.debug("Leaving expandedTypes(). No @context.");
    return { iris: written, written: written, note: "there is no " +
             "@context, so the types are as written" };
  }
  try {
    var out = await jsonld.expand({ "@context": ctx, type: written },
      { documentLoader: bbs2023.documentLoader });
    var iris = [].concat(((out || [])[0] || {})["@type"] || []);
    log.debug("Leaving expandedTypes(). " + iris.length + ".");
    return { iris: iris, written: written, note: "" };
  } catch (e) {
    log.debug("Leaving expandedTypes(). Failed: " + e.message);
    return { iris: null, written: written, note: "its @context could not " +
             "be applied offline (" + e.message + ")" };
  }
}

function typesMatch(types, typeValues) {
  log.debug("Entering typesMatch().");
  log.debug("Leaving typesMatch().");
  return typeValues.some(function (alt) {
    return [].concat(alt).every(function (t) {
      return types.indexOf(t) !== -1;
    });
  });
}

// The `types` row, for both W3C formats. A match on the expanded IRIs is
// B.1.1's; a match only on the types AS WRITTEN means the query's values
// are not fully expanded IRIs (the form B.1.1 requires) and is reported
// as such — this Verifier's own query builder writes the compact names.
async function checkTypeValues(s, key, query, credential) {
  log.debug("Entering checkTypeValues().");
  var label = "The credential's type is one the query asks for";
  var typeValues = ((query.meta || {}).type_values) || [];
  var t = await expandedTypes(credential);
  var shown = "type is [" + t.written.join(", ") + "]" +
      (t.iris && t.iris.join() !== t.written.join() ? ", expanded [" +
       t.iris.join(", ") + "]" : "") + (t.note ? " (" + t.note + ")" : "");
  if (!typeValues.length) {
    s.add(key, label, SKIP, shown + "; the query names no type_values.");
    log.debug("Leaving checkTypeValues(). No type_values.");
    return;
  }
  var asked = "; asked for " + JSON.stringify(typeValues);
  if (t.iris && typesMatch(t.iris, typeValues)) {
    s.add(key, label, PASS, shown + asked + ", matched after JSON-LD " +
          "expansion (OpenID4VP 1.0 Appendix B.1.1).");
  } else if (typesMatch(t.written, typeValues)) {
    s.add(key, label, PASS, shown + asked + ": matched only as WRITTEN. " +
          "Appendix B.1.1's type_values are fully expanded IRIs, and " +
          "the query's are compact names, which a Wallet comparing IRIs " +
          "would not match.");
  } else {
    s.add(key, label, FAIL, shown + asked + "; no alternative is " +
          "present, expanded or as written.");
  }
  log.debug("Leaving checkTypeValues().");
}

// Is the VP's signer the holder the credential is bound to (#469, C3/C4)?
// By KEY: the key that verified the VP is one the credential's cnf names
// (jwk, a DID-URL kid, a jku). By DID: the VP is signed with a key of the
// DID its kid (or iss) names, and that DID is the credential's sub or
// credentialSubject.id — or the VP's key is one of that subject DID's,
// resolved through did.js. Answers { status, detail }.
async function vpBinding(vcPayload, hk, signerJwk, required, ctx) {
  log.debug("Entering vpBinding().");
  var subject = ((vcPayload.vc || {}).credentialSubject || {}).id ||
      vcPayload.sub || "";
  var subjectDid = didLib.isDid(String(subject)) ?
      String(subject).split("#")[0] : "";
  var member = (vcPayload.vc || {}).credentialSubject &&
      (vcPayload.vc.credentialSubject || {}).id ? "credentialSubject.id" :
      "sub";
  var held = vcPayload.cnf ? await cnfKeys(vcPayload.cnf, ctx.fetchJson) :
      null;
  if (!required && !held && !subjectDid) {
    log.debug("Leaving vpBinding(). Not asked.");
    return { status: SKIP, detail: "the query does not require holder " +
             "binding and the credential names no holder." };
  }
  var key = signerJwk || (hk && hk.keys[0]) || null;
  if (key && held && held.keys && held.keys.some(function (k) {
    return sameKey(k, key);
  })) {
    log.debug("Leaving vpBinding(). cnf.");
    return { status: PASS, detail: "the VP key is the credential's " +
             held.member + "." };
  }
  if (hk && hk.did && subjectDid && hk.did === subjectDid) {
    log.debug("Leaving vpBinding(). Same DID.");
    return { status: PASS, detail: "the VP is signed with a key of " +
             hk.did + ", which is the credential's " + member + "." };
  }
  var subjectError = "";
  if (key && subjectDid) {
    try {
      var subjectKeys = await didVerificationKeys(subjectDid,
                                                  ctx.fetchJson);
      if (subjectKeys.some(function (k) {
        return sameKey(k, key);
      })) {
        log.debug("Leaving vpBinding(). Subject DID key.");
        return { status: PASS, detail: "the VP key is a verification " +
                 "method of " + subjectDid + ", the credential's " +
                 member + "." };
      }
    } catch (e) {
      subjectError = subjectDid + " could not be resolved: " + e.message;
    }
  }
  if ((held && held.unresolved) || subjectError) {
    log.debug("Leaving vpBinding(). Unresolved.");
    return { status: SKIP, detail: "could not tell: " + [held &&
      held.unresolved ? held.error : "", subjectError].filter(Boolean)
      .join("; ") };
  }
  log.debug("Leaving vpBinding(). Not bound.");
  return { status: FAIL, detail: !key ? "there is no VP key to compare." :
    held && held.keys ? "the VP key is not the credential's " +
      held.member + (subjectDid ? ", nor a key of its " + member + " " +
      subjectDid : "") + "." : subjectDid ? "the VP is not signed by " +
      subjectDid + ", the credential's " + member + (hk && hk.did ?
      " (it is signed by " + hk.did + ")" : "") + "." :
    held && held.error ? held.error : "the credential names no holder key." };
}

// OpenID4VP 1.0 Appendix B.1: with require_cryptographic_holder_binding
// true the Wallet MUST return a Verifiable Presentation; otherwise "a
// Verifiable Credential without Holder Binding MUST be returned" — so a
// bare VC JWT in vp_token is the CORRECT answer to such a query (#469, C1).
async function verifyJwtVcJson(s, query, presentation, ctx) {
  log.debug("Entering verifyJwtVcJson().");
  var formatLabel = "The presentation is a jwt_vc_json VP or VC JWT";
  var top;
  try {
    if (typeof presentation !== "string" ||
        presentation.indexOf("~") !== -1) {
      throw new Error("it is not a compact JWS.");
    }
    top = decodeJwt(presentation);
    if (!top.payload.vp && !top.payload.vc) {
      throw new Error("the JWT carries neither a vp nor a vc claim.");
    }
  } catch (e) {
    s.add("format", formatLabel, FAIL, e.message);
    log.debug("Leaving verifyJwtVcJson(). Unreadable.");
    return null;
  }
  var required = requiresBinding(query);
  var bare = !top.payload.vp;
  var vcs;
  if (bare) {
    vcs = [presentation];
    s.add("format", formatLabel, PASS, "a bare VC JWT with no VP around " +
          "it, which is what Appendix B.1 has a Wallet return when " +
          "holder binding is not required.");
    s.add("vp.signature", "The VP JWT verifies with the holder's key",
          required ? FAIL : SKIP, required ? "the query requires " +
          "cryptographic holder binding, and Appendix B.1 then requires " +
          "a Verifiable Presentation: a credential alone does not prove " +
          "who presented it." : "there is no VP, and the query does not " +
          "require holder binding.", required);
  } else {
    vcs = [].concat(top.payload.vp.verifiableCredential || []);
    s.add("format", formatLabel, vcs.length ? PASS : FAIL,
          "a VP JWT around " + vcs.length + " credential(s).");
    await checkVpJwt(s, query, presentation, top, vcs, ctx);
  }

  var claimsRoot = {};
  for (var i = 0; i < vcs.length; i++) {
    var tag = vcs.length > 1 ? "vc[" + i + "]." : "vc.";
    var vc;
    try {
      vc = decodeJwt(vcs[i]);
    } catch (e) {
      s.add(tag + "signature", "The credential's issuer signature verifies",
            FAIL, "the embedded credential is unreadable: " + e.message,
            true);
      continue;
    }
    await checkIssuerSignature(s, tag + "signature", vcs[i], vc.header,
                               vc.payload, ctx,
                               "The credential's issuer signature verifies",
                               { format: FORMAT_JWT_VC_JSON });
    var verdict = validityVerdict(sdJwtVc.validityWindowOf(
      { payload: vc.payload }), vc.payload.iat, ctx.now);
    s.add(tag + "validity", "The credential is within its validity window",
          verdict.status, verdict.detail);
    var vcBody = vc.payload.vc || vc.payload;
    var tokenRefs = statusRefsOf(vc.payload);
    var w3cRefs = statusRefsOf(vcBody);
    await checkCredentialStatus(s, tag + "status", { token: tokenRefs.token,
      w3c: w3cRefs.w3c.length ? w3cRefs.w3c : tokenRefs.w3c,
      other: tokenRefs.other },
      { header: vc.header, payload: vc.payload, format: FORMAT_JWT_VC_JSON,
        id: vc.payload.iss || issuerIdOf(vcBody) }, ctx);
    if (i === 0) {
      claimsRoot = Object.assign({}, vc.payload.vc || {});
      await checkTypeValues(s, "types", query, vc.payload.vc || {});
    }
  }
  checkRequestedClaims(s, query, function (c) {
    return pathPresent(claimsRoot, c);
  });
  log.debug("Leaving verifyJwtVcJson().");
  return claimsRoot.credentialSubject || claimsRoot;
}

// The VP JWT around jwt_vc_json credentials: its signature, the holder
// binding, nonce and aud (Appendix B.1.3.1.5's two requirements), its iat
// under this debugger's freshness policy, and exp / nbf (#469, C16).
async function checkVpJwt(s, query, presentation, vp, vcs, ctx) {
  log.debug("Entering checkVpJwt().");
  var required = requiresBinding(query);
  var first = null;
  try {
    first = vcs.length ? decodeJwt(vcs[0]) : null;
  } catch (e) {
    first = null;
  }
  var hk = null;
  var holderError = "";
  try {
    hk = await holderKey(vp.header, vp.payload, ctx.fetchJson);
  } catch (e) {
    holderError = e.message;
  }
  // A VP that names no key of its own is checked with the key its
  // credential is bound to.
  if (!hk && !holderError && first && first.payload.cnf) {
    var bound = await cnfKeys(first.payload.cnf, ctx.fetchJson);
    if (bound.keys) {
      hk = { keys: bound.keys, did: bound.did || "", from: "the " +
             "credential's " + bound.member + " (the VP names no key of " +
             "its own)" };
    }
  }
  var signer = null;
  var sigLabel = "The VP JWT verifies with the holder's key";
  if (holderError) {
    s.add("vp.signature", sigLabel, SKIP, "the holder key could not be " +
          "resolved: " + holderError, true);
  } else if (hk) {
    var v = verifyWithAny(presentation, hk.keys);
    signer = v.valid ? v.jwk : null;
    s.add("vp.signature", sigLabel, v.valid ? PASS : FAIL, (v.valid ?
          "verifies" : "does NOT verify") + " with the key from " + hk.from +
          (v.reason && !v.valid ? ": " + v.reason : "."), true);
  } else {
    s.add("vp.signature", sigLabel, FAIL, "it names no key (no jwk, no " +
          "DID kid or iss) and the credential is bound to none.", true);
  }
  var bind = first ? await vpBinding(first.payload, hk, signer, required,
                                     ctx) :
    { status: FAIL, detail: "there is no credential to be bound to." };
  s.add("vp.binding", "The VP is signed by the key the credential is " +
        "bound to", bind.status, bind.detail, required);
  var p = vp.payload;
  s.add("vp.nonce", "The VP JWT's nonce is this request's",
        p.nonce === ctx.session.nonce ? PASS : FAIL, "nonce is " +
        JSON.stringify(p.nonce) + (p.nonce === ctx.session.nonce ? "." :
        ", the request's was " + JSON.stringify(ctx.session.nonce) + "."));
  var audOk = !!ctx.audience && audMatches(p.aud, ctx.audience);
  s.add("vp.aud", "The VP JWT's aud is this Verifier's Client Identifier",
        audOk ? PASS : FAIL, "aud is " + JSON.stringify(p.aud) +
        (audOk ? "." : ", not " + (ctx.audience || "known: the request's " +
        "origin was not given") + "." + originSlashHint(p.aud,
                                                         ctx.audience)));
  var fresh = freshness(p.iat, ctx.now, { required: false,
    maxAge: ctx.maxAgeSeconds,
    what: "OpenID4VP 1.0 Appendix B.1.3.1.5 (nonce and aud only)" });
  s.add("vp.iat", "The VP JWT is fresh", fresh.status, fresh.detail);
  var win = validityVerdict({ expires: typeof p.exp === "number" ? p.exp :
    null, notBefore: typeof p.nbf === "number" ? p.nbf : null,
    expiresMember: "exp", notBeforeMember: "nbf" }, null, ctx.now);
  s.add("vp.validity", "The VP JWT is within its exp and nbf",
        win.status, win.detail);
  log.debug("Leaving checkVpJwt().");
}

// ---------------------------------------------------------------------------
// mso_mdoc: a DeviceResponse.
// ---------------------------------------------------------------------------
function slug(text) {
  log.debug("Entering slug().");
  log.debug("Leaving slug().");
  return String(text).toLowerCase().replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

async function verifyMdoc(s, query, presentation, ctx) {
  log.debug("Entering verifyMdoc().");
  var read;
  try {
    if (typeof presentation !== "string") {
      throw new Error("it is not a base64url string.");
    }
    read = mdoc.readDeviceResponse(presentation);
  } catch (e) {
    s.add("format", "The presentation is an mdoc DeviceResponse", FAIL,
          e.message);
    log.debug("Leaving verifyMdoc(). Unreadable.");
    return null;
  }
  var status = read.top.get("status");
  s.add("format", "The presentation is an mdoc DeviceResponse",
        status === 0 ? PASS : FAIL, "docType " + read.parsed.docType +
        ", status " + status + ", " + read.parsed.items.length +
        " element(s).");
  try {
    var issuerChecks = await mdoc.checkIssuerSigned(read.parsed);
    issuerChecks.forEach(function (c) {
      s.add("mdoc." + slug(c.name), c.name, c.ok ? PASS : FAIL, c.detail,
            true);
    });
  } catch (e) {
    s.add("mdoc.issuer-signed", "issuerSigned verifies", FAIL, e.message,
          true);
  }
  var chain = read.parsed.x5chain || [];
  if (chain.length) {
    var trust = x5cTrust(chain, { now: ctx.now,
                                  anchors: ctx.session.trustAnchors });
    s.add("mdoc.issuer-trust", "The document signer certificate is " +
          "trusted", trust.status, trust.detail, true);
    chainFindingRows(s, "mdoc.issuer-", trust, "The document signer's");
    trustedAuthoritiesRow(s, "mdoc.trusted-authorities", trust.certs, ctx);
  }
  var docTypeCheck = mdoc.checkDocType(read);
  s.add("mdoc.mso-doctype", docTypeCheck.name, docTypeCheck.ok ? PASS :
        FAIL, docTypeCheck.detail, true);
  var handover = mdocSessionTranscript(ctx.session);
  var dcMissingOrigin = isDcApiMode(ctx.session.responseMode) &&
      !ctx.session.origin;
  var device = dcMissingOrigin ? { status: FAIL } :
      checkMdocDevice(read, handover.transcript);
  s.add("mdoc.device-signature", "The device signature covers this " +
        "request", device.status, device.status === PASS ?
        "deviceSignature (" + device.name + ") verifies with the MSO's " +
        "device key over the " + handover.describe + "." :
        dcMissingOrigin ? "the request's origin was not given, so the " +
        "OpenID4VPDCAPIHandover transcript cannot be rebuilt." :
        device.status === SKIP ? device.detail :
        "deviceSignature does NOT verify over this request's " +
        handover.describe + ": another Verifier, origin, nonce, " +
        "response_uri or encryption key, or no device signature at all" +
        (device.detail ? " (" + device.detail.replace(/\.$/, "") + ")" :
         "") + ".", true);
  var want = (query.meta || {}).doctype_value;
  s.add("mdoc.doctype", "docType is the one the query asks for",
        want ? (want === read.parsed.docType ? PASS : FAIL) : SKIP,
        "docType is " + read.parsed.docType + (want ? (want ===
        read.parsed.docType ? "." : ", not " + want + ".") : "; the " +
        "query names no doctype_value."));
  var vf = read.parsed.validity || {};
  var win = { notBefore: vf.validFrom ? Math.floor(Date.parse(
                vf.validFrom) / 1000) : null,
              expires: vf.validUntil ? Math.floor(Date.parse(
                vf.validUntil) / 1000) : null,
              notBeforeMember: "validFrom", expiresMember: "validUntil" };
  var verdict = validityVerdict(win, null, ctx.now);
  s.add("validity", "The credential is within its validity window",
        verdict.status, verdict.detail);
  var root = {};
  read.parsed.items.forEach(function (it) {
    root[it.namespace] = root[it.namespace] || {};
    root[it.namespace][it.elementIdentifier] = it.value;
  });
  var x5chain = read.parsed.x5chain || [];
  var msoStatus = mapGet(read.parsed.mso, "status");
  await checkCredentialStatus(s, "status", statusRefsOf(msoStatus ?
    { status: cborToPlain(msoStatus) } : {}), { header: x5chain.length ?
    { x5c: [bytes.bytesToB64(bytes.asBytes(x5chain[0]))] } : {},
    payload: {}, id: "" }, ctx);
  checkRequestedClaims(s, query, function (c) {
    return pathPresent(root, c);
  });
  log.debug("Leaving verifyMdoc().");
  return root;
}

// ---------------------------------------------------------------------------
// ldp_vc: a VerifiablePresentation (or a bare credential) secured with Data
// Integrity. The holder proof is any suite verifyDataIntegrity() verifies;
// each credential carries its own Data Integrity proof, and a bbs-2023 one is
// a REVEAL DOCUMENT with a derived proof (W3C Data Integrity BBS
// Cryptosuites v1.0), verified by bbs2023.js from the document itself.
// ---------------------------------------------------------------------------
function asObject(value) {
  log.debug("Entering asObject().");
  if (typeof value === "string") {
    log.debug("Leaving asObject(). Parsed.");
    return JSON.parse(value);
  }
  log.debug("Leaving asObject().");
  return value;
}

// A credential secured with bbs-2023: its one Data Integrity proof names
// that cryptosuite.
function isBbsCredential(cred) {
  log.debug("Entering isBbsCredential().");
  var is = [].concat((cred && cred.proof) || []).some(function (p) {
    return p && p.cryptosuite === bbs2023.CRYPTOSUITE;
  });
  log.debug("Leaving isBbsCredential(). " + is);
  return is;
}

// The issuer's BBS public key, from the derived proof's verificationMethod:
// a did:key read in place (its id IS the Multikey), anything else resolved
// through did.js or fetched as a verification method document. A key that
// cannot be had is `unresolved` (#470 B2's rule); a key that is had and is
// not a BLS12-381 G2 Multikey is a plain error.
async function bbsIssuerKey(vm, ctx) {
  log.debug("Entering bbsIssuerKey().");
  var url = String(vm || "");
  if (!url) {
    log.debug("Leaving bbsIssuerKey(). None.");
    throw new Error("the proof names no verificationMethod.");
  }
  var did = url.split("#")[0];
  if (/^did:key:z/.test(did)) {
    log.debug("Leaving bbsIssuerKey(). did:key.");
    return bbs2023.multikeyToPublicKey(did.slice("did:key:".length));
  }
  if (!ctx.fetchJson && !didLib.isDid(url)) {
    log.debug("Leaving bbsIssuerKey(). No fetchJson.");
    throw unresolved("no fetchJson was given to read " + url + ".");
  }
  var resolved;
  try {
    resolved = await didLib.resolveVerificationMethod(url, {
      allowHttp: false,
      fetch: ctx.fetchJson ? fetchAdapter(ctx.fetchJson) : undefined });
  } catch (e) {
    log.debug("Leaving bbsIssuerKey(). Unresolved.");
    throw unresolved("could not resolve the verification method " + url +
                     ": " + e.message);
  }
  var multibase = (resolved.method || {}).publicKeyMultibase;
  if (!multibase) {
    log.debug("Leaving bbsIssuerKey(). No Multikey.");
    throw new Error("the verification method " + url + " publishes no " +
      "publicKeyMultibase, so it has no BBS key (a BLS12-381 G2 key has " +
      "no JOSE representation).");
  }
  log.debug("Leaving bbsIssuerKey().");
  return bbs2023.multikeyToPublicKey(multibase);
}

// The bbs-2023 derived proof of one reveal document, in the shape
// verifyDataIntegrity() answers, plus the presentation header it carries.
async function verifyBbsCredential(cred, ctx) {
  log.debug("Entering verifyBbsCredential().");
  var proof = [].concat(cred.proof || []).filter(function (p) {
    return p && p.cryptosuite === bbs2023.CRYPTOSUITE;
  })[0] || {};
  var vm = String(proof.verificationMethod || "");
  var out = { valid: false, suite: bbs2023.CRYPTOSUITE,
              verificationMethod: vm };
  var publicKey;
  try {
    publicKey = await bbsIssuerKey(vm, ctx);
  } catch (e) {
    log.debug("Leaving verifyBbsCredential(). No key.");
    return Object.assign(out, { unresolved: !!e.unresolved,
      reason: e.unresolved ? "could not resolve the issuer's BBS key: " +
        e.message : e.message });
  }
  var r = await bbs2023.verifyDerivedProof(cred, publicKey);
  out.presentationHeader = r.presentationHeader || null;
  if (!r.verified) {
    log.debug("Leaving verifyBbsCredential(). Not verified.");
    return Object.assign(out, { reason: r.reason });
  }
  if (proof.proofPurpose !== "assertionMethod") {
    log.debug("Leaving verifyBbsCredential(). Wrong purpose.");
    return Object.assign(out, { reason: "the derived proof verifies, but " +
      "proofPurpose is " + JSON.stringify(proof.proofPurpose) + ", not " +
      "assertionMethod." });
  }
  log.debug("Leaving verifyBbsCredential(). Valid.");
  return Object.assign(out, { valid: true, reason: "bbs-2023 by " + vm +
    ": " + r.reason });
}

// OpenID4VP 1.0 binds a presentation to its request by the nonce. A bbs-2023
// derived proof carries a BBS presentation header; for a bare reveal
// document that header IS the binding and must be the nonce, and inside a VP
// the VP proof's challenge and domain bind it (Appendix B.1.3.2.5), so the
// header may be the nonce or empty.
function checkPresentationHeader(s, key, r, nonce, inVp) {
  log.debug("Entering checkPresentationHeader(). inVp=" + inVp);
  var label = "The derived proof's presentation header binds it to this " +
      "request";
  if (!r.presentationHeader) {
    s.add(key, label, SKIP, "the derived proof could not be read, so it " +
          "has no presentation header to compare.");
    log.debug("Leaving checkPresentationHeader(). Unread.");
    return;
  }
  var ph = r.presentationHeader;
  var text = bytes.bytesToStr(ph);
  var isNonce = text === String(nonce || "") && ph.length > 0;
  if (isNonce) {
    s.add(key, label, PASS, "the presentation header is this request's " +
          "nonce" + (inVp ? "." : ", which is what binds a bare reveal " +
          "document to it."), !inVp);
  } else if (inVp && !ph.length) {
    s.add(key, label, PASS, "the presentation header is empty; the VP " +
          "proof's challenge and domain bind the presentation " +
          "(OpenID4VP 1.0 Appendix B.1.3.2.5).");
  } else {
    s.add(key, label, FAIL, "the presentation header is " +
          JSON.stringify(text) + ", not this request's nonce" +
          (inVp ? " (nor empty)" : ", and a bare reveal document has " +
          "nothing else to bind it") + ".", !inVp);
  }
  log.debug("Leaving checkPresentationHeader().");
}

// Is a Data Integrity proof's verificationMethod one its issuer controls
// (#467, S2)? VC Data Integrity has the verifier check that the
// verification method is authorised by the controller the document names,
// and until #467 that was checked only for a DID issuer: an issuer
// "https://university.example" with a proof by did:key:<anyone> passed. So:
//   a DID issuer          the method is under that DID;
//   an https issuer       the method is an https URL at or under it, or a
//                         did:web whose document lives at or under it;
//   anything else         nothing can be shown to be the issuer's.
// Answers "" when authorised, else why not.
function vmNotAuthorised(vm, issuerId) {
  log.debug("Entering vmNotAuthorised().");
  var method = String(vm || "");
  var issuer = String(issuerId || "");
  if (didLib.isDid(issuer)) {
    var vmDid = method.split("#")[0];
    log.debug("Leaving vmNotAuthorised(). DID issuer.");
    return vmDid === issuer ? "" : "the proof is by a key of " + vmDid +
      ", which is not the issuer " + issuer + ".";
  }
  var base = null;
  try {
    base = /^https:\/\//.test(issuer) ? new URL(issuer) : null;
  } catch (e) {
    base = null;
  }
  if (!base) {
    log.debug("Leaving vmNotAuthorised(). No usable issuer.");
    return "the issuer " + JSON.stringify(issuer) + " is neither a DID " +
      "nor an https URL, so no verification method can be shown to be " +
      "its own.";
  }
  var where = "";
  if (/^did:web:/.test(method)) {
    where = didLib.didWebToUrl(method.split("#")[0]);
  } else if (/^https:\/\//.test(method)) {
    where = method.split("#")[0];
  }
  var at = null;
  try {
    at = where ? new URL(where) : null;
  } catch (e) {
    at = null;
  }
  var prefix = base.pathname.replace(/\/$/, "") + "/";
  var under = !!at && at.origin === base.origin &&
      (at.pathname + "/").indexOf(prefix) === 0;
  log.debug("Leaving vmNotAuthorised(). " + under);
  return under ? "" : "verification method not authorised by the issuer: " +
    method + " is not controlled by " + issuer + " (it neither resolves " +
    "at or under that URL, nor is a did:web whose document does).";
}

// One credential with its own Data Integrity proof — any suite
// verifyDataIntegrity() verifies, or a bbs-2023 derived proof: the proof (by
// a key its issuer controls), validity, and status. Answers the proof's
// result, which for bbs-2023 carries the presentation header.
async function verifyDiCredential(s, tag, cred, ctx) {
  log.debug("Entering verifyDiCredential(). " + tag);
  var label = "The credential's issuer proof verifies";
  var issuerId = issuerIdOf(cred);
  var r = isBbsCredential(cred) ? await verifyBbsCredential(cred, ctx) :
    await verifyDataIntegrity(cred, { fetchJson: ctx.fetchJson,
      purpose: "assertionMethod", now: ctx.now });
  if (r.unsupported || r.unresolved) {
    s.add(tag + "proof", label, SKIP, r.reason, true);
  } else if (!r.valid) {
    s.add(tag + "proof", label, FAIL, r.reason, true);
  } else {
    var foreign = vmNotAuthorised(r.verificationMethod, issuerId);
    s.add(tag + "proof", label, foreign ? FAIL : PASS, foreign ?
          "the proof verifies, but " + foreign : r.reason, true);
  }
  var verdict = validityVerdict(ldpWindow(cred), null, ctx.now);
  s.add(tag + "validity", "The credential is within its validity window",
        verdict.status, verdict.detail);
  await checkCredentialStatus(s, tag + "status", statusRefsOf(cred),
    { header: {}, payload: { iss: issuerId }, id: issuerId }, ctx);
  log.debug("Leaving verifyDiCredential().");
  return r;
}

function holderIdOf(doc) {
  log.debug("Entering holderIdOf().");
  var h = doc && doc.holder;
  log.debug("Leaving holderIdOf().");
  return typeof h === "string" ? h : (h && h.id) || "";
}

async function verifyLdpVc(s, query, presentation, ctx) {
  log.debug("Entering verifyLdpVc().");
  var doc;
  try {
    doc = asObject(presentation);
    if (!isPlainObject(doc)) throw new Error("it is not a JSON object.");
  } catch (e) {
    s.add("format", "The presentation is an ldp_vc", FAIL, e.message);
    log.debug("Leaving verifyLdpVc(). Unreadable.");
    return null;
  }
  var isVp = [].concat(doc.type || []).indexOf(
    "VerifiablePresentation") !== -1;
  var creds;
  try {
    creds = isVp ? [].concat(doc.verifiableCredential || []).map(asObject) :
        [doc];
  } catch (e) {
    s.add("format", "The presentation is an ldp_vc", FAIL, "an embedded " +
          "credential is unreadable: " + e.message);
    log.debug("Leaving verifyLdpVc(). Unreadable credential.");
    return null;
  }
  s.add("format", "The presentation is an ldp_vc", creds.length ? PASS :
        FAIL, isVp ? "a VerifiablePresentation around " + creds.length +
        " credential(s)." : "a bare credential, with no holder proof " +
        "around it.");

  var holderJwk = null;
  var holderVm = "";
  if (isVp) {
    var proof = [].concat(doc.proof || [])[0] || {};
    var r = await verifyDataIntegrity(doc, { fetchJson: ctx.fetchJson,
      purpose: "authentication", now: ctx.now });
    if (r.unsupported) {
      s.add("vp.proof", "The VP's holder proof verifies", SKIP, r.reason,
            requiresBinding(query));
    } else {
      holderJwk = r.valid ? r.jwk : null;
      holderVm = r.verificationMethod || "";
      s.add("vp.proof", "The VP's holder proof verifies",
            r.valid ? PASS : FAIL, r.reason, true);
    }
    s.add("vp.challenge", "The VP proof's challenge is this request's " +
          "nonce", proof.challenge === ctx.session.nonce ? PASS : FAIL,
          "challenge is " + JSON.stringify(proof.challenge) + ".");
    var domainOk = !!ctx.audience && audMatches(proof.domain, ctx.audience);
    s.add("vp.domain", "The VP proof's domain is this Verifier's Client " +
          "Identifier", domainOk ? PASS : FAIL, "domain is " +
          JSON.stringify(proof.domain) + (domainOk ? "." : ", not " +
          (ctx.audience || "known: the request's origin was not given") +
          "." + originSlashHint(proof.domain, ctx.audience)));
  } else if (creds.length === 1 && isBbsCredential(creds[0])) {
    s.add("vp.proof", "The VP's holder proof verifies", SKIP, "a bare " +
          "bbs-2023 reveal document, with no VP around it: it is bound to " +
          "this request by its presentation header (the bbs.ph check), " +
          "which is how this Verifier accepts one. Baseline bbs-2023 does " +
          "not bind a credential to a holder key.");
  } else {
    s.add("vp.proof", "The VP's holder proof verifies",
          requiresBinding(query) ? FAIL : SKIP, requiresBinding(query) ?
          "the query requires holder binding and a credential alone does " +
          "not prove who presented it." :
          "the query does not require holder binding.");
  }

  var claimsRoot = null;
  var holder = holderIdOf(doc);
  for (var i = 0; i < creds.length; i++) {
    var env = creds[i];
    var tag = creds.length > 1 ? "vc[" + i + "]." : "vc.";
    if (bbs2023.isPreW3cEnvelope(env)) {
      s.add(tag + "proof", "The credential's issuer proof verifies", FAIL,
            bbs2023.PRE_W3C_ENVELOPE, true);
      continue;
    }
    if (!isPlainObject(env)) {
      s.add(tag + "proof", "The credential's issuer proof verifies", FAIL,
            "the embedded credential is not a JSON object.", true);
      continue;
    }
    var proved = await verifyDiCredential(s, tag, env, ctx);
    if (isBbsCredential(env)) {
      checkPresentationHeader(s, (i === 0 ? "" : tag) + "bbs.ph", proved,
                              ctx.session.nonce, isVp);
    }
    if (i !== 0) continue;
    claimsRoot = env;
    await checkTypeValues(s, "types", query, env);
    if (!isVp) continue;
    var subjects = [].concat(env.credentialSubject || []).map(function (x) {
      return x && x.id;
    }).filter(Boolean);
    if (!requiresBinding(query) && !subjects.length) {
      s.add("vp.binding", "The holder is the credential's subject", SKIP,
            "the query does not require holder binding and the " +
            "credential names no subject id.");
      continue;
    }
    var vmDid = holderVm.split("#")[0];
    var bound = !!holderJwk && !!holder && subjects.indexOf(holder) !== -1 &&
        vmDid === holder;
    s.add("vp.binding", "The holder is the credential's subject",
          bound ? PASS : FAIL, bound ? holder + " is the credential's " +
          "subject and signed the VP." : !holderJwk ? "the VP proof did " +
          "not verify." : subjects.indexOf(holder) === -1 ? "the holder " +
          JSON.stringify(holder) + " is not the credential's subject (" +
          subjects.join(", ") + ")." : "the VP is signed by " + vmDid +
          ", not by the holder " + holder + ".");
  }
  checkRequestedClaims(s, query, function (c) {
    return !!claimsRoot && pathPresent(claimsRoot, c);
  });
  log.debug("Leaving verifyLdpVc().");
  return claimsRoot ? { credentialSubject: claimsRoot.credentialSubject } :
    {};
}

// ---------------------------------------------------------------------------
// The whole response.
// ---------------------------------------------------------------------------

// The JWE protected header of a direct_post.jwt / dc_api.jwt answer, held to
// OpenID4VP 1.0 section 8.3 and RFC 7516 (#468, M6). Each rule is its own
// row, so a Wallet that gets one wrong is told which:
//
//   response.jwe.kid   "If the selected public key contains a kid
//                      parameter, the JWE MUST include the same value in
//                      the kid JWE Header Parameter"
//   response.jwe.alg   "The JWE alg algorithm used MUST be equal to the alg
//                      value of the chosen jwk."
//   response.jwe.enc   "The JWE enc content encryption algorithm used is
//                      obtained from the encrypted_response_enc_values_
//                      supported parameter of client metadata", which this
//                      Verifier sends as session.encValuesSupported (by
//                      default DEFAULT_ENC_VALUES, what requestObjectClaims
//                      writes)
//   response.jwe.crit  RFC 7516 section 4.1.13 gives crit RFC 7515 section
//                      4.1.11's rules: "If any of the listed extension
//                      Header Parameters are not understood and supported
//                      by the recipient, then the JWS is invalid", and
//                      "Producers MUST NOT use the empty list". This
//                      Verifier implements no JWE extension, so any crit
//                      names one it does not understand.
//
// The checks are made BEFORE decryption and do not stop it, so a Wallet
// that names the wrong kid still has its answer opened and shown — the
// FAIL is what decides the verdict.
function checkJweHeader(report, header, session) {
  log.debug("Entering checkJweHeader().");
  var g = "response";
  var key = session.decryptionJwk || {};
  var h = header || {};
  if (key.kid === undefined || key.kid === null || key.kid === "") {
    addCheck(report, "response.jwe.kid", g, "The JWE names the key it " +
             "was encrypted to (kid)", SKIP, "this Verifier's key carries " +
             "no kid, so section 8.3 asks for none.");
  } else {
    addCheck(report, "response.jwe.kid", g, "The JWE names the key it " +
             "was encrypted to (kid)", h.kid === key.kid ? PASS : FAIL,
             h.kid === key.kid ? "kid " + h.kid + "." : "the key in " +
             "client_metadata has kid " + JSON.stringify(key.kid) + " and " +
             "the JWE header " + (h.kid === undefined ? "has no kid" :
             "says " + JSON.stringify(h.kid)) + ". OpenID4VP 1.0 section " +
             "8.3: the JWE MUST include the same value.");
  }
  if (!key.alg) {
    addCheck(report, "response.jwe.alg", g, "The JWE alg is the key's " +
             "alg", SKIP, "this Verifier's key carries no alg to hold the " +
             "JWE to.");
  } else {
    addCheck(report, "response.jwe.alg", g, "The JWE alg is the key's " +
             "alg", h.alg === key.alg ? PASS : FAIL, h.alg === key.alg ?
             "alg " + h.alg + "." : "the key in client_metadata has alg " +
             JSON.stringify(key.alg) + " and the JWE says " +
             JSON.stringify(h.alg) + ". OpenID4VP 1.0 section 8.3: it " +
             "MUST be equal to the alg value of the chosen jwk.");
  }
  var encs = isArray(session.encValuesSupported) &&
      session.encValuesSupported.length ? session.encValuesSupported :
      DEFAULT_ENC_VALUES;
  var encOk = typeof h.enc === "string" && encs.indexOf(h.enc) !== -1;
  addCheck(report, "response.jwe.enc", g, "The JWE enc is one the request " +
           "offered", encOk ? PASS : FAIL, encOk ? "enc " + h.enc +
           ", one of " + encs.join(", ") + "." : "the JWE says enc " +
           JSON.stringify(h.enc) + " and the request's " +
           "encrypted_response_enc_values_supported was " +
           encs.join(", ") + " (OpenID4VP 1.0 section 8.3).");
  if (h.crit === undefined) {
    addCheck(report, "response.jwe.crit", g, "The JWE marks no extension " +
             "critical that this Verifier does not understand", PASS,
             "no crit.");
  } else {
    var why = !isArray(h.crit) || !h.crit.length ? "crit must be a " +
        "non-empty array of Header Parameter names; this one is " +
        JSON.stringify(h.crit) + " (RFC 7515 section 4.1.11, \"Producers " +
        "MUST NOT use the empty list\")." : "crit lists " +
        h.crit.map(function (n) {
          return JSON.stringify(n);
        }).join(", ") + ", and this Verifier implements no JWE extension. " +
        "RFC 7516 section 4.1.13 and RFC 7515 section 4.1.11: if any " +
        "listed extension is not understood and supported by the " +
        "recipient, the JWE is invalid.";
    addCheck(report, "response.jwe.crit", g, "The JWE marks no extension " +
             "critical that this Verifier does not understand", FAIL, why);
  }
  log.debug("Leaving checkJweHeader().");
}

// The decrypted answer as text. A "zip": "DEF" JWE (RFC 7516 section 4.1.3,
// "Compression with the DEFLATE [RFC1951] algorithm") is inflated first:
// section 8.3 does not forbid compression, so it is read and REPORTED
// (response.jwe.zip). Any other zip value is one this Verifier cannot
// undo, and is a FAIL that says so. null when nothing can be read.
async function jwePlaintext(report, opened) {
  log.debug("Entering jwePlaintext().");
  var zip = (opened.header || {}).zip;
  var label = "The JWE's compression is one this Verifier undoes";
  if (zip === undefined) {
    log.debug("Leaving jwePlaintext(). Not compressed.");
    return opened.plaintext;
  }
  if (zip !== "DEF" || !opened.plaintextBytes) {
    addCheck(report, "response.jwe.zip", "response", label, FAIL,
             zip !== "DEF" ? "zip is " + JSON.stringify(zip) + "; the one " +
             "value RFC 7516 section 4.1.3 defines is DEF, and no other is " +
             "implemented here." : "the decrypted bytes were not handed " +
             "back, so they cannot be inflated.");
    log.debug("Leaving jwePlaintext(). Unknown zip.");
    return null;
  }
  try {
    var raw = await inflate(opened.plaintextBytes, "deflate-raw");
    addCheck(report, "response.jwe.zip", "response", label, PASS,
             "zip DEF: " + opened.plaintextBytes.length + " byte(s) " +
             "inflated (RFC 1951) to " + raw.length + ".");
    log.debug("Leaving jwePlaintext(). Inflated.");
    return new TextDecoder().decode(raw);
  } catch (e) {
    addCheck(report, "response.jwe.zip", "response", label, FAIL,
             "zip DEF, and the plaintext does not inflate: " + e.message);
    log.debug("Leaving jwePlaintext(). Bad DEFLATE.");
    return null;
  }
}

// How the answer was ENCODED on its way to response_uri (#469, D2). Section
// 8.2: "The Authorization Response MUST be encoded in the request body
// using the format defined by the application/x-www-form-urlencoded HTTP
// content type", and section 8.3.1 says the same of direct_post.jwt's
// `response` field. The api keeps a JSON body (accept and report), and this
// row is where it is REPORTED: a FAIL, because the MUST is the Wallet's and
// a Wallet that breaks it would be refused by a Verifier that implements
// only the form. The answer is still opened and checked. No row when the
// media type is not known (a pasted answer) or under the DC API, which
// hands the page an object and has no body at all.
function checkEncoding(report, contentType, dc) {
  log.debug("Entering checkEncoding().");
  if (contentType === undefined || contentType === null || dc) {
    log.debug("Leaving checkEncoding(). Not known.");
    return;
  }
  var type = String(contentType).split(";")[0].trim().toLowerCase();
  var form = type === "application/x-www-form-urlencoded";
  addCheck(report, "response.encoding", "response", "The answer was " +
           "posted as a form", form ? PASS : FAIL, form ? "Content-Type " +
           type + ", as section 8.2 requires." : "it was posted as " +
           (type ? JSON.stringify(type) : "no Content-Type") + ". " +
           "OpenID4VP 1.0 section 8.2: the Authorization Response MUST be " +
           "encoded as application/x-www-form-urlencoded. The api kept " +
           "it, and it is checked below as if it had been.");
  log.debug("Leaving checkEncoding(). " + form);
}

async function openResponse(report, parsed, session) {
  log.debug("Entering openResponse().");
  var g = "response";
  var mode = session.responseMode || "direct_post";
  var jwtMode = isEncryptedMode(mode);
  var dc = isDcApiMode(mode);
  var label = "The answer arrived the way the request asked";
  if (jwtMode && !parsed.response) {
    addCheck(report, "response.mode", g, label, FAIL, "the request asked " +
             "for " + mode + " and " + (dc ? "the DC API data object " +
             "carries" : "a plain form arrived, with") + " no `response` " +
             "member: the answer was not encrypted.");
    log.debug("Leaving openResponse(). Plain under jwt.");
    return null;
  }
  if (!jwtMode && parsed.response) {
    addCheck(report, "response.mode", g, label, FAIL, "the request asked " +
             "for " + mode + " and an encrypted `response` arrived.");
    log.debug("Leaving openResponse(). Encrypted under plain.");
    return null;
  }
  addCheck(report, "response.mode", g, label, PASS, dc ? (jwtMode ?
           "a DC API data object with one `response` member, as " +
           "dc_api.jwt requires (Appendix A.4)." : "a DC API data object " +
           "carrying vp_token, as dc_api returns it (Appendix A.4).") :
           jwtMode ? "one `response` field, as direct_post.jwt requires." :
           "form fields, as direct_post sends them.");
  if (!jwtMode) {
    log.debug("Leaving openResponse(). Plain.");
    return parsed;
  }
  var header = null;
  try {
    header = joseJwe.parseCompact(parsed.response).header;
  } catch (e) {
    addCheck(report, "response.decrypt", g, "The encrypted answer opens " +
             "with this Verifier's key", FAIL, e.message);
    log.debug("Leaving openResponse(). Not a JWE.");
    return null;
  }
  checkJweHeader(report, header, session);
  try {
    var opened = await joseJwe.decryptCompact({ jwe: parsed.response,
      key: session.decryptionJwk });
    var kid = (opened.header || {}).kid;
    addCheck(report, "response.decrypt", g, "The encrypted answer opens " +
             "with this Verifier's key", PASS, "alg " + opened.header.alg +
             ", enc " + opened.header.enc + (kid ? ", kid " + kid : "") +
             ".");
    var text = await jwePlaintext(report, opened);
    if (text === null) {
      log.debug("Leaving openResponse(). Unreadable plaintext.");
      return null;
    }
    var inner = JSON.parse(text);
    log.debug("Leaving openResponse(). Decrypted.");
    return parseResponse(inner);
  } catch (e) {
    addCheck(report, "response.decrypt", g, "The encrypted answer opens " +
             "with this Verifier's key", FAIL, e.message);
    log.debug("Leaving openResponse(). Undecryptable.");
    return null;
  }
}

function requiredQueryIds(dcql) {
  log.debug("Entering requiredQueryIds().");
  var queries = sdJwtVp.dcqlCredentialQueries(dcql);
  if (!isArray(dcql && dcql.credential_sets) ||
      !dcql.credential_sets.length) {
    log.debug("Leaving requiredQueryIds(). All.");
    return { all: queries.map(function (q) {
      return q.id;
    }), sets: [] };
  }
  log.debug("Leaving requiredQueryIds(). Sets.");
  return { all: [], sets: dcql.credential_sets.filter(function (set) {
    return set.required !== false;
  }) };
}

function checkQueries(report, vpToken, dcql) {
  log.debug("Entering checkQueries().");
  var g = "response";
  var label = "vp_token answers the query";
  var known = {};
  sdJwtVp.dcqlCredentialQueries(dcql).forEach(function (q) {
    known[q.id] = q;
  });
  var problems = [];
  var answered = Object.keys(vpToken);
  answered.forEach(function (id) {
    if (!known[id]) {
      problems.push('"' + id + '" is no credential query of this request');
      return;
    }
    if (!isArray(vpToken[id]) || !vpToken[id].length) {
      problems.push('"' + id + '" must be a non-empty array of ' +
                    "presentations (section 8.1)");
    } else if (vpToken[id].length > 1 && known[id].multiple !== true) {
      problems.push('"' + id + '" carries ' + vpToken[id].length +
                    " presentations and the query did not set multiple");
    }
  });
  var req = requiredQueryIds(dcql);
  req.all.forEach(function (id) {
    if (answered.indexOf(id) === -1) {
      problems.push('the required query "' + id + '" is not answered');
    }
  });
  req.sets.forEach(function (set, i) {
    var met = set.options.some(function (option) {
      return option.every(function (id) {
        return answered.indexOf(id) !== -1;
      });
    });
    if (!met) {
      problems.push("required credential set " + i + " is satisfied by " +
                    "none of its options");
    }
  });
  addCheck(report, "response.queries", g, label, problems.length ? FAIL :
           PASS, problems.length ? problems.join("; ") + "." :
           "answers " + answered.join(", ") + ".");
  log.debug("Leaving checkQueries(). " + problems.length + " problem(s).");
}

var VERIFIERS = {
  "dc+sd-jwt": verifySdJwt,
  "jwt_vc_json": verifyJwtVcJson,
  "mso_mdoc": verifyMdoc,
  "ldp_vc": verifyLdpVc
};

async function verifyPresentations(report, vpToken, ctx) {
  log.debug("Entering verifyPresentations().");
  var out = [];
  var queries = sdJwtVp.dcqlCredentialQueries(ctx.session.dcql);
  for (var qi = 0; qi < queries.length; qi++) {
    var query = queries[qi];
    var list = isArray(vpToken[query.id]) ? vpToken[query.id] : [];
    for (var i = 0; i < list.length; i++) {
      var group = query.id + "[" + i + "] " + query.format;
      var s = scope(report, group, query.id + "[" + i + "].");
      var verify = VERIFIERS[query.format];
      if (!verify) {
        s.add("format", "The format is one this Verifier reads", FAIL,
              'format "' + query.format + '" is not one of ' +
              FORMATS.join(", ") + ".");
        continue;
      }
      var claims = null;
      var one = Object.assign({}, ctx, { query: query,
                                         authoritiesReported: false });
      try {
        claims = await verify(s, query, list[i], one);
      } catch (e) {
        s.add("error", "The presentation could be checked", FAIL,
              e.message);
      }
      if (isArray(query.trusted_authorities) && !one.authoritiesReported) {
        trustedAuthoritiesRow(s, "trusted-authorities", null, one);
      }
      out.push({ queryId: query.id, format: query.format, claims: claims });
    }
  }
  log.debug("Leaving verifyPresentations(). " + out.length +
            " presentation(s).");
  return out;
}

// The verdict (#467, S4): "fail" when any check failed; "incomplete" when
// none failed but an ESSENTIAL check was not performed (an issuer proof in
// a cryptosuite this debugger does not verify, an x5c chain nothing
// anchors, a holder signature the query needs and nobody checked); "pass"
// only when neither. OpenID4VP 1.0 section 8.6: a presentation whose checks
// fail MUST be discarded, and one whose authenticity was never established
// has not passed them. `ok` is kept, and is true only for "pass".
function finish(report, presentations) {
  log.debug("Entering finish().");
  var failed = report.checks.filter(function (c) {
    return c.status === FAIL;
  }).length;
  var notPerformed = report.checks.filter(function (c) {
    return c.essential && c.status === SKIP;
  }).length;
  var verdict = failed || !report.checks.length ? "fail" :
      notPerformed ? "incomplete" : "pass";
  log.debug("Leaving finish(). " + report.checks.length + " check(s), " +
            failed + " failed, " + notPerformed + " essential not " +
            "performed: " + verdict + ".");
  return { ok: verdict === "pass", verdict: verdict, failed: failed,
           incomplete: notPerformed, checks: report.checks,
           presentations: presentations || [] };
}

// Check a Wallet's answer. opts:
//   fields     what arrived: the direct_post form (a string, URLSearchParams
//              or an object), or the DC API's data object ({ vp_token } or
//              { response }), as an object or its JSON
//   session    { clientId, nonce, state, responseMode, responseUri, dcql,
//                decryptionJwk, origin, trustAnchors } — origin is the
//              page's origin, and is what a DC API answer's audience is
//              (Appendix A.4); trustAnchors (PEM or base64 DER) are what
//              an issuer's x5c chain may be anchored at; encValuesSupported
//              is the encrypted_response_enc_values_supported the request
//              sent, when it was not DEFAULT_ENC_VALUES
//   fetchJson  optional: issuer metadata, DID documents, key documents
//   fetchText  optional: (url, { accept }) => the body, for status lists:
//              a string, bytes (ArrayBuffer or Uint8Array, so a binary CWT
//              survives), or { body, contentType }; with none, every
//              status check is a skip that says so
//   statusSigningEku  optional: the OID (or OIDs) this PKI uses for
//              draft-ietf-oauth-status-list's id-kp-oauthStatusSigning,
//              which has no assigned number yet (section 14.9)
//   now        optional: the time to judge validity at
//   maxAgeSeconds  optional (or session.maxAgeSeconds): this debugger's
//              freshness policy for a KB-JWT's or VP JWT's iat, default
//              MAX_AGE_SECONDS; 0 sets no age limit (#469, C2)
//   contentType  optional: the Content-Type the answer was POSTed with to
//              response_uri, as the api recorded it. When given, it is held
//              to section 8.2 (response.encoding)
async function verifyResponse(opts) {
  log.debug("Entering verifyResponse().");
  var o = opts || {};
  var session = o.session || {};
  var report = { checks: [] };
  var g = "response";
  var dc = isDcApiMode(session.responseMode);
  var input = o.fields;
  if (dc && typeof input === "string" && /^\s*\{/.test(input)) {
    try {
      input = JSON.parse(input);
    } catch (e) {
      log.debug("verifyResponse(): DC API data is not JSON: " + e.message);
    }
  }
  checkEncoding(report, o.contentType, dc);
  var outer = parseResponse(input);
  if (outer.error) {
    addCheck(report, "response.error", g, "The Wallet answered with a " +
             "presentation", FAIL, "the Wallet refused: " + outer.error +
             (outer.errorDescription ? " — " + outer.errorDescription : "") +
             ".");
    log.debug("Leaving verifyResponse(). Error answer.");
    return finish(report, []);
  }
  var parsed = await openResponse(report, outer, session);
  if (!parsed) {
    log.debug("Leaving verifyResponse(). Could not open.");
    return finish(report, []);
  }
  if (parsed.error) {
    addCheck(report, "response.error", g, "The Wallet answered with a " +
             "presentation", FAIL, "the Wallet refused: " + parsed.error +
             (parsed.errorDescription ? " — " + parsed.errorDescription :
              "") + ".");
    log.debug("Leaving verifyResponse(). Encrypted error answer.");
    return finish(report, []);
  }
  if (dc) {
    addCheck(report, "response.state", g, "state is this request's", SKIP,
             "the Digital Credentials API defines no state, so a Verifier " +
             "cannot expect one (Appendix A.2).");
  } else if (session.state === undefined || session.state === null ||
      session.state === "") {
    addCheck(report, "response.state", g, "state is this request's", SKIP,
             "the request carried no state.");
  } else {
    addCheck(report, "response.state", g, "state is this request's",
             parsed.state === session.state ? PASS : FAIL,
             parsed.state === session.state ? "state matches." :
             "state is " + JSON.stringify(parsed.state) + ", the " +
             "request's was " + JSON.stringify(session.state) + ".");
  }
  var audience = session.clientId;
  if (dc) {
    // The Origin is used AS GIVEN, and is window.location.origin on the
    // page: the HTML Standard's ASCII serialization of an origin, scheme
    // "://" host [":" port], with no trailing slash (#471, E6). That is the
    // Origin OpenID4VP 1.0 means: section 2 defines it as "the combination
    // of a scheme/protocol, host, and port" ("The web origin is
    // https://verify.example.com"), Appendix A.2's expected_origins example
    // is "https://origin1.example.com", and Appendix B.2.6.2's worked
    // SessionTranscript hashes "https://example.com" — the bytes
    // tests/vp_verifier_engine.js reproduces. Only the illustrative
    // "origin:https://verifier.example.com/" of section 5.9.3 and Appendix
    // A.4 has a slash. The W3C Digital Credentials API records the
    // top-level document's origin, an origin and not a URL (its section
    // 6.7), and A.2 leaves how the wallet receives it to the platform. So
    // the KB-JWT aud is "origin:" + this, and the mdoc DC handover's
    // origin is this, unprefixed (B.2.6.2: "It MUST NOT be prefixed with
    // origin:"). A session origin with a path is a URL, not an Origin.
    var origin = String(session.origin || "");
    var pathed = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]+[/?#]/i.test(origin);
    audience = origin ? ORIGIN_PREFIX + origin : "";
    addCheck(report, "response.origin", g, "The audience is this page's " +
             "origin (DC API)", audience && !pathed ? PASS : FAIL,
             pathed ? "session.origin is " + JSON.stringify(origin) +
             ", a URL with a path, not an Origin (scheme, host and port, " +
             "OpenID4VP 1.0 section 2; window.location.origin has no " +
             "trailing slash)." : audience ?
             "over the Digital Credentials API every presentation's " +
             "audience is " + audience + ", signed request or not " +
             "(Appendix A.4)." : "session.origin was not given, so there is " +
             "no audience to hold the presentations to.");
  }
  var vpToken = parsed.vpToken;
  if (parsed.vpTokenError || !isPlainObject(vpToken)) {
    addCheck(report, "response.queries", g, "vp_token answers the query",
             FAIL, parsed.vpTokenError || (vpToken === undefined ?
             "there is no vp_token." : "vp_token must be a JSON object " +
             "keyed by credential query id (section 8.1)."));
    log.debug("Leaving verifyResponse(). No vp_token object.");
    return finish(report, []);
  }
  checkQueries(report, vpToken, session.dcql);
  var maxAge = typeof o.maxAgeSeconds === "number" ? o.maxAgeSeconds :
      typeof session.maxAgeSeconds === "number" ? session.maxAgeSeconds :
      MAX_AGE_SECONDS;
  var ctx = { session: session, fetchJson: o.fetchJson,
              fetchText: o.fetchText, audience: audience,
              maxAgeSeconds: maxAge,
              statusSigningEku: [].concat(o.statusSigningEku || []),
              now: nowSeconds(o.now) };
  var presentations = await verifyPresentations(report, vpToken, ctx);
  var summary = statusSummary(report);
  addCheck(report, "status", "status", "Credential status (revocation)",
           summary.status, summary.detail);
  if (parsed.idToken) {
    addCheck(report, "id_token", g, "The self-issued ID Token verifies",
             SKIP, "SIOPv2 ID Tokens are not checked by the Verifier " +
             "engine.");
  }
  log.debug("Leaving verifyResponse().");
  return finish(report, presentations);
}

module.exports = {
  FORMATS: FORMATS,
  REQUEST_AUD: REQUEST_AUD,
  SKEW_SECONDS: SKEW_SECONDS,
  MAX_AGE_SECONDS: MAX_AGE_SECONDS,
  RESPONSE_MODES: RESPONSE_MODES,
  DC_API_PROTOCOLS: DC_API_PROTOCOLS,
  VERIFIER_ATTESTATION_TYP: VERIFIER_ATTESTATION_TYP,
  randomToken: randomToken,
  buildDcql: buildDcql,
  makeVerifierIdentity: makeVerifierIdentity,
  makeVerifierRoot: makeVerifierRoot,
  verifierIdentityFile: verifierIdentityFile,
  readVerifierIdentityFile: readVerifierIdentityFile,
  p256PointOfCertificate: p256PointOfCertificate,
  makeRequestKey: makeRequestKey,
  makeAttester: makeAttester,
  verifierAttestation: verifierAttestation,
  preRegisteredJwks: preRegisteredJwks,
  didForKey: didForKey,
  clientIdFor: clientIdFor,
  responseEncryptionKey: responseEncryptionKey,
  vpFormatsSupported: vpFormatsSupported,
  requestObjectClaims: requestObjectClaims,
  signRequestObject: signRequestObject,
  signingAlgsFor: signingAlgsFor,
  planForWalletMetadata: planForWalletMetadata,
  akiValuesFromAnchors: akiValuesFromAnchors,
  encryptRequestObject: encryptRequestObject,
  dcApiRequest: dcApiRequest,
  authorizationRequestUri: authorizationRequestUri,
  parseResponse: parseResponse,
  verifyResponse: verifyResponse,
  verifyDataIntegrity: verifyDataIntegrity,
  mdocSessionTranscript: mdocSessionTranscript,
  jwkThumbprint: jwkThumbprint,
  jwtVcIssuerUrl: jwtVcIssuerUrl
};
