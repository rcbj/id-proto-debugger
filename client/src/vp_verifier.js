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
// SD-JWT digests and sd_hash, every JWS, the ecdsa-jcs-2019 proof) are pure
// JavaScript — @noble/hashes and jws.js's 'js' backend — so they work on an
// origin with no secure context. Three things it borrows are Web Crypto
// underneath and inherit that module's limits: certificate ISSUANCE
// (x509.js), the ECDH-ES unwrap of a direct_post.jwt answer (jose_jwe.js)
// and the mdoc COSE signatures (mdoc.js).
//
// Scope: PR 1 of 3. The x509_hash, x509_san_dns and redirect_uri Client
// Identifier prefixes; the four DCQL formats. Status lists, the other prefixes
// and cryptosuites other than bbs-2023 / ecdsa-jcs-2019 are reported as
// "skip" naming the later PR, never as a pass.
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
var nobleSha512 = require("@noble/hashes/sha512");
var p256 = require("@noble/curves/p256").p256;
var bytes = require("./crypto_bytes");
var jws = require("./jws");
var x509 = require("./x509");
var keyMaterial = require("./key_material");
var vpProtocols = require("./vp_protocols");
var joseJwe = require("./jose_jwe");
var sdJwtVc = require("./sd_jwt_vc");
var sdJwtVp = require("./sd_jwt_vp");
var mdoc = require("./mdoc");
var bbs2023 = require("./bbs2023");
var didLib = require("./did");

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
var SKEW_SECONDS = 300;
var MAX_AGE_SECONDS = 600;
var JWT_VC_ISSUER_WELL_KNOWN = "/.well-known/jwt-vc-issuer";
var PR3 = "#364 PR 3";

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
  var out = { id: String(q.id), format: q.format, meta: {} };
  if (q.format === FORMAT_SD_JWT && q.vct) {
    out.meta.vct_values = [].concat(q.vct);
  }
  if (q.format === FORMAT_MSO_MDOC && q.doctype) {
    out.meta.doctype_value = String(q.doctype);
  }
  if ((q.format === FORMAT_JWT_VC_JSON || q.format === FORMAT_LDP_VC) &&
      q.types && q.types.length) {
    out.meta.type_values = isArray(q.types[0]) ? q.types.map(function (t) {
      return t.slice();
    }) : [q.types.slice()];
  }
  var where = 'credential query "' + q.id + '"';
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
// ---------------------------------------------------------------------------
function x509HashOf(der) {
  log.debug("Entering x509HashOf().");
  log.debug("Leaving x509HashOf().");
  return bytes.bytesToB64u(nobleSha256(bytes.asBytes(der)));
}

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
  var rootKey = await keyMaterial.generateKeyPair("ec-p256");
  var leafKey = await keyMaterial.generateKeyPair("ec-p256");
  var root = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=Debugger Verifier Root,O=idptools",
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem,
    signatureAlg: "sha256-ecdsa", notBefore: notBefore,
    extensions: x509.defaultExtensions("root-ca")
  });
  var ext = x509.defaultExtensions("tls-server");
  ext.subjectAltName = { present: true, critical: false,
    names: [{ kind: "dns", value: String(o.dnsName) }] };
  if (o.caIssuersUrl) {
    ext.authorityInfoAccess = { present: true, critical: false,
      entries: [{ method: "caIssuers", url: String(o.caIssuersUrl) }] };
  }
  var leaf = await x509.issueCertificate({
    profile: "tls-server", subject: "CN=" + o.dnsName + ",O=idptools",
    subjectPublicKey: leafKey.publicPem,
    issuer: { certificatePem: root.pem, privateKeyPem: rootKey.privatePem,
              keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa", notBefore: notBefore, extensions: ext
  });
  var privateJwk = await keyMaterial.privToJwk(leafKey.privatePem, desc,
                                               "ES256");
  var publicJwk = await keyMaterial.pubToJwk(leafKey.publicPem, desc,
                                             "ES256", "sig");
  var leafDer = bytes.asBytes(leaf.der);
  log.debug("Leaving makeVerifierIdentity(). dns=" + o.dnsName);
  return {
    rootPem: root.pem, rootDer: bytes.asBytes(root.der),
    leafPem: leaf.pem, leafDer: leafDer,
    privateJwk: privateJwk, publicJwk: publicJwk,
    x5c: [bytes.bytesToB64(leafDer)],
    x509Hash: x509HashOf(leafDer),
    dnsName: String(o.dnsName), caIssuersUrl: o.caIssuersUrl || ""
  };
}

// The Client Identifier for a prefix (OpenID4VP 1.0 section 5.9.3). The
// other prefixes are #364 PR 3.
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
  log.debug("Leaving clientIdFor(). Unsupported.");
  throw new Error('the Client Identifier prefix "' + prefix + '" is not ' +
                  "built by this debugger yet (" + PR3 + ").");
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
function vpFormatsSupported() {
  log.debug("Entering vpFormatsSupported().");
  log.debug("Leaving vpFormatsSupported().");
  return {
    "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256", "ES384", "EdDSA"],
                   "kb-jwt_alg_values": ["ES256", "ES384", "EdDSA"] },
    "jwt_vc_json": { alg_values: ["ES256", "ES384", "EdDSA"] },
    "mso_mdoc": { issuerauth_alg_values: [-7],
                  deviceauth_alg_values: [-7] },
    "ldp_vc": { proof_type_values: ["DataIntegrityProof"],
                cryptosuite_values: ["bbs-2023", "ecdsa-jcs-2019"] }
  };
}

function requestObjectClaims(opts) {
  log.debug("Entering requestObjectClaims().");
  var o = opts || {};
  var mode = o.responseMode || "direct_post";
  if (mode !== "direct_post" && mode !== "direct_post.jwt") {
    log.debug("Leaving requestObjectClaims(). Bad mode.");
    throw new Error('response_mode "' + mode + '" is not one this ' +
                    "Verifier receives (direct_post, direct_post.jwt).");
  }
  var iat = nowSeconds(o.now);
  var claims = {};
  var prefix = vpProtocols.clientIdPrefix(o.clientId).prefix;
  if (prefix === "x509_hash" || prefix === "x509_san_dns") {
    claims.iss = o.clientId;
  }
  claims.client_id = o.clientId;
  claims.aud = REQUEST_AUD;
  claims.response_type = "vp_token";
  claims.response_mode = mode;
  claims.response_uri = o.responseUri;
  claims.nonce = o.nonce;
  if (o.state) claims.state = o.state;
  claims.dcql_query = o.dcql;
  claims.iat = iat;
  claims.exp = iat + (o.ttlSeconds || DEFAULT_TTL_SECONDS);
  var metadata = { vp_formats_supported: vpFormatsSupported() };
  if (mode === "direct_post.jwt") {
    if (!o.encryptionJwk) {
      log.debug("Leaving requestObjectClaims(). No encryption key.");
      throw new Error("direct_post.jwt needs an encryption key.");
    }
    metadata.jwks = { keys: [publicPart(o.encryptionJwk)] };
    metadata.encrypted_response_enc_values_supported =
      (o.encValuesSupported || DEFAULT_ENC_VALUES).slice();
  }
  claims.client_metadata = metadata;
  log.debug("Leaving requestObjectClaims().");
  return claims;
}

async function signRequestObject(opts) {
  log.debug("Entering signRequestObject().");
  var identity = opts.identity;
  var signed = await jws.signJwsAsync({
    algId: "ES256",
    protectedHeader: { alg: "ES256", typ: REQUEST_TYP, x5c: identity.x5c },
    payload: opts.claims,
    privateKey: { jwk: identity.privateJwk },
    backend: "js"
  });
  log.debug("Leaving signRequestObject().");
  return signed.serialized;
}

function encodeParam(name, value) {
  log.debug("Entering encodeParam(). " + name);
  log.debug("Leaving encodeParam().");
  return encodeURIComponent(name) + "=" + encodeURIComponent(
    typeof value === "string" ? value : JSON.stringify(value));
}

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
function addCheck(report, id, group, label, status, detail) {
  log.debug("Entering addCheck(). " + id + " " + status);
  report.checks.push({ id: id, group: group, label: label, status: status,
                       detail: detail || "" });
  log.debug("Leaving addCheck().");
}

function scope(report, group, prefix) {
  log.debug("Entering scope(). " + prefix);
  log.debug("Leaving scope().");
  return {
    report: report, group: group, prefix: prefix,
    add: function add(key, label, status, detail) {
      log.debug("Entering add(). " + prefix + key);
      addCheck(report, prefix + key, group, label, status, detail);
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

// A DID's assertion keys as a JWK Set, through did.js.
async function didJwks(did, fetchJson) {
  log.debug("Entering didJwks().");
  var jwk = sdJwtVc.jwkFromDid(did);
  if (jwk) {
    // One key and no set: a did:jwk IS its key, so there is no kid to
    // select by (and the header's DID-URL kid would match no member).
    log.debug("Leaving didJwks(). did:jwk.");
    return { jwks: { jwk: jwk }, from: "the did:jwk itself" };
  }
  var res = await didLib.resolve(String(did).split("#")[0],
    { fetch: fetchJson ? fetchAdapter(fetchJson) : undefined });
  var converted = didLib.assertionJwks(res.document);
  log.debug("Leaving didJwks().");
  return { jwks: converted.jwks, from: res.from };
}

// Where an issuer's key is: the x5c leaf, else the DID the issuer names,
// else /.well-known/jwt-vc-issuer under an https issuer.
async function issuerKey(header, payload, fetchJson) {
  log.debug("Entering issuerKey().");
  if (isArray(header.x5c) && header.x5c.length) {
    log.debug("Leaving issuerKey(). x5c.");
    return { key: bytes.derToPem(bytes.b64ToBytes(header.x5c[0]),
                                 "CERTIFICATE"),
             from: "the x5c leaf certificate in its header (the chain is " +
                   "not anchored by this debugger yet, " + PR3 + ")" };
  }
  var iss = String(payload.iss || "");
  var kid = String(header.kid || "");
  var did = didLib.isDid(iss) ? iss : didLib.isDid(kid) ? kid : "";
  if (did) {
    var found = await didJwks(did, fetchJson);
    log.debug("Leaving issuerKey(). DID.");
    return { key: found.jwks, from: found.from };
  }
  if (/^https:\/\//.test(iss)) {
    if (!fetchJson) {
      log.debug("Leaving issuerKey(). No fetch.");
      throw new Error("no fetchJson was given to read " + iss + "'s keys.");
    }
    var url = jwtVcIssuerUrl(iss);
    var meta = await fetchJson(url);
    if (!meta || meta.issuer !== iss) {
      log.debug("Leaving issuerKey(). Wrong issuer.");
      throw new Error(url + " names issuer " + JSON.stringify(
        meta && meta.issuer) + ", not " + iss + " (SD-JWT VC section 5).");
    }
    var jwks = meta.jwks || (meta.jwks_uri ? await fetchJson(meta.jwks_uri) :
                             null);
    if (!jwks || !isArray(jwks.keys)) {
      log.debug("Leaving issuerKey(). No keys.");
      throw new Error(url + " carries neither jwks nor a jwks_uri that " +
                      "answers with keys.");
    }
    log.debug("Leaving issuerKey(). Metadata.");
    return { key: jwks, from: meta.jwks ? url : meta.jwks_uri };
  }
  log.debug("Leaving issuerKey(). Nowhere.");
  throw new Error("the credential carries no x5c and its iss (" +
                  (iss || "absent") + ") is neither a DID nor an https " +
                  "URL, so there is nowhere to find its key.");
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

async function checkIssuerSignature(s, key, compact, header, payload,
                                    fetchJson, label) {
  log.debug("Entering checkIssuerSignature().");
  var found;
  try {
    found = await issuerKey(header, payload, fetchJson);
  } catch (e) {
    s.add(key, label, FAIL, "no issuer key: " + e.message);
    log.debug("Leaving checkIssuerSignature(). No key.");
    return false;
  }
  var v = verifyCompact(compact, found.key);
  s.add(key, label, v.valid ? PASS : FAIL, v.valid ?
        "verifies (" + header.alg + ") with the key from " + found.from +
        "." : "does NOT verify with the key from " + found.from +
        (v.reason ? ": " + v.reason : "."));
  log.debug("Leaving checkIssuerSignature(). " + v.valid);
  return v.valid;
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

// Freshness of a holder proof: iat within the skew of now and not older than
// MAX_AGE_SECONDS.
function freshness(iat, now) {
  log.debug("Entering freshness().");
  if (typeof iat !== "number") {
    log.debug("Leaving freshness(). No iat.");
    return { status: FAIL, detail: "there is no numeric iat." };
  }
  if (iat > now + SKEW_SECONDS) {
    log.debug("Leaving freshness(). Future.");
    return { status: FAIL, detail: "iat is " + (iat - now) + "s in the " +
             "future (allowed skew " + SKEW_SECONDS + "s)." };
  }
  if (iat < now - MAX_AGE_SECONDS) {
    log.debug("Leaving freshness(). Stale.");
    return { status: FAIL, detail: "iat is " + (now - iat) + "s old; a " +
             "proof older than " + MAX_AGE_SECONDS + "s was not made for " +
             "this request." };
  }
  log.debug("Leaving freshness().");
  return { status: PASS, detail: "iat is " + (now - iat) + "s old." };
}

function audMatches(aud, clientId) {
  log.debug("Entering audMatches().");
  log.debug("Leaving audMatches().");
  return isArray(aud) ? aud.length === 1 && aud[0] === clientId :
    aud === clientId;
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
                             header, payload, ctx.fetchJson,
                             "The issuer's signature verifies");

  var built = null;
  try {
    built = reconstruct(parsed);
    s.add("disclosures", "Every Disclosure's digest is in an _sd array",
          built.problems.length ? FAIL : PASS, built.problems.length ?
          built.problems.join(" ") : "all " + parsed.disclosures.length +
          " Disclosure(s) hash (" + (payload._sd_alg || "sha-256") +
          ") to a digest the issuer signed.");
  } catch (e) {
    s.add("disclosures", "Every Disclosure's digest is in an _sd array",
          FAIL, e.message);
  }

  var vctValues = ((query.meta || {}).vct_values) || [];
  if (!vctValues.length) {
    s.add("vct", "vct is one the query asks for", SKIP,
          "the query names no vct_values (vct is " +
          JSON.stringify(payload.vct) + ").");
  } else {
    var vctOk = vctValues.indexOf(payload.vct) !== -1;
    s.add("vct", "vct is one the query asks for", vctOk ? PASS : FAIL,
          "vct is " + JSON.stringify(payload.vct) + (vctOk ? "." :
          ", not one of " + vctValues.join(", ") + "."));
  }

  var verdict = validityVerdict(sdJwtVc.validityWindowOf(
    { payload: payload }), payload.iat, now);
  s.add("validity", "The credential is within its validity window",
        verdict.status, verdict.detail);

  await verifyKbJwt(s, query, parsed, ctx);

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
    "kb.signature": "The KB-JWT verifies with the credential's cnf.jwk",
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
      s.add(k, labels[k], SKIP, "there is no KB-JWT.");
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

  var cnf = (parsed.payload || {}).cnf;
  var cnfJwk = cnf && cnf.jwk;
  if (!cnfJwk) {
    s.add("kb.signature", labels["kb.signature"], FAIL, "the credential " +
          "has no cnf.jwk, so there is no key the holder can prove.");
  } else {
    var v = verifyCompact(parsed.kbJwt, { jwk: cnfJwk });
    s.add("kb.signature", labels["kb.signature"], v.valid ? PASS : FAIL,
          v.valid ? "the KB-JWT verifies with cnf.jwk (thumbprint " +
          jwkThumbprint(cnfJwk) + ")." : "the KB-JWT does NOT verify with " +
          "cnf.jwk" + (v.reason ? ": " + v.reason : "."));
  }
  s.add("kb.nonce", labels["kb.nonce"],
        p.nonce === ctx.session.nonce ? PASS : FAIL,
        p.nonce === ctx.session.nonce ? "nonce matches." : "nonce is " +
        JSON.stringify(p.nonce) + ", the request's was " +
        JSON.stringify(ctx.session.nonce) + ".");
  var audOk = audMatches(p.aud, ctx.session.clientId);
  s.add("kb.aud", labels["kb.aud"], audOk ? PASS : FAIL, audOk ?
        "aud is " + ctx.session.clientId + "." : "aud is " +
        JSON.stringify(p.aud) + ", not " + ctx.session.clientId + ".");
  var fresh = freshness(p.iat, ctx.now);
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
  var found = methods.filter(function (m) {
    return m.id === didUrl || (frag && m.id &&
                               m.id.split("#")[1] === frag);
  })[0] || (frag ? null : methods[0]);
  log.debug("Leaving keyForDidUrl().");
  return found ? found.jwk : null;
}

function boundKeyOf(vcPayload) {
  log.debug("Entering boundKeyOf().");
  if (vcPayload.cnf && vcPayload.cnf.jwk) {
    log.debug("Leaving boundKeyOf(). cnf.");
    return { jwk: vcPayload.cnf.jwk, member: "cnf.jwk" };
  }
  var subject = ((vcPayload.vc || {}).credentialSubject || {}).id ||
      vcPayload.sub || "";
  var jwk = sdJwtVc.jwkFromDid(subject);
  log.debug("Leaving boundKeyOf().");
  return jwk ? { jwk: jwk, member: "credentialSubject.id" } : null;
}

async function holderKey(header, payload, bound, fetchJson) {
  log.debug("Entering holderKey().");
  if (header.jwk) {
    log.debug("Leaving holderKey(). Header jwk.");
    return { jwk: header.jwk, from: "the jwk in its header" };
  }
  var didUrl = didLib.isDid(String(header.kid || "")) ? header.kid :
      didLib.isDid(String(payload.iss || "")) ? payload.iss : "";
  if (didUrl) {
    var jwk = await keyForDidUrl(didUrl, fetchJson);
    if (jwk) {
      log.debug("Leaving holderKey(). DID.");
      return { jwk: jwk, from: didUrl };
    }
  }
  if (bound) {
    log.debug("Leaving holderKey(). Bound key.");
    return { jwk: bound.jwk, from: "the credential's " + bound.member +
             " (the VP names no key of its own)" };
  }
  log.debug("Leaving holderKey(). None.");
  return null;
}

function typesMatch(types, typeValues) {
  log.debug("Entering typesMatch().");
  log.debug("Leaving typesMatch().");
  return typeValues.some(function (alt) {
    return alt.every(function (t) {
      return types.indexOf(t) !== -1;
    });
  });
}

async function verifyJwtVcJson(s, query, presentation, ctx) {
  log.debug("Entering verifyJwtVcJson().");
  var vp;
  try {
    if (typeof presentation !== "string" ||
        presentation.indexOf("~") !== -1) {
      throw new Error("it is not a compact JWS.");
    }
    vp = decodeJwt(presentation);
    if (!vp.payload.vp) throw new Error("the JWT carries no vp claim.");
  } catch (e) {
    s.add("format", "The presentation is a VP JWT", FAIL, e.message);
    log.debug("Leaving verifyJwtVcJson(). Unreadable.");
    return null;
  }
  var vcs = [].concat(vp.payload.vp.verifiableCredential || []);
  s.add("format", "The presentation is a VP JWT", vcs.length ? PASS : FAIL,
        vcs.length + " embedded credential(s).");
  var first = null;
  try {
    first = vcs.length ? decodeJwt(vcs[0]) : null;
  } catch (e) {
    first = null;
  }
  var bound = first ? boundKeyOf(first.payload) : null;

  var hk = null;
  var holderError = "";
  try {
    hk = await holderKey(vp.header, vp.payload, bound, ctx.fetchJson);
  } catch (e) {
    holderError = e.message;
  }
  if (holderError) {
    s.add("vp.signature", "The VP JWT verifies with the holder's key",
          FAIL, "the holder key could not be resolved: " + holderError);
  } else if (hk) {
    var v = verifyCompact(presentation, { jwk: hk.jwk });
    s.add("vp.signature", "The VP JWT verifies with the holder's key",
          v.valid ? PASS : FAIL, (v.valid ? "verifies" :
          "does NOT verify") + " with the key from " + hk.from +
          (v.reason && !v.valid ? ": " + v.reason : "."));
  } else {
    s.add("vp.signature", "The VP JWT verifies with the holder's key",
          FAIL, "it names no key (no jwk, no DID kid or iss) and the " +
          "credential is bound to none.");
  }
  if (!requiresBinding(query) && !bound) {
    s.add("vp.binding", "The VP is signed by the key the credential is " +
          "bound to", SKIP, "the query does not require holder binding.");
  } else {
    var bindOk = !!(hk && bound && sameKey(hk.jwk, bound.jwk));
    s.add("vp.binding", "The VP is signed by the key the credential is " +
          "bound to", bindOk ? PASS : FAIL, bindOk ? "the VP key is the " +
          "credential's " + bound.member + "." : bound ?
          "the VP key is not the credential's " + bound.member + "." :
          "the credential names no holder key.");
  }
  var p = vp.payload;
  s.add("vp.nonce", "The VP JWT's nonce is this request's",
        p.nonce === ctx.session.nonce ? PASS : FAIL, "nonce is " +
        JSON.stringify(p.nonce) + (p.nonce === ctx.session.nonce ? "." :
        ", the request's was " + JSON.stringify(ctx.session.nonce) + "."));
  var audOk = audMatches(p.aud, ctx.session.clientId);
  s.add("vp.aud", "The VP JWT's aud is this Verifier's Client Identifier",
        audOk ? PASS : FAIL, "aud is " + JSON.stringify(p.aud) +
        (audOk ? "." : ", not " + ctx.session.clientId + "."));
  var fresh = freshness(p.iat, ctx.now);
  s.add("vp.iat", "The VP JWT is fresh", fresh.status, fresh.detail);

  var claimsRoot = {};
  for (var i = 0; i < vcs.length; i++) {
    var tag = vcs.length > 1 ? "vc[" + i + "]." : "vc.";
    var vc;
    try {
      vc = decodeJwt(vcs[i]);
    } catch (e) {
      s.add(tag + "signature", "The credential's issuer signature verifies",
            FAIL, "the embedded credential is unreadable: " + e.message);
      continue;
    }
    await checkIssuerSignature(s, tag + "signature", vcs[i], vc.header,
                               vc.payload, ctx.fetchJson,
                               "The credential's issuer signature verifies");
    var verdict = validityVerdict(sdJwtVc.validityWindowOf(
      { payload: vc.payload }), vc.payload.iat, ctx.now);
    s.add(tag + "validity", "The credential is within its validity window",
          verdict.status, verdict.detail);
    if (i === 0) {
      claimsRoot = Object.assign({}, vc.payload.vc || {});
      var typeValues = ((query.meta || {}).type_values) || [];
      var types = [].concat((vc.payload.vc || {}).type || []);
      s.add("types", "The credential's type is one the query asks for",
            typeValues.length ? (typesMatch(types, typeValues) ? PASS :
            FAIL) : SKIP, "type is [" + types.join(", ") + "]" +
            (typeValues.length ? "; asked for " +
             JSON.stringify(typeValues) + "." : "; the query names no " +
             "type_values."));
    }
  }
  checkRequestedClaims(s, query, function (c) {
    return pathPresent(claimsRoot, c);
  });
  log.debug("Leaving verifyJwtVcJson().");
  return claimsRoot.credentialSubject || claimsRoot;
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
      s.add("mdoc." + slug(c.name), c.name, c.ok ? PASS : FAIL, c.detail);
    });
  } catch (e) {
    s.add("mdoc.issuer-signed", "issuerSigned verifies", FAIL, e.message);
  }
  var encJwk = ctx.session.responseMode === "direct_post.jwt" &&
      ctx.session.decryptionJwk ? publicPart(ctx.session.decryptionJwk) :
      null;
  try {
    var ok = await mdoc.checkDeviceSignature(read, {
      clientId: ctx.session.clientId, nonce: ctx.session.nonce,
      responseUri: ctx.session.responseUri, encryptionJwk: encJwk });
    s.add("mdoc.device-signature", "The device signature covers this " +
          "request", ok ? PASS : FAIL, ok ? "deviceSignature verifies " +
          "with the MSO's device key over the OpenID4VPHandover transcript " +
          "(client_id, nonce, " + (encJwk ? "the encryption key's " +
          "thumbprint" : "no encryption key") + ", response_uri)." :
          "deviceSignature does NOT verify over this request's session " +
          "transcript: another Verifier, nonce, response_uri or " +
          "encryption key, or no device signature at all.");
  } catch (e) {
    s.add("mdoc.device-signature", "The device signature covers this " +
          "request", FAIL, e.message);
  }
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
  checkRequestedClaims(s, query, function (c) {
    return pathPresent(root, c);
  });
  log.debug("Leaving verifyMdoc().");
  return root;
}

// ---------------------------------------------------------------------------
// ldp_vc: a bbs-2023 derived-proof envelope, alone or inside a
// VerifiablePresentation carrying an ecdsa-jcs-2019 holder proof.
// ---------------------------------------------------------------------------
async function verifyEcdsaJcs2019(vp, fetchJson) {
  log.debug("Entering verifyEcdsaJcs2019().");
  var proof = vp.proof || {};
  var config = Object.assign({}, proof);
  delete config.proofValue;
  if (vp["@context"]) config["@context"] = vp["@context"];
  var doc = Object.assign({}, vp);
  delete doc.proof;
  var data = bytes.concatBytes(
    nobleSha256(bytes.strBytes(vpProtocols.jcs(config))),
    nobleSha256(bytes.strBytes(vpProtocols.jcs(doc))));
  var pv = String(proof.proofValue || "");
  if (pv.charAt(0) !== "z") {
    log.debug("Leaving verifyEcdsaJcs2019(). Not base58btc.");
    return { valid: false, reason: "proofValue is not multibase " +
             "base58btc (z)." };
  }
  var jwk = await keyForDidUrl(proof.verificationMethod, fetchJson);
  if (!jwk) {
    log.debug("Leaving verifyEcdsaJcs2019(). No key.");
    return { valid: false, reason: "verificationMethod " +
             proof.verificationMethod + " resolves to no key." };
  }
  var spec = jws.algSpec("ES256");
  var ok = jws.verifyOctets(spec, jws.jwkToKey(spec, jwk, false), data,
                            didLib.base58Decode(pv.slice(1)));
  log.debug("Leaving verifyEcdsaJcs2019(). " + ok);
  return { valid: !!ok, jwk: jwk };
}

function asObject(value) {
  log.debug("Entering asObject().");
  if (typeof value === "string") {
    log.debug("Leaving asObject(). Parsed.");
    return JSON.parse(value);
  }
  log.debug("Leaving asObject().");
  return value;
}

async function verifyBbsEnvelope(s, env, ctx) {
  log.debug("Entering verifyBbsEnvelope().");
  var label = "The bbs-2023 derived proof verifies";
  try {
    var options = env.proofOptions || {};
    var resolved = await didLib.resolveVerificationMethod(
      options.verificationMethod, { allowHttp: false,
        fetch: ctx.fetchJson ? fetchAdapter(ctx.fetchJson) : undefined });
    var multibase = (resolved.method || {}).publicKeyMultibase;
    if (!multibase) {
      throw new Error("the verification method publishes no " +
                      "publicKeyMultibase.");
    }
    var header = await bbs2023.headerFor(options);
    var ok = bbs2023.verifyDerived(bbs2023.multibaseToBytes(multibase),
      bytes.b64uToBytes(env.proof), header,
      bytes.strBytes(String(ctx.session.nonce || "")),
      env.disclosedStatements || [], env.disclosedIndexes || []);
    s.add("bbs.proof", label, ok ? PASS : FAIL, ok ? "the issuer's BBS " +
          "signature covers the " + (env.disclosedStatements || []).length +
          " disclosed statement(s), with this request's nonce as the " +
          "presentation header." : "the derived proof does NOT verify " +
          "(another nonce, altered statements, or another issuer key).");
  } catch (e) {
    s.add("bbs.proof", label, FAIL, e.message);
  }
  log.debug("Leaving verifyBbsEnvelope().");
}

// The IRI each term means, from the contexts the credential names — only the
// ones bbs2023.js ships or was given, never fetched. A term no context
// defines keeps its own name, matched as the last segment of a predicate.
async function termIris(contexts) {
  log.debug("Entering termIris().");
  var out = {};
  var list = [].concat(contexts || []);
  for (var i = 0; i < list.length; i++) {
    if (typeof list[i] !== "string") continue;
    var loaded;
    try {
      loaded = await bbs2023.documentLoader(list[i]);
    } catch (e) {
      log.debug("termIris(): " + list[i] + " not available: " + e.message);
      continue;
    }
    var defs = ((loaded || {}).document || {})["@context"] || {};
    Object.keys(defs).forEach(function (term) {
      var d = defs[term];
      var iri = typeof d === "string" ? d : d && d["@id"];
      if (typeof iri === "string" && /^[a-z][a-z0-9+.-]*:/i.test(iri)) {
        out[term] = iri;
      }
    });
  }
  log.debug("Leaving termIris(). " + Object.keys(out).length + " term(s).");
  return out;
}

function statementsHaveClaim(statements, claim, iris) {
  log.debug("Entering statementsHaveClaim().");
  var names = claim.path.filter(function (seg) {
    return typeof seg === "string" && seg !== "credentialSubject";
  });
  var name = names[names.length - 1];
  if (!name) {
    log.debug("Leaving statementsHaveClaim(). No name.");
    return false;
  }
  var iri = iris[name];
  log.debug("Leaving statementsHaveClaim().");
  return statements.some(function (st) {
    if (iri) return st.indexOf("<" + iri + ">") !== -1;
    return st.indexOf("#" + name + ">") !== -1 ||
      st.indexOf("/" + name + ">") !== -1;
  });
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
  var env = isVp ? asObject([].concat(doc.verifiableCredential || [])[0]) :
      doc;
  s.add("format", "The presentation is an ldp_vc", PASS, isVp ?
        "a VerifiablePresentation around one credential." :
        "a bare credential envelope, with no holder proof around it.");

  var holderJwk = null;
  if (isVp) {
    var proof = doc.proof || {};
    if (proof.cryptosuite !== "ecdsa-jcs-2019") {
      s.add("vp.proof", "The VP's holder proof verifies", SKIP,
            "cryptosuite " + JSON.stringify(proof.cryptosuite) + " is not " +
            "verified by this debugger yet (" + PR3 + ").");
    } else {
      try {
        var r = await verifyEcdsaJcs2019(doc, ctx.fetchJson);
        holderJwk = r.valid ? r.jwk : null;
        s.add("vp.proof", "The VP's holder proof verifies",
              r.valid ? PASS : FAIL, r.valid ? "ecdsa-jcs-2019 by " +
              proof.verificationMethod + " verifies." :
              "ecdsa-jcs-2019 does NOT verify" + (r.reason ? ": " +
              r.reason : "."));
      } catch (e) {
        s.add("vp.proof", "The VP's holder proof verifies", FAIL,
              e.message);
      }
    }
    s.add("vp.challenge", "The VP proof's challenge is this request's " +
          "nonce", proof.challenge === ctx.session.nonce ? PASS : FAIL,
          "challenge is " + JSON.stringify(proof.challenge) + ".");
    s.add("vp.domain", "The VP proof's domain is this Verifier's Client " +
          "Identifier", proof.domain === ctx.session.clientId ? PASS :
          FAIL, "domain is " + JSON.stringify(proof.domain) + ".");
  } else {
    s.add("vp.proof", "The VP's holder proof verifies",
          requiresBinding(query) ? FAIL : SKIP, requiresBinding(query) ?
          "the query requires holder binding and a bbs-2023 derived proof " +
          "alone does not prove who presented it." :
          "the query does not require holder binding.");
  }

  var statements = [];
  var iris = {};
  if (env && env.cryptosuite === "bbs-2023") {
    iris = await termIris((env.proofOptions || {})["@context"]);
    statements = env.disclosedStatements || [];
    await verifyBbsEnvelope(s, env, ctx);
    if (isVp) {
      var holder = String(doc.holder || "");
      var named = holder && statements.some(function (st) {
        return st.indexOf("<" + holder + ">") !== -1;
      });
      s.add("vp.binding", "The holder is the credential's subject",
            named && holderJwk ? PASS : FAIL, named ?
            (holderJwk ? holder + " is a subject of the disclosed " +
             "statements and signed the VP." : "the VP proof did not " +
             "verify.") : "no disclosed statement names the holder " +
            JSON.stringify(holder) + ".");
    }
  } else {
    var suite = env && env.proof ? env.proof.cryptosuite : env &&
        env.cryptosuite;
    s.add("bbs.proof", "The credential's proof verifies", SKIP,
          "cryptosuite " + JSON.stringify(suite) + " is not verified by " +
          "this debugger yet (" + PR3 + ").");
  }
  checkRequestedClaims(s, query, function (c) {
    return statementsHaveClaim(statements, c, iris);
  });
  log.debug("Leaving verifyLdpVc().");
  return { statements: statements };
}

// ---------------------------------------------------------------------------
// The whole response.
// ---------------------------------------------------------------------------
async function openResponse(report, parsed, session) {
  log.debug("Entering openResponse().");
  var g = "response";
  var jwtMode = session.responseMode === "direct_post.jwt";
  if (jwtMode && !parsed.response) {
    addCheck(report, "response.mode", g, "The answer arrived the way the " +
             "request asked", FAIL, "the request asked for direct_post.jwt " +
             "and a plain form arrived (no `response` field): the answer " +
             "was not encrypted.");
    log.debug("Leaving openResponse(). Plain under jwt.");
    return null;
  }
  if (!jwtMode && parsed.response) {
    addCheck(report, "response.mode", g, "The answer arrived the way the " +
             "request asked", FAIL, "the request asked for direct_post " +
             "and an encrypted `response` arrived.");
    log.debug("Leaving openResponse(). Encrypted under plain.");
    return null;
  }
  addCheck(report, "response.mode", g, "The answer arrived the way the " +
           "request asked", PASS, jwtMode ? "one `response` field, as " +
           "direct_post.jwt requires." : "form fields, as direct_post " +
           "sends them.");
  if (!jwtMode) {
    log.debug("Leaving openResponse(). Plain.");
    return parsed;
  }
  try {
    var opened = await joseJwe.decryptCompact({ jwe: parsed.response,
      key: session.decryptionJwk });
    var inner = JSON.parse(opened.plaintext);
    var kid = (opened.header || {}).kid;
    addCheck(report, "response.decrypt", g, "The encrypted answer opens " +
             "with this Verifier's key", PASS, "alg " + opened.header.alg +
             ", enc " + opened.header.enc + (kid ? ", kid " + kid : "") +
             ".");
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
      try {
        claims = await verify(s, query, list[i], ctx);
      } catch (e) {
        s.add("error", "The presentation could be checked", FAIL,
              e.message);
      }
      out.push({ queryId: query.id, format: query.format, claims: claims });
    }
  }
  log.debug("Leaving verifyPresentations(). " + out.length +
            " presentation(s).");
  return out;
}

function finish(report, presentations) {
  log.debug("Entering finish().");
  var failed = report.checks.filter(function (c) {
    return c.status === FAIL;
  }).length;
  log.debug("Leaving finish(). " + report.checks.length + " check(s), " +
            failed + " failed.");
  return { ok: failed === 0 && report.checks.length > 0,
           checks: report.checks, presentations: presentations || [] };
}

async function verifyResponse(opts) {
  log.debug("Entering verifyResponse().");
  var o = opts || {};
  var session = o.session || {};
  var report = { checks: [] };
  var g = "response";
  var outer = parseResponse(o.fields);
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
  if (session.state === undefined || session.state === null ||
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
  var ctx = { session: session, fetchJson: o.fetchJson,
              now: nowSeconds(o.now) };
  var presentations = await verifyPresentations(report, vpToken, ctx);
  addCheck(report, "status", "status", "Credential status (revocation)",
           SKIP, "status lists are checked in " + PR3 + ".");
  if (parsed.idToken) {
    addCheck(report, "id_token", g, "The self-issued ID Token verifies",
             SKIP, "SIOPv2 ID Tokens are checked in " + PR3 + ".");
  }
  log.debug("Leaving verifyResponse().");
  return finish(report, presentations);
}

module.exports = {
  FORMATS: FORMATS,
  REQUEST_AUD: REQUEST_AUD,
  SKEW_SECONDS: SKEW_SECONDS,
  MAX_AGE_SECONDS: MAX_AGE_SECONDS,
  randomToken: randomToken,
  buildDcql: buildDcql,
  makeVerifierIdentity: makeVerifierIdentity,
  clientIdFor: clientIdFor,
  responseEncryptionKey: responseEncryptionKey,
  vpFormatsSupported: vpFormatsSupported,
  requestObjectClaims: requestObjectClaims,
  signRequestObject: signRequestObject,
  authorizationRequestUri: authorizationRequestUri,
  parseResponse: parseResponse,
  verifyResponse: verifyResponse,
  jwkThumbprint: jwkThumbprint,
  jwtVcIssuerUrl: jwtVcIssuerUrl
};
