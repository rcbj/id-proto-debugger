// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vp_protocols.js
//
// ---------------------------------------------------------------------------
// The PROTOCOL a VC presentation is answered under, chosen on step 0.
//
//   oid4vp   OpenID4VP 1.0 as the workflow always spoke it: any Client
//            Identifier prefix it can read, a request by value or by
//            reference, a vp_token sent in the clear by direct_post.
//   haip     OpenID4VP 1.0 under OpenID4VC HAIP 1.0 (final, December 2025).
//            Not another protocol: a PROFILE that takes the options away. The
//            request is a signed Request Object fetched by request_uri, its
//            Client Identifier is x509_hash (the Verifier is named by the
//            SHA-256 of its own certificate, carried in x5c), and the answer
//            is ENCRYPTED — direct_post.jwt, a JWE to a key the request
//            carries. A plaintext answer to such a request is the one thing
//            the profile exists to rule out.
//   siopv2   Self-Issued OpenID Provider v2: the wallet answers with an ID
//            Token it signs itself, iss equal to sub. Alone
//            (response_type=id_token) that authenticates a person who
//            controls a key and says nothing anybody else vouched for; with a
//            presentation (response_type="vp_token id_token") the ID Token is
//            signed by the SAME key the credential is bound to, which is what
//            ties the self-issued identity to the issued one.
//
// HAIP and SIOPv2 are not alternatives to each other — HAIP profiles a
// credential presentation, SIOPv2 is an authentication protocol that can carry
// one — and the choice is made once because each changes what the wallet must
// REFUSE, not merely what it shows.
//
// HAIP 1.0 profiles two credential formats, SD-JWT VC and ISO mdoc, and
// this wallet presents both (mdoc.js). It also presents jwt_vc_json and
// ldp_vc under the HAIP transport (the
// signed x509_hash request and the encrypted response), and says so on every
// page that does it: what HAIP constrains about the TRANSPORT applies to any
// format, and what it constrains about the FORMAT is reported as a departure
// rather than silently waived.
//
// No DOM: tests/vp_protocols_engine.js drives all of it in node.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vp_protocols",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var bytes = require("./crypto_bytes");
var jws = require("./jws");
var joseJwe = require("./jose_jwe");
var jweKem = require("./jwe_kem");
var dpop = require("./dpop");
var metadataClient = require("./metadata_client");
var didLib = require("./did");

var KEYS = {
  // Which protocol the presentation is answered under (see PROTOCOLS).
  PROTOCOL: "sdjwtvp_protocol",
  // The SIOPv2 subject syntax the holder chose (see SUBJECT_SYNTAXES).
  SUBJECT_SYNTAX: "sdjwtvp_siop_subject_syntax",
  // A PEM trust anchor for x509_hash / x509_san_dns requests. Optional: with
  // none, the chain is checked link by link and its root reported as
  // untrusted rather than trusted.
  X509_TRUST_ANCHOR: "sdjwtvp_x509_trust_anchor"
};

var PROTOCOL_OID4VP = "oid4vp";
var PROTOCOL_HAIP = "haip";
var PROTOCOL_SIOPV2 = "siopv2";

var PROTOCOLS = [
  {
    id: PROTOCOL_OID4VP,
    label: "OpenID4VP 1.0",
    title: "A presentation, as OpenID4VP allows it",
    summary: "Any Client Identifier this wallet can read, a request by value " +
        "or by reference, and the vp_token posted in the clear " +
        "(direct_post).",
    spec: "https://openid.net/specs/openid-4-verifiable-presentations-" +
        "1_0.html",
    responseTypes: ["vp_token"]
  },
  {
    id: PROTOCOL_HAIP,
    label: "OpenID4VC HAIP 1.0",
    title: "A presentation under the High Assurance Interoperability Profile",
    summary: "A signed Request Object fetched by request_uri, an x509_hash " +
        "Client Identifier checked against the Verifier's own certificate, " +
        "and an ENCRYPTED answer (direct_post.jwt). Anything less is " +
        "refused before a claim is shown.",
    spec: "https://openid.net/specs/openid4vc-high-assurance-" +
        "interoperability-profile-1_0.html",
    responseTypes: ["vp_token"]
  },
  {
    id: PROTOCOL_SIOPV2,
    label: "SIOPv2",
    title: "A self-issued ID Token, with or without a presentation",
    summary: "The wallet is its own OpenID Provider: it signs an ID Token " +
        "whose iss is its sub. With response_type \"vp_token id_token\" the " +
        "token is signed by the key the credential is bound to.",
    spec: "https://openid.net/specs/openid-connect-self-issued-v2-1_0.html",
    responseTypes: ["id_token", "vp_token id_token"]
  }
];

var DEFAULT_PROTOCOL = PROTOCOL_OID4VP;

// HAIP 1.0's own formats. Anything else presented under HAIP is reported.
var HAIP_FORMATS = ["dc+sd-jwt", "mso_mdoc"];

// The JWE algorithms this wallet encrypts a direct_post.jwt answer with.
// HAIP 1.0 section 5 names ECDH-ES on P-256 with A128GCM and A256GCM, and
// under HAIP that is all it uses (HAIP_RESPONSE_JWE_ALGS). OpenID4VP 1.0
// itself names no algorithm: the Verifier's key says which, so outside HAIP
// this wallet also encrypts to an ML-KEM or HPKE key — X-Wing (HPKE-10-KE)
// among them — through jose_jwe.js (#312). The CBC-HMAC encs are accepted
// because OpenID4VP allows any registered enc and jose_jwe.js does them.
var HAIP_RESPONSE_JWE_ALGS = ["ECDH-ES"];
var RESPONSE_JWE_ALGS = ["ECDH-ES"].concat(joseJwe.supportedAlgs()
  .filter(function (a) {
    return joseJwe.isKemAlg(a);
  }));
var RESPONSE_JWE_ENCS = ["A128GCM", "A256GCM", "A128CBC-HS256",
                         "A256CBC-HS512"];
// OpenID4VP 1.0 section 8.3: when the Verifier says nothing, A128GCM.
var DEFAULT_RESPONSE_ENC = "A128GCM";

// SIOPv2 section 8: the subject syntax types. A JWK Thumbprint subject is the
// thumbprint and travels with the public key in sub_jwk; a did:jwk subject is
// the key itself, and names its verification method in the header's kid.
var SUBJECT_JWK_THUMBPRINT = "urn:ietf:params:oauth:jwk-thumbprint";
var SUBJECT_DID_JWK = "did:jwk";
var SUBJECT_DID_KEY_METHOD = "did:key";
var SUBJECT_SYNTAXES = [SUBJECT_JWK_THUMBPRINT, SUBJECT_DID_JWK,
                        SUBJECT_DID_KEY_METHOD];

// How long a self-issued ID Token lives. Short, because nothing but the
// Verifier's own clock checks it and the nonce already makes it single-use.
var ID_TOKEN_LIFETIME_S = 300;

function protocols() {
  log.debug("Entering protocols().");
  log.debug("Leaving protocols().");
  return PROTOCOLS;
}

function protocolById(id) {
  log.debug("Entering protocolById(). id=" + id);
  for (var i = 0; i < PROTOCOLS.length; i++) {
    if (PROTOCOLS[i].id === id) {
      log.debug("Leaving protocolById().");
      return PROTOCOLS[i];
    }
  }
  log.debug("Leaving protocolById(). Unknown.");
  return null;
}

// ---------------------------------------------------------------------------
// A tiny DER reader: enough to find a certificate's SubjectPublicKeyInfo and
// its subjectAltName dNSNames. x509.js has a full one (pkijs), but it is a
// third of a megabyte the presentation pages do not otherwise need, and the
// two facts wanted here are positional.
// ---------------------------------------------------------------------------
function derTlv(der, offset) {
  log.debug("Entering derTlv().");
  var tag = der[offset];
  var len = der[offset + 1];
  var header = 2;
  if (len & 0x80) {
    var n = len & 0x7f;
    if (n === 0 || n > 4) {
      log.debug("Leaving derTlv(). Bad length.");
      throw new Error("not DER: an indefinite or oversized length at " +
                      "offset " + offset + ".");
    }
    len = 0;
    for (var i = 0; i < n; i++) {
      len = (len * 256) + der[offset + 2 + i];
    }
    header = 2 + n;
  }
  if (offset + header + len > der.length) {
    log.debug("Leaving derTlv(). Truncated.");
    throw new Error("not DER: a value runs past the end at offset " + offset +
                    ".");
  }
  log.debug("Leaving derTlv().");
  return { tag: tag, start: offset, valueStart: offset + header,
           end: offset + header + len };
}

function derChildren(der, tlv) {
  log.debug("Entering derChildren().");
  var out = [];
  var at = tlv.valueStart;
  while (at < tlv.end) {
    var child = derTlv(der, at);
    out.push(child);
    at = child.end;
  }
  log.debug("Leaving derChildren(). " + out.length + " child(ren).");
  return out;
}

// The parts of a certificate this module reads: the SPKI's DER and the
// dNSNames of its subjectAltName.
function certificateParts(derInput) {
  log.debug("Entering certificateParts().");
  var der = bytes.asBytes(derInput);
  var cert = derTlv(der, 0);
  var tbs = derChildren(der, cert)[0];
  var fields = derChildren(der, tbs);
  // [0] version is optional; with it the SPKI is the seventh field.
  var i = fields[0].tag === 0xa0 ? 1 : 0;
  var spki = fields[i + 5];
  var dnsNames = [];
  fields.forEach(function (f) {
    if (f.tag !== 0xa3) return;
    var exts = derChildren(der, derChildren(der, f)[0]);
    exts.forEach(function (ext) {
      var parts = derChildren(der, ext);
      var oid = bytes.bytesToHex(der.slice(parts[0].valueStart,
                                           parts[0].end));
      // 2.5.29.17 subjectAltName
      if (oid !== "551d11") return;
      var octets = parts[parts.length - 1];
      var names = derTlv(der, octets.valueStart);
      derChildren(der, names).forEach(function (gn) {
        if (gn.tag === 0x82) {
          dnsNames.push(bytes.bytesToStr(der.slice(gn.valueStart, gn.end)));
        }
      });
    });
  });
  log.debug("Leaving certificateParts(). " + dnsNames.length +
            " dNSName(s).");
  return { spkiDer: der.slice(spki.start, spki.end), dnsNames: dnsNames };
}

// The x509_hash Client Identifier value: base64url of the SHA-256 of the
// leaf certificate's DER (OpenID4VP 1.0 section 5.9.3).
function x509Hash(derInput) {
  log.debug("Entering x509Hash().");
  var der = bytes.asBytes(derInput);
  log.debug("Leaving x509Hash().");
  return crypto.subtle.digest("SHA-256", der).then(function (d) {
    return bytes.bytesToB64u(new Uint8Array(d));
  });
}

// The leaf certificate's public key as a JWK, for verifying the Request
// Object with the key the Client Identifier names.
function certificatePublicJwk(derInput, alg) {
  log.debug("Entering certificatePublicJwk(). alg=" + alg);
  var spki = certificateParts(derInput).spkiDer;
  var params = /^ES256$/.test(alg) ?
      { name: "ECDSA", namedCurve: "P-256" }
    : /^ES384$/.test(alg) ? { name: "ECDSA", namedCurve: "P-384" }
    : /^ES512$/.test(alg) ? { name: "ECDSA", namedCurve: "P-521" }
    : /^PS/.test(alg) ? { name: "RSA-PSS", hash: "SHA-" + alg.slice(2) }
    : /^RS/.test(alg) ? { name: "RSASSA-PKCS1-v1_5",
                          hash: "SHA-" + alg.slice(2) }
    : null;
  if (!params) {
    log.debug("Leaving certificatePublicJwk(). Unsupported alg.");
    return Promise.reject(new Error("this wallet cannot verify a Request " +
        "Object signed with " + alg + " against a certificate."));
  }
  log.debug("Leaving certificatePublicJwk().");
  return crypto.subtle.importKey("spki", spki, params, true, ["verify"])
    .then(function (key) {
      return crypto.subtle.exportKey("jwk", key);
    })
    .then(function (jwk) {
      delete jwk.key_ops;
      delete jwk.ext;
      return jwk;
    });
}

// ---------------------------------------------------------------------------
// The request's shape, read the same way by every check below.
// ---------------------------------------------------------------------------
function responseTypes(params) {
  log.debug("Entering responseTypes().");
  var types = String((params && params.response_type) || "").trim()
    .split(/\s+/).filter(function (t) { return t; });
  log.debug("Leaving responseTypes(). " + types.join(" "));
  return types;
}

function asksForIdToken(params) {
  log.debug("Entering asksForIdToken().");
  log.debug("Leaving asksForIdToken().");
  return responseTypes(params).indexOf("id_token") !== -1;
}

function asksForVpToken(params) {
  log.debug("Entering asksForVpToken().");
  log.debug("Leaving asksForVpToken().");
  return responseTypes(params).indexOf("vp_token") !== -1;
}

// The prefix of a Client Identifier (OpenID4VP 1.0 section 5.9), "" when it
// has none, which is the pre-registered case.
var CLIENT_ID_PREFIXES = ["redirect_uri", "x509_san_dns", "x509_hash",
  "decentralized_identifier", "verifier_attestation", "openid_federation",
  "origin", "pre-registered"];

function clientIdPrefix(clientId) {
  log.debug("Entering clientIdPrefix().");
  var id = String(clientId || "");
  var colon = id.indexOf(":");
  var prefix = colon > 0 ? id.slice(0, colon) : "";
  if (CLIENT_ID_PREFIXES.indexOf(prefix) === -1) {
    log.debug("Leaving clientIdPrefix(). None.");
    return { prefix: "", value: id };
  }
  log.debug("Leaving clientIdPrefix(). " + prefix);
  return { prefix: prefix, value: id.slice(colon + 1) };
}

// The response mode, with the default each response type implies: OAuth 2.0
// Multiple Response Types makes `fragment` the default for any response type
// that returns a token.
function responseMode(params) {
  log.debug("Entering responseMode().");
  var mode = String((params && params.response_mode) || "").trim();
  log.debug("Leaving responseMode(). " + (mode || "fragment (default)"));
  return mode || "fragment";
}

// Where the answer goes. direct_post and direct_post.jwt name a
// response_uri; every other mode returns to the redirect_uri.
function responseTarget(params) {
  log.debug("Entering responseTarget().");
  var mode = responseMode(params);
  var target = (mode === "direct_post" || mode === "direct_post.jwt") ?
      (params.response_uri || "") : (params.redirect_uri || "");
  log.debug("Leaving responseTarget(). " + target);
  return target;
}

// ---------------------------------------------------------------------------
// The x509 Client Identifiers (OpenID4VP 1.0 sections 5.9.3).
//
// x509_hash names the Verifier by the SHA-256 of its leaf certificate, and
// x509_san_dns by a DNS name in that certificate's subjectAltName. Both carry
// the chain in the Request Object's x5c header, leaf first; neither proves
// anything until the chain reaches an anchor the WALLET trusts, which is why
// the anchor is configured here and an unanchored chain is reported as
// exactly that rather than as valid.
//
// `verifyChain` is injected (x509.js's verifyChain()), so this module does
// not carry pkijs into every page that only builds a response.
// ---------------------------------------------------------------------------
function verifyX509Request(opts) {
  log.debug("Entering verifyX509Request().");
  var compact = String(opts.compact || "");
  var parts = compact.split(".");
  var header = JSON.parse(bytes.b64uToStr(parts[0]));
  var who = clientIdPrefix(opts.clientId);
  var out = { prefix: who.prefix, header: header, x5c: header.x5c || [],
              checks: [] };
  function check(name, ok, detail) {
    out.checks.push({ name: name, ok: ok, detail: detail });
  }
  if (!out.x5c.length) {
    check("x5c", false, "the Request Object carries no x5c header, so " +
          "there is no certificate for the Client Identifier to name.");
    log.debug("Leaving verifyX509Request(). No x5c.");
    return Promise.resolve(out);
  }
  check("x5c", true, out.x5c.length + " certificate(s), leaf first.");
  var leafDer = bytes.b64ToBytes(out.x5c[0]);
  var pems = out.x5c.map(function (b64) {
    return bytes.derToPem(bytes.b64ToBytes(b64), "CERTIFICATE");
  });
  log.debug("Leaving verifyX509Request().");
  return x509Hash(leafDer).then(function (hash) {
    out.leafHash = hash;
    if (who.prefix === "x509_hash") {
      check("x509_hash", hash === who.value, hash === who.value ?
            "the SHA-256 of the leaf certificate is the Client Identifier." :
            "the leaf certificate hashes to " + hash + ", not to " +
            who.value + " — this request was signed by somebody else.");
    }
    if (who.prefix === "x509_san_dns") {
      var names = certificateParts(leafDer).dnsNames;
      out.dnsNames = names;
      check("x509_san_dns", names.indexOf(who.value) !== -1,
            names.indexOf(who.value) !== -1 ?
            who.value + " is a dNSName in the leaf certificate." :
            "the leaf certificate names " + (names.join(", ") || "no DNS " +
            "name") + ", not " + who.value + ".");
      var target = opts.responseTarget || "";
      var host = "";
      try {
        host = new URL(target).hostname;
      } catch (e) {
        host = "";
      }
      check("response host", host === who.value, host === who.value ?
            "the answer goes to " + host + ", the name the certificate " +
            "certifies." :
            "the answer would go to " + (host || "(nowhere)") + ", which " +
            "is not " + who.value + " (section 5.9.3).");
    }
    return certificatePublicJwk(leafDer, header.alg);
  }).then(function (jwk) {
    out.leafJwk = jwk;
    return metadataClient.verifyJwsWithJwks(compact, { keys: [jwk] },
                                            "the Request Object")
      .catch(function (e) {
        return { valid: false, error: e.message };
      });
  }).then(function (v) {
    var valid = !!(v && v.valid);
    check("signature", valid, valid ?
          "the Request Object verifies with the leaf certificate's key." :
          "the Request Object does NOT verify with the leaf certificate's " +
          "key" + (v && v.error ? ": " + v.error : "."));
    if (!opts.verifyChain) {
      return null;
    }
    var chain = pems.slice();
    if (opts.trustAnchorPem) chain.push(opts.trustAnchorPem);
    return opts.verifyChain(chain);
  }).then(function (links) {
    out.chain = links || [];
    if (!links) {
      return out;
    }
    var broken = links.filter(function (l, i) {
      var last = i === links.length - 1;
      return !l.signatureValid || !l.namesMatch || l.expired ||
             l.notYetValid || (last && !l.selfSigned);
    });
    // The last link is self-signed only when it is a root; a chain ending at
    // an intermediate cannot be finished without an anchor.
    if (!opts.trustAnchorPem) {
      check("trust anchor", false, "no trust anchor is configured, so the " +
            "chain was checked link by link and its top is UNTRUSTED. " +
            "Set one on step 0 to know who this Verifier is.");
    } else {
      check("trust anchor", broken.length === 0, broken.length === 0 ?
            "the chain verifies up to the configured trust anchor." :
            broken.length + " link(s) of the chain do not verify up to the " +
            "configured trust anchor.");
    }
    log.debug("Leaving verifyX509Request(). " + out.checks.length +
              " check(s).");
    return out;
  });
}

// ---------------------------------------------------------------------------
// What each protocol demands of a request, as a list of rules.
//
// A rule is { id, ok, level, text }: level "block" stops the wallet
// answering, "warn" is shown and does not, "info" says what was seen. HAIP's
// rules are blocking because the profile's whole point is that the wallet
// does not negotiate them; a departure that is about the FORMAT rather than
// the transport is a warning, for the reason the header gives.
//
// `ctx`: { request (step 1's record), heldFormat, x509 (verifyX509Request's
// result, or null), subjectSyntax }.
// ---------------------------------------------------------------------------
function rule(id, ok, level, text) {
  log.debug("Entering rule(). " + id + "=" + ok);
  log.debug("Leaving rule().");
  return { id: id, ok: !!ok, level: ok ? "info" : level, text: text };
}

function x509Ok(x509, name) {
  log.debug("Entering x509Ok(). " + name);
  var found = ((x509 && x509.checks) || []).filter(function (c) {
    return c.name === name;
  })[0];
  log.debug("Leaving x509Ok().");
  return found ? found.ok : false;
}

// The JWE alg a Verifier key is used with: the key's own `alg`, or ECDH-ES
// for an EC P-256 key that names none (OpenID4VP 1.0 section 8.3 leaves the
// choice to the key, and HAIP's ECDH-ES P-256 key is the one commonly
// published without one). "" when this wallet cannot use the key.
function responseAlgFor(key) {
  log.debug("Entering responseAlgFor().");
  if (!key || (key.use && key.use !== "enc")) {
    log.debug("Leaving responseAlgFor(). Not an encryption key.");
    return "";
  }
  var isP256 = key.kty === "EC" && key.crv === "P-256";
  if (!key.alg || key.alg === "ECDH-ES") {
    log.debug("Leaving responseAlgFor(). ECDH-ES.");
    return isP256 ? "ECDH-ES" : "";
  }
  if (RESPONSE_JWE_ALGS.indexOf(key.alg) === -1) {
    log.debug("Leaving responseAlgFor(). Not an alg this wallet does.");
    return "";
  }
  try {
    kemKeyCheck(key);
  } catch (e) {
    log.debug("Leaving responseAlgFor(). Unusable " + key.alg + " key: " +
              e.message);
    return "";
  }
  log.debug("Leaving responseAlgFor(). " + key.alg);
  return key.alg;
}

// A KEM key is usable when jose_jwe.js could encrypt to it: the right kty
// and curve for its alg, and a public key of the right length.
function kemKeyCheck(key) {
  log.debug("Entering kemKeyCheck().");
  joseJwe.describeKemAlg(key.alg);
  jweKem.readKey(key.alg, key, false);
  log.debug("Leaving kemKeyCheck().");
}

// The Verifier keys this wallet can encrypt to, IN THE VERIFIER'S ORDER: the
// first is the one used, so a Verifier that lists an X-Wing key before its
// ECDH-ES one gets the post-quantum answer from a wallet that can make it.
//   opts.protocol         HAIP restricts the answer to ECDH-ES on P-256.
//   opts.needsThumbprint  an mso_mdoc presentation's session transcript
//                         carries the RFC 7638 thumbprint of the key, and
//                         an AKP key has no registered thumbprint members,
//                         so such a key is passed over.
function encryptionKeys(clientMetadata, opts) {
  log.debug("Entering encryptionKeys().");
  var o = opts || {};
  var keys = ((clientMetadata && clientMetadata.jwks) || {}).keys || [];
  var usable = keys.filter(function (k) {
    var alg = responseAlgFor(k);
    if (!alg) return false;
    if (o.protocol === PROTOCOL_HAIP &&
        HAIP_RESPONSE_JWE_ALGS.indexOf(alg) === -1) {
      return false;
    }
    if (o.needsThumbprint && k.kty === "AKP") return false;
    return true;
  });
  log.debug("Leaving encryptionKeys(). " + usable.length + " of " +
            keys.length + ".");
  return usable;
}

function encValues(clientMetadata) {
  log.debug("Entering encValues().");
  var listed = (clientMetadata &&
                clientMetadata.encrypted_response_enc_values_supported) ||
               [DEFAULT_RESPONSE_ENC];
  log.debug("Leaving encValues().");
  return [].concat(listed).filter(function (e) {
    return RESPONSE_JWE_ENCS.indexOf(e) !== -1;
  });
}

function oid4vpRules(params, ctx, out) {
  log.debug("Entering oid4vpRules().");
  var request = ctx.request || {};
  var who = clientIdPrefix(params.client_id);
  var mode = responseMode(params);
  out.push(rule("nonce", !!params.nonce, "block", params.nonce ?
    "nonce present: the answer is bound to this request." :
    "no nonce — nothing would stop the answer being replayed."));
  if (asksForVpToken(params)) {
    out.push(rule("dcql_query", !!request.dcql, "block", request.dcql ?
      "a DCQL query says what is wanted." :
      "no dcql_query, so the request does not say what it wants."));
  }
  if (who.prefix === "redirect_uri") {
    out.push(rule("redirect_uri prefix", !request.signed, "block",
      !request.signed ? "unsigned, as the redirect_uri prefix requires." :
      "a redirect_uri Client Identifier cannot sign (section 5.9.3), yet " +
      "this request is signed."));
    out.push(rule("redirect_uri target", responseTarget(params) === who.value,
      "block", responseTarget(params) === who.value ?
      "the answer goes to " + who.value + ", the Client Identifier itself." :
      "the answer would go to " + (responseTarget(params) || "(nowhere)") +
      " and not to " + who.value + ", the URL the Client Identifier names."));
  }
  if (who.prefix === "x509_hash" || who.prefix === "x509_san_dns") {
    out.push(rule(who.prefix + " signed", !!request.signed, "block",
      request.signed ? "signed, as an x509 Client Identifier requires." :
      "an x509 Client Identifier needs a signed Request Object."));
    if (request.signed) {
      out.push(rule(who.prefix, x509Ok(ctx.x509, who.prefix), "block",
        "the Client Identifier names the leaf certificate in x5c."));
      out.push(rule("request signature", x509Ok(ctx.x509, "signature"),
        "block", "the Request Object is signed by that certificate's key."));
      if (who.prefix === "x509_san_dns") {
        out.push(rule("response host", x509Ok(ctx.x509, "response host"),
          "block", "the answer goes to the certified DNS name."));
      }
      out.push(rule("trust anchor", x509Ok(ctx.x509, "trust anchor"),
        "warn", "the certificate chain reaches a trust anchor configured " +
        "in this wallet."));
    }
  }
  if (request.signed) {
    var payload = request.requestObjectPayload || {};
    var header = request.requestObjectHeader || {};
    out.push(rule("typ", header.typ === "oauth-authz-req+jwt", "warn",
      "the Request Object's typ is oauth-authz-req+jwt (RFC 9101 " +
      "section 10.8); it is " + (header.typ || "absent") + "."));
    if (request.outerClientId) {
      out.push(rule("client_id match", payload.client_id ===
        request.outerClientId, "block", "the client_id inside the signed " +
        "request (" + payload.client_id + ") is the one the wallet was " +
        "handed (" + request.outerClientId + ")."));
    }
    if (request.walletNonce) {
      out.push(rule("wallet_nonce", payload.wallet_nonce ===
        request.walletNonce, "block", "the Request Object echoes the " +
        "wallet_nonce this wallet POSTed to the request_uri."));
    }
  }
  var known = ["direct_post", "direct_post.jwt", "fragment", "query",
               "form_post", "post"];
  out.push(rule("response_mode", known.indexOf(mode) !== -1, "block",
    "response_mode " + mode + (known.indexOf(mode) !== -1 ?
    " — this wallet can deliver it." : " is not one this wallet can " +
    "deliver.")));
  if (mode === "direct_post" || mode === "direct_post.jwt") {
    out.push(rule("response_uri", !!params.response_uri, "block",
      params.response_uri ? "the answer is POSTed to " + params.response_uri +
      "." : mode + " needs a response_uri to post to."));
  } else {
    out.push(rule("redirect_uri", !!params.redirect_uri, "block",
      params.redirect_uri ? "the answer returns to " + params.redirect_uri +
      "." : mode + " needs a redirect_uri to return to."));
  }
  if (mode === "direct_post.jwt") {
    var keys = encryptionKeys(request.clientMetadata, {
      protocol: ctx.protocol,
      needsThumbprint: (ctx.requestedFormat || ctx.heldFormat) === "mso_mdoc"
    });
    out.push(rule("encryption key", keys.length > 0, "block",
      keys.length ? keys.length + " key(s) in client_metadata.jwks this " +
      "wallet can encrypt to; the answer goes to the first, " +
      (keys[0].kid || "(no kid)") + ", with " + responseAlgFor(keys[0]) +
      "." : "direct_post.jwt, but client_metadata.jwks has no key this " +
      "wallet can encrypt to (" + (ctx.protocol === PROTOCOL_HAIP ?
      "HAIP: an ECDH-ES P-256 key" : "an ECDH-ES P-256, ML-KEM or HPKE " +
      "key") + ")."));
    var encs = encValues(request.clientMetadata);
    out.push(rule("enc", encs.length > 0, "block", encs.length ?
      "content encryption " + encs.join(", ") + " offered." :
      "none of the offered encrypted_response_enc_values_supported is one " +
      "this wallet does."));
  }
  log.debug("Leaving oid4vpRules().");
}

function haipRules(params, ctx, out) {
  log.debug("Entering haipRules().");
  var request = ctx.request || {};
  var who = clientIdPrefix(params.client_id);
  out.push(rule("HAIP: request_uri", /request_uri/.test(request.source ||
    "") || !!request.requestObject, "block", "HAIP 1.0 has the request " +
    "passed by reference (request_uri) as a signed Request Object."));
  out.push(rule("HAIP: signed", !!request.signed, "block",
    "HAIP 1.0 requires a signed request (JAR)."));
  out.push(rule("HAIP: x509_hash", who.prefix === "x509_hash", "block",
    "HAIP 1.0 has the Verifier named by an x509_hash Client Identifier; " +
    "this one is " + (who.prefix || "pre-registered") + "."));
  var alg = (request.requestObjectHeader || {}).alg;
  out.push(rule("HAIP: ES256", !request.signed || alg === "ES256", "warn",
    "HAIP 1.0 makes ES256 the algorithm every party supports; this " +
    "request is signed with " + (alg || "nothing") + "."));
  out.push(rule("HAIP: direct_post.jwt", responseMode(params) ===
    "direct_post.jwt", "block", "HAIP 1.0 requires the answer ENCRYPTED " +
    "(direct_post.jwt); this request asks for " + responseMode(params) +
    "."));
  out.push(rule("HAIP: vp_token", responseTypes(params).join(" ") ===
    "vp_token", "block", "HAIP 1.0 profiles a credential presentation " +
    "(response_type vp_token)."));
  var format = ctx.requestedFormat || ctx.heldFormat || "";
  out.push(rule("HAIP: format", !format ||
    HAIP_FORMATS.indexOf(format) !== -1, "warn", "HAIP 1.0 profiles " +
    HAIP_FORMATS.join(" and ") + "; " + format + " is presented under the " +
    "HAIP transport as a departure from the profile."));
  log.debug("Leaving haipRules().");
}

function siopRules(params, ctx, out) {
  log.debug("Entering siopRules().");
  var request = ctx.request || {};
  var scopes = String(params.scope || "").split(/\s+/);
  out.push(rule("SIOPv2: id_token", asksForIdToken(params), "block",
    "SIOPv2 answers with an ID Token: response_type id_token, or " +
    "\"vp_token id_token\" with a presentation. This request asks for " +
    (params.response_type || "nothing") + "."));
  out.push(rule("SIOPv2: scope openid", scopes.indexOf("openid") !== -1,
    "block", "an OpenID Connect request carries scope openid."));
  var offered = subjectSyntaxesOffered(request.clientMetadata);
  var usable = offered.filter(function (s) {
    return SUBJECT_SYNTAXES.indexOf(s) !== -1;
  });
  out.push(rule("SIOPv2: subject syntax", usable.length > 0, "block",
    usable.length ? "subject syntax types both sides speak: " +
    usable.join(", ") + "." : "the Verifier accepts " + offered.join(", ") +
    " and this wallet makes " + SUBJECT_SYNTAXES.join(", ") +
    " — the answer is subject_syntax_types_not_supported."));
  log.debug("Leaving siopRules().");
}

function requestRules(protocolId, ctx) {
  log.debug("Entering requestRules(). protocol=" + protocolId);
  var params = (ctx.request && ctx.request.params) || {};
  var out = [];
  if (protocolId !== PROTOCOL_SIOPV2) {
    out.push(rule("response_type", responseTypes(params).join(" ") ===
      "vp_token", "block", "OpenID4VP asks for response_type vp_token; " +
      "this request asks for " + (params.response_type || "nothing") +
      (asksForIdToken(params) ? " — choose SIOPv2 on step 0 to answer an " +
      "ID Token." : ".")));
  }
  oid4vpRules(params, Object.assign({}, ctx, { protocol: protocolId }), out);
  if (protocolId === PROTOCOL_HAIP) haipRules(params, ctx, out);
  if (protocolId === PROTOCOL_SIOPV2) siopRules(params, ctx, out);
  log.debug("Leaving requestRules(). " + out.length + " rule(s).");
  return out;
}

function blockingRules(rules) {
  log.debug("Entering blockingRules().");
  log.debug("Leaving blockingRules().");
  return (rules || []).filter(function (r) {
    return !r.ok && r.level === "block";
  });
}

// ---------------------------------------------------------------------------
// SIOPv2's subject.
// ---------------------------------------------------------------------------
// What the Verifier said it accepts (SIOPv2 section 7.5). Absent, the
// specification's default is the JWK Thumbprint syntax.
function subjectSyntaxesOffered(clientMetadata) {
  log.debug("Entering subjectSyntaxesOffered().");
  var listed = clientMetadata && clientMetadata.subject_syntax_types_supported;
  log.debug("Leaving subjectSyntaxesOffered().");
  return listed && listed.length ? [].concat(listed) :
      [SUBJECT_JWK_THUMBPRINT];
}

// The syntax to sign with: the holder's preference when the Verifier accepts
// it, otherwise the first both sides speak, otherwise null — which is the
// subject_syntax_types_not_supported error, not a guess.
function chooseSubjectSyntax(clientMetadata, preferred) {
  log.debug("Entering chooseSubjectSyntax(). preferred=" + preferred);
  var offered = subjectSyntaxesOffered(clientMetadata);
  if (preferred && offered.indexOf(preferred) !== -1 &&
      SUBJECT_SYNTAXES.indexOf(preferred) !== -1) {
    log.debug("Leaving chooseSubjectSyntax(). The preference.");
    return preferred;
  }
  var both = SUBJECT_SYNTAXES.filter(function (s) {
    return offered.indexOf(s) !== -1;
  });
  log.debug("Leaving chooseSubjectSyntax(). " + (both[0] || "none"));
  return both[0] || null;
}

function publicJwk(jwk) {
  log.debug("Entering publicJwk().");
  var out = {};
  ["kty", "crv", "x", "y", "n", "e"].forEach(function (m) {
    if (jwk && jwk[m] !== undefined) out[m] = jwk[m];
  });
  log.debug("Leaving publicJwk().");
  return out;
}

// The subject a key has under a syntax, and what the ID Token's header
// names it by.
function subjectFor(syntax, privateOrPublicJwk) {
  log.debug("Entering subjectFor(). syntax=" + syntax);
  var pub = publicJwk(privateOrPublicJwk);
  if (syntax === SUBJECT_DID_JWK) {
    var didJwk = didLib.jwkToDidJwk(pub);
    log.debug("Leaving subjectFor(). did:jwk");
    return Promise.resolve({ sub: didJwk, kid: didJwk + "#0", subJwk: null });
  }
  if (syntax === SUBJECT_DID_KEY_METHOD) {
    var didKey = didLib.jwkToDidKey(pub);
    log.debug("Leaving subjectFor(). did:key");
    return Promise.resolve({ sub: didKey,
      kid: didKey + "#" + didKey.slice("did:key:".length), subJwk: null });
  }
  log.debug("Leaving subjectFor(). JWK Thumbprint.");
  return dpop.thumbprint(pub).then(function (tp) {
    return { sub: tp, kid: "", subJwk: pub };
  });
}

// The Self-Issued ID Token (SIOPv2 section 11): iss and sub are the same
// value, aud is the Client Identifier, and it carries the request's nonce.
// Signed ES256 with the key the subject names.
function selfIssuedIdToken(opts) {
  log.debug("Entering selfIssuedIdToken(). aud=" + opts.aud);
  var now = Math.floor((opts.now || Date.now()) / 1000);
  log.debug("Leaving selfIssuedIdToken().");
  return subjectFor(opts.syntax, opts.privateJwk).then(function (subject) {
    var header = { alg: "ES256", typ: "JWT" };
    if (subject.kid) header.kid = subject.kid;
    var payload = {
      iss: subject.sub,
      sub: subject.sub,
      aud: opts.aud,
      nonce: opts.nonce,
      iat: now,
      exp: now + ID_TOKEN_LIFETIME_S
    };
    if (subject.subJwk) payload.sub_jwk = subject.subJwk;
    Object.keys(opts.claims || {}).forEach(function (k) {
      if (payload[k] === undefined) payload[k] = opts.claims[k];
    });
    return jws.signJwsAsync({
      algId: "ES256",
      protectedHeader: header,
      payload: payload,
      privateKey: { jwk: opts.privateJwk },
      backend: "webcrypto"
    }).then(function (signed) {
      log.debug("Leaving selfIssuedIdToken().");
      return { jwt: signed.serialized, header: header, payload: payload,
               syntax: opts.syntax };
    });
  });
}

// A fresh P-256 key pair, for a PAIRWISE self-issued subject: one per
// Verifier, so that two Verifiers cannot correlate the person by the subject
// alone. Only for an ID Token without a presentation — a presentation names
// the credential's own key, and a pairwise subject beside it would be bound
// to nothing.
function generateSubjectKey() {
  log.debug("Entering generateSubjectKey().");
  log.debug("Leaving generateSubjectKey().");
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" },
                                   true, ["sign", "verify"])
    .then(function (pair) {
      return crypto.subtle.exportKey("jwk", pair.privateKey);
    })
    .then(function (jwk) {
      delete jwk.key_ops;
      delete jwk.ext;
      return jwk;
    });
}

// ---------------------------------------------------------------------------
// direct_post.jwt (OpenID4VP 1.0 section 8.3): the response parameters, as a
// JSON object, encrypted to a key from client_metadata.jwks. The JWE's kid is
// that key's kid — it is how the Verifier knows which of its keys to use — and
// the form carries one field, `response`.
// ---------------------------------------------------------------------------
//   opts.key        the Verifier key already chosen (encryptionKeys()[0]),
//                   so the page and an mdoc's transcript name the same one
//   opts.kid        or a kid to find it by
//   opts.protocol / opts.needsThumbprint  as encryptionKeys() takes them
function encryptResponse(opts) {
  log.debug("Entering encryptResponse().");
  var keys = encryptionKeys(opts.clientMetadata, opts);
  var key = opts.key && responseAlgFor(opts.key) ? opts.key :
    (opts.kid ? keys.filter(function (k) {
      return k.kid === opts.kid;
    })[0] : keys[0]);
  if (!key) {
    log.debug("Leaving encryptResponse(). No key.");
    return Promise.reject(new Error("client_metadata.jwks has no key this " +
        "wallet can encrypt the response to (no ECDH-ES P-256, ML-KEM or " +
        "HPKE key" + (opts.protocol === PROTOCOL_HAIP ? "; HAIP takes " +
        "ECDH-ES P-256 only" : "") + ")."));
  }
  var alg = responseAlgFor(key);
  var integrated = joseJwe.isIntegrated(alg);
  var encs = encValues(opts.clientMetadata);
  var enc = opts.enc && encs.indexOf(opts.enc) !== -1 ? opts.enc : encs[0];
  if (integrated) {
    // HPKE Integrated Encryption has no enc: HPKE encrypts the answer.
    enc = null;
  } else if (!enc) {
    log.debug("Leaving encryptResponse(). No enc.");
    return Promise.reject(new Error("the Verifier offers no content " +
        "encryption this wallet does."));
  }
  var header = {};
  if (key.kid) header.kid = key.kid;
  var plaintext = JSON.stringify(opts.fields);
  log.debug("Leaving encryptResponse().");
  return joseJwe.encryptCompact({
    alg: alg, enc: enc, plaintext: plaintext, key: key, header: header
  }).then(function (sealed) {
    log.debug("Leaving encryptResponse(). " + sealed.jwe.length + " chars.");
    return { jwe: sealed.jwe, header: sealed.header, plaintext: plaintext,
             key: key, enc: enc };
  });
}

// The response parameters, before any encoding: what the Verifier will read.
function responseFields(opts) {
  log.debug("Entering responseFields().");
  var fields = {};
  if (opts.vpToken) fields.vp_token = opts.vpToken;
  if (opts.idToken) fields.id_token = opts.idToken;
  if (opts.error) {
    fields.error = opts.error;
    if (opts.errorDescription) {
      fields.error_description = opts.errorDescription;
    }
  }
  if (opts.state) fields.state = opts.state;
  log.debug("Leaving responseFields(). " + Object.keys(fields).join(","));
  return fields;
}

// application/x-www-form-urlencoded, with an object value (vp_token) as its
// JSON (OpenID4VP 1.0 section 8.1).
function formEncode(fields) {
  log.debug("Entering formEncode().");
  var body = Object.keys(fields).map(function (k) {
    var v = fields[k];
    return encodeURIComponent(k) + "=" + encodeURIComponent(
      typeof v === "string" ? v : JSON.stringify(v));
  }).join("&");
  log.debug("Leaving formEncode().");
  return body;
}

// How the answer travels, worked out once so the page that sends it and the
// page that shows it agree: { mode, kind, target, fields, body, jwe }.
//   kind "post"      the wallet POSTs it (direct_post, direct_post.jwt, and
//                    SIOPv2's cross-device `post`)
//   kind "form"      the BROWSER posts it to the redirect_uri (form_post)
//   kind "redirect"  the browser is sent to the redirect_uri with the
//                    fields in the fragment or the query
function deliveryFor(params, fields, encryption) {
  log.debug("Entering deliveryFor().");
  var mode = responseMode(params);
  var target = responseTarget(params);
  var out = { mode: mode, target: target, fields: fields };
  if (mode === "direct_post.jwt") {
    out.kind = "post";
    out.fields = { response: encryption.jwe };
    out.body = formEncode(out.fields);
  } else if (mode === "direct_post" || mode === "post") {
    out.kind = "post";
    out.body = formEncode(fields);
  } else if (mode === "form_post") {
    out.kind = "form";
    out.body = formEncode(fields);
  } else {
    out.kind = "redirect";
    out.body = formEncode(fields);
    out.url = target + (mode === "query" ?
      (target.indexOf("?") === -1 ? "?" : "&") : "#") + out.body;
  }
  log.debug("Leaving deliveryFor(). " + out.kind + " " + mode);
  return out;
}

// The HTTP request as text, for the page to show before anything is sent.
function describeDelivery(d) {
  log.debug("Entering describeDelivery().");
  var text;
  if (d.kind === "redirect") {
    text = "HTTP/1.1 302 Found\nLocation: " + d.url;
  } else {
    text = ["POST " + (d.target || "(no target)"),
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: " + d.body.length, "", d.body].join("\n");
    if (d.kind === "form") {
      text = "(the BROWSER submits this, as an auto-posting form)\n" + text;
    }
  }
  log.debug("Leaving describeDelivery().");
  return text;
}

// Declining. SIOPv2 section 12 has user_cancelled for an End-User who says
// no to an ID Token; a presentation is declined with OpenID4VP's
// access_denied.
function refusalFields(params, reason) {
  log.debug("Entering refusalFields().");
  var siopOnly = asksForIdToken(params) && !asksForVpToken(params);
  var error = reason === "subject_syntax" ?
      "subject_syntax_types_not_supported" :
      (siopOnly ? "user_cancelled" : "access_denied");
  log.debug("Leaving refusalFields(). " + error);
  return responseFields({ error: error, state: params.state,
    errorDescription: reason === "subject_syntax" ?
      "This wallet cannot make a subject of any syntax the Verifier " +
      "accepts." : "The holder declined." });
}

// ---------------------------------------------------------------------------
// The wallet's own metadata, POSTed to a request_uri whose
// request_uri_method is post (OpenID4VP 1.0 section 5.10 and 10).
// ---------------------------------------------------------------------------
function walletMetadata() {
  log.debug("Entering walletMetadata().");
  log.debug("Leaving walletMetadata().");
  return {
    vp_formats_supported: {
      "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"],
                     "kb-jwt_alg_values": ["ES256"] },
      jwt_vc_json: { alg_values: ["ES256"] },
      ldp_vc: { proof_type_values: ["DataIntegrityProof"],
                cryptosuite_values: ["bbs-2023", "ecdsa-jcs-2019"] },
      mso_mdoc: { issuerauth_alg_values: [-7], deviceauth_alg_values: [-7] }
    },
    client_id_prefixes_supported: ["redirect_uri", "x509_hash",
                                   "x509_san_dns", "pre-registered"],
    request_object_signing_alg_values_supported: ["ES256", "ES384",
                                                  "ES512", "PS256", "RS256"],
    authorization_encryption_alg_values_supported: RESPONSE_JWE_ALGS
      .slice(),
    authorization_encryption_enc_values_supported: RESPONSE_JWE_ENCS,
    response_types_supported: ["vp_token", "id_token",
                               "vp_token id_token"],
    response_modes_supported: ["direct_post", "direct_post.jwt", "fragment",
                               "query", "form_post", "post"],
    subject_syntax_types_supported: SUBJECT_SYNTAXES
  };
}

function walletNonce() {
  log.debug("Entering walletNonce().");
  log.debug("Leaving walletNonce().");
  return bytes.bytesToB64u(bytes.randomBytes(16));
}

// ---------------------------------------------------------------------------
// ldp_vc holder binding: a W3C VerifiablePresentation around the bbs-2023
// reveal document (the credential with its derived proof), secured with an
// ecdsa-jcs-2019 Data Integrity proof by the holder (OpenID4VP 1.0 Appendix
// B.1.3.2: challenge is the nonce, domain the Client Identifier). The
// derived proof says the issuer signed these values; this one says the
// holder is the one presenting them, now, to this Verifier.
// ---------------------------------------------------------------------------

// RFC 8785 JSON Canonicalization Scheme. Member names sort by UTF-16 code
// units, which is what JavaScript's default string comparison is; numbers and
// strings serialise exactly as ECMAScript's JSON.stringify does, which is
// what the RFC adopts.
function jcs(value) {
  log.debug("Entering jcs().");
  var out;
  if (value === null || typeof value !== "object") {
    out = JSON.stringify(value);
  } else if (Object.prototype.toString.call(value) === "[object Array]") {
    out = "[" + value.map(function (v) {
      return jcs(v);
    }).join(",") + "]";
  } else {
    out = "{" + Object.keys(value).filter(function (k) {
      return value[k] !== undefined;
    }).sort().map(function (k) {
      return JSON.stringify(k) + ":" + jcs(value[k]);
    }).join(",") + "}";
  }
  log.debug("Leaving jcs().");
  return out;
}

function sha256Utf8(text) {
  log.debug("Entering sha256Utf8().");
  log.debug("Leaving sha256Utf8().");
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))
    .then(function (d) {
      return new Uint8Array(d);
    });
}

// The ecdsa-jcs-2019 proof (W3C VC Data Integrity ECDSA Cryptosuites v1.0,
// section 3.3): SHA-256 of the JCS of the proof configuration, then SHA-256
// of the JCS of the unsecured document, concatenated and signed P-256; the
// proofValue is the raw signature, multibase base58btc.
function ecdsaJcs2019Proof(opts) {
  log.debug("Entering ecdsaJcs2019Proof().");
  var doc = Object.assign({}, opts.document);
  delete doc.proof;
  var config = {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-jcs-2019",
    created: new Date(opts.now || Date.now()).toISOString()
      .replace(/\.\d{3}Z$/, "Z"),
    verificationMethod: opts.verificationMethod,
    proofPurpose: opts.proofPurpose || "authentication"
  };
  if (opts.challenge) config.challenge = opts.challenge;
  if (opts.domain) config.domain = opts.domain;
  if (doc["@context"]) config["@context"] = doc["@context"];
  log.debug("Leaving ecdsaJcs2019Proof().");
  return Promise.all([sha256Utf8(jcs(config)), sha256Utf8(jcs(doc))])
    .then(function (hashes) {
      var data = bytes.concatBytes(hashes[0], hashes[1]);
      var priv = Object.assign({}, opts.privateJwk);
      delete priv.key_ops;
      delete priv.ext;
      return crypto.subtle.importKey("jwk", priv,
          { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
        .then(function (key) {
          return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key,
                                    data);
        });
    })
    .then(function (sig) {
      // The proof keeps the @context it was hashed with (#469, C14): a
      // JCS verifier hashes the proof options EXACTLY AS RECEIVED (VC
      // Data Integrity, Verify Proof), so a proof that dropped it — as
      // this one did until #469 — verifies nowhere but here.
      var proof = Object.assign({}, config);
      proof.proofValue = "z" + didLib.base58Encode(new Uint8Array(sig));
      log.debug("Leaving ecdsaJcs2019Proof().");
      return proof;
    });
}

// The VP itself. `credential` is what the derived proof produced (the
// reveal document the page already builds); `holder` the DID the credential
// names as its subject.
function ldpVerifiablePresentation(opts) {
  log.debug("Entering ldpVerifiablePresentation(). holder=" + opts.holder);
  var vp = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiablePresentation"],
    holder: opts.holder,
    verifiableCredential: [opts.credential]
  };
  log.debug("Leaving ldpVerifiablePresentation().");
  return ecdsaJcs2019Proof({
    document: vp,
    privateJwk: opts.privateJwk,
    verificationMethod: opts.holder + "#0",
    challenge: opts.nonce,
    domain: opts.aud
  }).then(function (proof) {
    vp.proof = proof;
    log.debug("Leaving ldpVerifiablePresentation().");
    return vp;
  });
}

module.exports = {
  KEYS: KEYS,
  PROTOCOL_OID4VP: PROTOCOL_OID4VP,
  PROTOCOL_HAIP: PROTOCOL_HAIP,
  PROTOCOL_SIOPV2: PROTOCOL_SIOPV2,
  PROTOCOLS: PROTOCOLS,
  DEFAULT_PROTOCOL: DEFAULT_PROTOCOL,
  HAIP_FORMATS: HAIP_FORMATS,
  RESPONSE_JWE_ALGS: RESPONSE_JWE_ALGS,
  HAIP_RESPONSE_JWE_ALGS: HAIP_RESPONSE_JWE_ALGS,
  responseAlgFor: responseAlgFor,
  RESPONSE_JWE_ENCS: RESPONSE_JWE_ENCS,
  DEFAULT_RESPONSE_ENC: DEFAULT_RESPONSE_ENC,
  SUBJECT_JWK_THUMBPRINT: SUBJECT_JWK_THUMBPRINT,
  SUBJECT_DID_JWK: SUBJECT_DID_JWK,
  SUBJECT_DID_KEY: SUBJECT_DID_KEY_METHOD,
  SUBJECT_SYNTAXES: SUBJECT_SYNTAXES,
  ID_TOKEN_LIFETIME_S: ID_TOKEN_LIFETIME_S,
  protocols: protocols,
  protocolById: protocolById,
  certificateParts: certificateParts,
  x509Hash: x509Hash,
  certificatePublicJwk: certificatePublicJwk,
  CLIENT_ID_PREFIXES: CLIENT_ID_PREFIXES,
  responseTypes: responseTypes,
  asksForIdToken: asksForIdToken,
  asksForVpToken: asksForVpToken,
  clientIdPrefix: clientIdPrefix,
  responseMode: responseMode,
  responseTarget: responseTarget,
  verifyX509Request: verifyX509Request,
  encryptionKeys: encryptionKeys,
  encValues: encValues,
  requestRules: requestRules,
  blockingRules: blockingRules,
  subjectSyntaxesOffered: subjectSyntaxesOffered,
  chooseSubjectSyntax: chooseSubjectSyntax,
  subjectFor: subjectFor,
  selfIssuedIdToken: selfIssuedIdToken,
  generateSubjectKey: generateSubjectKey,
  encryptResponse: encryptResponse,
  responseFields: responseFields,
  formEncode: formEncode,
  deliveryFor: deliveryFor,
  describeDelivery: describeDelivery,
  refusalFields: refusalFields,
  walletMetadata: walletMetadata,
  walletNonce: walletNonce,
  jcs: jcs,
  ecdsaJcs2019Proof: ecdsaJcs2019Proof,
  ldpVerifiablePresentation: ldpVerifiablePresentation
};
