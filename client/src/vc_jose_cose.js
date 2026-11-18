// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_jose_cose.js
//
// ---------------------------------------------------------------------------
// W3C "Securing Verifiable Credentials using JOSE and COSE" (VC-JOSE-COSE,
// Recommendation 2025; #477): a VCDM 2.0 credential or presentation secured
// by ENVELOPING it, rather than with an embedded proof.
//
//   application/vc+jwt     a JWS whose payload IS the credential (no `vc`
//   application/vp+jwt     claim: section 1.1.2.1 forbids `vc` and `vp`);
//                          typ SHOULD be vc+jwt / vp+jwt, cty SHOULD be vc / vp
//   application/vc+sd-jwt  an SD-JWT (RFC 9901) over the same payload, with
//   application/vp+sd-jwt  `@context`, `type` and `issuer` never selectively
//                          disclosable (section 3.2.1)
//   application/vc+cose    a COSE_Sign1 (RFC 9052) whose payload is the
//   application/vp+cose    credential's JSON; typ (16) SHOULD be the media
//                          type, content type (3) application/vc / vp
//
// Inside a presentation, a secured credential travels as an
// EnvelopedVerifiableCredential: { "@context": v2, type, id: a data: URL of
// the media type with the secured bytes } (base64 for COSE).
//
// THESE ARE NOT dc+sd-jwt OR jwt_vc_json. dc+sd-jwt (IETF SD-JWT VC) has a
// `vct` and no JSON-LD; its earlier typ was ALSO vc+sd-jwt, so a vc+sd-jwt is
// read as W3C here only when its payload has the VCDM 2.0 @context and no
// `vct`. jwt_vc_json (OpenID4VCI 1.0, VCDM 1.1) wraps the credential in a
// `vc` claim, which this format forbids.
//
// Key discovery (section 4): the `kid` header (a DID URL, or a fragment of
// the issuer's DID), else `iss`, through the caller's resolveKey or did.js.
// Signing and verifying are crypto_provider.js, pure JS, for JOSE and COSE
// alike. NO DOM.
// ---------------------------------------------------------------------------

var provider = require("./crypto_provider");
var bytes = require("./crypto_bytes");
var cbor = require("./cbor");
// The deterministic CBOR ENCODER; cbor.js only decodes.
var mdoc = require("./mdoc");
var didLib = require("./did");
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha512 = require("@noble/hashes/sha512");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vc_jose_cose",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var FORMAT_VC_JWT = "vc+jwt";
var FORMAT_VC_SD_JWT = "vc+sd-jwt";
var FORMAT_VC_COSE = "vc+cose";
var V2 = "https://www.w3.org/ns/credentials/v2";

// form ("jwt" | "sdjwt" | "cose") x kind ("vc" | "vp").
var MEDIA = {
  jwt: { vc: "vc+jwt", vp: "vp+jwt" },
  sdjwt: { vc: "vc+sd-jwt", vp: "vp+sd-jwt" },
  cose: { vc: "vc+cose", vp: "vp+cose" }
};
var ENVELOPE = { vc: "EnvelopedVerifiableCredential",
                 vp: "EnvelopedVerifiablePresentation" };
var FORMAT_OF_FORM = { jwt: FORMAT_VC_JWT, sdjwt: FORMAT_VC_SD_JWT,
                       cose: FORMAT_VC_COSE };
// The members section 3.2.1 keeps out of selective disclosure.
var ALWAYS_DISCLOSED = ["@context", "type", "issuer"];

// JOSE alg and COSE alg -> crypto_provider algorithm.
var JOSE_ALGS = {
  ES256: "ecdsa-p256-sha256", ES384: "ecdsa-p384-sha384",
  ES512: "ecdsa-p521-sha512", ES256K: "ecdsa-secp256k1-sha256",
  EdDSA: "ed25519", Ed25519: "ed25519",
  PS256: "rsa-pss-sha256", PS384: "rsa-pss-sha384", PS512: "rsa-pss-sha512",
  RS256: "rsa-pkcs1-sha256", RS384: "rsa-pkcs1-sha384",
  RS512: "rsa-pkcs1-sha512"
};
var COSE_ALGS = {
  "-7": "ES256", "-35": "ES384", "-36": "ES512", "-47": "ES256K",
  "-8": "EdDSA", "-19": "Ed25519", "-37": "PS256", "-38": "PS384",
  "-39": "PS512", "-257": "RS256", "-258": "RS384", "-259": "RS512"
};
var COSE_ALG_OF = {};
Object.keys(COSE_ALGS).forEach(function (n) {
  COSE_ALG_OF[COSE_ALGS[n]] = parseInt(n, 10);
});
// COSE header labels (RFC 9052 section 3.1; typ is RFC 9596).
var COSE_ALG = 1;
var COSE_CTY = 3;
var COSE_KID = 4;
var COSE_TYP = 16;

// The JOSE alg a key signs with.
function algForJwk(jwk) {
  log.debug("Entering algForJwk().");
  var k = jwk || {};
  var alg = k.alg && JOSE_ALGS[k.alg] ? k.alg :
    k.kty === "OKP" ? "EdDSA" :
    k.kty === "RSA" ? "PS256" :
    { "P-256": "ES256", "P-384": "ES384", "P-521": "ES512",
      "secp256k1": "ES256K" }[k.crv];
  log.debug("Leaving algForJwk(). " + alg);
  return alg;
}

function importJwk(jwk) {
  log.debug("Entering importJwk().");
  var clean = Object.assign({}, jwk);
  delete clean.key_ops;
  delete clean.ext;
  delete clean.alg;
  delete clean.kid;
  delete clean.use;
  log.debug("Leaving importJwk().");
  return provider.importKey(clean, { format: "jwk" });
}

function b64uJson(text) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return JSON.parse(bytes.bytesToStr(bytes.b64uToBytes(text)));
}

function jsonB64u(value) {
  log.debug("Entering jsonB64u().");
  log.debug("Leaving jsonB64u().");
  return bytes.bytesToB64u(bytes.strBytes(JSON.stringify(value)));
}

function hasV2Context(doc) {
  log.debug("Entering hasV2Context().");
  var ctx = [].concat((doc && doc["@context"]) || []);
  log.debug("Leaving hasV2Context().");
  return ctx[0] === V2;
}

function kindOfDocument(doc) {
  log.debug("Entering kindOfDocument().");
  var types = [].concat((doc && doc.type) || []);
  log.debug("Leaving kindOfDocument().");
  return types.indexOf("VerifiablePresentation") >= 0 ? "vp" : "vc";
}

// ---------------------------------------------------------------------------
// Recognising one.
// ---------------------------------------------------------------------------

// A secured credential or presentation in any of the three forms, as text
// (compact JWS, SD-JWT, base64url or hex COSE) or bytes (COSE). Answers
// { form, kind, format } or null.
function detect(secured) {
  log.debug("Entering detect().");
  if (secured instanceof Uint8Array) {
    var c = coseKind(secured);
    log.debug("Leaving detect(). Bytes.");
    return c;
  }
  var text = String(secured || "").trim();
  if (!text) {
    log.debug("Leaving detect(). Empty.");
    return null;
  }
  if (/^data:/.test(text)) {
    try {
      var inner = unenvelopeUrl(text);
      log.debug("Leaving detect(). A data: URL.");
      return detect(inner.secured);
    } catch (e) {
      log.debug("Leaving detect(). Unreadable data: URL.");
      return null;
    }
  }
  var parts = text.split("~");
  var jws = parts[0].split(".");
  if (jws.length === 3) {
    var header;
    var payload;
    try {
      header = b64uJson(jws[0]);
      payload = b64uJson(jws[1]);
    } catch (e) {
      log.debug("Leaving detect(). Not JSON.");
      return null;
    }
    var w3c = hasV2Context(payload) && payload.vc === undefined &&
      payload.vp === undefined && payload.vct === undefined;
    var typ = String(header.typ || "").replace(/^application\//, "");
    var form = parts.length > 1 ? "sdjwt" : "jwt";
    var known = typ === MEDIA[form].vc || typ === MEDIA[form].vp;
    if (!w3c || (typ && !known && !(typ === "jwt" || typ === "JWT"))) {
      log.debug("Leaving detect(). Not VC-JOSE-COSE.");
      return null;
    }
    var kind = typ === MEDIA[form].vp ? "vp" : typ === MEDIA[form].vc ?
      "vc" : kindOfDocument(payload);
    log.debug("Leaving detect(). " + form + " " + kind);
    return { form: form, kind: kind, format: FORMAT_OF_FORM[form],
             typWarning: known ? "" : "typ is " + JSON.stringify(header.typ) +
               "; section 3 says it SHOULD be " + MEDIA[form][kind] + "." };
  }
  var raw = null;
  if (/^[0-9a-fA-F]+$/.test(text) && text.length % 2 === 0) {
    raw = bytes.hexToBytes ? bytes.hexToBytes(text) : null;
  } else if (/^[A-Za-z0-9_-]+$/.test(text)) {
    try {
      raw = bytes.b64uToBytes(text);
    } catch (e) {
      raw = null;
    }
  }
  var cose = raw ? coseKind(raw) : null;
  log.debug("Leaving detect(). " + (cose ? "COSE" : "nothing"));
  return cose;
}

// The COSE_Sign1 a byte string is (tagged 18 or bare), when its protected
// typ names a VC-JOSE-COSE media type or its payload is a VCDM 2.0 document.
function coseKind(raw) {
  log.debug("Entering coseKind().");
  var sign1;
  try {
    sign1 = readSign1(raw);
  } catch (e) {
    log.debug("Leaving coseKind(). Not COSE_Sign1.");
    return null;
  }
  var typ = String(sign1.protected.get(COSE_TYP) || "")
    .replace(/^application\//, "");
  var doc = null;
  try {
    doc = JSON.parse(bytes.bytesToStr(sign1.payload));
  } catch (e) {
    doc = null;
  }
  if (typ !== MEDIA.cose.vc && typ !== MEDIA.cose.vp && !hasV2Context(doc)) {
    log.debug("Leaving coseKind(). Not a VC.");
    return null;
  }
  var kind = typ === MEDIA.cose.vp ? "vp" : typ === MEDIA.cose.vc ? "vc" :
    kindOfDocument(doc);
  log.debug("Leaving coseKind(). " + kind);
  return { form: "cose", kind: kind, format: FORMAT_VC_COSE,
           typWarning: typ ? "" : "the COSE typ (16) header is absent; " +
             "section 3.3 says it SHOULD be application/" +
             MEDIA.cose[kind] + "." };
}

// ---------------------------------------------------------------------------
// Envelopes (VCDM 2.0 section 4.13; VC-JOSE-COSE section 3).
// ---------------------------------------------------------------------------
function envelope(form, kind, secured) {
  log.debug("Entering envelope(). " + form + " " + kind);
  var media = "application/" + MEDIA[form][kind];
  var data = secured instanceof Uint8Array ?
    ";base64," + bytes.bytesToB64(secured) : "," + String(secured);
  log.debug("Leaving envelope().");
  return { "@context": V2, id: "data:" + media + data,
           type: ENVELOPE[kind] };
}

// A data: URL back into { media, secured } (bytes for base64).
function unenvelopeUrl(url) {
  log.debug("Entering unenvelopeUrl().");
  var m = /^data:([^,;]+)(;base64)?,(.*)$/.exec(String(url));
  if (!m) {
    log.debug("Leaving unenvelopeUrl(). Not a data: URL.");
    throw new Error("an enveloped credential's id is a data: URL, and " +
                    "this is not one.");
  }
  var secured = m[2] ? bytes.b64ToBytes(m[3]) : decodeURIComponent(m[3]);
  log.debug("Leaving unenvelopeUrl(). " + m[1]);
  return { media: m[1], secured: secured };
}

function unenvelope(env) {
  log.debug("Entering unenvelope().");
  var types = [].concat((env && env.type) || []);
  if (types.indexOf(ENVELOPE.vc) < 0 && types.indexOf(ENVELOPE.vp) < 0) {
    log.debug("Leaving unenvelope(). Not an envelope.");
    throw new Error("not an EnvelopedVerifiableCredential or " +
                    "EnvelopedVerifiablePresentation.");
  }
  var out = unenvelopeUrl(env.id);
  log.debug("Leaving unenvelope().");
  return out;
}

// ---------------------------------------------------------------------------
// SD-JWT disclosures, RFC 9901 section 7.1, in full: object members (_sd),
// array elements ({"...": digest}), disclosures inside disclosed values, and
// every digest used at most once.
// ---------------------------------------------------------------------------
function sdHash(sdAlg) {
  log.debug("Entering sdHash(). " + sdAlg);
  var name = String(sdAlg || "sha-256").toLowerCase();
  var fn = { "sha-256": nobleSha256, "sha-384": nobleSha512.sha384,
             "sha-512": nobleSha512.sha512 }[name];
  if (!fn) {
    log.debug("Leaving sdHash(). Unsupported.");
    throw new Error("_sd_alg " + JSON.stringify(sdAlg) + " is not one this " +
                    "debugger computes (sha-256, sha-384, sha-512).");
  }
  log.debug("Leaving sdHash().");
  return fn;
}

function digestOf(encoded, hash) {
  log.debug("Entering digestOf().");
  log.debug("Leaving digestOf().");
  return bytes.bytesToB64u(hash(bytes.strBytes(encoded)));
}

// Answers { document, disclosed: [{ path, name, value, encoded }] }.
function processDisclosures(payload, encodedDisclosures) {
  log.debug("Entering processDisclosures(). " + encodedDisclosures.length);
  var hash = sdHash(payload._sd_alg);
  var byDigest = {};
  encodedDisclosures.forEach(function (encoded) {
    var arr = b64uJson(encoded);
    if (!Array.isArray(arr) || (arr.length !== 2 && arr.length !== 3)) {
      throw new Error("a Disclosure is a JSON array of 2 or 3 members.");
    }
    var digest = digestOf(encoded, hash);
    if (byDigest[digest]) {
      throw new Error("the same Disclosure appears twice.");
    }
    byDigest[digest] = { encoded: encoded, array: arr, used: false };
  });
  var disclosed = [];
  function walk(node, path) {
    if (Array.isArray(node)) {
      var outArr = [];
      node.forEach(function (item, i) {
        if (item && typeof item === "object" && !Array.isArray(item) &&
            Object.keys(item).length === 1 && item["..."] !== undefined) {
          var hit = byDigest[item["..."]];
          if (!hit) return;
          if (hit.used) throw new Error("a digest is referenced twice.");
          if (hit.array.length !== 2) {
            throw new Error("an array element's Disclosure has 2 members.");
          }
          hit.used = true;
          var p = path.concat([outArr.length]);
          disclosed.push({ path: p, name: null, value: hit.array[1],
                           encoded: hit.encoded });
          outArr.push(walk(hit.array[1], p));
        } else {
          outArr.push(walk(item, path.concat([outArr.length])));
        }
      });
      return outArr;
    }
    if (!node || typeof node !== "object") return node;
    var out = {};
    Object.keys(node).forEach(function (key) {
      if (key === "_sd" || (key === "_sd_alg" && path.length === 0)) return;
      out[key] = walk(node[key], path.concat([key]));
    });
    [].concat(node._sd || []).forEach(function (digest) {
      var hit = byDigest[digest];
      if (!hit) return;
      if (hit.used) throw new Error("a digest is referenced twice.");
      if (hit.array.length !== 3) {
        throw new Error("an object member's Disclosure has 3 members.");
      }
      var name = hit.array[1];
      if (name === "_sd" || name === "..." ||
          Object.prototype.hasOwnProperty.call(out, name)) {
        throw new Error("a Disclosure names " + JSON.stringify(name) +
                        ", which is already a member or reserved.");
      }
      hit.used = true;
      var p = path.concat([name]);
      disclosed.push({ path: p, name: name, value: hit.array[2],
                       encoded: hit.encoded });
      out[name] = walk(hit.array[2], p);
    });
    return out;
  }
  var document = walk(payload, []);
  var unused = Object.keys(byDigest).filter(function (d) {
    return !byDigest[d].used;
  });
  if (unused.length) {
    log.debug("Leaving processDisclosures(). Unreferenced.");
    throw new Error(unused.length + " Disclosure(s) are referenced by no " +
                    "digest in the payload (RFC 9901 section 7.1).");
  }
  log.debug("Leaving processDisclosures(). " + disclosed.length);
  return { document: document, disclosed: disclosed };
}

// ---------------------------------------------------------------------------
// COSE_Sign1.
// ---------------------------------------------------------------------------
function readSign1(raw) {
  log.debug("Entering readSign1().");
  var item = cbor.decode(raw);
  if (item && item.tag === 18 && item.value !== undefined) {
    item = item.value;
  }
  if (!Array.isArray(item) || item.length !== 4 ||
      !(item[0] instanceof Uint8Array) || !(item[2] instanceof Uint8Array) ||
      !(item[3] instanceof Uint8Array)) {
    log.debug("Leaving readSign1(). Not COSE_Sign1.");
    throw new Error("not a COSE_Sign1 (a four-element array).");
  }
  var protectedMap = item[0].length ? cbor.decode(item[0]) : new Map();
  if (!(protectedMap instanceof Map)) {
    log.debug("Leaving readSign1(). Bad protected header.");
    throw new Error("the COSE protected header is not a map.");
  }
  log.debug("Leaving readSign1().");
  return { protectedBytes: item[0], protected: protectedMap,
           unprotected: item[1] instanceof Map ? item[1] : new Map(),
           payload: item[2], signature: item[3] };
}

function sigStructure(protectedBytes, payload) {
  log.debug("Entering sigStructure().");
  log.debug("Leaving sigStructure().");
  return mdoc.encode(["Signature1", protectedBytes, new Uint8Array(0),
                      payload]);
}

// ---------------------------------------------------------------------------
// Securing (an issuer's or a holder's half). signer: { privateJwk, kid }.
// ---------------------------------------------------------------------------
function secureJwt(document, signer, extraClaims) {
  log.debug("Entering secureJwt().");
  var kind = kindOfDocument(document);
  var alg = algForJwk(signer.privateJwk);
  var header = { alg: alg, typ: MEDIA.jwt[kind], cty: kind };
  if (signer.kid) header.kid = signer.kid;
  var payload = Object.assign({}, extraClaims || {}, document);
  var input = jsonB64u(header) + "." + jsonB64u(payload);
  var sig = provider.sign(JOSE_ALGS[alg], importJwk(signer.privateJwk),
                          bytes.strBytes(input));
  log.debug("Leaving secureJwt(). " + alg);
  return input + "." + bytes.bytesToB64u(sig);
}

// `disclosable` lists JSON pointers (RFC 6901) to members or array elements
// to make selectively disclosable; @context, type and issuer cannot be.
function secureSdJwt(document, signer, disclosable, extraClaims) {
  log.debug("Entering secureSdJwt().");
  var payload = JSON.parse(JSON.stringify(document));
  var disclosures = [];
  var hash = nobleSha256;
  var pointers = (disclosable || []).map(parsePointer).sort(function (a, b) {
    return b.length - a.length;
  });
  pointers.forEach(function (path) {
    if (path.length === 1 && ALWAYS_DISCLOSED.indexOf(path[0]) >= 0) {
      throw new Error("\"" + path[0] + "\" is always disclosed " +
                      "(VC-JOSE-COSE section 3.2.1).");
    }
    var parent = payload;
    for (var i = 0; i < path.length - 1; i++) {
      parent = parent ? parent[path[i]] : undefined;
    }
    var last = path[path.length - 1];
    if (!parent || typeof parent !== "object" ||
        parent[last] === undefined) {
      throw new Error("the pointer /" + path.join("/") + " names nothing.");
    }
    var salt = bytes.bytesToB64u(bytes.randomBytes(16));
    var encoded;
    if (Array.isArray(parent)) {
      encoded = jsonB64u([salt, parent[last]]);
      parent[last] = { "...": digestOf(encoded, hash) };
    } else {
      encoded = jsonB64u([salt, last, parent[last]]);
      delete parent[last];
      parent._sd = (parent._sd || []).concat([digestOf(encoded, hash)]);
    }
    disclosures.push(encoded);
  });
  payload._sd_alg = "sha-256";
  var kind = kindOfDocument(document);
  var alg = algForJwk(signer.privateJwk);
  var header = { alg: alg, typ: MEDIA.sdjwt[kind], cty: kind };
  if (signer.kid) header.kid = signer.kid;
  var body = Object.assign({}, extraClaims || {}, payload);
  var input = jsonB64u(header) + "." + jsonB64u(body);
  var sig = provider.sign(JOSE_ALGS[alg], importJwk(signer.privateJwk),
                          bytes.strBytes(input));
  log.debug("Leaving secureSdJwt(). " + disclosures.length + " disclosure(s).");
  return [input + "." + bytes.bytesToB64u(sig)].concat(disclosures)
    .join("~") + "~";
}

function parsePointer(pointer) {
  log.debug("Entering parsePointer(). " + pointer);
  var text = String(pointer);
  if (text.charAt(0) !== "/") {
    log.debug("Leaving parsePointer(). Not a pointer.");
    throw new Error(JSON.stringify(pointer) + " is not a JSON pointer.");
  }
  log.debug("Leaving parsePointer().");
  return text.split("/").slice(1).map(function (s) {
    return /^(0|[1-9][0-9]*)$/.test(s) ? parseInt(s, 10) :
      s.replace(/~1/g, "/").replace(/~0/g, "~");
  });
}

function secureCose(document, signer) {
  log.debug("Entering secureCose().");
  var kind = kindOfDocument(document);
  var alg = algForJwk(signer.privateJwk);
  var header = new Map([[COSE_ALG, COSE_ALG_OF[alg]],
                        [COSE_CTY, "application/" + kind],
                        [COSE_TYP, "application/" + MEDIA.cose[kind]]]);
  if (signer.kid) header.set(COSE_KID, bytes.strBytes(String(signer.kid)));
  var protectedBytes = mdoc.encode(header);
  var payload = bytes.strBytes(JSON.stringify(document));
  var sig = provider.sign(JOSE_ALGS[alg], importJwk(signer.privateJwk),
                          sigStructure(protectedBytes, payload));
  log.debug("Leaving secureCose(). " + alg);
  return mdoc.encode(new cbor.Tagged(18, [protectedBytes, new Map(), payload,
                                          sig]));
}

// The holder's SD-JWT presentation: the issuer's JWT, the Disclosures kept,
// and a Key Binding JWT (typ kb+jwt) over the request's nonce and audience.
function presentSdJwt(serialized, keep, holder) {
  log.debug("Entering presentSdJwt().");
  var parts = String(serialized).split("~");
  var jwt = parts[0];
  var chosen = parts.slice(1).filter(function (d) {
    return d && keep.indexOf(d) >= 0;
  });
  var prefix = [jwt].concat(chosen).join("~") + "~";
  if (!holder) {
    log.debug("Leaving presentSdJwt(). No key binding.");
    return prefix;
  }
  var alg = algForJwk(holder.privateJwk);
  var header = { alg: alg, typ: "kb+jwt" };
  var claims = { iat: Math.floor(Date.now() / 1000), aud: holder.aud,
    nonce: holder.nonce,
    sd_hash: bytes.bytesToB64u(nobleSha256(bytes.strBytes(prefix))) };
  var input = jsonB64u(header) + "." + jsonB64u(claims);
  var sig = provider.sign(JOSE_ALGS[alg], importJwk(holder.privateJwk),
                          bytes.strBytes(input));
  log.debug("Leaving presentSdJwt(). " + chosen.length + " kept.");
  return prefix + input + "." + bytes.bytesToB64u(sig);
}

// ---------------------------------------------------------------------------
// Key discovery (section 4) and verifying.
// ---------------------------------------------------------------------------

// The verification method a kid names: absolute (a DID URL or an https URL)
// as it stands, or relative to the issuer's DID.
function verificationMethodFor(kid, issuer) {
  log.debug("Entering verificationMethodFor().");
  var k = String(kid || "");
  var iss = typeof issuer === "object" && issuer ? issuer.id : issuer;
  var out = !k ? (iss || "") :
    /^(did:|https?:)/.test(k) ? k :
    iss ? String(iss).split("#")[0] + (k.charAt(0) === "#" ? k : "#" + k) : k;
  log.debug("Leaving verificationMethodFor(). " + out);
  return out;
}

function defaultResolveKey(fetchImpl) {
  log.debug("Entering defaultResolveKey().");
  log.debug("Leaving defaultResolveKey().");
  return function resolveKey(vm) {
    log.debug("Entering resolveKey(). " + String(vm).slice(0, 80));
    var did = String(vm || "").split("#")[0];
    if (/^did:jwk:/.test(did)) {
      log.debug("Leaving resolveKey(). did:jwk.");
      return Promise.resolve(didLib.didJwkToJwk(did));
    }
    if (/^did:key:/.test(did)) {
      log.debug("Leaving resolveKey(). did:key.");
      return Promise.resolve(didLib.didKeyToJwk(did));
    }
    log.debug("Leaving resolveKey(). Resolving.");
    return didLib.resolveVerificationMethod(String(vm), { allowHttp: true,
      fetch: fetchImpl }).then(function (r) {
      return (r.method || {}).jwk || (r.method || {}).publicKeyJwk || null;
    });
  };
}

function checkTimes(payload, warnings, errors) {
  log.debug("Entering checkTimes().");
  var now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && payload.exp <= now) {
    errors.push("the signature expired (exp " + payload.exp + ").");
  }
  if (typeof payload.nbf === "number" && payload.nbf > now) {
    errors.push("the signature is not valid yet (nbf " + payload.nbf + ").");
  }
  if (payload.validUntil && Date.parse(payload.validUntil) <= Date.now()) {
    warnings.push("validUntil " + payload.validUntil + " has passed.");
  }
  log.debug("Leaving checkTimes().");
}

// A secured credential or presentation. opts: { resolveKey(vm) ->
// Promise<JWK>, kbAudience, kbNonce, requireKeyBinding }. Answers
// { valid, form, kind, format, document, header, disclosed, warnings,
//   errors, verificationMethod, jwk, keyBinding }.
async function verify(secured, opts) {
  log.debug("Entering verify().");
  var o = opts || {};
  var out = { valid: false, warnings: [], errors: [] };
  var info = detect(secured);
  if (!info) {
    log.debug("Leaving verify(). Not VC-JOSE-COSE.");
    out.errors.push("this is not a VC-JOSE-COSE credential or " +
                    "presentation.");
    return out;
  }
  Object.assign(out, info);
  if (info.typWarning) out.warnings.push(info.typWarning);
  var resolveKey = o.resolveKey || defaultResolveKey(o.fetch);
  try {
    if (info.form === "cose") {
      await verifyCose(secured, out, resolveKey);
    } else {
      await verifyJose(String(secured).trim(), out, resolveKey, o);
    }
  } catch (e) {
    out.errors.push(e.message);
  }
  if (out.document) {
    if (out.document.vc !== undefined || out.document.vp !== undefined) {
      out.errors.push("the payload has a `vc` or `vp` claim, which section " +
                      "1.1.2.1 forbids.");
    }
    checkTimes(out.document, out.warnings, out.errors);
  }
  out.valid = !out.errors.length;
  log.debug("Leaving verify(). " + out.valid);
  return out;
}

async function verifyJose(text, out, resolveKey, o) {
  log.debug("Entering verifyJose().");
  var parts = text.split("~");
  var jws = parts[0].split(".");
  var header = b64uJson(jws[0]);
  var payload = b64uJson(jws[1]);
  out.header = header;
  if (header.cty !== undefined && header.cty !== out.kind &&
      header.cty !== "application/" + out.kind) {
    out.warnings.push("cty is " + JSON.stringify(header.cty) + "; it " +
                      "SHOULD be " + out.kind + ".");
  }
  var spec = JOSE_ALGS[header.alg];
  if (!spec) throw new Error("alg " + JSON.stringify(header.alg) + " is not " +
                             "one this debugger verifies.");
  out.verificationMethod = verificationMethodFor(header.kid,
    header.iss || payload.iss || payload.issuer);
  var jwk = await resolveKey(out.verificationMethod);
  if (!jwk) throw new Error("the key named by " + out.verificationMethod +
                            " could not be found.");
  out.jwk = jwk;
  var ok = provider.verify(spec, importJwk(jwk),
    bytes.strBytes(jws[0] + "." + jws[1]), bytes.b64uToBytes(jws[2]));
  if (!ok) throw new Error("the " + header.alg + " signature does not " +
                           "verify with " + out.verificationMethod + ".");
  if (out.form === "sdjwt") {
    if (parts.length < 2) throw new Error("an SD-JWT ends with \"~\".");
    var kb = parts[parts.length - 1];
    var processed = processDisclosures(payload,
      parts.slice(1, parts.length - 1).filter(Boolean));
    out.document = processed.document;
    out.disclosed = processed.disclosed;
    out.keyBinding = kb ? verifyKeyBinding(parts, payload, kb, o) :
      { present: false };
    if (!kb && o.requireKeyBinding) {
      out.errors.push("a Key Binding JWT was required and is absent.");
    }
    if (kb && !out.keyBinding.valid) out.errors.push(out.keyBinding.reason);
  } else {
    out.document = payload;
  }
  log.debug("Leaving verifyJose().");
}

function verifyKeyBinding(parts, payload, kb, o) {
  log.debug("Entering verifyKeyBinding().");
  var cnf = (payload.cnf || {}).jwk;
  var kbParts = kb.split(".");
  var header = b64uJson(kbParts[0]);
  var claims = b64uJson(kbParts[1]);
  var prefix = parts.slice(0, parts.length - 1).join("~") + "~";
  var r = { present: true, header: header, claims: claims, valid: false };
  if (!cnf) {
    r.reason = "a Key Binding JWT came with a credential that has no " +
      "cnf.jwk to verify it with.";
  } else if (header.typ !== "kb+jwt") {
    r.reason = "the Key Binding JWT's typ is " + JSON.stringify(header.typ) +
      ", not kb+jwt.";
  } else if (!provider.verify(JOSE_ALGS[header.alg], importJwk(cnf),
      bytes.strBytes(kbParts[0] + "." + kbParts[1]),
      bytes.b64uToBytes(kbParts[2]))) {
    r.reason = "the Key Binding JWT's signature does not verify with " +
      "cnf.jwk.";
  } else if (claims.sd_hash !== bytes.bytesToB64u(nobleSha256(
      bytes.strBytes(prefix)))) {
    r.reason = "the Key Binding JWT's sd_hash is not the hash of what " +
      "came before it.";
  } else if (o.kbNonce !== undefined && claims.nonce !== o.kbNonce) {
    r.reason = "the Key Binding JWT's nonce is not this request's.";
  } else if (o.kbAudience !== undefined && claims.aud !== o.kbAudience) {
    r.reason = "the Key Binding JWT's aud is not this Verifier.";
  } else {
    r.valid = true;
  }
  log.debug("Leaving verifyKeyBinding(). " + r.valid);
  return r;
}

async function verifyCose(secured, out, resolveKey) {
  log.debug("Entering verifyCose().");
  var raw = secured instanceof Uint8Array ? secured :
    /^[0-9a-fA-F]+$/.test(String(secured).trim()) ?
      bytes.hexToBytes(String(secured).trim()) :
      bytes.b64uToBytes(String(secured).trim());
  var s = readSign1(raw);
  var algName = COSE_ALGS[String(s.protected.get(COSE_ALG))];
  if (!algName) throw new Error("COSE alg " + s.protected.get(COSE_ALG) +
                                " is not one this debugger verifies.");
  var document = JSON.parse(bytes.bytesToStr(s.payload));
  var kidBytes = s.protected.get(COSE_KID) || s.unprotected.get(COSE_KID);
  var kid = kidBytes instanceof Uint8Array ? bytes.bytesToStr(kidBytes) :
    kidBytes ? String(kidBytes) : "";
  out.header = { alg: algName, kid: kid,
                 typ: s.protected.get(COSE_TYP) || "",
                 cty: s.protected.get(COSE_CTY) || "" };
  out.verificationMethod = verificationMethodFor(kid, document.issuer);
  var jwk = await resolveKey(out.verificationMethod);
  if (!jwk) throw new Error("the key named by " + out.verificationMethod +
                            " could not be found.");
  out.jwk = jwk;
  if (!provider.verify(JOSE_ALGS[algName], importJwk(jwk),
                       sigStructure(s.protectedBytes, s.payload),
                       s.signature)) {
    throw new Error("the " + algName + " COSE_Sign1 signature does not " +
                    "verify with " + out.verificationMethod + ".");
  }
  out.document = document;
  log.debug("Leaving verifyCose().");
}

module.exports = {
  FORMAT_VC_JWT: FORMAT_VC_JWT,
  FORMAT_VC_SD_JWT: FORMAT_VC_SD_JWT,
  FORMAT_VC_COSE: FORMAT_VC_COSE,
  MEDIA: MEDIA,
  ALWAYS_DISCLOSED: ALWAYS_DISCLOSED,
  COSE_ALGS: COSE_ALGS,
  JOSE_ALGS: JOSE_ALGS,
  algForJwk: algForJwk,
  detect: detect,
  envelope: envelope,
  unenvelope: unenvelope,
  unenvelopeUrl: unenvelopeUrl,
  processDisclosures: processDisclosures,
  secureJwt: secureJwt,
  secureSdJwt: secureSdJwt,
  secureCose: secureCose,
  presentSdJwt: presentSdJwt,
  verificationMethodFor: verificationMethodFor,
  defaultResolveKey: defaultResolveKey,
  verify: verify
};
