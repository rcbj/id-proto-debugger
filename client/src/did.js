// File: did.js
//
// ---------------------------------------------------------------------------
// Decentralized Identifiers (W3C DID Core 1.0) for the VC workflows.
//
// Three methods, because the two credential formats reach for DIDs in
// different places and interoperate with different things:
//
//   did:jwk   the key IS the identifier — base64url JSON after the prefix.
//             Resolves with no network at all. walt.id's issuer signs with one.
//   did:key   the key is a multibase/multicodec-encoded public key. The method
//             most other wallets interoperate on, and what walt.id advertises in
//             cryptographic_binding_methods_supported.
//   did:web   the only one with a document to FETCH: an HTTPS GET of did.json.
//             This is the method the retrieval pane exists for.
//
// Everything here returns a DID Document in the shape DID Core defines, so a
// caller can treat a locally-decoded did:jwk and a fetched did:web identically.
// That matters because the pane displays one table either way, and the
// difference between "resolved" and "retrieved" is provenance, not structure.
//
// What this module deliberately does NOT do: decide whether a DID may be used
// for a given credential format. dc+sd-jwt has no DID-based issuer signature
// mechanism in draft-ietf-oauth-sd-jwt-vc — the -10 changelog says "A DID-based
// mechanism is not explicitly provided herein but still possible via profile/
// extension" — so using one there is an extension, and the pages say so. ldp_vc
// is the opposite: VC Data Model 2.0 and Data Integrity are DID-native.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "did",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var metadataClient = require("./metadata_client");

// ---------------------------------------------------------------------------
// base58btc, which did:key needs and nothing else in this repository has.
//
// The bbs-2023 work encodes its keys as multibase base64url ("u"), so there was
// no base58 anywhere. did:key uses "z", and the alphabet is Bitcoin's — it omits
// 0, O, I and l precisely so the four characters that look alike cannot be
// confused when a DID is read aloud or retyped.
// ---------------------------------------------------------------------------
var B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes) {
  if (!bytes.length) return "";
  // Leading zero bytes are not carried by the arithmetic below — base 58 has no
  // way to express them — so they are counted and re-emitted as "1"s, which is
  // what the encoding defines. Dropping them silently changes the key.
  var zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  var digits = [0];
  for (var i = zeros; i < bytes.length; i++) {
    var carry = bytes[i];
    for (var j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  var out = "";
  for (var z = 0; z < zeros; z++) out += B58.charAt(0);
  for (var k = digits.length - 1; k >= 0; k--) out += B58.charAt(digits[k]);
  return out;
}

function base58Decode(str) {
  var s = String(str || "");
  if (!s) return new Uint8Array(0);
  var zeros = 0;
  while (zeros < s.length && s.charAt(zeros) === B58.charAt(0)) zeros++;
  var bytes = [0];
  for (var i = zeros; i < s.length; i++) {
    var value = B58.indexOf(s.charAt(i));
    if (value < 0) throw new Error('"' + s.charAt(i) + '" is not a base58btc character.');
    var carry = value;
    for (var j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  var out = new Uint8Array(zeros + bytes.length);
  for (var k = 0; k < bytes.length; k++) out[zeros + k] = bytes[bytes.length - 1 - k];
  return out;
}

// ---------------------------------------------------------------------------
// multicodec, which is an unsigned varint and not a fixed-width number.
//
// The did:key table lists P-256 as 0x1200, and it is tempting to write that as
// the two bytes 0x12 0x00. It is not: as a varint 0x1200 is 0x80 0x24, which is
// why every P-256 did:key begins "zDn" rather than something else. Getting this
// wrong produces identifiers that decode cleanly in our own code and nowhere
// else — the same failure mode as a wrong ciphersuite constant.
// ---------------------------------------------------------------------------
var CODECS = [
  // code, name, JOSE curve, byte length of the key that follows
  { code: 0xed, name: "ed25519-pub", kty: "OKP", crv: "Ed25519", length: 32 },
  { code: 0xec, name: "x25519-pub", kty: "OKP", crv: "X25519", length: 32 },
  { code: 0xe7, name: "secp256k1-pub", kty: "EC", crv: "secp256k1", length: 33, compressed: true },
  { code: 0x1200, name: "p256-pub", kty: "EC", crv: "P-256", length: 33, compressed: true },
  { code: 0x1201, name: "p384-pub", kty: "EC", crv: "P-384", length: 49, compressed: true },
  { code: 0x1202, name: "p521-pub", kty: "EC", crv: "P-521", length: 67, compressed: true }
];

function codecFor(match) {
  for (var i = 0; i < CODECS.length; i++) {
    if (match(CODECS[i])) return CODECS[i];
  }
  return null;
}

function varintEncode(value) {
  var out = [];
  var n = value;
  while (n > 0x7f) {
    out.push((n & 0x7f) | 0x80);
    n = n >>> 7;
  }
  out.push(n);
  return out;
}

function varintDecode(bytes) {
  var result = 0;
  var shift = 0;
  var i = 0;
  for (; i < bytes.length; i++) {
    var b = bytes[i];
    result |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) return { value: result >>> 0, length: i + 1 };
    shift += 7;
    if (shift > 28) break;
  }
  throw new Error("the multicodec prefix is not a valid unsigned varint.");
}

// ---------------------------------------------------------------------------
// EC point compression, which did:key requires and JWK does not have.
//
// A JWK carries x and y separately; did:key carries the 33-byte compressed
// form — a parity byte then x. Going back the other way means recovering y from
// x, which is a modular square root: for every curve here p = 3 (mod 4), so
// y = ±(x^3 + ax + b)^((p+1)/4) mod p, and the parity byte says which sign.
//
// BigInt is used through its constructor rather than 123n literals, because
// browserify's parser has choked on the literal form in this repository before.
// ---------------------------------------------------------------------------
// Written as HEX, on one line each however long the line, and that is not a
// style preference. These were decimal strings split across two literals with a
// `+`, and P-384's and P-521's were each NINE DIGITS SHORT — a truncation that is
// invisible in a 116-digit decimal number, and which no test caught because the
// only curve anything here uses in practice is P-256, whose constants were
// right. The consequence was not a wrong answer but a refusal: decompressing any
// P-384 or P-521 did:key threw "no square root exists", because with the wrong
// field nothing is a square. Hex is how FIPS 186-4 and SEC 2 publish these, so
// a digit can be checked against the source by eye, and a truncated hex string
// is caught by the byte-length check in tests/did_document.js.
var CURVES = {
  "P-256": {
    p: BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    a: BigInt("-3"),
    b: BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    size: 32
  },
  "P-384": {
    p: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
    a: BigInt("-3"),
    b: BigInt("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
    size: 48
  },
  "P-521": {
    p: BigInt("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    a: BigInt("-3"),
    b: BigInt("0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
    size: 66
  }
};

function bytesToBigInt(bytes) {
  var hex = "0x";
  for (var i = 0; i < bytes.length; i++) {
    hex += ("0" + bytes[i].toString(16)).slice(-2);
  }
  return BigInt(hex === "0x" ? "0x0" : hex);
}

function bigIntToBytes(value, size) {
  var hex = value.toString(16);
  while (hex.length < size * 2) hex = "0" + hex;
  var out = new Uint8Array(size);
  for (var i = 0; i < size; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function modPow(base, exponent, modulus) {
  var result = BigInt(1);
  var b = ((base % modulus) + modulus) % modulus;
  var e = exponent;
  var two = BigInt(2);
  var zero = BigInt(0);
  while (e > zero) {
    if (e % two === BigInt(1)) result = (result * b) % modulus;
    e = e / two;
    b = (b * b) % modulus;
  }
  return result;
}

// x || y  ->  02/03 || x
function compressPoint(crv, xBytes, yBytes) {
  var out = new Uint8Array(xBytes.length + 1);
  // The parity of y is the whole of the information that was dropped.
  out[0] = (yBytes[yBytes.length - 1] & 1) === 1 ? 0x03 : 0x02;
  out.set(xBytes, 1);
  return out;
}

// 02/03 || x  ->  { x, y }
function decompressPoint(crv, compressed) {
  var curve = CURVES[crv];
  if (!curve) throw new Error("no parameters for curve " + crv + ", so its point cannot be decompressed.");
  var prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error("a compressed point starts with 0x02 or 0x03; this starts with 0x" +
                    prefix.toString(16) + ".");
  }
  var xBytes = compressed.slice(1);
  var x = bytesToBigInt(xBytes);
  var p = curve.p;
  var a = ((curve.a % p) + p) % p;
  var alpha = (modPow(x, BigInt(3), p) + a * x + curve.b) % p;
  alpha = ((alpha % p) + p) % p;
  // p = 3 (mod 4) for all three curves, so the square root is a single modPow.
  var y = modPow(alpha, (p + BigInt(1)) / BigInt(4), p);
  if (modPow(y, BigInt(2), p) !== alpha) {
    throw new Error("this x is not on curve " + crv + ": no square root exists.");
  }
  var wantOdd = prefix === 0x03;
  var isOdd = (y % BigInt(2)) === BigInt(1);
  if (wantOdd !== isOdd) y = p - y;
  return { x: xBytes, y: bigIntToBytes(y, curve.size) };
}

// ---------------------------------------------------------------------------
// The identifiers themselves.
// ---------------------------------------------------------------------------
function parse(did) {
  var s = String(did || "").trim();
  var m = /^did:([a-z0-9]+):([^#?]*)(.*)$/.exec(s);
  if (!m) return null;
  var fragment = "";
  var hash = m[3].indexOf("#");
  if (hash !== -1) fragment = m[3].slice(hash + 1);
  return { did: "did:" + m[1] + ":" + m[2], method: m[1], id: m[2], fragment: fragment };
}

function isDid(value) { return !!parse(value); }

// --- did:jwk ---------------------------------------------------------------
function jwkToDidJwk(jwk) {
  var pub = publicPart(jwk);
  return "did:jwk:" + metadataClient.utf8ToB64u(JSON.stringify(pub));
}

function didJwkToJwk(did) {
  var parsed = parse(did);
  if (!parsed || parsed.method !== "jwk") return null;
  try {
    return metadataClient.b64uToJson(parsed.id);
  } catch (e) {
    log.debug("didJwkToJwk(): not base64url JSON: " + e.message);
    return null;
  }
}

// --- did:key ---------------------------------------------------------------
function jwkToDidKey(jwk) {
  var codec = codecFor(function (c) {
    return c.kty === jwk.kty && c.crv === jwk.crv;
  });
  if (!codec) {
    throw new Error("did:key has no multicodec for a " + jwk.kty + " key on " + jwk.crv + ".");
  }
  var keyBytes;
  if (codec.compressed) {
    if (!jwk.x || !jwk.y) throw new Error("an EC did:key needs both x and y to compress the point.");
    keyBytes = compressPoint(jwk.crv, metadataClient.b64uToBytes(jwk.x), metadataClient.b64uToBytes(jwk.y));
  } else {
    if (!jwk.x) throw new Error("an OKP did:key needs x.");
    keyBytes = metadataClient.b64uToBytes(jwk.x);
  }
  var prefix = varintEncode(codec.code);
  var all = new Uint8Array(prefix.length + keyBytes.length);
  all.set(prefix, 0);
  all.set(keyBytes, prefix.length);
  return "did:key:z" + base58Encode(all);
}

function didKeyToJwk(did) {
  var parsed = parse(did);
  if (!parsed || parsed.method !== "key") return null;
  var id = parsed.id;
  if (id.charAt(0) !== "z") {
    throw new Error('a did:key is multibase base58btc, so it begins "z"; this begins "' +
                    id.charAt(0) + '".');
  }
  var bytes = base58Decode(id.slice(1));
  var head = varintDecode(bytes);
  var codec = codecFor(function (c) { return c.code === head.value; });
  if (!codec) {
    throw new Error("multicodec 0x" + head.value.toString(16) + " is not a public key type this " +
                    "supports (" + CODECS.map(function (c) { return c.name; }).join(", ") + ").");
  }
  var keyBytes = bytes.slice(head.length);
  if (keyBytes.length !== codec.length) {
    throw new Error("a " + codec.name + " key is " + codec.length + " bytes; this carries " +
                    keyBytes.length + ".");
  }
  if (!codec.compressed) {
    return { kty: codec.kty, crv: codec.crv, x: metadataClient.bytesToB64u(keyBytes) };
  }
  var point = decompressPoint(codec.crv, keyBytes);
  return {
    kty: codec.kty, crv: codec.crv,
    x: metadataClient.bytesToB64u(point.x),
    y: metadataClient.bytesToB64u(point.y)
  };
}

// --- did:web ---------------------------------------------------------------
//
// DID Core / did:web: the method-specific id is the host with path segments
// separated by ":", a port is percent-encoded as %3A, and a DID with no path
// takes /.well-known/did.json while one with a path appends /did.json.
function didWebToUrl(did) {
  var parsed = parse(did);
  if (!parsed || parsed.method !== "web") return "";
  var segments = parsed.id.split(":").map(decodeURIComponent);
  var host = segments.shift();
  if (!host) return "";
  var path = segments.length ? "/" + segments.join("/") + "/did.json" : "/.well-known/did.json";
  return "https://" + host + path;
}

// The same, for a stack that speaks plain HTTP. did:web mandates https, and
// this repository's local and containerized stacks do not have it — the same
// reason dev-mode.conf exists for walt.id. Only ever used against a host the
// caller already chose.
function didWebToUrlInsecure(did) {
  var url = didWebToUrl(did);
  return url ? url.replace(/^https:/, "http:") : "";
}

// ---------------------------------------------------------------------------
// Resolution, to a DID Document.
//
// did:jwk and did:key resolve LOCALLY — the document is derived from the
// identifier, there is nothing to fetch, and a pane must not imply otherwise.
// did:web is a real retrieval. All three come back in the same shape so the
// caller renders one table.
// ---------------------------------------------------------------------------
function documentForKey(did, jwk, methodType) {
  var vmId = did + "#0";
  var vm = {
    id: vmId,
    type: methodType || "JsonWebKey2020",
    controller: did,
    publicKeyJwk: publicPart(jwk)
  };
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
    id: did,
    verificationMethod: [vm],
    authentication: [vmId],
    assertionMethod: [vmId]
  };
}

function resolveLocally(did) {
  var parsed = parse(did);
  if (!parsed) return null;
  if (parsed.method === "jwk") {
    var jwk = didJwkToJwk(did);
    return jwk ? { document: documentForKey(parsed.did, jwk), from: "the did:jwk itself (no network call)" }
               : null;
  }
  if (parsed.method === "key") {
    var keyJwk = didKeyToJwk(did);
    return keyJwk ? { document: documentForKey(parsed.did, keyJwk),
                      from: "the did:key itself (no network call)" } : null;
  }
  return null;
}

// Returns a promise of { document, from, url }. `fetchImpl` is injectable so a
// node-based test can drive this without a browser.
function resolve(did, opts) {
  opts = opts || {};
  var parsed = parse(did);
  log.debug("Entering resolve(). did=" + String(did).slice(0, 60));
  if (!parsed) return Promise.reject(new Error('"' + did + '" is not a DID: it must begin "did:".'));
  if (parsed.method !== "web") {
    var local;
    try {
      local = resolveLocally(parsed.did);
    } catch (e) {
      return Promise.reject(e);
    }
    if (!local) {
      return Promise.reject(new Error("did:" + parsed.method + " is not a method this debugger " +
                                      "resolves (did:jwk, did:key and did:web are)."));
    }
    log.debug("Leaving resolve(). Resolved locally.");
    return Promise.resolve({ document: local.document, from: local.from, url: "" });
  }
  var url = opts.allowHttp ? didWebToUrlInsecure(parsed.did) : didWebToUrl(parsed.did);
  if (!url) return Promise.reject(new Error("that did:web has no host to fetch from."));
  var doFetch = opts.fetch || (typeof fetch === "function" ? fetch : null);
  if (!doFetch) return Promise.reject(new Error("no fetch implementation is available."));
  return doFetch(url).then(function (r) {
    return r.text().then(function (text) {
      if (!r.ok) {
        throw new Error("the DID document at " + url + " answered HTTP " + r.status + ".");
      }
      var doc;
      try {
        doc = JSON.parse(text);
      } catch (e) {
        throw new Error("the DID document at " + url + " is not JSON: " + e.message);
      }
      // DID Core: the document's id MUST be the DID that was resolved. A
      // document claiming to be somebody else is the interesting failure, so it
      // is refused rather than displayed as though it belonged here.
      if (doc.id && doc.id !== parsed.did) {
        throw new Error("the document at " + url + ' identifies itself as "' + doc.id +
                        '", not "' + parsed.did + '".');
      }
      log.debug("Leaving resolve(). Retrieved " + text.length + " characters.");
      return { document: doc, from: "retrieved from " + url, url: url };
    });
  });
}

// ---------------------------------------------------------------------------
// Reading a document.
// ---------------------------------------------------------------------------
// Every verification method, with its key as a JWK whichever way the document
// expressed it. A document may reference a method by id from authentication or
// assertionMethod instead of embedding it, which is why these are resolved
// against verificationMethod rather than read where they stand.
function verificationMethods(doc) {
  var out = [];
  var list = (doc && doc.verificationMethod) || [];
  for (var i = 0; i < list.length; i++) {
    var vm = list[i];
    if (!vm || typeof vm !== "object") continue;
    var jwk = null;
    if (vm.publicKeyJwk) {
      jwk = vm.publicKeyJwk;
    } else if (vm.publicKeyMultibase) {
      try {
        jwk = didKeyToJwk("did:key:" + vm.publicKeyMultibase);
      } catch (e) {
        // A multibase key this cannot decode (a BBS key, for instance) is still
        // worth listing: the pane shows the method, just without a JWK.
        log.debug("verificationMethods(): undecodable publicKeyMultibase on " + vm.id);
      }
    }
    out.push({ id: vm.id || "", type: vm.type || "", controller: vm.controller || "", jwk: jwk,
               publicKeyMultibase: vm.publicKeyMultibase || "" });
  }
  return out;
}

// The keys a document says may ASSERT — which is what verifies a credential
// signature. Falling back to every verification method when assertionMethod is
// absent is deliberate: a document that lists keys but no relationships is
// common in the wild, and refusing to verify against it would report a working
// credential as unverifiable.
function assertionKeys(doc) {
  var all = verificationMethods(doc);
  var refs = (doc && doc.assertionMethod) || [];
  if (!refs.length) return all;
  var out = [];
  refs.forEach(function (ref) {
    if (ref && typeof ref === "object") {
      out.push({ id: ref.id || "", type: ref.type || "", controller: ref.controller || "",
                 jwk: ref.publicKeyJwk || null, publicKeyMultibase: ref.publicKeyMultibase || "" });
      return;
    }
    for (var i = 0; i < all.length; i++) {
      if (all[i].id === ref) { out.push(all[i]); return; }
    }
  });
  return out.length ? out : all;
}

// The verification method a signature named, by its kid or by the DID's own
// fragment. Falls back to the first assertion key, because a document with one
// key and a signature with no kid is the common case and is unambiguous.
function keyForKid(doc, kid) {
  var keys = assertionKeys(doc);
  if (kid) {
    for (var i = 0; i < keys.length; i++) {
      if (keys[i].id === kid) return keys[i];
      // A kid is often just the fragment.
      if (keys[i].id && keys[i].id.indexOf("#") !== -1 &&
          keys[i].id.split("#")[1] === String(kid).replace(/^#/, "")) return keys[i];
    }
  }
  return keys[0] || null;
}

// The document's assertion keys as a JWKS, plus the ones that cannot be
// expressed as a JWK at all.
//
// Shared rather than written where it is needed, because two quite different
// callers need the same conversion and must agree about it: issuance step 3
// verifies a credential's issuer signature against these keys, and
// verifyDomainLinkage() below verifies a Domain Linkage Credential against them.
// Both are answering "did a key this DID authorises to ASSERT sign these bytes",
// and two implementations of that would be two chances to answer differently.
//
// `unusable` is not an error: a document may legitimately publish a key with no
// JOSE representation beside one that has — the mock issuer's carries its BBS key
// as a Multikey next to its RS256 JsonWebKey2020 — and a caller that found no
// usable key should be able to say WHICH keys it passed over rather than
// reporting an empty document.
function assertionJwks(doc) {
  log.debug("Entering assertionJwks().");
  var keys = [];
  var unusable = [];
  assertionKeys(doc).forEach(function (method) {
    if (!method) return;
    if (!method.jwk) {
      unusable.push((method.id || "(unnamed)") + (method.type ? " (" + method.type + ")" : ""));
      return;
    }
    var jwk = {};
    Object.keys(method.jwk).forEach(function (name) { jwk[name] = method.jwk[name]; });
    // The verification method's id is this key's name within the document, and it
    // is what a DID-URL kid names. Only filled in when the key carries no kid of
    // its own: that one is the issuer's own choice and is what a JWS header will
    // match, so overwriting it would leave a kid lookup nothing to find.
    if (!jwk.kid && method.id) jwk.kid = method.id;
    keys.push(jwk);
  });
  log.debug("Leaving assertionJwks(). " + keys.length + " usable, " + unusable.length + " not.");
  return { jwks: { keys: keys }, unusable: unusable };
}

// Only the members that identify a public key. A stray d would publish a
// private key in a DID document, which is the worst possible place for one.
function publicPart(jwk) {
  if (!jwk) return {};
  var out = { kty: jwk.kty };
  if (jwk.crv) out.crv = jwk.crv;
  if (jwk.x) out.x = jwk.x;
  if (jwk.y) out.y = jwk.y;
  if (jwk.n) out.n = jwk.n;
  if (jwk.e) out.e = jwk.e;
  return out;
}

// One verification method, named the way a proof names it.
//
// A Data Integrity proof's verificationMethod is "where my key is", and it may be
// either kind of URL. This project's ldp_vc credentials named an https URL that
// dereferences straight to a key document; a credential from a DID-named issuer
// names a DID URL instead, which is NOT fetchable — resolving it means resolving
// the DID and picking out the method its fragment names.
//
// Both are handled here rather than at the call site because the call site is a
// presentation page whose failure mode is a fetch of "did:web:…" that reports the
// issuer's key as unreachable. The two forms are one question with two answers.
//
// There is deliberately NO fallback to "the first key in the document": the proof
// named a specific method, and quietly verifying against a different one would
// turn "this proof was made by another key" into a confusing pass or fail
// somewhere else.
function resolveVerificationMethod(url, opts) {
  log.debug("Entering resolveVerificationMethod(). url=" + String(url).slice(0, 80));
  opts = opts || {};
  var wanted = String(url || "");
  if (!wanted) return Promise.reject(new Error("the proof names no verificationMethod."));
  if (!isDid(wanted)) {
    var doFetch = opts.fetch || (typeof fetch === "function" ? fetch : null);
    if (!doFetch) return Promise.reject(new Error("no fetch implementation is available."));
    // text() then parse, as resolve() does, so a key document that is not JSON —
    // an HTML error page from a misconfigured host is the usual one — says that
    // rather than surfacing a bare SyntaxError from somewhere inside a promise.
    return doFetch(wanted).then(function (r) {
      return r.text().then(function (text) {
        if (!r.ok) throw new Error(wanted + " answered HTTP " + r.status + ".");
        var method;
        try {
          method = JSON.parse(text);
        } catch (e) {
          throw new Error("the verification method at " + wanted + " is not JSON: " + e.message);
        }
        log.debug("Leaving resolveVerificationMethod(). Fetched an https verification method.");
        return { method: method, from: "retrieved from " + wanted };
      });
    });
  }
  var parsed = parse(wanted);
  return resolve(parsed.did, opts).then(function (res) {
    var methods = verificationMethods(res.document);
    var fragment = parsed.fragment;
    var found = null;
    for (var i = 0; i < methods.length; i++) {
      if (methods[i].id === wanted) { found = methods[i]; break; }
      if (fragment && methods[i].id && methods[i].id.split("#")[1] === fragment) {
        found = methods[i];
        break;
      }
    }
    if (!found) {
      throw new Error('the DID document for ' + parsed.did + ' has no verification method "' + wanted +
                      '". It publishes ' +
                      (methods.length ? methods.map(function (m) { return m.id; }).join(", ")
                                      : "none") + ".");
    }
    log.debug("Leaving resolveVerificationMethod(). Found " + found.id + " in the DID document.");
    return { method: found, from: res.from };
  });
}

// ---------------------------------------------------------------------------
// Well Known DID Configuration (DIF): proving a DID and an origin are the same
// entity.
//
// This is the check that the other documents cannot make. A DID document says
// which keys a DID has. A credential says which DID issued it. Neither says why
// the DID should be believed to be the same party as the https issuer a wallet
// discovered — and for did:web the appearance of an answer is worse than none,
// because the DID resolves by fetching the very origin whose claim is in
// question. Reading the DID document off example.com to decide whether
// did:web:example.com is example.com is circular.
//
// The Domain Linkage Credential breaks that: the DID signs, with its own key, a
// credential naming the origin. A verifier resolves the issuer DID, checks the
// signature against the keys that DID authorises to ASSERT, and checks that the
// origin in the credential is the origin the document came from. Nothing is
// established by where the file sat; it is established by the signature.
//
// Every requirement below is from the specification's own verification steps and
// from its "no additional members permitted" rules, which is why the negatives
// have their own checks rather than one pass/fail — a document that fails for a
// reason nobody can see teaches nothing.
// ---------------------------------------------------------------------------
var DID_CONFIGURATION_PATH = "/.well-known/did-configuration.json";
var DID_CONFIGURATION_CONTEXT = "https://identity.foundation/.well-known/did-configuration/v1";
var VC_V1_CONTEXT = "https://www.w3.org/2018/credentials/v1";
// The specification permits exactly these, in each of the two places it says so.
var LINKAGE_JWT_CLAIMS = ["iss", "sub", "nbf", "exp", "vc"];
var LINKAGE_JWT_HEADER = ["alg", "kid"];

function didConfigurationUrl(origin) {
  var trimmed = String(origin || "").replace(/\/+$/, "");
  return trimmed ? trimmed + DID_CONFIGURATION_PATH : "";
}

// The scheme+host+port of a URL, which is what the specification compares. A
// value that is not a URL comes back as given, so the comparison fails visibly
// rather than throwing.
function originOf(value) {
  try {
    return new URL(String(value)).origin;
  } catch (e) {
    log.debug("originOf(): " + value + " is not a URL.");
    return String(value || "");
  }
}

function extraMembers(object, permitted) {
  return Object.keys(object || {}).filter(function (name) {
    return permitted.indexOf(name) === -1;
  });
}

// Verify one entry of linked_dids, in the JWT form. Returns a promise of
// { valid, did, origin, checks: [{ name, ok, detail }] } — the caller decides
// how to show it, and every check is reported whether it passed or not.
//
// `opts.fetch` is passed through to resolve() so a node test can drive this
// without a browser; `opts.allowHttp` is needed wherever did:web must be fetched
// over plain http, as it must on this project's stacks.
function verifyDomainLinkage(entry, expectedOrigin, opts) {
  log.debug("Entering verifyDomainLinkage(). expectedOrigin=" + expectedOrigin);
  opts = opts || {};
  var checks = [];
  var fail = function (name, detail) {
    checks.push({ name: name, ok: false, detail: detail });
    log.debug("Leaving verifyDomainLinkage(). Failed at: " + name);
    return Promise.resolve({ valid: false, did: "", origin: "", checks: checks });
  };

  // The specification allows either form. Only the JWT one is verified here, and
  // an LD-proof entry is reported as unverified rather than as invalid: it is a
  // legitimate document this code cannot check, which is a different thing from a
  // document that fails its checks.
  if (entry && typeof entry === "object") {
    return fail("Credential form",
                "this entry is a Linked Data Proof credential. That form is valid per the " +
                "specification, but verifying it needs URDNA2015 canonicalization, which this " +
                "debugger does not implement — only the JWT form is checked here.");
  }
  var parts = String(entry || "").split(".");
  if (parts.length !== 3) {
    return fail("Credential form", "a linked_dids entry must be a JWT or a credential object; " +
                                   "this has " + parts.length + " dot-separated part(s).");
  }
  var header, payload;
  try {
    header = metadataClient.b64uToJson(parts[0]);
    payload = metadataClient.b64uToJson(parts[1]);
  } catch (e) {
    return fail("Credential form", "the JWT's header or payload is not base64url JSON: " + e.message);
  }

  // --- the JWT itself -------------------------------------------------------
  var headerExtra = extraMembers(header, LINKAGE_JWT_HEADER);
  checks.push({
    name: "JWT header",
    ok: !!header.alg && !!header.kid && !("typ" in header) && !headerExtra.length,
    detail: "alg " + (header.alg || "(absent)") + ", kid " + (header.kid || "(absent)") +
            '. The specification requires alg and kid, forbids typ — which a JWT library will add ' +
            'unless told not to — and permits nothing else' +
            (headerExtra.length ? "; this carries " + headerExtra.join(", ") : "") + "."
  });
  var payloadExtra = extraMembers(payload, LINKAGE_JWT_CLAIMS);
  checks.push({
    name: "JWT claims",
    ok: !payloadExtra.length,
    detail: payloadExtra.length
      ? "iat is the usual culprit, added by default by most libraries: " + payloadExtra.join(", ") +
        " " + (payloadExtra.length === 1 ? "is" : "are") + " not permitted here."
      : "iss, sub, nbf, exp and vc, and nothing else, as required."
  });

  var vc = payload.vc || {};
  var subject = vc.credentialSubject || {};
  var did = String(payload.iss || "");

  // --- the credential -------------------------------------------------------
  // Subject and issuer must both be the DID: a domain linkage credential is
  // self-issued by definition, because nobody but the DID's controller is in a
  // position to say which origin it controls. A credential naming somebody else
  // as issuer would prove only that the somebody else said so.
  checks.push({
    name: "Self-issued to one DID",
    ok: !!did && payload.sub === did && subject.id === did && vc.issuer === did,
    detail: "iss " + (payload.iss || "(absent)") + ", sub " + (payload.sub || "(absent)") +
            ", vc.issuer " + (vc.issuer || "(absent)") + ", credentialSubject.id " +
            (subject.id || "(absent)") + ". All four must be the same DID."
  });
  var contexts = [].concat(vc["@context"] || []);
  checks.push({
    name: "Credential @context",
    ok: contexts.indexOf(VC_V1_CONTEXT) !== -1 && contexts.indexOf(DID_CONFIGURATION_CONTEXT) !== -1,
    detail: "must contain both " + VC_V1_CONTEXT + " and " + DID_CONFIGURATION_CONTEXT +
            "; got " + (contexts.length ? contexts.join(", ") : "(none)") + "."
  });
  var types = [].concat(vc.type || []);
  checks.push({
    name: "Credential type",
    ok: types.indexOf("VerifiableCredential") !== -1 && types.indexOf("DomainLinkageCredential") !== -1,
    detail: "must contain VerifiableCredential and DomainLinkageCredential; got " +
            (types.length ? types.join(", ") : "(none)") + "."
  });
  // The specification says the credential MUST NOT have an id at its root. It is
  // an odd-looking rule and it is deliberate: this credential is not an
  // addressable thing to be fetched or revoked, it is an assertion about a pair.
  checks.push({
    name: "No credential id",
    ok: !("id" in vc),
    detail: ("id" in vc) ? 'the credential carries id "' + vc.id + '" at its root, which is forbidden.'
                         : "absent, as required."
  });

  // --- the linkage this document exists to make ----------------------------
  var claimedOrigin = String(subject.origin || "");
  var wanted = originOf(expectedOrigin);
  checks.push({
    name: "Origin",
    ok: !!claimedOrigin && originOf(claimedOrigin) === wanted,
    detail: 'the credential names origin "' + (claimedOrigin || "(absent)") +
            '" and was read from "' + wanted + '". These must be the same origin, or the ' +
            "credential belongs to a different site."
  });

  var now = Math.floor(Date.now() / 1000);
  checks.push({
    name: "Validity window",
    ok: (!payload.exp || payload.exp > now) && (!payload.nbf || payload.nbf <= now),
    detail: "nbf " + (payload.nbf || "—") + ", exp " + (payload.exp || "—") + ", now " + now + "."
  });

  // --- and the only check that cannot be faked ------------------------------
  if (!isDid(did)) {
    return fail("Issuer signature", 'the issuer "' + did + '" is not a DID, so there is nothing to ' +
                                    "resolve a verification key from.");
  }
  return resolve(did, { fetch: opts.fetch, allowHttp: opts.allowHttp })
    .then(function (res) {
      var converted = assertionJwks(res.document);
      if (!converted.jwks.keys.length) {
        throw new Error("the DID document publishes no assertion key that can verify a JWS" +
                        (converted.unusable.length ? " — it names " + converted.unusable.join(", ") : "") +
                        ".");
      }
      return metadataClient.verifyJwsWithJwks(String(entry), converted.jwks,
                                              "the Domain Linkage Credential")
        .then(function (verdict) {
          checks.push({
            name: "Issuer signature",
            ok: verdict.valid,
            detail: (verdict.valid ? "verified" : "DOES NOT verify") +
                    " against the assertionMethod keys of " + did + " (" + res.from +
                    ", alg " + verdict.header.alg + ", kid " + verdict.kid + ")."
          });
          var valid = checks.every(function (c) { return c.ok; });
          log.debug("Leaving verifyDomainLinkage(). valid=" + valid);
          return { valid: valid, did: did, origin: claimedOrigin, checks: checks };
        });
    })
    .catch(function (e) {
      checks.push({ name: "Issuer signature", ok: false,
                    detail: "could not be checked: " + e.message });
      return { valid: false, did: did, origin: claimedOrigin, checks: checks };
    });
}

// Fetch an origin's DID Configuration and verify every entry in it, returning the
// verdict for the DID asked about.
//
// `wantedDid` matters: an origin may link several DIDs, and the question a wallet
// has is not "does this site link any DID" but "does it link THIS one" — the DID
// its credential named. Without that, a site linking its own DID would appear to
// vouch for somebody else's.
function verifyOriginLinkage(origin, wantedDid, opts) {
  log.debug("Entering verifyOriginLinkage(). origin=" + origin + ", did=" + wantedDid);
  opts = opts || {};
  var url = didConfigurationUrl(origin);
  if (!url) return Promise.reject(new Error("no origin to fetch a DID Configuration from."));
  var doFetch = opts.fetch || (typeof fetch === "function" ? fetch : null);
  if (!doFetch) return Promise.reject(new Error("no fetch implementation is available."));
  return doFetch(url).then(function (r) {
    return r.text().then(function (text) {
      if (!r.ok) throw new Error(url + " answered HTTP " + r.status + ".");
      var doc;
      try {
        doc = JSON.parse(text);
      } catch (e) {
        throw new Error(url + " is not JSON: " + e.message);
      }
      if (doc["@context"] !== DID_CONFIGURATION_CONTEXT) {
        throw new Error('the resource\'s @context must be "' + DID_CONFIGURATION_CONTEXT +
                        '"; it is "' + doc["@context"] + '".');
      }
      var entries = doc.linked_dids;
      if (!Array.isArray(entries) || !entries.length) {
        throw new Error("the resource carries no linked_dids.");
      }
      // Every entry is verified, not just the first: the wanted DID may be any of
      // them, and an entry that fails is worth reporting beside one that passes.
      return Promise.all(entries.map(function (entry) {
        return verifyDomainLinkage(entry, origin, opts);
      })).then(function (results) {
        var matched = results.filter(function (r) { return r.did === wantedDid; });
        log.debug("Leaving verifyOriginLinkage(). " + results.length + " entry(ies), " +
                  matched.length + " for the DID asked about.");
        return {
          url: url,
          results: results,
          matched: matched,
          linked: matched.some(function (r) { return r.valid; })
        };
      });
    });
  });
}

// ---------------------------------------------------------------------------
// The DID Document members the Configuration Parameters pane shows and lets you
// edit, in the same shape op_metadata.js and vci_metadata.js use so one row
// builder renders all three. Ids and storage keys are prefixed "did_".
//
// Editable on purpose: this pane is where you try a document the issuer has not
// published yet, or break one deliberately to see what the verification does
// about it. That is the same reason the other two sections are editable.
// ---------------------------------------------------------------------------
var DID_METADATA = [
  { name: "id", type: "string", dflt: "",
    desc: "REQUIRED. The DID this document describes. DID Core: a resolved document's id MUST equal the DID that was resolved, so a mismatch here means the document belongs to somebody else." },
  { name: "controller", type: "string", dflt: "",
    desc: "OPTIONAL. The DID(s) authorised to make changes to this document." },
  { name: "verificationMethod", type: "json", dflt: "",
    desc: "The public keys this DID publishes, each with an id, a type and the key itself (publicKeyJwk, or publicKeyMultibase for a key with no JOSE representation such as BBS)." },
  { name: "authentication", type: "json", dflt: "",
    desc: "OPTIONAL. Which verification methods may authenticate as this DID — either ids referencing verificationMethod, or embedded methods." },
  { name: "assertionMethod", type: "json", dflt: "",
    desc: "OPTIONAL. Which verification methods may ASSERT — i.e. which keys may sign a credential. This is the relationship that matters when verifying an issuer signature." },
  { name: "service", type: "json", dflt: "",
    desc: "OPTIONAL. Service endpoints this DID publishes. Not used by either credential format here; shown because a real document often carries them." }
];

var DID_PREFIX = "did_";
function idFor(name) { return DID_PREFIX + name; }

module.exports = {
  DID_METADATA: DID_METADATA,
  idFor: idFor,
  parse: parse,
  isDid: isDid,
  base58Encode: base58Encode,
  base58Decode: base58Decode,
  varintEncode: varintEncode,
  varintDecode: varintDecode,
  compressPoint: compressPoint,
  decompressPoint: decompressPoint,
  jwkToDidJwk: jwkToDidJwk,
  didJwkToJwk: didJwkToJwk,
  jwkToDidKey: jwkToDidKey,
  didKeyToJwk: didKeyToJwk,
  didWebToUrl: didWebToUrl,
  didWebToUrlInsecure: didWebToUrlInsecure,
  documentForKey: documentForKey,
  resolveLocally: resolveLocally,
  resolve: resolve,
  verificationMethods: verificationMethods,
  assertionKeys: assertionKeys,
  assertionJwks: assertionJwks,
  keyForKid: keyForKid,
  resolveVerificationMethod: resolveVerificationMethod,
  publicPart: publicPart,
  didConfigurationUrl: didConfigurationUrl,
  verifyDomainLinkage: verifyDomainLinkage,
  verifyOriginLinkage: verifyOriginLinkage,
  DID_CONFIGURATION_PATH: DID_CONFIGURATION_PATH,
  DID_CONFIGURATION_CONTEXT: DID_CONFIGURATION_CONTEXT,
  CODECS: CODECS,
  // Exported for tests/did_document.js only, which checks p and b against their
  // published values. Nothing in the pages reads them: a truncated constant here
  // was a real bug, and the round trip alone could only report it as "this key is
  // not on the curve".
  CURVES_FOR_TESTS: CURVES
};
