// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: sd_cwt.js
//
// ---------------------------------------------------------------------------
// Selective Disclosure CBOR Web Tokens (#478): draft-ietf-spice-sd-cwt-09,
// a DRAFT, and every label this module gives the UI says so. No DOM.
//
// An SD-CWT is a COSE_Sign1 (tag 18) whose payload is a CWT Claims Set in
// which some claims are REDACTED:
//
//   * a redacted map entry leaves its Redacted Claim Hash in an array under
//     the map key simple(59) (redacted_claim_keys) at the same level;
//   * a redacted array element is replaced by tag 60 wrapping its hash;
//   * the Salted Disclosed Claims ([salt, value, key], [salt, value] or a
//     decoy's [salt]) travel bstr-wrapped in the UNPROTECTED header's
//     sd_claims (17), outside the issuer's signature;
//   * a Redacted Claim Hash is sd_alg (170; SHA-256 by default) over the
//     WHOLE bstr encoding of a disclosure, its CBOR byte-string head
//     included. Hashing only the contents reproduces nothing: Figure 8's
//     af375dc3… is SHA-256 over 58 21 83 50 …, not over 83 50 ….
//
// A presentation is a Key Binding Token: a COSE_Sign1 by the key in the
// SD-CWT's cnf claim, typ 294, carrying the SD-CWT (with the Holder's
// choice of disclosures) in its protected kcwt (13) header, and aud plus
// iat or cti (and the Verifier's cnonce) in its payload. Section 9's
// checks are each reported by name.
//
// AEAD-encrypted disclosures (section 12) are recognised and, having no
// key for them, ignored with a warning, which is what section 9 step 8
// says a Verifier without a key does.
// ---------------------------------------------------------------------------

var provider = require("./crypto_provider");
var bytes = require("./crypto_bytes");
var cbor = require("./cbor");
var mdoc = require("./mdoc");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "sd_cwt",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var DRAFT = "draft-ietf-spice-sd-cwt-09";
var TYP_SD_CWT = 293;
var TYP_KBT = 294;
var MEDIA_SD_CWT = "application/sd-cwt";
var MEDIA_KBT = "application/kb+cwt";

var H = { alg: 1, kid: 4, typ: 16, kcwt: 13, cwtClaims: 15, sdClaims: 17,
          sdAlg: 170, sdAeadClaims: 171, sdAead: 172 };
var C = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7, cnf: 8,
          vct: 11, cnonce: 39 };
// Table 2: the claims that are never redacted.
var NEVER_REDACTED = [1, 3, 4, 5, 6, 7, 8, 39];
var CLAIM_NAMES = { 1: "iss", 2: "sub", 3: "aud", 4: "exp", 5: "nbf",
                    6: "iat", 7: "cti", 8: "cnf", 11: "vct", 39: "cnonce" };

var REDACTED_KEYS = 59;
var REDACTED_ELEMENT = 60;

// COSE signature algorithms (RFC 9053, RFC 9864) to crypto_provider ids.
var SIG_ALGS = {
  "-7": "ecdsa-p256-sha256", "-9": "ecdsa-p256-sha256",
  "-35": "ecdsa-p384-sha384", "-51": "ecdsa-p384-sha384",
  "-36": "ecdsa-p521-sha512", "-52": "ecdsa-p521-sha512",
  "-47": "ecdsa-secp256k1-sha256", "-19": "ed25519", "-53": "ed448",
  "-8": "eddsa"
};
var SIG_NAMES = { "-7": "ES256", "-9": "ESP256", "-35": "ES384",
                  "-51": "ESP384", "-36": "ES512", "-52": "ESP512",
                  "-47": "ES256K", "-19": "Ed25519", "-53": "Ed448",
                  "-8": "EdDSA" };
var HASHES = { "-16": "sha256", "-43": "sha384", "-44": "sha512" };
var COSE_CRV = { 1: "P-256", 2: "P-384", 3: "P-521", 6: "Ed25519",
                 7: "Ed448", 8: "secp256k1" };
var JWK_CRV = { "P-256": 1, "P-384": 2, "P-521": 3, "Ed25519": 6,
                "Ed448": 7, "secp256k1": 8 };
// The fully-specified algorithm for a key (RFC 9864) when none is given.
var ALG_FOR_CRV = { "P-256": -9, "P-384": -51, "P-521": -52,
                    "Ed25519": -19, "Ed448": -53, "secp256k1": -47 };

function hex(data) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return bytes.bytesToHex(data);
}

function isSimple(k, n) {
  log.debug("Entering isSimple().");
  log.debug("Leaving isSimple().");
  return k !== null && typeof k === "object" && !(k instanceof Uint8Array) &&
    k.simple === n;
}

function tagged(v, tag) {
  log.debug("Entering tagged().");
  log.debug("Leaving tagged().");
  return v instanceof cbor.Tagged && v.tag === tag;
}

// A decoded value made encodable again: {simple: n} becomes mdoc.Simple.
function encodable(v) {
  log.debug("Entering encodable().");
  if (v instanceof Map) {
    var m = new Map();
    v.forEach(function (val, key) {
      m.set(key !== null && typeof key === "object" && !(key instanceof
            Uint8Array) && typeof key.simple === "number" ?
            new mdoc.Simple(key.simple) : encodable(key), encodable(val));
    });
    log.debug("Leaving encodable(). Map.");
    return m;
  }
  if (Array.isArray(v)) {
    log.debug("Leaving encodable(). Array.");
    return v.map(encodable);
  }
  if (v instanceof cbor.Tagged) {
    log.debug("Leaving encodable(). Tagged.");
    return new cbor.Tagged(v.tag, encodable(v.value));
  }
  log.debug("Leaving encodable().");
  return v;
}

// --- keys -----------------------------------------------------------------
function coseKeyToJwk(key) {
  log.debug("Entering coseKeyToJwk().");
  var kty = key.get(1);
  var out = { kty: kty === 2 ? "EC" : kty === 1 ? "OKP" : String(kty),
              crv: COSE_CRV[key.get(-1)] || String(key.get(-1)) };
  if (key.get(-2)) out.x = bytes.bytesToB64u(key.get(-2));
  if (key.get(-3) instanceof Uint8Array) {
    out.y = bytes.bytesToB64u(key.get(-3));
  }
  if (key.get(-4)) out.d = bytes.bytesToB64u(key.get(-4));
  log.debug("Leaving coseKeyToJwk().");
  return out;
}

function jwkToCoseKey(jwk) {
  log.debug("Entering jwkToCoseKey().");
  var m = new Map();
  m.set(1, jwk.kty === "EC" ? 2 : 1);
  m.set(-1, JWK_CRV[jwk.crv]);
  m.set(-2, bytes.b64uToBytes(jwk.x));
  if (jwk.y) m.set(-3, bytes.b64uToBytes(jwk.y));
  log.debug("Leaving jwkToCoseKey().");
  return m;
}

function importJwk(jwk, wantPrivate) {
  log.debug("Entering importJwk().");
  var clean = {};
  ["kty", "crv", "x", "y", "d"].forEach(function (k) {
    if (jwk[k] !== undefined && (k !== "d" || wantPrivate)) clean[k] = jwk[k];
  });
  log.debug("Leaving importJwk().");
  return provider.importKey(clean, { format: "jwk" });
}

function signerFor(alg, jwk) {
  log.debug("Entering signerFor(). " + alg);
  var id = SIG_ALGS[String(alg)];
  if (id === "eddsa") id = jwk && jwk.crv === "Ed448" ? "ed448" : "ed25519";
  if (!id) {
    log.debug("Leaving signerFor(). Unknown.");
    throw new Error("unsupported COSE signature algorithm " + alg + ".");
  }
  log.debug("Leaving signerFor(). " + id);
  return id;
}

// --- COSE_Sign1 -----------------------------------------------------------
function sigStructure(protectedBytes, payload) {
  log.debug("Entering sigStructure().");
  log.debug("Leaving sigStructure().");
  return mdoc.encode(["Signature1", protectedBytes, new Uint8Array(0),
                      payload]);
}

function sign1(protectedMap, unprotectedMap, payloadBytes, jwk) {
  log.debug("Entering sign1().");
  var protectedBytes = mdoc.encode(protectedMap);
  var sig = provider.sign(signerFor(protectedMap.get(H.alg), jwk),
                          importJwk(jwk, true),
                          sigStructure(protectedBytes, payloadBytes));
  log.debug("Leaving sign1().");
  return new cbor.Tagged(18, [protectedBytes, unprotectedMap, payloadBytes,
                              sig]);
}

function readSign1(item, what) {
  log.debug("Entering readSign1(). " + what);
  var v = item instanceof cbor.Tagged ? (item.tag === 18 ? item.value : null)
    : item;
  if (!Array.isArray(v) || v.length !== 4 ||
      !(v[0] instanceof Uint8Array) || !(v[2] instanceof Uint8Array)) {
    log.debug("Leaving readSign1(). Not a COSE_Sign1.");
    throw new Error("the " + what + " is not a COSE_Sign1.");
  }
  var out = { protectedBytes: v[0],
              protected: v[0].length ? cbor.decode(v[0]) : new Map(),
              unprotected: v[1] instanceof Map ? v[1] : new Map(),
              payloadBytes: v[2], payload: cbor.decode(v[2]),
              signature: v[3] };
  log.debug("Leaving readSign1().");
  return out;
}

function verifySign1(s, jwk) {
  log.debug("Entering verifySign1().");
  var ok;
  try {
    ok = provider.verify(signerFor(s.protected.get(H.alg), jwk),
                         importJwk(jwk), sigStructure(s.protectedBytes,
                         s.payloadBytes), s.signature);
  } catch (e) {
    log.debug("Leaving verifySign1(). " + e.message);
    return false;
  }
  log.debug("Leaving verifySign1(). " + ok);
  return ok;
}

// --- disclosures and restoration (sections 4.1 and 7) ---------------------
function hashAlgOf(s) {
  log.debug("Entering hashAlgOf().");
  var a = s.protected.get(H.sdAlg);
  var h = a === undefined ? "sha256" : HASHES[String(a)];
  if (!h) {
    log.debug("Leaving hashAlgOf(). Unsupported.");
    throw new Error("sd_alg " + a + " is not a hash this debugger supports " +
                    "(-16 SHA-256, -43 SHA-384, -44 SHA-512).");
  }
  log.debug("Leaving hashAlgOf(). " + h);
  return h;
}

// The Redacted Claim Hash of a disclosure given as its bstr contents.
function disclosureHash(hashAlg, disclosureBytes) {
  log.debug("Entering disclosureHash().");
  log.debug("Leaving disclosureHash().");
  return provider.digest(hashAlg, mdoc.encode(disclosureBytes));
}

// A table of the disclosures, by Redacted Claim Hash (hex).
function disclosureTable(hashAlg, list) {
  log.debug("Entering disclosureTable().");
  var table = {};
  var rows = [];
  (list || []).forEach(function (d) {
    var arr = cbor.decode(d);
    var h = hex(disclosureHash(hashAlg, d));
    var row = { hash: h, bytes: d, salt: arr[0],
                kind: arr.length === 3 ? "claim" : arr.length === 2 ?
                  "element" : "decoy",
                value: arr[1], key: arr[2] };
    if (!(arr[0] instanceof Uint8Array) || arr[0].length !== 16) {
      row.error = "its salt is not 16 bytes";
    }
    table[h] = row;
    rows.push(row);
  });
  log.debug("Leaving disclosureTable(). " + rows.length);
  return { table: table, rows: rows };
}

// Section 7: replace every Redacted Claim with its disclosure, recursing
// into what was disclosed. mode "holder" demands a disclosure for every
// Redacted Claim; "verifier" drops what is not disclosed.
function restore(node, table, mode, errors, used, path) {
  log.debug("Entering restore(). " + path);
  if (node instanceof Map) {
    var out = new Map();
    var redacted = null;
    node.forEach(function (v, k) {
      if (isSimple(k, REDACTED_KEYS)) {
        redacted = v;
      } else {
        out.set(k, restore(v, table, mode, errors, used, path + "/" + k));
      }
    });
    (Array.isArray(redacted) ? redacted : []).forEach(function (h) {
      var row = table[hex(h)];
      if (!row) {
        if (mode === "holder") {
          errors.push("a Redacted Claim Key at " + (path || "/") + " has no " +
                      "disclosure (section 6.2 requires one for each).");
        }
        return;
      }
      used[row.hash] = true;
      if (row.kind === "decoy") return;
      if (row.kind !== "claim") {
        errors.push("an array-element disclosure matches a Redacted Claim " +
                    "KEY at " + (path || "/") + ".");
        return;
      }
      if (out.has(row.key)) {
        errors.push("the disclosed claim " + JSON.stringify(row.key) +
                    " duplicates a claim already at " + (path || "/") +
                    " (section 9 step 9).");
        return;
      }
      out.set(row.key, restore(row.value, table, mode, errors, used,
                               path + "/" + row.key));
    });
    log.debug("Leaving restore(). Map.");
    return out;
  }
  if (Array.isArray(node)) {
    var arr = [];
    node.forEach(function (el, i) {
      if (!tagged(el, REDACTED_ELEMENT)) {
        arr.push(restore(el, table, mode, errors, used, path + "/" + i));
        return;
      }
      var row = table[hex(el.value)];
      if (!row) {
        if (mode === "holder") {
          errors.push("a Redacted Claim Element at " + path + "/" + i +
                      " has no disclosure.");
        }
        return;
      }
      used[row.hash] = true;
      if (row.kind === "decoy") return;
      if (row.kind !== "element") {
        errors.push("a claim-key disclosure matches a Redacted Claim " +
                    "ELEMENT at " + path + "/" + i + ".");
        return;
      }
      arr.push(restore(row.value, table, mode, errors, used, path + "/" + i));
    });
    log.debug("Leaving restore(). Array.");
    return arr;
  }
  if (node instanceof cbor.Tagged) {
    log.debug("Leaving restore(). Tagged.");
    return new cbor.Tagged(node.tag, restore(node.value, table, mode, errors,
                                             used, path));
  }
  log.debug("Leaving restore().");
  return node;
}

// Every Redacted Claim Hash anywhere in a node, disclosures included.
function hashesIn(node, out) {
  log.debug("Entering hashesIn().");
  if (node instanceof Map) {
    node.forEach(function (v, k) {
      if (isSimple(k, REDACTED_KEYS) && Array.isArray(v)) {
        v.forEach(function (h) {
          out.push(hex(h));
        });
      } else {
        hashesIn(v, out);
      }
    });
  } else if (Array.isArray(node)) {
    node.forEach(function (el) {
      if (tagged(el, REDACTED_ELEMENT)) {
        out.push(hex(el.value));
      } else {
        hashesIn(el, out);
      }
    });
  } else if (node instanceof cbor.Tagged) {
    hashesIn(node.value, out);
  }
  log.debug("Leaving hashesIn().");
  return out;
}

// --- issuance (sections 6 and 10) -----------------------------------------
function randomSalt() {
  log.debug("Entering randomSalt().");
  log.debug("Leaving randomSalt().");
  return provider.randomBytes(16);
}

function toMap(v) {
  log.debug("Entering toMap().");
  if (v instanceof Map || v === null || typeof v !== "object" ||
      v instanceof Uint8Array || v instanceof cbor.Tagged) {
    log.debug("Leaving toMap(). As is.");
    return Array.isArray(v) ? v.map(toMap) : v;
  }
  if (Array.isArray(v)) {
    log.debug("Leaving toMap(). Array.");
    return v.map(toMap);
  }
  var m = new Map();
  Object.keys(v).forEach(function (k) {
    m.set(/^-?\d+$/.test(k) ? Number(k) : k, toMap(v[k]));
  });
  log.debug("Leaving toMap(). Object.");
  return m;
}

function pathKey(p) {
  log.debug("Entering pathKey().");
  log.debug("Leaving pathKey().");
  return JSON.stringify(p);
}

// Redact `paths` (arrays of map keys and array indexes) in a claims Map,
// deepest first, so that a redacted container carries its own redacted
// members in its disclosure. Returns the disclosures (bstr contents).
function redact(claims, paths, hashAlg, decoys) {
  log.debug("Entering redact(). " + paths.length + " path(s).");
  var disclosures = [];
  var sorted = paths.slice().sort(function (a, b) {
    return b.length - a.length;
  });
  var done = {};
  sorted.forEach(function (p) {
    if (done[pathKey(p)]) return;
    done[pathKey(p)] = true;
    if (p.length === 1 && NEVER_REDACTED.indexOf(p[0]) !== -1) {
      throw new Error("claim " + (CLAIM_NAMES[p[0]] || p[0]) + " is never " +
                      "redacted (" + DRAFT + " Table 2).");
    }
    var parent = claims;
    for (var i = 0; i < p.length - 1; i++) {
      parent = parent instanceof Map ? parent.get(p[i]) : parent[p[i]];
      if (parent === undefined) {
        throw new Error("no claim at " + JSON.stringify(p) + ".");
      }
    }
    var last = p[p.length - 1];
    var d;
    if (parent instanceof Map) {
      if (!parent.has(last)) {
        throw new Error("no claim at " + JSON.stringify(p) + ".");
      }
      d = mdoc.encode([randomSalt(), parent.get(last), last]);
      parent.delete(last);
      var list = null;
      parent.forEach(function (v, k) {
        if (k instanceof mdoc.Simple && k.simple === REDACTED_KEYS) list = v;
      });
      if (!list) {
        list = [];
        parent.set(new mdoc.Simple(REDACTED_KEYS), list);
      }
      list.push(disclosureHash(hashAlg, d));
    } else if (Array.isArray(parent)) {
      d = mdoc.encode([randomSalt(), parent[last]]);
      parent[last] = new cbor.Tagged(REDACTED_ELEMENT,
                                     disclosureHash(hashAlg, d));
    } else {
      throw new Error("no map or array at " + JSON.stringify(p) + ".");
    }
    disclosures.push(d);
  });
  for (var n = 0; n < (decoys || 0); n++) {
    var decoy = mdoc.encode([randomSalt()]);
    var top = null;
    claims.forEach(function (v, k) {
      if (k instanceof mdoc.Simple && k.simple === REDACTED_KEYS) top = v;
    });
    if (!top) {
      top = [];
      claims.set(new mdoc.Simple(REDACTED_KEYS), top);
    }
    top.push(disclosureHash(hashAlg, decoy));
    disclosures.push(decoy);
  }
  log.debug("Leaving redact(). " + disclosures.length + " disclosure(s).");
  return disclosures;
}

// opts: claims (object or Map; integer-like keys become integers), redact
// ([path]), decoys (n), issuerKey (private JWK), alg (COSE; from the key
// when absent), kid (string or bytes), holderKey (public JWK, the cnf),
// sdAlg (-16 by default).
function issue(opts) {
  log.debug("Entering issue().");
  var claims = toMap(opts.claims);
  if (!opts.holderKey) {
    log.debug("Leaving issue(). No holder key.");
    throw new Error("an SD-CWT requires key binding: give the holder's key " +
                    "for its cnf claim (section 4).");
  }
  var cnf = new Map();
  cnf.set(1, jwkToCoseKey(opts.holderKey));
  claims.set(C.cnf, cnf);
  var sdAlg = opts.sdAlg || -16;
  var disclosures = redact(claims, opts.redact || [], HASHES[String(sdAlg)],
                           opts.decoys);
  var prot = new Map();
  prot.set(H.alg, opts.alg || ALG_FOR_CRV[opts.issuerKey.crv]);
  if (opts.kid !== undefined) {
    prot.set(H.kid, typeof opts.kid === "string" ? bytes.strBytes(opts.kid) :
             opts.kid);
  }
  prot.set(H.typ, TYP_SD_CWT);
  prot.set(H.sdAlg, sdAlg);
  var unprot = new Map();
  if (disclosures.length) unprot.set(H.sdClaims, disclosures);
  var out = mdoc.encode(sign1(prot, unprot, mdoc.encode(claims),
                              opts.issuerKey));
  log.debug("Leaving issue().");
  return out;
}

// --- reading ----------------------------------------------------------------
// opts.forceKind: "sd-cwt" | "kbt".
function parse(input) {
  log.debug("Entering parse().");
  var raw = input instanceof Uint8Array ? input :
    /^[0-9a-fA-F]+$/.test(String(input).trim()) ?
      bytes.hexToBytes(String(input).trim()) :
      bytes.b64uToBytes(String(input).trim());
  var item = cbor.decode(raw);
  var s = readSign1(item, "token");
  var typ = s.protected.get(H.typ);
  var kind = typ === TYP_KBT || typ === MEDIA_KBT || s.protected.has(H.kcwt) ?
    "kbt" : "sd-cwt";
  var out = { raw: raw, kind: kind, outer: s };
  if (kind === "kbt") {
    out.sdCwt = readSign1(s.protected.get(H.kcwt), "kcwt SD-CWT");
  } else {
    out.sdCwt = s;
  }
  log.debug("Leaving parse(). " + kind);
  return out;
}

function looksLikeSdCwt(input) {
  log.debug("Entering looksLikeSdCwt().");
  try {
    var p = parse(input);
    var typ = p.sdCwt.protected.get(H.typ);
    var ok = typ === TYP_SD_CWT || typ === MEDIA_SD_CWT ||
      (typeof typ === "string" && /\+sd-cwt$/.test(typ));
    log.debug("Leaving looksLikeSdCwt(). " + ok);
    return ok;
  } catch (e) {
    log.debug("Leaving looksLikeSdCwt(). " + e.message);
    return false;
  }
}

function numericTimes(m, errors, who) {
  log.debug("Entering numericTimes(). " + who);
  var t = {};
  ["exp", "nbf", "iat"].forEach(function (n) {
    var v = m.get(C[n]);
    if (v === undefined) return;
    if (typeof v !== "number" || !isFinite(v) ||
        Math.abs(v) > 9007199254740992) {
      errors.push(who + "'s " + n + " is not a finite NumericDate " +
                  "(section 5.2).");
      return;
    }
    t[n] = v;
  });
  log.debug("Leaving numericTimes().");
  return t;
}

function timeOrder(t, errors, who) {
  log.debug("Entering timeOrder(). " + who);
  if (t.nbf !== undefined && t.iat !== undefined && !(t.nbf <= t.iat)) {
    errors.push(who + ": nbf is after iat.");
  }
  if (t.nbf !== undefined && t.exp !== undefined && !(t.nbf < t.exp)) {
    errors.push(who + ": nbf is not before exp.");
  }
  if (t.iat !== undefined && t.exp !== undefined && !(t.iat < t.exp)) {
    errors.push(who + ": iat is not before exp.");
  }
  log.debug("Leaving timeOrder().");
}

function typOk(s, want, media) {
  log.debug("Entering typOk().");
  var typ = s.protected.get(H.typ);
  log.debug("Leaving typOk().");
  return typ === want || typ === media ||
    (want === TYP_SD_CWT && typeof typ === "string" &&
     /\+sd-cwt$/.test(typ));
}

// What an SD-CWT says, restored, with the bookkeeping both checks share.
function examine(s, mode, errors, warnings) {
  log.debug("Entering examine(). " + mode);
  var hashAlg = hashAlgOf(s);
  var list = s.unprotected.get(H.sdClaims);
  if (Array.isArray(list) && list.length === 0) {
    errors.push("sd_claims is an empty array (section 9 step 2).");
  }
  if (Array.isArray(s.unprotected.get(H.sdAeadClaims))) {
    if (s.unprotected.get(H.sdAeadClaims).length === 0) {
      errors.push("sd_aead_encrypted_claims is an empty array.");
    } else {
      warnings.push(s.unprotected.get(H.sdAeadClaims).length + " AEAD-" +
                    "encrypted disclosure(s) were ignored: this debugger " +
                    "holds no key for them (section 9 step 8).");
    }
  }
  var t = disclosureTable(hashAlg, list);
  t.rows.forEach(function (r) {
    if (r.error) errors.push("a disclosure is malformed: " + r.error + ".");
  });
  var used = {};
  var claims = restore(s.payload, t.table, mode, errors, used, "");
  var headerClaims = s.protected.get(H.cwtClaims);
  if (headerClaims instanceof Map) {
    var restoredHeader = restore(headerClaims, t.table, mode, errors, used,
                                 "#15");
    restoredHeader.forEach(function (v, k) {
      if (claims.has(k) && hex(mdoc.encode(encodable(claims.get(k)))) !==
          hex(mdoc.encode(encodable(v)))) {
        errors.push("claim " + (CLAIM_NAMES[k] || k) + " differs between " +
                    "the payload and the CWT Claims header (section 5.3).");
      }
    });
  }
  t.rows.forEach(function (r) {
    if (!used[r.hash]) {
      errors.push("a disclosure (" + r.kind + ", hash " +
                  r.hash.slice(0, 16) + "…) matches no Redacted Claim Hash " +
                  "(section 9 step 9).");
    }
  });
  var all = hashesIn(s.payload, []);
  log.debug("Leaving examine().");
  return { claims: claims, disclosures: t.rows, hashAlg: hashAlg,
           redactedCount: all.length };
}

// The holder's check of an ISSUED SD-CWT (section 6.2). opts: issuerKey
// (public JWK), holderKey (the holder's public JWK, to compare with cnf).
function confirm(input, opts) {
  log.debug("Entering confirm().");
  var o = opts || {};
  var errors = [];
  var warnings = [];
  var p;
  try {
    p = parse(input);
  } catch (e) {
    log.debug("Leaving confirm(). Unparseable.");
    return { valid: false, errors: [e.message], warnings: [] };
  }
  if (p.kind !== "sd-cwt") {
    log.debug("Leaving confirm(). A KBT.");
    return { valid: false, errors: ["this is a Key Binding Token, not an " +
             "issued SD-CWT."], warnings: [] };
  }
  var s = p.sdCwt;
  var r = null;
  try {
    if (!typOk(s, TYP_SD_CWT, MEDIA_SD_CWT)) {
      errors.push("typ is not 293 or application/sd-cwt (section 4).");
    }
    if (o.issuerKey && !verifySign1(s, o.issuerKey)) {
      errors.push("the issuer's signature does not verify.");
    }
    timeOrder(numericTimes(s.payload, errors, "SD-CWT"), errors, "SD-CWT");
    r = examine(s, "holder", errors, warnings);
    var cnf = (s.payload.get(C.cnf) || new Map()).get(1);
    if (!(cnf instanceof Map)) {
      errors.push("there is no COSE_Key in cnf (section 6).");
    } else if (o.holderKey && (coseKeyToJwk(cnf).x !== o.holderKey.x)) {
      errors.push("cnf names a key that is not the holder's.");
    }
  } catch (e) {
    errors.push(e.message);
  }
  log.debug("Leaving confirm(). " + errors.length + " error(s).");
  return { valid: errors.length === 0, errors: errors, warnings: warnings,
           parsed: p, claims: r && r.claims, disclosures: r && r.disclosures };
}

// --- presentation (section 8) ----------------------------------------------
// opts: disclose (a function(row) → boolean, or [hash hex]), holderKey
// (private JWK, the cnf key), alg (COSE; from the key when absent), aud,
// cnonce (bytes or string), iat (seconds; now when absent), cti.
function present(input, opts) {
  log.debug("Entering present().");
  var p = parse(input);
  if (p.kind !== "sd-cwt") {
    log.debug("Leaving present(). Not an issued SD-CWT.");
    throw new Error("present takes an issued SD-CWT.");
  }
  if (!opts.aud) {
    log.debug("Leaving present(). No aud.");
    throw new Error("a KBT must carry the Verifier as aud (section 8.1).");
  }
  var s = p.sdCwt;
  var t = disclosureTable(hashAlgOf(s), s.unprotected.get(H.sdClaims));
  var keep = t.rows.filter(function (r) {
    if (r.kind === "decoy") return false;
    return typeof opts.disclose === "function" ? opts.disclose(r) :
      (opts.disclose || []).indexOf(r.hash) !== -1;
  }).map(function (r) {
    return r.bytes;
  });
  var unprot = new Map();
  s.unprotected.forEach(function (v, k) {
    if (k !== H.sdClaims && k !== H.sdAeadClaims && k !== H.sdAead) {
      unprot.set(k, encodable(v));
    }
  });
  if (keep.length) unprot.set(H.sdClaims, keep);
  var inner = new cbor.Tagged(18, [s.protectedBytes, unprot, s.payloadBytes,
                                   s.signature]);
  var prot = new Map();
  prot.set(H.alg, opts.alg || ALG_FOR_CRV[opts.holderKey.crv]);
  prot.set(H.kcwt, inner);
  prot.set(H.typ, TYP_KBT);
  var payload = new Map();
  payload.set(C.aud, opts.aud);
  payload.set(C.iat, opts.iat !== undefined ? opts.iat :
              Math.floor(Date.now() / 1000));
  if (opts.cti !== undefined) payload.set(C.cti, opts.cti);
  if (opts.cnonce !== undefined) {
    payload.set(C.cnonce, typeof opts.cnonce === "string" ?
                bytes.strBytes(opts.cnonce) : opts.cnonce);
  }
  var out = mdoc.encode(sign1(prot, new Map(), mdoc.encode(payload),
                              opts.holderKey));
  log.debug("Leaving present(). " + keep.length + " disclosure(s).");
  return out;
}

// --- verification (section 9) -----------------------------------------------
// opts: issuerKey (public JWK) or resolveKey(kid bytes, protected Map) →
// JWK, aud (this Verifier), cnonce (expected; bytes or string), now
// (seconds; when given, exp/nbf are checked against it).
// Returns { valid, errors, warnings, claims (Map), disclosed, kbt }.
function verify(input, opts) {
  log.debug("Entering verify().");
  var o = opts || {};
  var errors = [];
  var warnings = [];
  var p;
  try {
    p = parse(input);
  } catch (e) {
    log.debug("Leaving verify(). Unparseable.");
    return { valid: false, errors: [e.message], warnings: [] };
  }
  if (p.kind !== "kbt") {
    log.debug("Leaving verify(). Not a KBT.");
    return { valid: false, warnings: [], errors: ["a presentation is a Key " +
             "Binding Token (section 8.1); this is an SD-CWT with none."] };
  }
  var kbt = p.outer;
  var s = p.sdCwt;
  var r = null;
  var kbtClaims = kbt.payload;
  try {
    if (!typOk(kbt, TYP_KBT, MEDIA_KBT)) {
      errors.push("the KBT's typ is not 294 or application/kb+cwt.");
    }
    if (!typOk(s, TYP_SD_CWT, MEDIA_SD_CWT)) {
      errors.push("the SD-CWT's typ is not 293 or application/sd-cwt.");
    }
    if (kbt.protected.has(H.cwtClaims)) {
      errors.push("a KBT's protected header must not carry CWT Claims.");
    }
    var issuerKey = o.issuerKey || (o.resolveKey ?
      o.resolveKey(s.protected.get(H.kid), s.protected) : null);
    if (!issuerKey) {
      errors.push("no issuer key to verify the SD-CWT with.");
    } else if (!verifySign1(s, issuerKey)) {
      errors.push("the issuer's signature on the SD-CWT does not verify.");
    }
    var st = numericTimes(s.payload, errors, "SD-CWT");
    timeOrder(st, errors, "SD-CWT");
    var cnf = (s.payload.get(C.cnf) || new Map()).get(1);
    if (!(cnf instanceof Map)) {
      errors.push("the SD-CWT's cnf carries no COSE_Key.");
    } else if (!verifySign1(kbt, coseKeyToJwk(cnf))) {
      errors.push("the KBT's signature by the cnf key does not verify.");
    }
    if (kbtClaims.has(C.iss) || kbtClaims.has(C.sub)) {
      errors.push("a KBT must carry neither iss nor sub (Table 3).");
    }
    if (o.aud !== undefined && kbtClaims.get(C.aud) !== o.aud) {
      errors.push("the KBT's aud (" + kbtClaims.get(C.aud) + ") is not " +
                  "this Verifier (" + o.aud + ").");
    }
    if (o.aud !== undefined && s.payload.has(C.aud) &&
        [].concat(s.payload.get(C.aud)).indexOf(o.aud) === -1) {
      errors.push("the SD-CWT's aud does not name this Verifier.");
    }
    if (o.cnonce !== undefined) {
      var want = typeof o.cnonce === "string" ? bytes.strBytes(o.cnonce) :
        o.cnonce;
      var got = kbtClaims.get(C.cnonce);
      if (!(got instanceof Uint8Array) || hex(got) !== hex(want)) {
        errors.push("the KBT's cnonce is not this request's.");
      }
    }
    var kt = numericTimes(kbtClaims, errors, "KBT");
    if (!kbtClaims.has(C.cti) && kt.iat === undefined) {
      errors.push("the KBT has neither iat nor cti (section 9 step 7).");
    }
    if (kt.iat === undefined && (kt.exp !== undefined ||
        kt.nbf !== undefined)) {
      errors.push("a KBT without iat carries no exp or nbf.");
    }
    timeOrder(kt, errors, "KBT");
    var both = function (a, b, test, msg) {
      if (a !== undefined && b !== undefined && !test(a, b)) {
        errors.push(msg);
      }
    };
    both(kt.exp, st.exp, function (a, b) {
      return a <= b;
    }, "the KBT outlives the SD-CWT (exp).");
    both(kt.nbf, st.nbf, function (a, b) {
      return a >= b;
    }, "the KBT's nbf is before the SD-CWT's.");
    both(kt.iat, st.iat, function (a, b) {
      return a >= b;
    }, "the KBT was made before the SD-CWT was issued.");
    both(kt.nbf, st.exp, function (a, b) {
      return a < b;
    }, "the KBT's nbf is after the SD-CWT expired.");
    both(kt.iat, st.exp, function (a, b) {
      return a < b;
    }, "the KBT was made after the SD-CWT expired.");
    both(kt.iat, st.nbf, function (a, b) {
      return a >= b;
    }, "the KBT was made before the SD-CWT was valid.");
    if (o.now !== undefined) {
      if (st.exp !== undefined && o.now >= st.exp) {
        errors.push("the SD-CWT has expired.");
      }
      if (st.nbf !== undefined && o.now < st.nbf) {
        errors.push("the SD-CWT is not yet valid.");
      }
    }
    r = examine(s, "verifier", errors, warnings);
  } catch (e) {
    errors.push(e.message);
  }
  log.debug("Leaving verify(). " + errors.length + " error(s).");
  return { valid: errors.length === 0, errors: errors, warnings: warnings,
           parsed: p, claims: r && r.claims,
           disclosed: r ? r.disclosures : [], kbtClaims: kbtClaims };
}

// A restored claims Map as plain JSON-friendly data, with the registered
// claim keys named (iss, sub, ...) and byte strings as base64url.
function toPlainClaims(claims) {
  log.debug("Entering toPlainClaims().");
  var plain = function (v) {
    if (v instanceof Map) {
      var o = {};
      v.forEach(function (val, k) {
        o[String(k)] = plain(val);
      });
      return o;
    }
    if (Array.isArray(v)) return v.map(plain);
    if (v instanceof Uint8Array) return bytes.bytesToB64u(v);
    if (v instanceof cbor.Tagged) return { tag: v.tag, value: plain(v.value) };
    return v;
  };
  var out = {};
  (claims || new Map()).forEach(function (v, k) {
    out[CLAIM_NAMES[k] || String(k)] = plain(v);
  });
  log.debug("Leaving toPlainClaims().");
  return out;
}

module.exports = {
  DRAFT: DRAFT,
  TYP_SD_CWT: TYP_SD_CWT,
  TYP_KBT: TYP_KBT,
  MEDIA_SD_CWT: MEDIA_SD_CWT,
  MEDIA_KBT: MEDIA_KBT,
  HEADER: H,
  CLAIMS: C,
  CLAIM_NAMES: CLAIM_NAMES,
  NEVER_REDACTED: NEVER_REDACTED,
  SIG_NAMES: SIG_NAMES,
  coseKeyToJwk: coseKeyToJwk,
  jwkToCoseKey: jwkToCoseKey,
  disclosureHash: disclosureHash,
  parse: parse,
  looksLikeSdCwt: looksLikeSdCwt,
  issue: issue,
  confirm: confirm,
  present: present,
  verify: verify,
  toPlainClaims: toPlainClaims
};
