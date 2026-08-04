// File: dpop.js
//
// ---------------------------------------------------------------------------
// DPoP — OAuth 2.0 Demonstrating Proof of Possession, RFC 9449. The wallet's
// half, with no DOM in it.
//
// What DPoP is for, in one line: it stops a stolen access token being usable.
// A Bearer token (RFC 6750) is a password — whoever holds the bytes may spend
// them. A DPoP-bound token names a public key in its `cnf.jkt` confirmation
// claim, and every request presenting it must carry a fresh signature from the
// matching private key over THAT request's method and URI. Copying the token is
// then not enough; you would need the key too.
//
// Where it belongs in these workflows:
//
//   OID4VCI  the Token Endpoint (section 6) and every protected endpoint the
//            issuer publishes — Credential, Deferred Credential, Notification.
//            The specification names DPoP twice: the Nonce Endpoint MAY return
//            a `DPoP-Nonce` for use "when presenting an access token at the
//            Credential Endpoint", and its Security Considerations say the use
//            of DPoP is RECOMMENDED for sender-constrained access tokens,
//            because mTLS is impractical for a native-app wallet.
//
//   OID4VP   nowhere. Its own words: "the result of an OpenID4VP interaction is
//            one or more Verifiable Presentations ... instead of an Access
//            Token". There is no token in that exchange to sender-constrain,
//            and the presentation's own proof of possession is the Key Binding
//            JWT. The presentation pages say so rather than offering a switch
//            that would do nothing.
//
// DPoP is also indifferent to the credential format. It binds an OAuth access
// token, not a credential, so it applies unchanged to `dc+sd-jwt`,
// `jwt_vc_json` and `ldp_vc` — nothing here reads the format.
//
// Everything in this module returns values. The pages own their own wording.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (a node-based test loading this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "dpop",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var metadataClient = require("./metadata_client");

// RFC 9449 section 4.2: the proof is explicitly typed, as RFC 8725 section 3.11
// recommends. A receiver that does not check `typ` will accept some other JWT
// the client signed with the same key as a DPoP proof, so this string is load
// bearing rather than decoration.
var PROOF_TYP = "dpop+jwt";

// The signature algorithms this wallet offers. RFC 9449 requires an asymmetric
// algorithm and forbids `none` and any MAC — a symmetric proof proves nothing,
// since the verifier would need the same secret and could mint proofs itself.
//
// ES256 first because it is what the OID4VCI credential proof already uses, so
// choosing Holder of Key (below) does not silently need a second algorithm.
var ALGS = {
  ES256: {
    generate: { name: "ECDSA", namedCurve: "P-256" },
    importAs: { name: "ECDSA", namedCurve: "P-256" },
    sign: { name: "ECDSA", hash: { name: "SHA-256" } },
    publicMembers: ["kty", "crv", "x", "y"]
  },
  RS256: {
    generate: {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    importAs: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
    sign: { name: "RSASSA-PKCS1-v1_5" },
    publicMembers: ["kty", "n", "e"]
  }
};
var DEFAULT_ALG = "ES256";

// Callers that return a promise turn this into a REJECTION rather than letting it
// escape synchronously. A function whose contract is "returns a promise" but which
// sometimes throws before returning one cannot be handled with `.catch()`, so a
// misconfigured algorithm would take the page down instead of filling in a status
// line — which is exactly what tests/dpop.js caught on its first run.
function algOrThrow(alg) {
  var spec = ALGS[alg || DEFAULT_ALG];
  if (!spec) {
    throw new Error("DPoP: " + alg + " is not an algorithm this wallet can sign with. " +
                    "RFC 9449 requires an asymmetric JWS algorithm; this page offers " +
                    Object.keys(ALGS).join(" and ") + ".");
  }
  return spec;
}

// ---------------------------------------------------------------------------
// The DPoP key pair.
//
// Only the public half ever leaves the browser, and it leaves in the clear: it
// travels in the `jwk` header of every proof, because the receiver has no other
// way to check the signature on a first request. That is not a weakness — the
// point is not to keep the key secret but to make the token useless without the
// PRIVATE half.
// ---------------------------------------------------------------------------
function generateKeyPair(alg) {
  log.debug("Entering generateKeyPair(). alg=" + (alg || DEFAULT_ALG));
  var name = alg || DEFAULT_ALG;
  var spec;
  try {
    spec = algOrThrow(name);
  } catch (e) {
    // Rejected rather than thrown, for the reason given at algOrThrow().
    log.debug("Leaving generateKeyPair(). Refused: " + e.message);
    return Promise.reject(e);
  }
  return crypto.subtle.generateKey(spec.generate, true, ["sign", "verify"])
    .then(function (pair) {
      return Promise.all([
        crypto.subtle.exportKey("jwk", pair.publicKey),
        crypto.subtle.exportKey("jwk", pair.privateKey)
      ]);
    })
    .then(function (jwks) {
      log.debug("Leaving generateKeyPair().");
      return {
        alg: name,
        // Only the members that identify the key. A stray `key_ops`/`ext` would
        // travel in every proof header and change the JWK Thumbprint's input if
        // anybody computed it over the whole object, so they are dropped here
        // rather than filtered at each use.
        publicJwk: publicOnly(jwks[0], spec),
        privateJwk: jwks[1]
      };
    });
}

function publicOnly(jwk, spec) {
  var out = {};
  spec.publicMembers.forEach(function (m) {
    if (jwk[m] !== undefined) out[m] = jwk[m];
  });
  return out;
}

// A key pair read back from storage carries no algorithm of its own, so it is
// inferred from the key type. This is also the guard that stops an `oct` key
// being used: RFC 9449 forbids a MAC, and a symmetric key has no public half to
// put in the header at all.
function algOfJwk(jwk) {
  if (!jwk || typeof jwk !== "object") return "";
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  if (jwk.kty === "RSA") return "RS256";
  return "";
}

// ---------------------------------------------------------------------------
// The JWK Thumbprint — RFC 7638, and the value that appears as `cnf.jkt` in a
// DPoP-bound access token (RFC 9449 section 6.1).
//
// Three things make this easy to get subtly wrong, and all three produce a
// thumbprint that looks perfectly well formed and matches nothing:
//
//   * only the REQUIRED members of the key type are included. `kid`, `alg`,
//     `use`, `key_ops` and `ext` are excluded — a key that gained a `kid` would
//     otherwise stop matching its own token.
//   * they are ordered LEXICOGRAPHICALLY by member name, which is not the order
//     Web Crypto exports them in.
//   * the JSON carries no whitespace at all.
//
// Checked against two published vectors: the EC key in RFC 9449's own worked
// example, whose thumbprint the same document prints as
// `0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I`, and the RSA key in RFC 7638
// section 3.1.
// ---------------------------------------------------------------------------
var THUMBPRINT_MEMBERS = {
  EC: ["crv", "kty", "x", "y"],
  RSA: ["e", "kty", "n"],
  OKP: ["crv", "kty", "x"],
  oct: ["k", "kty"]
};

function canonicalJwk(jwk) {
  log.debug("Entering canonicalJwk(). kty=" + (jwk && jwk.kty));
  if (!jwk || !jwk.kty) {
    throw new Error("a JWK Thumbprint needs a key with a kty.");
  }
  var members = THUMBPRINT_MEMBERS[jwk.kty];
  if (!members) {
    throw new Error("cannot compute a JWK Thumbprint for kty " + jwk.kty +
                    ": RFC 7638 defines the required members per key type and this is not one " +
                    "of them.");
  }
  var missing = members.filter(function (m) {
    return jwk[m] === undefined || jwk[m] === null || jwk[m] === "";
  });
  if (missing.length) {
    throw new Error("this " + jwk.kty + " key is missing " + missing.join(", ") +
                    ", which RFC 7638 requires in the thumbprint input.");
  }
  // Built member by member in the specification's order rather than by sorting
  // the key's own members, so a key carrying extras cannot change the result.
  var parts = members.map(function (m) {
    return JSON.stringify(m) + ":" + JSON.stringify(jwk[m]);
  });
  log.debug("Leaving canonicalJwk().");
  return "{" + parts.join(",") + "}";
}

function thumbprint(jwk) {
  log.debug("Entering thumbprint().");
  var canonical = canonicalJwk(jwk);
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))
    .then(function (digest) {
      log.debug("Leaving thumbprint().");
      return metadataClient.bytesToB64u(digest);
    });
}

// ---------------------------------------------------------------------------
// `htu` — RFC 9449 section 4.2: "the HTTP target URI ... without query and
// fragment parts".
//
// Section 4.3 also asks a receiver to apply RFC 3986 syntax-based and
// scheme-based normalization before comparing, so the sender does the same
// thing here and the two agree: a default port is dropped, the scheme and host
// are lowercased. Without that, `https://issuer.example:443/credential` and
// `https://issuer.example/credential` are the same endpoint and a byte
// comparison rejects the proof — a false negative that looks exactly like an
// attack.
// ---------------------------------------------------------------------------
function htuFor(url) {
  log.debug("Entering htuFor(). url=" + url);
  var parsed;
  try {
    parsed = new URL(String(url));
  } catch (e) {
    // Not something this wallet can normalize. Hand back what came in rather
    // than inventing a URL: the receiver's own comparison will refuse it, which
    // is a better failure than a proof that quietly claims the wrong endpoint.
    log.debug("Leaving htuFor(). Not a parseable URL; passing it through.");
    return String(url || "");
  }
  var scheme = parsed.protocol.toLowerCase();
  var host = parsed.hostname.toLowerCase();
  var port = parsed.port;
  if ((scheme === "https:" && port === "443") || (scheme === "http:" && port === "80")) {
    port = "";
  }
  var htu = scheme + "//" + host + (port ? ":" + port : "") + parsed.pathname;
  log.debug("Leaving htuFor(). htu=" + htu);
  return htu;
}

// `ath` — RFC 9449 section 4.2: the base64url of the SHA-256 of the ASCII
// encoding of the access token's value. Sent whenever the proof accompanies an
// access token, and it is what stops a proof captured from one request being
// replayed alongside a DIFFERENT token.
function athFor(accessToken) {
  log.debug("Entering athFor().");
  // ASCII, as the specification says. An access token is a JWT here, so it is
  // already ASCII; encoding it as UTF-8 would agree for every legal token and
  // disagree silently for an illegal one.
  var bytes = new Uint8Array(String(accessToken).length);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = String(accessToken).charCodeAt(i) & 0x7f;
  }
  return crypto.subtle.digest("SHA-256", bytes).then(function (digest) {
    log.debug("Leaving athFor().");
    return metadataClient.bytesToB64u(digest);
  });
}

// `jti` — RFC 9449 section 4.2 asks for at least 96 bits of pseudorandom data,
// so the receiver can detect a replayed proof. 128 bits here.
function newJti() {
  log.debug("Entering newJti().");
  var bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  log.debug("Leaving newJti().");
  return metadataClient.bytesToB64u(bytes);
}

// ---------------------------------------------------------------------------
// The proof itself.
//
// One per HTTP request, and never reusable: it names the method and the URI it
// was made for, so the proof that bought the access token at the token endpoint
// cannot be presented at the credential endpoint.
// ---------------------------------------------------------------------------
function proof(opts) {
  log.debug("Entering proof(). htm=" + opts.htm + ", htu=" + opts.htu +
            ", withToken=" + (opts.accessToken ? "yes" : "no") +
            ", withNonce=" + (opts.nonce ? "yes" : "no"));
  var key = opts.key || {};
  var alg = key.alg || algOfJwk(key.publicJwk) || DEFAULT_ALG;
  var spec;
  try {
    spec = algOrThrow(alg);
  } catch (e) {
    log.debug("Leaving proof(). Refused: " + e.message);
    return Promise.reject(e);
  }
  var header = { typ: PROOF_TYP, alg: alg, jwk: key.publicJwk };
  var payload = {
    jti: opts.jti || newJti(),
    htm: String(opts.htm || "POST").toUpperCase(),
    htu: htuFor(opts.htu),
    iat: Math.floor(Date.now() / 1000)
  };
  // A server-supplied nonce, when there is one. The server asks for it by
  // answering `use_dpop_nonce` with a `DPoP-Nonce` header, which is what makes
  // the proof's freshness the SERVER's judgement rather than a matter of
  // trusting the client's clock.
  if (opts.nonce) payload.nonce = opts.nonce;
  return Promise.resolve(opts.accessToken ? athFor(opts.accessToken) : null)
    .then(function (ath) {
      if (ath) payload.ath = ath;
      var signingInput = metadataClient.utf8ToB64u(JSON.stringify(header)) + "." +
                         metadataClient.utf8ToB64u(JSON.stringify(payload));
      return crypto.subtle.importKey("jwk", key.privateJwk, spec.importAs, false, ["sign"])
        .then(function (imported) {
          return crypto.subtle.sign(spec.sign, imported,
            new TextEncoder().encode(signingInput));
        })
        .then(function (sig) {
          log.debug("Leaving proof().");
          return {
            // Web Crypto returns ECDSA signatures as the raw r||s pair, which is
            // exactly the JWS encoding — no DER unwrapping needed.
            proof: signingInput + "." + metadataClient.bytesToB64u(sig),
            header: header,
            payload: payload
          };
        });
    });
}

// RFC 9449 section 7.1: a DPoP-bound token is presented with the `DPoP`
// authentication scheme, NOT `Bearer`. Presenting it as a Bearer token is a
// protocol error even though the bytes are identical, and a resource server
// that accepts either has thrown away the binding.
function authorizationHeader(accessToken) {
  return "DPoP " + accessToken;
}

// Did the server ask for a nonce? RFC 9449 sections 8 and 9: the authorization
// server answers 400 with `error: use_dpop_nonce`, a resource server answers
// 401 with the same error in `WWW-Authenticate`, and both supply the nonce in a
// `DPoP-Nonce` response header. Either way the client retries ONCE with it.
function nonceRequested(status, body, headers) {
  log.debug("Entering nonceRequested(). status=" + status);
  var wanted = false;
  if (body && body.error === "use_dpop_nonce") wanted = true;
  var authenticate = headers && (headers["www-authenticate"] || headers["WWW-Authenticate"]);
  if (authenticate && /use_dpop_nonce/.test(String(authenticate))) wanted = true;
  var nonce = headers ? (headers["dpop-nonce"] || headers["DPoP-Nonce"] || "") : "";
  log.debug("Leaving nonceRequested(). wanted=" + wanted + ", supplied=" + (nonce ? "yes" : "no"));
  return { wanted: wanted, nonce: String(nonce || "") };
}

// The `DPoP-Nonce` a fetch() Response carries, if any. Its own function because
// a Headers object is case-insensitive while a plain object is not, and both
// turn up here (the pages pass Headers, the tests pass objects).
function nonceFromResponse(response) {
  if (!response || !response.headers) return "";
  if (typeof response.headers.get === "function") {
    return response.headers.get("DPoP-Nonce") || "";
  }
  return response.headers["dpop-nonce"] || response.headers["DPoP-Nonce"] || "";
}

module.exports = {
  PROOF_TYP: PROOF_TYP,
  ALGS: Object.keys(ALGS),
  DEFAULT_ALG: DEFAULT_ALG,
  generateKeyPair: generateKeyPair,
  algOfJwk: algOfJwk,
  canonicalJwk: canonicalJwk,
  thumbprint: thumbprint,
  htuFor: htuFor,
  athFor: athFor,
  newJti: newJti,
  proof: proof,
  authorizationHeader: authorizationHeader,
  nonceRequested: nonceRequested,
  nonceFromResponse: nonceFromResponse
};
