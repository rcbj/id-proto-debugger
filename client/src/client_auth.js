// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: client_auth.js
//
// ---------------------------------------------------------------------------
// OAuth 2.0 CLIENT AUTHENTICATION at a token endpoint, one implementation
// for every token call a workflow makes. No DOM.
//
//   none                     RFC 6749 section 2.1: client_id in the body.
//   client_secret_basic      RFC 6749 section 2.3.1: HTTP Basic over the
//                            form-urlencoded client_id and secret (Appendix
//                            B), not over the raw strings.
//   client_secret_post       RFC 6749 section 2.3.1: both in the body.
//   client_secret_jwt        RFC 7523 section 2.2 / OpenID Connect Core 9:
//                            an HMAC client assertion keyed by the secret.
//   private_key_jwt          the same, signed by the client's private key.
//   attest_jwt_client_auth   draft-ietf-oauth-attestation-based-client-auth-
//                            12 (a DRAFT): the attester's Client Attestation
//                            in OAuth-Client-Attestation and a PoP by the
//                            instance key in OAuth-Client-Attestation-PoP,
//                            with the server's challenge when it sent one.
//
// A client assertion's aud is the authorization server's ISSUER identifier
// as its sole value and its typ client-authentication+jwt, as
// draft-ietf-oauth-rfc7523bis-11 requires; RFC 7523's original choice of
// the token endpoint URL stays selectable, because servers written before
// the update may expect it.
//
// SECRETS ARE NEVER STORED (root CLAUDE.md, "State persistence"): this
// module takes the secret as an argument and keeps nothing; the pages read
// it from a field typed on that page. What a request SHOWS has the secret
// replaced by <client_secret>.
// ---------------------------------------------------------------------------

var jws = require("./jws");
var bytes = require("./crypto_bytes");
var provider = require("./crypto_provider");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "client_auth",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var METHODS = ["none", "client_secret_basic", "client_secret_post",
               "client_secret_jwt", "private_key_jwt",
               "attest_jwt_client_auth"];
var LABELS = {
  none: "none (a public client)",
  client_secret_basic: "client_secret_basic (HTTP Basic)",
  client_secret_post: "client_secret_post (in the body)",
  client_secret_jwt: "client_secret_jwt (HMAC client assertion)",
  private_key_jwt: "private_key_jwt (signed client assertion, RFC 7523)",
  attest_jwt_client_auth: "attest_jwt_client_auth (Client Attestation, " +
    "DRAFT -12)"
};
var ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
var ASSERTION_TYP = "client-authentication+jwt";
var ATTESTATION_TYP = "oauth-client-attestation+jwt";
var POP_TYP = "oauth-client-attestation-pop+jwt";
var HEADER_ATTESTATION = "OAuth-Client-Attestation";
var HEADER_POP = "OAuth-Client-Attestation-PoP";
var HEADER_CHALLENGE = "OAuth-Client-Attestation-Challenge";
var NEEDS_SECRET = ["client_secret_basic", "client_secret_post",
                    "client_secret_jwt"];
var HMAC_ALGS = ["HS256", "HS384", "HS512"];
// jws.js algorithm ids for the JWS alg names a client assertion may carry.
var SIGN_ALGS = { ES256: "ES256", ES384: "ES384", ES512: "ES512",
                  ES256K: "ES256K", EdDSA: "EdDSA-Ed25519",
                  Ed25519: "Ed25519", PS256: "PS256", PS384: "PS384",
                  PS512: "PS512", RS256: "RS256", RS384: "RS384",
                  RS512: "RS512" };

// The default: the first method the server advertises that this module
// implements, in the server's order; none when it advertises nothing.
function defaultMethod(supported) {
  log.debug("Entering defaultMethod().");
  var list = Array.isArray(supported) ? supported : [];
  for (var i = 0; i < list.length; i++) {
    if (METHODS.indexOf(list[i]) !== -1) {
      log.debug("Leaving defaultMethod(). " + list[i]);
      return list[i];
    }
  }
  log.debug("Leaving defaultMethod(). none.");
  return "none";
}

// RFC 6749 Appendix B: application/x-www-form-urlencoded, per character.
function formEncode(value) {
  log.debug("Entering formEncode().");
  log.debug("Leaving formEncode().");
  return encodeURIComponent(String(value))
    .replace(/[!'()~]/g, function (c) {
      return "%" + c.charCodeAt(0).toString(16).toUpperCase();
    })
    .replace(/%20/g, "+");
}

function base64(text) {
  log.debug("Entering base64().");
  log.debug("Leaving base64().");
  return bytes.bytesToB64(bytes.strBytes(text));
}

function randomId() {
  log.debug("Entering randomId().");
  log.debug("Leaving randomId().");
  return bytes.bytesToB64u(provider.randomBytes(16));
}

// The JWS alg for a key when none was chosen.
function algForKey(jwk) {
  log.debug("Entering algForKey().");
  var byCrv = { "P-256": "ES256", "P-384": "ES384", "P-521": "ES512",
                "secp256k1": "ES256K", "Ed25519": "EdDSA" };
  log.debug("Leaving algForKey().");
  return jwk.kty === "RSA" ? "PS256" : byCrv[jwk.crv] || "ES256";
}

function signJwt(header, payload, key) {
  log.debug("Entering signJwt(). " + header.alg);
  var algId = HMAC_ALGS.indexOf(header.alg) !== -1 ? header.alg :
    SIGN_ALGS[header.alg];
  if (!algId) {
    log.debug("Leaving signJwt(). Unsupported.");
    return Promise.reject(new Error("unsupported client assertion alg " +
                                    header.alg + "."));
  }
  log.debug("Leaving signJwt().");
  return jws.signJwsAsync({ algId: algId, protectedHeader: header,
    payload: payload, privateKey: { jwk: key }, backend: "js" })
    .then(function (signed) {
      return signed.serialized;
    });
}

// The client assertion of RFC 7523 section 3 for client_secret_jwt or
// private_key_jwt. opts: clientId, audience, alg, kid, key (the private
// JWK, or for client_secret_jwt an oct JWK of the secret), typed (true:
// typ client-authentication+jwt), lifetime (seconds; 300), now, jti.
function clientAssertion(opts) {
  log.debug("Entering clientAssertion().");
  var now = opts.now || Math.floor(Date.now() / 1000);
  var header = { alg: opts.alg };
  if (opts.typed !== false) header.typ = ASSERTION_TYP;
  if (opts.kid) header.kid = opts.kid;
  var payload = { iss: opts.clientId, sub: opts.clientId, aud: opts.audience,
                  jti: opts.jti || randomId(), iat: now,
                  exp: now + (opts.lifetime || 300) };
  log.debug("Leaving clientAssertion().");
  return signJwt(header, payload, opts.key);
}

// The Client Attestation PoP JWT (draft -12 section 5.1): aud the AS
// issuer, a fresh jti, iat, and the server's challenge when there is one.
function attestationPop(opts) {
  log.debug("Entering attestationPop().");
  var header = { typ: POP_TYP, alg: opts.alg || algForKey(opts.instanceKey) };
  var payload = { aud: opts.issuer, jti: opts.jti || randomId(),
                  iat: opts.now || Math.floor(Date.now() / 1000) };
  if (opts.challenge) payload.challenge = opts.challenge;
  log.debug("Leaving attestationPop().");
  return signJwt(header, payload, opts.instanceKey);
}

// What the attestation names: its sub and cnf key (read, not verified —
// verifying it is the server's job against an attester it trusts).
function readAttestation(jwt) {
  log.debug("Entering readAttestation().");
  var parts = String(jwt || "").trim().split(".");
  if (parts.length !== 3) {
    log.debug("Leaving readAttestation(). Not a JWT.");
    throw new Error("the Client Attestation is not a compact JWT.");
  }
  var header = JSON.parse(bytes.bytesToStr(bytes.b64uToBytes(parts[0])));
  var payload = JSON.parse(bytes.bytesToStr(bytes.b64uToBytes(parts[1])));
  log.debug("Leaving readAttestation().");
  return { header: header, payload: payload,
           cnfJwk: (payload.cnf || {}).jwk || null };
}

// A Client Attestation made HERE, by an attester key the user supplies or
// generates — for testing against a server told to trust that key; a real
// one comes from the wallet provider. opts: attesterKey (private JWK), kid,
// clientId, instanceKey (public JWK), lifetime (seconds; 86400).
function makeAttestation(opts) {
  log.debug("Entering makeAttestation().");
  var now = Math.floor(Date.now() / 1000);
  var pub = {};
  ["kty", "crv", "x", "y", "n", "e"].forEach(function (k) {
    if (opts.instanceKey[k] !== undefined) pub[k] = opts.instanceKey[k];
  });
  var header = { typ: ATTESTATION_TYP,
                 alg: opts.alg || algForKey(opts.attesterKey) };
  if (opts.kid) header.kid = opts.kid;
  log.debug("Leaving makeAttestation().");
  return signJwt(header, { sub: opts.clientId, iat: now,
    exp: now + (opts.lifetime || 86400), cnf: { jwk: pub } },
    opts.attesterKey);
}

// Apply a method to a token request. opts: method, clientId, secret,
// issuer (the AS issuer identifier), tokenEndpoint, audienceChoice
// ("issuer" | "token_endpoint"), alg, kid, signingKey (private JWK,
// private_key_jwt), typed, attestation (JWT), instanceKey (private JWK),
// challenge. Returns a Promise of { params, headers, shownParams,
// shownHeaders, notes } — params and headers to ADD to the request; the
// shown ones with the secret replaced.
function apply(opts) {
  log.debug("Entering apply(). " + opts.method);
  var method = opts.method || "none";
  var out = { params: {}, headers: {}, shownParams: {}, shownHeaders: {},
              notes: [] };
  var both = function (k, v, shown) {
    out.params[k] = v;
    out.shownParams[k] = shown === undefined ? v : shown;
  };
  if (METHODS.indexOf(method) === -1) {
    log.debug("Leaving apply(). Unknown method.");
    return Promise.reject(new Error("unknown client authentication method " +
                                    method + "."));
  }
  if (NEEDS_SECRET.indexOf(method) !== -1 && !opts.secret) {
    log.debug("Leaving apply(). No secret.");
    return Promise.reject(new Error(method + " needs the client secret, " +
      "typed on this page (it is never stored)."));
  }
  if (!opts.clientId && method !== "attest_jwt_client_auth") {
    log.debug("Leaving apply(). No client_id.");
    return Promise.reject(new Error("no client_id is configured."));
  }
  if (method === "none") {
    both("client_id", opts.clientId);
    log.debug("Leaving apply(). none.");
    return Promise.resolve(out);
  }
  if (method === "client_secret_basic") {
    out.headers.Authorization = "Basic " + base64(formEncode(opts.clientId) +
                                                  ":" +
                                                  formEncode(opts.secret));
    out.shownHeaders.Authorization = "Basic base64(" +
      formEncode(opts.clientId) + ":<client_secret>)";
    log.debug("Leaving apply(). basic.");
    return Promise.resolve(out);
  }
  if (method === "client_secret_post") {
    both("client_id", opts.clientId);
    both("client_secret", opts.secret, "<client_secret>");
    log.debug("Leaving apply(). post.");
    return Promise.resolve(out);
  }
  if (method === "client_secret_jwt" || method === "private_key_jwt") {
    var audience = opts.audienceChoice === "token_endpoint" ?
      opts.tokenEndpoint : opts.issuer;
    if (!audience) {
      log.debug("Leaving apply(). No audience.");
      return Promise.reject(new Error("a client assertion's aud is the " +
        "authorization server's issuer identifier, and none is known " +
        "(retrieve its metadata first)."));
    }
    var key;
    var alg = opts.alg;
    if (method === "client_secret_jwt") {
      key = { kty: "oct", k: bytes.bytesToB64u(bytes.strBytes(opts.secret)) };
      alg = HMAC_ALGS.indexOf(alg) !== -1 ? alg : "HS256";
    } else {
      key = opts.signingKey;
      if (!key || !key.d) {
        log.debug("Leaving apply(). No private key.");
        return Promise.reject(new Error("private_key_jwt needs the client's " +
          "private key: generate one or paste it (a JWK)."));
      }
      alg = alg && HMAC_ALGS.indexOf(alg) === -1 ? alg : algForKey(key);
    }
    if (opts.audienceChoice === "token_endpoint") {
      out.notes.push("aud is the token endpoint URL (RFC 7523 as " +
        "published); draft-ietf-oauth-rfc7523bis-11 requires the issuer " +
        "identifier as the sole value instead.");
    }
    log.debug("Leaving apply(). Signing an assertion.");
    return clientAssertion({ clientId: opts.clientId, audience: audience,
      alg: alg, kid: opts.kid, key: key, typed: opts.typed })
      .then(function (assertion) {
        both("client_id", opts.clientId);
        both("client_assertion_type", ASSERTION_TYPE);
        both("client_assertion", assertion);
        return out;
      });
  }
  // attest_jwt_client_auth
  if (!opts.attestation || !opts.instanceKey || !opts.instanceKey.d) {
    log.debug("Leaving apply(). No attestation.");
    return Promise.reject(new Error("attest_jwt_client_auth needs a Client " +
      "Attestation and the private instance key its cnf names."));
  }
  if (!opts.issuer) {
    log.debug("Leaving apply(). No issuer.");
    return Promise.reject(new Error("the Client Attestation PoP's aud is " +
      "the authorization server's issuer identifier, and none is known."));
  }
  var att;
  try {
    att = readAttestation(opts.attestation);
  } catch (e) {
    log.debug("Leaving apply(). " + e.message);
    return Promise.reject(e);
  }
  if (opts.clientId && att.payload.sub !== opts.clientId) {
    out.notes.push("the attestation's sub (" + att.payload.sub + ") is not " +
      "the configured client_id; the server must refuse that (section " +
      "7.5).");
  }
  log.debug("Leaving apply(). Signing a PoP.");
  return attestationPop({ issuer: opts.issuer, instanceKey: opts.instanceKey,
                          challenge: opts.challenge })
    .then(function (pop) {
      out.headers[HEADER_ATTESTATION] = String(opts.attestation).trim();
      out.headers[HEADER_POP] = pop;
      out.shownHeaders[HEADER_ATTESTATION] = out.headers[HEADER_ATTESTATION];
      out.shownHeaders[HEADER_POP] = pop;
      if (opts.clientId) both("client_id", opts.clientId);
      return out;
    });
}

// A token request's text with the method applied, for the page to show.
function describe(method, url, baseParams, applied) {
  log.debug("Entering describe().");
  var lines = ["POST " + url, "Content-Type: " +
               "application/x-www-form-urlencoded"];
  Object.keys(applied.shownHeaders).forEach(function (h) {
    lines.push(h + ": " + applied.shownHeaders[h]);
  });
  var params = Object.assign({}, baseParams, applied.shownParams);
  lines.push("");
  lines.push(Object.keys(params).map(function (k) {
    return formEncode(k) + "=" + formEncode(params[k]);
  }).join("&"));
  log.debug("Leaving describe().");
  return lines.join("\n");
}

// The challenge a response carries (section 6.1/6.2), from a headers object
// whose names are lower-cased.
function challengeOf(headersLower) {
  log.debug("Entering challengeOf().");
  log.debug("Leaving challengeOf().");
  return (headersLower || {})[HEADER_CHALLENGE.toLowerCase()] || "";
}

module.exports = {
  METHODS: METHODS,
  LABELS: LABELS,
  ASSERTION_TYPE: ASSERTION_TYPE,
  ASSERTION_TYP: ASSERTION_TYP,
  ATTESTATION_TYP: ATTESTATION_TYP,
  POP_TYP: POP_TYP,
  HEADER_ATTESTATION: HEADER_ATTESTATION,
  HEADER_POP: HEADER_POP,
  HEADER_CHALLENGE: HEADER_CHALLENGE,
  NEEDS_SECRET: NEEDS_SECRET,
  defaultMethod: defaultMethod,
  formEncode: formEncode,
  clientAssertion: clientAssertion,
  attestationPop: attestationPop,
  readAttestation: readAttestation,
  makeAttestation: makeAttestation,
  apply: apply,
  describe: describe,
  challengeOf: challengeOf
};
