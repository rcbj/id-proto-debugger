// File: sd_jwt_vp.js
//
// ---------------------------------------------------------------------------
// State and mechanics shared by the SD-JWT VC PRESENTATION pages.
//
//   sd-jwt-vc-presentation-0.html  choose how the presentation starts
//   sd-jwt-vc-presentation-1.html  the Verifier's Authorization Request
//   sd-jwt-vc-presentation-2.html  choose what to disclose, build and send it
//   sd-jwt-vc-presentation-3.html  what the Verifier decided, and why
//
// The issuance workflow (sd-jwt-vc-issuance-*.html) puts a credential in this
// browser's storage; this workflow is the other half — a Verifier asks for part
// of it, and the wallet presents exactly that part and no more.
//
// Two specifications meet here:
//
//   OID4VP 1.0  the protocol: an Authorization Request with response_type
//               vp_token, a DCQL query naming the claims wanted, a nonce, and a
//               response_mode saying how the answer travels back.
//   RFC 9901    the artifact: an SD-JWT+KB, which is the issuer-signed JWT, the
//               Disclosures the holder chose, and a Key Binding JWT signed by
//               the holder key the credential is bound to.
//
// The KB-JWT is what makes a presentation more than a copy of a credential: it
// is signed over THIS request's nonce, addressed to THIS verifier, and carries
// sd_hash — a digest of exactly the bytes being presented — so a presentation
// cannot be replayed, redirected, or edited after the holder signed it.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (a node-based test loading this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "sd_jwt_vp",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");

var KEYS = {
  // Which way the presentation is being started (see USE_CASES).
  USE_CASE: "sdjwtvp_use_case",
  // The Authorization Request in hand: { params, source, receivedAt, signed,
  // signatureVerdict, requestObject }.
  REQUEST: "sdjwtvp_request",
  // Which Disclosures the holder chose, by their base64url value — not by index,
  // because an index means nothing if the credential in hand changes.
  SELECTED: "sdjwtvp_selected_disclosures",
  // The presentation that was built and sent: { presentation, kbJwt, sdHash,
  // sentAt, responseUri, vpToken, response }.
  PRESENTATION: "sdjwtvp_presentation",
  // What the Verifier said: its verdict document, fetched from its result
  // endpoint, plus the wallet's own re-check.
  RESULT: "sdjwtvp_result",
  // Where this wallet looks for the Verifier's keys when a request is signed.
  // A pre-registered client's key is known out of band; for this workflow that
  // "out of band" is a configurable JWKS URL.
  VERIFIER_JWKS_URL: "sdjwtvp_verifier_jwks_url"
};

var STEP1_URL = "/sd-jwt-vc-presentation-1.html";
var STEP2_URL = "/sd-jwt-vc-presentation-2.html";
var STEP3_URL = "/sd-jwt-vc-presentation-3.html";

// The Key Binding JWT's media type and the algorithm this wallet signs with.
// ES256 because that is what the holder key generated during issuance is
// (P-256), and what both issuers in this repository advertise.
var KB_TYP = "kb+jwt";
var KB_ALG = "ES256";

// ---------------------------------------------------------------------------
// How the presentation starts.
//
// OID4VP section 3 describes the same-device and cross-device flows, and section
// 5 the two ways the request itself can travel: by value in the query, or by
// reference at a request_uri where it can be SIGNED. They are not different
// protocols — what differs is how the wallet gets the request and how much it
// can prove about who sent it — so the choice is made once, here.
// ---------------------------------------------------------------------------
var USE_CASES = [
  {
    id: "same-device",
    spec: "Same device",
    label: "Request by value",
    title: "A link on the verifier's page opens your wallet",
    summary: "You are on the verifier's web page on this device. Following its link hands your wallet the " +
             "whole Authorization Request in the query string.",
    detail: "The client_id uses the redirect_uri prefix, which means the request cannot be signed — there is " +
            "no key the wallet could check it against. What binds the request to the verifier is that the " +
            "presentation goes back to that same URL and nowhere else.",
    mechanics: "Request by value → wallet consent → vp_token POSTed to response_uri (direct_post).",
    available: true
  },
  {
    id: "same-device-signed",
    spec: "Same device",
    label: "Signed request by reference",
    title: "The wallet fetches a signed request",
    summary: "The link carries only client_id and request_uri. Your wallet fetches the Request Object from " +
             "there and checks its signature before showing you anything.",
    detail: "A pre-registered client with a known key, so the wallet can verify that the request really came " +
            "from the verifier it claims to be, and that nobody altered the claims being asked for on the way.",
    mechanics: "request_uri → signed Request Object (RFC 9101) → verify → consent → direct_post.",
    available: true
  },
  {
    id: "cross-device",
    spec: "Cross device",
    label: "QR code",
    title: "Scan the verifier's QR code",
    summary: "The verifier shows the request as a QR code on its own screen. Your wallet is on another " +
             "device, so nothing can be redirected — it reads the request from the code.",
    detail: "The presentation cannot come back through a redirect either, which is exactly why " +
            "response_mode=direct_post exists: the wallet POSTs it straight to the verifier.",
    mechanics: "QR code (openid4vp://) → wallet reads the request → direct_post.",
    available: true
  }
];

var DEFAULT_USE_CASE = "same-device";

function useCases() { return USE_CASES; }

function useCaseById(id) {
  for (var i = 0; i < USE_CASES.length; i++) {
    if (USE_CASES[i].id === id) return USE_CASES[i];
  }
  return null;
}

function currentUseCase() {
  return useCaseById(sdJwtVc.get(KEYS.USE_CASE)) || useCaseById(DEFAULT_USE_CASE);
}

function setUseCase(id) {
  var uc = useCaseById(id);
  if (!uc) return null;
  sdJwtVc.set(KEYS.USE_CASE, uc.id);
  if (typeof document !== "undefined" && document.getElementById("vp_use_case_badge")) {
    renderUseCaseBadge();
  }
  return uc;
}

// Which way this presentation is being made, in the step indicator every page
// includes.
function renderUseCaseBadge() {
  log.debug("Entering renderUseCaseBadge().");
  var host = typeof document === "undefined" ? null : document.getElementById("vp_steps");
  if (!host) return null;
  var uc = currentUseCase();
  var existing = document.getElementById("vp_use_case_badge");
  if (existing) existing.parentNode.removeChild(existing);
  var badge = document.createElement("p");
  badge.id = "vp_use_case_badge";
  badge.className = "vc-use-case-badge";
  badge.innerHTML = 'Flow: <strong>' + metadataClient.escapeHtmlText(uc.spec) + ' &middot; ' +
                    metadataClient.escapeHtmlText(uc.label) + '</strong> — ' +
                    metadataClient.escapeHtmlText(uc.mechanics) +
                    ' <a href="/sd-jwt-vc-presentation-0.html">change</a>';
  host.parentNode.insertBefore(badge, host.nextSibling);
  log.debug("Leaving renderUseCaseBadge().");
  return uc;
}

// --- the request in hand ----------------------------------------------------
function storeRequest(record) { sdJwtVc.setJson(KEYS.REQUEST, record); }
function storedRequest() { return sdJwtVc.getJson(KEYS.REQUEST); }
function forgetRequest() {
  sdJwtVc.remove(KEYS.REQUEST);
  sdJwtVc.remove(KEYS.SELECTED);
  sdJwtVc.remove(KEYS.PRESENTATION);
  sdJwtVc.remove(KEYS.RESULT);
}

// The Authorization Request parameters OID4VP defines, read out of a query
// string. Everything is a string on the wire; dcql_query and client_metadata are
// JSON-serialized objects (section 5.1), so they are parsed here.
var REQUEST_PARAMS = ["client_id", "response_type", "response_mode", "response_uri", "redirect_uri",
                      "nonce", "state", "dcql_query", "client_metadata", "request_uri",
                      "request_uri_method", "request", "scope", "transaction_data"];

function parseRequestQuery(search) {
  log.debug("Entering parseRequestQuery().");
  var params = {};
  var query = String(search || "").replace(/^[?#]/, "");
  if (!query) {
    log.debug("Leaving parseRequestQuery(). Nothing to parse.");
    return params;
  }
  query.split("&").forEach(function (pair) {
    if (!pair) return;
    var eq = pair.indexOf("=");
    var name = decodeURIComponent(eq < 0 ? pair : pair.slice(0, eq));
    var value = eq < 0 ? "" : decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, " "));
    if (REQUEST_PARAMS.indexOf(name) === -1) return;
    params[name] = value;
  });
  log.debug("Leaving parseRequestQuery(). " + Object.keys(params).length + " known parameter(s).");
  return params;
}

// A request can also arrive as the openid4vp:// URI a QR code carries, or as a
// whole URL. Both end in a query string, which is the part that matters.
function parseRequestUri(text) {
  log.debug("Entering parseRequestUri().");
  var raw = String(text || "").trim();
  var q = raw.indexOf("?");
  var params = parseRequestQuery(q >= 0 ? raw.slice(q + 1) : raw);
  log.debug("Leaving parseRequestUri().");
  return params;
}

// The JSON-valued parameters, parsed. Kept separate from parseRequestQuery so a
// malformed one is reported rather than throwing while the request is read.
function requestObjectValue(params, name) {
  var raw = params && params[name];
  if (!raw) return null;
  if (typeof raw === "object") return raw;
  try {
    return JSON.parse(raw);
  } catch (e) {
    log.error("the " + name + " parameter is not JSON: " + e.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// The DCQL query (OID4VP section 6).
//
// One entry per credential the verifier wants, each naming a format, the
// metadata it must match (for SD-JWT VC, the vct), and — the part that makes
// this a selective-disclosure request — the claim paths it is asking for.
// ---------------------------------------------------------------------------
function dcqlCredentialQueries(dcql) {
  var list = (dcql && dcql.credentials) || [];
  return Object.prototype.toString.call(list) === "[object Array]" ? list : [];
}

// The claim paths one credential query asks for, as dotted strings — the shape
// the rest of the workflow compares against a Disclosure's claim name.
function dcqlClaimPaths(credentialQuery) {
  log.debug("Entering dcqlClaimPaths().");
  var claims = (credentialQuery && credentialQuery.claims) || [];
  var out = [];
  if (Object.prototype.toString.call(claims) === "[object Array]") {
    claims.forEach(function (claim) {
      var path = claim && claim.path;
      if (Object.prototype.toString.call(path) === "[object Array]") out.push(path.join("."));
      else if (path) out.push(String(path));
    });
  }
  log.debug("Leaving dcqlClaimPaths(). " + out.length + " path(s).");
  return out;
}

// Every claim path the whole query asks for, and the credential query id the
// response has to be keyed by.
function requestedClaims(dcql) {
  var out = [];
  dcqlCredentialQueries(dcql).forEach(function (q) {
    dcqlClaimPaths(q).forEach(function (p) { if (out.indexOf(p) === -1) out.push(p); });
  });
  return out;
}

function firstCredentialQueryId(dcql) {
  var queries = dcqlCredentialQueries(dcql);
  return (queries[0] && queries[0].id) || "";
}

// Whether the verifier insists on a Key Binding JWT. The default is true
// (section 6.1): a presentation without holder binding is the exception, and the
// wallet should not guess it is allowed.
function requiresKeyBinding(credentialQuery) {
  if (!credentialQuery) return true;
  return credentialQuery.require_cryptographic_holder_binding !== false;
}

// ---------------------------------------------------------------------------
// Building the presentation.
// ---------------------------------------------------------------------------
// The bytes the KB-JWT is signed over: the issuer-signed JWT and the selected
// Disclosures, each followed by a tilde (RFC 9901 section 4.3.1). Note the
// trailing tilde — it is part of what is hashed.
function presentedPrefix(issuerJwt, selectedDisclosures) {
  return [issuerJwt].concat(selectedDisclosures || []).join("~") + "~";
}

// sd_hash: the base64url of the digest of the US-ASCII of those bytes, using the
// same hash the Disclosures use (_sd_alg, default sha-256).
function sdHash(prefix, sdAlg) {
  log.debug("Entering sdHash(). alg=" + (sdAlg || "sha-256"));
  var alg = String(sdAlg || "sha-256").toLowerCase();
  var webcrypto = { "sha-256": "SHA-256", "sha-384": "SHA-384", "sha-512": "SHA-512" }[alg];
  if (!webcrypto) return Promise.reject(new Error('unsupported _sd_alg "' + sdAlg + '".'));
  var bytes = new Uint8Array(prefix.length);
  for (var i = 0; i < prefix.length; i++) { bytes[i] = prefix.charCodeAt(i) & 0xff; }
  log.debug("Leaving sdHash().");
  return crypto.subtle.digest(webcrypto, bytes).then(function (buf) {
    return metadataClient.bytesToB64u(buf);
  });
}

// The Key Binding JWT (RFC 9901 section 4.3): typ kb+jwt, and a payload of
// exactly iat, aud, nonce and sd_hash. OID4VP fixes the first two of those: the
// nonce is the request's nonce, and the aud is the verifier's Client Identifier.
function signKbJwt(opts) {
  log.debug("Entering signKbJwt(). aud=" + opts.aud);
  var header = { typ: KB_TYP, alg: KB_ALG };
  var payload = {
    iat: Math.floor(Date.now() / 1000),
    aud: opts.aud,
    nonce: opts.nonce,
    sd_hash: opts.sdHash
  };
  var signingInput = metadataClient.utf8ToB64u(JSON.stringify(header)) + "." +
                     metadataClient.utf8ToB64u(JSON.stringify(payload));
  return crypto.subtle.importKey("jwk", opts.holderPrivateJwk,
      { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
    .then(function (key) {
      return crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, key,
        new TextEncoder().encode(signingInput));
    })
    .then(function (sig) {
      // Web Crypto returns raw r||s, which is the JWS ES256 encoding.
      log.debug("Leaving signKbJwt().");
      return { jwt: signingInput + "." + metadataClient.bytesToB64u(sig), header: header, payload: payload };
    });
}

// The whole presentation: the prefix above with the KB-JWT appended.
function buildPresentation(opts) {
  log.debug("Entering buildPresentation(). " + (opts.selected || []).length + " Disclosure(s) selected.");
  var parsed = opts.parsed || sdJwtVc.parseSdJwt(opts.credential);
  var prefix = presentedPrefix(parsed.issuerJwt, opts.selected || []);
  return sdHash(prefix, (parsed.payload || {})._sd_alg)
    .then(function (hash) {
      if (!opts.keyBinding) {
        // The verifier said a holder proof is not required, so the presentation
        // is the SD-JWT as it stands — including the trailing tilde that says
        // "no KB-JWT here".
        log.debug("Leaving buildPresentation(). No key binding required.");
        return { presentation: prefix, prefix: prefix, sdHash: hash, kb: null };
      }
      return signKbJwt({
        holderPrivateJwk: opts.holderPrivateJwk,
        aud: opts.aud,
        nonce: opts.nonce,
        sdHash: hash
      }).then(function (kb) {
        log.debug("Leaving buildPresentation(). Signed a KB-JWT.");
        return { presentation: prefix + kb.jwt, prefix: prefix, sdHash: hash, kb: kb };
      });
    });
}

// The vp_token: a JSON object keyed by the DCQL credential query id, each value
// an array of presentations (OID4VP section 8.1).
function vpToken(credentialQueryId, presentation) {
  var token = {};
  token[credentialQueryId || "credential"] = [presentation];
  return token;
}

// --- what was presented, read back off the wire -----------------------------
// The claim set a verifier ends up with, computed from the presentation itself
// rather than from what the wallet believes it sent.
function presentedClaims(presentation) {
  log.debug("Entering presentedClaims().");
  var parsed = sdJwtVc.parseSdJwt(presentation);
  var claims = sdJwtVc.disclosedClaims(parsed);
  delete claims.cnf;
  log.debug("Leaving presentedClaims(). " + Object.keys(claims).length + " claim(s).");
  return { parsed: parsed, claims: claims };
}

module.exports = {
  KEYS: KEYS,
  STEP1_URL: STEP1_URL,
  STEP2_URL: STEP2_URL,
  STEP3_URL: STEP3_URL,
  KB_TYP: KB_TYP,
  KB_ALG: KB_ALG,
  USE_CASES: USE_CASES,
  DEFAULT_USE_CASE: DEFAULT_USE_CASE,
  useCases: useCases,
  useCaseById: useCaseById,
  currentUseCase: currentUseCase,
  setUseCase: setUseCase,
  renderUseCaseBadge: renderUseCaseBadge,
  storeRequest: storeRequest,
  storedRequest: storedRequest,
  forgetRequest: forgetRequest,
  REQUEST_PARAMS: REQUEST_PARAMS,
  parseRequestQuery: parseRequestQuery,
  parseRequestUri: parseRequestUri,
  requestObjectValue: requestObjectValue,
  dcqlCredentialQueries: dcqlCredentialQueries,
  dcqlClaimPaths: dcqlClaimPaths,
  requestedClaims: requestedClaims,
  firstCredentialQueryId: firstCredentialQueryId,
  requiresKeyBinding: requiresKeyBinding,
  presentedPrefix: presentedPrefix,
  sdHash: sdHash,
  signKbJwt: signKbJwt,
  buildPresentation: buildPresentation,
  vpToken: vpToken,
  presentedClaims: presentedClaims
};
