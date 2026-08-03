// File: jwt_vc_json_common.js
//
// ---------------------------------------------------------------------------
// The parts of a jwt_vc_json test that do not depend on WHOSE issuer or verifier
// is on the other end.
//
// Four tests use this — issuance and presentation, against the mock STS and
// against walt.id — and they differ only in the base URLs they are handed and in
// what they are allowed to assume about the implementation. Everything else (how
// a credential of this format is obtained, what it must look like, how a
// Verifiable Presentation JWT is built and submitted) is the same, so it lives
// here rather than four times over.
//
// Why jwt_vc_json needs its own tests rather than a flag on the SD-JWT ones: the
// two formats differ in the thing those tests are ABOUT. The SD-JWT suites are
// built around Disclosures — selecting them, hashing them, withholding them, the
// sd_hash that commits to exactly which ones went. None of that exists here.
// Threading a format flag through them would leave most of their assertions
// skipped and the rest reading as though selective disclosure had merely been
// declined, which is not the same statement as "this format cannot do it".
// ---------------------------------------------------------------------------

const crypto = require("crypto");
const assert = require("assert");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "jwt_vc_json_common",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // Loaded outside a configured run: info is the useful default and a
      // missing config file is not a reason to fail to load.
      return "info";
    }
  })()
});

const FORMAT = "jwt_vc_json";

// The wallet's client identifier, used in TWO places that must agree: the
// client_id sent with the pre-authorized code grant, and the iss of the proof of
// possession. walt.id enforces that they match ("Credential proof issuer claim
// must match the access token client_id") and it is right to — a proof made by
// one client and presented by another proves nothing about the presenter. Our
// mock does not check, so a mismatch only shows up against walt.id, which is
// exactly the kind of thing an interoperability run is for.
const WALLET_CLIENT_ID = process.env.OID4VCI_WALLET_CLIENT_ID || "idptools-debugger-tests";

function b64u(buf) { return Buffer.from(buf).toString("base64url"); }
function b64uDecode(s) { return Buffer.from(String(s), "base64url"); }
function jsonFromB64u(s) { return JSON.parse(b64uDecode(s).toString("utf8")); }

async function httpJson(url, options) {
  let r;
  try {
    r = await fetch(url, options);
  } catch (e) {
    // A refused connection or an unresolvable host arrives as an undici
    // TypeError whose message is "fetch failed" and whose stack is all internals.
    // These tests fail rather than skip when a service is missing, so the
    // failure has to name WHICH service and WHERE — the raw error names neither.
    const err = new Error("could not reach " + url + ": " + (e.cause ? e.cause.message : e.message) +
      ". Is the service running, and is its URL right?");
    err.cause = e;
    throw err;
  }
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // Not JSON — an HTML error page, or an empty body. The caller reports the
    // status and the raw text, which says more than a parse error would.
    body = raw;
  }
  return { ok: r.ok, status: r.status, body: body, raw: raw };
}

// An issuer's credential issuer metadata. The well-known is INSERTED before the
// issuer's path rather than appended (RFC 8414), which is what walt.id needs —
// its Credential Issuer Identifier is `…/openid4vci`, so the document lives at
// `…/.well-known/openid-credential-issuer/openid4vci`. Appending finds nothing.
// Both forms are tried, insertion first, because the mock issuer has no path and
// either works for it.
async function issuerMetadata(issuerBase) {
  log.debug("Entering issuerMetadata(). issuerBase=" + issuerBase);
  const base = String(issuerBase || "").replace(/\/+$/, "");
  let origin = base;
  let path = "";
  try {
    const u = new URL(base);
    origin = u.origin;
    path = u.pathname.replace(/\/+$/, "");
  } catch (e) {
    // Not an absolute URL: fall back to appending, which is all that can be done.
    log.debug("issuerMetadata(): " + base + " is not an absolute URL.");
  }
  const candidates = [];
  if (path) candidates.push(origin + "/.well-known/openid-credential-issuer" + path);
  candidates.push(base + "/.well-known/openid-credential-issuer");
  for (let i = 0; i < candidates.length; i++) {
    const r = await httpJson(candidates[i]);
    if (r.ok && r.body && r.body.credential_issuer) {
      log.debug("Leaving issuerMetadata(). Found at " + candidates[i]);
      return r.body;
    }
  }
  log.debug("Leaving issuerMetadata(). Nothing at " + candidates.join(" or "));
  return null;
}

// The credential_configuration_id this issuer offers in jwt_vc_json, or "" when
// it offers none.
//
// Returned rather than asserted so a caller can SKIP. The mock issuer and
// walt.id name their configurations differently — and walt.id only offers the
// format once its configuration has been added and the container restarted — so
// a test that hard-coded an id would fail for a configuration reason wearing the
// costume of a protocol failure.
async function jwtVcJsonConfigurationId(issuerBase) {
  log.debug("Entering jwtVcJsonConfigurationId().");
  const meta = await issuerMetadata(issuerBase);
  if (!meta) {
    log.debug("Leaving jwtVcJsonConfigurationId(). No metadata.");
    return { id: "", meta: null };
  }
  const configs = meta.credential_configurations_supported || {};
  const preferred = process.env.OID4VCI_JWT_VC_CONFIG_ID || "";
  if (preferred && configs[preferred] && configs[preferred].format === FORMAT) {
    log.debug("Leaving jwtVcJsonConfigurationId(). Using the configured " + preferred);
    return { id: preferred, meta: meta, entry: configs[preferred] };
  }
  const found = Object.keys(configs).filter(function (id) {
    return configs[id] && configs[id].format === FORMAT;
  });
  log.debug("Leaving jwtVcJsonConfigurationId(). " + found.length + " jwt_vc_json configuration(s).");
  return { id: found[0] || "", meta: meta, entry: found[0] ? configs[found[0]] : null };
}

// A real access token from an issuer that insists on one.
//
// Our mock accepts any bearer string, so the tests against it can send an opaque
// placeholder. walt.id cannot: it refuses anything that is not a JWS
// ("String does not look like JWS"), which is correct of it and is what made the
// first version of these tests fail with a 401 that looked like a jwt_vc_json
// problem and was not.
//
// The token is obtained with the PRE-AUTHORIZED CODE grant rather than by
// driving a browser through Keycloak. That grant exists precisely so a credential
// can be collected without an interactive authorization leg, walt.id advertises
// it, and it keeps this helper usable from a test with no browser. The
// authorization-code leg through the pages is already covered end to end by
// sd_jwt_vc_waltid.js; repeating it here would test the same thing twice and
// double the slowest part of the suite.
//
// Returns "" when the issuer offers no such route, so the caller can fall back to
// an opaque token — which is exactly right for the mock.
async function preAuthorizedAccessToken(issuerBase, profileId) {
  log.debug("Entering preAuthorizedAccessToken(). profileId=" + profileId);
  var base = String(issuerBase || "").replace(/\/+$/, "");
  var origin = base;
  try {
    origin = new URL(base).origin;
  } catch (e) {
    // Not absolute; the offer call below will fail and "" is returned.
    log.debug("preAuthorizedAccessToken(): " + base + " is not an absolute URL.");
  }
  var created = await httpJson(origin + "/issuer2/credential-offers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ profileId: profileId, authMethod: "PRE_AUTHORIZED", valueMode: "BY_VALUE" })
  }).catch(function () { return { ok: false, status: 0, raw: "" }; });
  if (created.status !== 201 && created.status !== 200) {
    log.debug("Leaving preAuthorizedAccessToken(). No offer endpoint (HTTP " + created.status + ").");
    return "";
  }
  var offerUri = String((created.body || {}).credentialOffer || "");
  var offerParam = "";
  try {
    offerParam = new URL(offerUri.replace("openid-credential-offer://", "https://wallet.invalid/"))
      .searchParams.get("credential_offer") || "";
  } catch (e) {
    offerParam = "";
  }
  if (!offerParam) {
    log.debug("Leaving preAuthorizedAccessToken(). The offer was not passed by value.");
    return "";
  }
  var offer = JSON.parse(offerParam);
  var grant = (offer.grants || {})["urn:ietf:params:oauth:grant-type:pre-authorized_code"] || {};
  var code = grant["pre-authorized_code"];
  if (!code) {
    log.debug("Leaving preAuthorizedAccessToken(). The offer carries no pre-authorized code.");
    return "";
  }

  var meta = await issuerMetadata(issuerBase);
  var asUrl = origin + "/.well-known/oauth-authorization-server" +
              (function () { try { return new URL(base).pathname.replace(/\/+$/, ""); } catch (e) { return ""; } })();
  var as = await httpJson(asUrl);
  var tokenEndpoint = ((as.body || {}).token_endpoint) || ((meta || {}).token_endpoint) || "";
  if (!tokenEndpoint) {
    log.debug("Leaving preAuthorizedAccessToken(). No token endpoint advertised.");
    return "";
  }
  // A client_id, always. The pre-authorized code grant has no client
  // authentication of its own, so it is tempting to send nothing — and walt.id
  // refuses that outright with "Anonymous pre-authorized code access is not
  // supported". It says so in its metadata too, as
  // pre-authorized_grant_anonymous_access_supported: false, which is the
  // machine-readable version of the same sentence and is logged below when it is
  // present. Sending an identifier costs nothing where it is not required.
  var anonymousOk = (as.body || {})["pre-authorized_grant_anonymous_access_supported"];
  if (anonymousOk === false) {
    log.debug("preAuthorizedAccessToken(): this issuer requires a client_id for the pre-authorized grant.");
  }
  var body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": code,
    client_id: WALLET_CLIENT_ID
  }).toString();
  var token = await httpJson(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body
  });
  var accessToken = (token.body || {}).access_token || "";
  log.debug("Leaving preAuthorizedAccessToken(). " + (accessToken ? "got a token" : "no token: " +
            String(token.raw).slice(0, 160)));
  return accessToken;
}

// Ask the issuer for a jwt_vc_json credential, with a real proof of possession.
//
// The access token is deliberately whatever the caller was given (the mock
// accepts an opaque one); this helper is about the CREDENTIAL, not about how the
// authorization was obtained — the SD-JWT suites already cover that path in
// full, through the pages.
// `proofKeyMode` says how the proof of possession identifies the holder, and the
// two issuers genuinely differ:
//
//   "jwk"  the public key inline in the proof header. Our mock reads header.jwk
//          and binds the credential with cnf.jwk.
//   "did"  a did:jwk in the header's kid. walt.id's jwt_vc_json profile binds
//          with credentialSubject.id = "<subjectDid>", and it resolves that from
//          the proof — hand it a bare jwk and it refuses the request with
//          "Cannot find in context: subjectDid", because there is no DID to put
//          in the credential.
//
// Neither is wrong and the specification permits both, which is why this is a
// parameter rather than a fix. It is also the substance of the interoperability
// finding: a wallet that only ever talked to one of these two would have no idea
// the other existed.
function didJwkFor(publicJwk) {
  var ordered = { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x };
  if (publicJwk.y) ordered.y = publicJwk.y;
  return "did:jwk:" + b64u(JSON.stringify(ordered));
}

async function mintJwtVcJson(issuerBase, configurationId, accessToken, proofKeyMode) {
  log.debug("Entering mintJwtVcJson(). configurationId=" + configurationId +
            ", proofKeyMode=" + (proofKeyMode || "jwk"));
  const meta = await issuerMetadata(issuerBase);
  assert.ok(meta && meta.credential_endpoint, "the issuer should publish a credential_endpoint.");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  const privateJwk = pair.privateKey.export({ format: "jwk" });

  let nonce = "";
  if (meta.nonce_endpoint) {
    const n = await httpJson(meta.nonce_endpoint, { method: "POST" });
    nonce = (n.body && n.body.c_nonce) || "";
  }
  const compact = { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y };
  const did = didJwkFor(compact);
  const head = b64u(JSON.stringify(
    proofKeyMode === "did"
      ? { typ: "openid4vci-proof+jwt", alg: "ES256", kid: did + "#0" }
      : { typ: "openid4vci-proof+jwt", alg: "ES256", jwk: compact }));
  const claims = b64u(JSON.stringify({
    // iss MUST be the client the access token was issued to — see WALLET_CLIENT_ID.
    iss: WALLET_CLIENT_ID, aud: meta.credential_issuer,
    iat: Math.floor(Date.now() / 1000), nonce: nonce
  }));
  const sig = b64u(crypto.sign("sha256", Buffer.from(head + "." + claims),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" }));

  const response = await httpJson(meta.credential_endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + (accessToken || "jwt-vc-json-test-token")
    },
    body: JSON.stringify({
      credential_configuration_id: configurationId,
      proofs: { jwt: [head + "." + claims + "." + sig] }
    })
  });
  assert.ok(response.ok,
    "the issuer should mint a " + FORMAT + " credential for configuration \"" + configurationId +
    "\", got HTTP " + response.status + " " + String(response.raw).slice(0, 300));

  const credential = (((response.body || {}).credentials || [])[0] || {}).credential ||
                     (response.body || {}).credential;
  assert.ok(credential, "the Credential Response should carry a credential: " +
    String(response.raw).slice(0, 300));
  log.debug("Leaving mintJwtVcJson().");
  return {
    credential: credential,
    // The whole Credential Response, so a caller can hand the issuer's ACTUAL
    // bytes to the wallet-side reader rather than rebuilding a body it merely
    // believes the issuer sends. Reconstructing it would assert the caller's
    // assumption about the shape, which is the assumption most likely wrong.
    responseBody: response.body,
    did: did,
    publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y },
    privateJwk: privateJwk,
    privateKey: pair.privateKey,
    metadata: meta
  };
}

// What a jwt_vc_json credential has to be, whoever issued it.
//
// These are the format's own rules, so they hold for the mock and for walt.id
// alike, and they are the assertions that make an interoperability run mean
// something: a test that only checked "something came back" would pass against
// an issuer returning an SD-JWT under a jwt_vc_json configuration id.
function assertIsJwtVcJson(credential, who) {
  log.debug("Entering assertIsJwtVcJson(). who=" + who);
  const label = who ? who + ": " : "";
  assert.strictEqual(String(credential).indexOf("~"), -1,
    label + "a jwt_vc_json credential is a bare JWT — a tilde means an SD-JWT Combined Serialization " +
    "came back under a jwt_vc_json configuration.");
  const parts = String(credential).split(".");
  assert.strictEqual(parts.length, 3, label + "and a three-part JWS. Got " + parts.length + " part(s).");
  const payload = jsonFromB64u(parts[1]);
  assert.ok(payload.vc && typeof payload.vc === "object",
    label + "the VC-JWT encoding puts the credential in the vc claim.");
  assert.ok(!payload._sd,
    label + "and carries no _sd digests: this format has no selective disclosure.");
  const types = [].concat(payload.vc.type || []);
  assert.ok(types.indexOf("VerifiableCredential") >= 0,
    label + "its type array should include VerifiableCredential. Got: " + JSON.stringify(types));
  assert.ok(payload.vc.credentialSubject && typeof payload.vc.credentialSubject === "object",
    label + "and a credentialSubject.");
  log.debug("Leaving assertIsJwtVcJson(). types=" + types.join("/"));
  return { payload: payload, vc: payload.vc, types: types,
           credentialSubject: payload.vc.credentialSubject };
}

// How the credential says who may present it.
//
// Two answers are in the wild and the difference is the whole reason the walt.id
// jobs exist: our mock binds with cnf.jwk (a key), while walt.id's own
// jwt_vc_json profiles bind with credentialSubject.id (a subject DID). Reported
// rather than asserted, so a test can say which it got instead of failing on an
// implementation's legitimate choice.
function holderBindingOf(payload) {
  const cnfJwk = ((payload || {}).cnf || {}).jwk;
  const subjectId = (((payload || {}).vc || {}).credentialSubject || {}).id || "";
  if (cnfJwk) return { kind: "cnf.jwk", jwk: cnfJwk, subjectId: subjectId };
  if (subjectId) return { kind: "credentialSubject.id", jwk: null, subjectId: subjectId };
  return { kind: "none", jwk: null, subjectId: "" };
}

// Put a credential where the wallet pages look for it, with the verifier this
// run should talk to. The same localStorage names the issuance workflow writes.
async function plantIntoWallet(driver, opts) {
  log.debug("Entering plantIntoWallet().");
  const By = opts.By;
  const until = opts.until;
  await driver.get(opts.baseUrl + "/vc-presentation-0.html");
  await driver.wait(until.elementLocated(By.id("vp_usecases")), opts.waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_credentials', JSON.stringify([arguments[0]]));" +
    "localStorage.setItem('sdjwtvc_holder_jwk', arguments[1]);" +
    "localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[2]);" +
    // Set explicitly rather than inferred: step 0's Configuration Parameters
    // pane wins over anything derived, and the baked default differs per target
    // (localhost:8081 locally, sts:8081 containerized, empty on the deployed
    // sites), so a test that did not say would point somewhere else.
    "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[3]);" +
    "localStorage.setItem('sdjwtvp_verifier_jwks_url', arguments[3] + '/oauth2/jwks');" +
    "localStorage.setItem('vci_credential_issuer', arguments[4]);",
    opts.credential, JSON.stringify(opts.publicJwk), JSON.stringify(opts.privateJwk),
    opts.verifierBase, opts.issuerBase);
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vp_usecases")), opts.waitTime);
  await driver.sleep(400);
  log.debug("Leaving plantIntoWallet().");
}

// A fresh Authorization Request from the mock verifier, asking for jwt_vc_json.
async function freshJwtVcJsonRequest(verifierBase, byReference) {
  log.debug("Entering freshJwtVcJsonRequest(). byReference=" + !!byReference);
  const query = ["format=" + encodeURIComponent(FORMAT)];
  if (byReference) query.push("by=reference");
  const r = await fetch(verifierBase + "/oid4vp/start?" + query.join("&"), { redirect: "manual" });
  const location = r.headers.get("location");
  assert.ok(location, "the verifier should redirect the wallet with its request.");
  const params = {};
  location.slice(location.indexOf("?") + 1).split("&").forEach(function (pair) {
    const eq = pair.indexOf("=");
    params[decodeURIComponent(pair.slice(0, eq))] = decodeURIComponent(pair.slice(eq + 1));
  });
  log.debug("Leaving freshJwtVcJsonRequest(). state=" + params.state);
  return { params: params, location: location };
}

async function verdictFor(verifierBase, state) {
  const r = await httpJson(verifierBase + "/oid4vp/result/" + encodeURIComponent(state));
  assert.ok(r.ok, "the verifier should report what it decided, got HTTP " + r.status);
  return r.body;
}

module.exports = {
  FORMAT: FORMAT,
  b64u: b64u,
  b64uDecode: b64uDecode,
  jsonFromB64u: jsonFromB64u,
  httpJson: httpJson,
  issuerMetadata: issuerMetadata,
  jwtVcJsonConfigurationId: jwtVcJsonConfigurationId,
  mintJwtVcJson: mintJwtVcJson,
  preAuthorizedAccessToken: preAuthorizedAccessToken,
  WALLET_CLIENT_ID: WALLET_CLIENT_ID,
  assertIsJwtVcJson: assertIsJwtVcJson,
  holderBindingOf: holderBindingOf,
  didJwkFor: didJwkFor,
  plantIntoWallet: plantIntoWallet,
  freshJwtVcJsonRequest: freshJwtVcJsonRequest,
  verdictFor: verdictFor
};
