// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: jwt_vc_json_common.js
//
// ---------------------------------------------------------------------------
// The parts of a jwt_vc_json test that do not depend on WHOSE issuer or
// verifier is on the other end.
//
// Four tests use this — issuance and presentation, against the mock STS and
// against walt.id — and they differ only in the base URLs they are handed and
// in what they are allowed to assume about the implementation. Everything else
// (how a credential of this format is obtained, what it must look like, how a
// Verifiable Presentation JWT is built and submitted) is the same, so it lives
// here rather than four times over.
//
// Why jwt_vc_json needs its own tests rather than a flag on the SD-JWT ones:
// the two formats differ in the thing those tests are ABOUT. The SD-JWT suites
// are built around Disclosures — selecting them, hashing them, withholding
// them, the sd_hash that commits to exactly which ones went. None of that
// exists here. Threading a format flag through them would leave most of their
// assertions skipped and the rest reading as though selective disclosure had
// merely been declined, which is not the same statement as "this format cannot
// do it".
// ---------------------------------------------------------------------------

const crypto = require("crypto");
const assert = require("assert");

var bunyan = require("bunyan");
const waitForContent = require("./wait_for.js");
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
// client_id sent with the pre-authorized code grant, and the iss of the proof
// of possession. walt.id enforces that they match ("Credential proof issuer
// claim must match the access token client_id") and it is right to — a proof
// made by one client and presented by another proves nothing about the
// presenter. Our mock does not check, so a mismatch only shows up against
// walt.id, which is exactly the kind of thing an interoperability run is for.
const WALLET_CLIENT_ID = process.env.OID4VCI_WALLET_CLIENT_ID ||
    "idptools-debugger-tests";

// The applications registry on the mock issuer, and the one call every OID4VC
// job makes into it. See tests/sts_applications.js for why the wallet is put
// there before it collects anything.
const registry = require("./sts_applications.js");
const { loadUrl } = require("./page_load.js");

// "The page's bundle has run", which is a different question from "the page's
// markup is there" and the one that matters before pressing anything: every
// control in this application is wired with an inline onclick naming a
// browserify --standalone global, so a click that lands before the bundle has
// executed raises ReferenceError inside the page and does nothing at all out
// here. waitForPageBundle() in tests/wait_for.js reads the page's own script
// tags, so this needs no table of global names, and its note records what the
// missing wait cost.
async function pageBundleReady(driver) {
  log.debug("Entering pageBundleReady().");
  await waitForContent.waitForPageBundle(driver,
    "the page this test just navigated to");
  log.debug("Leaving pageBundleReady().");
}

function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}
function b64uDecode(s) {
  log.debug("Entering b64uDecode().");
  log.debug("Leaving b64uDecode().");
  return Buffer.from(String(s), "base64url");
}
function jsonFromB64u(s) {
  log.debug("Entering jsonFromB64u().");
  log.debug("Leaving jsonFromB64u().");
  return JSON.parse(b64uDecode(s).toString("utf8"));
}

async function httpJson(url, options) {
  log.debug("Entering httpJson().");
  let r;
  try {
    r = await fetch(url, options);
  } catch (e) {
    // A refused connection or an unresolvable host arrives as an undici
    // TypeError whose message is "fetch failed" and whose stack is all
    // internals. These tests fail rather than skip when a service is missing,
    // so the failure has to name WHICH service and WHERE — the raw error names
    // neither.
    const err = new Error("could not reach " + url + ": " + (e.cause ?
        e.cause.message : e.message) +
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
  log.debug("Leaving httpJson().");
  return { ok: r.ok, status: r.status, body: body, raw: raw };
}

// An issuer's credential issuer metadata. The well-known is INSERTED before the
// issuer's path rather than appended (RFC 8414), which is what walt.id needs —
// its Credential Issuer Identifier is `…/openid4vci`, so the document lives at
// `…/.well-known/openid-credential-issuer/openid4vci`. Appending finds nothing.
// Both forms are tried, insertion first, because the mock issuer has no path
// and either works for it.
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
    // Not an absolute URL: fall back to appending, which is all that can be
    // done.
    log.debug("issuerMetadata(): " + base + " is not an absolute URL.");
  }
  const candidates = [];
  if (path) candidates.push(origin + "/.well-known/openid-credential-issuer" +
      path);
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

// THE SCOPES A WALLET ASKS FOR (rcbj/id-proto-debugger#327): the `scope`
// each credential configuration names in the issuer metadata, or only the
// configurations `ids` names. OpenID4VCI 1.0 is OAuth 2.0 and a wallet needs
// an ACCESS TOKEN, never an ID Token, so it asks for these and not for
// `openid`; iya-sts refuses an ID Token, in product mode, to an application
// that is not declared for OpenID Connect, and a wallet is declared for
// oauth2 and oid4vci alone.
function credentialScopes(meta, ids) {
  log.debug("Entering credentialScopes().");
  const configs = (meta && meta.credential_configurations_supported) || {};
  const names = ids && ids.length ? [].concat(ids) : Object.keys(configs);
  const scopes = [];
  names.forEach(function (id) {
    const scope = configs[id] && configs[id].scope;
    if (scope && scopes.indexOf(scope) < 0) {
      scopes.push(scope);
    }
  });
  log.debug("Leaving credentialScopes(). " + scopes.join(" "));
  return scopes;
}

// The credential_configuration_id this issuer offers in jwt_vc_json, or "" when
// it offers none.
//
// Returned rather than asserted so a caller can SKIP. The mock issuer and
// walt.id name their configurations differently — and walt.id only offers the
// format once its configuration has been added and the container restarted — so
// a test that hard-coded an id would fail for a configuration reason wearing
// the costume of a protocol failure.
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
    log.debug("Leaving jwtVcJsonConfigurationId(). Using the configured " +
              preferred);
    return { id: preferred, meta: meta, entry: configs[preferred] };
  }
  const found = Object.keys(configs).filter(function (id) {
    return configs[id] && configs[id].format === FORMAT;
  });
  log.debug("Leaving jwtVcJsonConfigurationId(). " + found.length +
            " jwt_vc_json configuration(s).");
  return { id: found[0] || "", meta: meta, entry: found[0] ?
          configs[found[0]] : null };
}

// A real access token from an issuer that insists on one.
//
// Our mock accepts any bearer string, so the tests against it can send an
// opaque placeholder. walt.id cannot: it refuses anything that is not a JWS
// ("String does not look like JWS"), which is correct of it and is what made
// the first version of these tests fail with a 401 that looked like a
// jwt_vc_json problem and was not.
//
// The token is obtained with the PRE-AUTHORIZED CODE grant rather than by
// driving a browser through Keycloak. That grant exists precisely so a
// credential can be collected without an interactive authorization leg, walt.id
// advertises it, and it keeps this helper usable from a test with no browser.
// The authorization-code leg through the pages is already covered end to end by
// sd_jwt_vc_waltid.js; repeating it here would test the same thing twice and
// double the slowest part of the suite.
//
// Returns "" when the issuer offers no such route, so the caller can fall back
// to an opaque token — which is exactly right for the mock.
async function preAuthorizedAccessToken(issuerBase, profileId) {
  log.debug("Entering preAuthorizedAccessToken(). profileId=" + profileId);
  var base = String(issuerBase || "").replace(/\/+$/, "");
  var origin = base;
  try {
    origin = new URL(base).origin;
  } catch (e) {
    // Not absolute; the offer call below will fail and "" is returned.
    log.debug("preAuthorizedAccessToken(): " + base +
              " is not an absolute URL.");
  }
  var created = await httpJson(origin + "/issuer2/credential-offers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ profileId: profileId, authMethod: "PRE_AUTHORIZED",
                         valueMode: "BY_VALUE" })
  }).catch(function () { return { ok: false, status: 0, raw: "" }; });
  if (created.status !== 201 && created.status !== 200) {
    log.debug("Leaving preAuthorizedAccessToken(). No offer endpoint (HTTP " +
              created.status + ").");
    return "";
  }
  var offerUri = String((created.body || {}).credentialOffer || "");
  var offerParam = "";
  try {
    offerParam = new URL(offerUri.replace("openid-credential-offer://",
        "https://wallet.invalid/"))
      .searchParams.get("credential_offer") || "";
  } catch (e) {
    offerParam = "";
  }
  if (!offerParam) {
    log.debug("Leaving preAuthorizedAccessToken(). The offer was not passed " +
              "by value.");
    return "";
  }
  var offer = JSON.parse(offerParam);
  var grant = (offer.grants ||
      {})["urn:ietf:params:oauth:grant-type:pre-authorized_code"] || {};
  var code = grant["pre-authorized_code"];
  if (!code) {
    log.debug("Leaving preAuthorizedAccessToken(). The offer carries no " +
              "pre-authorized code.");
    return "";
  }

  var meta = await issuerMetadata(issuerBase);
  var asUrl = origin + "/.well-known/oauth-authorization-server" +
              (function () { try {
                return new URL(base).pathname.replace(/\/+$/, "");
              } catch (e) {
                return "";
              } })();
  var as = await httpJson(asUrl);
  var tokenEndpoint = ((as.body || {}).token_endpoint) || ((meta ||
      {}).token_endpoint) || "";
  if (!tokenEndpoint) {
    log.debug("Leaving preAuthorizedAccessToken(). No token endpoint " +
              "advertised.");
    return "";
  }
  // A client_id, always. The pre-authorized code grant has no client
  // authentication of its own, so it is tempting to send nothing — and walt.id
  // refuses that outright with "Anonymous pre-authorized code access is not
  // supported". It says so in its metadata too, as
  // pre-authorized_grant_anonymous_access_supported: false, which is the
  // machine-readable version of the same sentence and is logged below when it
  // is present. Sending an identifier costs nothing where it is not required.
  var anonymousOk = (as.body ||
      {})["pre-authorized_grant_anonymous_access_supported"];
  if (anonymousOk === false) {
    log.debug("preAuthorizedAccessToken(): this issuer requires a client_id " +
              "for the pre-authorized grant.");
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
  log.debug("Leaving preAuthorizedAccessToken(). " + (accessToken ?
            "got a token" : "no token: " +
            String(token.raw).slice(0, 160)));
  return accessToken;
}

// Ask the issuer for a jwt_vc_json credential, with a real proof of possession.
//
// The access token is deliberately whatever the caller was given (the mock
// accepts an opaque one); this helper is about the CREDENTIAL, not about how
// the authorization was obtained — the SD-JWT suites already cover that path in
// full, through the pages. `proofKeyMode` says how the proof of possession
// identifies the holder, and the two issuers genuinely differ:
//
//   "jwk"  the public key inline in the proof header. Our mock reads header.jwk
//          and binds the credential with cnf.jwk.
//   "did"  a did:jwk in the header's kid. walt.id's jwt_vc_json profile binds
//          with credentialSubject.id = "<subjectDid>", and it resolves that
//          from the proof — hand it a bare jwk and it refuses the request with
//          "Cannot find in context: subjectDid", because there is no DID to put
//          in the credential.
//
// Neither is wrong and the specification permits both, which is why this is a
// parameter rather than a fix. It is also the substance of the interoperability
// finding: a wallet that only ever talked to one of these two would have no
// idea the other existed.
function didJwkFor(publicJwk) {
  log.debug("Entering didJwkFor().");
  var ordered = { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x };
  if (publicJwk.y) ordered.y = publicJwk.y;
  log.debug("Leaving didJwkFor().");
  return "did:jwk:" + b64u(JSON.stringify(ordered));
}

async function mintJwtVcJson(issuerBase, configurationId, accessToken,
                             proofKeyMode) {
  log.debug("Entering mintJwtVcJson(). configurationId=" + configurationId +
            ", proofKeyMode=" + (proofKeyMode || "jwk"));
  const meta = await issuerMetadata(issuerBase);
  assert.ok(meta && meta.credential_endpoint,
            "the issuer should publish a credential_endpoint.");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  const privateJwk = pair.privateKey.export({ format: "jwk" });

  let nonce = "";
  if (meta.nonce_endpoint) {
    const n = await httpJson(meta.nonce_endpoint, { method: "POST" });
    nonce = (n.body && n.body.c_nonce) || "";
  }
  const compact = { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x,
      y: publicJwk.y };
  const did = didJwkFor(compact);
  const head = b64u(JSON.stringify(
    proofKeyMode === "did"
      ? { typ: "openid4vci-proof+jwt", alg: "ES256", kid: did + "#0" }
      : { typ: "openid4vci-proof+jwt", alg: "ES256", jwk: compact }));
  const claims = b64u(JSON.stringify({
    // iss MUST be the client the access token was issued to — see
    // WALLET_CLIENT_ID.
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
    "the issuer should mint a " + FORMAT + " credential for configuration \"" +
        configurationId +
    "\", got HTTP " + response.status + " " + String(response.raw).slice(0,
        300));

  const credential = (((response.body || {}).credentials || [])[0] ||
      {}).credential ||
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
    publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x,
                y: publicJwk.y },
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
    label + "a jwt_vc_json credential is a bare JWT — a tilde means an " +
        "SD-JWT Combined Serialization " +
    "came back under a jwt_vc_json configuration.");
  const parts = String(credential).split(".");
  assert.strictEqual(parts.length, 3, label + "and a three-part JWS. Got " +
                     parts.length + " part(s).");
  const payload = jsonFromB64u(parts[1]);
  assert.ok(payload.vc && typeof payload.vc === "object",
    label + "the VC-JWT encoding puts the credential in the vc claim.");
  assert.ok(!payload._sd,
    label +
        "and carries no _sd digests: this format has no selective disclosure.");
  const types = [].concat(payload.vc.type || []);
  assert.ok(types.indexOf("VerifiableCredential") >= 0,
    label + "its type array should include VerifiableCredential. Got: " +
        JSON.stringify(types));
  assert.ok(payload.vc.credentialSubject &&
            typeof payload.vc.credentialSubject === "object",
    label + "and a credentialSubject.");
  log.debug("Leaving assertIsJwtVcJson(). types=" + types.join("/"));
  return { payload: payload, vc: payload.vc, types: types,
           credentialSubject: payload.vc.credentialSubject };
}

// How the credential says who may present it.
//
// Two answers are in the wild and the difference is the whole reason the
// walt.id jobs exist: our mock binds with cnf.jwk (a key), while walt.id's own
// jwt_vc_json profiles bind with credentialSubject.id (a subject DID). Reported
// rather than asserted, so a test can say which it got instead of failing on an
// implementation's legitimate choice.
function holderBindingOf(payload) {
  log.debug("Entering holderBindingOf().");
  const cnfJwk = ((payload || {}).cnf || {}).jwk;
  const subjectId = (((payload || {}).vc || {}).credentialSubject || {}).id ||
      "";
  if (cnfJwk) {
    log.debug("Leaving holderBindingOf().");
    return { kind: "cnf.jwk", jwk: cnfJwk, subjectId: subjectId };
  }
  if (subjectId) {
    log.debug("Leaving holderBindingOf().");
    return { kind: "credentialSubject.id", jwk: null, subjectId: subjectId };
  }
  log.debug("Leaving holderBindingOf().");
  return { kind: "none", jwk: null, subjectId: "" };
}

// Put a credential where the wallet pages look for it, with the verifier this
// run should talk to. The same localStorage names the issuance workflow writes.
async function plantIntoWallet(driver, opts) {
  log.debug("Entering plantIntoWallet().");
  const By = opts.By;
  const until = opts.until;
  await loadUrl(driver, opts.baseUrl + "/vc-presentation-0.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vp_usecases")), opts.waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_credentials', " +
        "JSON.stringify([arguments[0]]));" +
    "localStorage.setItem('sdjwtvc_holder_jwk', arguments[1]);" +
    "localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[2]);" +
    // Set explicitly rather than inferred: step 0's Configuration Parameters
    // pane wins over anything derived, and the baked default differs per target
    // (localhost:8081 locally, sts:8081 containerized, empty on the deployed
    // sites), so a test that did not say would point somewhere else.
    "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[3]);" +
    "localStorage.setItem('sdjwtvp_verifier_jwks_url', arguments[3] + " +
        "'/oauth2/jwks');" +
    "localStorage.setItem('vci_credential_issuer', arguments[4]);" +
    // The Verifier's website; a deployed site defaults to none.
    "localStorage.setItem('sdjwtvp_verifier_site_url', arguments[5]);",
    opts.credential, JSON.stringify(opts.publicJwk),
        JSON.stringify(opts.privateJwk),
    opts.verifierBase, opts.issuerBase,
    (process.env.COMPANION_URL || "http://localhost:9700")
        .replace(/\/+$/, "") + "/verifier");
  await driver.navigate().refresh();
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vp_usecases")), opts.waitTime);
  await driver.sleep(400);
  log.debug("Leaving plantIntoWallet().");
}

// STARTING A VERIFICATION, AND READING WHAT WAS DECIDED, AT iya-sts's OWN
// DOORS. They were the demonstration Verifier's `GET /oid4vp/start` (a 303 to
// the wallet carrying the request) and `GET /oid4vp/result/:state`, which
// iya-sts #591/#594 moved to its development companion; the doors every
// starter uses now are `POST /admin-api/verifications/start` — which answers
// the same wallet URL as JSON (`walletUrl`, the web wallet's page with the
// request on its query string) — and `GET /admin-api/verifications?state=`,
// whose answer carries the old result's members (`state`, `nonce`,
// `requested`, `received`, `verdict`) plus `found`. The management API's
// token is put on both by tools/attach-admin-token.js.
async function startVerification(verifierBase, format, byReference) {
  log.debug("Entering startVerification(). format=" + format +
            " byReference=" + !!byReference);
  const asked = { format: format, by: byReference ? "reference" : "value" };
  const r = await fetch(verifierBase + "/admin-api/verifications/start", {
    method: "POST",
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
    body: JSON.stringify(asked)
  });
  const body = await r.json().catch(function () {
    return null;
  });
  const location = body && body.ok ? String(body.walletUrl || "") : "";
  assert.ok(location,
    "the Verifier should start a " + format + " verification and name the " +
    "wallet URL carrying its request; POST /admin-api/verifications/start " +
    "answered " + r.status + ": " + JSON.stringify(body).slice(0, 300));
  const params = {};
  location.slice(location.indexOf("?") + 1).split("&").forEach(function (pair) {
    const eq = pair.indexOf("=");
    params[decodeURIComponent(pair.slice(0, eq))] =
           decodeURIComponent(pair.slice(eq + 1));
  });
  log.debug("Leaving startVerification(). state=" + params.state);
  return { params: params, location: location,
           query: location.split("?")[1] || "" };
}

// THE VERIFIER'S WEBSITE, AS A PERSON USES IT. The chooser on step 0 sends
// the browser to the Verifier's website (iya-sts's companion on this
// suite's stacks, `/verifier`), which is ONE page with a form: the format to
// ask for, by value or by reference, and whether the wallet is on this
// device. This fills it the way a person would and presses Start; for a
// wallet on this device the Verifier then redirects the browser to the
// wallet (the debugger) with its request. `opts`: { By, until, format,
// byReference, crossDevice, wait }.
async function startAtTheVerifierWebsite(driver, opts) {
  log.debug("Entering startAtTheVerifierWebsite(). format=" + opts.format);
  const By = opts.By;
  const until = opts.until;
  await driver.wait(until.elementLocated(By.id("start")), opts.wait,
    "the Verifier's website should show its start form (#start).");
  const chosen = await driver.executeScript(
    "var f = document.getElementById('format');" +
    "var known = Array.prototype.map.call(f.options, function (o) {" +
    "  return o.value; });" +
    "if (known.indexOf(arguments[0]) < 0) { return known; }" +
    "f.value = arguments[0];" +
    "document.getElementById('by').value = arguments[1];" +
    "document.getElementById('mode').value = arguments[2];" +
    "return true;",
    opts.format, opts.byReference ? "reference" : "value",
    opts.crossDevice ? "cross-device" : "same-device");
  assert.strictEqual(chosen, true,
    "the Verifier's website offers no " + opts.format + " format; it " +
    "offers " + JSON.stringify(chosen) + ".");
  await driver.findElement(By.id("start")).click();
  if (!opts.crossDevice) {
    await driver.wait(until.urlContains("vc-presentation-1.html"), opts.wait,
      "the Verifier should send the wallet its request.");
  }
  log.debug("Leaving startAtTheVerifierWebsite().");
}

// A PRE-AUTHORIZED CREDENTIAL OFFER, MADE THE WAY A PERSON MAKES ONE.
//
// A pre-authorized code IS the authorization for a credential about the
// person it names, so iya-sts makes one only for the person asking, on
// their own account page (`/portal/wallet`, iya-sts #589). The demonstration
// issuer page that used to make one for a configured `oid4vci.offerUsername`
// is gone (#594). So: sign the person in at the portal, choose the
// configuration and the mode — `cross-device` (H.2) or `deferred` (H.3) — and
// read what the page shows: the Transaction Code, and the offer URI behind
// the QR code (by reference, `credential_offer_uri`). The browser is left on
// the portal page; the caller hands the offer to the wallet.
//
// `opts`: { By, until, stsBase, username, password, mode, configuration,
// wait, consentScreen }. Answers { txCode, offerUri, qr, page, username }.
async function offerFromThePortalWallet(driver, opts) {
  log.debug("Entering offerFromThePortalWallet(). mode=" + opts.mode);
  const By = opts.By;
  const until = opts.until;
  const base = String(opts.stsBase).replace(/\/+$/, "");
  const portal = base + "/portal/wallet";
  // NOBODY SIGNED IN FIRST. The portal signs in through iya-sts's own
  // /oauth2/authorize, so a sign-on session an earlier step of the same job
  // left in this browser lets it straight in as THAT person, with no
  // screen — and the offer is then made for them rather than for
  // `opts.username`. So iya-sts's cookies go before the portal is opened.
  // WebDriver deletes the cookies of the page it is on, which is why a page
  // of that origin is loaded first.
  await driver.get(base + "/healthcheck");
  await driver.manage().deleteAllCookies();
  await driver.get(portal);
  await driver.wait(async function () {
    return (await driver.findElements(By.id("wallet-make"))).length > 0 ||
           (await driver.findElements(By.id("username"))).length > 0;
  }, opts.wait, "the portal's wallet page drew neither its form nor the " +
      "sign-in screen.");
  assert.ok((await driver.findElements(By.id("username"))).length > 0,
    "the portal let this browser in with no sign-in screen although its " +
    "cookies for " + base + " were cleared, so the offer would be made for " +
    "somebody other than " + opts.username + ".");
  await driver.findElement(By.id("username")).sendKeys(opts.username);
  await driver.findElement(By.id("password"))
      .sendKeys(opts.password || "any-password");
  await driver.findElement(By.id("kc-login")).click();
  if (opts.consentScreen) {
    await opts.consentScreen.passInBrowser(driver, By);
  }
  await driver.wait(until.elementLocated(By.id("wallet-make")), opts.wait,
    "the portal's wallet page should offer to make an offer (#wallet-make).");
  const chosen = await driver.executeScript(
    "var c = document.querySelector('input[name=configuration][value=\"' +" +
    "  arguments[0] + '\"]');" +
    "var m = document.querySelector('input[name=mode][value=\"' +" +
    "  arguments[1] + '\"]');" +
    "if (!c || !m) { return Array.prototype.map.call(" +
    "  document.querySelectorAll('input[name=configuration],input[name=mode]')," +
    "  function (i) { return i.name + '=' + i.value; }); }" +
    "c.click(); m.click(); return true;",
    opts.configuration, opts.mode);
  assert.strictEqual(chosen, true,
    "the portal's wallet page does not offer " + opts.configuration + " in " +
    "mode " + opts.mode + "; it offers " + JSON.stringify(chosen) + ".");
  await driver.findElement(By.id("wallet-make")).click();
  await driver.wait(until.elementLocated(By.id("tx_code")), opts.wait,
    "making the offer should draw it, with its Transaction Code (#tx_code).");
  const shown = await driver.executeScript(
    "var qr = document.getElementById('offer_qr');" +
    "return { txCode: document.getElementById('tx_code').textContent.trim()," +
    "  offerUri: document.getElementById('offer_uri').textContent.trim()," +
    "  qr: qr ? qr.tagName.toLowerCase() : ''," +
    "  page: document.body.textContent };");
  log.debug("Leaving offerFromThePortalWallet(). " +
            shown.offerUri.slice(0, 60));
  return { txCode: shown.txCode, offerUri: shown.offerUri, qr: shown.qr,
           page: shown.page, username: opts.username };
}

// A REQUEST, GOT THE WAY A PERSON GETS ONE: the Verifier's website, its
// form, and the redirect to the wallet. Answers what the wallet was handed —
// `{ params, location, query }` parsed off the URL the browser landed on —
// for the checks that need the request's state or DCQL query. `opts`:
// { By, until, siteUrl, format, byReference, wait }.
async function requestThroughTheVerifierWebsite(driver, opts) {
  log.debug("Entering requestThroughTheVerifierWebsite().");
  await driver.get(opts.siteUrl);
  await startAtTheVerifierWebsite(driver, { By: opts.By, until: opts.until,
    format: opts.format, byReference: !!opts.byReference, crossDevice: false,
    wait: opts.wait });
  const location = await driver.getCurrentUrl();
  const params = {};
  location.slice(location.indexOf("?") + 1).split("&").forEach(function (pair) {
    const eq = pair.indexOf("=");
    if (eq > 0) {
      params[decodeURIComponent(pair.slice(0, eq))] =
             decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, " "));
    }
  });
  log.debug("Leaving requestThroughTheVerifierWebsite(). state=" +
            params.state);
  return { params: params, location: location,
           query: location.split("?")[1] || "" };
}

async function verificationResult(verifierBase, state) {
  log.debug("Entering verificationResult().");
  const r = await httpJson(verifierBase + "/admin-api/verifications?state=" +
      encodeURIComponent(state));
  log.debug("Leaving verificationResult(). " + r.status);
  return r;
}

// THE VERIFIER'S VERDICT ON WHAT THE PAGES JUST SENT. Presentation step 3
// shows what the Verifier ANSWERED — all OID4VP gives a wallet — and the
// check-by-check verdict is the Verifier's own record, read here where an
// operator reads it (`/admin-api/verifications?state=`), by the `state` the
// wallet kept with what it sent. Waits for step 3 to report the answer first.
// `opts`: { By, until, wait, verifierBase, waitForStatus }.
async function verdictOfWhatWasSent(driver, opts) {
  log.debug("Entering verdictOfWhatWasSent().");
  await driver.wait(async function () {
    const t = await driver.findElement(opts.By.id("vp_verifier_status"))
        .getText();
    return /accepted the response|refused the response/.test(t);
  }, opts.wait, "step 3 never reported what the Verifier answered.");
  const state = await driver.executeScript(
    "var p = JSON.parse(localStorage.getItem('sdjwtvp_presentation') || " +
    "'{}'); return p.state || '';");
  assert.ok(state, "step 3 holds no state for what was sent, so the " +
            "Verifier's verdict on it cannot be looked up.");
  const doc = await verdictFor(opts.verifierBase, state);
  assert.ok(doc.verdict, "the Verifier has recorded no verdict for state " +
            state + ": " + JSON.stringify(doc).slice(0, 300));
  log.debug("Leaving verdictOfWhatWasSent(). ok=" + doc.verdict.ok);
  return doc.verdict;
}

// A fresh Authorization Request from iya-sts's Verifier, asking for
// jwt_vc_json.
async function freshJwtVcJsonRequest(verifierBase, byReference) {
  log.debug("Entering freshJwtVcJsonRequest(). byReference=" + !!byReference);
  const request = await startVerification(verifierBase, FORMAT, byReference);
  log.debug("Leaving freshJwtVcJsonRequest(). state=" + request.params.state);
  return { params: request.params, location: request.location };
}

async function verdictFor(verifierBase, state) {
  log.debug("Entering verdictFor().");
  const r = await verificationResult(verifierBase, state);
  assert.ok(r.ok, "the verifier should report what it decided, got HTTP " +
            r.status);
  log.debug("Leaving verdictFor().");
  return r.body;
}

// ---------------------------------------------------------------------------
// THE WALLET, IN THE MOCK ISSUER'S APPLICATIONS REGISTRY, BEFORE IT COLLECTS.
//
// Every job in the OID4VC family presents WALLET_CLIENT_ID at that issuer's
// token endpoint, so it is one call and it lives here rather than seven times
// over. It is a no-op against walt.id and against any other issuer this suite
// is pointed at — stsBaseFor() answers "" for anything that is not the mock —
// which is what the interoperability jobs need it to be.
//
// DECLARED FOR `oauth2` AS WELL AS `oid4vci`, because that is what a wallet
// does here: redeeming a pre-authorized code at /oauth2/token makes it an OAuth
// client of that authorization server, which is why one attribute —
// oauthClientId — is the identifier attribute of both families and of OpenID
// Connect beside them.
//
// NO REDIRECT URI. The pre-authorized code grant has no authorization request
// and therefore no callback, and the two jobs that DO drive the authorization
// code flow against this issuer register their own. An entry carrying a
// redirect URI nothing redirects to is the kind of plausible-and-wrong
// configuration this whole change exists to stop.
// ---------------------------------------------------------------------------
async function provisionWallet(issuerBase, options) {
  log.debug("Entering provisionWallet(). issuerBase=" + issuerBase);
  const opts = options || {};
  const clientId = opts.clientId || WALLET_CLIENT_ID;
  const fields = {
    oauthClientId: clientId,
    oauthGrantType: [].concat(opts.grantTypes ||
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]),
    // A wallet holds no secret: it is a public client in the RFC 7591 sense
    // and `none` is that sentence in the registry's own vocabulary.
    oauthTokenEndpointAuthMethod: "none",
    oauthConfidential: "FALSE"
  };
  if (opts.redirectUris && opts.redirectUris.length) {
    fields.oauthRedirectUri = [].concat(opts.redirectUris);
    fields.oauthResponseType = ["code"];
  }
  // THE SCOPES ARE DECLARED, ON `oauthAllowedScope` (iya-sts #708). They
  // were written to `oauthScope`, which is what a client has ASKED FOR and is
  // written by the token endpoint as requests arrive; an update may no longer
  // add to it (STS-REG-0361), so the second job to reconcile this shared
  // wallet was refused. RFC 7591 section 2's `scope` — "the list that the
  // client can use when requesting access tokens" — is the declaration.
  //
  // AND IT IS EVERY CREDENTIAL SCOPE THIS ISSUER OFFERS, not only the ones
  // this job asks for: WALLET_CLIENT_ID is one entry shared by every OID4VC
  // job, a product-mode authorization server issues a client that declares
  // anything only what it declares, and a declaration naming one job's scope
  // would narrow every other job's request to nothing until it reconciled.
  if (opts.scopes && opts.scopes.length) {
    const declared = [].concat(opts.scopes);
    credentialScopes(await issuerMetadata(issuerBase)).forEach(function (one) {
      if (declared.indexOf(one) < 0) {
        declared.push(one);
      }
    });
    fields.oauthAllowedScope = declared;
  }
  const entry = await registry.provision(registry.stsBaseFor(issuerBase), {
    identifier: clientId,
    name: opts.name || "OID4VCI wallet (debugger tests)",
    protocols: ["oauth2", "oid4vci"],
    fields: fields,
    why: opts.why || "the wallet that collects credentials from this issuer"
  });
  log.debug("Leaving provisionWallet().");
  return entry;
}

// AN ACCESS TOKEN THIS REALM ISSUED, FOR A HOLDER WHO EXISTS (2026-09-18).
// A product-mode Credential Issuer refuses a token it cannot verify, so a job
// that asks for a credential gets its token the way a wallet does: the holder
// is created beforehand through the management API with a real password and
// directory attributes, signs in through the authorization code flow with
// PKCE as WALLET_CLIENT_ID (registered with the redirect URI and the grant),
// and the code is redeemed. Answers the access token.
async function holderAccessToken(issuerBase, holder) {
  log.debug("Entering holderAccessToken(). holder=" + holder);
  const stsBase = registry.stsBaseFor(issuerBase);
  const redirectUri = "https://wallet." + holder + ".example.test/cb";
  const password = "Holder-" + crypto.randomBytes(9).toString("base64url") +
                   "-Aa1!";
  // The credential scopes, not `openid` (#327): see credentialScopes().
  const scopes = credentialScopes(await issuerMetadata(issuerBase));
  assert.ok(scopes.length,
    "the issuer's metadata names no credential configuration scope, so a " +
    "wallet has nothing to ask the authorization server for");
  await provisionWallet(issuerBase, {
    grantTypes: ["urn:ietf:params:oauth:grant-type:pre-authorized_code",
                 "authorization_code"],
    redirectUris: [redirectUri], scopes: scopes,
    why: "the wallet a holder signs in to for an access token" });
  await registry.ensurePerson(stsBase, holder, password);
  const granted = await registry.authorizationCode(stsBase, {
    clientId: WALLET_CLIENT_ID, redirectUri: redirectUri, username: holder,
    password: password, scope: scopes.join(" ") });
  const tokenSet = await httpJson(stsBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code: granted.code,
      redirect_uri: redirectUri, code_verifier: granted.verifier,
      client_id: WALLET_CLIENT_ID }).toString() });
  assert.strictEqual(tokenSet.status, 200,
    "the holder's code should redeem for an access token: " + tokenSet.raw);
  log.debug("Leaving holderAccessToken().");
  return tokenSet.body.access_token;
}

module.exports = {
  credentialScopes: credentialScopes,
  holderAccessToken: holderAccessToken,
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
  provisionWallet: provisionWallet,
  assertIsJwtVcJson: assertIsJwtVcJson,
  holderBindingOf: holderBindingOf,
  didJwkFor: didJwkFor,
  plantIntoWallet: plantIntoWallet,
  freshJwtVcJsonRequest: freshJwtVcJsonRequest,
  startVerification: startVerification,
  startAtTheVerifierWebsite: startAtTheVerifierWebsite,
  requestThroughTheVerifierWebsite: requestThroughTheVerifierWebsite,
  offerFromThePortalWallet: offerFromThePortalWallet,
  verificationResult: verificationResult,
  verdictOfWhatWasSent: verdictOfWhatWasSent,
  verdictFor: verdictFor
};
